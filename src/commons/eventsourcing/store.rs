use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};

use kvx::Namespace;
use rpki::{ca::idexchange::MyHandle, repository::x509::Time};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

use crate::commons::{
    api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord},
    error::KrillIoError,
    eventsourcing::{
        cmd::Command, segment, Aggregate, Key, KeyValueError, KeyValueStore, PostSaveEventListener,
        PreSaveEventListener, Scope, Segment, SegmentExt, StoredCommand, StoredCommandBuilder,
    },
};

use super::InitCommand;

pub type StoreResult<T> = Result<T, AggregateStoreError>;

//------------ Storable ------------------------------------------------------

pub trait Storable: Clone + Serialize + DeserializeOwned + Sized + 'static {}
impl<T: Clone + Serialize + DeserializeOwned + Sized + 'static> Storable for T {}

//------------ AggregateStore ------------------------------------------------

/// This type is responsible for managing aggregates.
pub struct AggregateStore<A: Aggregate> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<MyHandle, Arc<A>>>,
    history_cache: Option<Mutex<HashMap<MyHandle, Vec<CommandHistoryRecord>>>>,
    pre_save_listeners: Vec<Arc<dyn PreSaveEventListener<A>>>,
    post_save_listeners: Vec<Arc<dyn PostSaveEventListener<A>>>,
}

/// # Starting up
///
impl<A: Aggregate> AggregateStore<A> {
    /// Creates an AggregateStore using the given storage url
    pub fn create(storage_uri: &Url, namespace: &Namespace, use_history_cache: bool) -> StoreResult<Self> {
        let kv = KeyValueStore::create(storage_uri, namespace)?;
        Self::create_from_kv(kv, use_history_cache)
    }

    /// Creates an AggregateStore for upgrades using the given storage url
    pub fn create_upgrade_store(
        storage_uri: &Url,
        name_space: &Namespace,
        use_history_cache: bool,
    ) -> StoreResult<Self> {
        let kv = KeyValueStore::create_upgrade_store(storage_uri, name_space)?;
        Self::create_from_kv(kv, use_history_cache)
    }

    fn create_from_kv(kv: KeyValueStore, use_history_cache: bool) -> StoreResult<Self> {
        let cache = RwLock::new(HashMap::new());
        let history_cache = if !use_history_cache {
            None
        } else {
            Some(Mutex::new(HashMap::new()))
        };
        let pre_save_listeners = vec![];
        let post_save_listeners = vec![];

        let store = AggregateStore {
            kv,
            cache,
            history_cache,
            pre_save_listeners,
            post_save_listeners,
        };

        Ok(store)
    }

    /// Warms up the cache, to be used after startup. Will fail if any aggregates fail to load
    /// in which case a 'recover' operation can be tried.
    pub fn warm(&self) -> StoreResult<()> {
        for handle in self.list()? {
            self.warm_aggregate(&handle)?;
        }
        info!("Cache for CAs has been warmed.");
        Ok(())
    }

    /// Warm the cache for a specific aggregate.
    pub fn warm_aggregate(&self, handle: &MyHandle) -> StoreResult<()> {
        info!("Warming the cache for: '{}'", handle);

        self.get_latest(handle)
            .map_err(|e| AggregateStoreError::WarmupFailed(handle.clone(), e.to_string()))?;

        Ok(())
    }

    /// Adds a listener that will receive all events before they are stored.
    pub fn add_pre_save_listener<L: PreSaveEventListener<A>>(&mut self, sync_listener: Arc<L>) {
        self.pre_save_listeners.push(sync_listener);
    }

    /// Adds a listener that will receive a reference to all events after they are stored.
    pub fn add_post_save_listener<L: PostSaveEventListener<A>>(&mut self, listener: Arc<L>) {
        self.post_save_listeners.push(listener);
    }
}

/// # Manage Aggregates
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    /// Gets the latest version for the given aggregate. Returns
    /// an AggregateStoreError::UnknownAggregate in case the aggregate
    /// does not exist.
    pub fn get_latest(&self, handle: &MyHandle) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(handle, None, false)
    }

    /// Updates the snapshots for all entities in this store.
    pub fn update_snapshots(&self) -> Result<(), A::Error> {
        for handle in self.list()? {
            self.save_snapshot(&handle)?;
        }

        Ok(())
    }

    /// Gets the latest version for the given aggregate and updates the snapshot.
    pub fn save_snapshot(&self, handle: &MyHandle) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(handle, None, true)
    }

    /// Adds a new aggregate instance based on the init event.
    pub fn add(&self, cmd: A::InitCommand) -> Result<Arc<A>, A::Error> {
        let scope = Self::scope_for_agg(cmd.handle());

        self.kv
            .inner()
            .execute(&scope, move |kv| {
                // The closure needs to return a Result<T, kvx::Error>.
                // In our case T will be a Result<Arc<A>, A::Error>.
                // So.. any kvx error will be in the outer result, while
                // any aggregate related issues can still be returned
                // as an err in the inner result.
                let handle = cmd.handle().clone();

                let init_command_key = Self::key_for_command(&handle, 0);

                if kv.has(&init_command_key)? {
                    // This is no good.. this aggregate already exists.
                    Ok(Err(A::Error::from(AggregateStoreError::DuplicateAggregate(handle))))
                } else {
                    let processed_command_builder = StoredCommandBuilder::<A>::new(
                        cmd.actor().to_string(),
                        Time::now(),
                        handle.clone(),
                        0,
                        cmd.store(),
                    );

                    match A::process_init_command(cmd.clone()) {
                        Ok(init_event) => {
                            let aggregate = A::init(handle.clone(), init_event.clone());
                            let processed_command = processed_command_builder.finish_with_init_event(init_event);

                            let json = serde_json::to_value(&processed_command)?;
                            kv.store(&init_command_key, json)?;

                            let arc = Arc::new(aggregate);

                            self.cache_update(&handle, arc.clone());

                            Ok(Ok(arc))
                        }
                        Err(e) => Ok(Err(e)),
                    }
                }
            })
            .map_err(|kv_err| A::Error::from(AggregateStoreError::KeyStoreError(KeyValueError::KVError(kv_err))))?
    }

    /// Send a command to the latest aggregate referenced by the handle in the command.
    ///
    /// This will:
    /// - Retrieve the latest aggregate for this command.
    /// - Call the A::process_command function
    /// on success:
    ///   - call pre-save listeners with events
    ///   - save command and events
    ///   - call post-save listeners with events
    ///   - return aggregate
    /// on no-op (empty event list):
    ///   - do not save anything, return aggregate
    /// on error:
    ///   - save command and error, return error
    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(cmd.handle(), Some(&cmd), false)
    }

    /// Returns true if an instance exists for the id
    pub fn has(&self, id: &MyHandle) -> Result<bool, AggregateStoreError> {
        self.kv
            .has_scope(&Scope::from_segment(Segment::parse_lossy(id.as_str()))) // id should always be a valid Segment
            .map_err(AggregateStoreError::KeyStoreError)
    }

    /// Lists all known ids.
    pub fn list(&self) -> Result<Vec<MyHandle>, AggregateStoreError> {
        self.aggregates()
    }

    /// Get the latest aggregate and optionally apply a command to it.
    ///
    /// Uses `kvx::execute` to ensure that the whole operation is done inside
    /// a transaction (postgres) or lock (disk).
    fn execute_opt_command(
        &self,
        handle: &MyHandle,
        cmd_opt: Option<&A::Command>,
        save_snapshot: bool,
    ) -> Result<Arc<A>, A::Error> {
        self.kv
            .inner()
            .execute(&Self::scope_for_agg(handle), |kv| {
                // The closure needs to return a Result<T, kvx::Error>.
                // In our case T will be a Result<Arc<A>, A::Error>.
                // So.. any kvx error will be in the outer result, while
                // any aggregate related issues can still be returned
                // as an err in the inner result.

                // Get the aggregate from the cache, or get it from the store.
                let mut changed_from_cached = false;

                let res = match self.cache_get(handle) {
                    Some(arc) => Ok(arc),
                    None => {
                        // There was no cached aggregate, so try to get it
                        // or construct it from the store, and remember that
                        // it was changed compared to the (non-existent) cached
                        // version so that we know that should update the cache
                        // later.
                        changed_from_cached = true;

                        let snapshot_key = Self::key_for_snapshot(handle);
                        match kv.get(&snapshot_key)? {
                            Some(value) => {
                                let agg: A = serde_json::from_value(value)?;
                                Ok(Arc::new(agg))
                            }
                            None => {
                                let init_key = Self::key_for_command(handle, 0);
                                match kv.get(&init_key)? {
                                    Some(value) => {
                                        let init_command: StoredCommand<A> = serde_json::from_value(value)?;

                                        match init_command.into_init() {
                                            Some(init_event) => {
                                                let agg = A::init(handle.clone(), init_event);
                                                Ok(Arc::new(agg))
                                            }
                                            None => Err(A::Error::from(AggregateStoreError::UnknownAggregate(
                                                handle.clone(),
                                            ))),
                                        }
                                    }
                                    None => Err(A::Error::from(AggregateStoreError::UnknownAggregate(handle.clone()))),
                                }
                            }
                        }
                    }
                };

                let mut agg = match res {
                    Err(e) => return Ok(Err(e)),
                    Ok(agg) => agg,
                };

                // We have some version, cached or not. Now see if there are any further
                // changes that ought to be applied. If any changes are found, be sure
                // to mark the aggregate as changed so that the we can update the cache
                // later.
                let next_command = Self::key_for_command(handle, agg.version());
                if kv.has(&next_command)? {
                    let aggregate = Arc::make_mut(&mut agg);

                    // check and apply any applicable processed commands until:
                    // - there are no more processed commands
                    // - the command cannot be applied (return an error)
                    loop {
                        let version = aggregate.version();

                        let key = Self::key_for_command(handle, version);

                        match kv.get(&key)? {
                            None => break,
                            Some(value) => {
                                let command: StoredCommand<A> = serde_json::from_value(value)?;
                                aggregate.apply_command(command);
                                changed_from_cached = true;
                            }
                        }
                    }
                }

                // If a command was passed in, try to apply it, and make sure that it is
                // preserved (i.e. with events or an error).
                let res = if let Some(cmd) = cmd_opt {
                    let aggregate = Arc::make_mut(&mut agg);

                    let version = aggregate.version();

                    let processed_command_builder = StoredCommandBuilder::<A>::new(
                        cmd.actor().to_string(),
                        Time::now(),
                        cmd.handle().clone(),
                        version,
                        cmd.store(),
                    );

                    let command_key = Self::key_for_command(handle, version);

                    // The new command key MUST NOT be in use. If it is in use, then this points
                    // at a bug in Krill transaction / locking handling that we cannot recover
                    // from. So, exit here, as there is nothing sensible we can do with this error.
                    //
                    // See issue: https://github.com/NLnetLabs/krill/issues/322
                    if kv.has(&command_key)? {
                        error!("Command key for '{handle}' version '{version}' already exists.");
                        error!("This is a bug. Please report this issue to rpki-team@nlnetlabs.nl.");
                        error!("Krill will exit. If this issue repeats, consider removing {}.", handle);
                        std::process::exit(1);
                    }

                    match aggregate.process_command(cmd.clone()) {
                        Err(e) => {
                            // Store the processed command with the error.
                            let processed_command = processed_command_builder.finish_with_error(&e);

                            let json = serde_json::to_value(&processed_command)?;
                            aggregate.apply_command(processed_command);

                            changed_from_cached = true;
                            kv.store(&command_key, json)?;

                            Err(e)
                        }
                        Ok(events) => {
                            // note: An empty events vec may result from a no-op command. We don't save those.
                            if !events.is_empty() {
                                // The command contains some effect.
                                let processed_command = processed_command_builder.finish_with_events(events);

                                // We will need to apply the command first because:
                                // a) then we are really, really, sure that it can be applied (no panics)
                                // b) more importantly, we will need to pass an updated aggregate to pre-save listeners
                                //
                                // Unfortunately, this means that we will need to clone the command.
                                aggregate.apply_command(processed_command.clone());

                                // If the command contained any events then we should inform the
                                // pre-save listeners. They may still generate errors, and if
                                // they do, then we return with an error, without saving.
                                let mut opt_err: Option<A::Error> = None;
                                if let Some(events) = processed_command.events() {
                                    for pre_save_listener in &self.pre_save_listeners {
                                        if let Err(e) = pre_save_listener.as_ref().listen(aggregate, events) {
                                            opt_err = Some(e);
                                            break;
                                        }
                                    }
                                }

                                if let Some(e) = opt_err {
                                    // A pre-save listener reported and error. Return with the error
                                    // and do not save the updated aggregate.
                                    changed_from_cached = false;
                                    Err(e)
                                } else {
                                    // Save the latest command.
                                    let json = serde_json::to_value(&processed_command)?;
                                    kv.store(&command_key, json)?;

                                    // Now send the events to the 'post-save' listeners.
                                    if let Some(events) = processed_command.events() {
                                        for listener in &self.post_save_listeners {
                                            listener.as_ref().listen(aggregate, events);
                                        }
                                    }

                                    Ok(())
                                }
                            } else {
                                Ok(())
                            }
                        }
                    }
                } else {
                    Ok(())
                };

                if changed_from_cached {
                    self.cache_update(handle, agg.clone());
                }

                if save_snapshot {
                    let key = Self::key_for_snapshot(handle);
                    let value = serde_json::to_value(agg.as_ref())?;
                    kv.store(&key, value)?;
                }

                if let Err(e) = res {
                    Ok(Err(e))
                } else {
                    Ok(Ok(agg))
                }
            })
            .map_err(|kv_err| A::Error::from(AggregateStoreError::KeyStoreError(KeyValueError::KVError(kv_err))))?
    }
}

/// # Manage Commands
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    /// Find all commands that fit the criteria and return history
    pub fn command_history(
        &self,
        id: &MyHandle,
        crit: CommandHistoryCriteria,
    ) -> Result<CommandHistory, AggregateStoreError> {
        // If we have history cache, then first update it, and use that.
        // Otherwise parse *all* commands in history.

        // Little local helper so we can use borrowed records without keeping
        // the lock longer than it wants to live.
        fn command_history_for_records(
            crit: CommandHistoryCriteria,
            records: &[CommandHistoryRecord],
        ) -> CommandHistory {
            let offset = crit.offset();

            let rows = match crit.rows_limit() {
                Some(limit) => limit,
                None => records.len(),
            };

            let mut matching = Vec::with_capacity(rows);
            let mut skipped = 0;
            let mut total = 0;

            for record in records.iter() {
                if record.matches(&crit) {
                    total += 1;
                    if skipped < offset {
                        skipped += 1;
                    } else if total - skipped <= rows {
                        matching.push(record.clone());
                    }
                }
            }

            CommandHistory::new(offset, total, matching)
        }

        match &self.history_cache {
            Some(mutex) => {
                let mut cache_lock = mutex.lock().unwrap();
                let records = cache_lock.entry(id.clone()).or_default();
                self.update_history_records(records, id)?;
                Ok(command_history_for_records(crit, records))
            }
            None => {
                let mut records = vec![];
                self.update_history_records(&mut records, id)?;
                Ok(command_history_for_records(crit, &records))
            }
        }
    }

    /// Updates history records for a given aggregate
    fn update_history_records(
        &self,
        records: &mut Vec<CommandHistoryRecord>,
        id: &MyHandle,
    ) -> Result<(), AggregateStoreError> {
        let mut version = match records.last() {
            Some(record) => record.version + 1,
            None => 1,
        };

        while let Ok(command) = self.get_command(id, version) {
            records.push(CommandHistoryRecord::from(command));
            version += 1;
        }

        Ok(())
    }

    /// Get the command for this key, if it exists
    pub fn get_command(&self, id: &MyHandle, version: u64) -> Result<StoredCommand<A>, AggregateStoreError> {
        let key = Self::key_for_command(id, version);

        match self.kv.get_transactional(&key)? {
            Some(cmd) => Ok(cmd),
            None => Err(AggregateStoreError::CommandNotFound(id.clone(), version)),
        }
    }
}

impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    fn cache_get(&self, id: &MyHandle) -> Option<Arc<A>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    fn cache_remove(&self, id: &MyHandle) {
        self.cache.write().unwrap().remove(id);
    }

    fn cache_update(&self, id: &MyHandle, arc: Arc<A>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }
}

/// # Manage values in the KeyValue store
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    fn scope_for_agg(agg: &MyHandle) -> Scope {
        Scope::from_segment(Segment::parse_lossy(agg.as_str())) // agg should always be a valid Segment
    }

    fn key_for_snapshot(agg: &MyHandle) -> Key {
        Key::new_scoped(Self::scope_for_agg(agg), segment!("snapshot.json"))
    }

    fn key_for_command(agg: &MyHandle, version: u64) -> Key {
        Key::new_scoped(
            Self::scope_for_agg(agg),
            Segment::parse(&format!("command-{}.json", version)).unwrap(), // cannot panic as a u64 cannot contain a Scope::SEPARATOR
        )
    }

    /// Private, should be called through `list` which takes care of locking.
    fn aggregates(&self) -> Result<Vec<MyHandle>, AggregateStoreError> {
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = MyHandle::from_str(&scope.to_string()) {
                res.push(handle)
            }
        }

        Ok(res)
    }

    /// Drop an aggregate, completely. Handle with care!
    pub fn drop_aggregate(&self, id: &MyHandle) -> Result<(), AggregateStoreError> {
        let scope = Self::scope_for_agg(id);

        self.kv
            .inner()
            .execute(&scope, |kv| kv.delete_scope(&scope))
            .map_err(|kv_err| AggregateStoreError::KeyStoreError(KeyValueError::KVError(kv_err)))?;

        self.cache_remove(id);
        Ok(())
    }
}

//------------ AggregateStoreError -------------------------------------------

/// This type defines possible Errors for the AggregateStore
#[derive(Debug)]
pub enum AggregateStoreError {
    IoError(KrillIoError),
    KeyStoreError(KeyValueError),
    NotInitialized,
    UnknownAggregate(MyHandle),
    DuplicateAggregate(MyHandle),
    InitError(MyHandle),
    ReplayError(MyHandle, u64, u64),
    ConcurrentModification(MyHandle),
    UnknownCommand(MyHandle, u64),
    WarmupFailed(MyHandle, String),
    CouldNotRecover(MyHandle),
    CouldNotArchive(MyHandle, String),
    CommandCorrupt(MyHandle, u64),
    CommandNotFound(MyHandle, u64),
}

impl fmt::Display for AggregateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AggregateStoreError::IoError(e) => e.fmt(f),
            AggregateStoreError::KeyStoreError(e) => write!(f, "KeyStore Error: {}", e),
            AggregateStoreError::NotInitialized => write!(f, "This aggregate store is not initialized"),
            AggregateStoreError::UnknownAggregate(handle) => write!(f, "unknown entity: {}", handle),
            AggregateStoreError::DuplicateAggregate(handle) => write!(f, "duplicate entity: {}", handle),
            AggregateStoreError::InitError(handle) => write!(f, "Command 0 for '{}' has no init", handle),
            AggregateStoreError::ReplayError(handle, version, fail_version) => write!(
                f,
                "Event for '{}' version '{}' had version '{}'",
                handle, version, fail_version
            ),
            AggregateStoreError::ConcurrentModification(handle) => {
                write!(f, "concurrent modification attempt for entity: '{}'", handle)
            }
            AggregateStoreError::UnknownCommand(handle, version) => write!(
                f,
                "Aggregate '{}' does not have command with version '{}'",
                handle, version
            ),
            AggregateStoreError::WarmupFailed(handle, e) => {
                write!(f, "Could not rebuild state for '{}': {}", handle, e)
            }
            AggregateStoreError::CouldNotRecover(handle) => write!(
                f,
                "Could not recover state for '{}', aborting recover. Use backup!!",
                handle
            ),
            AggregateStoreError::CouldNotArchive(handle, e) => write!(
                f,
                "Could not archive commands and events for '{}'. Error: {}",
                handle, e
            ),
            AggregateStoreError::CommandCorrupt(handle, key) => {
                write!(f, "StoredCommand '{}' for '{}' was corrupt", handle, key)
            }
            AggregateStoreError::CommandNotFound(handle, key) => {
                write!(f, "StoredCommand '{}' for '{}' cannot be found", handle, key)
            }
        }
    }
}

impl From<KeyValueError> for AggregateStoreError {
    fn from(e: KeyValueError) -> Self {
        AggregateStoreError::KeyStoreError(e)
    }
}
