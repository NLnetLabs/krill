use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

use crate::commons::{
    api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord},
    error::KrillIoError,
    eventsourcing::{
        cmd::Command, locks::HandleLocks, segment, Aggregate, Key, KeyValueError, KeyValueStore, PostSaveEventListener,
        PreSaveEventListener, Scope, Segment, SegmentBuf, SegmentExt, StoredCommand, StoredCommandBuilder,
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
    locks: HandleLocks,
}

/// # Starting up
///
impl<A: Aggregate> AggregateStore<A> {
    /// Creates an AggregateStore using a disk based KeyValueStore
    pub fn create(
        storage_uri: &Url,
        name_space: impl Into<SegmentBuf>,
        use_history_cache: bool,
    ) -> StoreResult<Self> {
        let kv = KeyValueStore::create(storage_uri, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let history_cache = if !use_history_cache {
            None
        } else {
            Some(Mutex::new(HashMap::new()))
        };
        let pre_save_listeners = vec![];
        let post_save_listeners = vec![];
        let locks = HandleLocks::default();

        let store = AggregateStore {
            kv,
            cache,
            history_cache,
            pre_save_listeners,
            post_save_listeners,
            locks,
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

    /// Recovers aggregates to the latest possible consistent state based on the
    /// stored commands, and the enclosed associated events found in the keystore.
    ///
    /// Use this in case the state on disk is found to be inconsistent. I.e. the
    /// `warm` function failed and Krill exited.
    ///
    /// Will save new snapshot for latest consistent state and archive any surplus
    /// or corrupt commands. Will archive any non-snapshot / non-command keys.
    pub fn recover(&self) -> StoreResult<()> {
        // TODO: See issue #1086
        for handle in self.list()? {
            info!("Will recover state for '{}'", &handle);

            let scope = Scope::from_segment(Segment::parse_lossy(handle.as_str()));

            // If there is not even a valid init command for the
            // aggregate, then we can really only drop it altogether.

            let aggregate_opt = match self.get_command(&handle, 0) {
                Err(_) => None,
                Ok(init_command) => {
                    if let Some(init_event) = init_command.into_init() {
                        // Initialise
                        let mut aggregate = A::init(handle.clone(), init_event);

                        // Find the next command and apply it until there
                        // is no (valid) next command.
                        while let Ok(command) = self.get_command(&handle, aggregate.version()) {
                            aggregate.apply_command(command);
                        }

                        // Ret
                        Some(aggregate)
                    } else {
                        None
                    }
                }
            };

            match aggregate_opt {
                None => {
                    warn!(
                        "No valid initialisation command found for '{}', will remove it.",
                        handle
                    );

                    self.kv.drop_scope(&scope)?;
                }
                Some(aggregate) => {
                    // Archive any and all keys that are not command keys
                    // for versions we just applied.
                    for key in self.kv.keys(&scope, "")? {
                        // command keys use: command-#.json
                        let keep = if let Some(pfx_removed) = key.name().as_str().strip_prefix("command-") {
                            if let Some(suf_removed) = pfx_removed.strip_suffix(".json") {
                                if let Ok(nr) = suf_removed.parse::<u64>() {
                                    // Keep command if it's for the version
                                    // before this aggregate version.
                                    nr < aggregate.version()
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if !keep {
                            warn!("Archiving surplus key '{}' for '{}'", key, handle);
                            self.kv.archive_surplus(&key)?;
                        }
                    }

                    // Now store a new aggregate
                    self.store_snapshot(&handle, &aggregate)?;

                    // Store in mem cache
                    self.cache_update(&handle, Arc::new(aggregate));
                }
            }
        }

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
    pub fn get_latest(&self, handle: &MyHandle) -> StoreResult<Arc<A>> {
        let agg_lock = self.locks.for_handle(handle.clone());
        let _read_lock = agg_lock.read();
        self.get_latest_no_lock(handle)
    }

    /// Adds a new aggregate instance based on the init event.
    pub fn add(&self, cmd: A::InitCommand) -> StoreResult<Arc<A>> {
        let handle = cmd.handle().clone();

        let agg_lock = self.locks.for_handle(handle.clone());
        let _write_lock = agg_lock.write();

        let processed_command_builder =
            StoredCommandBuilder::<A>::new(cmd.actor().to_string(), Time::now(), handle.clone(), 0, cmd.store());

        let init_event = A::process_init_command(cmd).map_err(|_| AggregateStoreError::InitError(handle.clone()))?;
        let aggregate = A::init(handle.clone(), init_event.clone());

        // Store the init command. It is unlikely that this should fail, but
        // if it does then there is an issue with the storage layer that we cannot
        // recover from. So, exit.
        let processed_command = processed_command_builder.finish_with_init_event(init_event);
        if let Err(e) = self.store_command(&processed_command) {
            self.exit_with_fatal_storage_error(&handle, e);
        }

        // This should not fail, but if it does then it's not as critical
        // because we can always reconstitute the state without snapshots.
        self.store_snapshot(&handle, &aggregate)?;

        let arc = Arc::new(aggregate);
        self.cache_update(&handle, arc.clone());

        Ok(arc)
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
        debug!("Processing command {}", cmd);
        let handle = cmd.handle().clone();

        let agg_lock = self.locks.for_handle(handle.clone());
        let _write_lock = agg_lock.write();

        // Get the latest arc.
        let mut latest = self.get_latest_no_lock(&handle)?;

        if let Some(version) = cmd.version() {
            if version != latest.version() {
                error!(
                    "Version conflict updating '{}', expected version: {}, found: {}",
                    handle,
                    version,
                    latest.version()
                );

                return Err(A::Error::from(AggregateStoreError::ConcurrentModification(handle)));
            }
        }

        let processed_command_builder = StoredCommandBuilder::new(
            cmd.actor().to_string(),
            Time::now(),
            cmd.handle().clone(),
            latest.version(),
            cmd.store(),
        );

        match latest.process_command(cmd) {
            Err(e) => {
                // Store the processed command with the error.
                //
                // If persistence fails, then complain loudly, and exit. Krill should not keep running, because this would
                // result in discrepancies between state in memory and state on disk. Let Krill crash and an operator investigate.
                // See issue: https://github.com/NLnetLabs/krill/issues/322
                let processed_command = processed_command_builder.finish_with_error(&e);
                if let Err(e) = self.store_command(&processed_command) {
                    self.exit_with_fatal_storage_error(&handle, e);
                }

                // Update the cached aggregate so that its version is incremented
                let agg = Arc::make_mut(&mut latest);
                agg.increment_version();

                let mut cache = self.cache.write().unwrap();
                cache.insert(handle, Arc::new(agg.clone()));

                Err(e)
            }
            Ok(events) => {
                if events.is_empty() {
                    Ok(latest) // note: no-op no version info will be updated
                } else {
                    // The command contains some effect.
                    let processed_command = processed_command_builder.finish_with_events(events);

                    // We will need to apply the command first because:
                    // a) then we are really, really, sure that it can be applied (no panics)
                    // b) more importantly, we will need to pass an updated aggregate to pre-save listeners
                    //
                    // Unfortunately, this means that we will need to clone the command.
                    let agg = Arc::make_mut(&mut latest);
                    agg.apply_command(processed_command.clone());

                    // If the command contained any events then we should inform the
                    // pre-save listeners. They may still generate errors, and if
                    // they do, then we will exit here with an error, without saving.
                    if let Some(events) = processed_command.events() {
                        for pre_save_listener in &self.pre_save_listeners {
                            pre_save_listener.as_ref().listen(agg, events)?;
                        }
                    }

                    // Store the processed command - the effect could be an error that
                    // we want to keep, or some events that update the state.
                    //
                    // If persistence fails, then complain loudly, and exit. Krill should not keep running, because this would
                    // result in discrepancies between state in memory and state on disk. Let Krill crash and an operator investigate.
                    // See issue: https://github.com/NLnetLabs/krill/issues/322
                    if let Err(e) = self.store_command(&processed_command) {
                        self.exit_with_fatal_storage_error(&handle, e);
                    }

                    // For now, we also update the snapshot on disk on every change.
                    // See issue #1084
                    self.store_snapshot(&handle, agg)?;

                    // Update the memory cache.
                    let mut cache = self.cache.write().unwrap();
                    cache.insert(handle, Arc::new(agg.clone()));

                    // Now send the events to the 'post-save' listeners.
                    if let Some(events) = processed_command.events() {
                        for listener in &self.post_save_listeners {
                            listener.as_ref().listen(agg, events);
                        }
                    }

                    Ok(latest)
                }
            }
        }
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

    /// Exit with a fatal storage error
    fn exit_with_fatal_storage_error(&self, handle: &MyHandle, e: impl fmt::Display) {
        error!("Cannot save state for '{}'. Got error: {}", handle, e);
        error!("Please check permissions and storage space for: {}", self.kv);
        error!("Krill will now exit to prevent discrepancies between in-memory and stored state.");
        std::process::exit(1);
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
        fn command_history_for_records(crit: CommandHistoryCriteria, records: &[CommandHistoryRecord]) -> CommandHistory {
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
        match self.kv.get(&key) {
            Ok(Some(cmd)) => Ok(cmd),
            Ok(None) => Err(AggregateStoreError::CommandNotFound(id.clone(), version)),
            Err(e) => {
                error!(
                    "Found corrupt command at: {}, will try to archive. Error was: {}",
                    key, e
                );
                self.kv.archive_corrupt(&key)?;
                Err(AggregateStoreError::CommandCorrupt(id.clone(), version))
            }
        }
    }
}

impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    fn has_updates(&self, id: &MyHandle, aggregate: &A) -> bool {
        self.get_command(id, aggregate.version()).is_ok()
    }

    fn cache_get(&self, id: &MyHandle) -> Option<Arc<A>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    fn cache_remove(&self, id: &MyHandle) {
        self.cache.write().unwrap().remove(id);
    }

    fn cache_update(&self, id: &MyHandle, arc: Arc<A>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }

    // This fn uses no lock of its own, so that we can use it in the context
    // of the correct lock obtained by the caller. I.e. if we were to get a
    // read lock here, then we could not use it inside of `fn process` which
    // wants a write lock for the aggregate.
    fn get_latest_no_lock(&self, handle: &MyHandle) -> StoreResult<Arc<A>> {
        trace!("Trying to load aggregate id: {}", handle);

        match self.cache_get(handle) {
            None => match self.get_aggregate(handle, None)? {
                None => {
                    error!("Could not load aggregate with id: {} from disk", handle);
                    Err(AggregateStoreError::UnknownAggregate(handle.clone()))
                }
                Some(agg) => {
                    let arc: Arc<A> = Arc::new(agg);
                    self.cache_update(handle, arc.clone());
                    trace!("Loaded aggregate id: {} from disk", handle);
                    Ok(arc)
                }
            },
            Some(mut arc) => {
                if self.has_updates(handle, &arc) {
                    let agg = Arc::make_mut(&mut arc);
                    self.update_aggregate(handle, agg, None)?;
                }
                trace!("Loaded aggregate id: {} from memory", handle);
                Ok(arc)
            }
        }
    }
}

/// # Manage values in the KeyValue store
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    fn key_for_snapshot(agg: &MyHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
            segment!("snapshot.json"),
        )
    }

    fn key_for_backup_snapshot(agg: &MyHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
            segment!("snapshot-bk.json"),
        )
    }

    fn key_for_new_snapshot(agg: &MyHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
            segment!("snapshot-new.json"),
        )
    }

    fn key_for_command(agg: &MyHandle, version: u64) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
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

    fn store_command(&self, command: &StoredCommand<A>) -> Result<(), AggregateStoreError> {
        let key = Self::key_for_command(command.handle(), command.version());

        self.kv.store_new(&key, command)?;
        Ok(())
    }

    /// Get the latest aggregate
    /// limit to the event nr, i.e. the resulting aggregate version will be limit + 1
    fn get_aggregate(&self, id: &MyHandle, limit: Option<u64>) -> Result<Option<A>, AggregateStoreError> {
        // 1) Try to get a snapshot.
        // 2) If that fails, or if it exceeds the limit, try the backup
        // 3) If that fails, try to get the init event.
        //
        // Then replay all newer events that can be found up to the version (or latest if version is None)
        trace!("Getting aggregate for '{}'", id);

        let mut aggregate_opt: Option<A> = None;

        let snapshot_key = Self::key_for_snapshot(id);

        match self.kv.get::<A>(&snapshot_key) {
            Err(e) => {
                // snapshot file was present and corrupt
                error!(
                    "Could not parse snapshot for '{}', archiving as corrupt. Error was: {}",
                    id, e
                );
                self.kv.archive_corrupt(&snapshot_key)?;
            }
            Ok(Some(agg)) => {
                // snapshot present and okay
                trace!("Found snapshot for '{}'", id);
                if let Some(limit) = limit {
                    if limit >= agg.version() - 1 {
                        aggregate_opt = Some(agg)
                    } else {
                        warn!("Snapshot for '{}' is after version '{}', archiving it", id, limit);
                        self.kv.archive_surplus(&snapshot_key)?;
                    }
                } else {
                    debug!("Found valid snapshot for '{}'", id);
                    aggregate_opt = Some(agg)
                }
            }
            Ok(None) => {}
        }

        if aggregate_opt.is_none() {
            warn!("No suitable snapshot found for '{}' will try backup snapshot", id);
            let backup_snapshot_key = Self::key_for_backup_snapshot(id);
            match self.kv.get::<A>(&backup_snapshot_key) {
                Err(e) => {
                    // backup snapshot present and corrupt
                    error!(
                        "Could not parse backup snapshot for '{}', archiving as corrupt. Error: {}",
                        id, e
                    );
                    self.kv.archive_corrupt(&backup_snapshot_key)?;
                }
                Ok(Some(agg)) => {
                    trace!("Found backup snapshot for '{}'", id);
                    if let Some(limit) = limit {
                        if limit >= agg.version() - 1 {
                            aggregate_opt = Some(agg)
                        } else {
                            warn!(
                                "Backup snapshot for '{}' is after version '{}', archiving it",
                                id, limit
                            );
                            self.kv.archive_surplus(&backup_snapshot_key)?;
                        }
                    } else {
                        debug!("Found valid backup snapshot for '{}'", id);
                        aggregate_opt = Some(agg)
                    }
                }
                Ok(None) => {}
            }
        }

        if aggregate_opt.is_none() {
            warn!(
                "No suitable snapshot for '{}' will rebuild state from events. This can take some time.",
                id
            );

            if let Ok(init_command) = self.get_command(id, 0) {
                aggregate_opt = init_command.into_init().map(|init| A::init(id.clone(), init));
            }
        }

        match aggregate_opt {
            None => Ok(None),
            Some(mut aggregate) => {
                self.update_aggregate(id, &mut aggregate, limit)?;
                Ok(Some(aggregate))
            }
        }
    }

    fn update_aggregate(
        &self,
        id: &MyHandle,
        aggregate: &mut A,
        limit: Option<u64>,
    ) -> Result<(), AggregateStoreError> {
        let start = aggregate.version();

        if let Some(limit) = limit {
            debug!("Will update '{}' from version: {} to: {}", id, start, limit + 1);
        } else {
            debug!("Will update '{}' to latest version", id);
        }

        // check and apply any applicable processed commands until:
        // - the limit is reached (if supplied)
        // - there are no more processed commands
        // - the command cannot be applied (return an error)
        loop {
            let version = aggregate.version();
            if let Some(limit) = limit {
                if limit == version - 1 {
                    debug!("Updated '{}' to: {}", id, version);
                    break;
                }
            }

            if let Ok(command) = self.get_command(id, version) {
                aggregate.apply_command(command);
                debug!("Applied command {} to aggregate {}", version, id);
            } else {
                debug!("No more processed commands found. updated '{}' to: {}", id, version);
                break;
            }
        }

        Ok(())
    }

    /// Saves the latest snapshot - backs up previous snapshot, and drops previous backup.
    /// Uses moves to ensure that files are written entirely before they are made available
    /// for reading.
    pub fn store_snapshot<V: Aggregate>(&self, id: &MyHandle, aggregate: &V) -> Result<(), AggregateStoreError> {
        let snapshot_new = Self::key_for_new_snapshot(id);
        let snapshot_current = Self::key_for_snapshot(id);
        let snapshot_backup = Self::key_for_backup_snapshot(id);

        self.kv.store(&snapshot_new, aggregate)?;

        if self.kv.has(&snapshot_backup)? {
            self.kv.drop_key(&snapshot_backup)?;
        }
        if self.kv.has(&snapshot_current)? {
            self.kv.move_key(&snapshot_current, &snapshot_backup)?;
        }
        self.kv.move_key(&snapshot_new, &snapshot_current)?;

        Ok(())
    }

    /// Drop an aggregate, completely. Handle with care!
    pub fn drop_aggregate(&self, id: &MyHandle) -> Result<(), AggregateStoreError> {
        {
            // First get write access - ensure that no one is using this
            let agg_lock = self.locks.for_handle(id.clone());
            let _write_lock = agg_lock.write();

            self.cache_remove(id);
            self.kv
                .drop_scope(&Scope::from_segment(Segment::parse_lossy(id.as_str())))?;
            // id should always be a valid Segment
        }

        // Then drop the lock for this aggregate immediately. The write lock is
        // out of scope now, to ensure we do not get into a deadlock.
        self.locks.drop_handle(id);
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
