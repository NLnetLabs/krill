//! A store for aggregates.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::{error, fmt};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use log::{error, trace};
use rpki::ca::idexchange::MyHandle;
use rpki::repository::x509::Time;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;
use crate::commons::api::history::{
    CommandHistory, CommandHistoryCriteria, CommandHistoryRecord
};
use crate::commons::error::KrillIoError;
use crate::commons::storage::{
    Key, KeyValueError, KeyValueStore, Namespace, Segment, Scope
};
use super::agg::{
    Aggregate, Command, InitCommand, PostSaveEventListener,
    PreSaveEventListener, StoredCommand
};


//------------ Storable ------------------------------------------------------

/// A type that can be stored.
//
//  XXX Try to get rid of this trait.
pub trait Storable: Clone + Serialize + DeserializeOwned { }

impl<T: Clone + Serialize + DeserializeOwned> Storable for T { }


//------------ AggregateStore ------------------------------------------------

/// A store that manages all instances of a certain aggregate type.
pub struct AggregateStore<A: Aggregate> {
    /// The physical store for the aggregates.
    kv: KeyValueStore,

    /// A cache for the last seen version of an instance.
    cache: RwLock<HashMap<MyHandle, Arc<A>>>,

    /// A cache for the command history of an instance.
    history_cache: Option<Mutex<HashMap<MyHandle, Vec<CommandHistoryRecord>>>>,

    /// The pre-save listeners.
    pre_save_listeners: Vec<Arc<dyn PreSaveEventListener<A>>>,

    /// The post-save listeners.
    post_save_listeners: Vec<Arc<dyn PostSaveEventListener<A>>>,
}

/// # Starting up
impl<A: Aggregate> AggregateStore<A> {
    /// Creates a store using the given storage URL and namespace.
    ///
    /// If `use_history_cache` is `true`, the new store will cache any
    /// history cache record created for any instance.
    pub fn create(
        storage_uri: &Url,
        namespace: &Namespace,
        use_history_cache: bool,
    ) -> Result<Self, AggregateStoreError> {
        Ok(Self::create_from_kv(
            KeyValueStore::create(storage_uri, namespace)?, use_history_cache
        ))
    }

    /// Creates a store for upgrades using the given storage URL and namespace.
    ///
    /// If `use_history_cache` is `true`, the new store will cache any
    /// history cache record created for any instance.
    pub fn create_upgrade_store(
        storage_uri: &Url,
        namespace: &Namespace,
        use_history_cache: bool,
    ) -> Result<Self, AggregateStoreError> {
        Ok(Self::create_from_kv(
            KeyValueStore::create_upgrade_store(storage_uri, namespace)?,
            use_history_cache,
        ))
    }

    /// Creates a store for upgrades using the given key-value store.
    fn create_from_kv(
        kv: KeyValueStore,
        use_history_cache: bool,
    ) -> Self {
        Self {
            kv,
            cache: RwLock::new(HashMap::new()),
            history_cache: if use_history_cache {
                Some(Mutex::new(HashMap::new()))
            }
            else {
                None
            },
            pre_save_listeners: Vec::new(),
            post_save_listeners: Vec::new(),
        }
    }

    /// Warms up the cache.
    ///
    /// The method loads all instances and places them in the cache.
    /// It should be called after startup.
    ///
    /// It will fail if any aggregate fails to load.
    pub fn warm(&self) -> Result<(), AggregateStoreError> {
        for handle in self.list()? {
            self.get_latest(&handle).map_err(|e| {
                AggregateStoreError::WarmupFailed(
                    handle.clone(), e.to_string()
                )
            })?;
        }
        Ok(())
    }

    /// Adds a listener that will receive all events before they are stored.
    pub fn add_pre_save_listener<L: PreSaveEventListener<A>>(
        &mut self,
        sync_listener: Arc<L>,
    ) {
        self.pre_save_listeners.push(sync_listener);
    }

    /// Adds a listener that will receive a reference to all events after they
    /// are stored.
    pub fn add_post_save_listener<L: PostSaveEventListener<A>>(
        &mut self,
        listener: Arc<L>,
    ) {
        self.post_save_listeners.push(listener);
    }
}

/// # Manage Aggregates
impl<A: Aggregate> AggregateStore<A> {
    /// Returns whether an instance with the given handle exists.
    pub fn has(&self, id: &MyHandle) -> Result<bool, AggregateStoreError> {
        Ok(self.kv.has(&Self::key_for_command(id, 0))?)
    }

    /// Lists all known ids.
    pub fn list(&self) -> Result<Vec<MyHandle>, AggregateStoreError> {
        // XXX This looks extremely inefficient.
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = MyHandle::from_str(&scope.to_string()) {
                res.push(handle)
            }
        }

        Ok(res)
    }

    /// Gets the latest version for the given aggregate.
    ///
    /// Returns an “unknown aggregate” in case the aggregate does not exist.
    pub fn get_latest(&self, handle: &MyHandle) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(handle, None, false)
    }

    /// Returns the command for the given key and version.
    pub fn get_command(
        &self,
        id: &MyHandle,
        version: u64,
    ) -> Result<StoredCommand<A>, AggregateStoreError> {
        match self.kv.get(&Self::key_for_command(id, version))? {
            Some(cmd) => Ok(cmd),
            None => {
                Err(AggregateStoreError::CommandNotFound(id.clone(), version))
            }
        }
    }

    /// Updates the snapshots for all aggregates in this store.
    pub fn update_snapshots(&self) -> Result<(), A::Error> {
        for handle in self.list()? {
            self.save_snapshot(&handle)?;
        }

        Ok(())
    }

    /// Gets the latest version for the aggregate and updates the snapshot.
    pub fn save_snapshot(
        &self, handle: &MyHandle
    ) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(handle, None, true)
    }

    /// Adds a new aggregate instance based on the init command.
    pub fn add(&self, cmd: A::InitCommand) -> Result<Arc<A>, A::Error> {
        let scope = Self::scope_for_agg(cmd.handle());

        self.kv.execute(&scope, move |kv| {
            let init_command_key = Self::key_for_command(cmd.handle(), 0);

            if kv.has(&init_command_key)? {
                // This is no good.. this aggregate already exists.
                Ok(Err(A::Error::from(
                    AggregateStoreError::DuplicateAggregate(
                        cmd.handle().clone()
                    ),
                )))
            }
            else {
                let processed_command_builder = StoredCommand::<A>::builder(
                    cmd.actor().to_string(),
                    Time::now(),
                    cmd.handle().clone(),
                    0,
                    cmd.store(),
                );

                // XXX cmd needs to be cloned here because of the Fn
                //     closure of execute.
                match A::process_init_command(cmd.clone()) {
                    Ok(init_event) => {
                        let aggregate = A::init(
                            cmd.handle(), init_event.clone(),
                        );
                        let processed_command = processed_command_builder
                            .finish_with_init_event(init_event);

                        kv.store(&init_command_key, &processed_command)?;

                        let arc = Arc::new(aggregate);

                        self.cache_update(cmd.handle(), arc.clone());

                        Ok(Ok(arc))
                    }
                    Err(e) => Ok(Err(e)),
                }
            }
        }).map_err(|e| {
            A::Error::from(AggregateStoreError::KeyStoreError(e))
        })?
    }

    /// Sends a command an aggregate.
    ///
    /// This will wait for a lock for the latest aggregate for this command
    /// and the call [`Aggregate::process_command`] method.
    ///
    /// On success, it will:
    /// * call pre-save listeners with events
    /// * save command and events
    /// * call post-save listeners with events
    /// * return aggregate.
    ///
    /// If the command is a no-op, it will not save anything and return
    /// aggregate.
    ///
    /// On error, it will save the command and the error, then return the
    /// error.
    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(cmd.handle(), Some(&cmd), false)
    }

    /// Get the latest aggregate and optionally apply a command to it.
    ///
    /// This method is the heart of the whole operation.
    fn execute_opt_command(
        &self,
        handle: &MyHandle,
        cmd_opt: Option<&A::Command>,
        save_snapshot: bool,
    ) -> Result<Arc<A>, A::Error> {
        self.kv.execute(&Self::scope_for_agg(handle), |kv| {
            // Do we need to update the cache when we are done?
            let mut changed_from_cached = false;

            // Try to get the latest version from the cache or snapshot, or
            // the initial version if we have neither.
            let mut agg = match self.cache_get(handle) {
                Some(arc) => {
                    trace!("found cached snapshot for {handle}");
                    arc
                }
                None => {
                    // There was no cached aggregate, so try to get it
                    // or construct it from the store, and remember that
                    // it was changed compared to the (non-existent) cached
                    // version so that we know that should update the cache
                    // later.
                    changed_from_cached = true;

                    match kv.get(&Self::key_for_snapshot(handle))? {
                        Some(agg) => {
                            trace!("found snapshot for {handle}");
                            Arc::new(agg)
                        }
                        None => {
                            // No snapshot either. Get the init command and
                            // apply it.
                            let init_key = Self::key_for_command(handle, 0);
                            match kv.get::<StoredCommand<A>>(&init_key)? {
                                Some(init_command) => {
                                    trace!("found init command for {handle}");
                                    match init_command.into_init() {
                                        Some(init_event) => {
                                            let agg = A::init(
                                                &handle, init_event
                                            );
                                            Arc::new(agg)
                                        }
                                        None => {
                                            return Ok(Err(A::Error::from(
                                                AggregateStoreError::
                                                    UnknownAggregate(
                                                        handle.clone(),
                                                )
                                            )))
                                        }
                                    }
                                }
                                None => {
                                    trace!(
                                        "neither snapshot nor init \
                                         command found for {handle}"
                                    );
                                    return Ok(Err(A::Error::from(
                                        AggregateStoreError
                                            ::UnknownAggregate(
                                                    handle.clone()
                                        )
                                    )))
                                }
                            }
                        }
                    }
                }
            };

            // Check if there are additional commands in the store that we
            // haven’t applied yet.
            //
            // XXX This looks up the next version twice which can probably
            //     be avoided.
            let next_command = Self::key_for_command(handle, agg.version());
            if kv.has(&next_command)? {
                let aggregate = Arc::make_mut(&mut agg);

                // check and apply any applicable processed commands until:
                // - there are no more processed commands
                // - the command cannot be applied (return an error)
                loop {
                    let version = aggregate.version();

                    let key = Self::key_for_command(handle, version);

                    match kv.get::<StoredCommand<A>>(&key)? {
                        None => break,
                        Some(command) => {
                            trace!(
                                "found next command found for {handle}: {key}"
                            );
                            aggregate.apply_command(command);
                            changed_from_cached = true;
                        }
                    }
                }
            }

            // If a command was passed in, try to apply it, and make sure that
            // it is preserved.
            let res = if let Some(cmd) = cmd_opt {
                let aggregate = Arc::make_mut(&mut agg);

                let version = aggregate.version();

                let processed = StoredCommand::<A>::builder(
                    cmd.actor().to_string(),
                    Time::now(),
                    cmd.handle().clone(),
                    version,
                    cmd.store(),
                );

                let command_key = Self::key_for_command(handle, version);

                // The new command key MUST NOT be in use. If it is in use,
                // then this points to a bug in Krill transaction/locking
                // handling that we cannot recover from. So, exit here, as
                // there is nothing sensible we can do with this error.
                //
                // See issue: https://github.com/NLnetLabs/krill/issues/322
                if kv.has(&command_key)? {
                    error!(
                        "Command key for '{handle}' version '{version}' \
                         already exists."
                    );
                    error!(
                        "This is a bug. Please report this issue to \
                         rpki-team@nlnetlabs.nl."
                    );
                    error!(
                        "Krill will exit. If this issue repeats, consider \
                         removing {handle}."
                    );
                    std::process::exit(1);
                }

                match aggregate.process_command(cmd.clone()) {
                    Err(e) => {
                        // Store the processed command with the error.
                        let processed = processed.finish_with_error(&e);
                        aggregate.apply_command(processed.clone());
                        changed_from_cached = true;
                        kv.store(&command_key, &processed)?;
                        Err(e)
                    }
                    Ok(events) => {
                        // An empty events vec may result from a no-op
                        // command. We don't save those.
                        if !events.is_empty() {
                            // The command contains some effect.
                            let processed = processed.finish_with_events(
                                events
                            );

                            // We will need to apply the command first
                            // because:
                            // a) then we are really, really, sure that it
                            //    can be applied (no panics),
                            // b) more importantly, we will need to pass an
                            //    updated aggregate to pre-save listeners
                            //
                            // Unfortunately, this means that we will need
                            // to clone the command.
                            aggregate.apply_command(processed.clone());

                            // If the command contained any events then we
                            // should inform the pre-save listeners. They may
                            // still generate errors, and if they do, then we
                            // return with an error, without saving.
                            let mut opt_err: Option<A::Error> = None;
                            if let Some(events) = processed.events() {
                                for pre_save_listener
                                in &self.pre_save_listeners {
                                    if let Err(e)
                                        = pre_save_listener.as_ref()
                                            .listen(aggregate, events)
                                    {
                                        opt_err = Some(e);
                                        break;
                                    }
                                }
                            }

                            if let Some(e) = opt_err {
                                // A pre-save listener reported an error.
                                // Return with the error and do not save the
                                // updated aggregate.
                                changed_from_cached = false;
                                Err(e)
                            } else {
                                // Save the latest command.
                                kv.store(&command_key, &processed)?;

                                // Now send the events to the 'post-save'
                                // listeners.
                                if let Some(events) = processed.events() {
                                    for listener in &self.post_save_listeners {
                                        listener.as_ref().listen(
                                            aggregate, events
                                        );
                                    }
                                }

                                Ok(())
                            }
                        }
                        else {
                            Ok(())
                        }
                    }
                }
            }
            else {
                Ok(())
            };

            if changed_from_cached {
                self.cache_update(handle, agg.clone());
            }

            if save_snapshot {
                kv.store(&Self::key_for_snapshot(handle), agg.as_ref())?;
            }

            if let Err(e) = res {
                Ok(Err(e))
            }
            else {
                Ok(Ok(agg))
            }
        })
        .map_err(|e| A::Error::from(AggregateStoreError::KeyStoreError(e)))?
    }

    /// Drops the aggregate with the given ID completely.
    ///
    /// Handle with care!
    pub fn drop_aggregate(
        &self,
        id: &MyHandle,
    ) -> Result<(), AggregateStoreError> {
        let scope = Self::scope_for_agg(id);
        self.kv.execute(&scope, |kv| kv.delete_scope(&scope))?;
        self.cache_remove(id);
        Ok(())
    }
}


//--- Command History

impl<A: Aggregate> AggregateStore<A> {
    /// Find all commands that fit the criteria and return them as a history.
    pub fn command_history(
        &self,
        id: &MyHandle,
        criteria: CommandHistoryCriteria,
    ) -> Result<CommandHistory, AggregateStoreError> {
        // If we have history cache, then first update it, and use that.
        // Otherwise parse *all* commands in history.
        match &self.history_cache {
            Some(mutex) => {
                let mut cache_lock = mutex.lock().unwrap();
                let records = cache_lock.entry(id.clone()).or_default();
                self.update_history_records(id, records)?;
                Ok(Self::command_history_for_records(criteria, records))
            }
            None => {
                let mut records = vec![];
                self.update_history_records(id, &mut records)?;
                Ok(Self::command_history_for_records(criteria, &records))
            }
        }
    }

    /// Updates history records for a given aggregate.
    fn update_history_records(
        &self,
        id: &MyHandle,
        records: &mut Vec<CommandHistoryRecord>,
    ) -> Result<(), AggregateStoreError> {
        let mut version = match records.last() {
            Some(record) => record.version + 1,
            None => 1,
        };

        while let Ok(command) = self.get_command(id, version) {
            records.push(command.into_history_record());
            version += 1;
        }

        Ok(())
    }

    /// Creates the command history from criteria and records.
    fn command_history_for_records(
        criteria: CommandHistoryCriteria,
        records: &[CommandHistoryRecord],
    ) -> CommandHistory {
        let offset = criteria.offset;

        let rows = match criteria.rows_limit {
            Some(limit) => limit,
            None => records.len(),
        };

        let mut commands = Vec::with_capacity(rows);
        let mut skipped = 0;
        let mut total = 0;

        for record in records.iter() {
            if record.matches(&criteria) {
                total += 1;
                if skipped < offset {
                    skipped += 1;
                } else if total - skipped <= rows {
                    commands.push(record.clone());
                }
            }
        }

        CommandHistory { offset, total, commands }
    }
}


//--- Cache Management

impl<A: Aggregate> AggregateStore<A> {
    /// Retrieves the aggregate with the given ID from the cache.
    fn cache_get(&self, id: &MyHandle) -> Option<Arc<A>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    /// Removes the aggregate with the given ID from the cache.
    fn cache_remove(&self, id: &MyHandle) {
        self.cache.write().unwrap().remove(id);
    }

    /// Sets the aggregate with the given ID to the given value.
    fn cache_update(&self, id: &MyHandle, arc: Arc<A>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }
}


//--- Keys and Scopes

impl<A: Aggregate> AggregateStore<A> {
    /// Returns the scope for the aggregate with the given ID.
    fn scope_for_agg(id: &MyHandle) -> Scope {
        // id should always be a valid segment.
        //
        // XXX I’m not sure this is actually true. There is something with
        //     forward slashes.
        Scope::from_segment(Segment::parse_lossy(id.as_str())) 
    }

    /// Returns the key for the snapshot of the aggregate with the given ID.
    fn key_for_snapshot(agg: &MyHandle) -> Key {
        Key::new_scoped(
            Self::scope_for_agg(agg),
            const { Segment::make("snapshot.json") }
        )
    }

    /// Returns the key for the command for an aggregate and version.
    fn key_for_command(agg: &MyHandle, version: u64) -> Key {
        Key::new_scoped(
            Self::scope_for_agg(agg),
            // Cannot panic as a u64 cannot contain a Scope::SEPARATOR.
            Segment::parse(
                &format!("command-{}.json", version)
            ).unwrap(), 
        )
    }
}


//------------ AggregateStoreError -------------------------------------------

/// An error happened while accessing the aggregate store.
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
    CouldNotArchive(MyHandle, String),
    CommandCorrupt(MyHandle, u64),
    CommandNotFound(MyHandle, u64),
}

impl From<KeyValueError> for AggregateStoreError {
    fn from(e: KeyValueError) -> Self {
        AggregateStoreError::KeyStoreError(e)
    }
}

impl fmt::Display for AggregateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AggregateStoreError::IoError(e) => e.fmt(f),
            AggregateStoreError::KeyStoreError(e) => {
                write!(f, "KeyStore Error: {}", e)
            }
            AggregateStoreError::NotInitialized => {
                write!(f, "This aggregate store is not initialized")
            }
            AggregateStoreError::UnknownAggregate(handle) => {
                write!(f, "unknown entity: {}", handle)
            }
            AggregateStoreError::DuplicateAggregate(handle) => {
                write!(f, "duplicate entity: {}", handle)
            }
            AggregateStoreError::InitError(handle) => {
                write!(f, "Command 0 for '{}' has no init", handle)
            }
            AggregateStoreError::ReplayError(
                handle,
                version,
                fail_version,
            ) => write!(
                f,
                "Event for '{}' version '{}' had version '{}'",
                handle, version, fail_version
            ),
            AggregateStoreError::ConcurrentModification(handle) => {
                write!(
                    f,
                    "concurrent modification attempt for entity: '{}'",
                    handle
                )
            }
            AggregateStoreError::UnknownCommand(handle, version) => write!(
                f,
                "Aggregate '{}' does not have command with version '{}'",
                handle, version
            ),
            AggregateStoreError::WarmupFailed(handle, e) => {
                write!(f, "Could not rebuild state for '{}': {}", handle, e)
            }
            AggregateStoreError::CouldNotArchive(handle, e) => write!(
                f,
                "Could not archive commands and events for '{}'. Error: {}",
                handle, e
            ),
            AggregateStoreError::CommandCorrupt(handle, key) => {
                write!(
                    f,
                    "StoredCommand '{}' for '{}' was corrupt",
                    handle, key
                )
            }
            AggregateStoreError::CommandNotFound(handle, key) => {
                write!(
                    f,
                    "StoredCommand '{}' for '{}' cannot be found",
                    handle, key
                )
            }
        }
    }
}

impl error::Error for AggregateStoreError { }

