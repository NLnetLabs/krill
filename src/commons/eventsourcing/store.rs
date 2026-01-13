//! A store for aggregates.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::{error, fmt};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use log::{error, trace};
use rpki::ca::idexchange::MyHandle;
use rpki::repository::x509::Time;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;
use crate::api::history::{
    CommandHistory, CommandHistoryCriteria, CommandHistoryRecord
};
use crate::commons::error::KrillIoError;
use crate::commons::storage::{Ident, KeyValueError, KeyValueStore};
use super::agg::{Aggregate, Command, InitCommand, StoredCommand};


//------------ Storable ------------------------------------------------------

/// A type that can be stored.
//
//  XXX Try to get rid of this trait.
pub trait Storable: Clone + Serialize + DeserializeOwned { }

impl<T: Clone + Serialize + DeserializeOwned> Storable for T { }


//------------ AggregateStore ------------------------------------------------

/// A store that manages all instances of a certain aggregate type.
///
/// # Key-value store usage
///
/// Each aggregate store uses its own namespace. The scope of the key
/// consists of a single element comprised of the handle of the aggregate
/// instance in question. The name of the key is either `snapshot.json` for
/// the snapshot or `command-N.json` where `N` is the version the command is
/// taking the instance to. `command-0.json` therefore is the name of the
/// init command.
///
/// # Use within Krill
///
/// Within Krill, aggregate stores are used by the trust anchor proxy and
/// signer, by the properties, by the publication repository, the CA manager,
/// and signer info.
pub struct AggregateStore<A: Aggregate> {
    /// The physical store for the aggregates.
    kv: KeyValueStore,

    /// A cache for the last seen version of an instance.
    cache: RwLock<HashMap<MyHandle, Arc<A>>>,

    /// A cache for the command history of an instance.
    history_cache: Option<Mutex<HashMap<MyHandle, Vec<CommandHistoryRecord>>>>,
}

/// # Starting up
impl<A: Aggregate> AggregateStore<A> {
    /// Creates a store using the given storage URL and namespace.
    ///
    /// If `use_history_cache` is `true`, the new store will cache any
    /// history cache record created for any instance.
    pub fn create(
        storage_uri: &Url,
        namespace: &Ident,
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
        namespace: &Ident,
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
}

/// # Manage Aggregates
impl<A: Aggregate> AggregateStore<A> {
    /// Returns whether an instance with the given handle exists.
    pub fn has(&self, id: &MyHandle) -> Result<bool, AggregateStoreError> {
        Ok(self.kv.has(
            Some(&Self::scope_for_agg(id)), &Self::key_for_command(0)
        )?)
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
        match self.kv.get(
            Some(&Self::scope_for_agg(id)), &Self::key_for_command(version)
        )? {
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
    pub fn add_with_context(
        &self, cmd: A::InitCommand, context: A::Context<'_>,
    ) -> Result<Arc<A>, A::Error> {
        let scope = Self::scope_for_agg(cmd.handle());

        self.kv.execute(Some(&scope), |kv| {
            let init_command_key = Self::key_for_command(0);

            if kv.has(Some(&scope), &init_command_key)? {
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
                match A::process_init_command(cmd.clone(), context) {
                    Ok(init_event) => {
                        let aggregate = A::init(
                            cmd.handle(), init_event.clone(),
                        );
                        let processed_command = processed_command_builder
                            .finish_with_init_event(init_event);

                        kv.store(
                            Some(&scope), &init_command_key,
                            &processed_command
                        )?;

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
    pub fn command_with_context(
        &self, cmd: A::Command, context: A::Context<'_>
    ) -> Result<Arc<A>, A::Error> {
        self.execute_opt_command(cmd.handle(), Some((&cmd, context)), false)
    }

    /// Get the latest aggregate and optionally apply a command to it.
    ///
    /// This method is the heart of the whole operation.
    fn execute_opt_command(
        &self,
        handle: &MyHandle,
        cmd_opt: Option<(&A::Command, A::Context<'_>)>,
        save_snapshot: bool,
    ) -> Result<Arc<A>, A::Error> {
        let scope = Self::scope_for_agg(handle);
        self.kv.execute(Some(&scope), |kv| {
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

                    match kv.get(
                        Some(&scope), Self::key_for_snapshot()
                    )? {
                        Some(agg) => {
                            trace!("found snapshot for {handle}");
                            Arc::new(agg)
                        }
                        None => {
                            // No snapshot either. Get the init command and
                            // apply it.
                            let init_key = Self::key_for_command(0);
                            match kv.get::<StoredCommand<A>>(
                                Some(&scope), &init_key
                            )? {
                                Some(init_command) => {
                                    trace!("found init command for {handle}");
                                    match init_command.into_init() {
                                        Some(init_event) => {
                                            let agg = A::init(
                                                handle, init_event
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
            let next_command = Self::key_for_command(agg.version());
            if kv.has(Some(&scope), &next_command)? {
                let aggregate = Arc::make_mut(&mut agg);

                // check and apply any applicable processed commands until:
                // - there are no more processed commands
                // - the command cannot be applied (return an error)
                loop {
                    let version = aggregate.version();

                    let key = Self::key_for_command(version);

                    match kv.get::<StoredCommand<A>>(Some(&scope), &key)? {
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
            let res = if let Some((cmd, context)) = cmd_opt {
                let aggregate = Arc::make_mut(&mut agg);

                let version = aggregate.version();

                let processed = StoredCommand::<A>::builder(
                    cmd.actor().to_string(),
                    Time::now(),
                    cmd.handle().clone(),
                    version,
                    cmd.store(),
                );

                let command_key = Self::key_for_command(version);

                // The new command key MUST NOT be in use. If it is in use,
                // then this points to a bug in Krill transaction/locking
                // handling that we cannot recover from. So, exit here, as
                // there is nothing sensible we can do with this error.
                //
                // See issue: https://github.com/NLnetLabs/krill/issues/322
                if kv.has(Some(&scope), &command_key)? {
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

                match aggregate.process_command(cmd.clone(), context) {
                    Err(e) => {
                        // Store the processed command with the error.
                        let processed = processed.finish_with_error(&e);
                        aggregate.apply_command(processed.clone());
                        changed_from_cached = true;
                        kv.store(Some(&scope), &command_key, &processed)?;
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
                            let mut opt_err = None;
                            if let Some(events) = processed.events() {
                                if let Err(err) = aggregate.pre_save_events(
                                    events, context
                                ) {
                                    opt_err = Some(err);
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
                                kv.store(
                                    Some(&scope), &command_key, &processed
                                )?;

                                // Now send the events to the 'post-save'
                                // listeners.
                                if let Some(events) = processed.events() {
                                    aggregate.post_save_events(
                                        events, context
                                    );
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
                kv.store(
                    Some(&scope), Self::key_for_snapshot(),
                    agg.as_ref()
                )?;
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
        self.kv.execute(Some(&scope), |kv| kv.delete_scope(&scope))?;
        self.cache_remove(id);
        Ok(())
    }
}

impl<'a, A: Aggregate<Context<'a> = ()>> AggregateStore<A> {
    pub fn add(&self, cmd: A::InitCommand) -> Result<Arc<A>, A::Error> {
        self.add_with_context(cmd, ())
    }

    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error> {
        self.command_with_context(cmd, ())
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
    fn scope_for_agg(id: &MyHandle) -> Cow<'_, Ident> {
        Ident::from_handle(id)
    }

    /// Returns the key for the snapshot of the aggregate with the given ID.
    const fn key_for_snapshot() -> &'static Ident {
        const { Ident::make("snapshot.json") }
    }

    /// Returns the key for the command for an aggregate and version.
    fn key_for_command(version: u64) -> Box<Ident> {
        Ident::builder(
            const { Ident::make("command-") }
        ).push_u64(
            version
        ).finish_with_extension(
            const { Ident::make("json") }
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
                write!(f, "KeyStore Error: {e}")
            }
            AggregateStoreError::NotInitialized => {
                write!(f, "This aggregate store is not initialized")
            }
            AggregateStoreError::UnknownAggregate(handle) => {
                write!(f, "unknown entity: {handle}")
            }
            AggregateStoreError::DuplicateAggregate(handle) => {
                write!(f, "duplicate entity: {handle}")
            }
            AggregateStoreError::InitError(handle) => {
                write!(f, "Command 0 for '{handle}' has no init")
            }
            AggregateStoreError::ReplayError(
                handle,
                version,
                fail_version,
            ) => write!(
                f,
                "Event for '{handle}' version '{version}' had version '{fail_version}'"
            ),
            AggregateStoreError::ConcurrentModification(handle) => {
                write!(
                    f,
                    "concurrent modification attempt for entity: '{handle}'"
                )
            }
            AggregateStoreError::UnknownCommand(handle, version) => write!(
                f,
                "Aggregate '{handle}' does not have command with version '{version}'"
            ),
            AggregateStoreError::WarmupFailed(handle, e) => {
                write!(f, "Could not rebuild state for '{handle}': {e}")
            }
            AggregateStoreError::CouldNotArchive(handle, e) => write!(
                f,
                "Could not archive commands and events for '{handle}'. Error: {e}"
            ),
            AggregateStoreError::CommandCorrupt(handle, key) => {
                write!(
                    f,
                    "StoredCommand '{handle}' for '{key}' was corrupt"
                )
            }
            AggregateStoreError::CommandNotFound(handle, key) => {
                write!(
                    f,
                    "StoredCommand '{handle}' for '{key}' cannot be found"
                )
            }
        }
    }
}

impl error::Error for AggregateStoreError { }

