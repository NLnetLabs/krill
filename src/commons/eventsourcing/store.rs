use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::commons::{
    api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord},
    error::KrillIoError,
    eventsourcing::{
        cmd::Command, locks::HandleLocks, segment, Aggregate, Event, Key, KeyValueError, KeyValueStore,
        PostSaveEventListener, PreSaveEventListener, Scope, Segment, SegmentBuf, SegmentExt, StoredCommand,
        StoredCommandBuilder, WithStorableDetails,
    },
};

pub type StoreResult<T> = Result<T, AggregateStoreError>;

//------------ Storable ------------------------------------------------------

pub trait Storable: Clone + Serialize + DeserializeOwned + Sized + 'static {}
impl<T: Clone + Serialize + DeserializeOwned + Sized + 'static> Storable for T {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredValueInfo {
    pub snapshot_version: u64,
    pub last_event: u64,
    pub last_command: u64,
    pub last_update: Time,
}

impl Default for StoredValueInfo {
    fn default() -> Self {
        StoredValueInfo {
            snapshot_version: 0,
            last_event: 0,
            last_command: 0,
            last_update: Time::now(),
        }
    }
}

//------------ AggregateStore ------------------------------------------------

/// This type is responsible for managing aggregates.
pub struct AggregateStore<A: Aggregate> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<MyHandle, Arc<A>>>,
    history_cache: Mutex<Option<HashMap<MyHandle, Vec<CommandHistoryRecord>>>>,
    pre_save_listeners: Vec<Arc<dyn PreSaveEventListener<A>>>,
    post_save_listeners: Vec<Arc<dyn PostSaveEventListener<A>>>,
    locks: HandleLocks,
}

/// # Starting up
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    /// Creates an AggregateStore using a disk based KeyValueStore
    pub fn create(
        storage_uri: &Url,
        name_space: impl Into<SegmentBuf>,
        disable_history_cache: bool,
    ) -> StoreResult<Self> {
        let kv = KeyValueStore::create(storage_uri, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let history_cache = if disable_history_cache {
            Mutex::new(None)
        } else {
            Mutex::new(Some(HashMap::new()))
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

    /// Warm the cache for a specific aggregate. If successful save the latest snapshot
    /// as well (will help in case of migrations where snapshots were dropped).
    ///
    /// In case any surplus event(s) and/or command(s) are encountered, i.e. extra entries not
    /// recorded in the 'info.json' which is always saved last on state changes - then it is
    /// assumed that an incomplete transaction took place. The surplus entries will be archived
    /// and warnings will be reported.
    pub fn warm_aggregate(&self, handle: &MyHandle) -> StoreResult<()> {
        info!("Warming the cache for: '{}'", handle);

        self.get_latest(handle)
            .map_err(|e| AggregateStoreError::WarmupFailed(handle.clone(), e.to_string()))?;

        Ok(())
    }

    /// Recovers aggregates to the latest consistent saved in the keystore by verifying
    /// all commands, and the corresponding events. Use this in case the state on disk is
    /// found to be inconsistent. I.e. the `warm` function failed and Krill exited.
    ///
    /// Note Krill has an option to *always* use this recover function when it starts,
    /// but the default is that it just uses `warm` function instead. The reason for this
    /// is that `recover` can take longer, and that it could lead silent recovery without
    /// alerting to operators to underlying issues.
    pub fn recover(&self) -> StoreResult<()> {
        todo!("recover and archive corrupted commands")
        // let criteria = CommandHistoryCriteria::default();
        // for handle in self.list()? {
        //     info!("Will recover state for '{}'", &handle);

        //     // Check
        //     // - All commands, archive bad commands
        //     // - All events, archive bad events
        //     // - Keep track of last known good command and event
        //     // - Archive all commands and events after
        //     //
        //     // Rebuild state up to event:
        //     //   - use snapshot - archive if bad
        //     //   - use back-up snapshot if snapshot is no good - archive if bad
        //     //   - start from init event if back-up snapshot is bad, or if the version exceeds last good event
        //     //   - process events from (back-up) snapshot up to last good event
        //     //
        //     //  If still good:
        //     //   - save snapshot
        //     //   - save info

        //     let mut last_good_cmd = 0;
        //     let mut last_good_evt = 0;
        //     let mut last_update = Time::now();

        //     // Check all commands and associated events
        //     let mut all_ok = true;

        //     let command_keys = self.command_keys_ascending(&handle, &criteria)?;
        //     info!("Processing {} commands for {}", command_keys.len(), handle);
        //     for (counter, command_key) in command_keys.into_iter().enumerate() {
        //         if counter % 100 == 0 {
        //             info!("Processed {} commands", counter);
        //         }

        //         if all_ok {
        //             if let Ok(cmd) = self.get_command::<A::StorableCommandDetails>(&handle, &command_key) {
        //                 if let Some(events) = cmd.effect().events() {
        //                     for version in events {
        //                         if let Ok(Some(_)) = self.get_event::<A::Event>(&handle, *version) {
        //                             last_good_evt = *version;
        //                         } else {
        //                             all_ok = false;
        //                         }
        //                     }
        //                 }
        //                 last_good_cmd = cmd.sequence();
        //                 last_update = cmd.time();
        //             } else {
        //                 all_ok = false;
        //             }
        //         }
        //         if !all_ok {
        //             warn!(
        //                 "Command {} was corrupt, or not all events could be loaded. Will archive surplus",
        //                 command_key
        //             );
        //             // Bad command or event encountered.. archive surplus commands
        //             // note that we will clean surplus events later
        //             self.archive_surplus_command(&handle, &command_key)?;
        //         }
        //     }

        //     self.archive_surplus_events(&handle, last_good_evt + 1)?;

        //     if !all_ok {
        //         warn!(
        //             "State for '{}' can only be recovered to version: {}. Check corrupt and surplus dirs",
        //             &handle, last_good_evt
        //         );
        //     }

        //     // Get the latest aggregate, not that this ensures that the snapshots
        //     // are checked, and archived if corrupt, or if they are after the last_good_evt
        //     let agg = self
        //         .get_aggregate(&handle, Some(last_good_evt))?
        //         .ok_or_else(|| AggregateStoreError::CouldNotRecover(handle.clone()))?;

        //     let snapshot_version = agg.version();

        //     let info = StoredValueInfo {
        //         last_event: last_good_evt,
        //         last_command: last_good_cmd,
        //         last_update,
        //         snapshot_version,
        //     };

        //     self.store_snapshot(&handle, &agg)?;

        //     self.cache_update(&handle, Arc::new(agg));

        //     self.save_info(&handle, &info)?;
        // }
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
    pub fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>> {
        let handle = init.handle().clone();

        let agg_lock = self.locks.for_handle(handle.clone());
        let _write_lock = agg_lock.write();

        self.store_event(&init)?;

        let aggregate = A::init(init).map_err(|_| AggregateStoreError::InitError(handle.clone()))?;
        self.store_snapshot(&handle, &aggregate)?;

        let info = StoredValueInfo::default();
        self.save_info(&handle, &info)?;

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
                let processed_command = processed_command_builder.finish_with_error::<A::Event>(&e);
                if let Err(e) = self.store_command(&processed_command) {
                    error!("Cannot save state for '{}'. Got error: {}", handle, e);
                    error!("Will now exit Krill - please verify that the disk can be written to and is not full");
                    std::process::exit(1);
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
                        error!("Cannot save state for '{}'. Got error: {}", handle, e);
                        error!("Will now exit Krill - please verify that the disk can be written to and is not full");
                        std::process::exit(1);
                    }

                    // For now, we also update the snapshot on disk on every change.
                    // See issue #1084
                    self.store_snapshot(&handle, agg)?;

                    // Update the memory cache.
                    let mut cache = self.cache.write().unwrap();
                    cache.insert(handle.clone(), Arc::new(agg.clone()));

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
        let mut cache_lock = self.history_cache.lock().unwrap();

        let records = match cache_lock.as_mut() {
            Some(map) => {
                let records = map.entry(id.clone()).or_default();
                self.update_history_records(records, id)?;
                Cow::Borrowed(records)
            }
            None => {
                let mut records = vec![];
                self.update_history_records(&mut records, id)?;
                Cow::Owned(records)
            }
        };

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

        Ok(CommandHistory::new(offset, total, matching))
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
    pub fn get_command(
        &self,
        id: &MyHandle,
        sequence: u64,
    ) -> Result<StoredCommand<A::StorableCommandDetails, A::Event>, AggregateStoreError> {
        let key = Self::key_for_command(id, sequence);
        match self.kv.get(&key) {
            Ok(Some(cmd)) => Ok(cmd),
            Ok(None) => Err(AggregateStoreError::CommandNotFound(id.clone(), sequence)),
            Err(e) => {
                error!(
                    "Found corrupt command at: {}, will try to archive. Error was: {}",
                    key, e
                );
                self.kv.archive_corrupt(&key)?;
                Err(AggregateStoreError::CommandCorrupt(id.clone(), sequence))
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
    fn key_for_info(agg: &MyHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())),
            segment!("info.json"),
        ) // agg should always be a valid Segment
    }

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

    fn key_for_event(agg: &MyHandle, version: u64) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
            Segment::parse(&format!("delta-{}.json", version)).unwrap(), // cannot panic as a u64 cannot contain a Scope::SEPARATOR
        )
    }

    fn key_for_command(agg: &MyHandle, sequence: u64) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(agg.as_str())), // agg should always be a valid Segment
            Segment::parse(&format!("command-{}.json", sequence)).unwrap(), // cannot panic as a u64 cannot contain a Scope::SEPARATOR
        )
    }

    // fn command_keys_ascending(
    //     &self,
    //     id: &MyHandle,
    //     crit: &CommandHistoryCriteria,
    // ) -> Result<Vec<CommandKey>, AggregateStoreError> {
    //     let mut command_keys = vec![];

    //     for key in self
    //         .kv
    //         .keys(&Scope::from_segment(Segment::parse_lossy(id.as_str())), "command--")?
    //     // id should always be a valid Segment
    //     {
    //         match CommandKey::from_str(key.name().as_str()) {
    //             Ok(command_key) => {
    //                 if command_key.matches_crit(crit) {
    //                     command_keys.push(command_key);
    //                 }
    //             }
    //             Err(_) => {
    //                 warn!("Found strange command-like key in disk key-value store: {}", key.name());
    //             }
    //         }
    //     }

    //     command_keys.sort_by(|a, b| a.sequence.cmp(&b.sequence));

    //     Ok(command_keys)
    // }

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

    /// Clean surplus events
    // fn archive_surplus_events(&self, id: &MyHandle, from: u64) -> Result<(), AggregateStoreError> {
    //     for key in self
    //         .kv
    //         .keys(&Scope::from_segment(Segment::parse_lossy(id.as_str())), "delta-")?
    //     // id should always be a valid Segment
    //     {
    //         let name = key.name().as_str();
    //         if name.starts_with("delta-") {
    //             let start = 6;
    //             if name.len() > start {
    //                 if let Ok(v) = u64::from_str(&name[start..]) {
    //                     if v >= from {
    //                         let key = Self::key_for_event(id, v);
    //                         warn!("Archiving surplus event for '{}': {}", id, key);
    //                         self.kv
    //                             .archive_surplus(&key)
    //                             .map_err(AggregateStoreError::KeyStoreError)?
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    // /// Archive a surplus value for a key
    // fn archive_surplus_command(&self, id: &MyHandle, key: &CommandKey) -> Result<(), AggregateStoreError> {
    //     let key = Self::key_for_command(id, key);
    //     warn!("Archiving surplus command for '{}': {}", id, key);
    //     self.kv
    //         .archive_surplus(&key)
    //         .map_err(AggregateStoreError::KeyStoreError)
    // }

    /// MUST check if the event already exists and return an error if it does.
    fn store_event<V: Event>(&self, event: &V) -> Result<(), AggregateStoreError> {
        let id = event.handle();
        let version = event.version();
        let key = Self::key_for_event(id, version);
        self.kv.store_new(&key, event)?;
        Ok(())
    }

    fn store_command<D: WithStorableDetails, E: Event>(
        &self,
        command: &StoredCommand<D, E>,
    ) -> Result<(), AggregateStoreError> {
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
            let init_key = Self::key_for_event(id, 0);
            aggregate_opt = match self.kv.get::<A::InitEvent>(&init_key)? {
                Some(e) => {
                    trace!("Rebuilding aggregate {} from init event", id);
                    Some(A::init(e).map_err(|_| AggregateStoreError::InitError(id.clone()))?)
                }
                None => None,
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
                if version != command.version() {
                    error!("Trying to apply event to wrong version of aggregate in replay");
                    return Err(AggregateStoreError::ReplayError(id.clone(), version, command.version()));
                }
                aggregate.apply_command(command);
                debug!("Applied event nr {} to aggregate {}", version, id);
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

    // fn get_info(&self, id: &MyHandle) -> Result<StoredValueInfo, AggregateStoreError> {
    //     let key = Self::key_for_info(id);
    //     let info = self
    //         .kv
    //         .get(&key)
    //         .map_err(|_| AggregateStoreError::InfoCorrupt(id.clone()))?;
    //     info.ok_or_else(|| AggregateStoreError::InfoMissing(id.clone()))
    // }

    fn save_info(&self, id: &MyHandle, info: &StoredValueInfo) -> Result<(), AggregateStoreError> {
        let key = Self::key_for_info(id);
        self.kv.store(&key, info).map_err(AggregateStoreError::KeyStoreError)
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
    InfoMissing(MyHandle),
    InfoCorrupt(MyHandle),
    WrongEventForAggregate(MyHandle, MyHandle, u64, u64),
    ConcurrentModification(MyHandle),
    UnknownCommand(MyHandle, u64),
    CommandOffsetTooLarge(u64, u64),
    WarmupFailed(MyHandle, String),
    CouldNotRecover(MyHandle),
    CouldNotArchive(MyHandle, String),
    CommandCorrupt(MyHandle, u64),
    CommandNotFound(MyHandle, u64),
    EventCorrupt(MyHandle, u64),
}

impl fmt::Display for AggregateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AggregateStoreError::IoError(e) => e.fmt(f),
            AggregateStoreError::KeyStoreError(e) => write!(f, "KeyStore Error: {}", e),
            AggregateStoreError::NotInitialized => write!(f, "This aggregate store is not initialized"),
            AggregateStoreError::UnknownAggregate(handle) => write!(f, "unknown entity: {}", handle),
            AggregateStoreError::InitError(handle) => {
                write!(f, "Init event exists for '{}', but cannot be applied", handle)
            }
            AggregateStoreError::ReplayError(handle, version, fail_version) => write!(
                f,
                "Event for '{}' version '{}' had version '{}'",
                handle, version, fail_version
            ),
            AggregateStoreError::InfoMissing(handle) => write!(f, "Missing stored value info for '{}'", handle),
            AggregateStoreError::InfoCorrupt(handle) => write!(f, "Corrupt stored value info for '{}'", handle),
            AggregateStoreError::WrongEventForAggregate(expected, found, expected_v, found_v) => {
                write!(
                    f,
                    "event not applicable to entity. Expected: {} {}, found: {} {}",
                    expected, expected_v, found, found_v
                )
            }
            AggregateStoreError::ConcurrentModification(handle) => {
                write!(f, "concurrent modification attempt for entity: '{}'", handle)
            }
            AggregateStoreError::UnknownCommand(handle, seq) => write!(
                f,
                "Aggregate '{}' does not have command with sequence '{}'",
                handle, seq
            ),
            AggregateStoreError::CommandOffsetTooLarge(offset, total) => {
                write!(f, "Offset '{}' exceeds total '{}'", offset, total)
            }
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
            AggregateStoreError::EventCorrupt(handle, version) => {
                write!(f, "Stored event '{}' for '{}' was corrupt", handle, version)
            }
        }
    }
}

impl From<KeyValueError> for AggregateStoreError {
    fn from(e: KeyValueError) -> Self {
        AggregateStoreError::KeyStoreError(e)
    }
}
