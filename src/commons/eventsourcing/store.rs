use std::fmt;
use std::{collections::HashMap, path::Path};

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use rpki::x509::Time;

use crate::commons::eventsourcing::cmd::{Command, StoredCommandBuilder};
use crate::commons::eventsourcing::{
    Aggregate, Event, KeyStoreKey, KeyValueError, KeyValueStore, PostSaveEventListener, StoredCommand,
    WithStorableDetails,
};
use crate::commons::{
    api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord, Handle, Label},
    error::KrillIoError,
};

use super::PreSaveEventListener;

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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
// Do NOT EVER change the order.. this is used to check whether migrations are needed
#[allow(non_camel_case_types)]
pub enum KeyStoreVersion {
    Pre0_6,
    V0_6,
    V0_7,
    V0_8_0_RC1,
    V0_8,
    V0_8_1_RC1,
    V0_8_1,
    V0_8_2,
    V0_9_0_RC1,
}

impl KeyStoreVersion {
    pub fn current() -> Self {
        KeyStoreVersion::V0_9_0_RC1
    }
}

//------------ CommandKey ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandKey {
    pub sequence: u64,
    pub timestamp_secs: i64,
    pub label: Label,
}

impl CommandKey {
    pub fn new(sequence: u64, time: Time, label: Label) -> Self {
        CommandKey {
            sequence,
            timestamp_secs: time.timestamp(),
            label,
        }
    }

    pub fn for_stored<S: WithStorableDetails>(command: &StoredCommand<S>) -> CommandKey {
        CommandKey::new(command.sequence(), command.time(), command.details().summary().label)
    }

    pub fn matches_crit(&self, crit: &CommandHistoryCriteria) -> bool {
        crit.matches_timestamp_secs(self.timestamp_secs)
            && crit.matches_label(&self.label)
            && crit.matches_sequence(self.sequence)
    }
}

impl fmt::Display for CommandKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "command--{}--{}--{}", self.timestamp_secs, self.sequence, self.label)
    }
}

impl FromStr for CommandKey {
    type Err = CommandKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("--").collect();
        if parts.len() != 4 || parts[0] != "command" {
            Err(CommandKeyError(s.to_string()))
        } else {
            let timestamp_secs = i64::from_str(&parts[1]).map_err(|_| CommandKeyError(s.to_string()))?;
            let sequence = u64::from_str(&parts[2]).map_err(|_| CommandKeyError(s.to_string()))?;
            // strip .json if present on the label part
            let label = {
                let end = parts[3].to_string();
                let last = if end.ends_with(".json") {
                    end.len() - 5
                } else {
                    end.len()
                };
                (end[0..last]).to_string()
            };

            Ok(CommandKey {
                sequence,
                timestamp_secs,
                label,
            })
        }
    }
}

//------------ CommandKeyError -----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandKeyError(String);

impl fmt::Display for CommandKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid command key: {}", self.0)
    }
}

//------------ AggregateStore ------------------------------------------------

/// This type is responsible for managing aggregates.
pub struct AggregateStore<A: Aggregate> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<Handle, Arc<A>>>,
    pre_save_listeners: Vec<Arc<dyn PreSaveEventListener<A>>>,
    post_save_listeners: Vec<Arc<dyn PostSaveEventListener<A>>>,
    outer_lock: RwLock<()>,
}

/// # Starting up
///
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    /// Creates an AggregateStore using a disk based KeyValueStore
    pub fn disk(work_dir: &Path, name_space: &str) -> StoreResult<Self> {
        let mut path = work_dir.to_path_buf();
        path.push(name_space);
        let existed = path.exists();

        let kv = KeyValueStore::disk(work_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let pre_save_listeners = vec![];
        let post_save_listeners = vec![];
        let outer_lock = RwLock::new(());

        let store = AggregateStore {
            kv,
            cache,
            pre_save_listeners,
            post_save_listeners,
            outer_lock,
        };

        if !existed {
            store.set_version(&KeyStoreVersion::current())?;
        }

        Ok(store)
    }

    /// Warms up the cache, to be used after startup. Will fail if any aggregates fail to load
    /// in which case a 'recover' operation can be tried.
    ///
    /// In case any surplus event(s) and/or command(s) are encountered, i.e. extra entries not
    /// recorded in the 'info.json' which is always saved last on state changes - then it is
    /// assumed that an incomplete transaction took place. The surplus entries will be archived
    /// and warnings will be reported.
    pub fn warm(&self) -> StoreResult<()> {
        for handle in self.list()? {
            let _ = self
                .get_latest(&handle)
                .map_err(|e| AggregateStoreError::WarmupFailed(handle.clone(), e.to_string()))?;

            // check that last command and event are consistent with
            // the info, if not fail warmup and force recover
            let info = self.get_info(&handle)?;

            // for events we can just check if the next event, after
            // the last event in the info exists
            if self.get_event::<A::Event>(&handle, info.last_event + 1)?.is_some() {
                warn!(
                    "Found surplus event(s) for '{}' when warming up the cache. Will archive!",
                    handle
                );
                self.archive_surplus_events(&handle, info.last_event + 1)?;
            }

            // Check if there are any commands with a sequence after the last
            // recorded sequence in the info.
            let mut crit = CommandHistoryCriteria::default();
            crit.set_after_sequence(info.last_command);
            let surplus_commands = self.command_keys_ascending(&handle, &crit)?;
            if !surplus_commands.is_empty() {
                warn!(
                    "Found surplus command(s) for '{}' when warming up the cache. Will archive!",
                    handle
                );

                for command in surplus_commands {
                    self.archive_surplus_command(&handle, &command)?;
                }
            }
        }
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
        let criteria = CommandHistoryCriteria::default();
        for handle in self.list()? {
            info!("Will recover state for '{}'", &handle);

            // Check
            // - All commands, archive bad commands
            // - All events, archive bad events
            // - Keep track of last known good command and event
            // - Archive all commands and events after
            //
            // Rebuild state up to event:
            //   - use snapshot - archive if bad
            //   - use back-up snapshot if snapshot is no good - archive if bad
            //   - start from init event if back-up snapshot is bad, or if the version exceeds last good event
            //   - process events from (back-up) snapshot up to last good event
            //
            //  If still good:
            //   - save snapshot
            //   - save info

            let mut last_good_cmd = 0;
            let mut last_good_evt = 0;
            let mut last_update = Time::now();

            // Check all commands and associated events
            let mut all_ok = true;

            let command_keys = self.command_keys_ascending(&handle, &criteria)?;
            info!("Processing {} commands for {}", command_keys.len(), handle);
            for (counter, command_key) in command_keys.into_iter().enumerate() {
                if counter % 100 == 0 {
                    info!("Processed {} commands", counter);
                }

                if all_ok {
                    if let Ok(cmd) = self.get_command::<A::StorableCommandDetails>(&handle, &command_key) {
                        if let Some(events) = cmd.effect().events() {
                            for version in events {
                                if let Ok(Some(_)) = self.get_event::<A::Event>(&handle, *version) {
                                    last_good_evt = *version;
                                } else {
                                    all_ok = false;
                                }
                            }
                        }
                        last_good_cmd = cmd.sequence();
                        last_update = cmd.time();
                    } else {
                        all_ok = false;
                    }
                }
                if !all_ok {
                    warn!(
                        "Command {} was corrupt, or not all events could be loaded. Will archive surplus",
                        command_key
                    );
                    // Bad command or event encountered.. archive surplus commands
                    // note that we will clean surplus events later
                    self.archive_surplus_command(&handle, &command_key)?;
                }
            }

            self.archive_surplus_events(&handle, last_good_evt + 1)?;

            if !all_ok {
                warn!(
                    "State for '{}' can only be recovered to version: {}. Check corrupt and surplus dirs",
                    &handle, last_good_evt
                );
            }

            // Get the latest aggregate, not that this ensures that the snapshots
            // are checked, and archived if corrupt, or if they are after the last_good_evt
            let agg = self
                .get_aggregate(&handle, Some(last_good_evt))?
                .ok_or_else(|| AggregateStoreError::CouldNotRecover(handle.clone()))?;

            let snapshot_version = agg.version();

            let info = StoredValueInfo {
                last_event: last_good_evt,
                last_command: last_good_cmd,
                last_update,
                snapshot_version,
            };

            self.store_snapshot(&handle, &agg)?;

            self.cache_update(&handle, Arc::new(agg));

            self.save_info(&handle, &info)?;
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
    pub fn get_latest(&self, handle: &Handle) -> StoreResult<Arc<A>> {
        let _lock = self.outer_lock.read().unwrap();
        self.get_latest_no_lock(handle)
    }

    /// Adds a new aggregate instance based on the init event.
    pub fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>> {
        let _lock = self.outer_lock.write().unwrap();

        self.store_event(&init)?;

        let handle = init.handle().clone();

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

        let _lock = self.outer_lock.write().unwrap();

        // Get the latest arc.
        let handle = cmd.handle().clone();

        let mut info = self.get_info(&handle)?;
        info.last_update = Time::now();
        info.last_command += 1;

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

        let stored_command_builder = StoredCommandBuilder::new(&cmd, latest.version(), info.last_command);

        let res = match latest.process_command(cmd) {
            Err(e) => {
                let stored_command = stored_command_builder.finish_with_error(&e);
                self.store_command(stored_command)?;
                Err(e)
            }
            Ok(events) => {
                if events.is_empty() {
                    return Ok(latest); // otherwise the version info will be updated
                } else {
                    let agg = Arc::make_mut(&mut latest);

                    // Using a lock on the hashmap here to ensure that all updates happen sequentially.
                    // It would be better to get a lock only for this specific aggregate. So it may be
                    // worth rethinking the structure.
                    //
                    // That said.. saving and applying events is really quick, so this should not hurt
                    // performance much.
                    //
                    // Also note that we don't need the lock to update the inner arc in the cache. We
                    // just need it to be in scope until we are done updating.
                    let mut cache = self.cache.write().unwrap();

                    // It should be impossible to get events for the wrong aggregate, and the wrong
                    // versions, because we are doing the update here inside the outer lock, and aggregates
                    // generally do not lie about who do they are.
                    //
                    // Still.. some defensive coding in case we do have some issue. Double check that the
                    // events are for this aggregate, and are a contiguous sequence of version starting with
                    // this version.
                    let version_before = agg.version();
                    let nr_events = events.len() as u64;

                    // Event numbers apply to the current version of an aggregate, so the first event
                    // here applies to the current version (before applying) and the 2nd to +1 and so
                    // on.
                    info.last_event = version_before + nr_events - 1;

                    for i in 0..nr_events {
                        let event = &events[i as usize];
                        let expected_version = version_before + i;
                        if event.version() != expected_version || event.handle() != &handle {
                            error!("Unexpected event: {}", event);
                            return Err(A::Error::from(AggregateStoreError::WrongEventForAggregate(
                                handle,
                                event.handle().clone(),
                                expected_version,
                                event.version(),
                            )));
                        }
                    }

                    // Time to start saving things.
                    let stored_command = stored_command_builder.finish_with_events(events.as_slice());

                    // If persistence fails, then complain loudly, and exit. Krill should not keep running, because this would
                    // result in discrepancies between state in memory and state on disk. Let Krill crash and an operator investigate.
                    // See issue: https://github.com/NLnetLabs/krill/issues/322
                    if let Err(e) = self.store_command(stored_command) {
                        error!("Cannot save state for '{}'. Got error: {}", handle, e);
                        error!("Will now exit Krill - please verify that the disk can be written to and is not full");
                        std::process::exit(1);
                    }

                    // Apply events, check that the aggregate can be updated, and make sure
                    // we have an updated version so we can store it.
                    for event in &events {
                        agg.apply(event.clone());
                    }

                    // Apply events to pre save listeners which may still return errors
                    for pre_save_listener in &self.pre_save_listeners {
                        pre_save_listener.as_ref().listen(agg, events.as_slice())?;
                    }

                    // Nothing broke, so it's safe to store the command, events and aggregate
                    for event in &events {
                        self.store_event(event)?;
                    }
                    info.snapshot_version = agg.version();
                    self.store_snapshot(&handle, agg)?;

                    cache.insert(handle.clone(), Arc::new(agg.clone()));

                    // Now send the events to the 'post-save' listeners.
                    for listener in &self.post_save_listeners {
                        listener.as_ref().listen(agg, events.as_slice());
                    }

                    Ok(latest)
                }
            }
        };

        self.save_info(&handle, &info)?;

        res
    }

    /// Returns true if an instance exists for the id
    pub fn has(&self, id: &Handle) -> Result<bool, AggregateStoreError> {
        let _lock = self.outer_lock.read().unwrap();
        self.kv
            .has_scope(id.to_string())
            .map_err(AggregateStoreError::KeyStoreError)
    }

    /// Lists all known ids.
    pub fn list(&self) -> Result<Vec<Handle>, AggregateStoreError> {
        let _lock = self.outer_lock.read().unwrap();
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
        id: &Handle,
        crit: CommandHistoryCriteria,
    ) -> Result<CommandHistory, AggregateStoreError> {
        let offset = crit.offset();

        let command_keys = self.command_keys_ascending(id, &crit)?;

        let rows = match crit.rows_limit() {
            Some(limit) => limit,
            None => command_keys.len(),
        };

        let mut commands: Vec<CommandHistoryRecord> = Vec::with_capacity(rows);
        let mut skipped = 0;
        let mut total = 0;

        for command_key in command_keys {
            total += 1;
            if skipped < offset {
                skipped += 1;
            } else if commands.len() < rows {
                let key = Self::key_for_command(id, &command_key);
                let stored: StoredCommand<A::StorableCommandDetails> = self
                    .kv
                    .get(&key)?
                    .ok_or_else(|| AggregateStoreError::CommandNotFound(id.clone(), command_key))?;

                let stored = stored.into();
                commands.push(stored);
            }
        }
        Ok(CommandHistory::new(offset, total, commands))
    }

    /// Get the command for this key, if it exists
    pub fn get_command<D: WithStorableDetails>(
        &self,
        id: &Handle,
        command_key: &CommandKey,
    ) -> Result<StoredCommand<D>, AggregateStoreError> {
        let key = Self::key_for_command(id, command_key);
        match self.kv.get(&key) {
            Ok(Some(cmd)) => Ok(cmd),
            Ok(None) => Err(AggregateStoreError::CommandNotFound(id.clone(), command_key.clone())),
            Err(e) => {
                error!(
                    "Found corrupt command at: {}, will try to archive. Error was: {}",
                    key, e
                );
                self.kv.archive_corrupt(&key)?;
                Err(AggregateStoreError::CommandCorrupt(id.clone(), command_key.clone()))
            }
        }
    }

    /// Get the value for this key, if any exists.
    pub fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, AggregateStoreError> {
        let key = Self::key_for_event(id, version);
        match self.kv.get(&key) {
            Ok(res_opt) => Ok(res_opt),
            Err(e) => {
                error!(
                    "Found corrupt event for {}, version {}, archiving. Error: {}",
                    id, version, e
                );
                self.kv.archive_corrupt(&key)?;
                Err(AggregateStoreError::EventCorrupt(id.clone(), version))
            }
        }
    }
}

impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
    fn has_updates(&self, id: &Handle, aggregate: &A) -> StoreResult<bool> {
        Ok(self.get_event::<A::Event>(id, aggregate.version())?.is_some())
    }

    fn cache_get(&self, id: &Handle) -> Option<Arc<A>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    fn cache_remove(&self, id: &Handle) {
        self.cache.write().unwrap().remove(id);
    }

    fn cache_update(&self, id: &Handle, arc: Arc<A>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }

    fn get_latest_no_lock(&self, handle: &Handle) -> StoreResult<Arc<A>> {
        trace!("Trying to load aggregate id: {}", handle);

        let info_key = Self::key_for_info(handle);
        let limit = self
            .kv
            .get::<StoredValueInfo>(&info_key)
            .map_err(|_| AggregateStoreError::InfoCorrupt(handle.clone()))?
            .map(|info| info.last_event);

        match self.cache_get(handle) {
            None => match self.get_aggregate(handle, limit)? {
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
                if self.has_updates(handle, &arc)? {
                    let agg = Arc::make_mut(&mut arc);
                    self.update_aggregate(handle, agg, limit)?;
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
    fn key_version() -> KeyStoreKey {
        KeyStoreKey::simple("version".to_string())
    }

    fn key_for_info(agg: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), "info.json".to_string())
    }

    fn key_for_snapshot(agg: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), "snapshot.json".to_string())
    }

    fn key_for_backup_snapshot(agg: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), "snapshot-bk.json".to_string())
    }

    fn key_for_new_snapshot(agg: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), "snapshot-new.json".to_string())
    }

    fn key_for_event(agg: &Handle, version: u64) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), format!("delta-{}.json", version))
    }

    fn key_for_command(agg: &Handle, command: &CommandKey) -> KeyStoreKey {
        KeyStoreKey::scoped(agg.to_string(), format!("{}.json", command))
    }

    pub fn get_version(&self) -> Result<KeyStoreVersion, AggregateStoreError> {
        match self.kv.get::<KeyStoreVersion>(&Self::key_version())? {
            Some(version) => Ok(version),
            None => Ok(KeyStoreVersion::Pre0_6),
        }
    }

    pub fn set_version(&self, version: &KeyStoreVersion) -> Result<(), AggregateStoreError> {
        self.kv.store(&Self::key_version(), version)?;
        Ok(())
    }

    fn command_keys_ascending(
        &self,
        id: &Handle,
        crit: &CommandHistoryCriteria,
    ) -> Result<Vec<CommandKey>, AggregateStoreError> {
        let mut command_keys = vec![];

        for key in self.kv.keys(Some(id.to_string()), "command--")? {
            match CommandKey::from_str(key.name()) {
                Ok(command_key) => {
                    if command_key.matches_crit(crit) {
                        command_keys.push(command_key);
                    }
                }
                Err(_) => {
                    warn!("Found strange command-like key in disk key-value store: {}", key.name());
                }
            }
        }

        command_keys.sort_by(|a, b| a.sequence.cmp(&b.sequence));

        Ok(command_keys)
    }

    /// Private, should be called through `list` which takes care of locking.
    fn aggregates(&self) -> Result<Vec<Handle>, AggregateStoreError> {
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = Handle::from_str(&scope) {
                res.push(handle)
            }
        }

        Ok(res)
    }

    /// Clean surplus events
    fn archive_surplus_events(&self, id: &Handle, from: u64) -> Result<(), AggregateStoreError> {
        for key in self.kv.keys(Some(id.to_string()), "delta-")? {
            let name = key.name();
            if name.starts_with("delta-") && name.ends_with(".json") {
                let start = 6;
                let end = name.len() - 5;
                if end > start {
                    if let Ok(v) = u64::from_str(&name[start..end]) {
                        if v >= from {
                            let key = Self::key_for_event(id, v);
                            warn!("Archiving surplus event for '{}': {}", id, key);
                            self.kv
                                .archive_surplus(&key)
                                .map_err(AggregateStoreError::KeyStoreError)?
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Archive a surplus value for a key
    fn archive_surplus_command(&self, id: &Handle, key: &CommandKey) -> Result<(), AggregateStoreError> {
        let key = Self::key_for_command(id, key);
        warn!("Archiving surplus command for '{}': {}", id, key);
        self.kv
            .archive_surplus(&key)
            .map_err(AggregateStoreError::KeyStoreError)
    }

    /// MUST check if the event already exists and return an error if it does.
    fn store_event<V: Event>(&self, event: &V) -> Result<(), AggregateStoreError> {
        let id = event.handle();
        let version = event.version();
        let key = Self::key_for_event(id, version);
        self.kv.store_new(&key, event)?;
        Ok(())
    }

    fn store_command<S: WithStorableDetails>(&self, command: StoredCommand<S>) -> Result<(), AggregateStoreError> {
        let id = command.handle();

        let command_key = CommandKey::for_stored(&command);
        let key = Self::key_for_command(id, &command_key);

        self.kv.store_new(&key, &command)?;
        Ok(())
    }

    /// Get the latest aggregate
    /// limit to the event nr, i.e. the resulting aggregate version will be limit + 1
    fn get_aggregate(&self, id: &Handle, limit: Option<u64>) -> Result<Option<A>, AggregateStoreError> {
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
                        trace!("Discarding snapshot after limit '{}'", id);
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
            warn!("No snapshot found for '{}' will try backup snapshot", id);
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
                            trace!("Discarding backup snapshot after limit '{}'", id);
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
            warn!("No snapshots found for '{}' will try from initialization event.", id);
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

    fn update_aggregate(&self, id: &Handle, aggregate: &mut A, limit: Option<u64>) -> Result<(), AggregateStoreError> {
        let start = aggregate.version();
        let limit = if let Some(limit) = limit {
            debug!("Will attempt to update '{}' using explicit limit", id);
            limit
        } else if let Ok(info) = self.get_info(id) {
            debug!("Will attempt to update '{}' using limit from info", id);
            info.last_event
        } else {
            let nr_events = self.kv.keys(Some(id.to_string()), "delta-")?.len();
            if nr_events < 1 {
                return Err(AggregateStoreError::InfoMissing(id.clone()));
            } else {
                let limit = (nr_events - 1) as u64;
                debug!("Will attempt to update '{}' from limit based on nr of events", id,);
                limit
            }
        };

        if limit == aggregate.version() - 1 {
            // already at version, done
            // note that an event has the version of the aggregate it *affects*. So delta 10 results in version 11.
            debug!("Snapshot for '{}' is up to date", id);
            return Ok(());
        }

        debug!(
            "Will attempt to update '{}' from version: {} to: {}",
            id,
            start,
            limit + 1
        );

        if start > limit {
            return Err(AggregateStoreError::ReplayError(id.clone(), limit, start));
        }

        for version in start..limit + 1 {
            if let Some(e) = self.get_event(id, version)? {
                if aggregate.version() != version {
                    error!("Trying to apply event to wrong version of aggregate in replay");
                    return Err(AggregateStoreError::ReplayError(id.clone(), limit, version));
                }
                aggregate.apply(e);
                debug!("Applied event nr {} to aggregate {}", version, id);
            } else {
                return Err(AggregateStoreError::ReplayError(id.clone(), limit, version));
            }
        }

        Ok(())
    }

    /// Saves the latest snapshot - overwrites any previous snapshot.
    fn store_snapshot<V: Aggregate>(&self, id: &Handle, aggregate: &V) -> Result<(), AggregateStoreError> {
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
    pub fn drop_aggregate(&self, id: &Handle) -> Result<(), AggregateStoreError> {
        self.cache_remove(id);
        self.kv.drop_scope(id.as_str())?;
        Ok(())
    }

    fn get_info(&self, id: &Handle) -> Result<StoredValueInfo, AggregateStoreError> {
        let key = Self::key_for_info(id);
        let info = self
            .kv
            .get(&key)
            .map_err(|_| AggregateStoreError::InfoCorrupt(id.clone()))?;
        info.ok_or_else(|| AggregateStoreError::InfoMissing(id.clone()))
    }

    fn save_info(&self, id: &Handle, info: &StoredValueInfo) -> Result<(), AggregateStoreError> {
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
    UnknownAggregate(Handle),
    InitError(Handle),
    ReplayError(Handle, u64, u64),
    InfoMissing(Handle),
    InfoCorrupt(Handle),
    WrongEventForAggregate(Handle, Handle, u64, u64),
    ConcurrentModification(Handle),
    UnknownCommand(Handle, u64),
    CommandOffsetTooLarge(u64, u64),
    WarmupFailed(Handle, String),
    CouldNotRecover(Handle),
    CouldNotArchive(Handle, String),
    CommandCorrupt(Handle, CommandKey),
    CommandNotFound(Handle, CommandKey),
    EventCorrupt(Handle, u64),
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
            AggregateStoreError::ReplayError(handle, target_version, fail_version) => write!(
                f,
                "Cannot reconstruct '{}' to version '{}', failed at version {}",
                handle, target_version, fail_version
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

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn command_key_to_from_str() {
        let key_str = "command--1576389600--87--cmd-ca-publish";
        let key = CommandKey::from_str(key_str).unwrap();
        assert_eq!(key_str, &key.to_string());

        let key_with_dot_json_str = "command--1576389600--87--cmd-ca-publish.json";
        let key_with_dot_json = CommandKey::from_str(key_with_dot_json_str).unwrap();

        assert_eq!(key, key_with_dot_json);
    }
}
