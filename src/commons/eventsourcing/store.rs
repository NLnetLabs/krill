use std::any::Any;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use rpki::x509::Time;

use crate::commons::api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord, Handle, Label};
use crate::commons::eventsourcing::{Aggregate, Event, StoredCommand, WithStorableDetails};

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyStoreVersion {
    Pre0_6,
    V0_6,
    V0_7,
    V0_8,
}

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

    pub fn matches_crit(&self, crit: &CommandHistoryCriteria) -> bool {
        crit.matches_timestamp_secs(self.timestamp_secs) && crit.matches_label(&self.label)
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
            Err(CommandKeyError)
        } else {
            let timestamp_secs = i64::from_str(&parts[1]).map_err(|_| CommandKeyError)?;
            let sequence = u64::from_str(&parts[2]).map_err(|_| CommandKeyError)?;
            let label = parts[3].to_string();
            Ok(CommandKey {
                sequence,
                timestamp_secs,
                label,
            })
        }
    }
}

impl From<CommandKey> for PathBuf {
    fn from(ck: CommandKey) -> Self {
        PathBuf::from(format!("{}.json", ck))
    }
}

impl From<&CommandKey> for PathBuf {
    fn from(ck: &CommandKey) -> Self {
        PathBuf::from(format!("{}.json", ck))
    }
}

impl TryFrom<PathBuf> for CommandKey {
    type Error = CommandKeyError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let s = path.file_name().ok_or_else(|| CommandKeyError)?;
        let s = s.to_string_lossy().to_string();
        let s = s.as_str();
        if !s.ends_with(".json") {
            Err(CommandKeyError)
        } else {
            let s = &s[0..s.len() - 5];
            CommandKey::from_str(s)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandKeyError;

impl fmt::Display for CommandKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid command key")
    }
}

//------------ KeyStore ------------------------------------------------------

/// Generic KeyStore for AggregateManager
pub trait KeyStore {
    type Key: From<CommandKey> + From<&'static CommandKey> + TryInto<CommandKey>;

    fn get_version(&self) -> Result<KeyStoreVersion, KeyStoreError>;
    fn set_version(&self, version: &KeyStoreVersion) -> Result<(), KeyStoreError>;

    fn key_for_info() -> Self::Key;
    fn key_for_snapshot() -> Self::Key;
    fn key_for_backup_snapshot() -> Self::Key;
    fn key_for_new_snapshot() -> Self::Key;
    fn key_for_event(version: u64) -> Self::Key;
    fn key_for_command<S: WithStorableDetails>(command: &StoredCommand<S>) -> CommandKey;
    fn key_for_archived(key: &Self::Key) -> Self::Key;
    fn key_for_corrupt(key: &Self::Key) -> Self::Key;
    fn key_for_surplus(key: &Self::Key) -> Self::Key;

    /// Returns all keys for a Handle in the store, matching a &str
    fn keys(&self, id: &Handle, matching: &str) -> Vec<Self::Key>;

    /// Returns all keys for a Handle in the store, matching a &str, sorted ascending
    fn keys_ascending(&self, id: &Handle, matching: &str) -> Vec<Self::Key>;

    fn command_keys_ascending(&self, id: &Handle, crit: &CommandHistoryCriteria) -> Vec<CommandKey>;

    /// Returns whether a key already exists.
    fn has_key(&self, id: &Handle, key: &Self::Key) -> bool;

    fn has_aggregate(&self, id: &Handle) -> bool;

    fn aggregates(&self) -> Vec<Handle>;

    fn get_info(&self, id: &Handle) -> Result<StoredValueInfo, KeyStoreError> {
        let key = Self::key_for_info();
        let info = self.get(id, &key).map_err(|_| KeyStoreError::InfoCorrupt(id.clone()))?;
        info.ok_or_else(|| KeyStoreError::InfoMissing(id.clone()))
    }

    fn save_info(&self, id: &Handle, info: &StoredValueInfo) -> Result<(), KeyStoreError> {
        let key = Self::key_for_info();
        self.store(id, &key, info)
    }

    /// Write or overwrite the value for an existing. Must not
    /// throw an error if the key already exists.
    fn store<V: Any + Serialize>(&self, id: &Handle, key: &Self::Key, value: &V) -> Result<(), KeyStoreError>;

    /// Get the value for this key, if any exists.
    fn get<V: DeserializeOwned>(&self, id: &Handle, key: &Self::Key) -> Result<Option<V>, KeyStoreError>;

    /// Drop the value for this key
    fn drop(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError>;

    /// Move a value to a new key
    fn move_key(&self, id: &Handle, from: &Self::Key, to: &Self::Key) -> Result<(), KeyStoreError>;

    /// Archive a value for this key
    fn archive(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError> {
        self.move_key(id, key, &Self::key_for_archived(key))?;
        Ok(())
    }

    /// Archive a corrupt value for a key
    fn archive_corrupt(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError> {
        self.move_key(id, key, &Self::key_for_corrupt(key))?;
        Ok(())
    }

    /// Archive a surplus value for a key
    fn archive_surplus(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError> {
        self.move_key(id, key, &Self::key_for_surplus(key))?;
        Ok(())
    }

    /// Get the command for this key, if it exists
    fn get_command<D: WithStorableDetails>(
        &self,
        id: &Handle,
        key: &Self::Key,
    ) -> Result<StoredCommand<D>, KeyStoreError> {
        if self.has_key(id, key) {
            if let Ok(Some(cmd)) = self.get(id, key) {
                Ok(cmd)
            } else {
                error!("Found corrupt command for '{}', archiving", id);
                self.archive_corrupt(id, key)?;
                Err(KeyStoreError::CommandCorrupt)
            }
        } else {
            Err(KeyStoreError::CommandNotFound)
        }
    }

    /// Get the value for this key, if any exists.
    fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, KeyStoreError> {
        let key = Self::key_for_event(version);
        if self.has_key(id, &key) {
            if let Ok(Some(evt)) = self.get(id, &key) {
                trace!("Found event nr '{}' for aggregate '{}'", version, id);
                Ok(Some(evt))
            } else {
                error!("Found corrupt event for {}, version {}, archiving", id, version);
                self.archive_corrupt(id, &key)?;
                Err(KeyStoreError::EventCorrupt)
            }
        } else {
            trace!("Did not find event nr '{}' for aggregate '{}'", version, id);
            Ok(None)
        }
    }

    /// Archive an event
    fn archive_event(&self, id: &Handle, version: u64) -> Result<(), KeyStoreError> {
        let key = Self::key_for_event(version);
        self.archive(id, &key)
    }

    /// Mark an event as corrupt (or surplus)
    fn archive_surplus_event(&self, id: &Handle, version: u64) -> Result<(), KeyStoreError> {
        let key = Self::key_for_event(version);
        self.archive(id, &key)
    }

    /// MUST check if the event already exists and return an error if it does.
    fn store_event<V: Event>(&self, event: &V) -> Result<(), KeyStoreError> {
        trace!("Storing event: {}", event);

        let id = event.handle();
        let version = event.version();
        let key = Self::key_for_event(version);
        if self.has_key(id, &key) {
            Err(KeyStoreError::EventExists(id.clone(), version))
        } else {
            self.store(id, &key, event)
        }
    }

    fn store_command<S: WithStorableDetails>(&self, command: StoredCommand<S>) -> Result<(), KeyStoreError> {
        let id = command.handle();

        let command_key = Self::key_for_command(&command);
        let key = command_key.clone().into();

        if self.has_key(id, &key) {
            Err(KeyStoreError::CommandExists(command_key))
        } else {
            self.store(id, &key, &command)
        }
    }

    /// Get the latest aggregate
    fn get_aggregate<V: Aggregate>(&self, id: &Handle, limit: Option<u64>) -> Result<Option<V>, KeyStoreError> {
        // 1) Try to get a snapshot.
        // 2) If that fails try the backup
        // 3) If that fails, try to get the init event.
        //
        // Then replay all newer events that can be found up to the version (or latest if version is None)
        trace!("Getting aggregate for '{}'", id);

        let mut aggregate_opt: Option<V> = None;

        let snapshot_key = Self::key_for_snapshot();
        if self.has_key(id, &snapshot_key) {
            if let Ok(Some(agg)) = self.get::<V>(id, &snapshot_key) {
                trace!("Found snapshot for '{}'", id);
                if let Some(limit) = limit {
                    if limit >= agg.version() {
                        aggregate_opt = Some(agg)
                    } else {
                        trace!("Discarding snapshot after limit '{}'", id);
                        self.archive_surplus(id, &snapshot_key)?;
                    }
                } else {
                    aggregate_opt = Some(agg)
                }
            } else {
                error!("Could not parse snapshot for '{}', archiving as corrupt", id);
                self.archive_corrupt(id, &snapshot_key)?;
            }
        }

        let backup_snapshot_key = Self::key_for_backup_snapshot();
        if self.has_key(id, &backup_snapshot_key) {
            if let Ok(Some(agg)) = self.get::<V>(id, &backup_snapshot_key) {
                if aggregate_opt.is_none() {
                    trace!("Found backup snapshot for '{}'", id);
                    if let Some(limit) = limit {
                        if limit >= agg.version() {
                            aggregate_opt = Some(agg)
                        } else {
                            trace!("Discarding backup snapshot after limit '{}'", id);
                            self.archive_surplus(id, &backup_snapshot_key)?;
                        }
                    } else {
                        aggregate_opt = Some(agg)
                    }
                }
            } else {
                error!("Could not parse backup snapshot for '{}', archiving as corrupt", id);
                self.archive_corrupt(id, &backup_snapshot_key)?;
            }
        }

        if aggregate_opt.is_none() {
            aggregate_opt = match self.get_event::<V::InitEvent>(id, 0)? {
                Some(e) => {
                    trace!("Rebuilding aggregate {} from init event", id);
                    Some(V::init(e).map_err(|_| KeyStoreError::InitError(id.clone()))?)
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

    fn update_aggregate<A: Aggregate>(
        &self,
        id: &Handle,
        aggregate: &mut A,
        limit: Option<u64>,
    ) -> Result<(), KeyStoreError> {
        let limit = if let Some(limit) = limit {
            limit
        } else if let Ok(info) = self.get_info(id) {
            info.last_event
        } else {
            (self.keys_ascending(id, "delta-").len() - 1) as u64
        };

        if limit == aggregate.version() {
            // already at version, done
            return Ok(());
        }

        let start = aggregate.version();
        if start > limit {
            return Err(KeyStoreError::ReplayError(id.clone(), limit, start));
        }

        for version in start..limit + 1 {
            if let Some(e) = self.get_event(id, aggregate.version())? {
                aggregate.apply(e);
                trace!("Applied event nr {} to aggregate {}", version - 1, id);
            } else {
                return Err(KeyStoreError::ReplayError(id.clone(), limit, version));
            }
        }

        Ok(())
    }

    /// Saves the latest snapshot - overwrites any previous snapshot.
    fn store_snapshot<V: Aggregate>(&self, id: &Handle, aggregate: &V) -> Result<(), KeyStoreError> {
        let snapshot_new = Self::key_for_new_snapshot();
        let snapshot_current = Self::key_for_snapshot();
        let snapshot_backup = Self::key_for_backup_snapshot();

        self.store(id, &snapshot_new, aggregate)?;
        if self.has_key(id, &snapshot_backup) {
            self.drop(id, &snapshot_backup)?;
        }
        if self.has_key(id, &snapshot_current) {
            self.move_key(id, &snapshot_current, &snapshot_backup)?;
        }
        self.move_key(id, &snapshot_new, &snapshot_current)?;

        Ok(())
    }

    /// Find all commands that fit the criteria and return history
    fn command_history<A: Aggregate>(
        &self,
        id: &Handle,
        crit: CommandHistoryCriteria,
    ) -> Result<CommandHistory, KeyStoreError> {
        let offset = crit.offset();
        let rows = crit.rows();

        let mut commands: Vec<CommandHistoryRecord> = Vec::with_capacity(rows);
        let mut skipped = 0;
        let mut total = 0;

        for key in self.command_keys_ascending(id, &crit) {
            total += 1;
            if skipped < offset {
                skipped += 1;
            } else if commands.len() < rows {
                let stored: StoredCommand<A::StorableCommandDetails> = self
                    .get(id, &key.into())?
                    .ok_or_else(|| KeyStoreError::CommandNotFound)?;

                let stored = stored.into();
                commands.push(stored);
            }
        }
        Ok(CommandHistory::new(offset, total, commands))
    }
}

//------------ KeyStoreError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum KeyStoreError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Key '{}' already exists", _0)]
    KeyExists(String),

    #[display(fmt = "Key '{}' does not exist", _0)]
    KeyUnknown(String),

    #[display(fmt = "Cannot apply init event to '{}'", _0)]
    InitError(Handle),

    #[display(fmt = "Cannot reconstruct '{}' to version '{}', failed at version {}", _0, _1, _2)]
    ReplayError(Handle, u64, u64),

    #[display(fmt = "No history for aggregate with key '{}'", _0)]
    NoHistory(Handle),

    #[display(fmt = "This keystore is not initialised")]
    NotInitialised,

    #[display(fmt = "Missing stored value info for '{}'", _0)]
    InfoMissing(Handle),

    #[display(fmt = "Corrupt stored value info for '{}'", _0)]
    InfoCorrupt(Handle),

    #[display(fmt = "StoredCommand cannot be found")]
    CommandNotFound,

    #[display(fmt = "StoredCommand was corrupt")]
    CommandCorrupt,

    #[display(fmt = "Command exists for key: {}", _0)]
    CommandExists(CommandKey),

    #[display(fmt = "StoredCommand offset out of bounds")]
    CommandOffSetError,

    #[display(fmt = "Stored event was corrupt")]
    EventCorrupt,

    #[display(fmt = "Event version {} already recorded for {}", _1, _0)]
    EventExists(Handle, u64),
}

impl From<io::Error> for KeyStoreError {
    fn from(e: io::Error) -> Self {
        KeyStoreError::IoError(e)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(e: serde_json::Error) -> Self {
        KeyStoreError::JsonError(e)
    }
}

impl std::error::Error for KeyStoreError {}
