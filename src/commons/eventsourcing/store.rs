use std::any::Any;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fmt, fs};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;

use rpki::x509::Time;

use crate::commons::api::{CommandHistory, CommandHistoryCriteria, CommandHistoryRecord, Handle, Label};
use crate::commons::eventsourcing::{Aggregate, Event, StoredCommand, WithStorableDetails};
use crate::commons::util::file;

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
    sequence: u64,
    timestamp_secs: i64,
    label: Label,
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

//------------ KeyStore ------------------------------------------------------

/// Generic KeyStore for AggregateManager
pub trait KeyStore {
    type Key: From<CommandKey> + From<&'static CommandKey> + TryInto<CommandKey>;

    fn get_version(&self) -> Result<KeyStoreVersion, KeyStoreError>;
    fn set_version(&self, version: &KeyStoreVersion) -> Result<(), KeyStoreError>;

    fn key_for_info() -> Self::Key;
    fn key_for_snapshot() -> Self::Key;
    fn key_for_event(version: u64) -> Self::Key;
    fn key_for_command<S: WithStorableDetails>(command: &StoredCommand<S>) -> CommandKey;

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
        let info = self.get(id, &key)?;
        Ok(info.unwrap_or_else(StoredValueInfo::default))
    }

    fn save_info(&self, id: &Handle, info: &StoredValueInfo) -> Result<(), KeyStoreError> {
        let key = Self::key_for_info();
        self.store(id, &key, info)
    }

    /// Write or overwrite the value for an existing. Must not
    /// throw an error if the key already exists.
    fn store<V: Any + Serialize>(&self, id: &Handle, key: &Self::Key, value: &V) -> Result<(), KeyStoreError>;

    /// Get the value for this key, if any exists.
    fn get<V: Any + Storable>(&self, id: &Handle, key: &Self::Key) -> Result<Option<V>, KeyStoreError>;

    /// Drop the value for this key
    fn drop(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError>;

    /// Get the value for this key, if any exists.
    fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, KeyStoreError>;

    /// MUST check if the event already exists and return an error if it does.
    fn store_event<V: Event>(&self, event: &V) -> Result<(), KeyStoreError>;

    fn store_command<S: WithStorableDetails>(&self, command: StoredCommand<S>) -> Result<(), KeyStoreError>;

    /// Get the latest aggregate
    fn get_aggregate<V: Aggregate>(&self, id: &Handle) -> Result<Option<V>, KeyStoreError>;

    /// Saves the latest snapshot - overwrites any previous snapshot.
    fn store_snapshot<V: Aggregate>(&self, id: &Handle, aggregate: &V) -> Result<(), KeyStoreError>;

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

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "No history for aggregate with key '{}'", _0)]
    NoHistory(Handle),

    #[display(fmt = "This keystore is not initialised")]
    NotInitialised,

    #[display(fmt = "StoredCommand cannot be found")]
    CommandNotFound,

    #[display(fmt = "StoredCommand offset out of bounds")]
    CommandOffSetError,
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

//------------ DiskKeyStore --------------------------------------------------

/// This type can store and retrieve values to/from disk, using json
/// serialization.
pub struct DiskKeyStore {
    dir: PathBuf,
}

impl KeyStore for DiskKeyStore {
    type Key = PathBuf;

    fn get_version(&self) -> Result<KeyStoreVersion, KeyStoreError> {
        if !self.dir.exists() {
            Err(KeyStoreError::NotInitialised)
        } else {
            let path = self.version_path();
            if path.exists() {
                let f = File::open(path)?;

                match serde_json::from_reader(f) {
                    Err(e) => {
                        error!("Could not read current version of keystore");
                        Err(KeyStoreError::JsonError(e))
                    }
                    Ok(v) => Ok(v),
                }
            } else {
                Ok(KeyStoreVersion::Pre0_6)
            }
        }
    }

    fn set_version(&self, version: &KeyStoreVersion) -> Result<(), KeyStoreError> {
        let path = self.version_path();
        let mut f = file::create_file_with_path(&path)?;
        let json = serde_json::to_string_pretty(version)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn key_for_info() -> Self::Key {
        PathBuf::from("info.json")
    }

    fn key_for_snapshot() -> Self::Key {
        PathBuf::from("snapshot.json")
    }

    fn key_for_event(version: u64) -> Self::Key {
        PathBuf::from(format!("delta-{}.json", version))
    }

    fn key_for_command<S: WithStorableDetails>(command: &StoredCommand<S>) -> CommandKey {
        CommandKey::new(command.sequence(), command.time(), command.details().summary().label)
    }

    fn keys(&self, id: &Handle, matching: &str) -> Vec<Self::Key> {
        let mut res = vec![];
        let dir = self.dir_for_aggregate(id);
        if let Ok(entry_results) = fs::read_dir(dir) {
            for entry_result in entry_results {
                if let Ok(dir_entry) = entry_result {
                    let file_name = dir_entry.file_name();
                    if file_name.to_string_lossy().contains(matching) {
                        res.push(PathBuf::from(file_name));
                    }
                }
            }
        }

        res
    }

    fn keys_ascending(&self, id: &Handle, matching: &str) -> Vec<Self::Key> {
        let mut res = self.keys(id, matching);
        res.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        res
    }

    fn command_keys_ascending(&self, id: &Handle, crit: &CommandHistoryCriteria) -> Vec<CommandKey> {
        let mut command_keys = vec![];

        for key in self.keys(id, "command--") {
            if let Ok(command_key) = CommandKey::try_from(key) {
                if command_key.matches_crit(crit) {
                    command_keys.push(command_key);
                }
            }
        }

        command_keys.sort_by(|a, b| a.sequence.cmp(&b.sequence));
        command_keys
    }

    fn has_key(&self, id: &Handle, key: &Self::Key) -> bool {
        self.file_path(id, key).exists()
    }

    fn has_aggregate(&self, id: &Handle) -> bool {
        self.dir_for_aggregate(id).exists()
    }

    fn aggregates(&self) -> Vec<Handle> {
        let mut res: Vec<Handle> = Vec::new();

        if let Ok(dir) = fs::read_dir(&self.dir) {
            for d in dir {
                if let Ok(d) = d {
                    let path = d.path();
                    if path.is_dir() {
                        if let Ok(id) = Handle::try_from(&path) {
                            res.push(id);
                        }
                    }
                }
            }
        }

        res
    }

    fn store<V: Any + Serialize>(&self, id: &Handle, key: &Self::Key, value: &V) -> Result<(), KeyStoreError> {
        let mut f = file::create_file_with_path(&self.file_path(id, key))?;
        let json = serde_json::to_string_pretty(value)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn get<V: Any + Storable>(&self, id: &Handle, key: &Self::Key) -> Result<Option<V>, KeyStoreError> {
        let path = self.file_path(id, key);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            match serde_json::from_reader(f) {
                Err(e) => {
                    warn!("Ignoring file '{}', could not deserialize json: '{}'.", path_str, e);
                    Ok(None)
                }
                Ok(v) => {
                    trace!("Deserialized json at: {}", path_str);
                    Ok(Some(v))
                }
            }
        } else {
            trace!("Could not find file at: {}", path_str);
            Ok(None)
        }
    }

    fn drop(&self, id: &Handle, key: &Self::Key) -> Result<(), KeyStoreError> {
        let path = self.file_path(id, key);
        if !path.exists() {
            Err(KeyStoreError::KeyUnknown(key.to_string_lossy().to_string()))
        } else {
            fs::remove_file(path)?;
            Ok(())
        }
    }

    /// Get the value for this key, if any exists.
    fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, KeyStoreError> {
        let path = self.path_for_event(id, version);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            match serde_json::from_reader(f) {
                Err(e) => {
                    error!("Could not deserialize json at: {}, error: {}", path_str, e);
                    Err(KeyStoreError::JsonError(e))
                }
                Ok(v) => {
                    trace!("Deserialized event at: {}", path_str);
                    Ok(Some(v))
                }
            }
        } else {
            trace!("No more events at: {}", path_str);
            Ok(None)
        }
    }

    fn store_event<V: Event>(&self, event: &V) -> Result<(), KeyStoreError> {
        trace!("Storing event: {}", event);

        let id = event.handle();
        let key = Self::key_for_event(event.version());
        if self.has_key(id, &key) {
            Err(KeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            self.store(id, &key, event)
        }
    }

    fn store_command<S: WithStorableDetails>(&self, command: StoredCommand<S>) -> Result<(), KeyStoreError> {
        let id = command.handle();

        let key = Self::key_for_command(&command).into();

        if self.has_key(id, &key) {
            Err(KeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            self.store(id, &key, &command)
        }
    }

    fn get_aggregate<V: Aggregate>(&self, id: &Handle) -> Result<Option<V>, KeyStoreError> {
        // try to get a snapshot.
        // If that fails, try to get the init event.
        // Then replay all newer events that can be found.
        let key = Self::key_for_snapshot();
        let aggregate_opt = match self.get::<V>(id, &key)? {
            Some(aggregate) => Some(aggregate),
            None => match self.get_event::<V::InitEvent>(id, 0)? {
                Some(e) => Some(V::init(e).map_err(|_| KeyStoreError::InitError)?),
                None => None,
            },
        };

        match aggregate_opt {
            None => Ok(None),
            Some(mut aggregate) => {
                self.update_aggregate(id, &mut aggregate)?;
                Ok(Some(aggregate))
            }
        }
    }

    fn store_snapshot<V: Aggregate>(&self, id: &Handle, aggregate: &V) -> Result<(), KeyStoreError> {
        let key = Self::key_for_snapshot();
        self.store(id, &key, aggregate)
    }
}

impl DiskKeyStore {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Self {
        let mut dir = work_dir.clone();
        dir.push(name_space);
        DiskKeyStore { dir }
    }

    /// Creates a directory for the name_space under the work_dir.
    pub fn under_work_dir(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let mut path = work_dir.clone();
        path.push(name_space);
        if !path.is_dir() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self::new(work_dir, name_space))
    }

    fn version_path(&self) -> PathBuf {
        let mut path = self.dir.clone();
        path.push("version");
        path
    }

    fn file_path(&self, id: &Handle, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(key);
        file_path
    }

    fn dir_for_aggregate(&self, id: &Handle) -> PathBuf {
        let mut dir_path = self.dir.clone();
        dir_path.push(id.to_path_buf());
        dir_path
    }

    fn path_for_event(&self, id: &Handle, version: u64) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(format!("delta-{}.json", version));
        file_path
    }

    pub fn update_aggregate<A: Aggregate>(&self, id: &Handle, aggregate: &mut A) -> Result<(), KeyStoreError> {
        while let Some(e) = self.get_event(id, aggregate.version())? {
            aggregate.apply(e);
        }
        Ok(())
    }
}
