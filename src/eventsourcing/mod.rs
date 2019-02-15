//! Event sourcing support for Krill

mod es_example; // Example implementation and tests.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use crate::util::file;


//------------ Storable ------------------------------------------------------

pub trait Storable: Clone + Serialize + DeserializeOwned + Sized {}
impl<T: Clone + Serialize + DeserializeOwned + Sized> Storable for T { }


//------------ AggregateId ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AggregateId(String);

impl From<&str> for AggregateId {
    fn from(s: &str) -> Self {
        AggregateId(s.to_string())
    }
}

impl From<String> for AggregateId {
    fn from(s: String) -> Self {
        AggregateId(s)
    }
}

impl AsRef<str> for AggregateId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for AggregateId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ Aggregate -----------------------------------------------------

pub trait Aggregate: Storable {

    type Command: Command<Event = Self::Event>;
    type Event: Event;
    type InitEvent: Event;
    type Error: std::error::Error;

    /// Creates a new instance. Expects an event with data needed to
    /// initialise the instance. Typically this means that a specific
    /// 'create' event is passed, with all the needed data, or just an empty
    /// marker if no data is needed. Implementations must return an error in
    /// case the instance cannot be created.
    fn init(event: Self::InitEvent) -> Result<Self, Self::Error>;

    /// Returns the current version of the aggregate.
    fn version(&self) -> u64;

    /// Moves this, and applies the event to this. This MUST not result in
    /// any errors. Applying the event just updates data and is side-effect
    /// free.
    ///
    /// Note that both self and the event are moved. This is done because we
    /// want to enable moving data into the new aggregate without the need for
    /// additional allocations.
    fn apply(&mut self, event: Self::Event);

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these event here. The command processing must be side-effect free.
    ///
    /// The command is moved, because we want to enable moving its data
    /// without reallocating.
    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error>;
}


//------------ Event --------------------------------------------------------

pub trait Event: Storable {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn id(&self) -> &AggregateId;

    /// The version of the aggregate that this event updates.
    /// In other words, an aggregate that is currently at version x, will get
    /// version x + 1, when the event for version x is applied.
    fn version(&self) -> u64;
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StoredEvent<E: Storable> {
    id: AggregateId,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E
}

impl<E: Storable> StoredEvent<E> {
    pub fn new(id: &AggregateId, version: u64, event: E) -> Self {
        StoredEvent { id: id.clone(), version, details: event }
    }

    pub fn details(&self) -> &E { & self.details }

    pub fn into_details(self) -> E { self.details }

    /// Return the parts of this event.
    pub fn unwrap(self) -> (AggregateId, u64, E) {
        (self.id, self.version, self.details)
    }
}

impl<E: Storable> Event for StoredEvent<E> {
    fn id(&self) -> &AggregateId {
        &self.id
    }

    fn version(&self) -> u64 {
        self.version
    }
}

//------------ Command -------------------------------------------------------

/// Commands are used to send an intent to change an aggregate.
///
/// Think of this as the data container for your update API, plus some
/// meta-data to ensure that the command is sent to the right instance of an
/// Aggregate, and that concurrency issues are handled.
pub trait Command: Storable {
    /// Identify the type of event returned by the aggregate that uses this
    /// command. This is needed because we may need to check whether a
    /// command conflicts with recent events.
    type Event: Event;

    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn id(&self) -> &AggregateId;

    /// The version of the aggregate that this command updates. If this
    /// command should update whatever the latest version happens to be, then
    /// use None here.
    fn version(&self) -> Option<u64>;

    /// In case of concurrent processing of commands, the aggregate may be
    /// outdated when a command is applied. In such cases this method expects
    /// the list of events that happened since the ['affected_version'] and
    /// will return whether there is a conflict. If there is no conflict that
    /// the command may be applied again.
    ///
    /// Note that this defaults to true, which is the safe choice when in
    /// doubt. If you choose to implement this, then you will also need to
    /// implement the ['set_affected_version'] function.
    fn conflicts(&self, _events: &[Self::Event]) -> bool { true }
}


//------------ SentCommand ---------------------------------------------------

/// Convenience wrapper so that implementations can just implement
/// ['CommandDetails'] and leave the id and version boilerplate.
#[derive(Clone, Deserialize, Serialize)]
pub struct SentCommand<C: CommandDetails> {
    id: AggregateId,
    version: Option<u64>,
    #[serde(deserialize_with = "C::deserialize")]
    details: C
}

impl<C: CommandDetails> Command for SentCommand<C> {
    type Event = C::Event;

    fn id(&self) -> &AggregateId {
        &self.id
    }

    fn version(&self) -> Option<u64> {
        self.version
    }
}

impl<C: CommandDetails> SentCommand<C> {
    pub fn new(id: &AggregateId, version: Option<u64>, details: C) -> Self {
        SentCommand { id: id.clone(), version, details }
    }

    pub fn into_details(self) -> C { self.details }
}


//------------ CommandDetails ------------------------------------------------

/// Implement this for an enum with CommandDetails, so you you can reuse the
/// id and version boilerplate from ['SentCommand'].
pub trait CommandDetails: Storable {
    type Event: Event;
}


//------------ KeyStore ------------------------------------------------------

/// Generic KeyStore for AggregateManager
pub trait KeyStore {

    type Key;

    fn key_for_snapshot() -> Self::Key;
    fn key_for_event(version: u64) -> Self::Key;

    /// Returns whether a key already exists.
    fn has_key(&self, id: &AggregateId, key: &Self::Key) -> bool;

    fn has_aggregate(&self, id: &AggregateId) -> bool;

    fn aggregates(&self) -> Vec<AggregateId>; // Use Iterator?

    /// Throws an error if the key already exists.
    fn store<V: Any + Serialize>(
        &self,
        id: &AggregateId,
        key: &Self::Key,
        value: &V
    ) -> Result<(), KeyStoreError>;

    /// Get the value for this key, if any exists.
    fn get<V: Any + Storable>(
        &self,
        id: &AggregateId,
        key: &Self::Key
    ) -> Result<Option<V>, KeyStoreError>;
}


//------------ KeyStoreError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum KeyStoreError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Key already exists: {}", _0)]
    KeyExists(String)
}

impl From<io::Error> for KeyStoreError {
    fn from(e: io::Error) -> Self { KeyStoreError::IoError(e) }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(e: serde_json::Error) -> Self { KeyStoreError::JsonError(e) }
}

impl std::error::Error for KeyStoreError { }


//------------ DiskKeyStore --------------------------------------------------

/// This type can store and retrieve values to/from disk, using json
/// serialization.
pub struct DiskKeyStore {
    dir: PathBuf
}

impl KeyStore for DiskKeyStore {
    type Key = PathBuf;

    fn key_for_snapshot() -> Self::Key {
        PathBuf::from("snapshot.json")
    }

    fn key_for_event(version: u64) -> Self::Key {
        PathBuf::from(format!("delta-{}.json", version))
    }

    fn has_key(&self, id: &AggregateId, key: &Self::Key) -> bool {
        self.file_path(id, key).exists()
    }

    fn has_aggregate(&self, _id: &AggregateId) -> bool {
        unimplemented!()
    }

    fn aggregates(&self) -> Vec<AggregateId> {
        let mut res: Vec<AggregateId> = Vec::new();
        for d in fs::read_dir(&self.dir).unwrap() {
            let full_path = d.unwrap().path();
            let path = full_path.file_name().unwrap();
            res.push(AggregateId::from(path.to_string_lossy().as_ref()));
        }
        res
    }

    fn store<V: Any + Serialize>(
        &self,
        id: &AggregateId,
        key: &Self::Key,
        value: &V
    ) -> Result<(), KeyStoreError> {
        if self.has_key(id, key) {
            Err(KeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            let mut f = file::create_file_with_path(&self.file_path(id, key))?;
            let json = serde_json::to_string(value)?;
            f.write_all(json.as_ref())?;
            Ok(())
        }
    }

    fn get<V: Any + Storable>(
        &self,
        id: &AggregateId,
        key: &Self::Key
    ) -> Result<Option<V>, KeyStoreError> {
        if self.has_key(id, key) {
            let f = File::open(self.file_path(id, key))?;
            let v: V = serde_json::from_reader(f)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}

impl DiskKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        DiskKeyStore { dir }
    }

    pub fn under_work_dir(
        work_dir: &PathBuf,
        name_space: &str
    ) -> Result<Self, io::Error> {
        let mut path = work_dir.clone();
        path.push(name_space);
        if ! path.is_dir() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self::new(path))
    }

    fn file_path(&self, id: &AggregateId, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir.clone();
        file_path.push(id.to_string());
        file_path.push(key);
        file_path
    }
}
