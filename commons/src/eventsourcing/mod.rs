//! Event sourcing support for Krill

mod es_example; // Example implementation and tests.

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use crate::util::file;

const SNAPSHOT_FREQ: u64 = 5;

//------------ Storable ------------------------------------------------------

pub trait Storable: Clone + Serialize + DeserializeOwned + Sized {}
impl<T: Clone + Serialize + DeserializeOwned + Sized> Storable for T { }


//------------ AggregateId ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AggregateId(String);


impl AggregateId {
    pub fn as_str(&self) -> &str {
        &self.0.as_str()
    }
}

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
        self.as_str()
    }
}

impl AsRef<String> for AggregateId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl AsRef<Path> for AggregateId {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl fmt::Display for AggregateId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ Aggregate -----------------------------------------------------

pub trait Aggregate: Storable + Send + Sync + 'static {

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

    /// Applies the event to this. This MUST not result in any errors, and
    /// this MUST be side-effect free. Applying the event just updates the
    /// internal data of the aggregate.
    ///
    /// Note the event is moved. This is done because we want to avoid
    /// doing additional allocations where we can.
    fn apply(&mut self, event: Self::Event);

    /// Applies all events. Assumes that the list ordered, starting with the
    /// oldest event, applicable, self.version matches the oldest event, and
    /// contiguous, i.e. there are no missing events.
    fn apply_all(&mut self, events: Vec<Self::Event>) {
        for event in events {
            self.apply(event);
        }
    }

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these event here.
    ///
    /// The command is moved, because we want to enable moving its data
    /// without reallocating.
    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error>;
}


//------------ Event --------------------------------------------------------

pub trait Event: Storable + 'static {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn id(&self) -> &AggregateId;

    /// The version of the aggregate that this event updates. An aggregate that
    /// is currently at version x, will get version x + 1, when the event for
    /// version x is applied.
    fn version(&self) -> u64;
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StoredEvent<E: Storable + 'static> {
    id: AggregateId,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E
}

impl<E: Storable + 'static> StoredEvent<E> {

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

impl<E: Storable + 'static> Event for StoredEvent<E> {
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
pub trait CommandDetails: Storable + 'static {
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

    /// Get the value for this key, if any exists.

    fn get_event<V: Event>(
        &self,
        id: &AggregateId,
        version: u64
    ) -> Result<Option<V>, KeyStoreError>;

    fn store_event<V: Event>(
        &self,
        event: &V
    ) -> Result<(), KeyStoreError>;

    /// Get the latest aggregate

    fn get_aggregate<V: Aggregate>(
        &self,
        id: &AggregateId
    ) -> Result<Option<V>, KeyStoreError>;

    /// Saves the latest snapshot - overwrites any previous snapshot.

    fn store_aggregate<V: Aggregate>(
        &self,
        id: &AggregateId,
        aggregate: &V
    ) -> Result<(), KeyStoreError>;
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
    KeyExists(String),

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError
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
    dir: PathBuf,
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

    fn has_aggregate(&self, id: &AggregateId) -> bool {
        self.dir_for_aggregate(id).exists()
    }

    fn aggregates(&self) -> Vec<AggregateId> {
        let mut res: Vec<AggregateId> = Vec::new();

        if let Ok(dir) = fs::read_dir(&self.dir) {
            for d in dir {
                let full_path = d.unwrap().path();
                let path = full_path.file_name().unwrap();

                let id = AggregateId::from(path.to_string_lossy().as_ref());
                res.push(id);
            }
        }

        res
    }

    fn store<V: Any + Serialize>(
        &self,
        id: &AggregateId,
        key: &Self::Key,
        value: &V
    ) -> Result<(), KeyStoreError> {
        let mut f = file::create_file_with_path(&self.file_path(id, key))?;
        let json = serde_json::to_string(value)?;
        f.write_all(json.as_ref())?;
        Ok(())
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

    /// Get the value for this key, if any exists.
    fn get_event<V: Event>(
        &self,
        id: &AggregateId,
        version: u64
    ) -> Result<Option<V>, KeyStoreError> {
        let path = self.path_for_event(id, version);
        if path.exists() {
            let f = File::open(path)?;
            let v: V = serde_json::from_reader(f)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn store_event<V: Event>(
        &self,
        event: &V
    ) -> Result<(), KeyStoreError> {
        let id = event.id();
        let key = Self::key_for_event(event.version());
        if self.has_key(id, &key) {
            Err(KeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            self.store(id, &key, event)
        }
    }

    fn get_aggregate<V: Aggregate>(
        &self,
        id: &AggregateId
    ) -> Result<Option<V>, KeyStoreError> {
        // try to get a snapshot.
        // If that fails, try to get the init event.
        // Then replay all newer events that can be found.
        let key = Self::key_for_snapshot();
        let aggregate_opt = match self.get::<V>(id, &key)? {
            Some(aggregate) => Some(aggregate),
            None => {
                match self.get_event::<V::InitEvent>(id, 0)? {
                    Some(e) => Some(V::init(e).map_err(|_|KeyStoreError::InitError)?),
                    None => None
                }
            }
        };

        match aggregate_opt {
            None => Ok(None),
            Some(mut aggregate) => {
                self.update_aggregate(id, &mut aggregate)?;
                Ok(Some(aggregate))
            }
        }
    }

    fn store_aggregate<V: Aggregate>(
        &self,
        id: &AggregateId,
        aggregate: &V
    ) -> Result<(), KeyStoreError> {
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
    pub fn under_work_dir(
        work_dir: &PathBuf,
        name_space: &str
    ) -> Result<Self, io::Error> {
        let mut path = work_dir.clone();
        path.push(name_space);
        if ! path.is_dir() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self::new(work_dir, name_space))
    }

    fn file_path(&self, id: &AggregateId, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(key);
        file_path
    }

    fn dir_for_aggregate(&self, id: &AggregateId) -> PathBuf {
        let mut dir_path = self.dir.clone();
        dir_path.push(id);
        dir_path
    }

    fn path_for_event(
        &self,
        id: &AggregateId,
        version: u64
    ) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(format!("delta-{}.json", version));
        file_path
    }

    fn update_aggregate<A: Aggregate>(
        &self,
        id: &AggregateId,
        aggregate: &mut A
    ) -> Result<(), KeyStoreError> {
        while let Some(e) = self.get_event(id, aggregate.version())? {
            aggregate.apply(e);
        }
        Ok(())
    }

}


pub type StoreResult<T> = Result<T, AggregateStoreError>;

pub trait AggregateStore<A: Aggregate>: Send + Sync {
    /// Gets the latest version for the given aggregate. Returns
    /// an AggregateStoreError::UnknownAggregate in case the aggregate
    /// does not exist.
    fn get_latest(&self, id: &AggregateId) -> StoreResult<Arc<A>>;

    /// Adds a new aggregate instance based on the init event.
    fn add(&self, id: &AggregateId, init: A::InitEvent) -> StoreResult<()>;

    /// Updates the aggregate instance in the store. Expects that the
    /// Arc<A> retrieved using 'get_latest' is moved here, so clone on
    /// writes can be avoided, and a verification can be done that there
    /// is no concurrent modification. Returns the updated instance if all
    /// is well, or an AggregateStoreError::ConcurrentModification if you
    /// try to update an outdated instance.
    fn update(&self, id: &AggregateId, agg: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>>;

    /// Returns true if an instance exists for the id
    fn has(&self, id: &AggregateId) -> bool;

    /// Lists all known ids.
    fn list(&self) -> Vec<AggregateId>;
}


/// This type defines possible Errors for the AggregateStore
#[derive(Debug, Display)]
pub enum AggregateStoreError {
    #[display(fmt = "{}", _0)]
    KeyStoreError(KeyStoreError),

    #[display(fmt = "Unknown aggregate: {}", _0)]
    UnknownAggregate(AggregateId),

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "Event not applicable to aggregate, id or version is off")]
    WrongEventForAggregate,

    #[display(fmt = "Trying to update outdated aggregate")]
    ConcurrentModification,
}

impl From<KeyStoreError> for AggregateStoreError {
    fn from(e: KeyStoreError) -> Self { AggregateStoreError::KeyStoreError(e) }
}


pub struct DiskAggregateStore<A: Aggregate> {
    store: DiskKeyStore,
    cache: RwLock<HashMap<AggregateId, Arc<A>>>,
    use_cache: bool
}

impl<A: Aggregate> DiskAggregateStore<A> {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let store = DiskKeyStore::under_work_dir(work_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let use_cache = true;
        Ok(DiskAggregateStore { store, cache, use_cache })
    }
}

impl<A: Aggregate> DiskAggregateStore<A> {
    fn has_updates(
        &self,
        id: &AggregateId,
        aggregate: &A
    ) -> StoreResult<bool> {
        Ok(self.store.get_event::<A::Event>(id, aggregate.version())?.is_some())
    }

    fn cache_get(&self, id: &AggregateId) -> Option<Arc<A>> {
        if self.use_cache {
            self.cache.read().unwrap().get(id).cloned()
        } else {
            None
        }
    }

    fn cache_update(&self, id: &AggregateId, arc: Arc<A>) {
        if self.use_cache {
            self.cache.write().unwrap().insert(id.clone(), arc);
        }
    }
}

impl<A: Aggregate> AggregateStore<A> for DiskAggregateStore<A> {
    fn get_latest(&self, id: &AggregateId) -> StoreResult<Arc<A>> {
        match self.cache_get(id) {
            None => {
                match self.store.get_aggregate(id)? {
                    None => Err(AggregateStoreError::UnknownAggregate(id.clone())),
                    Some(agg) => {
                        let arc: Arc<A> = Arc::new(agg);
                        self.cache_update(id, arc.clone());
                        Ok(arc)
                    }
                }
            },
            Some(mut arc) => {
                if self.has_updates(id, &arc)? {
                    let agg = Arc::make_mut(&mut arc);
                    self.store.update_aggregate(id, agg)?;
                }
                Ok(arc)
            }
        }
    }

    fn add(&self, id: &AggregateId, init: A::InitEvent) -> StoreResult<()> {
        self.store.store_event(&init)?;

        let aggregate = A::init(init).map_err(|_| AggregateStoreError::InitError)?;
        self.store.store_aggregate(id, &aggregate)?;

        let arc = Arc::new(aggregate);
        self.cache_update(id, arc);

        Ok(())
    }


    fn update(&self, id: &AggregateId, prev: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>> {
        // Get the latest arc.
        let mut latest = self.get_latest(id)?;

        {
            // Verify whether there is a concurrency issue
            if prev.version() != latest.version() {
                return Err(AggregateStoreError::ConcurrentModification)
            }

            // forget the previous version
            std::mem::forget(prev);

            // make the arc mutable, hopefully forgetting prev will avoid the clone
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
            let _write_lock = self.cache.write().unwrap();

            // There is a possible race condition. We may only have obtained the lock
            if self.has_updates(id, &agg)? {
                self.store.update_aggregate(id, agg)?;
            }

            let version_before = agg.version();
            let nr_events = events.len() as u64;

            for i in 0..nr_events {
                let event = &events[i as usize];
                if event.version() != version_before + i || event.id() != id {
                    return Err(AggregateStoreError::WrongEventForAggregate);
                }
            }

            for event in events {
                self.store.store_event(&event)?;
                agg.apply(event);
                if agg.version() % SNAPSHOT_FREQ == 0 {
                    self.store.store_aggregate(id, agg)?;
                }
            }
        }

        Ok(latest)
    }

    fn has(&self, id: &AggregateId) -> bool {
        self.store.has_aggregate(id)
    }

    fn list(&self) -> Vec<AggregateId> {
        self.store.aggregates()
    }
}



