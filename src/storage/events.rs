use std::any::Any;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::io::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::RwLock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use crate::util::file;
use std::sync::Arc;


//------------ Storable ------------------------------------------------------

pub trait Storable: Serialize + DeserializeOwned + Sized {}
impl<T: Serialize + DeserializeOwned + Sized> Storable for T { }


//------------ AggregateId ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AggregateId(String);

impl AggregateId {
    pub fn new(s: &str) -> Self {
        AggregateId(s.to_string())
    }
}

//------------ Aggregate -----------------------------------------------------

pub trait Aggregate: Storable + Clone {

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

#[derive(Deserialize, Serialize)]
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

    pub fn event(&self) -> &E { & self.details }

    pub fn into_details(self) -> E { self.details }

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
#[derive(Deserialize, Serialize)]
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


//------------ AggregateRef --------------------------------------------------

/// This type wraps the Aggregate references returned by the AggregateManager,
/// so that we can change the implementation details of the of the latter.
/// This derefs to the Aggregate.
pub struct AggregateRef<A: Aggregate> {
    agg: Arc<A>
}

impl<A: Aggregate> Deref for AggregateRef<A> {
    type Target = A;

    fn deref(&self) -> &'_ Self::Target {
        &self.agg
    }
}

impl<A: Aggregate> AsRef<A> for AggregateRef<A> {
    fn as_ref(&self) -> &A {
        &self.agg
    }
}


//------------ AggregateManager ----------------------------------------------

/// This type is responsible for managing Aggregates. I.e. creating new
/// Aggregate instances, returning a reference for reading, dispatching
/// commands to an aggregate, and storing them.
pub struct AggregateManager<A:Aggregate, S: KeyStore> {
    /// Stores a the most recent aggregate.
    ///
    /// Note. We may wish to change this in future. E.g. just remember the
    /// version of the aggregate and get it from storage as needed. Or even
    /// make this a choice - keep things we use often in memory, but not
    /// other things.
    ///
    /// We may then also wish to change the return types, and maybe we will
    /// have to push the write locking down to the keystore.. I.e. any new
    /// save already requires a new key - it is a write once store. So, if we
    /// get an error then that is an indication of a concurrency issue.
    cache: RwLock<HashMap<AggregateId, Arc<A>>>,
    store: S
}

impl<A: 'static + Aggregate, S: 'static + KeyStore> AggregateManager<A, S> {

    pub fn new(store: S) -> Self {
        let values = RwLock::new(HashMap::new());
        AggregateManager {
            cache: values, store
        }
    }

    fn update_cache(
        &self,
        id: &AggregateId,
        mut force: bool
    ) -> Result<(), AggMgrErr<A::Error, S::Error>> {

        let mut cache = self.cache.write().unwrap();

        let mut has_key = cache.contains_key(id);

        if ! has_key {
            let init_key = S::key_for_event(id, 0);
            if let Some(init) = self.store.get::<A::InitEvent>(&init_key)
                .map_err(AggMgrErr::KeyStoreError)? {
                let mut agg = A::init(init).map_err(AggMgrErr::AggregateError)?;

                cache.insert(id.clone(), Arc::new(agg));
                force = true;
                has_key = true;
            }
        }

        if has_key && force {
            // We MUST have an entry now
            let arc = cache.get_mut(id).unwrap();
            let agg = Arc::make_mut(arc);

            loop {
                let ver = agg.version();
                let key = S::key_for_event(id, ver);
                if let Some(event) = self.store.get::<A::Event>(&key)
                    .map_err(AggMgrErr::KeyStoreError)? {
                    agg.apply(event)
                } else {
                    break
                }
            }
        }

        Ok(())
    }


    /// Get a reference to the latest version of the aggregate.
    #[allow(clippy::type_complexity)]
    pub fn get_latest(
        &self,
        id: &AggregateId
    ) -> Result<Option<AggregateRef<A>>, AggMgrErr<A::Error, S::Error>> {
        self.update_cache(id, false)?;
        Ok(self.cache.read().unwrap().get(id)
            .map(|arc| AggregateRef { agg: arc.clone() } ))
    }

    #[allow(clippy::type_complexity)]
    pub fn create(
        &self,
        id: &AggregateId,
        event: A::InitEvent
    ) -> Result<(), AggMgrErr<A::Error, S::Error>> {
        self.update_cache(id, true)?;

        let mut cache = self.cache.write().unwrap();
        if cache.contains_key(id) {
            Err(AggMgrErr::AggregateAlreadyExists)
        } else {
            let key = S::key_for_event(id, 0);
            self.store.store(&key, &event).map_err(AggMgrErr::KeyStoreError)?;

            let agg = A::init(event).map_err(AggMgrErr::AggregateError)?;

            cache.insert(id.clone(), Arc::new(agg));
            Ok(())
        }
    }

    /// Apply a command to the latest aggregate, save the events and return
    /// the updated aggregate.
    #[allow(clippy::type_complexity)]
    pub fn apply(
        &self,
        command: A::Command
    ) -> Result<(), AggMgrErr<A::Error, S::Error>> {
        let id = command.id().clone();
        self.update_cache(&id, true)?;

        let mut cache = self.cache.write().unwrap();

        match cache.get_mut(&id) {
            None => Err(AggMgrErr::AggregateDoesNotExist),
            Some(agg) => {

                let agg = Arc::make_mut(agg);

                if let Some(version) = command.version() {
                    if version != agg.version() {
                        // TODO check conflicts
                        return Err(AggMgrErr::ConcurrentModification)
                    }
                }

                let events = agg.process_command(command)
                    .map_err(AggMgrErr::AggregateError)?;

                for e in events {
                    let key = S::key_for_event(&id, e.version());
                    self.store.store(&key, &e).map_err(AggMgrErr::KeyStoreError)?;
                    agg.apply(e);
                }

                Ok(())
            }
        }
    }
}


//------------ AggMgrErr -----------------------------------------------------

#[derive(Debug, Display)]
pub enum AggMgrErr<A: Display, K: Display> {
    #[display(fmt = "Aggregate does not exist")]
    AggregateDoesNotExist,

    #[display(fmt = "Aggregate already exists")]
    AggregateAlreadyExists,

    #[display(fmt = "Concurrent modification. Command rejected")]
    ConcurrentModification,

    #[display(fmt = "{}", _0)]
    AggregateError(A),

    #[display(fmt = "{}", _0)]
    KeyStoreError(K),
}


//------------ KeyStore ------------------------------------------------------

/// Generic KeyStore for AggregateManager
pub trait KeyStore {
    type Key;
    type Error: std::error::Error;

    fn key_for_snapshot(id: &AggregateId, version: u64) -> Self::Key;
    fn key_for_event(id: &AggregateId, version: u64) -> Self::Key;

    /// Returns whether a key already exists.
    fn has_key(&self, key: &Self::Key) -> bool;

    /// Throws an error if the key already exists.
    fn store<V: Any + Serialize>(&self, key: &Self::Key, value: &V) -> Result<(), Self::Error>;

    /// Get the value for this key, if any exists.
    fn get<V: Any + Storable>(&self, key: &Self::Key) -> Result<Option<V>, Self::Error>;
}


//------------ DiskKeyStore --------------------------------------------------

/// This type can store and retrieve values to/from disk, using json
/// serialization.
pub struct DiskKeyStore {
    dir: PathBuf
}

impl KeyStore for DiskKeyStore {
    type Key = PathBuf;
    type Error = DiskKeyStoreError;

    fn key_for_snapshot(id: &AggregateId, version: u64) -> Self::Key {
        PathBuf::from(format!("snapshot-{}-{}", id.0, version))
    }

    fn key_for_event(id: &AggregateId, version: u64) -> Self::Key {
        PathBuf::from(format!("delta-{}-{}", id.0, version))
    }

    fn has_key(&self, key: &Self::Key) -> bool {
        self.file_path(key).exists()
    }

    fn store<V: Any + Serialize>(&self, key: &Self::Key, value: &V) -> Result<(),
        Self::Error> {
        if self.has_key(key) {
            Err(DiskKeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            let mut f = file::create_file_with_path(&self.file_path(key))?;
            let json = serde_json::to_string(value)?;
            f.write_all(json.as_ref())?;
            Ok(())
        }
    }

    fn get<V: Any + Storable>(&self, key: &Self::Key) -> Result<Option<V>, Self::Error> {
        if self.has_key(key) {
            let f = File::open(self.file_path(&key))?;
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

    fn file_path(&self, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir.clone();
        file_path.push(key);
        file_path
    }
}

//------------ DiskKeyStoreError ---------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum DiskKeyStoreError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Key already exists: {}", _0)]
    KeyExists(String)
}

impl From<io::Error> for DiskKeyStoreError {
    fn from(e: io::Error) -> Self { DiskKeyStoreError::IoError(e) }
}

impl From<serde_json::Error> for DiskKeyStoreError {
    fn from(e: serde_json::Error) -> Self { DiskKeyStoreError::JsonError(e) }
}

impl std::error::Error for DiskKeyStoreError { }



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::util::test;

    #[derive(Clone, Deserialize, Serialize)]
    struct Person {
        id: AggregateId,
        version: u64,
        name: String,
        age: u8
    }

    impl Person {
        pub fn id(&self) -> &AggregateId { &self.id }
        pub fn version(&self) -> u64 { self.version }
        pub fn name(&self) -> &String { &self.name }
        pub fn age(&self) -> u8 { self.age }
    }

    #[derive(Deserialize, Serialize)]
    pub struct InitPersonDetails {
        pub name: String
    }

    #[derive(Deserialize, Serialize)]
    enum PersonEventDetails {
        NameChanged(String),
        HadBirthday
    }

    #[derive(Deserialize, Serialize)]
    enum PersonCommandDetails {
        ChangeName(String),
        GoAroundTheSun
    }

    impl CommandDetails for PersonCommandDetails {
        type Event = PersonEvent;
    }

    type InitPersonEvent = StoredEvent<InitPersonDetails>;

    impl InitPersonEvent {
        pub fn init(id: &AggregateId, name: &str) -> Self {
            StoredEvent::new(id, 0, InitPersonDetails { name: name.to_string()})
        }
    }

    type PersonEvent = StoredEvent<PersonEventDetails>;

    impl PersonEvent {
        pub fn had_birthday(p: &Person) -> Self {
            StoredEvent::new(p.id(), p.version, PersonEventDetails::HadBirthday)
        }

        pub fn name_changed(p: &Person, name: String) -> Self {
            StoredEvent::new(
                p.id(),
                p.version,
                PersonEventDetails::NameChanged(name))
        }
    }

    type PersonCommand = SentCommand<PersonCommandDetails>;

    impl PersonCommand {

        pub fn go_around_sun(id: &AggregateId, version: Option<u64>) -> Self {
            Self::new(id, version, PersonCommandDetails::GoAroundTheSun)
        }

        pub fn change_name(id: &AggregateId, version: Option<u64>, s: &str) -> Self {
            let details = PersonCommandDetails::ChangeName(s.to_string());
            Self::new(id, version, details)
        }
    }

    #[derive(Clone, Debug, Display)]
    enum PersonError {
        #[display(fmt = "No person can live longer than 255 years")]
        TooOld
    }

    impl std::error::Error for PersonError {}

    impl Aggregate for Person {
        type Command = PersonCommand;
        type Event = PersonEvent;
        type InitEvent = InitPersonEvent;
        type Error = PersonError;

        fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
            let (id, _version, init) = event.unwrap();
            Ok(Person {
                id, version: 1, name: init.name, age: 0
            })
        }

        fn version(&self) -> u64 {
            self.version
        }

        fn apply(&mut self, event: Self::Event) {
            match event.into_details() {
                PersonEventDetails::NameChanged(name) => { self.name = name },
                PersonEventDetails::HadBirthday => { self.age = self.age + 1 }
            }
            self.version = self.version + 1;
        }

        fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
            match command.into_details() {
                PersonCommandDetails::ChangeName(name) => {
                    let event = PersonEvent::name_changed(&self, name);
                    Ok(vec![event])
                },
                PersonCommandDetails::GoAroundTheSun => {
                    if self.age == 255 {
                        Err(PersonError::TooOld)
                    } else {
                        let event = PersonEvent::had_birthday(&self);
                        Ok(vec![event])
                    }
                }
            }
        }
    }

    type PersonManager = AggregateManager<Person, DiskKeyStore>;


    #[test]
    fn test() {
        test::test_with_tmp_dir(|d| {

            let storage = DiskKeyStore::new(d.clone());
            let manager = PersonManager::new(storage);

            let id_alice = AggregateId::new("alice");
            let alice_init = InitPersonEvent::init(&id_alice, "alice smith");

            manager.create(&id_alice, alice_init).unwrap();

            let alice = manager.get_latest(&id_alice).unwrap().unwrap();
            assert_eq!(alice.name(), "alice smith");
            assert_eq!(alice.age(), 0);

            let mut age = 0;
            loop {
                manager.apply(
                    PersonCommand::go_around_sun(&id_alice, None)
                ).unwrap();
                age = age + 1;
                if age == 21 {
                    break
                }
            }

            let alice = manager.get_latest(&id_alice).unwrap().unwrap();
            assert_eq!(alice.name(), "alice smith");
            assert_eq!(alice.age(), 21);

            manager.apply(
                PersonCommand::change_name(&id_alice, Some(22), "alice smith-doe")
            ).unwrap();

            let alice = manager.get_latest(&id_alice).unwrap().unwrap();
            assert_eq!(alice.name(), "alice smith-doe");
            assert_eq!(alice.age(), 21);

            // Should read state from disk
            let storage = DiskKeyStore::new(d);
            let manager = PersonManager::new(storage);

            let alice = manager.get_latest(&id_alice).unwrap().unwrap();
            assert_eq!(alice.name(), "alice smith-doe");
            assert_eq!(alice.age(), 21);
        })
    }


}