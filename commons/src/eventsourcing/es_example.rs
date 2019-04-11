//! Example implementation using the eventsourcing module.
//!
//! Goal is two-fold: document using a simple domain, and test the module.
//!
use super::*;


//------------ InitPersonEvent -----------------------------------------------

/// Every aggregate defines their own initialisation event. This is the first
/// event stored for an instance.
///
/// Here we define a type wrapping around the generic StoredEvent, so we only
/// need to define the unique initialisation details.
type InitPersonEvent = StoredEvent<InitPersonDetails>;

impl InitPersonEvent {

    pub fn init(id: &AggregateId, name: &str) -> Self {
        StoredEvent::new(id, 0, InitPersonDetails { name: name.to_string()})
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct InitPersonDetails {
    pub name: String
}


//------------ InitPersonEvent -----------------------------------------------

/// Every aggregate defines their own set of events - i.e. state changes. The
/// state of an aggregate can only change when events are applied. And events
/// cannot have side effects. If they did, then replaying events would become
/// problematic.
///
/// Here we make a type alias wrapped around the generic StoredEvent and
/// include an enum with event details specific for Persons. Furthermore we
/// provide an implementation for this type alias so that we can have some
/// convenience functions for creating these events.
type PersonEvent = StoredEvent<PersonEventDetails>;

#[derive(Clone, Deserialize, Serialize)]
enum PersonEventDetails {
    NameChanged(String),
    HadBirthday
}

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


//------------ PersonCommand -------------------------------------------------

/// In order to change an aggregate a command is sent to it. The aggregate
/// will then validate the command and if there are no issues, it will return
/// a list (vec) of events that may be applied. This process in itself does
/// not change any state, the state of the aggregate is only changed when
/// those events are applied.
///
/// Commands are not recorded. Only the resulting events are. For this reason
/// commands may have side-effects: e.g. write something to disk, send an
/// email, etc.
///
/// Here we define a type wrapping around the generic SentCommand, so we only
/// need to provide an enum with specific command details. We also have an
/// implementation for this type alias providing some convenience methods.
type PersonCommand = SentCommand<PersonCommandDetails>;

#[derive(Clone, Deserialize, Serialize)]
enum PersonCommandDetails {
    ChangeName(String),
    GoAroundTheSun
}

impl CommandDetails for PersonCommandDetails {
    type Event = PersonEvent;
}

impl PersonCommand {

    pub fn go_around_sun(id: &AggregateId, version: Option<u64>) -> Self {
        Self::new(id, version, PersonCommandDetails::GoAroundTheSun)
    }


    pub fn change_name(id: &AggregateId, version: Option<u64>, s: &str) -> Self {
        let details = PersonCommandDetails::ChangeName(s.to_string());
        Self::new(id, version, details)
    }
}

//------------ PersonError ---------------------------------------------------

/// Errors specific to the Person aggregate, should only ever be returned when
/// applying a command that does not validate.
#[derive(Clone, Debug, Display)]
enum PersonError {
    #[display(fmt = "No person can live longer than 255 years")]
    TooOld
}

impl std::error::Error for PersonError {}


//------------ PersonResult --------------------------------------------------

/// A shorthand for the result type returned by the process_command function
/// of the Person aggregate.
type PersonResult = Result<Vec<PersonEvent>, PersonError>;


//------------ Person ------------------------------------------------------

/// Defines a person object. Persons have a name and an age.
///
#[derive(Clone, Deserialize, Serialize)]
struct Person {
    /// The id is needed when generating events.
    id: AggregateId,

    /// The version of for this particular Person. Versions
    /// are incremented whenever events are applied. They are
    /// used to store those and apply events in the correct
    /// sequence, as well as to detect concurrency issues when
    /// a command is sent.
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

impl Aggregate for Person {
    type Command = PersonCommand;
    type Event = PersonEvent;
    type InitEvent = InitPersonEvent;
    type Error = PersonError;

    fn init(event: InitPersonEvent) -> Result<Self, PersonError> {
        let (id, _version, init) = event.unwrap();
        Ok(Person {
            id, version: 1, name: init.name, age: 0
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: PersonEvent) {
        match event.into_details() {
            PersonEventDetails::NameChanged(name) => { self.name = name },
            PersonEventDetails::HadBirthday => { self.age += 1 }
        }
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> PersonResult {
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


/// This type is responsible for managing all persons. I.e. creating new
/// instances, returning a reference for reading, dispatching commands, and
/// storing them.
///
/// It is generic over the keystore used.
///
// Compiler does not see this is used in test
#[allow(dead_code)]
struct PersonManager<S: KeyStore> {
    /// Here we use a cache to make matters complicated^H interesting..
    /// Of course this may not always be the best idea..
    cache: RwLock<HashMap<AggregateId, Arc<Person>>>,

    /// The keystore where snapshots and events may be retrieved and stored.
    store: S
}

impl<S: KeyStore> PersonManager<S> {

    // Compiler does not see this is used in test
    #[allow(dead_code)]
    pub fn new(store: S) -> Self {
        let values = RwLock::new(HashMap::new());
        PersonManager {
            cache: values, store
        }
    }

    // Compiler does not see this is used in test
    #[allow(dead_code)]

    fn update_cache(
        &self,
        id: &AggregateId,
        mut force: bool
    ) -> Result<(), PersonManagerError> {

        let mut cache = self.cache.write().unwrap();

        let mut has_key = cache.contains_key(id);

        if ! has_key {
            let init_key = S::key_for_event(0);
            if let Some(init) = self.store.get(id, &init_key)? {
                let mut agg = Person::init(init)?;

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
                let key = S::key_for_event(ver);
                if let Some(event) = self.store.get(id, &key)? {
                    agg.apply(event)
                } else {
                    break
                }
            }
        }

        Ok(())
    }


    /// Get a reference to the latest version of the aggregate.
    // Compiler does not see this is used in test
    #[allow(dead_code)]

    fn get_latest(
        &self,
        id: &AggregateId
    ) -> Result<Option<Arc<Person>>, PersonManagerError> {
        self.update_cache(id, false)?;
        Ok(self.cache.read().unwrap().get(id).cloned())
    }

    // Compiler does not see this is used in test
    #[allow(dead_code)]

    fn create(
        &self,
        id: &AggregateId,
        event: InitPersonEvent
    ) -> Result<(), PersonManagerError> {
        self.update_cache(id, true)?;

        let mut cache = self.cache.write().unwrap();
        if cache.contains_key(id) {
            Err(PersonManagerError::AggregateAlreadyExists)
        } else {
            let key = S::key_for_event(0);
            self.store.store(id, &key, &event)?;

            let agg = Person::init(event)?;

            cache.insert(id.clone(), Arc::new(agg));
            Ok(())
        }
    }

    /// Apply a command to the latest aggregate, save the events and return
    /// the updated aggregate.
    // Compiler does not see this is used in test
    #[allow(dead_code)]
    fn apply(
        &self,
        command: PersonCommand
    ) -> Result<(), PersonManagerError> {
        let id = command.id().clone();
        self.update_cache(&id, true)?;

        let mut cache = self.cache.write().unwrap();

        match cache.get_mut(&id) {
            None => Err(PersonManagerError::AggregateDoesNotExist),
            Some(agg) => {

                let agg = Arc::make_mut(agg);

                if let Some(version) = command.version() {
                    if version != agg.version() {
                        // TODO check conflicts
                        return Err(PersonManagerError::ConcurrentModification)
                    }
                }

                let events = agg.process_command(command)?;

                for e in events {
                    let key = S::key_for_event(e.version());
                    self.store.store(&id, &key, &e)?;

                    agg.apply(e);
                }

                Ok(())
            }
        }
    }
}


//------------ PersonManagerError --------------------------------------------

// Compiler does not see this is used in test
#[allow(dead_code)]
#[derive(Debug, Display)]
enum PersonManagerError {
    #[display(fmt = "Aggregate does not exist")]
    AggregateDoesNotExist,

    #[display(fmt = "Aggregate already exists")]
    AggregateAlreadyExists,

    #[display(fmt = "Concurrent modification. Command rejected")]
    ConcurrentModification,

    #[display(fmt = "{}", _0)]
    PersonError(PersonError),

    #[display(fmt = "{}", _0)]
    KeyStoreError(KeyStoreError),
}

impl From<PersonError> for PersonManagerError {
    fn from(e: PersonError) -> Self { PersonManagerError::PersonError(e) }
}

impl From<KeyStoreError> for PersonManagerError {
    fn from(e: KeyStoreError) -> Self { PersonManagerError::KeyStoreError(e) }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::util::test;

    #[test]
    fn test() {
        test::test_with_tmp_dir(|d| {

            let storage = DiskKeyStore::under_work_dir(&d, "person").unwrap();
            let manager = PersonManager::new(storage);

            let id_alice = AggregateId::from("alice");
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
            let storage = DiskKeyStore::under_work_dir(&d, "person").unwrap();
            let manager = PersonManager::new(storage);

            let alice = manager.get_latest(&id_alice).unwrap().unwrap();
            assert_eq!(alice.name(), "alice smith-doe");
            assert_eq!(alice.age(), 21);
        })
    }
}