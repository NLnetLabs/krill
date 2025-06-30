//! Example implementation using the eventsourcing module.
//!
//! Goal is two-fold: document using a simple domain, and test the module.
#![cfg(test)]

use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use rpki::ca::idexchange::MyHandle;
use crate::api::history::{CommandHistoryCriteria, CommandSummary};
use crate::commons::storage::Namespace;
use crate::constants::ACTOR_DEF_TEST;
use crate::commons::test::mem_storage;
use super::*;


//------------ PersonInitEvent -----------------------------------------------

/// The initialization event for the [`Person`] aggregate.
///
/// Every aggregate defines their own initialization event. This is the
/// first event stored for an instance.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct PersonInitEvent {
    pub name: String,
}

impl InitEvent for PersonInitEvent {}

impl fmt::Display for PersonInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "person initialized with name '{}'", self.name)
    }
}


//------------ InitPersonCommand ---------------------------------------------

/// The initializaion command for the [`Person`] aggregate.
type PersonInitCommand = SentInitCommand<PersonInitCommandDetails>;

impl PersonInitCommand {
    fn make(id: MyHandle, name: String) -> Self {
        PersonInitCommand::new(
            id,
            PersonInitCommandDetails { name },
            &ACTOR_DEF_TEST,
        )
    }
}

#[derive(Clone, Debug)]
struct PersonInitCommandDetails {
    name: String,
}

impl fmt::Display for PersonInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for PersonInitCommandDetails {
    type StorableDetails = PersonStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        PersonStorableCommand::make_init()
    }
}

//------------ InitPersonEvent -----------------------------------------------

/// An event for the [`Person`] aggregate.
///
/// Every aggregate defines their own set of events - i.e. state changes.
/// The state of an aggregate can only change when events are applied.
/// And events cannot have side effects. If they did, then replaying
/// events would become problematic.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum PersonEvent {
    NameChanged(String),
    HadBirthday,
}

impl PersonEvent {
    pub fn had_birthday() -> Self {
        PersonEvent::HadBirthday
    }

    pub fn name_changed(name: String) -> Self {
        PersonEvent::NameChanged(name)
    }
}

impl Event for PersonEvent {}

impl fmt::Display for PersonEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PersonEvent::NameChanged(new_name) => {
                write!(f, "changed name to '{new_name}'")
            }
            PersonEvent::HadBirthday => write!(f, "went around the sun."),
        }
    }
}


//------------ PersonCommand -------------------------------------------------

/// A command for the [`Person`] aggregate.
///
/// In order to change an aggregate a command is sent to it. The aggregate
/// will then validate the command and if there are no issues, it will
/// return a list (vec) of events that may be applied. This process in
/// itself does not change any state, the state of the aggregate is
/// only changed when those events are applied.
///
/// Commands are not recorded. Only the resulting events are. For this
/// reason commands may have side-effects: e.g. write something to
/// disk, send an email, etc.
///
/// Here we define a type wrapping around the generic SentCommand, so we
/// only need to provide an enum with specific command details. We
/// also have an implementation for this type alias providing some
/// convenience methods.
type PersonCommand = SentCommand<PersonCommandDetails>;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum PersonCommandDetails {
    ChangeName(String),
    GoAroundTheSun,
}

impl fmt::Display for PersonCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PersonCommandDetails::ChangeName(name) => {
                write!(f, "Change name to {name}")
            }
            PersonCommandDetails::GoAroundTheSun => {
                write!(f, "Go around the sun")
            }
        }
    }
}

impl CommandDetails for PersonCommandDetails {
    type Event = PersonEvent;
    type StorableDetails = PersonStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        match self {
            PersonCommandDetails::ChangeName(name) => {
                PersonStorableCommand::ChangeName(name.clone())
            }
            PersonCommandDetails::GoAroundTheSun => {
                PersonStorableCommand::GoAroundTheSun
            }
        }
    }
}

impl PersonCommand {
    pub fn go_around_sun(id: MyHandle, version: Option<u64>) -> Self {
        Self::new(
            id,
            version,
            PersonCommandDetails::GoAroundTheSun,
            &ACTOR_DEF_TEST,
        )
    }

    pub fn change_name(
        id: MyHandle,
        version: Option<u64>,
        s: &str,
    ) -> Self {
        let details = PersonCommandDetails::ChangeName(s.to_string());
        Self::new(id, version, details, &ACTOR_DEF_TEST)
    }
}


//------------ PersonStorableCommand -----------------------------------------

/// The storable version for command.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum PersonStorableCommand {
    Init,
    ChangeName(String),
    GoAroundTheSun,
}

impl fmt::Display for PersonStorableCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersonStorableCommand::Init => write!(f, "Initialise person"),
            PersonStorableCommand::ChangeName(name) => {
                write!(f, "Change name to {name}")
            }
            PersonStorableCommand::GoAroundTheSun => {
                write!(f, "Go around the sun")
            }
        }
    }
}

impl WithStorableDetails for PersonStorableCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            PersonStorableCommand::Init => {
                CommandSummary::new("person-init", self)
            }
            PersonStorableCommand::ChangeName(name) => {
                CommandSummary::new("person-change-name", self)
                    .arg("name", name)
            }
            PersonStorableCommand::GoAroundTheSun => {
                CommandSummary::new("person-around-sun", self)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}


//------------ PersonError ---------------------------------------------------

/// Errors specific to the Person aggregate.
///
/// This should only ever be returned when applying a command that does not
/// validate.
#[derive(Clone, Debug)]
enum PersonError {
    TooOld,
    Custom(String),
}

impl fmt::Display for PersonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PersonError::TooOld => {
                write!(f, "No person can live longer than 255 years")
            }
            PersonError::Custom(s) => s.fmt(f),
        }
    }
}

impl From<AggregateStoreError> for PersonError {
    fn from(e: AggregateStoreError) -> Self {
        PersonError::Custom(e.to_string())
    }
}

impl std::error::Error for PersonError {}


//------------ Person ------------------------------------------------------

/// Defines a person object.
///
/// Persons have a name and an age.
#[derive(Clone, Deserialize, Serialize)]
struct Person {
    /// The id is needed when generating events.
    id: MyHandle,

    /// The version of for this particular Person. Versions
    /// are incremented whenever events are applied. They are
    /// used to store those and apply events in the correct
    /// sequence, as well as to detect concurrency issues when
    /// a command is sent.
    version: u64,

    name: String,
    age: u8,
}

impl Person {
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn age(&self) -> u8 {
        self.age
    }
}

impl Aggregate for Person {
    type InitCommand = PersonInitCommand;
    type InitEvent = PersonInitEvent;

    type Command = PersonCommand;
    type Event = PersonEvent;

    type StorableCommandDetails = PersonStorableCommand;

    type Error = PersonError;

    fn init(id: &MyHandle, event: PersonInitEvent) -> Self {
        Person {
            id: id.clone(),
            version: 1,
            name: event.name,
            age: 0,
        }
    }

    fn process_init_command(
        command: Self::InitCommand,
    ) -> Result<Self::InitEvent, Self::Error> {
        Ok(PersonInitEvent {
            name: command.into_details().name,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn apply(&mut self, event: PersonEvent) {
        match event {
            PersonEvent::NameChanged(name) => self.name = name,
            PersonEvent::HadBirthday => self.age += 1,
        }
    }

    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Event>, Self::Error> {
        match command.into_details() {
            PersonCommandDetails::ChangeName(name) => {
                let event = PersonEvent::name_changed(name);
                Ok(vec![event])
            }
            PersonCommandDetails::GoAroundTheSun => {
                if self.age == 255 {
                    Err(PersonError::TooOld)
                } else {
                    let event = PersonEvent::had_birthday();
                    Ok(vec![event])
                }
            }
        }
    }
}


//------------ EventCounter --------------------------------------------------

/// Example listener that simply counts all events
struct EventCounter {
    counter: RwLock<Counter>,
}

struct Counter {
    total: usize,
}

impl Default for EventCounter {
    fn default() -> Self {
        EventCounter {
            counter: RwLock::new(Counter { total: 0 }),
        }
    }
}

impl EventCounter {
    pub fn total(&self) -> usize {
        self.counter.read().unwrap().total
    }
}

impl<A: Aggregate> PostSaveEventListener<A> for EventCounter {
    fn listen(&self, _agg: &A, events: &[A::Event]) {
        self.counter.write().unwrap().total += events.len();
    }
}


//------------ Test Function -------------------------------------------------

#[test]
fn event_sourcing_framework() {
    let storage_uri = mem_storage();

    let counter = Arc::new(EventCounter::default());

    let mut manager = AggregateStore::<Person>::create(
        &storage_uri,
        const { Namespace::make("person") },
        false,
    )
    .unwrap();
    manager.add_post_save_listener(counter.clone());

    let alice_name = "alice smith".to_string();
    let alice_handle = MyHandle::from_str("alice").unwrap();
    let alice_init_cmd =
        PersonInitCommand::make(alice_handle.clone(), alice_name);

    manager.add(alice_init_cmd).unwrap();

    let mut alice = manager.get_latest(&alice_handle).unwrap();
    assert_eq!("alice smith", alice.name());
    assert_eq!(0, alice.age());

    let mut age = 0;
    loop {
        let get_older = PersonCommand::go_around_sun(
            alice_handle.clone(), None
        );
        alice = manager.command(get_older).unwrap();

        age += 1;
        if age == 21 {
            break;
        }
    }

    assert_eq!("alice smith", alice.name());
    assert_eq!(21, alice.age());

    let change_name = PersonCommand::change_name(
        alice_handle.clone(),
        Some(22),
        "alice smith-doe",
    );
    let alice = manager.command(change_name).unwrap();
    assert_eq!("alice smith-doe", alice.name());
    assert_eq!(21, alice.age());

    // Should read state again when restarted with same data store
    // mapping.
    let manager = AggregateStore::<Person>::create(
        &storage_uri,
        const { Namespace::make("person") },
        false,
    )
    .unwrap();

    let alice = manager.get_latest(&alice_handle).unwrap();
    assert_eq!("alice smith-doe", alice.name());
    assert_eq!(21, alice.age());

    assert_eq!(22, counter.total());

    // Get paginated history
    let crit = CommandHistoryCriteria {
        offset: 3,
        rows_limit: Some(10),
        .. Default::default()
    };

    let history = manager.command_history(&alice_handle, crit).unwrap();
    assert_eq!(history.total, 22);
    assert_eq!(history.offset, 3);
    assert_eq!(history.commands.len(), 10);
    assert_eq!(history.commands.first().unwrap().version, 4);

    // Get history excluding 'around the sun' commands
    let crit = CommandHistoryCriteria {
        rows_limit: Some(100),
        label_excludes: Some(vec!["person-around-sun".into()]),
        .. Default::default()
    };
    let history = manager.command_history(&alice_handle, crit).unwrap();
    assert_eq!(history.total, 1);
}

