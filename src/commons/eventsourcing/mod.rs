//! Event sourcing support for Krill

mod agg;
pub use self::agg::Aggregate;

mod evt;
pub use self::evt::{Event, StoredEvent};

mod cmd;
pub use self::cmd::{Command, CommandDetails, SentCommand, StoredCommand, WithStorableDetails};

mod store;
pub use self::store::*;

mod listener;
pub use self::listener::{EventCounter, EventListener};

mod kv;
pub use self::kv::*;

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    //! Example implementation using the eventsourcing module.
    //!
    //! Goal is two-fold: document using a simple domain, and test the module.
    //!

    use std::str::FromStr;
    use std::sync::Arc;
    use std::{fmt, fs};

    use serde::Serialize;

    use crate::test;
    use crate::{
        commons::{
            actor::Actor,
            api::{CommandHistoryCriteria, CommandSummary, Handle},
        },
        constants::ACTOR_DEF_TEST,
    };

    use super::*;

    //------------ InitPersonEvent -----------------------------------------------

    /// Every aggregate defines their own initialisation event. This is the first
    /// event stored for an instance.
    ///
    /// Here we define a type wrapping around the generic StoredEvent, so we only
    /// need to define the unique initialisation details.
    type InitPersonEvent = StoredEvent<InitPersonDetails>;

    impl InitPersonEvent {
        pub fn init(id: &Handle, name: &str) -> Self {
            StoredEvent::new(id, 0, InitPersonDetails { name: name.to_string() })
        }
    }

    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    struct InitPersonDetails {
        pub name: String,
    }

    impl fmt::Display for InitPersonDetails {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "person initialised with name '{}'", self.name)
        }
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

    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    enum PersonEventDetails {
        NameChanged(String),
        HadBirthday,
    }

    impl PersonEvent {
        pub fn had_birthday(p: &Person) -> Self {
            StoredEvent::new(p.id(), p.version, PersonEventDetails::HadBirthday)
        }

        pub fn name_changed(p: &Person, name: String) -> Self {
            StoredEvent::new(p.id(), p.version, PersonEventDetails::NameChanged(name))
        }
    }

    impl fmt::Display for PersonEventDetails {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                PersonEventDetails::NameChanged(new_name) => write!(f, "changed name to '{}'", new_name),
                PersonEventDetails::HadBirthday => write!(f, "went around the sun."),
            }
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

    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    enum PersonCommandDetails {
        ChangeName(String),
        GoAroundTheSun,
    }

    impl fmt::Display for PersonCommandDetails {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                PersonCommandDetails::ChangeName(name) => write!(f, "Change name to {}", name),
                PersonCommandDetails::GoAroundTheSun => write!(f, "Go around the sun"),
            }
        }
    }

    impl WithStorableDetails for PersonCommandDetails {
        fn summary(&self) -> CommandSummary {
            match self {
                PersonCommandDetails::ChangeName(name) => {
                    CommandSummary::new("person-change-name", &self).with_arg("name", name)
                }
                PersonCommandDetails::GoAroundTheSun => CommandSummary::new("person-around-sun", &self),
            }
        }
    }

    impl CommandDetails for PersonCommandDetails {
        type Event = PersonEvent;
        type StorableDetails = Self;

        fn store(&self) -> Self::StorableDetails {
            self.clone()
        }
    }

    impl PersonCommand {
        pub fn go_around_sun(id: &Handle, version: Option<u64>) -> Self {
            let actor = Actor::test_from_def(ACTOR_DEF_TEST);
            Self::new(id, version, PersonCommandDetails::GoAroundTheSun, &actor)
        }

        pub fn change_name(id: &Handle, version: Option<u64>, s: &str) -> Self {
            let details = PersonCommandDetails::ChangeName(s.to_string());
            let actor = Actor::test_from_def(ACTOR_DEF_TEST);
            Self::new(id, version, details, &actor)
        }
    }

    //------------ PersonError ---------------------------------------------------

    /// Errors specific to the Person aggregate, should only ever be returned when
    /// applying a command that does not validate.
    #[derive(Clone, Debug)]
    enum PersonError {
        TooOld,
        Custom(String),
    }

    impl fmt::Display for PersonError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                PersonError::TooOld => write!(f, "No person can live longer than 255 years"),
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
        id: Handle,

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
        pub fn id(&self) -> &Handle {
            &self.id
        }
        pub fn name(&self) -> &String {
            &self.name
        }
        pub fn age(&self) -> u8 {
            self.age
        }
    }

    impl Aggregate for Person {
        type Command = PersonCommand;
        type StorableCommandDetails = PersonCommandDetails;
        type Event = PersonEvent;
        type InitEvent = InitPersonEvent;
        type Error = PersonError;

        fn init(event: InitPersonEvent) -> Result<Self, PersonError> {
            let (id, _version, init) = event.unpack();
            Ok(Person {
                id,
                version: 1,
                name: init.name,
                age: 0,
            })
        }

        fn version(&self) -> u64 {
            self.version
        }

        fn apply(&mut self, event: PersonEvent) {
            match event.into_details() {
                PersonEventDetails::NameChanged(name) => self.name = name,
                PersonEventDetails::HadBirthday => self.age += 1,
            }
            self.version += 1;
        }

        fn process_command(&self, command: Self::Command) -> PersonResult {
            match command.into_details() {
                PersonCommandDetails::ChangeName(name) => {
                    let event = PersonEvent::name_changed(&self, name);
                    Ok(vec![event])
                }
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

    #[test]
    fn event_sourcing_framework() {
        let d = test::tmp_dir();

        let counter = Arc::new(EventCounter::default());
        let mut manager = AggregateStore::<Person>::new(&d, "person").unwrap();
        manager.add_listener(counter.clone());

        let id_alice = Handle::from_str("alice").unwrap();
        let alice_init = InitPersonEvent::init(&id_alice, "alice smith");

        manager.add(alice_init).unwrap();

        let mut alice = manager.get_latest(&id_alice).unwrap();
        assert_eq!("alice smith", alice.name());
        assert_eq!(0, alice.age());

        let mut age = 0;
        loop {
            let get_older = PersonCommand::go_around_sun(&id_alice, None);
            alice = manager.command(get_older).unwrap();

            age += 1;
            if age == 21 {
                break;
            }
        }

        assert_eq!("alice smith", alice.name());
        assert_eq!(21, alice.age());

        let change_name = PersonCommand::change_name(&id_alice, Some(22), "alice smith-doe");
        let alice = manager.command(change_name).unwrap();
        assert_eq!("alice smith-doe", alice.name());
        assert_eq!(21, alice.age());

        // Should read state from disk
        let manager = AggregateStore::<Person>::new(&d, "person").unwrap();

        let alice = manager.get_latest(&id_alice).unwrap();
        assert_eq!("alice smith-doe", alice.name());
        assert_eq!(21, alice.age());

        assert_eq!(22, counter.total());

        // Get paginated history
        let mut crit = CommandHistoryCriteria::default();
        crit.set_offset(3);
        crit.set_rows(10);

        let history = manager.command_history(&id_alice, crit).unwrap();
        assert_eq!(history.total(), 22);
        assert_eq!(history.offset(), 3);
        assert_eq!(history.commands().len(), 10);
        assert_eq!(history.commands().first().unwrap().sequence, 4);

        // Get history excluding 'around the sun' commands
        let mut crit = CommandHistoryCriteria::default();
        crit.set_excludes(&["person-around-sun"]);
        let history = manager.command_history(&id_alice, crit).unwrap();
        assert_eq!(history.total(), 1);

        let _ = fs::remove_dir_all(d);
    }
}
