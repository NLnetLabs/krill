//! Event sourcing support for Krill

mod agg;
pub use self::agg::Aggregate;

mod evt;
pub use self::evt::{Event, StoredEvent};

mod cmd;
pub use self::cmd::{Command, CommandDetails, SentCommand};

mod store;
pub use self::store::{DiskKeyStore, KeyStore, KeyStoreError, Storable};

mod agg_store;
pub use self::agg_store::{AggregateStore, AggregateStoreError, DiskAggregateStore};

mod listener;
pub use self::listener::{EventCounter, EventListener};

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    //! Example implementation using the eventsourcing module.
    //!
    //! Goal is two-fold: document using a simple domain, and test the module.
    //!

    use std::sync::Arc;

    use serde::Serialize;

    use crate::api::Handle;
    use crate::util::test;

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
            StoredEvent::new(
                id,
                0,
                InitPersonDetails {
                    name: name.to_string(),
                },
            )
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct InitPersonDetails {
        pub name: String,
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
        GoAroundTheSun,
    }

    impl CommandDetails for PersonCommandDetails {
        type Event = PersonEvent;
    }

    impl PersonCommand {
        pub fn go_around_sun(id: &Handle, version: Option<u64>) -> Self {
            Self::new(id, version, PersonCommandDetails::GoAroundTheSun)
        }

        pub fn change_name(id: &Handle, version: Option<u64>, s: &str) -> Self {
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
        TooOld,
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
        pub fn version(&self) -> u64 {
            self.version
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
        type Event = PersonEvent;
        type InitEvent = InitPersonEvent;
        type Error = PersonError;

        fn init(event: InitPersonEvent) -> Result<Self, PersonError> {
            let (id, _version, init) = event.unwrap();
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
    fn test() {
        test::test_under_tmp(|d| {
            let counter = Arc::new(EventCounter::default());
            let mut manager = DiskAggregateStore::<Person>::new(&d, "person").unwrap();
            manager.add_listener(counter.clone());

            let id_alice = Handle::from("alice");
            let alice_init = InitPersonEvent::init(&id_alice, "alice smith");

            manager.add(alice_init).unwrap();

            let mut alice = manager.get_latest(&id_alice).unwrap();
            assert_eq!("alice smith", alice.name());
            assert_eq!(0, alice.age());

            let mut age = 0;
            loop {
                let get_older = PersonCommand::go_around_sun(&id_alice, None);
                let events = alice.process_command(get_older).unwrap();
                alice = manager.update(&id_alice, alice, events).unwrap();

                age += 1;
                if age == 21 {
                    break;
                }
            }

            assert_eq!("alice smith", alice.name());
            assert_eq!(21, alice.age());

            let change_name = PersonCommand::change_name(&id_alice, Some(22), "alice smith-doe");
            let events = alice.process_command(change_name).unwrap();
            let alice = manager.update(&id_alice, alice, events).unwrap();
            assert_eq!("alice smith-doe", alice.name());
            assert_eq!(21, alice.age());

            // Should read state from disk
            let manager = DiskAggregateStore::<Person>::new(&d, "person").unwrap();

            let alice = manager.get_latest(&id_alice).unwrap();
            assert_eq!("alice smith-doe", alice.name());
            assert_eq!(21, alice.age());

            assert_eq!(22, counter.total())
        })
    }
}
