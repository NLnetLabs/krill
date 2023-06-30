//! Event sourcing support for Krill

mod agg;
pub use self::agg::*;

mod wal;
pub use self::wal::*;

mod evt;
pub use self::evt::*;

mod cmd;
pub use self::cmd::*;

mod store;
pub use self::store::*;

mod listener;
pub use self::listener::*;

pub mod locks;

mod kv;
pub use self::kv::{segment, Key, KeyValueError, KeyValueStore, Scope, Segment, SegmentBuf, SegmentExt};

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    //! Example implementation using the eventsourcing module.
    //!
    //! Goal is two-fold: document using a simple domain, and test the module.
    //!

    use std::{fmt, str::FromStr, sync::Arc};

    use serde::Serialize;

    use rpki::ca::idexchange::MyHandle;

    use crate::{
        commons::{
            actor::Actor,
            api::{CommandHistoryCriteria, CommandSummary},
        },
        constants::ACTOR_DEF_TEST,
        test::tmp_storage,
    };

    use super::*;

    //------------ PersonInitEvent -----------------------------------------------

    /// Every aggregate defines their own initialization event. This is the first
    /// event stored for an instance.
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
    type PersonInitCommand = SentInitCommand<PersonInitCommandDetails>;

    impl PersonInitCommand {
        fn make(id: &MyHandle, name: String) -> Self {
            let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
            PersonInitCommand::new(id, PersonInitCommandDetails { name }, &actor)
        }
    }

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

    /// Every aggregate defines their own set of events - i.e. state changes. The
    /// state of an aggregate can only change when events are applied. And events
    /// cannot have side effects. If they did, then replaying events would become
    /// problematic.
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
                PersonEvent::NameChanged(new_name) => write!(f, "changed name to '{}'", new_name),
                PersonEvent::HadBirthday => write!(f, "went around the sun."),
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

    impl CommandDetails for PersonCommandDetails {
        type Event = PersonEvent;
        type StorableDetails = PersonStorableCommand;

        fn store(&self) -> Self::StorableDetails {
            match self {
                PersonCommandDetails::ChangeName(name) => PersonStorableCommand::ChangeName(name.clone()),
                PersonCommandDetails::GoAroundTheSun => PersonStorableCommand::GoAroundTheSun,
            }
        }
    }

    impl PersonCommand {
        pub fn go_around_sun(id: &MyHandle, version: Option<u64>) -> Self {
            let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
            Self::new(id, version, PersonCommandDetails::GoAroundTheSun, &actor)
        }

        pub fn change_name(id: &MyHandle, version: Option<u64>, s: &str) -> Self {
            let details = PersonCommandDetails::ChangeName(s.to_string());
            let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
            Self::new(id, version, details, &actor)
        }
    }

    //------------ PersonStorableCommand -----------------------------------------

    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    enum PersonStorableCommand {
        Initialise,
        ChangeName(String),
        GoAroundTheSun,
    }

    impl fmt::Display for PersonStorableCommand {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                PersonStorableCommand::Initialise => write!(f, "Initialise person"),
                PersonStorableCommand::ChangeName(name) => write!(f, "Change name to {}", name),
                PersonStorableCommand::GoAroundTheSun => write!(f, "Go around the sun"),
            }
        }
    }

    impl WithStorableDetails for PersonStorableCommand {
        fn summary(&self) -> CommandSummary {
            match self {
                PersonStorableCommand::Initialise => CommandSummary::new("person-init", self),
                PersonStorableCommand::ChangeName(name) => {
                    CommandSummary::new("person-change-name", self).with_arg("name", name)
                }
                PersonStorableCommand::GoAroundTheSun => CommandSummary::new("person-around-sun", self),
            }
        }

        fn make_init() -> Self {
            Self::Initialise
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

    //------------ Person ------------------------------------------------------

    /// Defines a person object. Persons have a name and an age.
    ///
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

        fn init(id: MyHandle, event: PersonInitEvent) -> Self {
            Person {
                id,
                version: 1,
                name: event.name,
                age: 0,
            }
        }

        fn process_init_command(command: Self::InitCommand) -> Result<Self::InitEvent, Self::Error> {
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

        fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
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

    #[test]
    fn event_sourcing_framework() {
        // crate::test::test_under_tmp(|data_dir| {
        //     let storage_uri = crate::commons::util::storage::storage_uri_from_data_dir(&data_dir).unwrap();

        let storage_uri = tmp_storage();

        let counter = Arc::new(EventCounter::default());
        let mut manager = AggregateStore::<Person>::create(&storage_uri, segment!("person"), false).unwrap();
        manager.add_post_save_listener(counter.clone());

        let alice_name = "alice smith".to_string();
        let alice_handle = MyHandle::from_str("alice").unwrap();
        let alice_init_cmd = PersonInitCommand::make(&alice_handle, alice_name);

        manager.add(alice_init_cmd).unwrap();

        let mut alice = manager.get_latest(&alice_handle).unwrap();
        assert_eq!("alice smith", alice.name());
        assert_eq!(0, alice.age());

        let mut age = 0;
        loop {
            let get_older = PersonCommand::go_around_sun(&alice_handle, None);
            alice = manager.command(get_older).unwrap();

            age += 1;
            if age == 21 {
                break;
            }
        }

        assert_eq!("alice smith", alice.name());
        assert_eq!(21, alice.age());

        let change_name = PersonCommand::change_name(&alice_handle, Some(22), "alice smith-doe");
        let alice = manager.command(change_name).unwrap();
        assert_eq!("alice smith-doe", alice.name());
        assert_eq!(21, alice.age());

        // Should read state from disk
        let manager = AggregateStore::<Person>::create(&storage_uri, segment!("person"), false).unwrap();

        let alice = manager.get_latest(&alice_handle).unwrap();
        assert_eq!("alice smith-doe", alice.name());
        assert_eq!(21, alice.age());

        assert_eq!(22, counter.total());

        // Get paginated history
        let mut crit = CommandHistoryCriteria::default();
        crit.set_offset(3);
        crit.set_rows(10);

        let history = manager.command_history(&alice_handle, crit).unwrap();
        assert_eq!(history.total(), 22);
        assert_eq!(history.offset(), 3);
        assert_eq!(history.commands().len(), 10);
        assert_eq!(history.commands().first().unwrap().version, 4);

        // Get history excluding 'around the sun' commands
        let mut crit = CommandHistoryCriteria::default();
        crit.set_excludes(&["person-around-sun"]);
        let history = manager.command_history(&alice_handle, crit).unwrap();
        assert_eq!(history.total(), 1);
        // })
    }
}
