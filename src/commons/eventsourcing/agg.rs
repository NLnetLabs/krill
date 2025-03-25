//! Definitions related to aggregates.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::fmt;
use rpki::ca::idexchange::MyHandle;
use rpki::repository::x509::Time;
use serde::{Deserialize, Serialize};
use crate::api;
use crate::api::history::{CommandHistoryRecord, CommandSummary};
use crate::commons::actor::Actor;
use super::store::{AggregateStoreError, Storable};


//------------ Aggregate -----------------------------------------------------

/// This trait defines an aggregate for use with the event sourcing framework.
///
/// An aggregate is term coming from DDD (Domain Driven Design) and is used
/// to describe an abstraction where a cluster of structs (the aggregate)
/// provides a 'bounded context' for functionality that is exposed only by a
/// single top-level struct: the aggregate root. Here we name this aggregate
/// root simply ‘aggregate’ for brevity.
///
/// The aggregate root is responsible for guarding its own consistency. In
/// the context of the event sourcing framework this means that it can be
/// sent a command, through the [`process_command`][Self::process_command]
/// method. A command represents an intent to achieve something sent by the
/// user of the aggregate. The aggregate will then take this intent and
/// decide whether it can be executed. If successful a number of events
/// are returned that contain state changes to the aggregate. These events
/// still need to be applied to become persisted.
//
//  XXX This needs to be 'static due to the event listeners in the aggregate
//      store.
pub trait Aggregate: Storable + 'static {
    /// The type representing the initial command.
    type InitCommand: InitCommand<
        StorableDetails = Self::StorableCommandDetails,
    >;

    /// The type representing consecutive commands.
    type Command: Command<StorableDetails = Self::StorableCommandDetails>;

    /// The type representing the details of a command to be stored.
    type StorableCommandDetails: WithStorableDetails;

    /// The type representing the initial event.
    type InitEvent: InitEvent;

    /// The type representing consecutive events.
    type Event: Event;

    /// The type returned when processing a command fails.
    type Error: std::error::Error + Send + Sync + From<AggregateStoreError>;

    /// Creates a new instance.
    ///
    /// Expects an [`InitEvent`][Self::InitEvent] with data needed to
    /// initialize the instance. Initialization is not allowed to fail – it
    /// is just data and must not have any side effects.
    ///
    /// The init event is generated once using
    /// [`process_init_command`][Self::process_init_command].
    ///
    /// The handle is not strictly necessary inside an aggregate, it is
    /// what you use to refer to an instance in the AggregateStore. But,
    /// it is quite convenient to store it inside an Aggregate as well.
    /// More importantly, the handle is not typically included in the
    /// init event itself.
    fn init(handle: &MyHandle, event: Self::InitEvent) -> Self;

    /// Tries to initialise a new InitEvent for a new instance.
    ///
    /// This can fail. The init event resulting from successfull processing
    /// is not applied here, but returned so that we can re-build state from
    /// history.
    fn process_init_command(
        command: Self::InitCommand,
    ) -> Result<Self::InitEvent, Self::Error>;

    /// Processes a command.
    ///
    /// An implementation should validate the command and return either an
    /// error or a list of events that will result in the desired new state.
    /// If the list is empty then this was a no-op.
    ///
    /// The events are not applied here, but need to be applied using
    /// [`apply_command`][Self::apply_command] so that we can re-build
    /// state from history.
    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Event>, Self::Error>;

    /// Returns the current version of the aggregate.
    fn version(&self) -> u64;

    /// Increments current version of the aggregate.
    fn increment_version(&mut self);

    /// Applies an event to the aggregate.
    ///
    /// This must not result in any errors, and must be side-effect free.
    /// Applying the event only updates the internal data of the aggregate.
    ///
    /// Note the event is moved, so you can use data from the event when
    /// updating the aggregate’s state without cloning.
    fn apply(&mut self, event: Self::Event);

    /// Applies a stored command.
    ///
    /// The method increases the aggregate’s version – it thus assumes that
    /// the command is applied to the correct version of the correct
    /// aggregate –, and then applies each of the contained events in order.
    //
    // XXX This should probably be a method on `AggregateStore` rather than
    //     on this trait.
    fn apply_command(&mut self, command: StoredCommand<Self>) {
        self.increment_version();
        if let Some(events) = command.into_events() {
            for event in events {
                self.apply(event);
            }
        }
    }
}


//------------ InitEvent ----------------------------------------------------

/// A type that represents the initial event creating a new aggregate.
pub trait InitEvent:
    fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static
{
}


//------------ Event --------------------------------------------------------

/// A type that represents events applied to an existing aggregate.
pub trait Event:
    fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static
{
}


//------------ WithStorableDetails -------------------------------------------

/// A type representing the details of a command to be stored.
///
/// Note that command details are stored purely for auditing reasons. Only
/// events are replayed when re-creating the state of an aggregate.
pub trait WithStorableDetails: Storable {
    /// Converts the details into a command summary for the API.
    fn summary(&self) -> CommandSummary;

    /// Creates an instance representing the initialisation command.
    ///
    /// No data is passed to this function, so the value created this way
    /// will not contain any data for reporting. This should be fine, as
    /// all relevant data for history will be in the init event.
    fn make_init() -> Self;
}


//------------ InitCommand ---------------------------------------------------

/// The command used to create a new aggregate instance.
pub trait InitCommand: Clone {
    /// The type representing the storable components of this command.
    ///
    /// Commands may contain short-lived things (e.g. an `Arc<Signer>`) or
    /// even secrets which should not be persisted.
    type StorableDetails: WithStorableDetails;

    /// Returns an identifier for this instance.
    ///
    /// This is useful when storing and retrieving the command.
    fn handle(&self) -> &MyHandle;

    /// Returns the actor who sent the command.
    ///
    /// There is no default so as to avoid accidentally attributing a
    /// command by a user instead as if it were an internal command by
    /// Krill itself.
    fn actor(&self) -> &str;

    /// Returns the storable information for this command
    fn store(&self) -> Self::StorableDetails;
}


//------------ SentInitCommand -----------------------------------------------

/// An convenience wrapper for an init command keeping handle and actor.
///
/// This type can be used when the handle and actor are simply kept in the
/// command. All additional information is kept in a struct implementing
/// ['InitCommandDetails'].
#[derive(Clone, Debug)]
pub struct SentInitCommand<I> {
    /// The handle identifying the aggregate entity.
    handle: MyHandle,

    /// The actor initiating the command.
    actor: String,

    /// The details of the command.
    details: I,
}

impl<I> SentInitCommand<I> {
    /// Creates a new init command.
    pub fn new(id: MyHandle, details: I, actor: &Actor) -> Self {
        SentInitCommand {
            handle: id,
            details,
            actor: actor.to_string(),
        }
    }

    /// Returns a reference to the details.
    pub fn details(&self) -> &I {
        &self.details
    }

    /// Converts the command into the details.
    pub fn into_details(self) -> I {
        self.details
    }
}

impl<I: InitCommandDetails> InitCommand for SentInitCommand<I> {
    type StorableDetails = I::StorableDetails;

    fn handle(&self) -> &MyHandle {
        &self.handle
    }

    fn actor(&self) -> &str {
        &self.actor
    }

    fn store(&self) -> Self::StorableDetails {
        self.details.store()
    }
}

impl<I> fmt::Display for SentInitCommand<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "initialise '{}'", self.handle)
    }
}


//------------ InitCommandDetails --------------------------------------------

/// A type containing the detail for an init command.
///
/// This is all the data from an [`InitCommand`] except for the handle and
/// actor and should be used with a ['SentInitCommand'].
pub trait InitCommandDetails: Clone {
    /// The type representing the storable components of this command.
    ///
    /// Commands may contain short-lived things (e.g. an `Arc<Signer>`) or
    /// even secrets which should not be persisted.
    type StorableDetails: WithStorableDetails;

    /// Returns the storable information for this command
    fn store(&self) -> Self::StorableDetails;
}


//------------ Command -------------------------------------------------------

/// A commands used to send an intent to change an aggregate.
///
/// Think of this as the data container for your update API, plus some
/// meta-data to ensure that the command is sent to the right instance of an
/// Aggregate, and that concurrency issues are handled.
pub trait Command: Clone {
    /// The type representing the storable components of this command.
    ///
    /// Commands may contain short-lived things (e.g. an `Arc<Signer>`) or
    /// even secrets which should not be persisted.
    type StorableDetails: WithStorableDetails;

    /// Identifies the aggregate the command is applied to.
    fn handle(&self) -> &MyHandle;

    /// Returns the version of the aggregate that this command updates.
    ///
    /// If this command should update whatever the latest version happens to
    /// be, return `None` here.
    fn version(&self) -> Option<u64>;

    /// Returns the actor who sent the command.
    ///
    /// There is no default so as to avoid accidentally attributing a command
    /// by a user instead as if it were an internal command by Krill itself.
    fn actor(&self) -> &str;

    /// Returns the storable information for this command
    fn store(&self) -> Self::StorableDetails;
}


//------------ SentCommand ---------------------------------------------------

/// An convenience wrapper for a command keeping handle, version, and actor.
///
/// This type can be used when the handle, version, and actor are simply kept
/// in the command. All additional information is kept in a struct
/// implementing ['CommandDetails'].
#[derive(Clone)]
pub struct SentCommand<C> {
    /// The handle identifying the aggregate entity.
    handle: MyHandle,

    /// The version of the aggregate to apply the command to.
    ///
    /// If this is `None`, then the command should be applied to the current
    /// version.
    version: Option<u64>,

    /// The actor initiating the command.
    actor: String,

    /// The details of the command.
    details: C,
}

impl<C> SentCommand<C> {
    /// Creates a new command.
    pub fn new(
        id: MyHandle,
        version: Option<u64>,
        details: C,
        actor: &Actor,
    ) -> Self {
        SentCommand {
            handle: id,
            version,
            details,
            actor: actor.audit_name(),
        }
    }

    /// Converts the command into the details.
    pub fn into_details(self) -> C {
        self.details
    }
}

impl<C: CommandDetails> Command for SentCommand<C> {
    type StorableDetails = C::StorableDetails;

    fn handle(&self) -> &MyHandle {
        &self.handle
    }

    fn version(&self) -> Option<u64> {
        self.version
    }

    fn store(&self) -> Self::StorableDetails {
        self.details.store()
    }

    fn actor(&self) -> &str {
        &self.actor
    }
}

impl<C: fmt::Display> fmt::Display for SentCommand<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let version_string = self
            .version
            .as_ref()
            .map(u64::to_string)
            .unwrap_or_else(|| "any".to_string());
        write!(
            f,
            "id '{}' version '{}' details '{}'",
            self.handle, version_string, self.details
        )
    }
}


//------------ CommandDetails ------------------------------------------------

/// A type containing the detail for a command.
///
/// This is all the data from an [`Command`] except for the handle, version,
/// and actor, and should be used with a ['SentInitCommand'].
pub trait CommandDetails: Clone {
    type Event: Event;
    type StorableDetails: WithStorableDetails;

    fn store(&self) -> Self::StorableDetails;
}


//------------ StoredCommandBuilder ------------------------------------------

/// Helper type to create StoredCommand instances.
pub struct StoredCommandBuilder<A: Aggregate> {
    /// The actor initiating the command.
    actor: String,

    /// The time the command was processed.
    time: Time,

    /// The handle of the instance the command applies to.
    handle: MyHandle,

    /// The version of aggregate this was applied to.
    version: u64,

    /// The details of the command.
    details: A::StorableCommandDetails,
}

impl<A: Aggregate> StoredCommandBuilder<A> {
    /// Creates a new builder.
    pub fn new(
        actor: String,
        time: Time,
        handle: MyHandle,
        version: u64,
        details: A::StorableCommandDetails,
    ) -> Self {
        StoredCommandBuilder {
            actor,
            time,
            handle,
            version,
            details,
        }
    }

    /// Processing the command resulted in the given init event.
    pub fn finish_with_init_event(
        self,
        init_event: A::InitEvent,
    ) -> StoredCommand<A> {
        self.finish_with_effect(StoredEffect::Init { init: init_event })
    }

    /// Processing the command resulted in the given list of events.
    pub fn finish_with_events(
        self,
        events: Vec<A::Event>,
    ) -> StoredCommand<A> {
        self.finish_with_effect(StoredEffect::Success { events })
    }

    /// Processing the command resulted in the given error.
    pub fn finish_with_error(
        self,
        error: impl fmt::Display,
    ) -> StoredCommand<A> {
        self.finish_with_effect(
            StoredEffect::Error { msg: error.to_string() }
        )
    }

    /// Processing the command resulted in the given effect.
    fn finish_with_effect(
        self,
        effect: StoredEffect<A::Event, A::InitEvent>,
    ) -> StoredCommand<A> {
        StoredCommand::new(
            self.actor,
            self.time,
            self.handle,
            self.version,
            self.details,
            effect,
        )
    }
}


//------------ StoredCommand -------------------------------------------------

/// A description of a command that was processed and its effect.
///
/// Commands that turn out to be no-ops (no events, no errors) should not be
/// stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(bound(deserialize = "A::Event: Event"))]
pub struct StoredCommand<A: Aggregate> {
    /// The actor initiating the command.
    actor: String,

    /// The time the command was processed.
    time: Time,

    /// The handle of the instance the command applies to.
    handle: MyHandle,

    /// The version of aggregate this was applied to.
    version: u64,

    /// The details of the command.
    #[serde(deserialize_with = "A::StorableCommandDetails::deserialize")]
    details: A::StorableCommandDetails,

    /// The effect of the command.
    effect: StoredEffect<A::Event, A::InitEvent>,
}

impl<A: Aggregate> StoredCommand<A> {
    /// Creates a new command.
    ///
    /// This is not `pub` since `StoredCommandBuilder` is usually used.
    fn new(
        actor: String,
        time: Time,
        handle: MyHandle,
        version: u64,
        details: A::StorableCommandDetails,
        effect: StoredEffect<A::Event, A::InitEvent>,
    ) -> Self {
        StoredCommand {
            actor,
            time,
            handle,
            version,
            details,
            effect,
        }
    }

    /// Starts building a stored command by creating a builder.
    pub fn builder(
        actor: String,
        time: Time,
        handle: MyHandle,
        version: u64,
        details: A::StorableCommandDetails,
    ) -> StoredCommandBuilder<A> {
        StoredCommandBuilder::new(actor, time, handle, version, details)
    }

    /// Returns the audit name of the actor that initiated the command.
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Returns the time when the command was processed.
    pub fn time(&self) -> Time {
        self.time
    }

    /// Returns the handle of the instance this command applies to.
    pub fn handle(&self) -> &MyHandle {
        &self.handle
    }

    /// Returns the version of aggregate the command was applied to.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the details of the command.
    pub fn details(&self) -> &A::StorableCommandDetails {
        &self.details
    }

    /// Returns the effect of the command.
    pub fn effect(&self) -> &StoredEffect<A::Event, A::InitEvent> {
        &self.effect
    }

    /// Returns the events if the effect of the command was a list of events.
    pub fn events(&self) -> Option<&Vec<A::Event>> {
        match &self.effect {
            StoredEffect::Error { .. } | StoredEffect::Init { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }

    /// Converts into the events if the effect was a list of events.
    pub fn into_events(self) -> Option<Vec<A::Event>> {
        match self.effect {
            StoredEffect::Error { .. } | StoredEffect::Init { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }

    /// Converts into the init event if the effect was an init event.
    pub fn into_init(self) -> Option<A::InitEvent> {
        match self.effect {
            StoredEffect::Init { init } => Some(init),
            _ => None,
        }
    }

    /// Returns the history details of the command.
    pub fn to_history_details(&self) -> api::history::CommandDetails
    where
        <A as Aggregate>::StorableCommandDetails: fmt::Display
    {
        api::history::CommandDetails {
            actor: self.actor.clone(),
            time: self.time,
            handle: self.handle.clone(),
            version: self.version,
            msg: self.details.to_string(),
            details: to_json_value(&self.details),
            effect: self.effect.to_history_details(),
        }
    }

    /// Converts the command into a command history record.
    pub fn into_history_record(self) -> CommandHistoryRecord {
        CommandHistoryRecord {
            actor: self.actor,
            timestamp: self.time.timestamp_millis(),
            handle: self.handle,
            version: self.version,
            summary: self.details.summary(),
            effect: self.effect.into(),
        }
    }
}


//------------ StoredEffect --------------------------------------------------

/// The effect of processing a command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "snake_case",
    tag = "result",
    bound(deserialize = "E: Event")
)]
pub enum StoredEffect<E: Event, I: InitEvent> {
    /// The command resulted in an error with the given message.
    Error { msg: String },

    /// The command was successful and resulted resulted in the given events.
    Success { events: Vec<E> },

    /// The command was successful and resulted in an init event.
    Init { init: I },
}

impl<E: Event, I: InitEvent> StoredEffect<E, I> {
    fn to_history_details(&self) -> api::history::CommandEffect {
        match self {
            Self::Error { msg } => {
                api::history::CommandEffect::Error { msg: msg.clone() }
            }
            Self::Success { events } => {
                api::history::CommandEffect::Success {
                    events: events.iter().map(|ev| {
                        api::history::CommandEffectEvent {
                            msg: ev.to_string(),
                            details: to_json_value(ev)
                        }
                    }).collect(),
                }
            }
            Self::Init { init } => {
                api::history::CommandEffect::Init {
                    init: api::history::CommandEffectEvent {
                        msg: init.to_string(),
                        details: to_json_value(init),
                    }
                }
            }
        }
    }
}


//------------ PreSaveEventListener ------------------------------------------

/// A listener that receives events before the aggregate is saved.
///
/// The listener is allowed to return an error in case of issues, which will
/// will result in rolling back the intended change to an aggregate.
pub trait PreSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, events: &[A::Event]) -> Result<(), A::Error>;
}

//------------ PostSaveEventListener -----------------------------------------

/// A listener that receives events after the aggregate is saved.
///
/// The listener is not allowed to fail.
pub trait PostSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, events: &[A::Event]);
}


//------------ Helper Functions ----------------------------------------------

/// Unfailably creates a JSON value from a serializable object.
///
/// If serializing fails, creates a placeholder value with the error message.
fn to_json_value<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_else(|err| {
        serde_json::json!({ "serialization_error": err.to_string() })
    })
}

