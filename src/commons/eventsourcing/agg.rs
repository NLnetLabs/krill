use rpki::ca::idexchange::MyHandle;

use super::{
    AggregateStoreError, Command, Event, InitCommand, InitEvent, Storable,
    StoredCommand,
};
use crate::commons::eventsourcing::WithStorableDetails;

//------------ Aggregate -----------------------------------------------------

/// This trait defines an Aggregate for use with the event sourcing framework.
///
/// An aggregate is term coming from DDD (Domain Driven Design) and is used to
/// describe an abstraction where a cluster of structs (the aggregate)
/// provides a 'bounded context' for functionality that is exposed only by a
/// single top-level struct: the aggregate root. Here we name this aggregate
/// root simply 'Aggregate' for brevity.
///
/// The aggregate root is responsible for guarding its own consistency. In the
/// context of the event sourcing framework this means that it can be sent a
/// command, through the [`process_command`] method. A command represents an
/// intent to achieve something sent by the used of the aggregate. The
/// Aggregate will then take this intent and decide whether it can be
/// executed. If successful a number of 'events' are returned that contain
/// state changes to the aggregate. These events still need to be applied to
/// become persisted.
pub trait Aggregate: Storable + Send + Sync + 'static {
    type InitCommand: InitCommand<
        StorableDetails = Self::StorableCommandDetails,
    >;
    type InitEvent: InitEvent;

    type Command: Command<StorableDetails = Self::StorableCommandDetails>;
    type Event: Event;

    type StorableCommandDetails: WithStorableDetails;

    type Error: std::error::Error + Send + Sync + From<AggregateStoreError>;

    /// Creates a new instance. Expects an InitEvent with data needed to
    /// initialize the instance. This is not allowed to fail - it's just
    /// data and MUST not have any side effects.
    ///
    /// The InitEvent is generated once using `process_init_command`.
    ///
    /// The handle is not strictly necessary inside an aggregate, it is
    /// what you use to refer to an instance in the AggregateStore. But,
    /// it's quite convenient to store it inside an Aggregate as well.
    ///
    /// More importantly, the handle is not typically included in the
    /// InitEvent itself.
    fn init(handle: MyHandle, event: Self::InitEvent) -> Self;

    /// Tries to initialise a new InitEvent for a new instance. This
    /// can fail. The InitEvent is not applied here, but returned so
    /// that we can re-build state from history.
    fn process_init_command(
        command: Self::InitCommand,
    ) -> Result<Self::InitEvent, Self::Error>;

    /// Returns the current version of the aggregate.
    fn version(&self) -> u64;

    /// Increments current version of the aggregate.
    fn increment_version(&mut self);

    /// Applies the event to this. This MUST not result in any errors, and
    /// this MUST be side-effect free. Applying the event just updates the
    /// internal data of the aggregate.
    ///
    /// Note the event is moved. This is done because we want to avoid
    /// doing additional allocations where we can.
    fn apply(&mut self, event: Self::Event);

    /// Applies a processed command:
    /// - assumes that this is for THIS Aggregate and version
    /// - increments the version for this aggregate
    /// - applies any contained event
    ///
    /// NOTE:
    fn apply_command(&mut self, command: StoredCommand<Self>) {
        self.increment_version();
        if let Some(events) = command.into_events() {
            for event in events {
                self.apply(event);
            }
        }
    }

    /// Processes a command. I.e. validate the command, and return either an
    /// error, or a list of events that will result in the desired new state.
    /// If the list is empty then this was a no-op.
    ///
    /// The events are not applied here, but need to be applied using
    /// [`apply_command`] so that we can re-build state from history.
    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Event>, Self::Error>;
}
