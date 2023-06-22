use std::fmt;

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::commons::{
    actor::Actor,
    api::{CommandHistoryRecord, CommandSummary},
    eventsourcing::{Event, Storable},
};

//------------ WithStorableDetails -------------------------------------------

/// Must be implemented for all 'StorableDetails' used in Commands.
///
/// In addition to implementing Storable so that the details can be stored
/// *and* retrieved, the details also need to be able to present a generic
/// CommandSummary for use in history.
pub trait WithStorableDetails: Storable + Send + Sync {
    fn summary(&self) -> CommandSummary;
}

//------------ Command -------------------------------------------------------

/// Commands are used to send an intent to change an aggregate.
///
/// Think of this as the data container for your update API, plus some
/// meta-data to ensure that the command is sent to the right instance of an
/// Aggregate, and that concurrency issues are handled.
pub trait Command: fmt::Display + Send + Sync {
    /// Identify the type of storable component for this command. Commands
    /// may contain short-lived things (e.g. an Arc<Signer>) or even secrets
    /// which should not be persisted.
    type StorableDetails: WithStorableDetails;

    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &MyHandle;

    /// The version of the aggregate that this command updates. If this
    /// command should update whatever the latest version happens to be, then
    /// use None here.
    fn version(&self) -> Option<u64>;

    /// The actor who sent the command. There is no default so as to avoid
    /// accidentally attributing a command by a user instead as if it were an
    /// internal command by Krill itself.
    fn actor(&self) -> &str;

    /// Get the storable information for this command
    fn store(&self) -> Self::StorableDetails;
}

//------------ SentCommand ---------------------------------------------------

/// Convenience wrapper so that implementations can just implement
/// ['CommandDetails'] and leave the id and version boilerplate.
#[derive(Clone)]
pub struct SentCommand<C: CommandDetails> {
    handle: MyHandle,
    version: Option<u64>,
    details: C,
    actor: String,
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

impl<C: CommandDetails> SentCommand<C> {
    pub fn new(id: &MyHandle, version: Option<u64>, details: C, actor: &Actor) -> Self {
        let actor_name = if actor.is_user() {
            format!("user:{}", actor.name())
        } else {
            actor.name().to_string()
        };

        SentCommand {
            handle: id.clone(),
            version,
            details,
            actor: actor_name,
        }
    }

    pub fn into_details(self) -> C {
        self.details
    }
}

impl<C: CommandDetails> fmt::Display for SentCommand<C> {
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

/// Implement this for an enum with CommandDetails, so you you can reuse the
/// id and version boilerplate from ['SentCommand'].
pub trait CommandDetails: fmt::Display + Send + Sync + 'static {
    type Event: Event;
    type StorableDetails: WithStorableDetails;

    fn store(&self) -> Self::StorableDetails;
}

pub struct StoredCommandBuilder<D: WithStorableDetails> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64, // version of aggregate this was applied to (successful or not)
    details: D,
}

impl<D: WithStorableDetails> StoredCommandBuilder<D> {
    pub fn new(
        actor: String,
        time: Time,
        handle: MyHandle,
        version: u64, // version of aggregate this was applied to (successful or not)
        details: D,
    ) -> Self {
        StoredCommandBuilder {
            actor,
            time,
            handle,
            version,
            details,
        }
    }

    pub fn finish_with_events<E: Event>(self, events: Vec<E>) -> StoredCommand<D, E> {
        self.with_effect(StoredEffect::success(events))
    }

    pub fn finish_with_error<E: Event>(self, error: impl fmt::Display) -> StoredCommand<D, E> {
        self.with_effect(StoredEffect::error(error))
    }

    fn with_effect<E: Event>(self, effect: StoredEffect<E>) -> StoredCommand<D, E> {
        StoredCommand::new(self.actor, self.time, self.handle, self.version, self.details, effect)
    }
}

//------------ StoredCommand -------------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(bound(deserialize = "E: Event"))]
pub struct StoredCommand<D: WithStorableDetails, E: Event> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64, // version of aggregate this was applied to (successful or not)
    #[serde(deserialize_with = "D::deserialize")]
    details: D,
    effect: StoredEffect<E>,
}

impl<D: WithStorableDetails, E: Event> StoredCommand<D, E> {
    pub fn new(actor: String, time: Time, handle: MyHandle, version: u64, details: D, effect: StoredEffect<E>) -> Self {
        StoredCommand {
            actor,
            time,
            handle,
            version,
            details,
            effect,
        }
    }

    pub fn actor(&self) -> &String {
        &self.actor
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn handle(&self) -> &MyHandle {
        &self.handle
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn details(&self) -> &D {
        &self.details
    }

    pub fn effect(&self) -> &StoredEffect<E> {
        &self.effect
    }

    pub fn events(&self) -> Option<&Vec<E>> {
        match &self.effect {
            StoredEffect::Error { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }

    pub fn into_events(self) -> Option<Vec<E>> {
        match self.effect {
            StoredEffect::Error { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }
}

impl<D: WithStorableDetails, E: Event> From<StoredCommand<D, E>> for CommandHistoryRecord {
    fn from(command: StoredCommand<D, E>) -> Self {
        CommandHistoryRecord {
            actor: command.actor,
            timestamp: command.time.timestamp_millis(),
            handle: command.handle,
            version: command.version,
            summary: command.details.summary(),
            effect: command.effect.into(),
        }
    }
}

//------------ StoredEffect --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result", bound(deserialize = "E: Event"))]
pub enum StoredEffect<E: Event> {
    Error { msg: String },
    Success { events: Vec<E> },
}

impl<E: Event> StoredEffect<E> {
    pub fn error(e: impl fmt::Display) -> Self {
        Self::Error { msg: e.to_string() }
    }

    pub fn success(events: Vec<E>) -> Self {
        Self::Success { events }
    }

    pub fn successful(&self) -> bool {
        match self {
            StoredEffect::Error { .. } => false,
            StoredEffect::Success { .. } => true,
        }
    }

    pub fn events(&self) -> Option<&Vec<E>> {
        match self {
            StoredEffect::Error { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }
}
