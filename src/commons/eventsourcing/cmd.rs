use std::fmt;

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::commons::{
    actor::Actor,
    api::{CommandHistoryRecord, CommandSummary, StoredEffect},
    eventsourcing::{
        store::CommandKey,
        {Event, Storable},
    },
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

//------------ StoredCommand -------------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredCommand<S: WithStorableDetails> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    #[serde(deserialize_with = "S::deserialize")]
    details: S,
    effect: StoredEffect,
}

impl<S: WithStorableDetails> StoredCommand<S> {
    pub fn new(
        actor: String,
        time: Time,
        handle: MyHandle,
        version: u64,
        sequence: u64,
        details: S,
        effect: StoredEffect,
    ) -> Self {
        StoredCommand {
            actor,
            time,
            handle,
            version,
            sequence,
            details,
            effect,
        }
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn handle(&self) -> &MyHandle {
        &self.handle
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn details(&self) -> &S {
        &self.details
    }

    pub fn effect(&self) -> &StoredEffect {
        &self.effect
    }
}
impl<S: WithStorableDetails> From<StoredCommand<S>> for CommandHistoryRecord {
    fn from(command: StoredCommand<S>) -> Self {
        let summary = command.details.summary();
        let command_key = CommandKey::new(command.sequence, command.time, summary.label.clone());

        CommandHistoryRecord {
            key: command_key.to_string(),
            actor: command.actor,
            timestamp: command.time.timestamp_millis(),
            handle: command.handle,
            version: command.version,
            sequence: command.sequence,
            summary,
            effect: command.effect,
        }
    }
}

//------------ StoredCommandBuilder ------------------------------------------

/// Builder to avoid cloning commands, so they can be sent to the aggregate by value,
/// and we can add the effect later.
pub struct StoredCommandBuilder<C: Command> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64,
    sequence: u64,
    details: C::StorableDetails,
}

impl<C: Command> StoredCommandBuilder<C> {
    pub fn new(cmd: &C, version: u64, sequence: u64) -> StoredCommandBuilder<C> {
        let actor = cmd.actor().to_string();
        let time = Time::now();
        let handle = cmd.handle().clone();
        let details = cmd.store();
        StoredCommandBuilder {
            actor,
            time,
            handle,
            version,
            sequence,
            details,
        }
    }

    fn finish(self, effect: StoredEffect) -> StoredCommand<C::StorableDetails> {
        StoredCommand {
            actor: self.actor,
            time: self.time,
            handle: self.handle,
            version: self.version,
            sequence: self.sequence,
            details: self.details,
            effect,
        }
    }

    pub fn finish_with_events<E: Event>(self, events: &[E]) -> StoredCommand<C::StorableDetails> {
        let events = events.iter().map(|e| e.version()).collect();
        let effect = StoredEffect::Success { events };
        self.finish(effect)
    }

    pub fn finish_with_error<E: fmt::Display>(self, err: &E) -> StoredCommand<C::StorableDetails> {
        let effect = StoredEffect::Error { msg: err.to_string() };
        self.finish(effect)
    }
}
