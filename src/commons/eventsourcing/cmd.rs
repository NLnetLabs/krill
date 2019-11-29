use std::fmt;

use rpki::x509::Time;

use crate::commons::api::Handle;
use crate::commons::eventsourcing::Event;

//------------ Command -------------------------------------------------------

/// Commands are used to send an intent to change an aggregate.
///
/// Think of this as the data container for your update API, plus some
/// meta-data to ensure that the command is sent to the right instance of an
/// Aggregate, and that concurrency issues are handled.
pub trait Command: fmt::Display {
    /// Identify the type of event returned by the aggregate that uses this
    /// command. This is needed because we may need to check whether a
    /// command conflicts with recent events.
    type Event: Event;

    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &Handle;

    /// The version of the aggregate that this command updates. If this
    /// command should update whatever the latest version happens to be, then
    /// use None here.
    fn version(&self) -> Option<u64>;

    /// The actor who sent the command. Defaults to "krill" so that it is not
    /// mandatory to implement this.
    fn actor(&self) -> &str {
        "krill"
    }

    /// In case of concurrent processing of commands, the aggregate may be
    /// outdated when a command is applied. In such cases this method expects
    /// the list of events that happened since the ['affected_version'] and
    /// will return whether there is a conflict. If there is no conflict that
    /// the command may be applied again.
    ///
    /// Note that this defaults to true, which is the safe choice when in
    /// doubt. If you choose to implement this, then you will also need to
    /// implement the ['set_affected_version'] function.
    fn conflicts(&self, _events: &[Self::Event]) -> bool {
        true
    }

    /// Get a summary for the command audit log
    fn summary(&self) -> String;
}

//------------ SentCommand ---------------------------------------------------

/// Convenience wrapper so that implementations can just implement
/// ['CommandDetails'] and leave the id and version boilerplate.
#[derive(Clone)]
pub struct SentCommand<C: CommandDetails> {
    handle: Handle,
    version: Option<u64>,
    details: C,
}

impl<C: CommandDetails> Command for SentCommand<C> {
    type Event = C::Event;

    fn handle(&self) -> &Handle {
        &self.handle
    }

    fn version(&self) -> Option<u64> {
        self.version
    }

    fn summary(&self) -> String {
        self.details.to_string()
    }
}

impl<C: CommandDetails> SentCommand<C> {
    pub fn new(id: &Handle, version: Option<u64>, details: C) -> Self {
        SentCommand {
            handle: id.clone(),
            version,
            details,
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
pub trait CommandDetails: fmt::Display + 'static {
    type Event: Event;
}

//------------ StoredCommand -------------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredCommand {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,
    summary: String,
    effect: StoredEffect,
}

impl StoredCommand {
    pub fn time(&self) -> Time {
        self.time
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

//------------ StoredEffect --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEffect {
    Error(String),
    Events(Vec<u64>),
}

//------------ StoredCommandBuilder ------------------------------------------

/// Builder to avoid cloning commands, so they can be sent to the aggregate by value,
/// and we can add the effect later.
pub struct StoredCommandBuilder {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,
    summary: String,
}

impl StoredCommandBuilder {
    pub fn new<C: Command>(cmd: &C, version: u64) -> Self {
        let actor = cmd.actor().to_string();
        let time = Time::now();
        let handle = cmd.handle().clone();
        let summary = cmd.summary();
        StoredCommandBuilder {
            actor,
            time,
            handle,
            version,
            summary,
        }
    }

    fn finish(self, effect: StoredEffect) -> StoredCommand {
        StoredCommand {
            actor: self.actor,
            time: self.time,
            handle: self.handle,
            version: self.version,
            summary: self.summary,
            effect,
        }
    }

    pub fn finish_with_events<E: Event>(self, events: &[E]) -> StoredCommand {
        let events = events.iter().map(|e| e.version()).collect();
        let effect = StoredEffect::Events(events);
        self.finish(effect)
    }

    pub fn finish_with_error<E: fmt::Display>(self, err: &E) -> StoredCommand {
        let effect = StoredEffect::Error(err.to_string());
        self.finish(effect)
    }
}
