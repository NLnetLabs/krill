use std::fmt;
use std::path::Path;

use super::{
    Command,
    Event,
    Storable
};


//------------ AggregateId ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AggregateId(String);


impl AggregateId {
    pub fn as_str(&self) -> &str {
        &self.0.as_str()
    }
}

impl From<&str> for AggregateId {
    fn from(s: &str) -> Self {
        AggregateId(s.to_string())
    }
}

impl From<String> for AggregateId {
    fn from(s: String) -> Self {
        AggregateId(s)
    }
}

impl AsRef<str> for AggregateId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<String> for AggregateId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl AsRef<Path> for AggregateId {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl fmt::Display for AggregateId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ Aggregate -----------------------------------------------------

pub trait Aggregate: Storable + Send + Sync + 'static {

    type Command: Command<Event = Self::Event>;
    type Event: Event;
    type InitEvent: Event;
    type Error: std::error::Error;

    /// Creates a new instance. Expects an event with data needed to
    /// initialise the instance. Typically this means that a specific
    /// 'create' event is passed, with all the needed data, or just an empty
    /// marker if no data is needed. Implementations must return an error in
    /// case the instance cannot be created.
    fn init(event: Self::InitEvent) -> Result<Self, Self::Error>;

    /// Returns the current version of the aggregate.
    fn version(&self) -> u64;

    /// Applies the event to this. This MUST not result in any errors, and
    /// this MUST be side-effect free. Applying the event just updates the
    /// internal data of the aggregate.
    ///
    /// Note the event is moved. This is done because we want to avoid
    /// doing additional allocations where we can.
    fn apply(&mut self, event: Self::Event);

    /// Applies all events. Assumes that the list ordered, starting with the
    /// oldest event, applicable, self.version matches the oldest event, and
    /// contiguous, i.e. there are no missing events.
    fn apply_all(&mut self, events: Vec<Self::Event>) {
        for event in events {
            self.apply(event);
        }
    }

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these event here.
    ///
    /// The command is moved, because we want to enable moving its data
    /// without reallocating.
    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error>;
}