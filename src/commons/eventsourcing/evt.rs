use crate::commons::api::Handle;

use std::fmt;

use super::Storable;

pub trait InitEvent: fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static {}

//------------ Event --------------------------------------------------------

pub trait Event: fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &Handle;

    /// The version of the aggregate that this event updates. An aggregate that
    /// is currently at version x, will get version x + 1, when the event for
    /// version x is applied.
    fn version(&self) -> u64;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredEvent<E: fmt::Display + Eq + PartialEq + Storable + 'static> {
    id: Handle,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E,
}

impl<E: fmt::Display + Eq + PartialEq + Storable + Send + Sync + 'static> StoredEvent<E> {
    pub fn new(id: &Handle, version: u64, event: E) -> Self {
        StoredEvent {
            id: id.clone(),
            version,
            details: event,
        }
    }

    pub fn details(&self) -> &E {
        &self.details
    }

    pub fn into_details(self) -> E {
        self.details
    }

    /// Return the parts of this event.
    pub fn unpack(self) -> (Handle, u64, E) {
        (self.id, self.version, self.details)
    }
}

impl<E: fmt::Display + Eq + PartialEq + Storable + Send + Sync + 'static> Event for StoredEvent<E> {
    fn handle(&self) -> &Handle {
        &self.id
    }

    fn version(&self) -> u64 {
        self.version
    }
}

impl<E: fmt::Display + Eq + PartialEq + Storable + Send + Sync + 'static> fmt::Display for StoredEvent<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id: {} version: {} details: {}", self.id, self.version, self.details)
    }
}
