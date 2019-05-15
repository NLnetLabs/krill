use super::{
    AggregateId,
    Storable
};


//------------ Event --------------------------------------------------------

pub trait Event: Storable + 'static {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn id(&self) -> &AggregateId;

    /// The version of the aggregate that this event updates. An aggregate that
    /// is currently at version x, will get version x + 1, when the event for
    /// version x is applied.
    fn version(&self) -> u64;
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StoredEvent<E: Storable + 'static> {
    id: AggregateId,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E
}

impl<E: Storable + 'static> StoredEvent<E> {

    pub fn new(id: &AggregateId, version: u64, event: E) -> Self {
        StoredEvent { id: id.clone(), version, details: event }
    }

    pub fn details(&self) -> &E { & self.details }

    pub fn into_details(self) -> E { self.details }

    /// Return the parts of this event.
    pub fn unwrap(self) -> (AggregateId, u64, E) {
        (self.id, self.version, self.details)
    }
}

impl<E: Storable + 'static> Event for StoredEvent<E> {
    fn id(&self) -> &AggregateId {
        &self.id
    }

    fn version(&self) -> u64 {
        self.version
    }
}