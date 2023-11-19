use std::sync::RwLock;

use super::Aggregate;

//------------ PreSaveEventListener ------------------------------------------

/// This trait defines a listener for events which is designed to receive
/// the events *before* the Aggregate is saved. Thus, they are allowed
/// to return an error in case of issues, which will then roll back the
/// intended change to an aggregate.
#[async_trait::async_trait]
pub trait PreSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    async fn listen(&self, agg: &A, events: &[A::Event]) -> Result<(), A::Error>;
}

//------------ PostSaveEventListener ------------------------------------------

/// This trait defines a listener for events which is designed to receive
/// them *after* the updated Aggregate is saved. Because the updates already
/// happened EventListeners of this type are not allowed to fail.
#[async_trait::async_trait]
pub trait PostSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    async fn listen(&self, agg: &A, events: &[A::Event]);
}

//------------ EventCounter --------------------------------------------------

/// Example listener that simply counts all events
pub struct EventCounter {
    counter: RwLock<Counter>,
}

struct Counter {
    total: usize,
}

impl Default for EventCounter {
    fn default() -> Self {
        EventCounter {
            counter: RwLock::new(Counter { total: 0 }),
        }
    }
}

impl EventCounter {
    pub fn total(&self) -> usize {
        self.counter.read().unwrap().total
    }
}

#[async_trait::async_trait]
impl<A: Aggregate> PostSaveEventListener<A> for EventCounter {
    async fn listen(&self, _agg: &A, events: &[A::Event]) {
        self.counter.write().unwrap().total += events.len();
    }
}
