use tokio::sync::RwLock;

use super::Aggregate;

//------------ EventListener -------------------------------------------------

/// This trait defines a listener for type of events.
/// EventListeners can be registered to an AggregateStore, and
/// will receive all events for the Aggregate as they are being
/// stored.
///
/// Note that at this time the events really happened, so
/// EventListeners do not have the luxury of failure in case
/// they do not like what happened.
#[async_trait]
pub trait EventListener<A: Aggregate>: Send + Sync + 'static {
    async fn listen(&self, agg: &A, event: &A::Event);
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
    pub async fn total(&self) -> usize {
        self.counter.read().await.total
    }
}

#[async_trait]
impl<A: Aggregate> EventListener<A> for EventCounter {
    async fn listen(&self, _agg: &A, _event: &A::Event) {
        self.counter.write().await.total += 1
    }
}
