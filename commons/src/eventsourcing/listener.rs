use super::{
    Event
};
use std::sync::RwLock;


//------------ EventListener -------------------------------------------------

/// This trait defines a listener for type of events.
/// EventListeners can be registered to an AggregateStore, and
/// will receive all events for the Aggregate as they are being
/// stored.
///
/// Note that at this time the events really happened, so
/// EventListeners do not have the luxury of failure in case
/// they do not like what happened.
pub trait EventListener<E: Event>: Send + Sync + 'static {
    fn listen(&self, event: &E);
}


//------------ EventCounter --------------------------------------------------

/// Example listener that simply counts all events
pub struct EventCounter {
    counter: RwLock<Counter>
}

struct Counter {
    total: usize
}

impl EventCounter {
    pub fn new() -> Self {
        EventCounter { counter: RwLock::new(Counter { total: 0 }) }
    }

    pub fn total(&self) -> usize {
        self.counter.read().unwrap().total
    }
}

impl<E: Event> EventListener<E> for EventCounter {
    fn listen(&self, _event: &E) {
        self.counter.write().unwrap().total += 1
    }
}
