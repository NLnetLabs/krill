use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use super::{
    Aggregate,
    AggregateId,
    DiskKeyStore,
    Event,
    EventListener,
    KeyStore,
    KeyStoreError,
};

const SNAPSHOT_FREQ: u64 = 5;

pub type StoreResult<T> = Result<T, AggregateStoreError>;

pub trait AggregateStore<A: Aggregate>: Send + Sync {
    /// Gets the latest version for the given aggregate. Returns
    /// an AggregateStoreError::UnknownAggregate in case the aggregate
    /// does not exist.
    fn get_latest(&self, id: &AggregateId) -> StoreResult<Arc<A>>;

    /// Adds a new aggregate instance based on the init event.
    fn add(&self, id: &AggregateId, init: A::InitEvent) -> StoreResult<()>;

    /// Updates the aggregate instance in the store. Expects that the
    /// Arc<A> retrieved using 'get_latest' is moved here, so clone on
    /// writes can be avoided, and a verification can be done that there
    /// is no concurrent modification. Returns the updated instance if all
    /// is well, or an AggregateStoreError::ConcurrentModification if you
    /// try to update an outdated instance.
    fn update(&self, id: &AggregateId, agg: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>>;

    /// Returns true if an instance exists for the id
    fn has(&self, id: &AggregateId) -> bool;

    /// Lists all known ids.
    fn list(&self) -> Vec<AggregateId>;

    /// Adds a listener that will receive a reference to all events as they
    /// are stored.
    fn add_listener<L: EventListener<A>>(&mut self, listener: Arc<L>);
}


/// This type defines possible Errors for the AggregateStore
#[derive(Debug, Display)]
pub enum AggregateStoreError {
    #[display(fmt = "{}", _0)]
    KeyStoreError(KeyStoreError),

    #[display(fmt = "Unknown aggregate: {}", _0)]
    UnknownAggregate(AggregateId),

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "Event not applicable to aggregate, id or version is off")]
    WrongEventForAggregate,

    #[display(fmt = "Trying to update outdated aggregate")]
    ConcurrentModification,
}

impl From<KeyStoreError> for AggregateStoreError {
    fn from(e: KeyStoreError) -> Self { AggregateStoreError::KeyStoreError(e) }
}


pub struct DiskAggregateStore<A: Aggregate> {
    store: DiskKeyStore,
    cache: RwLock<HashMap<AggregateId, Arc<A>>>,
    use_cache: bool,
    listeners: Vec<Arc<EventListener<A>>>
}

impl<A: Aggregate> DiskAggregateStore<A> {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let store = DiskKeyStore::under_work_dir(work_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let use_cache = true;
        let listeners = vec![];
        Ok(DiskAggregateStore { store, cache, use_cache, listeners })
    }
}

impl<A: Aggregate> DiskAggregateStore<A> {
    fn has_updates(
        &self,
        id: &AggregateId,
        aggregate: &A
    ) -> StoreResult<bool> {
        Ok(self.store.get_event::<A::Event>(id, aggregate.version())?.is_some())
    }

    fn cache_get(&self, id: &AggregateId) -> Option<Arc<A>> {
        if self.use_cache {
            self.cache.read().unwrap().get(id).cloned()
        } else {
            None
        }
    }

    fn cache_update(&self, id: &AggregateId, arc: Arc<A>) {
        if self.use_cache {
            self.cache.write().unwrap().insert(id.clone(), arc);
        }
    }
}

impl<A: Aggregate> AggregateStore<A> for DiskAggregateStore<A> {
    fn get_latest(&self, id: &AggregateId) -> StoreResult<Arc<A>> {
        info!("Trying to load aggregate id: {}", id);
        match self.cache_get(id) {
            None => {
                match self.store.get_aggregate(id)? {
                    None => {
                        error!("Could not load aggregate with id: {} from disk", id);
                        Err(AggregateStoreError::UnknownAggregate(id.clone()))
                    },
                    Some(agg) => {
                        let arc: Arc<A> = Arc::new(agg);
                        self.cache_update(id, arc.clone());
                        info!("Loaded aggregate id: {} from disk", id);
                        Ok(arc)
                    }
                }
            },
            Some(mut arc) => {
                if self.has_updates(id, &arc)? {
                    let agg = Arc::make_mut(&mut arc);
                    self.store.update_aggregate(id, agg)?;
                }
                info!("Loaded aggregate id: {} from memory", id);
                Ok(arc)
            }
        }
    }

    fn add(&self, id: &AggregateId, init: A::InitEvent) -> StoreResult<()> {
        self.store.store_event(&init)?;

        let aggregate = A::init(init).map_err(|_| AggregateStoreError::InitError)?;
        self.store.store_aggregate(id, &aggregate)?;

        let arc = Arc::new(aggregate);
        self.cache_update(id, arc);

        Ok(())
    }


    fn update(&self, id: &AggregateId, prev: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>> {
        // Get the latest arc.
        let mut latest = self.get_latest(id)?;

        {
            // Verify whether there is a concurrency issue
            if prev.version() != latest.version() {
                return Err(AggregateStoreError::ConcurrentModification)
            }

            // forget the previous version
            std::mem::forget(prev);

            // make the arc mutable, hopefully forgetting prev will avoid the clone
            let agg = Arc::make_mut(&mut latest);

            // Using a lock on the hashmap here to ensure that all updates happen sequentially.
            // It would be better to get a lock only for this specific aggregate. So it may be
            // worth rethinking the stru
            //
            // That said.. saving and applying events is really quick, so this should not hurt
            // performance much.
            //
            // Also note that we don't need the lock to update the inner arc in the cache. We
            // just need it to be in scope until we are done updating.
            let _write_lock = self.cache.write().unwrap();

            // There is a possible race condition. We may only have obtained the lock
            if self.has_updates(id, &agg)? {
                self.store.update_aggregate(id, agg)?;
            }

            let version_before = agg.version();
            let nr_events = events.len() as u64;

            for i in 0..nr_events {
                let event = &events[i as usize];
                if event.version() != version_before + i || event.id() != id {
                    return Err(AggregateStoreError::WrongEventForAggregate);
                }
            }

            for event in events {
                self.store.store_event(&event)?;

                for listener in &self.listeners {
                    listener.as_ref().listen(agg, &event);
                }

                agg.apply(event);
                if agg.version() % SNAPSHOT_FREQ == 0 {
                    self.store.store_aggregate(id, agg)?;
                }
            }
        }

        Ok(latest)
    }

    fn has(&self, id: &AggregateId) -> bool {
        self.store.has_aggregate(id)
    }

    fn list(&self) -> Vec<AggregateId> {
        self.store.aggregates()
    }

    fn add_listener<L: EventListener<A>>(&mut self, listener: Arc<L>) {
        self.listeners.push(listener)
    }
}