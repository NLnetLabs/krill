use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use crate::api::admin::Handle;

use super::{Aggregate, DiskKeyStore, Event, EventListener, KeyStore, KeyStoreError};

const SNAPSHOT_FREQ: u64 = 5;

pub type StoreResult<T> = Result<T, AggregateStoreError>;

pub trait AggregateStore<A: Aggregate>: Send + Sync {
    /// Gets the latest version for the given aggregate. Returns
    /// an AggregateStoreError::UnknownAggregate in case the aggregate
    /// does not exist.
    fn get_latest(&self, id: &Handle) -> StoreResult<Arc<A>>;

    /// Adds a new aggregate instance based on the init event.
    fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>>;

    /// Updates the aggregate instance in the store. Expects that the
    /// Arc<A> retrieved using 'get_latest' is moved here, so clone on
    /// writes can be avoided, and a verification can be done that there
    /// is no concurrent modification. Returns the updated instance if all
    /// is well, or an AggregateStoreError::ConcurrentModification if you
    /// try to update an outdated instance.
    fn update(&self, id: &Handle, agg: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>>;

    /// Returns true if an instance exists for the id
    fn has(&self, id: &Handle) -> bool;

    /// Lists all known ids.
    fn list(&self) -> Vec<Handle>;

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
    UnknownAggregate(Handle),

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "Event not applicable to aggregate, id or version is off")]
    WrongEventForAggregate,

    #[display(fmt = "Trying to update outdated aggregate: {}", _0)]
    ConcurrentModification(Handle),
}

impl From<KeyStoreError> for AggregateStoreError {
    fn from(e: KeyStoreError) -> Self {
        AggregateStoreError::KeyStoreError(e)
    }
}

pub struct DiskAggregateStore<A: Aggregate> {
    store: DiskKeyStore,
    cache: RwLock<HashMap<Handle, Arc<A>>>,
    use_cache: bool,
    listeners: Vec<Arc<EventListener<A>>>,
    outer_lock: RwLock<()>,
}

impl<A: Aggregate> DiskAggregateStore<A> {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let store = DiskKeyStore::under_work_dir(work_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let use_cache = true;
        let listeners = vec![];
        let lock = RwLock::new(());
        Ok(DiskAggregateStore {
            store,
            cache,
            use_cache,
            listeners,
            outer_lock: lock,
        })
    }
}

impl<A: Aggregate> DiskAggregateStore<A> {
    fn has_updates(&self, id: &Handle, aggregate: &A) -> StoreResult<bool> {
        Ok(self
            .store
            .get_event::<A::Event>(id, aggregate.version())?
            .is_some())
    }

    fn cache_get(&self, id: &Handle) -> Option<Arc<A>> {
        if self.use_cache {
            self.cache.read().unwrap().get(id).cloned()
        } else {
            None
        }
    }

    fn cache_update(&self, id: &Handle, arc: Arc<A>) {
        if self.use_cache {
            self.cache.write().unwrap().insert(id.clone(), arc);
        }
    }

    fn get_latest_no_lock(&self, handle: &Handle) -> StoreResult<Arc<A>> {
        debug!("Trying to load aggregate id: {}", handle);
        match self.cache_get(handle) {
            None => match self.store.get_aggregate(handle)? {
                None => {
                    error!("Could not load aggregate with id: {} from disk", handle);
                    Err(AggregateStoreError::UnknownAggregate(handle.clone()))
                }
                Some(agg) => {
                    let arc: Arc<A> = Arc::new(agg);
                    self.cache_update(handle, arc.clone());
                    debug!("Loaded aggregate id: {} from disk", handle);
                    Ok(arc)
                }
            },
            Some(mut arc) => {
                if self.has_updates(handle, &arc)? {
                    let agg = Arc::make_mut(&mut arc);
                    self.store.update_aggregate(handle, agg)?;
                }
                debug!("Loaded aggregate id: {} from memory", handle);
                Ok(arc)
            }
        }
    }
}

impl<A: Aggregate> AggregateStore<A> for DiskAggregateStore<A> {
    fn get_latest(&self, handle: &Handle) -> StoreResult<Arc<A>> {
        let _lock = self.outer_lock.read().unwrap();
        self.get_latest_no_lock(handle)
    }

    fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>> {
        let _lock = self.outer_lock.write().unwrap();

        self.store.store_event(&init)?;

        let handle = init.handle().clone();

        let aggregate = A::init(init).map_err(|_| AggregateStoreError::InitError)?;
        self.store.store_aggregate(&handle, &aggregate)?;

        let arc = Arc::new(aggregate);
        self.cache_update(&handle, arc.clone());

        Ok(arc)
    }

    fn update(&self, handle: &Handle, prev: Arc<A>, events: Vec<A::Event>) -> StoreResult<Arc<A>> {
        let _lock = self.outer_lock.write().unwrap();

        // Get the latest arc.
        let mut latest = self.get_latest_no_lock(handle)?;
        {
            // Verify whether there is a concurrency issue
            if prev.version() != latest.version() {
                return Err(AggregateStoreError::ConcurrentModification(handle.clone()));
            }

            // forget the previous version
            std::mem::forget(prev);

            // make the arc mutable, hopefully forgetting prev will avoid the clone
            let agg = Arc::make_mut(&mut latest);

            // Using a lock on the hashmap here to ensure that all updates happen sequentially.
            // It would be better to get a lock only for this specific aggregate. So it may be
            // worth rethinking the structure.
            //
            // That said.. saving and applying events is really quick, so this should not hurt
            // performance much.
            //
            // Also note that we don't need the lock to update the inner arc in the cache. We
            // just need it to be in scope until we are done updating.
            let mut cache = self.cache.write().unwrap();

            // There is a possible race condition. We may only have obtained the lock
            if self.has_updates(handle, &agg)? {
                self.store.update_aggregate(handle, agg)?;
            }

            let version_before = agg.version();
            let nr_events = events.len() as u64;

            for i in 0..nr_events {
                let event = &events[i as usize];
                if event.version() != version_before + i || event.handle() != handle {
                    return Err(AggregateStoreError::WrongEventForAggregate);
                }
            }

            for event in events {
                self.store.store_event(&event)?;

                agg.apply(event.clone());
                if agg.version() % SNAPSHOT_FREQ == 0 {
                    self.store.store_aggregate(handle, agg)?;
                }

                for listener in &self.listeners {
                    listener.as_ref().listen(agg, &event);
                }
            }

            cache.insert(handle.clone(), Arc::new(agg.clone()));
        }

        Ok(latest)
    }

    fn has(&self, id: &Handle) -> bool {
        let _lock = self.outer_lock.read().unwrap();
        self.store.has_aggregate(id)
    }

    fn list(&self) -> Vec<Handle> {
        let _lock = self.outer_lock.read().unwrap();
        self.store.aggregates()
    }

    fn add_listener<L: EventListener<A>>(&mut self, listener: Arc<L>) {
        let _lock = self.outer_lock.write().unwrap();

        self.listeners.push(listener)
    }
}
