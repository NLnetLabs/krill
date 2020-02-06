use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use crate::commons::api::Handle;
use crate::commons::eventsourcing::agg::AggregateHistory;
use crate::commons::eventsourcing::cmd::{Command, StoredCommandBuilder};
use crate::commons::eventsourcing::{
    Aggregate, DiskKeyStore, Event, EventListener, KeyStore, KeyStoreError,
};

const SNAPSHOT_FREQ: u64 = 5;

pub type StoreResult<T> = Result<T, AggregateStoreError>;

pub trait AggregateStore<A: Aggregate>: Send + Sync
where
    A::Error: From<AggregateStoreError>,
{
    /// Gets the latest version for the given aggregate. Returns
    /// an AggregateStoreError::UnknownAggregate in case the aggregate
    /// does not exist.
    fn get_latest(&self, id: &Handle) -> StoreResult<Arc<A>>;

    /// Adds a new aggregate instance based on the init event.
    fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>>;

    /// Sends a command to the appropriate aggregate, and on
    /// success: save command and events, return aggregate
    /// no-op: do not save any thing, return aggregate
    /// error: save command and error, return error
    fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error>;

    /// Returns true if an instance exists for the id
    fn has(&self, id: &Handle) -> bool;

    /// Lists all known ids.
    fn list(&self) -> Vec<Handle>;

    /// Adds a listener that will receive a reference to all events as they
    /// are stored.
    fn add_listener<L: EventListener<A>>(&mut self, listener: Arc<L>);

    /// Lists the complete history for an aggregate.
    fn history(&self, id: &Handle) -> StoreResult<AggregateHistory<A>>;
}

/// This type defines possible Errors for the AggregateStore
#[derive(Debug, Display)]
pub enum AggregateStoreError {
    #[display(fmt = "{}", _0)]
    KeyStoreError(KeyStoreError),

    #[display(fmt = "unknown entity: {}", _0)]
    UnknownAggregate(Handle),

    #[display(fmt = "init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "event not applicable to entity, id or version is off")]
    WrongEventForAggregate,

    #[display(fmt = "concurrent modifcation attempt for entity: '{}'", _0)]
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
    listeners: Vec<Arc<dyn EventListener<A>>>,
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
        trace!("Trying to load aggregate id: {}", handle);
        match self.cache_get(handle) {
            None => match self.store.get_aggregate(handle)? {
                None => {
                    error!("Could not load aggregate with id: {} from disk", handle);
                    Err(AggregateStoreError::UnknownAggregate(handle.clone()))
                }
                Some(agg) => {
                    let arc: Arc<A> = Arc::new(agg);
                    self.cache_update(handle, arc.clone());
                    trace!("Loaded aggregate id: {} from disk", handle);
                    Ok(arc)
                }
            },
            Some(mut arc) => {
                if self.has_updates(handle, &arc)? {
                    let agg = Arc::make_mut(&mut arc);
                    self.store.update_aggregate(handle, agg)?;
                }
                trace!("Loaded aggregate id: {} from memory", handle);
                Ok(arc)
            }
        }
    }
}

impl<A: Aggregate> AggregateStore<A> for DiskAggregateStore<A>
where
    A::Error: From<AggregateStoreError>,
{
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

    fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error> {
        let _lock = self.outer_lock.write().unwrap();

        // Get the latest arc.
        let handle = cmd.handle().clone();

        let mut latest = self.get_latest_no_lock(&handle)?;

        if let Some(version) = cmd.version() {
            if version != latest.version() {
                error!(
                    "Version conflict updating '{}', expected version: {}, found: {}",
                    handle,
                    version,
                    latest.version()
                );

                return Err(A::Error::from(AggregateStoreError::ConcurrentModification(
                    handle,
                )));
            }
        }

        let stored_command_builder = StoredCommandBuilder::new(&cmd, latest.version());

        match latest.process_command(cmd) {
            Err(e) => {
                let stored_command = stored_command_builder.finish_with_error(&e);
                self.store
                    .store_command(stored_command)
                    .map_err(AggregateStoreError::KeyStoreError)?;
                Err(e)
            }
            Ok(events) => {
                if events.is_empty() {
                    Ok(latest)
                } else {
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

                    // It should be impossible to get events for the wrong aggregate, and the wrong
                    // versions, because we are doing the update here inside the outer lock, and aggregates
                    // generally do not lie about who do they are.
                    //
                    // Still.. some defensive coding in case we do have some issue. Double check that the
                    // events are for this aggregate, and are a contiguous sequence of version starting with
                    // this version.
                    let version_before = agg.version();
                    let nr_events = events.len() as u64;
                    for i in 0..nr_events {
                        let event = &events[i as usize];
                        if event.version() != version_before + i || event.handle() != &handle {
                            return Err(A::Error::from(
                                AggregateStoreError::WrongEventForAggregate,
                            ));
                        }
                    }

                    // Time to start saving things.
                    let stored_command =
                        stored_command_builder.finish_with_events(events.as_slice());
                    self.store
                        .store_command(stored_command)
                        .map_err(AggregateStoreError::KeyStoreError)?;

                    for event in &events {
                        self.store
                            .store_event(event)
                            .map_err(AggregateStoreError::KeyStoreError)?;

                        agg.apply(event.clone());
                        if agg.version() % SNAPSHOT_FREQ == 0 {
                            self.store
                                .store_aggregate(&handle, agg)
                                .map_err(AggregateStoreError::KeyStoreError)?;
                        }
                    }

                    cache.insert(handle, Arc::new(agg.clone()));

                    // Only send this to listeners after everything has been saved.
                    for event in events {
                        for listener in &self.listeners {
                            listener.as_ref().listen(agg, &event);
                        }
                    }

                    Ok(latest)
                }
            }
        }
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

    fn history(&self, id: &Handle) -> StoreResult<AggregateHistory<A>> {
        self.store
            .history::<A>(id)
            .map_err(AggregateStoreError::KeyStoreError)
    }
}
