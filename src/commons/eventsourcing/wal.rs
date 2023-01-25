use std::{
    collections::HashMap,
    fmt::{self},
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

use rpki::ca::idexchange::MyHandle;

use crate::commons::eventsourcing::{locks::HandleLocks, KeyStoreKey, KeyValueError, KeyValueStore, Storable};

//------------ WalSupport ----------------------------------------------------

/// Implement this trait to get write-ahead logging support for a type.
///
/// We achieve write-ahead logging support by insisting that implementing
/// types define the following:
///
/// - commands
///
/// Commands are used to send an intent to change the state. However, rather
/// than changing the state, they return a result which can either be an
/// error or a list of 'events'.
///
/// - events
///
/// Events contain the data that can be applied to a type to change its
/// state. We do this as a separate step, because this will allow us to
/// replay events - from write-ahead logs - to get a stored snapshot to
/// a current state.
///
/// The following caveats apply to this:
///   -- Events MUST NOT cause side-effects
///   -- Events MUST NOT return errors when applied
///   -- All state changes MUST use events
///
/// - errors
///
/// So that we can have type specific errors.
///
/// This is similar to how the [`Aggregate`] trait works, and in fact
/// we re-use some its definitions here - such as [`Event`] and [`Command`].
///
/// But, there is a key difference which is that in this case there are
/// no guarantees that all past events are kept - or rather they are very
/// likely NOT kept. And we have no "init" event.
///
/// While there are similar concepts being used, the concerns here are
/// somewhat different.. we use this type to achieve atomicity and durability
/// by way of the [`WalStore`] defined below, but we can keep things a bit
/// simpler here compared to the fully event-sourced [`Aggregate`] types.
pub trait WalSupport: Storable {
    type Command: WalCommand;
    type Change: WalChange;
    type Error: std::error::Error + From<WalStoreError>;

    /// Returns the current version.
    fn revision(&self) -> u64;

    /// Applies the event to this. This MUST not result in any errors, and
    /// this MUST be side-effect free. Applying the event just updates the
    /// internal data of the aggregate.
    ///
    /// Note the event is moved. This is done because we want to avoid
    /// doing additional allocations where we can.
    fn apply(&mut self, set: WalSet<Self>);

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these events here.
    ///
    /// The command is moved, because we want to enable moving its data
    /// without reallocating.
    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Change>, Self::Error>;
}

//------------ WalCommand ----------------------------------------------------

pub trait WalCommand: fmt::Display {
    fn handle(&self) -> &MyHandle;
}

//------------ WalEvent ------------------------------------------------------

pub trait WalChange: fmt::Display + Eq + PartialEq + Send + Sync + Storable {}

//------------ WalSet --------------------------------------------------------

/// Describes a set of "write-ahead" changes affecting the specified revision.
/// Meaning that it can only be applied if the type is of the given revision, and
/// it will get this revision + 1 after it has been applied.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalSet<T: WalSupport> {
    revision: u64,
    summary: String,
    changes: Vec<T::Change>,
}

impl<T: WalSupport> WalSet<T> {
    pub fn into_changes(self) -> Vec<T::Change> {
        self.changes
    }
}

//------------ WalStore ------------------------------------------------------

/// This type is responsible for loading / saving and updating [`WalSupport`]
/// capable types.
///
/// This is similar to how [`AggregateStore`] is used to manage [`Aggregate`]
/// types. However, there are some important differences:
/// - Commands and events for a change are saved as a single file.
/// - Old commands and events are no longer relevant and will be removed.
///   (we may want to support archiving those in future).
/// - We do not have any listeners in this case.
/// - We cannot replay [`WriteAheadSupport`] types from just events, we
///   *always* need to start with an existing snapshot.
#[derive(Debug)]
pub struct WalStore<T: WalSupport> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<MyHandle, Arc<T>>>,
    locks: HandleLocks,
}

impl<T: WalSupport> WalStore<T> {
    /// Creates a new store using a disk based keystore for the given data
    /// directory and namespace (directory).
    pub fn disk(krill_data_dir: &Path, name_space: &str) -> WalStoreResult<Self> {
        let mut path = krill_data_dir.to_path_buf();
        path.push(name_space);

        let kv = KeyValueStore::disk(krill_data_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());
        let locks = HandleLocks::default();

        Ok(WalStore { kv, cache, locks })
    }

    /// Warms up the store: caches all instances.
    pub fn warm(&self) -> WalStoreResult<()> {
        for handle in self.list()? {
            let latest = self
                .get_latest(&handle)
                .map_err(|e| WalStoreError::WarmupFailed(handle.clone(), e.to_string()))?;

            self.cache.write().unwrap().insert(handle, latest);
        }
        Ok(())
    }

    /// Add a new entity for the given handle. Fails if the handle is in use.
    pub fn add(&self, handle: &MyHandle, instance: T) -> WalStoreResult<()> {
        let handle_lock = self.locks.for_handle(handle.clone());
        let _write = handle_lock.write();

        let instance = Arc::new(instance);
        let key = Self::key_for_snapshot(handle);
        self.kv.store_new(&key, &instance)?; // Fails if this key exists
        self.cache.write().unwrap().insert(handle.clone(), instance);
        Ok(())
    }

    /// Checks whether there is an instance for the given handle.
    pub fn has(&self, handle: &MyHandle) -> WalStoreResult<bool> {
        let key = Self::key_for_snapshot(handle);
        self.kv.has(&key).map_err(WalStoreError::KeyStoreError)
    }

    /// Get the latest revision for the given handle.
    ///
    /// This will use the cache if it's available and otherwise get a snapshot
    /// from the keystore. Then it will check whether there are any further
    /// changes.
    pub fn get_latest(&self, handle: &MyHandle) -> WalStoreResult<Arc<T>> {
        let handle_lock = self.locks.for_handle(handle.clone());
        let _read = handle_lock.read();

        self.get_latest_no_lock(handle)
    }

    /// Get the latest revision without using a lock.
    ///
    /// Intended to be used by public functions which manage the locked read/write access
    /// to this instance for this handle.
    fn get_latest_no_lock(&self, handle: &MyHandle) -> WalStoreResult<Arc<T>> {
        let mut instance = match self.cache.read().unwrap().get(handle).cloned() {
            None => Arc::new(self.get_snapshot(handle)?),
            Some(instance) => instance,
        };

        if !self.kv.has(&Self::key_for_wal_set(handle, instance.revision()))? {
            // No further changes for this revision exist.
            //
            // Note: this is expected to be the case if our cached instances
            //       are kept up-to-date, and we run on a single node. Double
            //       checking this should not be too expensive though, and it
            //       allows us to use same code path for warming the cache and
            //       for getting the latest instance in other cases.
            Ok(instance)
        } else {
            // Changes exist:
            // - apply all of them
            // - update the cache instance
            // - return updated
            let instance = Arc::make_mut(&mut instance);

            loop {
                let wal_set_key = Self::key_for_wal_set(handle, instance.revision());
                if let Some(set) = self.kv.get(&wal_set_key)? {
                    instance.apply(set)
                } else {
                    break;
                }
            }

            let instance = Arc::new(instance.clone());
            self.cache.write().unwrap().insert(handle.clone(), instance.clone());
            Ok(instance)
        }
    }

    /// Remove an instance from this store. Irrevocable.
    pub fn remove(&self, handle: &MyHandle) -> WalStoreResult<()> {
        if !self.has(handle)? {
            Err(WalStoreError::Unknown(handle.clone()))
        } else {
            {
                // First get a lock and remove the object
                let handle_lock = self.locks.for_handle(handle.clone());
                let _write = handle_lock.write();
                self.cache.write().unwrap().remove(handle);
                self.kv.drop_scope(handle.as_str())?;
            }

            // Then drop the lock for it as well. We could not do this
            // while holding the write lock.
            //
            // Note that the corresponding entity was removed from the key
            // value store while we had a write lock for its handle.
            // So, even if another concurrent thread would now try to update
            // this same entity, that update would fail because the entity
            // no longer exists.
            self.locks.drop_handle(handle);
            Ok(())
        }
    }

    fn get_snapshot(&self, handle: &MyHandle) -> WalStoreResult<T> {
        self.kv
            .get(&Self::key_for_snapshot(handle))?
            .ok_or_else(|| WalStoreError::Unknown(handle.clone()))
    }

    /// Returns a list of all instances managed in this store.
    pub fn list(&self) -> WalStoreResult<Vec<MyHandle>> {
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = MyHandle::from_str(&scope) {
                res.push(handle)
            }
        }

        Ok(res)
    }

    /// Process a command:
    /// - gets the instance for the command
    /// - sends the command
    /// - in case the command is successful
    ///     - apply the wal set locally
    ///     - save the wal set
    ///     - if saved properly update the cache
    ///     
    ///
    ///
    pub fn send_command(&self, command: T::Command) -> Result<Arc<T>, T::Error> {
        let handle = command.handle().clone();

        let handle_lock = self.locks.for_handle(handle.clone());
        let _write = handle_lock.write();

        let mut latest = self.get_latest_no_lock(&handle)?;

        let summary = command.to_string();
        let revision = latest.revision();
        let changes = latest.process_command(command)?;

        if changes.is_empty() {
            debug!("No changes need for '{}' when processing command: {}", handle, summary);
            Ok(latest)
        } else {
            // lock the cache first, before writing any updates
            let mut cache = self.cache.write().unwrap();

            let set: WalSet<T> = WalSet {
                revision,
                summary,
                changes,
            };

            let key_for_wal_set = Self::key_for_wal_set(&handle, revision);
            self.kv
                .store_new(&key_for_wal_set, &set)
                .map_err(WalStoreError::KeyStoreError)?;

            let latest = Arc::make_mut(&mut latest);
            latest.apply(set);

            let latest = Arc::new(latest.clone());
            cache.insert(handle, latest.clone());

            Ok(latest)
        }
    }

    /// Update snapshot and archive or delete old wal sets
    ///
    /// This is a separate function because serializing a large instance can
    /// be expensive.
    pub fn update_snapshot(&self, handle: &MyHandle, archive: bool) -> WalStoreResult<()> {
        // Note that we do not need to keep a lock for the instance when we update the snapshot.
        // This function just updates the latest snapshot in the key value store, and it removes
        // or archives all write-ahead log ("wal-") changes predating the new snapshot.
        //
        // It is fine if another thread gets the entity for this handle and updates it while we
        // do this. As it turns out, writing snapshots can be expensive for large objects, so
        // we do not want block updates while we do this.
        //
        // This function is intended to be called in the back-ground at regular (slow) intervals
        // so any updates that were just missed will simply be folded in to the new snapshot when
        // this function is called again.
        let latest = self.get_latest(handle)?;
        let key = Self::key_for_snapshot(handle);
        self.kv.store(&key, &latest)?;

        // Archive or delete old wal sets
        for key in self.kv.keys(Some(handle.to_string()), "wal-")? {
            // Carefully inspect the key, just ignore keys
            // following a format that is not expected.
            // Who knows what people write in this dir?
            if let Some(remaining) = key.name().strip_prefix("wal-") {
                if let Some(number) = remaining.strip_suffix(".json") {
                    if let Ok(revision) = u64::from_str(number) {
                        if revision < latest.revision() {
                            if archive {
                                self.kv.archive(&key)?;
                            } else {
                                self.kv.drop_key(&key)?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn key_for_snapshot(handle: &MyHandle) -> KeyStoreKey {
        KeyStoreKey::scoped(handle.to_string(), "snapshot.json".to_string())
    }

    fn key_for_wal_set(handle: &MyHandle, revision: u64) -> KeyStoreKey {
        KeyStoreKey::scoped(handle.to_string(), format!("wal-{}.json", revision))
    }
}

//------------ WalStoreResult-------------------------------------------------

pub type WalStoreResult<T> = Result<T, WalStoreError>;

//------------ WalStoreError -------------------------------------------------

/// This type defines possible Errors for the AggregateStore
#[derive(Debug)]
pub enum WalStoreError {
    KeyStoreError(KeyValueError),
    Unknown(MyHandle),
    WarmupFailed(MyHandle, String),
}

impl From<KeyValueError> for WalStoreError {
    fn from(e: KeyValueError) -> Self {
        WalStoreError::KeyStoreError(e)
    }
}

impl fmt::Display for WalStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WalStoreError::KeyStoreError(e) => write!(f, "KeyStore Error: {}", e),
            WalStoreError::Unknown(handle) => write!(f, "Unknown entity: {}", handle),
            WalStoreError::WarmupFailed(handle, e) => write!(f, "Warmup failed with entity '{}' error: {}", handle, e),
        }
    }
}
