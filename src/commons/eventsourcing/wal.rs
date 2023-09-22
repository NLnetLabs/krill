use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Arc, RwLock},
};

use kvx::Namespace;
use rpki::ca::idexchange::MyHandle;
use serde::Serialize;
use url::Url;

use crate::commons::eventsourcing::{segment, Key, KeyValueError, KeyValueStore, Scope, Segment, SegmentExt, Storable};

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

pub trait WalCommand: Clone + fmt::Display {
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
}

impl<T: WalSupport> WalStore<T> {
    /// Creates a new store using a disk based keystore for the given data
    /// directory and namespace (directory).
    pub fn create(storage_uri: &Url, name_space: &Namespace) -> WalStoreResult<Self> {
        let kv = KeyValueStore::create(storage_uri, name_space)?;
        let cache = RwLock::new(HashMap::new());

        Ok(WalStore { kv, cache })
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
        let scope = Self::scope_for_handle(handle);
        let instance = Arc::new(instance);

        self.kv
            .execute(&scope, |kv| {
                let key = Self::key_for_snapshot(handle);
                let json = serde_json::to_value(instance.as_ref())?;
                kv.store(&key, json)?;

                self.cache_update(handle, instance.clone());

                Ok(())
            })
            .map_err(WalStoreError::KeyStoreError)
    }

    /// Checks whether there is an instance for the given handle.
    pub fn has(&self, handle: &MyHandle) -> WalStoreResult<bool> {
        let scope = Self::scope_for_handle(handle);
        self.kv.has_scope(&scope).map_err(WalStoreError::KeyStoreError)
    }

    /// Get the latest revision for the given handle.
    ///
    /// This will use the cache if it's available and otherwise get a snapshot
    /// from the keystore. Then it will check whether there are any further
    /// changes.
    pub fn get_latest(&self, handle: &MyHandle) -> Result<Arc<T>, T::Error> {
        self.execute_opt_command(handle, None, false)
    }

    /// Remove an instance from this store. Irrevocable.
    pub fn remove(&self, handle: &MyHandle) -> WalStoreResult<()> {
        if !self.has(handle)? {
            Err(WalStoreError::Unknown(handle.clone()))
        } else {
            let scope = Self::scope_for_handle(handle);

            self.kv
                .execute(&scope, |kv| {
                    kv.delete_scope(&scope)?;
                    self.cache_remove(handle);
                    Ok(())
                })
                .map_err(WalStoreError::KeyStoreError)
        }
    }

    /// Returns a list of all instances managed in this store.
    pub fn list(&self) -> WalStoreResult<Vec<MyHandle>> {
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = MyHandle::from_str(&scope.to_string()) {
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
    pub fn send_command(&self, command: T::Command) -> Result<Arc<T>, T::Error> {
        let handle = command.handle().clone();
        self.execute_opt_command(&handle, Some(command), false)
    }

    fn execute_opt_command(
        &self,
        handle: &MyHandle,
        cmd_opt: Option<T::Command>,
        save_snapshot: bool,
    ) -> Result<Arc<T>, T::Error> {
        self.kv
            .execute(&Self::scope_for_handle(handle), |kv| {
                // Track whether anything has changed compared to the cached
                // instance (if any) so that we will know whether the cache
                // should be updated.
                let mut changed_from_cached = false;

                // Get the instance from the cache, or get it from the store.
                let latest_option = match self.cache_get(handle) {
                    Some(t) => {
                        debug!("Found cached instance for '{handle}', at revision: {}", t.revision());
                        Some(t)
                    }
                    None => {
                        trace!("No cached instance found for '{handle}'");
                        changed_from_cached = true;

                        let key = Self::key_for_snapshot(handle);

                        match kv.get(&key)? {
                            Some(value) => {
                                debug!("Deserializing stored instance for '{handle}'");
                                let latest: T = serde_json::from_value(value)?;
                                Some(Arc::new(latest))
                            }
                            None => {
                                debug!("No instance found instance for '{handle}'");
                                None
                            }
                        }
                    }
                };

                // Get a mutable instance to work with, or return with an
                // inner Err informing the caller that there is no instance.
                let mut latest = match latest_option {
                    Some(latest) => latest,
                    None => return Ok(Err(T::Error::from(WalStoreError::Unknown(handle.clone())))),
                };

                // Check for updates and apply changes
                {
                    // Check if there any new changes that ought to be applied.
                    // If so, apply them and remember that the instance was changed
                    // compared to the (possible) cached version.

                    let latest_inner = Arc::make_mut(&mut latest);

                    // Check for changes and apply them until:
                    // - there are no more changes
                    // - or we encountered an error
                    loop {
                        let revision = latest_inner.revision();
                        let key = Self::key_for_wal_set(handle, revision);

                        if let Some(value) = kv.get(&key)? {
                            let set: WalSet<T> = serde_json::from_value(value)?;
                            debug!("applying revision '{revision}' to '{handle}'");
                            latest_inner.apply(set);
                            changed_from_cached = true;
                        } else {
                            break;
                        }
                    }

                    // Process the command
                    if let Some(command) = cmd_opt.clone() {
                        let summary = command.to_string();
                        let revision = latest_inner.revision();

                        debug!("Applying command {command} to {handle}");
                        match latest_inner.process_command(command) {
                            Err(e) => {
                                debug!("Error applying command to '{handle}'. Error: {e}");
                                return Ok(Err(e));
                            }
                            Ok(changes) => {
                                if changes.is_empty() {
                                    debug!(
                                        "No changes needed for '{}' when processing command: {}",
                                        handle, summary
                                    );
                                } else {
                                    debug!(
                                        "{} changes resulted for '{}' when processing command: {}",
                                        changes.len(),
                                        handle,
                                        summary
                                    );
                                    changed_from_cached = true;

                                    let set: WalSet<T> = WalSet {
                                        revision,
                                        summary,
                                        changes,
                                    };

                                    let key_for_wal_set = Self::key_for_wal_set(handle, revision);

                                    if kv.has(&key_for_wal_set)? {
                                        error!("Change set for '{handle}' version '{revision}' already exists.");
                                        error!("This is a bug. Please report this issue to rpki-team@nlnetlabs.nl.");
                                        error!("Krill will exit. If this issue repeats, consider removing {}.", handle);
                                        std::process::exit(1);
                                    }

                                    let json = serde_json::to_value(&set)?;

                                    latest_inner.apply(set);

                                    kv.store(&key_for_wal_set, json)?;
                                }
                            }
                        }
                    }
                }

                if changed_from_cached {
                    self.cache_update(handle, latest.clone());
                }

                if save_snapshot {
                    // Save the latest version as snapshot
                    let key = Self::key_for_snapshot(handle);
                    let value = serde_json::to_value(latest.as_ref())?;
                    kv.store(&key, value)?;

                    // Delete all wal sets (changes), since we are doing
                    // this inside a transaction or locked scope we can
                    // assume that all changes were applied, and there
                    // are no other threads creating additional changes
                    // that we were not aware of.
                    for key in kv.list_keys(&Self::scope_for_handle(handle))? {
                        if key.name().as_str().starts_with("wal-") {
                            kv.delete(&key)?;
                        }
                    }
                }

                Ok(Ok(latest))
            })
            .map_err(|e| T::Error::from(WalStoreError::KeyStoreError(e)))?
    }

    pub fn update_snapshots(&self) -> Result<(), T::Error> {
        for handle in self.list()? {
            self.update_snapshot(&handle)?;
        }
        Ok(())
    }

    /// Update snapshot and archive or delete old wal sets
    pub fn update_snapshot(&self, handle: &MyHandle) -> Result<Arc<T>, T::Error> {
        self.execute_opt_command(handle, None, true)
    }

    fn cache_get(&self, id: &MyHandle) -> Option<Arc<T>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    fn cache_remove(&self, id: &MyHandle) {
        self.cache.write().unwrap().remove(id);
    }

    fn cache_update(&self, id: &MyHandle, arc: Arc<T>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }

    fn scope_for_handle(handle: &MyHandle) -> Scope {
        // handle should always be a valid Segment
        Scope::from_segment(Segment::parse_lossy(handle.as_str()))
    }

    fn key_for_snapshot(handle: &MyHandle) -> Key {
        Key::new_scoped(Self::scope_for_handle(handle), segment!("snapshot.json"))
    }

    fn key_for_wal_set(handle: &MyHandle, revision: u64) -> Key {
        Key::new_scoped(
            Self::scope_for_handle(handle),
            Segment::parse(&format!("wal-{}.json", revision)).unwrap(), // cannot panic as a u64 cannot contain a Scope::SEPARATOR
        )
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
