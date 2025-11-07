//! Support for Write-ahead logging.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::{error, fmt};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use log::{error, warn, trace};
use rpki::ca::idexchange::MyHandle;
use serde::{Deserialize, Serialize};
use url::Url;
use crate::commons::storage::{Ident, KeyValueError, KeyValueStore};
use super::store::Storable;


//------------ WalSupport ----------------------------------------------------

/// A type that supports write-ahead logging.
///
/// Write-ahead logging is used to store a version of a type on disk and then
/// collect a number of events that update the value. This is similar to an
/// aggregate with the exception that you can only replay the value from the
/// last stored version. Thus, write-ahead logging is a simplified version
/// of the more complete event-sourcing model implemented by
/// [`Aggregate`][super::agg::Aggregate].
///
/// As with aggregates, all updates are made through “commands” which, when
/// applied create a number of events, called “changes” here. Only the
/// changes are stored in a [`WalSet<_>`] and can be applied to a value.
/// Consequently, these types do not have an audit log.
///
///
/// # Key-value store usage
///
/// Each aggregate store uses its own namespace. The first element of the
/// scope is the handle of the instance. The second element of the handle
/// is either `snapshot.json` for the snapshot or `wal-N.json` where
/// `N` is the version the command is taking the instance to.
///
///
/// # Use within Krill
///
/// Within Krill, write-ahead logging is currently used by the
/// [`Scheduler`][crate::daemon::scheduler::Scheduler] and
/// [`RepositoryContent`][crate::pubd::RepositoryContent].
pub trait WalSupport: Storable {
    /// The type representing a command.
    type Command: WalCommand;

    /// The type representing a single change.
    type Change: WalChange;

    /// The type returned when applying a command fails.
    type Error: std::error::Error + From<WalStoreError>;

    /// Returns the current version.
    fn revision(&self) -> u64;

    /// Applies the event.
    ///
    /// This must not result in any errors, and must be side-effect free.
    /// Applying the changes just updates the internal data of the aggregate.
    fn apply(&mut self, set: WalSet<Self>);

    /// Processes a command and converts it into a change set.
    ///
    /// Validates the command and, if successful, returns a list of
    /// changes that will result in the desired new state. The changes are
    /// not applied to the value.
    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Change>, Self::Error>;
}


//------------ WalCommand ----------------------------------------------------

/// A type representing a command for a write-ahead logging type.
///
/// The `Display` impl is used to generate the summary for the command.
pub trait WalCommand: Clone + fmt::Display {
    /// Returns the identifier of the entity.
    fn handle(&self) -> &MyHandle;
}


//------------ WalChange -----------------------------------------------------

/// A change to the state of a write-ahead logging type.
pub trait WalChange: fmt::Display + Eq + PartialEq + Send + Sync + Storable {
}


//------------ WalSet --------------------------------------------------------

/// The set of “write-ahead” changes affecting a specific revision of a value.
///
/// The set can only be applied to a given revision of the value. If applied,
/// it will change its revision to that revision plus 1.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalSet<T: WalSupport> {
    /// The revision this set should be applied to.
    revision: u64,

    /// A summary of the changes made by the set.
    summary: String,

    /// The individual changes of the set.
    changes: Vec<T::Change>,
}

impl<T: WalSupport> WalSet<T> {
    /// Converts the set into a list of changes.
    pub fn into_changes(self) -> Vec<T::Change> {
        self.changes
    }
}


//------------ WalStore ------------------------------------------------------

/// A store that manages all instances of a write-ahear logging type.
#[derive(Debug)]
pub struct WalStore<T: WalSupport> {
    /// The physical store for the aggregates.
    kv: KeyValueStore,

    /// A cache for the last seen version of an instance.
    cache: RwLock<HashMap<MyHandle, Arc<T>>>,
}

impl<T: WalSupport> WalStore<T> {
    /// Creates a new store using the given storage URL and namespace.
    pub fn create(
        storage_uri: &Url,
        namespace: &Ident,
    ) -> Result<Self, WalStoreError> {
        Ok(WalStore {
            kv: KeyValueStore::create(storage_uri, namespace)?,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Warms up the cache.
    ///
    /// The method loads all instances and places them in the cache.
    /// It should be called after startup.
    ///
    /// It will fail if any instance fails to load.
    pub fn warm(&self) -> Result<(), WalStoreError> {
        for handle in self.list()? {
            let latest = self.get_latest(&handle).map_err(|e| {
                WalStoreError::WarmupFailed(handle.clone(), e.to_string())
            })?;

            self.cache.write().unwrap().insert(handle, latest);
        }
        Ok(())
    }

    /// Add a new instance with the given handle.
    ///
    /// Fails if the handle is in use.
    pub fn add(
        &self, handle: &MyHandle, instance: T
    ) -> Result<(), WalStoreError> {
        let scope = Self::scope_for_handle(handle);
        let instance = Arc::new(instance);

        self.kv.execute(Some(&scope), |kv| {
            kv.store(
                Some(&scope), Self::key_for_snapshot(),
                instance.as_ref()
            )?;

            self.cache_update(handle, instance.clone());

            Ok(())
        }).map_err(WalStoreError::KeyStoreError)
    }

    /// Checks whether there is an instance with the given handle.
    pub fn has(&self, handle: &MyHandle) -> Result<bool, WalStoreError> {
        self.kv.has_scope(
            &Self::scope_for_handle(handle)
        ).map_err(WalStoreError::KeyStoreError)
    }

    /// Returns the latest revision for the given handle.
    ///
    /// This will use the cache if it's available and otherwise get a snapshot
    /// from the keystore. Then it will check whether there are any further
    /// changes.
    pub fn get_latest(&self, handle: &MyHandle) -> Result<Arc<T>, T::Error> {
        self.execute_opt_command(handle, None, false)
    }

    /// Removes an instance from this store.
    ///
    /// This operation is irrevocable.
    pub fn remove(&self, handle: &MyHandle) -> Result<(), WalStoreError> {
        let scope = Self::scope_for_handle(handle);
        if !self.kv.has_scope(&scope)? {
            Err(WalStoreError::Unknown(handle.clone()))
        }
        else {
            self.kv.execute(Some(&scope), |kv| {
                kv.delete_scope(&scope)
            }).map_err(WalStoreError::KeyStoreError)?;
            self.cache_remove(handle);
            Ok(())
        }
    }

    /// Returns a list of all instances managed in this store.
    pub fn list(&self) -> Result<Vec<MyHandle>, WalStoreError> {
        let mut res = vec![];

        for scope in self.kv.scopes()? {
            if let Ok(handle) = MyHandle::from_str(&scope.to_string()) {
                res.push(handle)
            }
        }

        Ok(res)
    }

    /// Processes a command.
    ///
    /// The method:
    /// * gets the instance for the command,
    /// * sends the command,
    /// * in case the command is successful:
    ///     * applies the wal set locally,
    ///     * saves the wal set
    ///     * if saving succeeds, updates the cache.
    pub fn send_command(
        &self,
        command: T::Command,
    ) -> Result<Arc<T>, T::Error> {
        let handle = command.handle().clone();
        self.execute_opt_command(&handle, Some(command), false)
    }

    pub fn update_snapshots(&self) -> Result<(), T::Error> {
        for handle in self.list()? {
            self.update_snapshot(&handle)?;
        }
        Ok(())
    }

    /// Update snapshot and archive or delete old wal sets
    pub fn update_snapshot(
        &self,
        handle: &MyHandle,
    ) -> Result<Arc<T>, T::Error> {
        self.execute_opt_command(handle, None, true)
    }

    /// Get the latest version of an instance and optionally apply a command.
    ///
    /// This method is the heart of the whole operation.
    fn execute_opt_command(
        &self,
        handle: &MyHandle,
        cmd_opt: Option<T::Command>,
        save_snapshot: bool,
    ) -> Result<Arc<T>, T::Error> {
        let scope = Self::scope_for_handle(handle);
        self.kv.execute(Some(&scope), |kv| {
            // Do we need to update the cache when we are done?
            let mut changed_from_cached = false;

            // Get the instance from the cache or from the store. Error out
            // if we don’t find it there either.
            let mut latest = match self.cache_get(handle) {
                Some(t) => {
                    trace!(
                        "Found cached instance for '{handle}', \
                         at revision: {}",
                         t.revision()
                    );
                    t
                }
                None => {
                    trace!("No cached instance found for '{handle}'");
                    changed_from_cached = true;

                    match kv.get(Some(&scope), Self::key_for_snapshot())? {
                        Some(value) => {
                            trace!(
                                "Deserializing stored instance for '{handle}'"
                            );
                            Arc::new(value)
                        }
                        None => {
                            trace!(
                                "No instance found instance for '{handle}'"
                            );
                            return Ok(Err(T::Error::from(
                                WalStoreError::Unknown(handle.clone())
                            )));
                        }
                    }
                }
            };

            // Check for updates and apply changes.
            {
                // Check if there any new changes that ought to be applied.
                // If so, apply them and remember that the instance was
                // changed compared to the (possible) cached version.

                let latest_inner = Arc::make_mut(&mut latest);

                // Check for changes and apply them until:
                // - there are no more changes
                // - or we encountered an error
                while let Some(value) = kv.get(
                    Some(&scope),
                    &Self::key_for_wal_set(latest_inner.revision())
                )? {
                    trace!("applying revision '{handle}'");
                    latest_inner.apply(value);
                    changed_from_cached = true;
                }

                // Process the command
                if let Some(command) = cmd_opt.clone() {
                    let summary = command.to_string();
                    let revision = latest_inner.revision();

                    trace!("Applying command {command} to {handle}");
                    match latest_inner.process_command(command) {
                        Err(e) => {
                            warn!(
                                "Command '{summary}' for '{handle}' \
                                 failed. Error: '{e}'"
                            );
                            return Ok(Err(e));
                        }
                        Ok(changes) => {
                            if changes.is_empty() {
                                trace!(
                                    "No changes needed for '{handle}' when \
                                     processing command: {summary}",
                                );
                            }
                            else {
                                trace!(
                                    "{} changes resulted for '{}' when \
                                     processing command: {}",
                                    changes.len(), handle, summary,
                                );
                                changed_from_cached = true;

                                let set: WalSet<T> = WalSet {
                                    revision, summary, changes,
                                };

                                let key_for_wal_set = Self::key_for_wal_set(
                                    revision
                                );

                                if kv.has(Some(&scope), &key_for_wal_set)? {
                                    error!(
                                        "Change set for '{handle}' version \
                                         '{revision}' already exists."
                                    );
                                    error!(
                                        "This is a bug. Please report this \
                                         issue to rpki-team@nlnetlabs.nl."
                                    );
                                    error!(
                                        "Krill will exit. If this issue \
                                        repeats, consider removing {handle}."
                                    );
                                    std::process::exit(1);
                                }

                                latest_inner.apply(set.clone());

                                kv.store(
                                    Some(&scope), &key_for_wal_set, &set
                                )?;
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
                kv.store(
                    Some(&scope), Self::key_for_snapshot(), latest.as_ref()
                )?;

                // Delete all wal sets (changes), since we are doing
                // this inside a transaction or locked scope we can
                // assume that all changes were applied, and there
                // are no other threads creating additional changes
                // that we were not aware of.
                for key in kv.list_keys(Some(&scope))? {
                    if key.as_str().starts_with("wal-") {
                        kv.delete(Some(&scope), &key)?;
                    }
                }
            }

            Ok(Ok(latest))
        }).map_err(|e| T::Error::from(WalStoreError::KeyStoreError(e)))?
    }
}


//--- Cache

impl<T: WalSupport> WalStore<T> {
    /// Returns the instance with the given handle from the cache.
    fn cache_get(&self, id: &MyHandle) -> Option<Arc<T>> {
        self.cache.read().unwrap().get(id).cloned()
    }

    /// Removes the instance with the given handle from the cache.
    fn cache_remove(&self, id: &MyHandle) {
        self.cache.write().unwrap().remove(id);
    }

    /// Updates the instance with the given handle in the cache.
    fn cache_update(&self, id: &MyHandle, arc: Arc<T>) {
        self.cache.write().unwrap().insert(id.clone(), arc);
    }
}


//--- Keys and Scopes

impl<T: WalSupport> WalStore<T> {
    /// Returns the scope for the instance with the given ID.
    fn scope_for_handle(handle: &MyHandle) -> Cow<'_, Ident> {
        Ident::from_handle(handle)
    }

    /// Returns the key for the snapshot of the aggregate with the given ID.
    const fn key_for_snapshot() -> &'static Ident {
        const { Ident::make("snapshot.json") }
    }

    /// Returns the key for the command for an aggregate and version.
    fn key_for_wal_set(revision: u64) -> Box<Ident> {
        Ident::builder(
            const { Ident::make("wal-") }
        ).push_u64(
            revision
        ).finish_with_extension(
            const { Ident::make("json") }
        )
    }
}


//------------ WalStoreError -------------------------------------------------

/// An error happened while accessing the write-ahead log store.
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
            WalStoreError::KeyStoreError(e) => {
                write!(f, "KeyStore Error: {e}")
            }
            WalStoreError::Unknown(handle) => {
                write!(f, "Unknown entity: {handle}")
            }
            WalStoreError::WarmupFailed(handle, e) => write!(
                f,
                "Warmup failed with entity '{handle}' error: {e}"
            ),
        }
    }
}

impl error::Error for WalStoreError { }

