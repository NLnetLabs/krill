//! The publicly exposed key-value store.

use std::fmt;
use std::str::FromStr;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use url::Url;

use crate::commons::storage;
use crate::commons::storage::{
    Backend, Key, Namespace, NamespaceBuf, Scope, Transaction,
};


//------------ KeyValueStore -------------------------------------------------

/// A key-value store.
///
/// # Use within Krill
///
/// The following components use the key-value store directly:
///
/// * aggregate store, WAL store,
/// * queue,
/// * CA objects, CA status,
/// * OpenSSL signer.
#[derive(Debug)]
pub struct KeyValueStore {
    inner: Backend,
}

impl KeyValueStore {
    /// Creates a new store.
    pub fn create(
        storage_uri: &Url,
        namespace: &Namespace,
    ) -> Result<Self, KeyValueError> {
        Ok(Self {
            inner: Backend::new(storage_uri, namespace)?.ok_or_else(|| {
                KeyValueError::UnknownScheme(storage_uri.scheme().into())
            })?
        })
    }

    /// Returns whether the store has no entries.
    pub fn is_empty(&self) -> Result<bool, KeyValueError> {
        // NOTE: this is not done using `self.execute` as this would result
        // in a lockfile to be created for disk based inner stores, and that
        // would make them appear as not empty.
        self.inner.is_empty().map_err(KeyValueError::Inner)
    }

    /// Wipes the complete store.
    pub fn wipe(&self) -> Result<(), KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.clear())
    }

    pub fn execute<F, T>(
        &self,
        scope: &Scope,
        op: F,
    ) -> Result<T, KeyValueError>
    where
        F: Fn(&mut Transaction) -> Result<T, storage::Error>,
    {
        self.inner.execute(scope, op).map_err(KeyValueError::Inner)
    }
}

// # Keys and Values
impl KeyValueStore {
    /// Stores a key value pair, serialized as json, overwrite existing
    pub fn store<V: Serialize>(
        &self,
        key: &Key,
        value: &V,
    ) -> Result<(), KeyValueError> {
        self.execute(
            key.scope(),
            |kv| kv.store(key, value),
        )
    }

    /// Stores a key value pair, serialized as json, fails if existing
    pub fn store_new<V: Serialize>(
        &self,
        key: &Key,
        value: &V,
    ) -> Result<(), KeyValueError> {
        self.execute(
            key.scope(),
            |kv| {
                if kv.has(key)? {
                    Ok(Err(KeyValueError::DuplicateKey(key.clone())))
                }
                else {
                    kv.store(key, value)?;
                    Ok(Ok(()))
                }
            }
        )?
    }

    /// Gets a value for a key, returns an error if the value cannot be
    /// deserialized, returns None if it cannot be found.
    pub fn get<V: DeserializeOwned>(
        &self,
        key: &Key,
    ) -> Result<Option<V>, KeyValueError> {
        self.execute(key.scope(), |kv| {
            kv.get(key)
        })
    }

    /// Returns whether a key exists
    pub fn has(&self, key: &Key) -> Result<bool, KeyValueError> {
        self.execute(key.scope(), |kv| kv.has(key))
    }

    /// Delete a key-value pair.
    ///
    /// Returns an error if the key does not exist.
    pub fn drop_key(&self, key: &Key) -> Result<(), KeyValueError> {
        self.execute(key.scope(), |kv| kv.delete(key))
    }

    /// Returns all keys under a scope (scopes are exact strings, 'sub'-scopes
    /// would need to be specified explicitly.. e.g. 'ca' and 'ca/archived'
    /// are two distinct scopes.
    ///
    /// If matching is not empty then the key must contain the given `&str`.
    pub fn keys(
        &self,
        scope: &Scope,
        matching: &str,
    ) -> Result<Vec<Key>, KeyValueError> {
        self.execute(scope, |kv| {
            // storage list_keys returns keys in sub-scopes
            kv.list_keys(scope).map(|keys| {
                keys.into_iter()
                    .filter(|key| {
                        key.scope() == scope
                            && (matching.is_empty()
                                || key.name().as_str().contains(matching))
                    })
                    .collect()
            })
        })
    }
}

// # Scopes
impl KeyValueStore {
    /// Returns whether a scope exists
    pub fn has_scope(&self, scope: &Scope) -> Result<bool, KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.has_scope(scope))
    }

    /// Delete a scope
    pub fn drop_scope(&self, scope: &Scope) -> Result<(), KeyValueError> {
        self.execute(scope, |kv| kv.delete_scope(scope))
    }

    /// Returns all scopes.
    ///
    /// The returned vec will contain all scopes, including their subscopes.
    /// It will not, however, contain the global scope.
    pub fn scopes(&self) -> Result<Vec<Scope>, KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.list_scopes())
    }
}

// # Migration Support
impl KeyValueStore {
    /// Creates a new KeyValueStore for upgrades.
    ///
    /// Adds the implicit prefix "upgrade-{version}-" to the given namespace.
    pub fn create_upgrade_store(
        storage_uri: &Url,
        namespace: &Namespace,
    ) -> Result<Self, KeyValueError> {
        Self::create(
            storage_uri,
            &Self::prefixed_namespace(namespace, "upgrade")?
        )
    }

    fn prefixed_namespace(
        namespace: &Namespace,
        prefix: &str,
    ) -> Result<NamespaceBuf, KeyValueError> {
        let namespace_string = format!("{prefix}_{namespace}");
        NamespaceBuf::from_str(&namespace_string).map_err(|e| {
            KeyValueError::Other(format!(
                "Cannot parse namespace: {namespace_string}. Error: {e}"
            ))
        })
    }

    /// Archive this store (i.e. for this namespace). Deletes
    /// any existing archive for this namespace if present.
    pub fn migrate_to_archive(
        &mut self,
        storage_uri: &Url,
        namespace: &Namespace,
    ) -> Result<(), KeyValueError> {
        let archive_ns = Self::prefixed_namespace(namespace, "archive")?;
        // Wipe any existing archive, before archiving this store.
        // We don't want to keep too much old data. See issue: #1088.
        KeyValueStore::create(storage_uri, &archive_ns)?.wipe()?;
        self.inner.migrate_namespace(&archive_ns)?;
        Ok(())
    }

    /// Make this (upgrade) store the current store.
    ///
    /// Fails if there is a non-empty current store.
    pub fn migrate_to_current(
        &mut self,
        storage_uri: &Url,
        namespace: &Namespace,
    ) -> Result<(), KeyValueError> {
        let current_store = KeyValueStore::create(storage_uri, namespace)?;
        if !current_store.is_empty()? {
            Err(KeyValueError::Other(format!(
                "Abort migrate upgraded store for {namespace} to current. The current store was not archived."
            )))
        } else {
            self.inner
                .migrate_namespace(namespace)
                .map_err(KeyValueError::Inner)
        }
    }

    /// Import all data from the given KV store into this
    ///
    /// The closure `keep` is given each scope and decides whether it should
    /// be copied.
    ///
    /// NOTE: This function is not transactional because both this, and the
    /// other       keystore could be in the same database and nested
    /// transactions are       currently not supported. This should be
    /// okay, because this function       is intended to be used for
    /// migrations and testing (copy test data       into a store) while
    /// Krill is not running.
    pub fn import(
        &self,
        other: &Self,
        mut keep: impl FnMut(&Scope) -> bool,
    ) -> Result<(), KeyValueError> {
        let mut scopes = other.scopes()?;
        scopes.push(Scope::global());

        for scope in scopes {
            if !keep(&scope) {
                continue
            }
            for key in other.keys(&scope, "")? {
                if let Some(value) = other.inner.get_any(&key)? {
                    self.inner.store_any(&key, &value)?
                }
            }
        }

        Ok(())
    }
}


//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    UnknownScheme(String),
    DuplicateKey(Key),
    Inner(storage::Error),
    Other(String),
}

impl From<storage::Error> for KeyValueError {
    fn from(e: storage::Error) -> Self {
        KeyValueError::Inner(e)
    }
}

impl fmt::Display for KeyValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyValueError::UnknownScheme(e) => {
                write!(f, "Unknown Scheme: {e}")
            }
            KeyValueError::DuplicateKey(key) => {
                write!(f, "Duplicate key: {key}")
            }
            KeyValueError::Inner(e) => write!(f, "Store error: {e}"),
            KeyValueError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

