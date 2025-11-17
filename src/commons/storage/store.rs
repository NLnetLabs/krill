//! The publicly exposed key-value store.

use std::{error, fmt};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use url::Url;
use crate::commons::storage;
use crate::commons::error::Error;
use crate::commons::storage::{Backend, Ident, Transaction};


//------------ StorageSystem -------------------------------------------------

/// The system that provides the key-value stores.
#[derive(Debug)]
pub struct StorageSystem {
    storage_uri: Url,
}

impl StorageSystem {
    /// Creates a new storage system.
    ///
    /// The provided URI will be used as the default storage URI.
    pub fn new(
        storage_uri: Url
    ) -> Result<Self, StorageConnectError> {
        Ok(Self { storage_uri })
    }

    /// Opens the default store with the given namespace.
    pub fn open(
        &self, namespace: &Ident
    ) -> Result<KeyValueStore, OpenStoreError> {
        KeyValueStore::create(&self.storage_uri, namespace).map_err(
            OpenStoreError
        )
    }

    /// Opens a store for upgrades for the given namespace.
    ///
    /// Prefixes the namespace with `"upgrade_"`.
    pub fn open_upgrade(
        &self, namespace: &Ident
    ) -> Result<KeyValueStore, OpenStoreError> {
        KeyValueStore::create(
            &self.storage_uri,
            &KeyValueStore::prefixed_namespace(
                namespace, const { Ident::make("upgrade") }
            )
        ).map_err(
            OpenStoreError
        )
    }

    /// Opens a store with the given storage URI and namespace.
    pub fn open_uri(
        &self, storage_uri: &Url, namespace: &Ident
    ) -> Result<KeyValueStore, OpenStoreError> {
        KeyValueStore::create(storage_uri, namespace).map_err(
            OpenStoreError
        )
    }

    /// Returns the default URI of the storage system.
    pub fn default_uri(&self) -> &Url {
        &self.storage_uri
    }
}


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
    fn create(
        storage_uri: &Url,
        namespace: &Ident,
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
        self.execute(None, |kv| kv.clear())
    }

    pub fn execute<F, T>(
        &self,
        scope: Option<&Ident>,
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
        scope: Option<&Ident>,
        key: &Ident,
        value: &V,
    ) -> Result<(), KeyValueError> {
        self.execute(
            scope,
            |kv| kv.store(scope, key, value),
        )
    }

    /// Stores a key value pair, serialized as json, fails if existing
    pub fn store_new<V: Serialize>(
        &self,
        scope: Option<&Ident>,
        key: &Ident,
        value: &V,
    ) -> Result<(), KeyValueError> {
        self.execute(
            scope,
            |kv| {
                if kv.has(scope, key)? {
                    Ok(Err(KeyValueError::duplicate_key(scope, key)))
                }
                else {
                    kv.store(scope, key, value)?;
                    Ok(Ok(()))
                }
            }
        )?
    }

    /// Gets a value for a key, returns an error if the value cannot be
    /// deserialized, returns None if it cannot be found.
    pub fn get<V: DeserializeOwned>(
        &self, scope: Option<&Ident>, key: &Ident,
    ) -> Result<Option<V>, KeyValueError> {
        self.execute(scope, |kv| {
            kv.get(scope, key)
        })
    }

    /// Returns whether a key exists
    pub fn has(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<bool, KeyValueError> {
        self.execute(scope, |kv| kv.has(scope, key))
    }

    /// Delete a key-value pair.
    ///
    /// Returns an error if the key does not exist.
    pub fn drop_key(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<(), KeyValueError> {
        self.execute(scope, |kv| kv.delete(scope, key))
    }

    /// Returns all keys under a scope (scopes are exact strings, 'sub'-scopes
    /// would need to be specified explicitly.. e.g. 'ca' and 'ca/archived'
    /// are two distinct scopes.
    ///
    /// If matching is not empty then the key must contain the given `&str`.
    pub fn keys(
        &self, scope: Option<&Ident>, contains: &str,
    ) -> Result<Vec<Box<Ident>>, KeyValueError> {
        self.execute(scope, |kv| {
            // storage list_keys returns keys in sub-scopes
            kv.list_keys(scope).map(|mut res| {
                res.retain(|item| item.as_str().contains(contains));
                res
            })
        })
    }
}

// # Scopes
impl KeyValueStore {
    /// Returns whether a scope exists
    pub fn has_scope(
        &self, scope: &Ident
    ) -> Result<bool, KeyValueError> {
        self.execute(None, |kv| kv.has_scope(scope))
    }

    /// Delete a scope
    pub fn drop_scope(
        &self, scope: &Ident
    ) -> Result<(), KeyValueError> {
        self.execute(None, |kv| kv.delete_scope(scope))
    }

    /// Returns all scopes.
    ///
    /// The returned vec will contain all scopes, including their subscopes.
    /// It will not, however, contain the global scope.
    pub fn scopes(&self) -> Result<Vec<Box<Ident>>, KeyValueError> {
        self.execute(None, |kv| kv.list_scopes())
    }
}

// # Migration Support
impl KeyValueStore {
    fn prefixed_namespace(
        namespace: &Ident,
        prefix: &Ident,
    ) -> Box<Ident> {
        Ident::builder(prefix).push_ident(
            const { Ident::make("_") }
        ).push_ident(
            namespace
        ).finish()
    }

    /// Archive this store (i.e. for this namespace). Deletes
    /// any existing archive for this namespace if present.
    pub fn migrate_to_archive(
        &mut self,
        storage_uri: &Url,
        namespace: &Ident,
    ) -> Result<(), KeyValueError> {
        let archive_ns = Self::prefixed_namespace(
            namespace, const { Ident::make("archive") }
        );

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
        namespace: &Ident,
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
    ) -> Result<(), KeyValueError> {
        let mut scopes: Vec<_>
            = other.scopes()?.into_iter().map(Some).collect();
        scopes.push(None);

        for scope in scopes {
            for key in other.keys(scope.as_deref(), "")? {
                if let Some(value)
                    = other.inner.get_any(scope.as_deref(), &key)?
                {
                    self.inner.store_any(scope.as_deref(), &key, &value)?
                }
            }
        }

        Ok(())
    }
}


//------------ StorageConnectError -------------------------------------------

/// An error occured while connecting to a storage system.
#[derive(Debug)]
pub struct StorageConnectError(());

impl fmt::Display for StorageConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("storage connect error")
    }
}

impl error::Error for StorageConnectError { }

impl From<StorageConnectError> for crate::commons::error::Error {
    fn from(src: StorageConnectError) -> Self {
        Self::custom(format_args!("{}", src))
    }
}


//------------ OpenStoreError ------------------------------------------------

/// An error occured while opening a store.
#[derive(Debug)]
pub struct OpenStoreError(KeyValueError);

impl fmt::Display for OpenStoreError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for OpenStoreError { }

impl From<OpenStoreError> for Error {
    fn from(src: OpenStoreError) -> Error {
        Error::custom(format_args!("{}", src))
    }
}


//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    UnknownScheme(String),
    DuplicateKey(Option<Box<Ident>>, Box<Ident>),
    Inner(storage::Error),
    Other(String),
}

impl KeyValueError {
    fn duplicate_key(scope: Option<&Ident>, key: &Ident) -> Self {
        Self::DuplicateKey(scope.map(Into::into), key.into())
    }
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
            KeyValueError::DuplicateKey(scope, key) => {
                match scope {
                    Some(scope) => {
                        write!(f, "Duplicate key {key} in scope {scope}")
                    }
                    None => {
                        write!(f, "Duplicate key {key} in global scope")
                    }
                }
            }
            KeyValueError::Inner(e) => write!(f, "Store error: {e}"),
            KeyValueError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

