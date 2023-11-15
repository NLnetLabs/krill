use std::{collections::HashMap, fmt};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use url::Url;

use crate::commons::{
    error::KrillIoError,
    storage::{Disk, Key, Memory, Namespace, NamespaceBuf, Scope},
};

#[derive(Debug)]
pub enum KeyValueStore {
    Memory(Memory),
    Disk(Disk),
}

// # Construct and high level functions.
impl KeyValueStore {
    /// Creates a new KeyValueStore.
    pub fn create(storage_uri: &Url, namespace: &Namespace) -> Result<Self, KeyValueError> {
        match storage_uri.scheme() {
            "local" => {
                let path = format!("{}{}", storage_uri.host_str().unwrap_or_default(), storage_uri.path());

                Ok(KeyValueStore::Disk(Disk::new(&path, namespace.as_str())?))
            }
            "memory" => Ok(KeyValueStore::Memory(Memory::new(
                storage_uri.host_str(),
                namespace.to_owned(),
            )?)),
            scheme => Err(KeyValueError::UnknownScheme(scheme.to_owned()))?,
        }
    }

    /// Returns true if this KeyValueStore (with this namespace) has any entries.
    pub fn is_empty(&self) -> Result<bool, KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.is_empty())
    }

    /// Wipe the complete store. Needless to say perhaps.. use with care..
    pub fn wipe(&self) -> Result<(), KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.clear())
    }

    /// Execute one or more `KeyValueStoreDispatcher` operations
    /// within a transaction or scope lock context inside the given
    /// closure.
    ///
    /// The closure needs to return a Result<T, KeyValueError>. This
    /// allows the caller to simply use the ? operator on any kv
    /// calls that could result in an error within the closure.
    ///
    /// T can be () if no return value is needed. If anything can
    /// fail in the closure, other than kv calls, then T can be
    /// a Result<X,Y>.
    pub fn execute<F, T>(&self, scope: &Scope, op: F) -> Result<T, KeyValueError>
    where
        F: FnOnce(&KeyValueStoreDispatcher) -> Result<T, KeyValueError>,
    {
        let dispatcher = match self {
            KeyValueStore::Memory(memory) => KeyValueStoreDispatcher::Memory(memory),
            KeyValueStore::Disk(disk) => KeyValueStoreDispatcher::Disk(disk),
        };
        dispatcher.execute(scope, op)
    }
}

// # Keys and Values
impl KeyValueStore {
    /// Stores a key value pair, serialized as json, overwrite existing
    pub fn store<V: Serialize>(&self, key: &Key, value: &V) -> Result<(), KeyValueError> {
        self.execute(key.scope(), |kv: &KeyValueStoreDispatcher| {
            kv.store(key, serde_json::to_value(value)?)
        })
    }

    /// Stores a key value pair, serialized as json, fails if existing
    pub fn store_new<V: Serialize>(&self, key: &Key, value: &V) -> Result<(), KeyValueError> {
        self.execute(key.scope(), |kv: &KeyValueStoreDispatcher| match kv.get(key)? {
            None => kv.store(key, serde_json::to_value(value)?),
            _ => Err(KeyValueError::UnknownKey(key.to_owned())),
        })
    }

    /// Gets a value for a key, returns an error if the value cannot be deserialized,
    /// returns None if it cannot be found.
    pub fn get<V: DeserializeOwned>(&self, key: &Key) -> Result<Option<V>, KeyValueError> {
        self.execute(key.scope(), |kv| {
            if let Some(value) = kv.get(key)? {
                trace!("got value for key: {}", key);
                Ok(Some(serde_json::from_value(value)?))
            } else {
                trace!("got nothing for key: {}", key);
                Ok(None)
            }
        })
    }

    /// Returns whether a key exists
    pub fn has(&self, key: &Key) -> Result<bool, KeyValueError> {
        self.execute(key.scope(), |kv| kv.has(key))
    }

    /// Returns all keys for the given scope
    pub fn list_keys(&self, scope: &Scope) -> StorageResult<Vec<Key>> {
        self.execute(scope, |kv| kv.list_keys(scope))
    }

    /// Delete a key-value pair
    pub fn drop_key(&self, key: &Key) -> Result<(), KeyValueError> {
        self.execute(key.scope(), |kv| kv.delete(key))
    }

    /// Returns all keys under a scope (scopes are exact strings, 'sub'-scopes
    /// would need to be specified explicitly.. e.g. 'ca' and 'ca/archived' are
    /// two distinct scopes.
    ///
    /// If matching is not empty then the key must contain the given `&str`.
    pub fn keys(&self, scope: &Scope, matching: &str) -> Result<Vec<Key>, KeyValueError> {
        self.execute(scope, |kv| {
            kv.list_keys(scope).map(|keys| {
                keys.into_iter()
                    .filter(|key| {
                        key.scope() == scope && (matching.is_empty() || key.name().as_str().contains(matching))
                    })
                    .collect()
            })
        })
    }

    /// Returns all key value pairs under a scope.
    pub fn key_value_pairs(&self, scope: &Scope, matching: &str) -> Result<HashMap<Key, Value>, KeyValueError> {
        self.execute(scope, |kv| {
            let keys: Vec<Key> = kv.list_keys(scope).map(|keys| {
                keys.into_iter()
                    .filter(|key| {
                        key.scope() == scope && (matching.is_empty() || key.name().as_str().contains(matching))
                    })
                    .collect()
            })?;

            let mut pairs = HashMap::new();
            for key in keys {
                if let Some(value) = kv.get(&key)? {
                    pairs.insert(key, value);
                }
            }

            Ok(pairs)
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

    /// Returns all scopes, including sub_scopes
    pub fn scopes(&self) -> Result<Vec<Scope>, KeyValueError> {
        self.execute(&Scope::global(), |kv| kv.list_scopes())
    }
}

// # Migration Support
impl KeyValueStore {
    /// Creates a new KeyValueStore for upgrades.
    ///
    /// Adds the implicit prefix "upgrade-{version}-" to the given namespace.
    pub fn create_upgrade_store(storage_uri: &Url, namespace: &Namespace) -> Result<Self, KeyValueError> {
        let namespace = Self::prefixed_namespace(namespace, "upgrade")?;
        KeyValueStore::create(storage_uri, namespace.as_ref())
    }

    fn prefixed_namespace(namespace: &Namespace, prefix: &str) -> Result<NamespaceBuf, KeyValueError> {
        let namespace_string = format!("{}_{}", prefix, namespace);
        Namespace::parse(&namespace_string)
            .map_err(|e| KeyValueError::Other(format!("Cannot parse namespace: {}. Error: {}", namespace_string, e)))
            .map(|ns| ns.to_owned())
    }

    /// Archive this store (i.e. for this namespace). Deletes
    /// any existing archive for this namespace if present.
    pub fn migrate_to_archive(&mut self, storage_uri: &Url, namespace: &Namespace) -> Result<(), KeyValueError> {
        let archive_ns = Self::prefixed_namespace(namespace, "archive")?;
        // Wipe any existing archive, before archiving this store.
        // We don't want to keep too much old data. See issue: #1088.
        let archive_store = KeyValueStore::create(storage_uri, &archive_ns)?;
        archive_store.wipe()?;

        match self {
            KeyValueStore::Memory(memory) => memory.migrate_namespace(archive_ns),
            KeyValueStore::Disk(disk) => disk.migrate_namespace(archive_ns),
        }
    }

    /// Make this (upgrade) store the current store.
    ///
    /// Fails if there is a non-empty current store.
    pub fn migrate_to_current(&mut self, storage_uri: &Url, namespace: &Namespace) -> Result<(), KeyValueError> {
        let current_store = KeyValueStore::create(storage_uri, namespace)?;
        if !current_store.is_empty()? {
            Err(KeyValueError::Other(format!(
                "Abort migrate upgraded store for {} to current. The current store was not archived.",
                namespace
            )))
        } else {
            match self {
                KeyValueStore::Memory(memory) => memory.migrate_namespace(namespace.into()),
                KeyValueStore::Disk(disk) => disk.migrate_namespace(namespace.into()),
            }
        }
    }

    /// Import all data from the given KV store into this
    ///
    /// NOTE: This function is not transactional because both this, and the other
    ///       keystore could be in the same database and nested transactions are
    ///       currently not supported. This should be okay, because this function
    ///       is intended to be used for migrations and testing (copy test data
    ///       into a store) while Krill is not running.
    pub fn import(&self, other: &Self) -> Result<(), KeyValueError> {
        debug!("Import keys from {} into {}", other, self);
        let mut scopes = other.scopes()?;
        scopes.push(Scope::global()); // not explicitly listed but should be migrated as well.

        for scope in scopes {
            let key_value_pairs = other.key_value_pairs(&scope, "")?;
            trace!(
                "Migrating {} key value pairs in scope {}.",
                key_value_pairs.len(),
                scope
            );

            self.execute(&scope, |kv| {
                for (key, value) in key_value_pairs.into_iter() {
                    trace!("  ---storing key {}", key);
                    kv.store(&key, value)?;
                }
                Ok(())
            })?;
        }

        Ok(())
    }
}

impl fmt::Display for KeyValueStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyValueStore::Memory(memory) => memory.fmt(f),
            KeyValueStore::Disk(disk) => disk.fmt(f),
        }
    }
}

//------------ KeyValueStoreDispatcher ---------------------------------------

#[derive(Debug)]
pub enum KeyValueStoreDispatcher<'a> {
    Memory(&'a Memory),
    Disk(&'a Disk),
}

impl<'a> KeyValueStoreDispatcher<'a> {
    pub fn execute<F, T>(&self, scope: &Scope, op: F) -> Result<T, KeyValueError>
    where
        F: FnOnce(&KeyValueStoreDispatcher) -> Result<T, KeyValueError>,
    {
        match self {
            KeyValueStoreDispatcher::Memory(memory) => memory.execute(scope, op),
            KeyValueStoreDispatcher::Disk(disk) => disk.execute(scope, op),
        }
    }

    fn is_empty(&self) -> StorageResult<bool> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.is_empty(),
            KeyValueStoreDispatcher::Disk(d) => d.is_empty(),
        }
    }
    pub fn has(&self, key: &Key) -> StorageResult<bool> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.has(key),
            KeyValueStoreDispatcher::Disk(d) => d.has(key),
        }
    }
    fn has_scope(&self, scope: &Scope) -> StorageResult<bool> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.has_scope(scope),
            KeyValueStoreDispatcher::Disk(d) => d.has_scope(scope),
        }
    }

    pub fn get(&self, key: &Key) -> StorageResult<Option<Value>> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.get(key),
            KeyValueStoreDispatcher::Disk(d) => d.get(key),
        }
    }

    pub fn list_keys(&self, scope: &Scope) -> StorageResult<Vec<Key>> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.list_keys(scope),
            KeyValueStoreDispatcher::Disk(d) => d.list_keys(scope),
        }
    }
    fn list_scopes(&self) -> StorageResult<Vec<Scope>> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.list_scopes(),
            KeyValueStoreDispatcher::Disk(d) => d.list_scopes(),
        }
    }

    /// Store a value.
    pub fn store(&self, key: &Key, value: Value) -> StorageResult<()> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.store(key, value),
            KeyValueStoreDispatcher::Disk(d) => d.store(key, value),
        }
    }

    /// Move a value to a new key. Fails if the original value does not exist.
    pub fn move_value(&self, from: &Key, to: &Key) -> StorageResult<()> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.move_value(from, to),
            KeyValueStoreDispatcher::Disk(d) => d.move_value(from, to),
        }
    }

    /// Delete a value for a key.
    pub fn delete(&self, key: &Key) -> StorageResult<()> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.delete(key),
            KeyValueStoreDispatcher::Disk(d) => d.delete(key),
        }
    }

    /// Delete all values for a scope.
    pub fn delete_scope(&self, scope: &Scope) -> StorageResult<()> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.delete_scope(scope),
            KeyValueStoreDispatcher::Disk(d) => d.delete_scope(scope),
        }
    }

    /// Delete all values within the namespace of this store.
    fn clear(&self) -> StorageResult<()> {
        match self {
            KeyValueStoreDispatcher::Memory(m) => m.clear(),
            KeyValueStoreDispatcher::Disk(d) => d.clear(),
        }
    }
}

impl<'a> fmt::Display for KeyValueStoreDispatcher<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyValueStoreDispatcher::Memory(memory) => memory.fmt(f),
            KeyValueStoreDispatcher::Disk(disk) => disk.fmt(f),
        }
    }
}

//------------ StorageResult -------------------------------------------------

pub type StorageResult<T> = Result<T, KeyValueError>;

//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    UnknownScheme(String),
    IoError(KrillIoError),
    JsonError(serde_json::Error),
    UnknownKey(Key),
    InvalidKey(Key),
    DuplicateKey(Key),
    InvalidTaskKey(Key),
    Other(String),
}

impl From<KrillIoError> for KeyValueError {
    fn from(e: KrillIoError) -> Self {
        KeyValueError::IoError(e)
    }
}

impl From<serde_json::Error> for KeyValueError {
    fn from(e: serde_json::Error) -> Self {
        KeyValueError::JsonError(e)
    }
}

impl fmt::Display for KeyValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyValueError::UnknownScheme(e) => write!(f, "Unknown Scheme: {}", e),
            KeyValueError::IoError(e) => write!(f, "I/O error: {}", e),
            KeyValueError::JsonError(e) => write!(f, "JSON error: {}", e),
            KeyValueError::UnknownKey(key) => write!(f, "Unknown key: {}", key),
            KeyValueError::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            KeyValueError::DuplicateKey(key) => write!(f, "Duplicate key: {}", key),
            KeyValueError::InvalidTaskKey(key) => write!(f, "Invalid task key: {}", key),
            KeyValueError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use futures_util::join;
    use rand::{distributions::Alphanumeric, Rng};

    use crate::{commons::storage::SegmentBuf, test};

    use super::*;

    fn random_value(length: usize) -> Value {
        Value::from(
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .map(char::from)
                .collect::<String>(),
        )
    }

    fn random_segment() -> SegmentBuf {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn random_namespace() -> NamespaceBuf {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn random_scope(depth: usize) -> Scope {
        Scope::new(std::iter::repeat_with(random_segment).take(depth).collect())
    }

    fn random_key(depth: usize) -> Key {
        Key::new_scoped(random_scope(depth), random_segment())
    }

    fn impl_store(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(content));
    }

    fn impl_store_new(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());

        assert!(store.store_new(&key, &content).is_ok());
        assert!(store.store_new(&key, &content).is_err());
    }

    fn impl_store_scoped(store: KeyValueStore) {
        let content = "content".to_owned();
        let id = random_segment();
        let scope = Scope::from_segment(SegmentBuf::parse_lossy("scope"));
        let key = Key::new_scoped(scope.clone(), id.clone());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(content.clone()));
        assert!(store.has_scope(&scope).unwrap());

        let simple = Key::new_global(id);
        store.store(&simple, &content).unwrap();
        assert!(store.has(&simple).unwrap());
        assert_eq!(store.get(&simple).unwrap(), Some(content));
    }

    fn impl_get(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert_eq!(store.get::<String>(&key).unwrap(), None);

        store.store(&key, &content).unwrap();
        assert_eq!(store.get(&key).unwrap(), Some(content));
    }

    fn impl_get_transactional(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert_eq!(store.get::<String>(&key).unwrap(), None);

        store.store(&key, &content).unwrap();
        assert_eq!(store.get(&key).unwrap(), Some(content));
    }

    fn impl_has(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert!(!store.has(&key).unwrap());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());
    }

    fn impl_drop_key(store: KeyValueStore) {
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        store.drop_key(&key).unwrap();
        assert!(!store.has(&key).unwrap());
    }

    fn impl_drop_scope(store: KeyValueStore) {
        let content = "content".to_owned();
        let scope = Scope::from_segment(random_segment());
        let key = Key::new_scoped(scope.clone(), random_segment());
        let key2 = Key::new_scoped(Scope::from_segment(random_segment()), random_segment());
        store.store(&key, &content).unwrap();
        store.store(&key2, &content).unwrap();
        assert!(store.has_scope(&scope).unwrap());
        assert!(store.has(&key).unwrap());
        assert!(store.has(&key2).unwrap());

        store.drop_scope(&scope).unwrap();
        assert!(!store.has_scope(&scope).unwrap());
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&key2).unwrap());
    }

    fn impl_wipe(store: KeyValueStore) {
        let content = "content".to_owned();
        let scope = Scope::from_segment(SegmentBuf::parse_lossy("scope"));
        let key = Key::new_scoped(scope.clone(), random_segment());
        store.store(&key, &content).unwrap();
        assert!(store.has_scope(&scope).unwrap());
        assert!(store.has(&key).unwrap());

        store.wipe().unwrap();
        assert!(!store.has_scope(&scope).unwrap());
        assert!(!store.has(&key).unwrap());
        assert!(store.keys(&Scope::global(), "").unwrap().is_empty());
    }

    fn impl_list_scopes(store: KeyValueStore) {
        let content = "content".to_owned();
        let id = SegmentBuf::parse_lossy("id");
        let scope = Scope::from_segment(random_segment());
        let key = Key::new_scoped(scope.clone(), id.clone());

        assert!(store.scopes().unwrap().is_empty());

        store.store(&key, &content).unwrap();
        assert_eq!(store.scopes().unwrap(), [scope.clone()]);

        let scope2 = Scope::from_segment(random_segment());
        let key2 = Key::new_scoped(scope2.clone(), id);
        store.store(&key2, &content).unwrap();

        let mut scopes = store.scopes().unwrap();
        scopes.sort();
        let mut expected = vec![scope.clone(), scope2.clone()];
        expected.sort();
        assert_eq!(scopes, expected);

        store.drop_scope(&scope2).unwrap();
        assert_eq!(store.scopes().unwrap(), vec![scope]);
    }

    fn impl_has_scope(store: KeyValueStore) {
        let content = "content".to_owned();
        let scope = Scope::from_segment(random_segment());
        let key = Key::new_scoped(scope.clone(), SegmentBuf::parse_lossy("id"));
        assert!(!store.has_scope(&scope).unwrap());

        store.store(&key, &content).unwrap();
        assert!(store.has_scope(&scope).unwrap());
    }

    fn impl_list_keys(store: KeyValueStore) {
        let content = "content".to_owned();
        let id = SegmentBuf::parse_lossy("command--id");
        let scope = Scope::from_segment(SegmentBuf::parse_lossy("command"));
        let key = Key::new_scoped(scope.clone(), id);

        let id2 = SegmentBuf::parse_lossy("command--ls");
        let id3 = random_segment();
        let key2 = Key::new_scoped(scope.clone(), id2.clone());
        let key3 = Key::new_global(id3.clone());

        store.store(&key, &content).unwrap();
        store.store(&key2, &content).unwrap();
        store.store(&key3, &content).unwrap();

        let mut keys = store.keys(&scope, "command--").unwrap();
        keys.sort();
        let mut expected = vec![key.clone(), key2.clone()];
        expected.sort();

        assert_eq!(keys, expected);
        assert_eq!(store.keys(&scope, id2.as_str()).unwrap(), [key2.clone()]);
        assert_eq!(store.keys(&scope, id3.as_str()).unwrap(), []);
        assert_eq!(store.keys(&Scope::global(), id3.as_str()).unwrap(), [key3]);

        let mut keys = store.keys(&scope, "").unwrap();
        keys.sort();
        let mut expected = vec![key, key2];
        expected.sort();

        assert_eq!(keys, expected);
    }

    fn impl_is_empty(store: KeyValueStore) {
        assert!(store.is_empty().unwrap());
        store.store(&random_key(1), &random_value(8)).unwrap();

        assert!(!store.is_empty().unwrap());
    }

    async fn impl_execute(store: KeyValueStore) {
        // Test that one transaction does not interfere with another
        // We start with an empty store, then start multiple threads
        // that each use the same store to add / remove and eventually
        // remove all keys that they have added in a single transaction.
        //
        // We expect that threads use separate transactions / locks, so
        // they may have to wait on one another, but they won't see any
        // of the key value pairs that are put there by others (i.e. we
        // clean up at the end)

        async fn one_thread_execute(store: &KeyValueStore) {
            let scope = Scope::global();

            store
                .execute(&scope, |kv| {
                    // start with an empty kv
                    assert!(kv.is_empty().unwrap());

                    // add a bunch of keys, see that they are there
                    // and nothing else
                    let mut keys: Vec<Key> = (0..8).map(|_| random_key(1)).collect();
                    keys.sort();

                    for key in &keys {
                        kv.store(key, random_value(8)).unwrap();
                    }
                    assert!(!kv.is_empty().unwrap());

                    // TODO: use non-blocking sleep when we have an async closure
                    std::thread::sleep(std::time::Duration::from_millis(200));

                    let mut stored_keys = kv.list_keys(&scope).unwrap();
                    stored_keys.sort();

                    assert_eq!(keys.len(), stored_keys.len());
                    assert_eq!(keys, stored_keys);

                    for key in &keys {
                        kv.delete(key).unwrap();
                    }
                    assert!(kv.is_empty().unwrap());

                    Ok(())
                })
                .unwrap();
        }

        let thread_1 = one_thread_execute(&store);
        let thread_2 = one_thread_execute(&store);

        join!(thread_1, thread_2);
    }

    fn test_store(storage_uri: &Url) -> KeyValueStore {
        KeyValueStore::create(storage_uri, &random_namespace()).unwrap()
    }

    async fn test_impl(storage_uri: Url) {
        impl_store(test_store(&storage_uri));
        impl_store_new(test_store(&storage_uri));
        impl_store_scoped(test_store(&storage_uri));
        impl_get(test_store(&storage_uri));
        impl_get_transactional(test_store(&storage_uri));
        impl_has(test_store(&storage_uri));
        impl_drop_key(test_store(&storage_uri));
        impl_drop_scope(test_store(&storage_uri));
        impl_wipe(test_store(&storage_uri));
        impl_list_scopes(test_store(&storage_uri));
        impl_has_scope(test_store(&storage_uri));
        impl_list_keys(test_store(&storage_uri));
        impl_is_empty(test_store(&storage_uri));
        impl_execute(test_store(&storage_uri)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mem_store_tests() {
        let storage_uri = test::mem_storage();
        test_impl(storage_uri).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn disk_store_tests() {
        let (dir, cleanup) = test::tmp_dir();
        let storage_uri = Url::parse(&format!("local://{}/{}", dir.display(), test::random_hex_string())).unwrap();
        test_impl(storage_uri).await;

        cleanup();
    }
}
