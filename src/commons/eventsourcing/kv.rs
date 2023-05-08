use std::fmt;

pub use kvx::{segment, Key, Scope, Segment, SegmentBuf};
use kvx::{KeyValueStoreBackend, ReadStore, WriteStore};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

use crate::commons::{error::KrillIoError, util::KrillVersion};

pub trait SegmentExt {
    fn parse_lossy(value: &str) -> SegmentBuf;
    fn concat(lhs: impl Into<SegmentBuf>, rhs: impl Into<SegmentBuf>) -> SegmentBuf;
}

impl SegmentExt for Segment {
    fn parse_lossy(value: &str) -> SegmentBuf {
        match Segment::parse(value) {
            Ok(segment) => segment.to_owned(),
            Err(error) => {
                let sanitized = value.trim().replace(Scope::SEPARATOR, "+");
                let nonempty = sanitized.is_empty().then(|| "EMPTY".to_owned()).unwrap_or(sanitized);
                let segment = Segment::parse(&nonempty).unwrap(); // cannot panic as all checks are performed above
                warn!("{value} is not a valid Segment: {error}\nusing {segment} instead");
                segment.to_owned()
            }
        }
    }

    fn concat(lhs: impl Into<SegmentBuf>, rhs: impl Into<SegmentBuf>) -> SegmentBuf {
        Segment::parse(&format!("{}{}", lhs.into(), rhs.into()))
            .unwrap()
            .to_owned()
    }
}

#[derive(Debug)]
pub struct KeyValueStore {
    inner: kvx::KeyValueStore,
}

impl KeyValueStore {
    pub fn create(storage_uri: &Url, name_space: impl Into<SegmentBuf>) -> Result<Self, KeyValueError> {
        let store = KeyValueStore {
            inner: kvx::KeyValueStore::new(storage_uri, name_space)?,
        };
        store.init_version()?;
        Ok(store)
    }

    /// Stores a key value pair, serialized as json, overwrite existing
    pub fn store<V: Serialize>(&self, key: &Key, value: &V) -> Result<(), KeyValueError> {
        Ok(self.inner.store(key, serde_json::to_value(value)?)?)
    }

    /// Stores a key value pair, serialized as json, fails if existing
    pub fn store_new<V: Serialize>(&self, key: &Key, value: &V) -> Result<(), KeyValueError> {
        Ok(self.inner.transaction(
            key.scope(),
            &mut move |kv: &dyn KeyValueStoreBackend| match kv.get(key)? {
                None => kv.store(key, serde_json::to_value(value)?),
                _ => Err(kvx::Error::Unknown),
            },
        )?)
    }

    /// Gets a value for a key, returns an error if the value cannot be deserialized,
    /// returns None if it cannot be found.
    pub fn get<V: DeserializeOwned>(&self, key: &Key) -> Result<Option<V>, KeyValueError> {
        if let Some(value) = self.inner.get(key)? {
            Ok(serde_json::from_value(value)?)
        } else {
            Ok(None)
        }
    }

    /// Transactional `get`.
    pub fn get_transactional<V: DeserializeOwned>(&self, key: &Key) -> Result<Option<V>, KeyValueError> {
        let mut result: Option<V> = None;
        let result_ref = &mut result;
        self.inner
            .transaction(key.scope(), &mut move |kv: &dyn KeyValueStoreBackend| {
                if let Some(value) = kv.get(key)? {
                    *result_ref = Some(serde_json::from_value(value)?)
                }

                Ok(())
            })?;

        Ok(result)
    }

    /// Returns whether a key exists
    pub fn has(&self, key: &Key) -> Result<bool, KeyValueError> {
        Ok(self.inner.has(key)?)
    }

    /// Delete a key-value pair
    pub fn drop_key(&self, key: &Key) -> Result<(), KeyValueError> {
        Ok(self.inner.delete(key)?)
    }

    /// Delete a scope
    pub fn drop_scope(&self, scope: &Scope) -> Result<(), KeyValueError> {
        Ok(self.inner.delete_scope(scope)?)
    }

    /// Wipe the complete store. Needless to say perhaps.. use with care..
    pub fn wipe(&self) -> Result<(), KeyValueError> {
        Ok(self.inner.clear()?)
    }

    /// Move a value from one key to another
    pub fn move_key(&self, from: &Key, to: &Key) -> Result<(), KeyValueError> {
        Ok(self.inner.move_value(from, to)?)
    }

    /// Archive a key
    pub fn archive(&self, key: &Key) -> Result<(), KeyValueError> {
        self.move_key(key, &key.clone().with_sub_scope(segment!("archived")))
    }

    /// Archive a key as corrupt
    pub fn archive_corrupt(&self, key: &Key) -> Result<(), KeyValueError> {
        self.move_key(key, &key.clone().with_sub_scope(segment!("corrupt")))
    }

    /// Archive a key as surplus
    pub fn archive_surplus(&self, key: &Key) -> Result<(), KeyValueError> {
        self.move_key(key, &key.clone().with_sub_scope(segment!("surplus")))
    }

    /// Returns all 1st level scopes
    pub fn scopes(&self) -> Result<Vec<Scope>, KeyValueError> {
        Ok(self.inner.list_scopes()?)
    }

    /// Returns whether a scope exists
    pub fn has_scope(&self, scope: &Scope) -> Result<bool, KeyValueError> {
        Ok(self.inner.has_scope(scope)?)
    }

    /// Returns all keys under a scope (scopes are exact strings, 'sub'-scopes
    /// would need to be specified explicitly.. e.g. 'ca' and 'ca/archived' are
    /// two distinct scopes.
    ///
    /// If matching is not empty then the key must contain the given `&str`.
    pub fn keys(&self, scope: &Scope, matching: &str) -> Result<Vec<Key>, KeyValueError> {
        Ok(self
            .inner
            .list_keys(scope)?
            .into_iter()
            .filter(|key| matching.is_empty() || key.name().as_str().contains(matching))
            .collect())
    }

    /// Stores the Krill version in the store, if it does not exist already. Can
    /// occur at the same time as another store, but they will write the same
    /// version anyway.
    fn init_version(&self) -> Result<(), KeyValueError> {
        if self.inner.get(&Self::version_key())?.is_none() {
            self.version_set_current()?
        }

        Ok(())
    }

    /// Returns the version of a key store.
    /// KeyStore use a specific key-value pair to track their version. If the key is absent it
    /// is assumed that the version was from before Krill 0.6.0. An error is returned if the key
    /// is present, but the value is corrupt or not recognized.
    pub fn version(&self) -> Result<KrillVersion, KeyValueError> {
        self.get(&Self::version_key())
            .map(|version_opt| version_opt.unwrap_or_else(KrillVersion::v0_5_0_or_before))
    }

    /// Returns whether the version of this key store predates the given version.
    /// KeyStore use a specific key-value pair to track their version. If the key is absent it
    /// is assumed that the version was from before Krill 0.6.0. An error is returned if the key
    /// is present, but the value is corrupt or not recognized.
    pub fn version_is_before(&self, later: KrillVersion) -> Result<bool, KeyValueError> {
        let version = self.version()?;
        Ok(version < later)
    }

    pub fn version_is_after(&self, earlier: KrillVersion) -> Result<bool, KeyValueError> {
        let version = self.version()?;
        Ok(version > earlier)
    }

    /// Returns whether the version of the deployed keystore matches that of the
    /// currently deployed code.
    pub fn version_is_current(&self) -> Result<bool, KeyValueError> {
        self.version().map(|deployed| deployed == KrillVersion::code_version())
    }

    /// Sets the version of this key store to the currently deployed code
    pub fn version_set_current(&self) -> Result<(), KeyValueError> {
        self.store(&Self::version_key(), &KrillVersion::code_version())
    }

    fn version_key() -> Key {
        Key::new_global(segment!("version"))
    }
}

//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    UnknownScheme(String),
    IoError(KrillIoError),
    JsonError(serde_json::Error),
    UnknownKey(Key),
    DuplicateKey(Key),
    KVError(kvx::Error),
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

impl From<kvx::Error> for KeyValueError {
    fn from(e: kvx::Error) -> Self {
        KeyValueError::KVError(e)
    }
}

impl fmt::Display for KeyValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyValueError::UnknownScheme(e) => write!(f, "Unknown Scheme: {}", e),
            KeyValueError::IoError(e) => write!(f, "I/O error: {}", e),
            KeyValueError::JsonError(e) => write!(f, "JSON error: {}", e),
            KeyValueError::UnknownKey(key) => write!(f, "Unknown key: {}", key),
            KeyValueError::DuplicateKey(key) => write!(f, "Duplicate key: {}", key),
            KeyValueError::KVError(e) => write!(f, "Store error: {}", e),
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    use rand::{distributions::Alphanumeric, Rng};

    fn random_segment() -> SegmentBuf {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn get_storage_uri() -> Url {
        env::var("KRILL_KV_STORAGE_URL")
            .ok()
            .and_then(|s| Url::parse(&s).ok())
            .unwrap_or_else(|| Url::parse("memory:///tmp").unwrap())
    }

    #[test]
    fn test_store() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(content));
    }

    #[test]
    fn test_store_new() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());

        assert!(store.store_new(&key, &content).is_ok());
        assert!(store.store_new(&key, &content).is_err());
    }

    #[test]
    fn test_store_scoped() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let id = random_segment();
        let scope = Scope::from_segment(segment!("scope"));
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

    #[test]
    fn test_get() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert_eq!(store.get::<String>(&key).unwrap(), None);

        store.store(&key, &content).unwrap();
        assert_eq!(store.get(&key).unwrap(), Some(content));
    }

    #[test]
    fn test_get_transactional() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert_eq!(store.get_transactional::<String>(&key).unwrap(), None);

        store.store(&key, &content).unwrap();
        assert_eq!(store.get_transactional(&key).unwrap(), Some(content));
    }

    #[test]
    fn test_has() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        assert!(!store.has(&key).unwrap());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());
    }

    #[test]
    fn test_drop_key() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let key = Key::new_global(random_segment());
        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        store.drop_key(&key).unwrap();
        assert!(!store.has(&key).unwrap());
    }

    #[test]
    fn test_drop_scope() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
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

    #[test]
    fn test_wipe() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let scope = Scope::from_segment(segment!("scope"));
        let key = Key::new_scoped(scope.clone(), random_segment());
        store.store(&key, &content).unwrap();
        assert!(store.has_scope(&scope).unwrap());
        assert!(store.has(&key).unwrap());

        store.wipe().unwrap();
        assert!(!store.has_scope(&scope).unwrap());
        assert!(!store.has(&key).unwrap());
        assert!(store.keys(&Scope::global(), "").unwrap().is_empty());
    }

    #[test]
    fn test_move_key() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_string();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        let target = Key::new_global(random_segment());
        store.move_key(&key, &target).unwrap();
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&target).unwrap());
    }

    #[test]
    fn test_archive() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_string();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        store.archive(&key).unwrap();
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&key.with_sub_scope(segment!("archived"))).unwrap());
    }

    #[test]
    fn test_archive_corrupt() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_string();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        store.archive_corrupt(&key).unwrap();
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&key.with_sub_scope(segment!("corrupt"))).unwrap());
    }

    #[test]
    fn test_archive_surplus() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_string();
        let key = Key::new_global(random_segment());

        store.store(&key, &content).unwrap();
        assert!(store.has(&key).unwrap());

        store.archive_surplus(&key).unwrap();
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&key.with_sub_scope(segment!("surplus"))).unwrap());
    }

    #[test]
    fn test_scopes() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let id = segment!("id");
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

    #[test]
    fn test_has_scope() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let scope = Scope::from_segment(random_segment());
        let key = Key::new_scoped(scope.clone(), segment!("id"));
        assert!(!store.has_scope(&scope).unwrap());

        store.store(&key, &content).unwrap();
        assert!(store.has_scope(&scope).unwrap());
    }

    #[test]
    fn test_keys() {
        let storage_uri = get_storage_uri();

        let store = KeyValueStore::create(&storage_uri, random_segment()).unwrap();
        let content = "content".to_owned();
        let id = segment!("command--id");
        let scope = Scope::from_segment(segment!("command"));
        let key = Key::new_scoped(scope.clone(), id);

        let id2 = segment!("command--ls");
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
}
