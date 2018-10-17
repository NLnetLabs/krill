//! The KeyStore trait and some implementations.

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::iter::FromIterator;
use std::num;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use std::fs::ReadDir;

/// A Key for KeyStores.
///
/// These keys are based 'paths' which are Strings whose values can safely
/// be used to map keys to file a on disk for storage.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Key {
    path: PathBuf
}

impl Key {
    /// Creates a new key based on the path.
    ///
    /// Paths must not contain '/' so that they can be used as a single
    /// sub-dir when using a disk based key store.
    ///
    /// Other than this the may contain any character allowed in a
    /// 'segment' in the 'hier-part' defined in RFC3896 only, i.e:
    ///
    /// segment       = *pchar
    ///
    /// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
    ///
    /// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    /// pct-encoded   = "%" HEXDIG HEXDIG
    /// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" /
    ///                 "*" / "+" / "," / ";" / "="
    pub fn from_path(path: PathBuf) -> Result<Key, InvalidKey> {
        Self::verify_path(&path)?;
        Ok(Self { path })
    }

    /// Creates a new key based on a string. See 'from_path' for restrictions
    /// on allowed characters.
    pub fn from_string(path: String) -> Result<Key, InvalidKey> {
        let path = PathBuf::from(path);
        Self::from_path(path)
    }

    /// Creates an instance from a static str. Will unwrap, and panic, if
    /// unsafe characters are used. See 'from_path' for restrictions.
    pub fn from_str(s: &str) -> Key {
        let path = PathBuf::from(s);
        Self::from_path(path).unwrap()
    }

    fn verify_path(path: &PathBuf) -> Result<(), InvalidKey> {
        match path.to_str() {
            None => { return Err(InvalidKey) },
            Some(s) => {
                if ! s.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || // ALPHA DIGIT
                        b == b'-' || b == b'.' || b == b'_' || b == b'~' ||
                        b == b'%' || // Not checking against invalid % encoding (e.g. %%)
                        b == b'!' || b == b'$' || b == b'&' || b == b'\'' ||
                        b == b'(' || b == b')' || b == b'*' || b == b'+'  ||
                        b == b',' || b == b';' || b == b'='
                }) {
                    return Err(InvalidKey)
                }
            }
        }

        if path.components().all(|c| { c == Component::Normal("..".as_ref())})
            || ! path.is_relative()
        {
            return Err(InvalidKey);
        }

        Ok(())
    }
}

/// This type defines the meta-information for changes to a value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Info {
    #[serde(with = "ts_seconds")]
    date_time: DateTime<Utc>,
    actor: String,
    message: String
}

impl Info {
    pub fn new(
        date_time: DateTime<Utc>,
        actor: String,
        message: String
    ) -> Self {
        Info { date_time, actor, message }
    }

    pub fn now(
        actor: String,
        message: String
    ) -> Self {
        Info { date_time: Utc::now(), actor, message }
    }

    pub fn date_time(&self) -> &DateTime<Utc> {
        &self.date_time
    }

    pub fn actor(&self) -> &String {
        &self.actor
    }

    pub fn message(&self) -> &String {
        &self.message
    }
}


/// This type is used to signify any error in key formats.
#[derive(Debug)]
pub struct InvalidKey;

/// A KeyStore stores and archives Values of any type associated with a unique
/// Key and meta-information in the form of Info.
///
/// Internally it will use keys derived off the base key supplied by the
/// user of this Trait, to achieve the following:
///
/// Key -->
///     Values  -> 0, 1, ..
///     Info    -> 0, 1, ..
///     Current -> 0 | 1 | ..
///
pub trait KeyStore {

    type KeyIter: Iterator<Item=Key>;

    fn keys(&self) -> Self::KeyIter;

    /// Stores a key value pair.
    fn store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error>;

    /// Retrieves an optional Arc containing the current value, given the key.
    fn current_value<V: Any + Clone + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error>;

    /// Returns the current version for this key, if present. Version
    /// counting starts at 0.
    fn version(&self, key: &Key) -> Result<Option<u32>, Error>;




    // XXX TODO:
    // versioned_value()
    // versioned_info()


    fn key_for_name(&self, key: &Key, name: String) -> Key {
        let mut path = key.path.clone();
        path.push(name);
        Key { path }
    }

    fn key_for_value(&self, key: &Key, version: u32) -> Key {
        self.key_for_name(key, format!("v{}", version))
    }

    fn key_for_info(&self, key: &Key, version: u32) -> Key {
        self.key_for_name(key, format!("i{}", version))
    }

    fn key_for_version(&self, key: &Key) -> Key {
        self.key_for_name(key, "version".to_string())
    }



}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="Json serialization error: {}", _0)]
    JsonError(serde_json::Error),

    #[fail(display ="Something went wrong: {}", _0)]
    IoError(io::Error),

    #[fail(display ="Bad syntax in version: {}", _0)]
    IntError(num::ParseIntError),

    #[fail(display ="Something went wrong: {}", _0)]
    Other(String)
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<num::ParseIntError> for Error {
    fn from(e: num::ParseIntError) -> Self {
        Error::IntError(e)
    }
}


#[derive(Debug)]
/// This type implements an in memory keystore.
///
/// Note that this will only keep current Values only, as keeping archived
/// Values and Info in memory would incur too much memory usage.
pub struct MemoryKeyStore {
    store: HashMap<Key, CurrentMemoryEntry>
}

#[derive(Debug)]
struct CurrentMemoryEntry {
    version: u32,
    info: Info,
    value: Arc<Any + Send + Sync>
}

impl CurrentMemoryEntry {
    pub fn value_copy(&self) -> Arc<Any + Send + Sync> {
        self.value.clone()
    }
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        MemoryKeyStore { store: HashMap::new() }
    }
}

pub struct MemKeyIterator {
    keys: Vec<Key>
}

impl Iterator for MemKeyIterator {

    type Item = Key;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.keys.pop()
    }
}

impl KeyStore for MemoryKeyStore {

    type KeyIter = MemKeyIterator;

    fn keys(&self) -> Self::KeyIter {
        MemKeyIterator {
            keys:
                Vec::from_iter(
                    self.store.keys().map(|k| { k.clone() })
                )
        }
    }

    fn store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error> {
        let v = Arc::new(value);

        if let Some(current) = self.store.get_mut(&key) {
            current.version += 1;
            current.info = info;
            current.value = v;
            return Ok(())
        }

        let current = CurrentMemoryEntry {
            version: 0,
            info,
            value: v
        };

        self.store.insert(key, current);
        Ok(())
    }

    fn current_value<V: Any + Clone + DeserializeOwned + Send + Sync>(
        &self, key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        match self.store.get(key) {
            None => Ok(None),
            Some(ref v) => {
                if let Ok(res) = v.value_copy().downcast::<V>() {
                    Ok(Some(res))
                } else {
                    Err(Error::Other("Object has the wrong type!".to_string()))
                }
            }
        }
    }

    fn version(&self, key: &Key) -> Result<Option<u32>, Error> {
        Ok(self.store.get(key).map(|c| { c.version }))
    }
}

#[derive(Debug)]
pub struct DiskKeyStore {
    base_dir: PathBuf
}

/// An KeyIterator for a DiskKeyStorage.
pub struct DiskKeyIterator {
    dir_contents: ReadDir
}

impl DiskKeyIterator {
    /// Creates a DiskKeyIterator based on the DiskKeyStorage basepath, panics
    /// in case this underlying directory is gone..
    pub fn new(base: &PathBuf) -> Self {
        DiskKeyIterator { dir_contents: base.read_dir().unwrap() }
    }
}

impl Iterator for DiskKeyIterator {

    type Item = Key;

    /// This function will panic in case the directory lay-out is corrupted.
    /// E.g. if someone manually added dirs with names that are disallowed
    /// as Keys.
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match self.dir_contents.next() {
            None => None,
            Some(r) => {
                match r {
                    Err(e) => panic!(e),
                    Ok(e) => {
                        let path = PathBuf::from(e.path().file_name().unwrap());
                        match Key::from_path(path) {
                            Err(e) => panic!(e),
                            Ok(k) => { Some(k)
                            }
                        }
                    }
                }
            }
        }
    }
}


impl DiskKeyStore {
    pub fn new(base_dir: PathBuf) -> Result<Self, Error> {
        if base_dir.is_dir() {
            Ok(DiskKeyStore{base_dir})
        } else {
            panic!("Invalid base_dir for DiskKeyStore")
        }
    }

    fn verify_or_create_dir(&self, key: &Key) -> Result<(), Error> {
        if key.path.to_string_lossy().contains("/") {
            return Err(Error::Other("Key cannot contain subdir.".to_string()))
        }

        let mut full_path = PathBuf::new();
        full_path.push(self.base_dir.as_path());
        full_path.push(key.path.as_path());

        if !full_path.exists() {
            fs::create_dir_all(full_path)?;
        } else {
            if ! full_path.is_dir() {
                return Err(Error::Other("Key is not a dir".to_string()));
            }
        }

        Ok(())
    }
}

impl KeyStore for DiskKeyStore {

    type KeyIter = DiskKeyIterator;

    fn keys(&self) -> Self::KeyIter {
        DiskKeyIterator::new(&self.base_dir)
    }

    fn store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error> {
        self.verify_or_create_dir(&key)?;

        let new_version = match self.version(&key)? {
            None => 0,
            Some(v) => v + 1
        };

        let version_key = self.key_for_version(&key);
        let mut f = File::create(version_key.path)?;
        write!(f, "{}", new_version)?;

        let value_key = self.key_for_value(&key, new_version);
        let mut f = File::create(value_key.path)?;
        let v = serde_json::to_string(&value)?;
        f.write(v.as_ref())?;

        let info_key = self.key_for_info(&key, new_version);
        let mut f = File::create(info_key.path)?;
        let i = serde_json::to_string(&info)?;
        f.write(i.as_ref())?;

        Ok(())
    }

    fn current_value<V: Any + Clone + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        match self.version(key)? {
            None => Ok(None),
            Some(v) => {
                let value_key = self.key_for_value(&key, v);
                let path = value_key.path;

                let f = File::open(path)?;
                let v: V = serde_json::from_reader(f)?;
                Ok(Some(Arc::new(v)))
            }
        }


    }

    fn version(&self, key: &Key) -> Result<Option<u32>, Error> {
        let k = self.key_for_version(key);
        if k.path.exists() {
            let mut f = File::open(k.path)?;
            let mut s: String = "".to_string();
            f.read_to_string(&mut s)?;
            Ok(Some(u32::from_str(s.as_ref())?))
        } else {
            Ok(None)
        }
    }

    fn key_for_name(&self, key: &Key, name: String) -> Key {
        let mut path = self.base_dir.clone();
        path.push(key.path.clone());
        path.push(name);
        Key { path }
    }
}

#[derive(Debug)]
/// This keystore uses an in memory keystore for caching, and falls back
/// to a disk based key store.
pub struct CachingDiskKeyStore {
    mem_store: MemoryKeyStore,
    disk_store: DiskKeyStore
}

impl CachingDiskKeyStore {
    pub fn new(base_dir: PathBuf) -> Result<Self, Error> {
        let mem_store = MemoryKeyStore::new();
        let disk_store = DiskKeyStore::new(base_dir)?;
        Ok(CachingDiskKeyStore{mem_store, disk_store})
    }
}


impl KeyStore for CachingDiskKeyStore {

    type KeyIter = DiskKeyIterator;

    fn keys(&self) -> Self::KeyIter {
        DiskKeyIterator::new(&self.disk_store.base_dir)
    }

    fn store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error> {
        self.mem_store.store(key.clone(), value.clone(), info.clone())?;
        self.disk_store.store(key, value, info)
    }

    /// Retrieves the value from memory if possible, from disk otherwise.
    ///
    /// Note: this will NOT cache the value if it's retrieved from disk. Doing
    /// so would require '&mut self' which seems wrong. For now at least.
    ///
    /// In practical terms this should only cause a lookup penalty until a
    /// value is saved again after a restart.
    fn current_value<V: Any + Clone + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        let from_mem = self.mem_store.current_value(key)?;
        match from_mem {
            Some(v) => Ok(Some(v)),
            None => {
                self.disk_store.current_value(key)
            }
        }
    }

    /// Retrieves the current version from memory if possible, from disk
    /// otherwise.
    fn version(&self, key: &Key) -> Result<Option<u32>, Error> {
        let from_mem = self.mem_store.version(key)?;
        match from_mem {
            Some(v) => Ok(Some(v)),
            None => {
                self.disk_store.version(key)
            }

        }
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use test;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestStruct {
        v1: String,
        v2: u128
    }

    #[test]
    fn should_store_and_retrieve_in_memory() {
        let mut store = MemoryKeyStore::new();
        let key = Key::from_string("key_name".to_string()).unwrap();
        let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
        let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
        store.store(key.clone(), value.clone(), info).unwrap();

        let found: Option<Arc<TestStruct>> =
            store.current_value(&key).unwrap();

        assert_eq!(Some(Arc::new(value)), found)
    }

    #[test]
    fn should_store_and_retrieve_from_disk() {
        test::test_with_tmp_dir(|d| {
            let mut store = DiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_string("key1".to_string()).unwrap();
            let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());

            store.store(key.clone(), value.clone(), info).unwrap();

            let found: Option<Arc<TestStruct>> =
                store.current_value(&key).unwrap();

            assert_eq!(Some(Arc::new(value.clone())), found);

            let info2 = Info::new(
                Utc::now(),
                "them".to_string(),
                "same content!".to_string()
            );

            store.store(key.clone(), value.clone(), info2).unwrap();
        });


    }

    #[test]
    fn should_store_and_retrieve_from_caching_disk() {
        test::test_with_tmp_dir(|d| {
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_string("key_name".to_string()).unwrap();
            let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());

            store.store(key.clone(), value.clone(), info).unwrap();

            let found: Option<Arc<TestStruct>> =
                store.current_value(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)
        });
    }

    #[test]
    fn should_report_keys_from_mem_store() {
        let mut store = MemoryKeyStore::new();
        let key = Key::from_string("key_name".to_string()).unwrap();
        let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
        let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
        store.store(key.clone(), value.clone(), info).unwrap();

        let stored_keys: Vec<Key> = store.keys().collect();
        assert!(stored_keys.contains(&key));
        assert_eq!(1, stored_keys.len());
    }

    #[test]
    fn should_report_keys_from_disk_store() {
        test::test_with_tmp_dir(|d| {
            let mut store = DiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_string("key_name".to_string()).unwrap();
            let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
            store.store(key.clone(), value.clone(), info).unwrap();

            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());
        });
    }

    #[test]
    fn should_report_keys_from_caching_disk_store() {
        test::test_with_tmp_dir(|d| {
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_string("key_name".to_string()).unwrap();
            let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
            store.store(key.clone(), value.clone(), info).unwrap();

            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());
        });
    }


}