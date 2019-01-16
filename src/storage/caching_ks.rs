//! A keystore implementation using local storage and caching.
use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fs::{File, ReadDir};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use crate::storage::keystore::{Error, Info, Key, KeyStore};


//------------ CurrentMemoryEntry --------------------------------------------

/// This type is used to store current values in memory for caching.
#[derive(Clone, Debug)]
struct CurrentMemoryEntry {
    version: i32,
    value: Arc<Any + Send + Sync>
}

impl CurrentMemoryEntry {
    pub fn value_copy(&self) -> Arc<Any + Send + Sync> {
        self.value.clone()
    }
}


//------------ CachingDiskKeyStore -------------------------------------------

/// This keystore uses an in memory keystore for caching, and falls back
/// to a disk based key store.
#[derive(Clone, Debug)]
pub struct CachingDiskKeyStore {
    cache: Arc<RwLock<HashMap<Key, CurrentMemoryEntry>>>,
    base_dir: PathBuf
}

/// # Creating
impl CachingDiskKeyStore {
    pub fn new(base_dir: PathBuf) -> Result<Self, Error> {
        if ! base_dir.is_dir() {
            Err(Error::Other("Invalid base_dir for DiskKeyStore".to_string()))
        } else {
            let cache = HashMap::new();
            Ok(CachingDiskKeyStore{
                cache: Arc::new(RwLock::new(cache)),
                base_dir})
        }
    }
}

/// # Cache support functions
impl CachingDiskKeyStore {
    /// Stores the current value for key into an Arc, for safe sharing.
    fn cache_store<V: Any + Serialize + Send + Sync>(
        &self,
        key: Key,
        value: V,
        version: i32
    ) -> Result<(), Error>{
        let v = Arc::new(value);

        let mut w = self.cache.write()
            .map_err(|_| Error::from_str("Write Lock error"))?;
        if let Some(current) = w.get_mut(&key) {
            current.version += 1;
            current.value = v;
            return Ok(())

        }
        let current = CurrentMemoryEntry {
            version,
            value: v
        };

        w.insert(key, current);
        Ok(())
    }

    /// Gets the current value for a key, if any.
    fn cache_get<V: Any + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        let r = self.cache.read().map_err(
            |_| Error::from_str("Can't get read lock"))?;
        match r.get(key) {
            None => Ok(None),
            Some(ref v) => {
                if let Ok(res) = v.value_copy().downcast::<V>() {
                    Ok(Some(res))
                } else {
                    Err(Error::from_str("Object has the wrong type!"))
                }
            }
        }
    }

    /// Gets the version for the current value for a key, if any.
    fn cache_version(&self, key: &Key) -> Result<Option<i32>, Error> {
        let r = self.cache.read().map_err(
            |_| Error::from_str("Can't get read lock"))?;
        Ok(r.get(key).map(|c| { c.version }))
    }
}


/// # Store on / retrieve from disk
impl CachingDiskKeyStore {
    /// Verifies that the base directory exists, or tries to create it.
    fn verify_or_create_dir(&self, key: &Key) -> Result<(), Error> {
        if key.path().to_string_lossy().contains("/") {
            return Err(Error::from_str("Key cannot contain subdir."))
        }

        let mut full_path = PathBuf::new();
        full_path.push(self.base_dir.as_path());
        full_path.push(key.path().as_path());

        if !full_path.exists() {
            fs::create_dir_all(full_path)?;
        } else {
            if ! full_path.is_dir() {
                return Err(Error::from_str("Key is not a dir"));
            }
        }

        Ok(())
    }

    /// Returns the full path for a file, relative to the basedir of the
    /// cache.
    fn full_path(&self, path: &PathBuf) -> PathBuf {
        let mut res = self.base_dir.clone();
        res.push(path);
        res
    }

    /// Stores the value, info and version to disk. Serialized to json.
    fn disk_store<V: Any + Serialize + Send + Sync>(
        &self,
        key: &Key,
        value: &V,
        info: &Info,
        version: i32
    ) -> Result<(), Error> {
        self.verify_or_create_dir(&key)?;

        let version_key = self.key_for_version(&key);
        let mut f = File::create(self.full_path(version_key.path()))?;
        write!(f, "{}", version)?;

        let value_key = self.key_for_value(&key, version);
        let mut f = File::create(self.full_path(value_key.path()))?;
        let v = serde_json::to_string(&value)?;
        f.write(v.as_ref())?;

        let info_key = self.key_for_info(&key, version);
        let mut f = File::create(self.full_path(info_key.path()))?;
        let i = serde_json::to_string(&info)?;
        f.write(i.as_ref())?;

        Ok(())
    }

    /// Gets the current value from disk, if there is a current version.
    fn disk_get<V: Any + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<V>, Error> {
        match self.version(key)? {
            None => Ok(None),
            Some(v) => {
                if v > 0 {
                    let value_key = self.key_for_value(&key, v);
                    let f = File::open(self.full_path(value_key.path()))?;
                    let v: V = serde_json::from_reader(f)?;
                    Ok(Some(v))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Gets the current version for a key. Negative numbers indicate that
    /// the version was archived.
    fn disk_version(&self, key: &Key) -> Result<Option<i32>, Error> {
        let k = self.full_path(self.key_for_version(key).path());
        if k.exists() {
            let mut f = File::open(k)?;
            let mut s: String = "".to_string();
            f.read_to_string(&mut s)?;
            Ok(Some(i32::from_str(s.as_ref())?))
        } else {
            Ok(None)
        }
    }

    /// Archives the current version for a key, by negating the version
    /// number. Note that versions can be 'revived' simply by storing a new
    /// value for a key.
    fn disk_archive(&self, key: &Key, info: Info) -> Result<(), Error> {
        if let Some(v) = self.disk_version(key)? {
            if v > 0 {
                let version_key = self.key_for_version(key);
                let mut f = File::create(self.full_path(version_key.path()))?;
                write!(f, "{}", v * -1)?;

                let arch_key = self.key_for_archive_info(&key, v);
                let mut f = File::create(self.full_path(arch_key.path()))?;
                let i = serde_json::to_string(&info)?;
                f.write(i.as_ref())?;

                return Ok(())
            }
        }
        Err(Error::from_str("No version to archive"))
    }

}


/// # Implements Keystore methods
impl KeyStore for CachingDiskKeyStore {

    type KeyIter = DiskKeyIterator;

    fn keys(&self) -> Self::KeyIter {
        DiskKeyIterator::new(&self.base_dir)
    }

    fn store<V: Any + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error> {
        let next = self.next_version(&key)?;
        self.disk_store(&key, &value, &info, next)?;
        self.cache_store(key, value, next)
    }

    fn archive(&mut self, key: &Key, info: Info) -> Result<(), Error> {
        {
            let mut w = self.cache.write().unwrap();
            w.remove_entry(key); // Don't care if it was actually cached.
        }
        self.disk_archive(key, info)
    }

    fn get<V: Any + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        match self.cache_get(key)? {
            Some(v) => Ok(Some(v)), // return from cache if possible
            None => {
                match self.disk_get(key)? { // try to get from disk
                    None => Ok(None),
                    Some(v) => {
                        // cache for future reference
                        let version = self.version(key).unwrap().unwrap();
                        let arc: Arc<V> = Arc::new(v);
                        let mut w = self.cache.write().unwrap();
                        let entry = CurrentMemoryEntry {
                            version,
                            value: arc.clone()
                        };
                        w.insert(key.clone(), entry);

                        // and return
                        Ok(Some(arc))
                    }
                }
            }
        }
    }

    fn version(&self, key: &Key) -> Result<Option<i32>, Error> {
        match self.cache_version(key)? {
            Some(v) => Ok(Some(v)),
            None => {
                self.disk_version(key)
            }
        }
    }
}


//------------ DiskKeyIterator -----------------------------------------------

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


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::Utc;
    use crate::util::test;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestStruct {
        s: String
    }

    impl TestStruct {
        fn from_str(s: &str) -> Self {
            TestStruct { s: s.to_string() }
        }
    }

    #[test]
    fn should_store_and_retrieve_from_caching_disk() {
        test::test_with_tmp_dir(|d| {
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_str("key_name");
            let value = TestStruct::from_str("foo");
            let info = Info::new(Utc::now(), "me", "A!");

            store.store(key.clone(), value.clone(), info).unwrap();

            let found: Option<Arc<TestStruct>> =
                store.get(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)
        });
    }

    #[test]
    fn should_report_keys_from_caching_disk_store() {
        test::test_with_tmp_dir(|d| {
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_str("key_name");
            let value = TestStruct::from_str("foo");
            let info = Info::new(Utc::now(), "me", "A!");
            store.store(key.clone(), value.clone(), info).unwrap();

            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());
        });
    }

    #[test]
    fn should_read_from_disk() {
        test::test_with_tmp_dir(|d| {
            // Store stuff in memory and on disk
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d.clone()))
                .unwrap();
            let key = Key::from_str("key_name");
            let value = TestStruct::from_str("foo");
            let info = Info::new(Utc::now(), "me", "A!");
            store.store(key.clone(), value.clone(), info).unwrap();

            // Initiate a new keystore pointing to the same dir, so it can
            // read values from there.
            let store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();

            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());

            let found: Option<Arc<TestStruct>> =
                store.get(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)
        });
    }

    #[test]
    fn should_archive() {
        test::test_with_tmp_dir(|d| {
            // Store stuff in memory and on disk
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d.clone()))
                .unwrap();
            let key = Key::from_str("key_name");
            let value = TestStruct::from_str("foo");
            let actor = "me";
            let msg = "created";
            let info = Info::new(Utc::now(), actor, msg);
            store.store(key.clone(), value.clone(), info).unwrap();

            let msg = "removed";
            let info = Info::new(Utc::now(), actor, msg);
            store.archive(&key, info).unwrap();

            // The key should still exist
            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());

            // But nothing is returned for it
            let found: Option<Arc<TestStruct>> = store.get(&key).unwrap();
            assert_eq!(None, found);

            // Storing a new value should increment version and give stuff
            // back again.
            let value = TestStruct::from_str("bar");
            let msg = "re-created!";
            let info = Info::new(Utc::now(), actor, msg);

            store.store(key.clone(), value.clone(), info).unwrap();

            assert_eq!(2, store.version(&key).unwrap().unwrap());
            let found: Option<Arc<TestStruct>> = store.get(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)
        });
    }
}