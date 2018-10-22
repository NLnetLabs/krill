use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::ReadDir;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::str::FromStr;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use super::keystore::{Error, Info, Key, KeyStore};


/// This type is used to store current values in memory for caching.
#[derive(Debug)]
struct CurrentMemoryEntry {
    version: i32,
    value: Arc<Any + Send + Sync>
}

impl CurrentMemoryEntry {
    pub fn value_copy(&self) -> Arc<Any + Send + Sync> {
        self.value.clone()
    }
}


/// This keystore uses an in memory keystore for caching, and falls back
/// to a disk based key store.
#[derive(Debug)]
pub struct CachingDiskKeyStore {
    cache: RwLock<HashMap<Key, CurrentMemoryEntry>>,
    base_dir: PathBuf
}

/// # Creating
impl CachingDiskKeyStore {
    pub fn new(base_dir: PathBuf) -> Result<Self, Error> {
        if ! base_dir.is_dir() {
            Err(Error::Other("Invalid base_dir for DiskKeyStore".to_string()))
        } else {
            let cache = HashMap::new();
            Ok(CachingDiskKeyStore{cache: RwLock::new(cache), base_dir})
        }
    }
}

/// # Cache support functions
impl CachingDiskKeyStore {
    fn cache_store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
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

    fn cache_get_current<V: Any + Clone + DeserializeOwned + Send + Sync>(
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

    fn cache_get_version(&self, key: &Key) -> Result<Option<i32>, Error> {
        let r = self.cache.read().map_err(
            |_| Error::from_str("Can't get read lock"))?;
        Ok(r.get(key).map(|c| { c.version }))
    }
}


/// # Store on / retrieve from disk
impl CachingDiskKeyStore {
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

    fn full_path(&self, path: &PathBuf) -> PathBuf {
        let mut res = self.base_dir.clone();
        res.push(path);
        res
    }

    fn disk_store<V: Any + Clone + Serialize + Send + Sync>(
        &mut self,
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

    fn disk_get_current<V: Any + Clone + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        match self.version(key)? {
            None => Ok(None),
            Some(v) => {
                if v > 0 {
                    let value_key = self.key_for_value(&key, v);
                    let f = File::open(self.full_path(value_key.path()))?;
                    let v: V = serde_json::from_reader(f)?;
                    Ok(Some(Arc::new(v)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn disk_get_version(&self, key: &Key) -> Result<Option<i32>, Error> {
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

    fn disk_archive_version(&mut self, key: &Key) -> Result<(), Error> {
        if let Some(v) = self.disk_get_version(key)? {
            if v > 0 {
                let version_key = self.key_for_version(key);
                let mut f = File::create(self.full_path(version_key.path()))?;
                write!(f, "{}", v * -1)?;
                return Ok(())
            }
        }
        Err(Error::from_str("No version to archive"))
    }

}


impl KeyStore for CachingDiskKeyStore {

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
        let next = self.next_version(&key)?;
        self.disk_store(&key, &value, &info, next)?;
        self.cache_store(key, value, next)
    }

    fn archive(&mut self, key: &Key) -> Result<(), Error> {
        {
            let mut w = self.cache.write()
                .map_err(|_| Error::from_str("Can't get write lock"))?;
            w.remove_entry(key); // Don't care if it was actually cached.
        }
        self.disk_archive_version(key)
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
        match self.cache_get_current(key)? {
            Some(v) => Ok(Some(v)),
            None => {
                self.disk_get_current(key)
            }
        }
    }

    /// Retrieves the current version from memory if possible, from disk
    /// otherwise.
    fn version(&self, key: &Key) -> Result<Option<i32>, Error> {
        match self.cache_get_version(key)? {
            Some(v) => Ok(Some(v)),
            None => {
                self.disk_get_version(key)
            }

        }
    }
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


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::Utc;
    use test;

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
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());

            store.store(key.clone(), value.clone(), info).unwrap();

            let found: Option<Arc<TestStruct>> =
                store.current_value(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)
        });
    }

    #[test]
    fn should_report_keys_from_caching_disk_store() {
        test::test_with_tmp_dir(|d| {
            let mut store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();
            let key = Key::from_str("key_name");
            let value = TestStruct::from_str("foo");
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
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
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
            store.store(key.clone(), value.clone(), info).unwrap();

            // Initiate a new keystore pointing to the same dir, so it can
            // read values from there.
            let store = CachingDiskKeyStore::new(PathBuf::from(d)).unwrap();

            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());
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
            let info = Info::new(Utc::now(), "me".to_string(), "A!".to_string());
            store.store(key.clone(), value.clone(), info).unwrap();

            store.archive(&key).unwrap();

            // The key should still exist
            let stored_keys: Vec<Key> = store.keys().collect();
            assert!(stored_keys.contains(&key));
            assert_eq!(1, stored_keys.len());

            // But nothing is returned for it
            let found: Option<Arc<TestStruct>> =
                store.current_value(&key).unwrap();
            assert_eq!(None, found);

            // Storing a new value should increment version and give stuff
            // back again.
            let value = TestStruct::from_str("bar");
            let info = Info::new(Utc::now(), "me".to_string(), "B".to_string());

            store.store(key.clone(), value.clone(), info).unwrap();

            assert_eq!(2, store.version(&key).unwrap().unwrap());
            let found: Option<Arc<TestStruct>> =
                store.current_value(&key).unwrap();

            assert_eq!(Some(Arc::new(value)), found)

        });
    }


}