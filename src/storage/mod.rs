//! The KeyStore trait and some implementations.

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;

/// A Key for KeyStores.
///
/// These keys are based 'paths' which are Strings whose values can safely
/// be used to map keys to file a on disk for storage.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Key {
    path: String
}

impl Key {
    /// Creates a new key based on the path. Only the following characters are
    /// allowed: alphanumeric and '/'. Paths MAY NOT start with a '/' - they
    /// are supposed to be relative. The '.' character is disallowed to
    /// prevent that relative paths go outside of their predesignated scope.
    pub fn new(path: String) -> Result<Key, InvalidKey> {
        if Path::new(&path).is_relative() {
            Ok(Key{path})
        } else {
            Err(InvalidKey)
        }
    }
}

#[derive(Debug)]
pub struct InvalidKey;

pub trait KeyStore {
    /// Stores a key value pair.
    fn store<V: Serialize + Any>(
        &mut self,
        key: Key,
        value: V
    ) -> Result<(), Error>;

    /// Retrieves an optional reference to a value, given the key.
    fn retrieve<V: Any + Clone + DeserializeOwned>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error>;
}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="Json serialization error: {}", _0)]
    JsonError(serde_json::Error),

    #[fail(display ="Something went wrong: {}", _0)]
    IoError(io::Error),

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


#[derive(Debug)]
pub struct MemoryKeyStore {
    store: HashMap<Key, Box<Any>>
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        MemoryKeyStore { store: HashMap::new() }
    }
}

impl KeyStore for MemoryKeyStore {
    fn store<V: Serialize + Any>(&mut self, key: Key, value: V) -> Result<(), Error> {
        let v = Box::new(value);
        self.store.entry(key).or_insert(v);
        Ok(())
    }

    fn retrieve<V: Any + Clone + DeserializeOwned>(&self, key: &Key) -> Result<Option<Arc<V>>, Error> {
        match self.store.get(key) {
            None => Ok(None),
            Some(ref v) => {
                match v.downcast_ref::<V>() {
                    Some(res) => Ok(Some(Arc::new(res.clone()))),
                    None => Err(Error::Other("Object has the wrong type!".to_string()))
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct DiskKeyStore {
    base_dir: String
}

impl DiskKeyStore {
    pub fn new(base_dir: String) -> Result<Self, Error> {
        let meta_data = fs::metadata(&base_dir)?;
        if meta_data.is_dir() {
            Ok(DiskKeyStore{base_dir})
        } else {
            panic!("Invalid base_dir for DiskKeyStore")
        }
    }
}

impl KeyStore for DiskKeyStore {

    fn store<V: Serialize + Any>(
        &mut self,
        key: Key,
        value: V
    ) -> Result<(), Error> {
        let v = serde_json::to_string(&value)?;
        let path_string = format!("{}{}", self.base_dir, key.path);
        let full_path = Path::new(&path_string);

        if !full_path.exists() {
            if let Some(base_path) = full_path.parent() {
                fs::create_dir_all(base_path)?;
            }
        }

        let mut f = File::create(full_path)?;
        f.write(v.as_ref())?;

        Ok(())
    }

    fn retrieve<V: Any + Clone + DeserializeOwned>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error> {
        let path_string = format!("{}{}", self.base_dir, key.path);
        let path = Path::new(&path_string);
        if ! path.exists() {
            Ok(None)
        } else {
            let f = File::open(path)?;
            let v: V = serde_json::from_reader(f)?;
            Ok(Some(Arc::new(v)))
        }
    }
}




//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestStruct {
        v1: String,
        v2: u128
    }

    #[test]
    fn should_store_and_retrieve_in_memory() {
        let mut store = MemoryKeyStore::new();
        let key = Key::new("some/path/file.txt".to_string()).unwrap();
        let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
        store.store(key.clone(), value.clone()).unwrap();

        let found: Option<Arc<TestStruct>> = store.retrieve(&key).unwrap();

        assert_eq!(Some(Arc::new(value)), found)
    }

    #[test]
    fn should_store_and_retrieve_from_disk() {
        let mut store = DiskKeyStore::new("work/".to_string()).unwrap();
        let key = Key::new("some/path/file.txt".to_string()).unwrap();
        let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
        store.store(key.clone(), value.clone()).unwrap();

        let found: Option<Arc<TestStruct>> = store.retrieve(&key).unwrap();

        assert_eq!(Some(Arc::new(value)), found)
    }


}