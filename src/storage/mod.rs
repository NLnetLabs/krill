//! The KeyStore trait and some implementations.

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::sync::Arc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use std::path::PathBuf;
use std::path::Component;

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
    /// Paths must be relative, must not contain '\' (but '/' will work on
    /// windows here), must not contain '/..' to avoid escaping the base_dir
    /// for the DiskKeyStore implementation. And may contain characters
    /// allowed in the 'hier-part' defined in RFC3896 only, i.e:
    ///
    /// path-rootless = segment-nz *( "/" segment )
    ///
    /// segment       = *pchar
    /// segment-nz    = 1*pchar
    ///
    /// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
    ///
    /// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    /// pct-encoded   = "%" HEXDIG HEXDIG
    /// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" /
    ///                 "*" / "+" / "," / ";" / "="
    pub fn new(path: String) -> Result<Key, InvalidKey> {

        if ! path.bytes().all(|b| {
            b == b'/' || // Allow sub-dirs
            b.is_ascii_alphanumeric() || // ALPHA DIGIT
            b == b'-' || b == b'.' || b == b'_' || b == b'~' ||
            b == b'%' || // Not checking against invalid % encoding (e.g. %%)
            b == b'!' || b == b'$' || b == b'&' || b == b'\'' ||
            b == b'(' || b == b')' || b == b'*' || b == b'+'  ||
            b == b',' || b == b';' || b == b'='
        }) {
            return Err(InvalidKey)
        }

        let path = PathBuf::from(path);
        if path.components().all(|c| { c == Component::Normal("..".as_ref())})
           || ! path.is_relative()
        {
            return Err(InvalidKey);
        }

        Ok(Key{path})
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
    base_dir: PathBuf
}

impl DiskKeyStore {
    pub fn new(base_dir: String) -> Result<Self, Error> {
        let meta_data = fs::metadata(&base_dir)?;
        if meta_data.is_dir() {
            let base_dir = PathBuf::from(base_dir);
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

        let mut full_path = PathBuf::new();
        full_path.push(self.base_dir.as_path());
        full_path.push(key.path.as_path());

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
        let mut full_path = PathBuf::new();
        full_path.push(self.base_dir.as_path());
        full_path.push(key.path.as_path());

        if ! full_path.exists() {
            Ok(None)
        } else {
            let f = File::open(full_path)?;
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