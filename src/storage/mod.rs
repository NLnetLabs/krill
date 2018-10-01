//! The KeyStore trait and some implementations.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
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
        if path.bytes().all(
            |b| b.is_ascii_alphanumeric() || b == b'/' || b == b'.'
        ) {
            Ok(Key{path})
        } else {
            Err(InvalidKey)
        }
    }
}

#[derive(Debug)]
pub struct InvalidKey;

pub trait KeyStore {
    fn store<V: Serialize>(&mut self, key: Key, value: V) -> Result<(), Error>;
    fn retrieve<'a, V: Deserialize<'a>>(&'a self, key: &Key) -> Result<Option<V>, Error>;
}

#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display ="Json serialization error: {}", _0)]
    JsonError(serde_json::Error)
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}



pub struct MemoryKeyStore {
    store: HashMap<Key, String>
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        MemoryKeyStore { store: HashMap::new() }
    }
}

impl KeyStore for MemoryKeyStore {
    fn store<V: Serialize>(&mut self, key: Key, value: V) -> Result<(), Error> {
        let v = serde_json::to_string(&value)?;
        self.store.entry(key).or_insert(v);
        Ok(())
    }

    fn retrieve<'a, V: Deserialize<'a>>(&'a self, key: &Key) -> Result<Option<V>, Error> {
        match self.store.get(key) {
            None => Ok(None),
            Some(v) => {
                let res: V = serde_json::from_str(v.as_ref())?;
                Ok(Some(res))
            }
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
    fn should_store_and_retrieve() {
        let mut store = MemoryKeyStore::new();
        let key = Key::new("some/path/file.txt".to_string()).unwrap();
        let value = TestStruct { v1: "blabla".to_string(), v2: 42 };
        store.store(key.clone(), value.clone()).unwrap();

        let found: Option<TestStruct> = store.retrieve(&key).unwrap();

        assert_eq!(Some(value), found)
    }
}