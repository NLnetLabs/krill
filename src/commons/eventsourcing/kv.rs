use std::any::Any;
use std::path::PathBuf;
use std::{fmt, io};

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

use crate::commons::util::file;

/// Using an enum here, because we expect to have more implementations in future.
/// Not using generics because it's harder on the compiler.
pub enum KeyValueImpl {
    Disk(KeyValueDiskImpl),
}

impl KeyValueImpl {
    pub fn disk(workdir: &PathBuf, name_space: &str) -> Result<Self, KeyValueError> {
        let mut base = workdir.clone();
        base.push(name_space);

        if !base.exists() {
            file::create_dir(&base)?;
        }

        Ok(KeyValueImpl::Disk(KeyValueDiskImpl { base }))
    }

    pub fn store<V: Any + Serialize>(&self, key: &str, value: &V) -> Result<(), KeyValueError> {
        match self {
            KeyValueImpl::Disk(disk_store) => disk_store.store(key, value),
        }
    }

    pub fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>, KeyValueError> {
        match self {
            KeyValueImpl::Disk(disk_store) => disk_store.get(key),
        }
    }
}

impl KeyValueImpl {}

/// This type can store and retrieve values to/from disk, using json
/// serialization
pub struct KeyValueDiskImpl {
    base: PathBuf,
}

impl KeyValueDiskImpl {
    fn file_path(&self, key: &str) -> PathBuf {
        let mut path = self.base.clone();
        path.push(key);
        path
    }

    fn store<V: Any + Serialize>(&self, key: &str, value: &V) -> Result<(), KeyValueError> {
        let mut f = file::create_file_with_path(&self.file_path(key))?;
        let json = serde_json::to_string_pretty(value)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>, KeyValueError> {
        let path = self.file_path(key);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            let v = serde_json::from_reader(f)?;
            Ok(Some(v))
        } else {
            trace!("Could not find file at: {}", path_str);
            Ok(None)
        }
    }
}

//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    IoError(io::Error),
    JsonError(serde_json::Error),
}

impl From<io::Error> for KeyValueError {
    fn from(e: io::Error) -> Self {
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
            KeyValueError::IoError(e) => write!(f, "I/O error: {}", e),
            KeyValueError::JsonError(e) => write!(f, "JSON error: {}", e),
        }
    }
}
