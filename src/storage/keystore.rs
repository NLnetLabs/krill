//! The KeyStore trait and some implementations.

use std::any::Any;
use std::io;
use std::num;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;

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

    /// Creates an instance from a static str. Will unwrap, and panic, if
    /// unsafe characters are used. Use 'from_path' for a method that returns
    /// a Result instead, and see there for restrictions.
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

    pub fn path(&self) -> &PathBuf {
        &self.path
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
