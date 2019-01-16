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

//------------ Key -----------------------------------------------------------

/// A Key for KeyStores.
///
/// These keys are based 'paths' whose values can safely be used to map
/// keys to file a on disk for storage.
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
    /// See [`verify_path`] for further restrictions.
    ///
    /// [`verify_path`]: struct.Key.html#method.verify_path
    pub fn from_path(path: PathBuf) -> Result<Key, InvalidKey> {
        Self::verify_path(&path)?;
        Ok(Self { path })
    }

    /// Creates an instance from a static str. Will unwrap, and panic, if
    /// unsafe characters are used. Use [`from_path`] for a method that
    /// returns a Result instead, and see [`verify_path`] for restrictions.
    ///
    /// [`from_path`]: struct.Key.html#method.from_path
    /// [`verify_path`]: struct.Key.html#method.verify_path
    pub fn from_str(s: &str) -> Key {
        let path = PathBuf::from(s);
        Self::from_path(path).unwrap()
    }

    /// Other than this the may contain any character allowed in a
    /// 'segment' in the 'hier-part' defined in RFC3896 only, i.e:
    ///
    /// ```text
    /// segment       = *pchar
    ///
    /// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
    ///
    /// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    /// pct-encoded   = "%" HEXDIG HEXDIG
    /// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" /
    ///                 "*" / "+" / "," / ";" / "="
    /// ```
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


//------------ Info ----------------------------------------------------------

/// This type defines the meta-information for changes to a value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Info {
    #[serde(with = "ts_seconds")]
    date_time: DateTime<Utc>,
    actor: String,
    message: String
}


impl Info {
    /// Creates a new Info value for a given date_time, actor and message.
    pub fn new(
        date_time: DateTime<Utc>,
        actor: &str,
        message: &str
    ) -> Self {
        Info {
            date_time,
            actor: actor.to_string(),
            message: message.to_string()
        }
    }

    /// Creates a new Info value for an actor and message, using now for the
    /// date_time.
    pub fn now(
        actor: &str,
        message: &str
    ) -> Self {
        Self::new(Utc::now(), actor, message)
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


//------------ InvalidKey ----------------------------------------------------

/// This type is used to signify any error in key formats.
#[derive(Debug)]
pub struct InvalidKey;


//------------ KeyStore ------------------------------------------------------

/// A KeyStore stores and archives Values of any type associated with a unique
/// Key and meta-information in the form of Info.
///
/// Internally it will use keys derived off the base key supplied by the
/// user of this Trait, to achieve the following:
///
/// ```text
/// keyname /
///     v1, v2, ..  (values)
///     i1, i2, ..  (info)
///     a2, ..      (archive info, only for versions that were archived)
///     version     (the current version, negative if archived)
/// ```
pub trait KeyStore {

    type KeyIter: Iterator<Item=Key>;

    /// Returns all keys, present and archived.
    fn keys(&self) -> Self::KeyIter;

    /// Stores a key value pair.
    fn store<V: Any + Serialize + Send + Sync>(
        &mut self,
        key: Key,
        value: V,
        info: Info
    ) -> Result<(), Error>;

    /// Archives the value. The key will be preserved, and if a new value is
    /// stored for this key the version number will continue from the point
    /// where this value was archived. However, asking for the current version
    /// or value for this key will return Ok(None).
    ///
    /// The info for this change will be stored using the negative of the
    /// current version.
    fn archive(&mut self, key: &Key, info: Info) -> Result<(), Error>;

    /// Retrieves an optional Arc containing the current value, given the key.
    /// If the value was archived, Ok(None) will be returned.
    fn get<V: Any + DeserializeOwned + Send + Sync>(
        &self,
        key: &Key
    ) -> Result<Option<Arc<V>>, Error>;

    /// Returns the current version for this key, if present. Version
    /// counting starts at 1. If a key was archived a negative will be
    /// returned.
    fn version(&self, key: &Key) -> Result<Option<i32>, Error>;

    // XXX TODO:
    // versioned_value()
    // versioned_info()

    /// Helper method for resolving relative keys. See [`key_for_value`],
    /// [`key_for_info`] and [`key_for_version`] for methods that you are
    /// more likely to need.
    ///
    /// [`key_for_value`]: trait.KeyStore.html#method.key_for_value
    /// [`key_for_info`]: trait.KeyStore.html#method.key_for_info
    /// [`key_for_version`]: trait.KeyStore.html#method.key_for_version
    fn key_for_name(&self, key: &Key, name: String) -> Key {
        let mut path = key.path.clone();
        path.push(name);
        Key { path }
    }

    /// Returns the relative key for a versioned value element for a key.
    fn key_for_value(&self, key: &Key, version: i32) -> Key {
        self.key_for_name(key, format!("v{}", version))
    }

    /// Returns the relative key for a versioned info element for a key.
    fn key_for_info(&self, key: &Key, version: i32) -> Key {
        self.key_for_name(key, format!("i{}", version))
    }

    /// Returns the relative key for a versioned info element for a key.
    fn key_for_archive_info(&self, key: &Key, version: i32) -> Key {
        self.key_for_name(key, format!("a{}", version))
    }

    /// Returns the relative key for the version element for a key.
    fn key_for_version(&self, key: &Key) -> Key {
        self.key_for_name(key, "version".to_string())
    }

    /// Returns the next version for key, taking archived versions into
    /// consideration. Counting starts at 1.
    fn next_version(&self, key: &Key) -> Result<i32, Error> {
        match self.version(key)? {
            None => Ok(1),
            Some(current) => {
                if current < 0 {
                    Ok(current * -1 + 1)
                } else {
                    Ok(current + 1)
                }
            }
        }
    }
}

//------------ Error ---------------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt ="Json serialization error: {}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt ="Something went wrong: {}", _0)]
    IoError(io::Error),

    #[display(fmt ="Bad syntax in version: {}", _0)]
    IntError(num::ParseIntError),

    #[display(fmt ="Something went wrong: {}", _0)]
    Other(String)
}

impl Error {
    pub fn from_str(s: &str) -> Self {
        Error::Other(s.to_string())
    }
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
