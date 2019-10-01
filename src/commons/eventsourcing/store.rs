use std::any::Any;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;

use crate::commons::api::Handle;
use crate::commons::util::file;

use super::{Aggregate, Event};
use commons::eventsourcing::agg::AggregateHistory;

//------------ Storable ------------------------------------------------------

pub trait Storable: Clone + Serialize + DeserializeOwned + Sized + 'static {}
impl<T: Clone + Serialize + DeserializeOwned + Sized + 'static> Storable for T {}

//------------ KeyStore ------------------------------------------------------

/// Generic KeyStore for AggregateManager
pub trait KeyStore {
    type Key;

    fn key_for_snapshot() -> Self::Key;
    fn key_for_event(version: u64) -> Self::Key;

    /// Returns whether a key already exists.

    fn has_key(&self, id: &Handle, key: &Self::Key) -> bool;

    fn has_aggregate(&self, id: &Handle) -> bool;

    fn aggregates(&self) -> Vec<Handle>; // Use Iterator?

    /// Throws an error if the key already exists.

    fn store<V: Any + Serialize>(
        &self,
        id: &Handle,
        key: &Self::Key,
        value: &V,
    ) -> Result<(), KeyStoreError>;

    /// Get the value for this key, if any exists.

    fn get<V: Any + Storable>(
        &self,
        id: &Handle,
        key: &Self::Key,
    ) -> Result<Option<V>, KeyStoreError>;

    /// Get the value for this key, if any exists.

    fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, KeyStoreError>;

    fn store_event<V: Event>(&self, event: &V) -> Result<(), KeyStoreError>;

    /// Get the latest aggregate

    fn get_aggregate<V: Aggregate>(&self, id: &Handle) -> Result<Option<V>, KeyStoreError>;

    /// Saves the latest snapshot - overwrites any previous snapshot.

    fn store_aggregate<V: Aggregate>(
        &self,
        id: &Handle,
        aggregate: &V,
    ) -> Result<(), KeyStoreError>;
}

//------------ KeyStoreError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum KeyStoreError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Key '{}' already exists", _0)]
    KeyExists(String),

    #[display(fmt = "Aggregate init event exists, but cannot be applied")]
    InitError,

    #[display(fmt = "No history for aggregate with key '{}'", _0)]
    NoHistory(Handle),
}

impl From<io::Error> for KeyStoreError {
    fn from(e: io::Error) -> Self {
        KeyStoreError::IoError(e)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(e: serde_json::Error) -> Self {
        KeyStoreError::JsonError(e)
    }
}

impl std::error::Error for KeyStoreError {}

//------------ DiskKeyStore --------------------------------------------------

/// This type can store and retrieve values to/from disk, using json
/// serialization.
pub struct DiskKeyStore {
    dir: PathBuf,
}

impl KeyStore for DiskKeyStore {
    type Key = PathBuf;

    fn key_for_snapshot() -> Self::Key {
        PathBuf::from("snapshot.json")
    }

    fn key_for_event(version: u64) -> Self::Key {
        PathBuf::from(format!("delta-{}.json", version))
    }

    fn has_key(&self, id: &Handle, key: &Self::Key) -> bool {
        self.file_path(id, key).exists()
    }

    fn has_aggregate(&self, id: &Handle) -> bool {
        self.dir_for_aggregate(id).exists()
    }

    fn aggregates(&self) -> Vec<Handle> {
        let mut res: Vec<Handle> = Vec::new();

        if let Ok(dir) = fs::read_dir(&self.dir) {
            for d in dir {
                let path = d.unwrap().path();
                let id = Handle::from_path_unsafe(&path);
                res.push(id);
            }
        }

        res
    }

    fn store<V: Any + Serialize>(
        &self,
        id: &Handle,
        key: &Self::Key,
        value: &V,
    ) -> Result<(), KeyStoreError> {
        let mut f = file::create_file_with_path(&self.file_path(id, key))?;
        let json = serde_json::to_string_pretty(value)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn get<V: Any + Storable>(
        &self,
        id: &Handle,
        key: &Self::Key,
    ) -> Result<Option<V>, KeyStoreError> {
        let path = self.file_path(id, key);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            match serde_json::from_reader(f) {
                Err(e) => {
                    error!("Could not deserialize json at: {}, error: {}", path_str, e);
                    Err(KeyStoreError::JsonError(e))
                }
                Ok(v) => {
                    trace!("Deserialized json at: {}", path_str);
                    Ok(Some(v))
                }
            }
        } else {
            trace!("Could not find file at: {}", path_str);
            Ok(None)
        }
    }

    /// Get the value for this key, if any exists.
    fn get_event<V: Event>(&self, id: &Handle, version: u64) -> Result<Option<V>, KeyStoreError> {
        let path = self.path_for_event(id, version);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            match serde_json::from_reader(f) {
                Err(e) => {
                    error!("Could not deserialize json at: {}, error: {}", path_str, e);
                    Err(KeyStoreError::JsonError(e))
                }
                Ok(v) => {
                    trace!("Deserialized event at: {}", path_str);
                    Ok(Some(v))
                }
            }
        } else {
            trace!("No more events at: {}", path_str);
            Ok(None)
        }
    }

    fn store_event<V: Event>(&self, event: &V) -> Result<(), KeyStoreError> {
        let id = event.handle();
        let key = Self::key_for_event(event.version());
        if self.has_key(id, &key) {
            Err(KeyStoreError::KeyExists(key.to_string_lossy().to_string()))
        } else {
            self.store(id, &key, event)
        }
    }

    fn get_aggregate<V: Aggregate>(&self, id: &Handle) -> Result<Option<V>, KeyStoreError> {
        // try to get a snapshot.
        // If that fails, try to get the init event.
        // Then replay all newer events that can be found.
        let key = Self::key_for_snapshot();
        let aggregate_opt = match self.get::<V>(id, &key)? {
            Some(aggregate) => Some(aggregate),
            None => match self.get_event::<V::InitEvent>(id, 0)? {
                Some(e) => Some(V::init(e).map_err(|_| KeyStoreError::InitError)?),
                None => None,
            },
        };

        match aggregate_opt {
            None => Ok(None),
            Some(mut aggregate) => {
                self.update_aggregate(id, &mut aggregate)?;
                Ok(Some(aggregate))
            }
        }
    }

    fn store_aggregate<V: Aggregate>(
        &self,
        id: &Handle,
        aggregate: &V,
    ) -> Result<(), KeyStoreError> {
        let key = Self::key_for_snapshot();
        self.store(id, &key, aggregate)
    }
}

impl DiskKeyStore {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Self {
        let mut dir = work_dir.clone();
        dir.push(name_space);
        DiskKeyStore { dir }
    }

    /// Creates a directory for the name_space under the work_dir.
    pub fn under_work_dir(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let mut path = work_dir.clone();
        path.push(name_space);
        if !path.is_dir() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self::new(work_dir, name_space))
    }

    fn file_path(&self, id: &Handle, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(key);
        file_path
    }

    fn dir_for_aggregate(&self, id: &Handle) -> PathBuf {
        let mut dir_path = self.dir.clone();
        dir_path.push(id.to_path_buf());
        dir_path
    }

    fn path_for_event(&self, id: &Handle, version: u64) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(format!("delta-{}.json", version));
        file_path
    }

    pub fn update_aggregate<A: Aggregate>(
        &self,
        id: &Handle,
        aggregate: &mut A,
    ) -> Result<(), KeyStoreError> {
        while let Some(e) = self.get_event(id, aggregate.version())? {
            aggregate.apply(e);
        }
        Ok(())
    }

    pub fn history<A: Aggregate>(&self, id: &Handle) -> Result<AggregateHistory<A>, KeyStoreError> {
        let init = self
            .get_event::<A::InitEvent>(id, 0)?
            .ok_or_else(|| KeyStoreError::NoHistory(id.clone()))?;

        let mut events: Vec<A::Event> = vec![];
        let mut version = 1;
        while let Some(e) = self.get_event(id, version)? {
            events.push(e);
            version += 1;
        }

        Ok(AggregateHistory::new(init, events))
    }
}
