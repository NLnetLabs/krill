//! In-memory storage.

use std::{error, fmt, mem, thread};
use std::collections::{HashMap, HashSet};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use url::Url;
use crate::commons::storage::{
    Key, Namespace, NamespaceBuf, SegmentBuf, Scope
};
use super::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ Store ---------------------------------------------------------

#[derive(Debug)]
pub struct Store {
    namespace: Arc<MemoryNamespace>,
}

impl Store {
    pub fn wipe_all() {
        MEMORY.wipe_all()
    }

    pub fn from_uri(
        uri: &Url, namespace: &Namespace
    ) -> Result<Option<Self>, Error> {
        if uri.scheme() != "memory" {
            return Ok(None)
        }
    
        Ok(Some(Store {
            namespace: MEMORY.get_namespace(
                uri.host_str().unwrap_or_default().into(),
                namespace.into()
            )
        }))
    }

    pub fn execute<F, T>(&self, scope: &Scope, op: F) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let wait = Duration::from_millis(10);
        let tries = 1000;

        for i in 0..tries {
            if self.namespace.locks().insert(scope.clone()) {
                // The scope was not yet present. We’ve won and can go on.
                break
            }
            else if i >= tries {
                return Err(Error::ScopeLocked(scope.clone()).into())
            }
            thread::sleep(wait);
        }

        let res = op(&mut SuperTransaction::from(self));

        self.namespace.locks().remove(scope);

        res
    }
}


/// # Reading
impl Store {
    /// Returns whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.namespace.values().is_empty())
    }

    /// Returns whether the store contains the given key.
    pub fn has(&self, key: &Key) -> Result<bool, Error> {
        Ok(
            self.namespace.values().get(key.scope()).map(|scope| {
                scope.contains_key(key.name())
            }).unwrap_or(false)
        )
    }

    /// Returns whether the store contains the given scope.
    pub fn has_scope(&self, scope: &Scope) -> Result<bool, Error> {
        Ok(self.namespace.values().contains_key(scope))
    }

    /// Returns the contents of the stored value with the given key.
    ///
    /// If the value does not exist, returns `Ok(None)?.
    pub fn get<T: DeserializeOwned>(
        &self, key: &Key
    ) -> Result<Option<T>, Error> {
        match self.namespace.values().get(key.scope()).and_then(|scope| {
            scope.get(key.name())
        }) {
            Some(value) => {
                serde_json::from_value(value.clone()).map_err(|err| {
                    Error::deserialize(key.clone(), err)
                })
            }
            None => Ok(None)
        }
    }

    pub fn get_any(&self, key: &Key) -> Result<Option<Value>, Error> {
        self.get(key)
    }

    /// Returns all the keys in the given scope.
    ///
    /// This includes all keys directly under the given scope as well as
    /// all keys in sub-scopes.
    pub fn list_keys(&self, scope: &Scope) -> Result<Vec<Key>, Error> {
        let values = self.namespace.values();
        let mut res = Vec::new();
        for (stored_scope, stored_names) in values.iter() {
            if !stored_scope.starts_with(scope) {
                continue
            }
            for name in stored_names.keys() {
                res.push(Key::new_scoped(stored_scope.clone(), name.clone()))
            }
        }
        Ok(res)
    }

    /// Returns all the scopes in the score.
    ///
    pub fn list_scopes(&self) -> Result<Vec<Scope>, Error> {
        Ok(
            self.namespace.values().keys().filter(|scope| {
                !scope.is_global()
            }).cloned().collect()
        )
    }
}


/// # Writing
impl Store {
    /// Stores the provided value under the gvien key.
    ///
    /// Quielty overwrites a possibly already existing value.
    pub fn store<T: Serialize>(
        &self, key: &Key, value: &T
    ) -> Result<(), Error> {
        self.namespace.values().entry(
            key.scope().clone()
        ).or_default().insert(
            key.name().into(),
            serde_json::to_value(value).map_err(|err| {
                Error::serialize(key.clone(), err)
            })?,
        );
        Ok(())
    }

    pub fn store_any(&self, key: &Key, value: &Value) -> Result<(), Error> {
        self.store(key, value)
    }

    /// Moves a value from one key to another.
    pub fn move_value(&self, from: &Key, to: &Key) -> Result<(), Error> {
        let mut values = self.namespace.values();
        
        let value = values.get_mut(from.scope()).and_then(|scope| {
            scope.remove(from.name())
        }).ok_or_else(|| Error::NotFound(from.clone()))?;

        values.entry(to.scope().clone()).or_default().insert(
            to.name().into(), value
        );
        Ok(())
    }

    /// Moves an entire scope to a new scope.
    pub fn move_scope(
        &self, from: &Scope, to: &Scope
    ) -> Result<(), Error> {
        let mut values = self.namespace.values();
        let scope = match values.remove(from) {
            Some(scope) => scope,
            None => {
                return Err(Error::NoScope(from.clone()));
            }
        };
        values.insert(to.clone(), scope);
        Ok(())
    }

    /// Removes the stored value for a given key.
    pub fn delete(&self, key: &Key) -> Result<(), Error> {
        let mut values = self.namespace.values();
        let scope = match values.get_mut(key.scope()) {
            Some(scope) => scope,
            None => return Err(Error::NotFound(key.clone()))
        };
        if scope.remove(key.name()).is_none() {
            return Err(Error::NotFound(key.clone()))
        }
        if !scope.is_empty() {
            return Ok(())
        }
        values.remove(key.scope());
        Ok(())
    }

    /// Removes an entire scope.
    pub fn delete_scope(&self, scope: &Scope) -> Result<(), Error> {
        self.namespace.values().remove(scope);
        Ok(())
    }

    /// Removes the entire store.
    pub fn clear(&self) -> Result<(), Error> {
        self.namespace.values().clear();
        Ok(())
    }

    pub fn migrate_namespace(
        &mut self, target: &Namespace
    ) -> Result<(), Error> {
        if !self.namespace.locks().is_empty() {
            return Err(Error::PendingLocks);
        }
        let mut namespaces = MEMORY.namespaces.lock().expect("poisoned lock");
        let new_key = (self.namespace.ns_key.0.clone(), target.into());
        let new = namespaces.entry(new_key.clone()).or_insert_with(|| {
            MemoryNamespace::new(new_key).into()
        }).clone();

        // Check that new is empty.
        let mut new_values = new.values();
        if !new_values.is_empty() {
            return Err(Error::NonemptyTargetNamespace(target.into()))
        }

        // Swap out the values.
        mem::swap(new_values.deref_mut(), self.namespace.values().deref_mut());

        // Delete our namespace
        namespaces.remove(&self.namespace.ns_key);

        self.namespace = new.clone();
        Ok(())
    }
}


//------------ Transaction ---------------------------------------------------

pub type Transaction<'a> = &'a Store;


//------------ MemoryValues --------------------------------------------------

type MemoryValues = HashMap<Scope, HashMap<SegmentBuf, Value>>;


//------------ MemoryNamespace -----------------------------------------------

#[derive(Debug)]
struct MemoryNamespace {
    ns_key: NsKey,
    values: Mutex<MemoryValues>,
    locks: Mutex<HashSet<Scope>>,
}

impl MemoryNamespace {
    fn new(ns_key: NsKey) -> Self {
        Self {
            ns_key,
            values: Default::default(),
            locks: Default::default(),
        }
    }

    fn values(&self) -> MutexGuard<MemoryValues> {
        self.values.lock().expect("poisoned lock")
    }

    fn locks(&self) -> MutexGuard<HashSet<Scope>> {
        self.locks.lock().expect("poisoned lock")
    }
}


//------------ NsKey ---------------------------------------------------------

type NsKey = (String, NamespaceBuf);


//------------ Memory --------------------------------------------------------

/// The place where data is actually stored.
#[derive(Debug, Default)]
struct Memory {
    namespaces: Mutex<HashMap<NsKey, Arc<MemoryNamespace>>>,
}

impl Memory {
    fn wipe_all(&self) {
        self.namespaces.lock().expect("poisoned lock").clear();
    }

    fn get_namespace(
        &self,
        prefix: String,
        namespace: NamespaceBuf,
    ) -> Arc<MemoryNamespace> {
        let ns_key = (prefix, namespace);
        let mut namespaces = self.namespaces.lock().expect("poisoned lock");
        namespaces.entry(ns_key.clone()).or_insert_with(|| {
            MemoryNamespace::new(ns_key).into()
        }).clone()
    }
}


//------------ MEMORY --------------------------------------------------------

lazy_static! {
    static ref MEMORY: Memory = Memory::default();
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    ScopeLocked(Scope),
    Deserialize {
        key: Key,
        err: String,
    },
    Serialize {
        key: Key,
        err: String,
    },
    NotFound(Key),
    NoScope(Scope),
    NonemptyTargetNamespace(NamespaceBuf),
    PendingLocks,
}

impl Error {
    fn deserialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Deserialize { key, err: err.to_string() }
    }

    fn serialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Serialize { key, err: err.to_string() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ScopeLocked(scope) => {
                write!(f, "scope {scope} already locked")
            }
            Error::Deserialize { key, err } => {
                write!(f,
                    "failed to deserialize value for key '{key}': {err}"
                )
            }
            Error::Serialize { key, err } => {
                write!(f,
                    "failed to serialize value for key '{key}': {err}"
                )
            }
            Error::NotFound(key) => write!(f, "no such key '{key}'"),
            Error::NoScope(scope) => write!(f, "no such scope '{scope}'"),
            Error::NonemptyTargetNamespace(ns) => {
                write!(f, "non-empty target namespace '{ns}'")
            }
            Error::PendingLocks => {
                f.write_str("pending locks on migration")
            }
        }
    }
}

impl error::Error for Error { }

