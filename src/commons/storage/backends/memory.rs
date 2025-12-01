//! In-memory storage.

use std::{error, fmt, mem};
use std::collections::HashMap;
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use url::Url;
use crate::commons::storage::Ident;
use super::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ System --------------------------------------------------------

#[derive(Debug, Default)]
pub struct System {
    locations: Mutex<HashMap<Option<u64>, Location>>,
}

impl System {
    pub fn location(&self, uri: &Uri) -> Result<Location, Error> {
        let mut locations = self.locations.lock().expect("poisoned lock");
        Ok(locations.entry(uri.path).or_default().clone())
    }
}


//------------ Location ------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Location {
    namespaces: Arc<Mutex<HashMap<Box<Ident>, Arc<MemoryNamespace>>>>,
}

impl Location {
    pub fn open(
        &self, namespace: &Ident,
    ) -> Result<Store, Error> {
        let mut namespaces = self.namespaces.lock().expect("poisoned lock");
        Ok(Store::new(
            namespaces.entry(namespace.into()).or_default().clone()
        ))
    }

    pub fn is_empty(
        &self, namespace: &Ident,
    ) -> Result<bool, Error> {
        let namespaces = self.namespaces.lock().expect("poisoned lock");
        let Some(namespace) = namespaces.get(namespace) else {
            return Ok(true)
        };
        Ok(namespace.scopes().is_empty())
    }

    pub fn migrate(
        &self, src_ns: &Ident, dst_ns: &Ident
    ) -> Result<(), Error> {
        let mut namespaces = self.namespaces.lock().expect("poisoned lock");
        {
            let Some(src) = namespaces.get(src_ns).cloned() else {
                return Err(Error::MissingSourceNamespace(src_ns.into()))
            };

            src.try_clear_locks()?;

            let dst = namespaces.entry(dst_ns.into()).or_default().clone();
            dst.try_clear_locks()?;

            let mut dst_scopes = dst.scopes();
            if !dst_scopes.is_empty() {
                return Err(Error::NonemptyTargetNamespace(dst_ns.into()))
            }

            mem::swap(dst_scopes.deref_mut(), src.scopes().deref_mut());
        }

        namespaces.remove(src_ns);

        Ok(())
    }
}


//------------ Store ---------------------------------------------------------

#[derive(Debug)]
pub struct Store {
    namespace: Arc<MemoryNamespace>,
}

impl Store {
    fn new(namespace: Arc<MemoryNamespace>) -> Self {
        Store { namespace }
    }

    pub fn execute<F, T>(
        &self, scope: Option<&Ident>, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        match scope {
            Some(scope) => self.execute_scoped(scope.into(), op),
            None => self.execute_global(op),
        }
    }

    fn execute_global<F, T>(
        &self, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let _lock = self.namespace.get_lock(None);
        let _lock = _lock.write().expect("poisoned lock");
        op(&mut SuperTransaction::from(self))
    }

    fn execute_scoped<F, T>(
        &self, scope: Box<Ident>, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let _root_lock = self.namespace.get_lock(None);
        let _root_lock = _root_lock.read().expect("poisoned lock");
        let _lock = self.namespace.get_lock(Some(scope));
        let _lock = _lock.write().expect("poisoned lock");
        op(&mut SuperTransaction::from(self))
    }
}


/// # Reading
impl Store {
    /// Returns whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.namespace.scopes().is_empty())
    }

    /// Returns whether the store contains the given key.
    pub fn has(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<bool, Error> {
        Ok(
            self.namespace.scopes().get(scope).map(|scope| {
                scope.contains_key(key)
            }).unwrap_or(false)
        )
    }

    /// Returns whether the store contains the given scope.
    pub fn has_scope(&self, scope: &Ident) -> Result<bool, Error> {
        Ok(self.namespace.scopes().contains(scope))
    }

    /// Returns the contents of the stored value with the given key.
    ///
    /// If the value does not exist, returns `Ok(None)?.
    pub fn get<T: DeserializeOwned>(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<T>, Error> {
        match self.namespace.scopes().get(scope).and_then(|scope| {
            scope.get(key)
        }) {
            Some(value) => {
                serde_json::from_value(value.clone()).map_err(|err| {
                    Error::deserialize(scope, key, err)
                })
            }
            None => Ok(None)
        }
    }

    pub fn get_any(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<Value>, Error> {
        self.get(scope, key)
    }

    /// Returns all the keys in the given scope.
    ///
    /// This includes all keys directly under the given scope as well as
    /// all keys in sub-scopes.
    pub fn list_keys(
        &self, scope: Option<&Ident>
    ) -> Result<Vec<Box<Ident>>, Error> {
        let scopes = self.namespace.scopes();
        let Some(scope) = scopes.get(scope) else {
            return Ok(Vec::new())
        };
        Ok(scope.keys().cloned().collect())
    }

    /// Returns all the scopes in the score.
    ///
    pub fn list_scopes(&self) -> Result<Vec<Box<Ident>>, Error> {
        Ok(self.namespace.scopes().scopes())
    }
}


/// # Writing
impl Store {
    /// Stores the provided value under the gvien key.
    ///
    /// Quielty overwrites a possibly already existing value.
    pub fn store<T: Serialize>(
        &self, scope: Option<&Ident>, key: &Ident, value: &T
    ) -> Result<(), Error> {
        self.namespace.scopes().get_or_create(scope).insert(
            key.into(),
            serde_json::to_value(value).map_err(|err| {
                Error::serialize(scope, key, err)
            })?,
        );
        Ok(())
    }

    pub fn store_any(
        &self, scope: Option<&Ident>, key: &Ident, value: &Value
    ) -> Result<(), Error> {
        self.store(scope, key, value)
    }

    /// Moves a value from one key to another.
    pub fn move_value(
        &self, from_scope: Option<&Ident>, from_key: &Ident,
        to_scope: Option<&Ident>, to_key: &Ident,
    ) -> Result<(), Error> {
        let mut scopes = self.namespace.scopes();

        let value = scopes.remove_value(from_scope, from_key)?;
        scopes.get_or_create(to_scope).insert(to_key.into(), value);
        Ok(())
    }

    /// Moves an entire scope to a new scope.
    pub fn move_scope(
        &self, from: &Ident, to: &Ident
    ) -> Result<(), Error> {
        let mut values = self.namespace.scopes();
        let scope = match values.remove(from) {
            Some(scope) => scope,
            None => {
                return Err(Error::NoScope(from.into()));
            }
        };
        values.insert(to, scope)?;
        Ok(())
    }

    /// Removes the stored value for a given key.
    pub fn delete(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<(), Error> {
        let _ = self.namespace.scopes().remove_value(scope, key)?;
        Ok(())
    }

    /// Removes an entire scope.
    pub fn delete_scope(&self, scope: &Ident) -> Result<(), Error> {
        self.namespace.scopes().remove(scope);
        Ok(())
    }

    /// Removes the entire store.
    pub fn clear(&self) -> Result<(), Error> {
        self.namespace.scopes().clear();
        Ok(())
    }

        /*
    pub fn migrate_namespace(
        &mut self, target: &Ident
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
        let mut new_values = new.scopes();
        if !new_values.is_empty() {
            return Err(Error::NonemptyTargetNamespace(target.into()))
        }

        // Swap out the values.
        mem::swap(new_values.deref_mut(), self.namespace.scopes().deref_mut());

        // Delete our namespace
        namespaces.remove(&self.namespace.ns_key);

        self.namespace = new.clone();
        Ok(())
    }
        */
}


//------------ Transaction ---------------------------------------------------

pub type Transaction<'a> = &'a Store;

//------------ MemoryValues --------------------------------------------------

type MemoryValues = HashMap<Box<Ident>, Value>;

//------------ MemoryScopes --------------------------------------------------

#[derive(Debug, Default)]
struct MemoryScopes {
    global: MemoryValues,
    scopes: HashMap<Box<Ident>, MemoryValues>,
}

impl MemoryScopes {
    fn is_empty(&self) -> bool {
        self.global.is_empty() && self.scopes.is_empty()
    }

    fn contains(&self, scope: &Ident) -> bool {
        self.scopes.contains_key(scope)
    }

    fn get(&self, scope: Option<&Ident>) -> Option<&MemoryValues> {
        match scope {
            Some(scope) => self.scopes.get(scope),
            None => Some(&self.global)
        }
    }

    fn get_mut(
        &mut self, scope: Option<&Ident>
    ) -> Option<&mut MemoryValues> {
        match scope {
            Some(scope) => self.scopes.get_mut(scope),
            None => Some(&mut self.global)
        }
    }

    fn get_or_create(&mut self, scope: Option<&Ident>) -> &mut MemoryValues {
        match scope {
            Some(scope) => self.scopes.entry(scope.into()).or_default(),
            None => &mut self.global
        }
    }

    fn insert(
        &mut self, scope: &Ident, values: MemoryValues
    ) -> Result<(), Error> {
        if self.scopes.contains_key(scope) {
            return Err(Error::TargetScopeExists(scope.into()))
        }
        self.scopes.insert(scope.into(), values);
        Ok(())
    }

    fn remove(&mut self, scope: &Ident) -> Option<MemoryValues> {
        self.scopes.remove(scope)
    }

    fn clear(&mut self) {
        self.global.clear();
        self.scopes.clear();
    }

    fn scopes(&self) -> Vec<Box<Ident>> {
        self.scopes.keys().cloned().collect()
    }

    fn remove_value(
        &mut self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Value, Error> {
        let values = match self.get_mut(scope) {
            Some(scope) => scope,
            None => {
                return Err(Error::NotFound {
                    scope: scope.map(Into::into),
                    key: key.into()
                })
            }
        };
        let Some(value) = values.remove(key) else {
            return Err(Error::NotFound {
                scope: scope.map(Into::into),
                key: key.into()
            })
        };
        if let Some(scope) = scope {
            if values.is_empty() {
                self.remove(scope);
            }
        }
        Ok(value)
    }
}


//------------ MemoryNamespace -----------------------------------------------

#[derive(Debug, Default)]
struct MemoryNamespace {
    scopes: Mutex<MemoryScopes>,
    locks: Mutex<HashMap<Option<Box<Ident>>, Arc<RwLock<()>>>>,
}

impl MemoryNamespace {
    fn scopes(&self) -> MutexGuard<'_, MemoryScopes> {
        self.scopes.lock().expect("poisoned lock")
    }

    fn get_lock(&self, scope: Option<Box<Ident>>) -> Arc<RwLock<()>> {
        self.locks().entry(scope).or_default().clone()
    }

    fn locks(
        &self
    ) -> MutexGuard<'_, HashMap<Option<Box<Ident>>, Arc<RwLock<()>>>> {
        self.locks.lock().expect("poisoned lock")
    }

    fn try_clear_locks(&self) -> Result<(), Error> {
        // Try to get a write lock on every present lock. If that succeeds,
        // clear the hash map.

        let mut locks = self.locks();
        for lock in locks.values() {
            drop(lock.try_write().map_err(|_| Error::PendingLocks)?);
        }
        locks.clear();
        Ok(())
    }
}


//------------ Uri -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    path: Option<u64>,
}

impl Uri {
    pub fn new(seed: Option<u64>) -> Self {
        Uri { path: seed }
    }

    pub fn parse_uri(uri: &Url) -> Result<Option<Uri>, UriError> {
        if uri.scheme() != "memory" {
            return Ok(None)
        }
        if uri.path().is_empty() {
            return Ok(Some(Uri { path: None }))
        }
        if let Ok(path) = u64::from_str(uri.path()) {
            return Ok(Some(Uri { path: Some(path) }))
        }
        Err(UriError::BadPath(uri.path().into()))
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("memory:")?;
        if let Some(path) = self.path {
            write!(f, "{path}")?
        }
        Ok(())
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    ScopeLocked(Option<Box<Ident>>),
    Deserialize {
        scope: Option<Box<Ident>>,
        key: Box<Ident>,
        err: String,
    },
    Serialize {
        scope: Option<Box<Ident>>,
        key: Box<Ident>,
        err: String,
    },
    NotFound {
        scope: Option<Box<Ident>>,
        key: Box<Ident>,
    },
    NoScope(Box<Ident>),
    TargetScopeExists(Box<Ident>),
    MissingSourceNamespace(Box<Ident>),
    NonemptyTargetNamespace(Box<Ident>),
    PendingLocks,
}

impl Error {
    fn deserialize(
        scope: Option<&Ident>, key: &Ident, err: impl fmt::Display
    ) -> Self {
        Error::Deserialize {
            scope: scope.map(Into::into),
            key: key.into(),
            err: err.to_string()
        }
    }

    fn serialize(
        scope: Option<&Ident>, key: &Ident, err: impl fmt::Display
    ) -> Self {
        Error::Serialize {
            scope: scope.map(Into::into),
            key: key.into(),
            err: err.to_string()
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ScopeLocked(scope) => {
                match scope {
                    Some(scope) => write!(f, "scope {scope} already locked"),
                    None => write!(f, "global scope already locked")
                }
            }
            Error::Deserialize { scope, key, err } => {
                match scope {
                    Some(scope) => {
                        write!(f,
                            "failed to deserialize value for key '{key}' \
                            in scope '{scope}': {err}"
                        )
                    }
                    None => {
                        write!(f,
                            "failed to deserialize value for key '{key}' \
                            in global scope: {err}"
                        )
                    }
                }
            }
            Error::Serialize { scope, key, err } => {
                match scope {
                    Some(scope) => {
                        write!(f,
                            "failed to serialize value for key '{key}' \
                            in scope '{scope}': {err}"
                        )
                    }
                    None => {
                        write!(f,
                            "failed to serialize value for key '{key}' \
                            in global scope: {err}"
                        )
                    }
                }
            }
            Error::NotFound { scope, key } => {
                match scope {
                    Some(scope) => {
                        write!(f, "no key '{key}' in scope '{scope}'")
                    }
                    None => {
                        write!(f, "no key '{key}' in global scope")
                    }
                }
            }
            Error::NoScope(scope) => write!(f, "no such scope '{scope}'"),
            Error::TargetScopeExists(scope) => {
                write!(f, "target scope '{scope}' exists")
            }
            Error::MissingSourceNamespace(ns) => {
                write!(f, "missing source namespace '{ns}'")
            }
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


//------------ UriError ------------------------------------------------------

#[derive(Debug)]
pub enum UriError {
    BadPath(String),
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadPath(path) => write!(f, "invalid memory path '{path}'"),
        }
    }
}

impl error::Error for UriError { }

