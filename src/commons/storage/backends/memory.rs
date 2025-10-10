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
use crate::commons::storage::Ident;
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
        uri: &Url, namespace: &Ident, 
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

    pub fn execute<F, T>(
        &self, scope: Option<&Ident>, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let wait = Duration::from_millis(10);
        let tries = 1000;

        for i in 0..tries {
            if self.namespace.locks().insert(scope.map(Into::into)) {
                // The scope was not yet present. We’ve won and can go on.
                break
            }
            else if i >= tries {
                return Err(Error::ScopeLocked(scope.map(Into::into)).into())
            }
            thread::sleep(wait);
        }

        let res = op(&mut SuperTransaction::from(self));

        self.namespace.locks().remove(&scope.map(Into::into));

        res
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

#[derive(Debug)]
struct MemoryNamespace {
    ns_key: NsKey,
    scopes: Mutex<MemoryScopes>,
    locks: Mutex<HashSet<Option<Box<Ident>>>>,
}

impl MemoryNamespace {
    fn new(ns_key: NsKey) -> Self {
        Self {
            ns_key,
            scopes: Default::default(),
            locks: Default::default(),
        }
    }

    fn scopes(&self) -> MutexGuard<'_, MemoryScopes> {
        self.scopes.lock().expect("poisoned lock")
    }

    fn locks(&self) -> MutexGuard<'_, HashSet<Option<Box<Ident>>>> {
        self.locks.lock().expect("poisoned lock")
    }
}


//------------ NsKey ---------------------------------------------------------

/// The key for a store.
///
/// The first component is the URI, the second the namespace within that URI.
type NsKey = (String, Box<Ident>);


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
        namespace: Box<Ident>,
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

