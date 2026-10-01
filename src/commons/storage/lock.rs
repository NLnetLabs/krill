//! A scope lock for the key-value store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use super::ident::Ident;


//------------ MemoryScopeLocks ----------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryScopeLocks {
    namespaces: Mutex<MemoryNamespaces>,
}

impl MemoryScopeLocks {
    pub fn get(&self, namespace: &Ident, scope: &Ident) -> MemoryLock {
        self.namespaces.lock().expect("poisoned lock").get(namespace, scope)
    }
}


//------------ MemoryNamespaces ----------------------------------------------

#[derive(Debug, Default)]
struct MemoryNamespaces {
    namespaces: HashMap<Box<Ident>, MemoryScopes>,
}

impl MemoryNamespaces {
    fn get(&mut self, namespace: &Ident, scope: &Ident) -> MemoryLock {
        if let Some(namespace) = self.namespaces.get_mut(namespace) {
            return namespace.get(scope)
        }

        self.namespaces.entry(namespace.into()).or_default().get(scope)
    }
}


//------------ MemoryScopes --------------------------------------------------

#[derive(Debug, Default)]
struct MemoryScopes {
    scopes: HashMap<Box<Ident>, MemoryLock>,
}

impl MemoryScopes {
    fn get(&mut self, scope: &Ident) -> MemoryLock {
        if let Some(scope) = self.scopes.get(scope) {
            return scope.clone();
        }

        self.scopes.entry(scope.into()).or_default().clone()
    }
}


//------------ MemoryLock ----------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct MemoryLock {
    lock: Arc<Mutex<()>>,
}

impl MemoryLock {
    pub fn lock(&self) -> MemoryGuard<'_> {
        MemoryGuard {
            _guard: self.lock.lock().expect("poisoned lock")
        }
    }
}


//------------ MemoryGuard ---------------------------------------------------

pub struct MemoryGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

