use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Display,
    str::FromStr,
    sync::{Mutex, MutexGuard},
};

use futures_util::Future;
use lazy_static::lazy_static;

use crate::commons::storage::{Key, KeyValueError, NamespaceBuf, Scope, StorageResult};

use super::KeyValueStoreDispatcher;

#[derive(Debug)]
pub struct MemoryStore(HashMap<NamespaceBuf, HashMap<Key, serde_json::Value>>);

impl MemoryStore {
    fn new() -> Self {
        MemoryStore(HashMap::new())
    }

    fn has(&self, namespace: &NamespaceBuf, key: &Key) -> bool {
        self.0.get(namespace).map(|m| m.contains_key(key)).unwrap_or(false)
    }

    fn namespace_is_empty(&self, namespace: &NamespaceBuf) -> bool {
        self.0.get(namespace).map(|m| m.is_empty()).unwrap_or(true)
    }

    fn has_scope(&self, namespace: &NamespaceBuf, scope: &Scope) -> bool {
        self.0
            .get(namespace)
            .map(|m| m.keys().any(|k| k.scope().starts_with(scope)))
            .unwrap_or_default()
    }

    fn get(&self, namespace: &NamespaceBuf, key: &Key) -> Option<serde_json::Value> {
        self.0.get(namespace).and_then(|m| m.get(key).cloned())
    }

    fn insert(&mut self, namespace: &NamespaceBuf, key: &Key, value: serde_json::Value) {
        let map = self.0.entry(namespace.clone()).or_default();
        map.insert(key.clone(), value);
    }

    fn delete(&mut self, namespace: &NamespaceBuf, key: &Key) -> StorageResult<()> {
        self.0
            .get_mut(namespace)
            .ok_or(KeyValueError::UnknownKey(key.clone()))?
            .remove(key)
            .ok_or(KeyValueError::UnknownKey(key.clone()))?;
        Ok(())
    }

    fn move_value(&mut self, namespace: &NamespaceBuf, from: &Key, to: &Key) -> StorageResult<()> {
        match self.0.get_mut(namespace) {
            None => Err(KeyValueError::Other(format!("unknown namespace: {}", namespace))),
            Some(map) => match map.remove(from) {
                Some(value) => {
                    map.insert(to.clone(), value);
                    Ok(())
                }
                None => Err(KeyValueError::UnknownKey(from.clone())),
            },
        }
    }

    fn list_keys(&self, namespace: &NamespaceBuf, scope: &Scope) -> Vec<Key> {
        self.0
            .get(namespace)
            .map(|m| {
                m.keys()
                    .filter(|k| k.scope().starts_with(scope))
                    .cloned()
                    .collect::<Vec<Key>>()
            })
            .unwrap_or_default()
    }

    fn list_scopes(&self, namespace: &NamespaceBuf) -> Vec<Scope> {
        let scopes: BTreeSet<Scope> = self
            .0
            .get(namespace)
            .map(|m| m.keys().flat_map(|k| k.scope().sub_scopes()).collect())
            .unwrap_or_default();

        scopes.into_iter().collect()
    }

    fn delete_scope(&mut self, namespace: &NamespaceBuf, scope: &Scope) -> StorageResult<()> {
        if let Some(map) = self.0.get_mut(namespace) {
            map.retain(|k, _| !k.scope().starts_with(scope));
        }

        Ok(())
    }

    fn migrate_namespace(&mut self, from: &NamespaceBuf, to: &NamespaceBuf) -> StorageResult<()> {
        if !self.namespace_is_empty(to) {
            Err(KeyValueError::Other(format!(
                "target in-memory namespace {} is not empty",
                to.as_str()
            )))
        } else {
            match self.0.remove(from) {
                None => Err(KeyValueError::Other(format!(
                    "original in-memory namespace {} does not exist",
                    from.as_str()
                ))),
                Some(map) => {
                    self.0.insert(to.clone(), map);
                    Ok(())
                }
            }
        }
    }

    pub fn clear(&mut self, namespace: &NamespaceBuf) -> StorageResult<()> {
        self.0.insert(namespace.clone(), HashMap::new());
        Ok(())
    }
}

lazy_static! {
    static ref STORE: Mutex<MemoryStore> = Mutex::new(MemoryStore::new());
    static ref LOCKS: Mutex<HashSet<ScopeLock>> = Mutex::new(HashSet::new());
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ScopeLock(String);

impl ScopeLock {
    fn new(namespace: &NamespaceBuf, scope: &Scope) -> Self {
        ScopeLock(format!("{}/{}", namespace, scope))
    }
}

#[derive(Clone, Debug)]
pub struct Memory {
    // Used to prevent namespace collisions in the shared (lazy static) in memory structure.
    namespace_prefix: Option<String>,
    effective_namespace: NamespaceBuf,
    inner: &'static Mutex<MemoryStore>,
    locks: &'static Mutex<HashSet<ScopeLock>>,
}

impl Memory {
    pub(crate) fn new(namespace_prefix: Option<&str>, namespace: NamespaceBuf) -> StorageResult<Self> {
        let namespace_prefix = namespace_prefix.map(|s| s.to_string());
        let effective_namespace = Self::effective_namespace(&namespace_prefix, namespace)?;

        Ok(Memory {
            namespace_prefix,
            effective_namespace,
            inner: &STORE,
            locks: &LOCKS,
        })
    }

    fn effective_namespace(namespace_prefix: &Option<String>, namespace: NamespaceBuf) -> StorageResult<NamespaceBuf> {
        if let Some(pfx) = namespace_prefix {
            NamespaceBuf::from_str(&format!("{}_{}", pfx, namespace)).map_err(|e| {
                KeyValueError::UnknownScheme(format!("cannot parse prefix '{}' for memory store: {}", pfx, e))
            })
        } else {
            Ok(namespace)
        }
    }

    pub(super) fn lock(&self) -> StorageResult<MutexGuard<'_, MemoryStore>> {
        self.inner
            .lock()
            .map_err(|e| KeyValueError::Other(format!("cannot unlock mutex: {e}")))
    }
}

impl Display for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "memory://{}", self.effective_namespace)
    }
}

impl Memory {
    pub async fn execute<'f, F, T, Ret>(&self, scope: &Scope, op: F) -> Result<T, KeyValueError>
    where
        F: FnOnce(KeyValueStoreDispatcher) -> Ret,
        Ret: Future<Output = Result<T, KeyValueError>>,
    {
        //     fn transaction(&self, scope: &Scope, callback: TransactionCallback) -> Result<()> {
        // Try to get a lock for 10 seconds. We may need to make this configurable.
        // Dependent on use cases it may actually not be that exceptional for locks
        // to be kept for even longer.
        let wait_ms = 10;
        let tries = 1000;

        let scope_lock = ScopeLock::new(&self.effective_namespace, scope);

        for i in 0..tries {
            let mut locks = self
                .locks
                .lock()
                .map_err(|e| KeyValueError::Other(format!("Can't get lock: {e}")))?;

            if locks.contains(&scope_lock) {
                if i >= tries {
                    return Err(KeyValueError::Other(format!("Scope {} already locked", scope)));
                } else {
                    drop(locks);
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                }
            } else {
                locks.insert(scope_lock.clone());
                break;
            }
        }

        let dispatcher = KeyValueStoreDispatcher::Memory(self.clone());
        let res = op(dispatcher).await;

        let mut locks = self
            .locks
            .lock()
            .map_err(|e| KeyValueError::Other(format!("cannot get lock: {e}")))?;

        locks.remove(&scope_lock);

        res
    }
}

impl Memory {
    pub fn is_empty(&self) -> StorageResult<bool> {
        self.lock().map(|l| l.namespace_is_empty(&self.effective_namespace))
    }

    pub fn has(&self, key: &Key) -> StorageResult<bool> {
        Ok(self.lock()?.has(&self.effective_namespace, key))
    }

    pub fn has_scope(&self, scope: &Scope) -> StorageResult<bool> {
        Ok(self.lock()?.has_scope(&self.effective_namespace, scope))
    }

    pub fn get(&self, key: &Key) -> StorageResult<Option<serde_json::Value>> {
        Ok(self.lock()?.get(&self.effective_namespace, key))
    }

    pub fn list_keys(&self, scope: &Scope) -> StorageResult<Vec<Key>> {
        Ok(self.lock()?.list_keys(&self.effective_namespace, scope))
    }

    pub fn list_scopes(&self) -> StorageResult<Vec<Scope>> {
        Ok(self.lock()?.list_scopes(&self.effective_namespace))
    }
}

impl Memory {
    pub fn store(&self, key: &Key, value: serde_json::Value) -> StorageResult<()> {
        self.lock()?.insert(&self.effective_namespace, key, value);
        Ok(())
    }

    pub fn move_value(&self, from: &Key, to: &Key) -> StorageResult<()> {
        self.lock()?.move_value(&self.effective_namespace, from, to)
    }

    pub fn delete(&self, key: &Key) -> StorageResult<()> {
        self.lock()?.delete(&self.effective_namespace, key)
    }

    pub fn delete_scope(&self, scope: &Scope) -> StorageResult<()> {
        self.lock()?.delete_scope(&self.effective_namespace, scope)
    }

    pub fn clear(&self) -> StorageResult<()> {
        self.lock()?.clear(&self.effective_namespace)
    }

    pub fn migrate_namespace(&mut self, to: NamespaceBuf) -> StorageResult<()> {
        // We need to preserve the namespace prefix if it was set.
        // This prefix is used to prevent namespace collisions in the
        // shared (lazy static) in memory structure.
        let effective_to = Self::effective_namespace(&self.namespace_prefix, to)?;

        self.lock()?
            .migrate_namespace(&self.effective_namespace, &effective_to)?;
        self.effective_namespace = effective_to;

        Ok(())
    }
}
