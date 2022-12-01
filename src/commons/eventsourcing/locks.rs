//! Support locking on Handles so that updates can be
//! performed sequentially. Useful for both event sourced
//! types (Aggregates) as well as write-ahead logging
//! types.

//------------ HandleLocks ---------------------------------------------------

use std::{
    collections::HashMap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use rpki::ca::idexchange::MyHandle;

#[derive(Debug, Default)]
struct HandleLockMap(HashMap<MyHandle, RwLock<()>>);

impl HandleLockMap {
    fn create_handle_lock(&mut self, handle: MyHandle) {
        self.0.insert(handle, RwLock::new(()));
    }

    fn has_handle(&self, handle: &MyHandle) -> bool {
        self.0.contains_key(handle)
    }

    fn drop_handle_lock(&mut self, handle: &MyHandle) {
        self.0.remove(handle);
    }
}

pub struct HandleLock<'a> {
    // Needs a read reference to the map that holds the RwLock
    // for the handle.
    map: RwLockReadGuard<'a, HandleLockMap>,
    handle: MyHandle,
}

impl HandleLock<'_> {
    // panics if there is no entry for the handle.
    pub fn read(&self) -> RwLockReadGuard<'_, ()> {
        self.map.0.get(&self.handle).unwrap().read().unwrap()
    }

    // panics if there is no entry for the handle.
    pub fn write(&self) -> RwLockWriteGuard<'_, ()> {
        self.map.0.get(&self.handle).unwrap().write().unwrap()
    }
}

/// This structure is used to ensure that we have unique access to an instance for a [`Handle`]
/// managed in an [`AggregateStore`] or [`WalStore`]. Currently uses a `std::sync::RwLock`, but
/// this should be improved to use an async lock instead (e.g. `tokio::sync::RwLock`).
/// This has not been done yet, because that change is quite pervasive.
#[derive(Debug, Default)]
pub struct HandleLocks {
    locks: RwLock<HandleLockMap>,
}

impl HandleLocks {
    pub fn for_handle(&self, handle: MyHandle) -> HandleLock<'_> {
        {
            // Return the lock *if* there is an entry for the handle
            let map = self.locks.read().unwrap();
            if map.has_handle(&handle) {
                return HandleLock { map, handle };
            }
        }

        {
            // There was no entry.. try to create an entry for the
            // handle.
            let mut map = self.locks.write().unwrap();

            // But.. first check again, because we could have had a
            // race condition if two threads call this function.
            if !map.has_handle(&handle) {
                map.create_handle_lock(handle.clone());
            }
        }

        // Entry probably exists now, but recurse in case the entry
        // was dropped immediately after creation.
        self.for_handle(handle)
    }

    pub fn drop_handle(&self, handle: &MyHandle) {
        let mut map = self.locks.write().unwrap();
        map.drop_handle_lock(handle);
    }
}
