//! Tests for the storage module.
//!
//! This module contains tests that are run for each storage backend which
//! requires a wee bit of macro magic.
#![cfg(test)]

use tempfile::{TempDir, tempdir};
use super::{Ident, KeyValueStore, StorageSystem, StorageUri};


//------------ Macro to Construct Tests --------------------------------------

/// A macro to construct a function testing each backend.
///
/// For details, see the macro invocation below. This is just up here because
/// Rust wants it that way.
macro_rules! testfns {
    (
        $(
            fn $name:ident($harness:ident: impl Harness) $body:block
        )*
    ) => {
        mod testfns {
            use super::*;

            $(
                pub fn $name($harness: impl Harness) $body
            )*
        }

        mod memory {
            use super::*;

            $(
                #[test]
                fn $name() {
                    super::testfns::$name(MemoryHarness::new());
                }
            )*
        }

        mod disk {
            use super::*;

            $(
                #[test]
                fn $name() {
                    super::testfns::$name(DiskHarness::new());
                }
            )*
        }
    }
}


//------------ Test Data -----------------------------------------------------

const NAMESPACE: &Ident = Ident::make("namespace");
const SCOPE: &Ident = Ident::make("scope");
const SCOPE_2: &Ident= Ident::make("other_scope");
const KEY: &Ident = Ident::make("key");
const KEY_2: &Ident = Ident::make("other_key");
const CONTENT: u32 = 42;
const CONTENT_2: u32 = 43;
const CONTENT_3: u32 = 44;
const CONTENT_4: u32 = 45;


//------------ Test Functions ------------------------------------------------

// All the test functions.
//
// They all need to have the same signature taking one argument as an
// `impl Harness` and return unit. Each function will be transformed into a
// test function for each of the backends (currently memory and disk). The
// harness will give it access to a temporary test store atop that given
// backend. You can create a store for a specific namespace via the `store`
// method and access the store’s URL via `url`. This will allow you to
// determine the backend via the URL’s scheme if needed.
testfns! {
    fn store_get(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        store.store(None, KEY, &CONTENT).unwrap();
        assert!(store.has(None, KEY).unwrap());
        assert_eq!(store.get(None, KEY).unwrap(), Some(CONTENT));
    }

    fn store_new(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        assert!(store.store_new(None, KEY, &CONTENT).is_ok());
        assert!(store.store_new(None, KEY, &CONTENT).is_err());
    }

    fn store_scoped(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        assert!(store.has(Some(SCOPE), KEY).unwrap());
        assert_eq!(store.get(Some(SCOPE), KEY).unwrap(), Some(CONTENT));
        assert!(store.has_scope(SCOPE).unwrap());

        store.store(None, KEY, &CONTENT_2).unwrap();
        assert!(store.has(None, KEY).unwrap());
        assert_eq!(store.get(None, KEY).unwrap(), Some(CONTENT_2));

        assert!(store.has(Some(SCOPE), KEY).unwrap());
        assert_eq!(store.get(Some(SCOPE), KEY).unwrap(), Some(CONTENT));
    }

    fn get(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        assert!(store.get::<String>(None, KEY).unwrap().is_none());

        store.store(None, KEY, &CONTENT).unwrap();
        assert_eq!(store.get(None, KEY).unwrap(), Some(CONTENT));
    }

    fn has(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        assert!(!store.has(None, KEY).unwrap());

        store.store(None, KEY, &CONTENT).unwrap();
        assert!(store.has(None, KEY).unwrap());
    }

    fn drop_global_key(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        assert!(store.drop_key(None, KEY).is_err());

        store.store(None, KEY, &CONTENT).unwrap();
        assert!(store.has(None, KEY).unwrap());

        store.drop_key(None, KEY).unwrap();
        assert!(!store.has(None, KEY).unwrap());
    }

    fn drop_scoped_key(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        assert!(store.drop_key(Some(SCOPE), KEY).is_err());

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        assert!(store.has(Some(SCOPE), KEY).unwrap());

        store.drop_key(Some(SCOPE), KEY).unwrap();
        assert!(!store.has(Some(SCOPE), KEY).unwrap());
        assert!(!store.has_scope(SCOPE).unwrap());
    }

    fn drop_scope(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        store.store(Some(SCOPE_2), KEY_2, &CONTENT_2).unwrap();
        assert!(store.has_scope(SCOPE).unwrap());
        assert!(store.has_scope(SCOPE_2).unwrap());
        assert!(store.has(Some(SCOPE), KEY).unwrap());
        assert!(store.has(Some(SCOPE_2), KEY_2).unwrap());

        store.drop_scope(SCOPE).unwrap();
        assert!(!store.has_scope(SCOPE).unwrap());
        assert!(store.has_scope(SCOPE_2).unwrap());
        assert!(!store.has(Some(SCOPE), KEY).unwrap());
        assert!(store.has(Some(SCOPE_2), KEY_2).unwrap());
    }

    fn wipe(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        assert!(store.has_scope(SCOPE).unwrap());
        assert!(store.has(Some(SCOPE), KEY).unwrap());
        
        store.wipe().unwrap();
        assert!(!store.has_scope(SCOPE).unwrap());
        assert!(!store.has(Some(SCOPE), KEY).unwrap());
        assert!(store.keys(None, "").unwrap().is_empty());
        assert!(store.keys(Some(SCOPE), "").unwrap().is_empty());
    }

    fn scopes(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        assert!(store.scopes().unwrap().is_empty());

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        assert_eq!(store.scopes().unwrap(), [SCOPE.into()]);

        store.store(Some(SCOPE_2), KEY_2, &CONTENT_2).unwrap();

        let mut scopes = store.scopes().unwrap();
        scopes.sort();
        let mut expected = vec![SCOPE.into(), SCOPE_2.into()];
        expected.sort();
        assert_eq!(scopes, expected);

        store.drop_scope(SCOPE_2).unwrap();
        assert_eq!(store.scopes().unwrap(), [SCOPE.into()]);

        store.drop_scope(SCOPE).unwrap();
        assert!(store.scopes().unwrap().is_empty());
    }

    fn has_scope(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        assert!(!store.has_scope(SCOPE).unwrap());

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        assert!(store.has_scope(SCOPE).unwrap());

        store.drop_key(Some(SCOPE), KEY).unwrap();
        assert!(!store.has_scope(SCOPE).unwrap());
    }

    fn keys(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        const KEY_ID: &Ident = Ident::make("command--id");
        const KEY_LS: &Ident = Ident::make("command--ls");
        const KEY_OTHER: &Ident = Ident::make("other");

        // key: Some(SCOPE), KEY_ID
        // key2: Some(SCOPE), KEY_LS
        // key3: None, KEY_OTHER
        // key4: None, KEY_ID

        store.store(Some(SCOPE), KEY_ID, &CONTENT).unwrap();
        store.store(Some(SCOPE), KEY_LS, &CONTENT_2).unwrap();
        store.store(None, KEY_OTHER, &CONTENT_3).unwrap();
        store.store(None, KEY_ID, &CONTENT_4).unwrap();

        let mut keys = store.keys(Some(SCOPE), "command--").unwrap();
        keys.sort();
        let mut expected = vec![KEY_ID.into(), KEY_LS.into()];
        expected.sort();
        assert_eq!(keys, expected);

        assert_eq!(
            store.keys(Some(SCOPE), KEY_LS.as_str()).unwrap(),
            [KEY_LS.into()]
        );
        assert_eq!(store.keys(Some(SCOPE), KEY_OTHER.as_str()).unwrap(), []);
        assert_eq!(
            store.keys(None, KEY_OTHER.as_str()).unwrap(),
            [KEY_OTHER.into()]
        );

        let mut keys = store.keys(Some(SCOPE), "").unwrap();
        keys.sort();
        let mut expected = vec![KEY_ID.into(), KEY_LS.into()];
        expected.sort();
        assert_eq!(keys, expected);
    }

    fn move_value(harness: impl Harness) {
        let store = harness.store(NAMESPACE);

        store.store(Some(SCOPE), KEY, &CONTENT).unwrap();
        store.store(Some(SCOPE), KEY_2, &CONTENT_2).unwrap();
        assert!(store.has_scope(SCOPE).unwrap());
        assert!(!store.has_scope(SCOPE_2).unwrap());
        assert_eq!(store.get(Some(SCOPE), KEY).unwrap(), Some(CONTENT));
        assert!(!store.has(Some(SCOPE_2), KEY).unwrap());
        assert_eq!(store.get(Some(SCOPE), KEY_2).unwrap(), Some(CONTENT_2));
        assert!(!store.has(Some(SCOPE_2), KEY_2).unwrap());

        store.execute(None, |store| {
            store.move_value(Some(SCOPE), KEY, Some(SCOPE_2), KEY)
        }).unwrap();
        assert!(store.has_scope(SCOPE).unwrap());
        assert!(store.has_scope(SCOPE_2).unwrap());
        assert!(!store.has(Some(SCOPE), KEY).unwrap());
        assert_eq!(store.get(Some(SCOPE_2), KEY).unwrap(), Some(CONTENT));
        assert_eq!(store.get(Some(SCOPE), KEY_2).unwrap(), Some(CONTENT_2));
        assert!(!store.has(Some(SCOPE_2), KEY_2).unwrap());

        store.execute(None, |store| {
            store.move_value(Some(SCOPE), KEY_2, Some(SCOPE_2), KEY_2)
        }).unwrap();
        assert!(!store.has_scope(SCOPE).unwrap());
        assert!(store.has_scope(SCOPE_2).unwrap());
        assert!(!store.has(Some(SCOPE), KEY).unwrap());
        assert_eq!(store.get(Some(SCOPE_2), KEY).unwrap(), Some(CONTENT));
        assert!(!store.has(Some(SCOPE), KEY_2).unwrap());
        assert_eq!(store.get(Some(SCOPE_2), KEY_2).unwrap(), Some(CONTENT_2));
    }
}




//------------ Harness -------------------------------------------------------

/// A test harness for a specific storage backend.
trait Harness {
    /// Returns the URL of the backend.
    #[allow(dead_code)]
    fn uri(&self) -> &StorageUri;

    /// Creates a new store for the given namespace.
    fn store(&self, namespace: &Ident) -> KeyValueStore;
}


//------------ MemoryHarness -------------------------------------------------

/// The test harness for the memory backend.
struct MemoryHarness {
    storage: StorageSystem,
}

impl MemoryHarness {
    fn new() -> Self {
        Self {
            storage: StorageSystem::new_memory(None)
        }
    }
}

impl Harness for MemoryHarness {
    fn uri(&self) -> &StorageUri {
        self.storage.default_uri()
    }

    fn store(&self, namespace: &Ident) -> KeyValueStore {
        self.storage.open(namespace).unwrap()
    }
}


//------------ DiskHarness ---------------------------------------------------

/// The test harness for the dist backend.
///
/// Creates a temporary directory using the `tempfile` crate which will be
/// removed automatically when the harness is dropped.
struct DiskHarness {
    _dir: TempDir,
    storage: StorageSystem,
}

impl DiskHarness {
    fn new() -> Self {
        let _dir = tempdir().unwrap();
        let storage = StorageSystem::new_disk(_dir.path().into());

        Self { _dir, storage }
    }
}

impl Harness for DiskHarness {
    fn uri(&self) -> &StorageUri {
        self.storage.default_uri()
    }

    fn store(&self, namespace: &Ident) -> KeyValueStore {
        self.storage.open(namespace).unwrap()
    }
}

