//! Tests for the storage module.
//!
//! This module contains tests that are run for each storage backend which
//! requires a wee bit of macro magic.
#![cfg(test)]

use std::sync::{Mutex, MutexGuard};
use lazy_static::lazy_static;
use tempfile::{TempDir, tempdir};
use url::Url;
use super::{Key, KeyValueStore, Namespace, Scope, Segment};


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

const NAMESPACE: &Namespace = Namespace::make("namespace");
const SCOPE_SEGMENT: &Segment = Segment::make("scope");
const SCOPE_SEGMENT_2: &Segment = Segment::make("other_scope");
const KEY_SEGMENT: &Segment = Segment::make("key");
const KEY_SEGMENT_2: &Segment = Segment::make("other_key");
const CONTENT: u32 = 42;
const CONTENT_2: u32 = 43;
const CONTENT_3: u32 = 44;
const CONTENT_4: u32 = 45;


//------------ Test Functions ------------------------------------------------

// All the test functions.
//
// The all need to have the same signature taking one argument as an
// `impl Harness` and return unit. Each function will be transformed into a
// test function for each of the backends (currently memory and disk). The
// harness will give it access to a temporary test store atop that given
// backend. You can create a store for a specific namespace via the `store`
// method and access the store’s URL via `url`. This will allow you to
// determine the backend via the URL’s scheme if needed.
testfns! {
    fn store_get(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let key = Key::new_global(KEY_SEGMENT);

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(CONTENT));
    }

    fn store_new(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let key = Key::new_global(KEY_SEGMENT);

        assert!(store.store_new(&key, &CONTENT).is_ok());
        assert!(store.store_new(&key, &CONTENT).is_err());
    }

    fn store_scoped(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(SCOPE_SEGMENT);
        let key = Key::new_scoped(scope.clone(), KEY_SEGMENT);

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(CONTENT));
        assert!(store.has_scope(&scope).unwrap());

        let simple = Key::new_global(KEY_SEGMENT);
        store.store(&simple, &CONTENT_2).unwrap();
        assert!(store.has(&simple).unwrap());
        assert_eq!(store.get(&simple).unwrap(), Some(CONTENT_2));

        assert!(store.has(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), Some(CONTENT));
    }

    fn get(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let key = Key::new_global(KEY_SEGMENT);
        assert!(store.get::<String>(&key).unwrap().is_none());

        store.store(&key, &CONTENT).unwrap();
        assert_eq!(store.get(&key).unwrap(), Some(CONTENT));
    }

    fn has(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let key = Key::new_global(KEY_SEGMENT);
        assert!(!store.has(&key).unwrap());

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has(&key).unwrap());
    }

    fn drop_key(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let key = Key::new_global(KEY_SEGMENT);

        assert!(store.drop_key(&key).is_err());

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has(&key).unwrap());

        store.drop_key(&key).unwrap();
        assert!(!store.has(&key).unwrap());
    }

    fn drop_scope(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(SCOPE_SEGMENT);
        let scope2 = Scope::from_segment(SCOPE_SEGMENT_2);
        let key = Key::new_scoped(scope.clone(), KEY_SEGMENT);
        let key2 = Key::new_scoped(scope2.clone(), KEY_SEGMENT_2);

        store.store(&key, &CONTENT).unwrap();
        store.store(&key2, &CONTENT_2).unwrap();
        assert!(store.has_scope(&scope).unwrap());
        assert!(store.has_scope(&scope2).unwrap());
        assert!(store.has(&key).unwrap());
        assert!(store.has(&key2).unwrap());

        store.drop_scope(&scope).unwrap();
        assert!(!store.has_scope(&scope).unwrap());
        assert!(store.has_scope(&scope2).unwrap());
        assert!(!store.has(&key).unwrap());
        assert!(store.has(&key2).unwrap());
    }

    fn wipe(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(SCOPE_SEGMENT);
        let key = Key::new_scoped(scope.clone(), KEY_SEGMENT);

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has_scope(&scope).unwrap());
        assert!(store.has(&key).unwrap());
        
        store.wipe().unwrap();
        assert!(!store.has_scope(&scope).unwrap());
        assert!(!store.has(&key).unwrap());
        assert!(store.keys(&Scope::global(), "").unwrap().is_empty());
    }

    fn scopes(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(SCOPE_SEGMENT);
        let scope2 = Scope::from_segment(SCOPE_SEGMENT_2);
        let key = Key::new_scoped(scope.clone(), KEY_SEGMENT);
        let key2 = Key::new_scoped(scope2.clone(), KEY_SEGMENT_2);

        assert!(store.scopes().unwrap().is_empty());

        store.store(&key, &CONTENT).unwrap();
        assert_eq!(store.scopes().unwrap(), [scope.clone()]);

        store.store(&key2, &CONTENT_2).unwrap();

        let mut scopes = store.scopes().unwrap();
        scopes.sort();
        let mut expected = vec![scope.clone(), scope2.clone()];
        expected.sort();
        assert_eq!(scopes, expected);

        store.drop_scope(&scope2).unwrap();
        assert_eq!(store.scopes().unwrap(), [scope.clone()]);

        store.drop_scope(&scope).unwrap();
        assert!(store.scopes().unwrap().is_empty());
    }

    fn has_scope(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(SCOPE_SEGMENT);
        let key = Key::new_scoped(scope.clone(), KEY_SEGMENT);

        assert!(!store.has_scope(&scope).unwrap());

        store.store(&key, &CONTENT).unwrap();
        assert!(store.has_scope(&scope).unwrap());

        store.drop_key(&key).unwrap();
        assert!(!store.has_scope(&scope).unwrap());
    }

    fn keys(harness: impl Harness) {
        let store = harness.store(NAMESPACE);
        let scope = Scope::from_segment(Segment::make("command"));
        let id = Segment::make("command--id");
        let id2 = Segment::make("command--ls");
        let id3 = Segment::make("other");
        let key = Key::new_scoped(scope.clone(), id);
        let key2 = Key::new_scoped(scope.clone(), id2);
        let key3 = Key::new_global(id3);
        let key4 = Key::new_global(id);

        store.store(&key, &CONTENT).unwrap();
        store.store(&key2, &CONTENT_2).unwrap();
        store.store(&key3, &CONTENT_3).unwrap();
        store.store(&key4, &CONTENT_4).unwrap();

        let mut keys = store.keys(&scope, "command--").unwrap();
        keys.sort();
        let mut expected = vec![key.clone(), key2.clone()];
        expected.sort();
        assert_eq!(keys, expected);

        assert_eq!(store.keys(&scope, id2.as_str()).unwrap(), [key2.clone()]);
        assert_eq!(store.keys(&scope, id3.as_str()).unwrap(), []);
        assert_eq!(
            store.keys(&Scope::global(), id3.as_str()).unwrap(),
            [key3]
        );

        let mut keys = store.keys(&scope, "").unwrap();
        keys.sort();
        let mut expected = vec![key, key2];
        expected.sort();
        assert_eq!(keys, expected);
    }
}




//------------ Harness -------------------------------------------------------

/// A test harness for a specific storage backend.
trait Harness {
    /// Returns the URL of the backend.
    #[allow(dead_code)]
    fn url(&self) -> Url;

    /// Creates a new store for the given namespace.
    fn store(&self, namespace: &Namespace) -> KeyValueStore;
}


//------------ MemoryHarness -------------------------------------------------

/// The test harness for the memory backend.
///
/// Because there is only a single shared memory store for the whole process,
/// we can only run a single test using it at the same time and need to wipe
/// it clean before the test. This is why there are a lock and a guard here.
struct MemoryHarness<'a> {
    _guard: MutexGuard<'a, ()>,
}

lazy_static! {
    static ref MEMORY_LOCK: Mutex<()> = Mutex::new(());
}

impl<'a> MemoryHarness<'a> {
    fn new() -> Self {
        let _guard = MEMORY_LOCK.lock().unwrap();
        super::backends::memory::Store::wipe_all();
        Self { _guard }
    }
}

impl<'a> Harness for MemoryHarness<'a> {
    fn url(&self) -> Url {
        Url::parse("memory:").unwrap()
    }

    fn store(&self, namespace: &Namespace) -> KeyValueStore {
        KeyValueStore::create(
            &Url::parse("memory:").unwrap(),
            namespace,
        ).unwrap()
    }
}


//------------ DiskHarness ---------------------------------------------------

/// The test harness for the dist backend.
///
/// Creates a temporary directory using the `tempfile` crate which will be
/// removed automatically when the harness is dropped.
struct DiskHarness {
    _dir: TempDir,
    url: Url,
}

impl DiskHarness {
    fn new() -> Self {
        let _dir = tempdir().unwrap();
        let url = format!("local://{}", _dir.path().display());
        let url = Url::parse(&url).unwrap();
        Self { _dir, url }
    }
}

impl Harness for DiskHarness {
    fn url(&self) -> Url {
        self.url.clone()
    }

    fn store(&self, namespace: &Namespace) -> KeyValueStore {
        KeyValueStore::create(&self.url, namespace).unwrap()
    }
}

