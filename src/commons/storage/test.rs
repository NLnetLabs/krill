//! Tests for the storage module.
//!
//! This module contains tests that are run for each storage backend.
#![cfg(test)]

use std::panic;
use tempfile::{TempDir, tempdir};
use url::Url;
use super::{KeyValueStore, Namespace};


//------------ Macro to Construct Tests --------------------------------------

/// A macro to construct a function testing each backend.
///
/// For details, see the macro invocation below. This is just up here because
/// Rust wants it here.
macro_rules! testfns {
    (
        $(
            $name:ident => $closure:expr
        ),*
    ) => {
        $(
            #[test]
            fn $name() {
                let hook = panic::take_hook();
                panic::set_hook(Box::new(move |info| {
                    eprintln!("Panic in memory backend.");
                    hook(info);
                }));
                $closure(&MemoryHarness);

                // Do it twice to get the default hook again.
                let _ = panic::take_hook();
                let hook = panic::take_hook();
                panic::set_hook(Box::new(move |info| {
                    eprintln!("Panic in disk backend.");
                    hook(info);
                }));
                $closure(&DiskHarness::new());

                // Clean up, just in case.
                let _ = panic::take_hook();
            }
        )*
    }
}


//------------ Test Functions ------------------------------------------------

// All the test functions.
//
// Each test function is given here by its name and a closure that does the
// actual testing. The closure is given a reference to a test harness which
// is a generic type implementing `Harness` -- see the trait definition
// below. It is run once for each of the backends we support.
testfns! {

    noop => |harness: &dyn Harness| {
        let _store = harness.store(Namespace::make("test"));
        if harness.url().scheme() == "local" {
            panic!("Boom: {}", harness.url());
        }
    }
}




//------------ Harness -------------------------------------------------------

/// A test harness for a specific storage backend.
trait Harness {
    /// Returns the URL of the backend.
    fn url(&self) -> Url;

    /// Creates a new store for the given namespace.
    fn store(&self, namespace: &Namespace) -> KeyValueStore;
}


//------------ MemoryHarness -------------------------------------------------

/// The test harness for the memory backend.
struct MemoryHarness;

impl Harness for MemoryHarness {
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

