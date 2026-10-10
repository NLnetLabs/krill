//! Persistent storage of data.

pub use self::backends::{
    StorageUri, ParseStorageUriError, Transaction, Error,
};
pub use self::ident::{Ident, IdentBuilder, IdentError};
pub use self::store::{
    KeyValueStore, KeyValueError, OpenStoreError, StorageSystem,
};

use self::backends::{Backend, BackendSystem};

mod backends;
mod ident;
mod store;
mod test;

