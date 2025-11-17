//! Persistent storage of data.

pub use self::backends::{Backend, Transaction, Error};
pub use self::ident::{Ident, IdentBuilder, IdentError};
pub use self::store::{
    KeyValueStore, KeyValueError, OpenStoreError, StorageConnectError,
    StorageSystem
};

mod backends;
mod ident;
mod store;
mod test;

