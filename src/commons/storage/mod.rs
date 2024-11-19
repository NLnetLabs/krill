//! Persistent storage of data.

pub use self::store::{KeyValueStore, Transaction, Error, StoreNewError};
pub use self::types::{
    Key, Namespace, NamespaceBuf, ParseNamespaceError, ParseSegmentError,
    Scope, Segment, SegmentBuf
};

mod backends;
mod store;
mod types;

