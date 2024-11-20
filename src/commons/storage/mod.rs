//! Persistent storage of data.

pub use self::backends::{Backend, Transaction, Error};
pub use self::store::{KeyValueStore, KeyValueError};
pub use self::types::{
    Key, Namespace, NamespaceBuf, ParseNamespaceError, ParseSegmentError,
    Scope, Segment, SegmentBuf
};

mod backends;
mod store;
mod types;

