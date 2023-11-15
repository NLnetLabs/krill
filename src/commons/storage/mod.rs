pub use disk::Disk;
pub use key::Key;
pub use memory::{Memory, MemoryStore};
pub use namespace::{Namespace, NamespaceBuf, ParseNamespaceError};
pub use queue::*;
pub use scope::Scope;
pub use segment::{ParseSegmentError, Segment, SegmentBuf};
pub use types::Storable;

pub use self::kv::{KeyValueError, KeyValueStore, KeyValueStoreDispatcher, StorageResult};

mod disk;
mod key;
mod kv;
mod memory;
mod namespace;
mod queue;
mod scope;
mod segment;
mod types;
