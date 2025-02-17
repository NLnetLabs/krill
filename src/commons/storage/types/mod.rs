//! Types for addressing stored data.

pub use self::key::Key;
pub use self::namespace::{Namespace, NamespaceBuf, ParseNamespaceError};
pub use self::scope::Scope;
pub use self::segment::{ParseSegmentError, Segment, SegmentBuf};

mod key;
mod namespace;
mod scope;
mod segment;
