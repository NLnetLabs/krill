mod kv;
pub use self::kv::{
    namespace, segment, Key, KeyValueError, KeyValueStore, Namespace, Scope, Segment, SegmentBuf, SegmentExt,
};
