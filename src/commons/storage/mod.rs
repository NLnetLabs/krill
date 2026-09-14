
pub use self::combined::{
    StorageSystem, StorageUri, Store, StoreError, Transaction
};
pub use self::kv::{KeyValueError, KeyValueStore, KeyValueTransaction};
pub use self::ident::Ident;

pub mod combined;
pub mod ident;
pub mod kv;
pub mod statements;

pub mod disk;
pub mod psql;
pub mod sqlite;
