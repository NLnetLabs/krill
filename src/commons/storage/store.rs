//! The key-value store.

use std::fmt;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use url::Url;
use super::types::{Key, Namespace, Scope};

macro_rules! store {
    ( $( ( $variant:ident, $module:ident ) )* ) => {


        //------------ KeyValueStore -----------------------------------------

        #[derive(Debug)]
        pub struct KeyValueStore(StoreInner);

        #[derive(Debug)]
        enum StoreInner {
            $(
                $variant( super::backends::$module::Store),
            )*
        }

        impl KeyValueStore {
            pub fn new(
                storage_uri: &Url, namespace: &Namespace
            ) -> Result<Self, StoreNewError> {
                $(
                    if let Some(inner) =
                    super::backends::$module::Store::from_uri(
                        storage_uri, namespace
                    )? {
                        return Ok(KeyValueStore(StoreInner::$variant(inner)))
                    }
                )*

                Err(StoreNewError::UnknownStorageScheme(
                    storage_uri.scheme().into()
                ))
            }

            pub fn execute<F, T>(
                &self, scope: &Scope, op: F
            ) -> Result<T, Error>
            where
                F: for<'a> Fn(&mut Transaction<'a>) -> Result<T, Error>
            {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            inner.execute(scope, op)
                        }
                    )*
                }
            }

            pub fn is_empty(&self) -> Result<bool, Error> {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.is_empty()?)
                        }
                    )*
                }
            }

            pub fn get_any(&self, key: &Key) -> Result<Option<Value>, Error> {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.get_any(key)?)
                        }
                    )*
                }
            }

            pub fn store_any(
                &self, key: &Key, value: &Value
            ) -> Result<(), Error> {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.store_any(key, value)?)
                        }
                    )*
                }
            }

            pub fn migrate_namespace(
                &mut self, to: &Namespace
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.migrate_namespace(to)?)
                        }
                    )*
                }
            }
        }


        //------------ Transaction -------------------------------------------

        #[derive(Debug)]
        pub struct Transaction<'a>(TransactionInner<'a>);

        #[derive(Debug)]
        enum TransactionInner<'a> {
            $(
                $variant(super::backends::$module::Transaction<'a>),
            )*
        }

        $(
            impl<'a> From<super::backends::$module::Transaction<'a>>
            for Transaction<'a> {
                fn from(
                    src: super::backends::$module::Transaction<'a>
                ) -> Self {
                    Self(TransactionInner::$variant(src))
                }
            }

            impl<'a> TryFrom<Transaction<'a>>
            for super::backends::$module::Transaction<'a> {
                type Error = ();

                fn try_from(
                    src: Transaction<'a>
                ) -> Result<Self, Self::Error> {
                    match src.0 {
                        TransactionInner::$variant(inner) => Ok(inner),
                        _ => Err(())
                    }
                }
            }
        )*

        /// # Reading
        impl<'a> Transaction<'a> {
            pub fn has(&mut self, key: &Key) -> Result<bool, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.has(key)?)
                        }
                    )*
                }
            }

            pub fn has_scope(&mut self, scope: &Scope) -> Result<bool, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.has_scope(scope)?)
                        }
                    )*
                }
            }

            pub fn get<T: DeserializeOwned>(
                &mut self, key: &Key
            ) -> Result<Option<T>, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.get(key)?)
                        }
                    )*
                }
            }

            pub fn list_keys(
                &mut self, scope: &Scope
            ) -> Result<Vec<Key>, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.list_keys(scope)?)
                        }
                    )*
                }
            }

            pub fn list_scopes(&mut self) -> Result<Vec<Scope>, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.list_scopes()?)
                        }
                    )*
                }
            }
        }


        /// # Writing
        impl<'a> Transaction<'a> {
            pub fn store<T: Serialize>(
                &mut self, key: &Key, value: &T
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.store(key, value)?)
                        }
                    )*
                }
            }

            pub fn move_value(
                &mut self, from: &Key, to: &Key
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.move_value(from, to)?)
                        }
                    )*
                }
            }

            pub fn move_scope(
                &mut self, from: &Scope, to: &Scope
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.move_scope(from, to)?)
                        }
                    )*
                }
            }

            pub fn delete(&mut self, key: &Key) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.delete(key)?)
                        }
                    )*
                }
            }

            pub fn delete_scope(&mut self, scope: &Scope) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.delete_scope(scope)?)
                        }
                    )*
                }
            }

            pub fn clear(&mut self) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.clear()?)
                        }
                    )*
                }
            }
        }


        //------------ Value -------------------------------------------------

        pub type Value = serde_json::Value;


        //------------ Error -------------------------------------------------

        #[derive(Debug)]
        pub struct Error(ErrorInner);

        #[derive(Debug)]
        enum ErrorInner {
            $(
                $variant(super::backends::$module::Error),
            )*
        }

        $(
            impl From<super::backends::$module::Error> for Error {
                fn from(src: super::backends::$module::Error) -> Self {
                    Self(ErrorInner::$variant(src))
                }
            }
        )*

        impl fmt::Display for Error {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match &self.0 {
                    $(
                        ErrorInner::$variant(inner) => inner.fmt(f),
                    )*
                }
            }
        }


        //------------ StoreNewError -----------------------------------------

        #[derive(Debug)]
        pub enum StoreNewError {
            UnknownStorageScheme(String),
            Store(Error)
        }

        impl From<Error> for StoreNewError {
            fn from(src: Error) -> Self {
                Self::Store(src)
            }
        }

        $(
            impl From<super::backends::$module::Error> for StoreNewError {
                fn from(src: super::backends::$module::Error) -> Self {
                    Self::Store(src.into())
                }
            }
        )*

        impl fmt::Display for StoreNewError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    Self::UnknownStorageScheme(ref scheme) => {
                        write!(f, "unknown storage scheme: {scheme}")
                    }
                    Self::Store(ref inner) => inner.fmt(f)
                }
            }
        }
    }
}

#[cfg(not(feature = "postgres"))]
store! {
    (Disk, disk)
    (Memory, memory)
}

#[cfg(feature = "postgres")]
store! {
    (Disk, disk)
    (Memory, memory)
    (Postgres, postgres)
}

