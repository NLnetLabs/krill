//! Storage backends.


//============ Modules =======================================================
//
// These need to be added to the macro invocation at the very bottom of this
// file.

mod disk;
mod memory;


//============ Backend Enum ==================================================

use std::fmt;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use url::Url;
use super::types::{Key, Namespace, Scope};

macro_rules! store {
    ( $( ( $variant:ident, $module:ident ) )* ) => {


        //------------ Backend -----------------------------------------------

        #[derive(Debug)]
        pub struct Backend(StoreInner);

        #[derive(Debug)]
        enum StoreInner {
            $(
                $variant( self::$module::Store),
            )*
        }

        impl Backend {
            pub fn new(
                storage_uri: &Url, namespace: &Namespace
            ) -> Result<Option<Self>, Error> {
                $(
                    if let Some(inner) =
                    self::$module::Store::from_uri(
                        storage_uri, namespace
                    )? {
                        return Ok(Some(Backend(StoreInner::$variant(inner))))
                    }
                )*

                Ok(None)
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
                $variant(self::$module::Transaction<'a>),
            )*
        }

        $(
            impl<'a> From<self::$module::Transaction<'a>>
            for Transaction<'a> {
                fn from(
                    src: self::$module::Transaction<'a>
                ) -> Self {
                    Self(TransactionInner::$variant(src))
                }
            }

            impl<'a> TryFrom<Transaction<'a>>
            for self::$module::Transaction<'a> {
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
                $variant(self::$module::Error),
            )*
        }

        $(
            impl From<self::$module::Error> for Error {
                fn from(src: self::$module::Error) -> Self {
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
    }
}

store! {
    (Disk, disk)
    (Memory, memory)
}

