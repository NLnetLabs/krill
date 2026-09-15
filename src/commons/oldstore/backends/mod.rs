//! Storage backends.


//============ Modules =======================================================
//
// These need to be added to the macro invocation at the very bottom of this
// file.

mod disk;
pub(super) mod memory; // Test code wants to access the Store directly.


//============ Backend Enum ==================================================

use std::{error, fmt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use url::Url;
use super::{Ident, KeyValueError};

macro_rules! store {
    ( $( ( $variant:ident, $module:ident ) )* ) => {

        //------------ BackendSystem -----------------------------------------

        #[derive(Debug, Default)]
        pub struct BackendSystem {
            $(
                $module: self::$module::System,
            )*
        }

        impl BackendSystem {
            fn location(
                &self, uri: &StorageUri
            )  -> Result<Location, KeyValueError> {
                match &uri.0 {
                    $(
                        UriInner::$variant(uri) => {
                            Ok(Location::$variant(
                                self.$module.location(uri).map_err(|err| {
                                    KeyValueError::Inner(
                                        Error(ErrorInner::$variant(err))
                                    )
                                })?
                            ))
                        }
                    )*
                }
            }

            pub fn open(
                &self, storage_uri: &StorageUri, namespace: &Ident,
            ) -> Result<Backend, KeyValueError> {
                Ok(self.location(storage_uri)?.open(namespace)?)
            }

            pub fn is_empty(
                &self, storage_uri: &StorageUri, namespace: &Ident,
            ) -> Result<bool, KeyValueError> {
                Ok(self.location(storage_uri)?.is_empty(namespace)?)
            }

            pub fn migrate(
                &self,
                storage_uri: &StorageUri,
                src_ns: &Ident,
                dst_ns: &Ident
            ) -> Result<(), KeyValueError> {
                Ok(self.location(storage_uri)?.migrate(src_ns, dst_ns)?)
            }
        }


        //------------ Location ----------------------------------------------

        #[derive(Debug)]
        enum Location {
            $(
                $variant( self::$module::Location ),
            )*
        }

        impl Location {
            fn open(
                &self, namespace: &Ident,
            ) -> Result<Backend, Error> {
                match self {
                    $(
                        Self::$variant(inner) => {
                            Ok(Backend(StoreInner::$variant(
                                inner.open(namespace)?
                            )))
                        }
                    )*
                }
            }

            fn is_empty(
                &self, namespace: &Ident,
            ) -> Result<bool, Error> {
                match self {
                    $(
                        Self::$variant(inner) => {
                            Ok(inner.is_empty(namespace)?)
                        }
                    )*
                }
            }

            fn migrate(
                &self, src_ns: &Ident, dst_ns: &Ident
            ) -> Result<(), Error> {
                match self {
                    $(
                        Self::$variant(inner) => {
                            Ok(inner.migrate(src_ns, dst_ns)?)
                        }
                    )*
                }
            }
        }


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
            pub fn execute<F, T>(
                &self, scope: Option<&Ident>, op: F
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

            pub fn get_any(
                &self, scope: Option<&Ident>, key: &Ident
            ) -> Result<Option<Value>, Error> {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.get_any(scope, key)?)
                        }
                    )*
                }
            }

            pub fn store_any(
                &self, scope: Option<&Ident>, key: &Ident, value: &Value
            ) -> Result<(), Error> {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            Ok(inner.store_any(scope, key, value)?)
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
            pub fn has(
                &mut self, scope: Option<&Ident>, key: &Ident,
            ) -> Result<bool, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.has(scope, key)?)
                        }
                    )*
                }
            }

            pub fn has_scope(
                &mut self, scope: &Ident
            ) -> Result<bool, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.has_scope(scope)?)
                        }
                    )*
                }
            }

            pub fn get<T: DeserializeOwned>(
                &mut self, scope: Option<&Ident>, key: &Ident
            ) -> Result<Option<T>, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.get(scope, key)?)
                        }
                    )*
                }
            }

            pub fn list_keys(
                &mut self, scope: Option<&Ident>,
            ) -> Result<Vec<Box<Ident>>, Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.list_keys(scope)?)
                        }
                    )*
                }
            }

            pub fn list_scopes(&mut self) -> Result<Vec<Box<Ident>>, Error> {
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
                &mut self, scope: Option<&Ident>, key: &Ident, value: &T
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.store(scope, key, value)?)
                        }
                    )*
                }
            }

            pub fn move_value(
                &mut self,
                from_scope: Option<&Ident>, from_key: &Ident,
                to_scope: Option<&Ident>, to_key: &Ident,
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.move_value(
                                from_scope, from_key, to_scope, to_key
                            )?)
                        }
                    )*
                }
            }

            pub fn move_scope(
                &mut self, from: &Ident, to: &Ident,
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.move_scope(from, to)?)
                        }
                    )*
                }
            }

            pub fn delete(
                &mut self, scope: Option<&Ident>, key: &Ident
            ) -> Result<(), Error> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            Ok(inner.delete(scope, key)?)
                        }
                    )*
                }
            }

            pub fn delete_scope(
                &mut self, scope: &Ident
            ) -> Result<(), Error> {
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


        //------------ StorageUri --------------------------------------------

        #[derive(Clone, Debug, PartialEq)]
        pub struct StorageUri(UriInner);

        #[derive(Clone, Debug, PartialEq)]
        enum UriInner {
            $(
                $variant(self::$module::Uri),
            )*
        }

        impl StorageUri {
            pub fn memory(seed: Option<u64>) -> Self {
                Self(UriInner::Memory(self::memory::Uri::new(seed)))
            }

            pub fn disk(path: PathBuf) -> Self {
                Self(UriInner::Disk(self::disk::Uri::new(path)))
            }

            pub fn data_dir(&self) -> Option<&Path> {
                if let UriInner::Disk(inner) = &self.0 {
                    Some(inner.path())
                }
                else {
                    None
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for StorageUri {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D
            ) -> Result<Self, D::Error> {
                Self::from_str(&String::deserialize(deserializer)?).map_err(
                    serde::de::Error::custom
                )
            }
        }

        impl FromStr for StorageUri {
            type Err = ParseStorageUriError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match Url::parse(s) {
                    Ok(url) => {
                        $(
                            if let Some(res) =
                                self::$module::Uri::parse_uri(&url)?
                            {
                                return Ok(StorageUri(UriInner::$variant(res)))
                            }
                        )*

                        Err(ParseStorageUriError(
                            UriErrorInner::UnknownScheme(
                                url.scheme().into()
                            )
                        ))
                    }
                    Err(_) => {
                        self::disk::Uri::parse_str(s).map(|disk| {
                            Self(UriInner::Disk(disk))
                        }).map_err(|err| {
                            ParseStorageUriError(UriErrorInner::Disk(err))
                        })
                    }
                }
            }
        }

        impl fmt::Display for StorageUri {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match &self.0 {
                    $(
                        UriInner::$variant(inner) => inner.fmt(f),
                    )*
                }
            }
        }


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

        impl error::Error for Error { }


        //------------ ParseStorageUriError ----------------------------------

        #[derive(Debug)]
        pub struct ParseStorageUriError(UriErrorInner);

        #[derive(Debug)]
        enum UriErrorInner {
            UnknownScheme(String),
            $(
                $variant(self::$module::UriError),
            )*
        }

        $(
            impl From<self::$module::UriError> for ParseStorageUriError {
                fn from(src: self::$module::UriError) -> Self {
                    Self(UriErrorInner::$variant(src))
                }
            }
        )*

        impl fmt::Display for ParseStorageUriError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match &self.0 {
                    UriErrorInner::UnknownScheme(scheme) => {
                        write!(f, "unknown scheme '{scheme}'")
                    }
                    $(
                        UriErrorInner::$variant(err) => err.fmt(f),
                    )*
                }
            }
        }

        impl error::Error for ParseStorageUriError { }
    }
}

store! {
    (Disk, disk)
    (Memory, memory)
}

