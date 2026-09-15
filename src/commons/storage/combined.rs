use std::{error, fmt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::runtime;
use url::Url;
use super::statements::{
    ManipulationStatement, QueryOneStatement, QueryOptStatement,
    QueryStatement, Schema, StatementError,
};


macro_rules! store {
    ( $( ( $variant:ident, $module:ident ) )* ) => {

        //------------ StorageUri --------------------------------------------

        /// The address of a storage location.
        #[derive(Clone, Debug, PartialEq)]
        pub struct StorageUri(UriInner);

        #[derive(Clone, Debug, PartialEq)]
        enum UriInner {
            $(
                $variant(super::$module::Uri),
            )*
        }

        impl StorageUri {
            pub fn memory() -> Self {
                Self(UriInner::Sqlite(super::sqlite::Uri::memory()))
            }

            pub fn disk(path: impl Into<PathBuf>) -> Self {
                Self(UriInner::Disk(super::disk::Uri::new(path.into())))
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
                                super::$module::Uri::parse_uri(&url)?
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
                        super::disk::Uri::parse_str(s).map(|disk| {
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


        //------------ StorageSystem -----------------------------------------

        /// System-wide information about the storage sub-system.
        #[derive(Debug)]
        pub struct StorageSystem {
            /// The storage URI to be used by default.
            default_uri: StorageUri,

            $(
                $module: Option<super::$module::System>,
            )*
        }

        impl StorageSystem {
            /// Creates a new storage system.
            ///
            /// The provided URI will be used as the default storage URI.
            pub fn new(
                default_uri: StorageUri,
                tokio: &runtime::Handle,
            ) -> Self {
                Self {
                    default_uri,
                    $(
                        $module: Some(super::$module::System::new(tokio)),
                    )*
                }
            }

            /// Creates a storage system for test usage only.
            ///
            /// This will only provide the disk and SQLite backends.
            ///
            /// The default URI will be the memory store.
            #[cfg(test)]
            pub fn new_test() -> Self {
                Self {
                    default_uri: StorageUri::memory(),
                    $(
                        $module: super::$module::System::new_test(),
                    )*
                }
            }

            /// Creates a new disk storage system using the given path.
            pub fn new_disk(
                path: impl Into<PathBuf>,
                tokio: &runtime::Handle,
            ) -> Self {
                Self::new(StorageUri::disk(path), tokio)
            }

            /// Opens the default store.
            pub fn open(
                &self,
            ) -> Result<Store, StoreError> {
                self.open_uri(&self.default_uri)
            }

            /// Opens the store for the given storage URI.
            pub fn open_uri(
                &self, uri: &StorageUri
            ) -> Result<Store, StoreError> {
                match &uri.0 {
                    $(
                        UriInner::$variant(inner) => {
                            if let Some(system) = self.$module.as_ref() {
                                Ok(Store(StoreInner::$variant(
                                    system.open(inner)?
                                )))
                            }
                            else {
                                Err(StoreError::other(
                                    "storage backend not available"
                                ))
                            }
                        }
                    )*
                }
            }

            /// Returns the default URI of the storage system.
            pub fn default_uri(&self) -> &StorageUri {
                &self.default_uri
            }
        }


        //------------ Store -------------------------------------------------

        #[derive(Clone, Debug)]
        pub struct Store(StoreInner);

        #[derive(Clone, Debug)]
        enum StoreInner {
            $(
                $variant(super::$module::Store),
            )*
        }

        impl Store {
            pub(crate) fn init<S: Schema>(
                &mut self, schema: S
            ) -> Result<(), StoreError> {
                match &mut self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            inner.init(schema)
                        }
                    )*
                }
            }

            pub fn execute<F, T, E>(&self, op: F) -> Result<T, E>
            where
                F: for<'a> Fn(&mut Transaction<'a>) -> Result<T, E>,
                E: From<StoreError>,
            {
                match &self.0 {
                    $(
                        StoreInner::$variant(inner) => {
                            inner.execute(op)
                        }
                    )*
                }
            }
        }


        //------------ Transaction -------------------------------------------
    
        /// A single transaction on a storage connection.
        #[derive(Debug)]
        pub struct Transaction<'a>(TransactionInner<'a>);

        #[derive(Debug)]
        enum TransactionInner<'a> {
            $(
                $variant(super::$module::Transaction<'a>),
            )*
        }

        $(
            impl<'a> From<super::$module::Transaction<'a>>
            for Transaction<'a> {
                fn from(
                    src: super::$module::Transaction<'a>
                ) -> Self {
                    Self(TransactionInner::$variant(src))
                }
            }

            impl<'a> TryFrom<Transaction<'a>>
            for super::$module::Transaction<'a> {
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

        impl<'a> Transaction<'a> {
            pub fn manipulate<S: ManipulationStatement>(
                &mut self, params: S::Params<'_>
            ) -> Result<u64, StoreError> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            inner.manipulate::<S>(params)
                        }
                    )*
                }
            }

            pub fn query<'p, S: QueryStatement>(
                &mut self, params: S::Params<'_>,
            ) -> Result<Vec<S::Row>, StoreError> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            inner.query::<S>(params)
                        }
                    )*
                }
            }

            pub fn query_one<S: QueryOneStatement>(
                &mut self, params: S::Params<'_>
            ) -> Result<S::Row, StoreError> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            inner.query_one::<S>(params)
                        }
                    )*
                }
            }

            pub fn query_opt<S: QueryOptStatement>(
                &mut self, params: S::Params<'_>
            ) -> Result<Option<S::Row>, StoreError> {
                match &mut self.0 {
                    $(
                        TransactionInner::$variant(inner) => {
                            inner.query_opt::<S>(params)
                        }
                    )*
                }
            }
        }


        //------------ StoreError --------------------------------------------

        #[derive(Debug)]
        pub struct StoreError(ErrorInner);

        #[derive(Debug)]
        enum ErrorInner {
            $(
                $variant(super::$module::Error),
            )*
            Statement(StatementError),
            Other(Box<dyn error::Error + Send + Sync>),
        }

        $(
            impl From<super::$module::Error> for StoreError {
                fn from(src: super::$module::Error) -> Self {
                    Self(ErrorInner::$variant(src))
                }
            }
        )*

        impl StoreError {
            pub fn other(
                src: impl Into<Box<dyn error::Error + Send + Sync>>
            ) -> Self {
                Self(ErrorInner::Other(src.into()))
            }
        }

        impl From<StatementError> for StoreError {
            fn from(src: StatementError) -> Self {
                Self(ErrorInner::Statement(src))
            }
        }

        impl fmt::Display for StoreError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match &self.0 {
                    $(
                        ErrorInner::$variant(inner) => inner.fmt(f),
                    )*
                    ErrorInner::Statement(inner) => inner.fmt(f),
                    ErrorInner::Other(inner) => inner.fmt(f),
                }
            }
        }

        impl error::Error for StoreError { }


        //------------ ParseStorageUriError ----------------------------------

        #[derive(Debug)]
        pub struct ParseStorageUriError(UriErrorInner);

        #[derive(Debug)]
        enum UriErrorInner {
            UnknownScheme(String),
            $(
                $variant(super::$module::UriError),
            )*
        }

        $(
            impl From<super::$module::UriError> for ParseStorageUriError {
                fn from(src: super::$module::UriError) -> Self {
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
    (PSql, psql)
    (Sqlite, sqlite)
    (Disk, disk)
}

