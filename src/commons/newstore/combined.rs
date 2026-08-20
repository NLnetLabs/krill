#![allow(unused)] // XXX TODO

use std::{error, fmt};
use tokio::runtime;
use super::statements::{
    ManipulationStatement, Params, QueryOneStatement, QueryOptStatement,
    QueryStatement, Statement, StatementError,
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


        //------------ System ------------------------------------------------

        /// System-wide information about the storage sub-system.
        #[derive(Debug)]
        pub struct System {
            $(
                $module: super::$module::System,
            )*
        }

        impl System {
            pub fn new(tokio: &runtime::Handle) -> Self {
                Self {
                    $(
                        $module: super::$module::System::new(tokio),
                    )*
                }
            }

            pub fn open(
                &self, uri: &StorageUri
            ) -> Result<Store, StoreError> {
                match &uri.0 {
                    $(
                        UriInner::$variant(inner) => {
                            Ok(Store(StoreInner::$variant(
                                self.$module.open(inner)?
                            )))
                        }
                    )*
                }
            }
        }


        //------------ Store -------------------------------------------------

        #[derive(Debug)]
        pub struct Store(StoreInner);

        #[derive(Debug)]
        enum StoreInner {
            $(
                $variant(super::$module::Store),
            )*
        }

        impl Store {
            pub fn execute<F, T>(&mut self, op: F) -> Result<T, StoreError>
            where
                F: for<'a> Fn(&mut Transaction<'a>) -> Result<T, StoreError>
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
        }

        $(
            impl From<super::$module::Error> for StoreError {
                fn from(src: super::$module::Error) -> Self {
                    Self(ErrorInner::$variant(src))
                }
            }
        )*

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

