//! Traits for implementing statements on different backends.

use std::{error, fmt};
use super::disk::{DiskStore, Error as DiskError};
use super::combined::StoreError;


//============ Statement Traits ==============================================

//------------ Statement -----------------------------------------------------

/// A storage access statement.
///
/// This trait contains the parts that are common to all statements: Convert
/// the parameters into the query definition.
///
/// The trait provides the parameter list as an associated type.
///
/// For the database backends, it also provides the SQL query string to use
/// for the query.
///
/// For the file backend, it provides a way to convert the parameter list
/// into a file system path.
pub trait Statement: 'static {
    type Params<'a>: Params<'a>;

    /// The SQL query string for the PostgreSQL backend.
    ///
    /// Use the placeholders `$1`, `$2`, and so on for the parameters.
    const PSQL_QUERY: &'static str;

    /// The SQL query string for the SQLite backend.
    ///
    /// Use the placeholders `?1`, `?2`, and so on for the parameters.
    const SQLITE_QUERY: &'static str;
}


//------------ ManipulationStatement -----------------------------------------

/// A storage access statement with no expected result.
///
/// When executed on a database backend, the statement will be run based on
/// the parameter list and the number of affected rows will be returned.
///
/// When executed on the file backend, the method [`file_execute`] will be
/// run with the file path determined from the parameters.
pub trait ManipulationStatement: Statement {
    fn run_disk<'a>(
        params: Self::Params<'a>, store: &mut DiskStore
    ) -> Result<u64, DiskError>;
}


//------------ QueryStatement ------------------------------------------------

/// A storage access statement that returns a sequence of rows.
///
/// The type of each row returned is provided via the associated type `Row`.
/// How each backends row type is convered to this returned row type needs
/// to be implemented.
pub trait QueryStatement: Statement {
    /// The type returned for each row.
    type Row;

    /// Converts a PostgreSQL row into a statement row.
    ///
    /// The imoplementation can decide to ignore a row by returning `None`.
    fn psql_row(
        row: tokio_postgres::Row
    ) -> Result<Option<Self::Row>, StatementError>;

    /// Converts a SQLite row into a statement row.
    ///
    /// The imoplementation can decide to ignore a row by returning `None`.
    fn sqlite_row(
        row: &rusqlite::Row
    ) -> Result<Option<Self::Row>, StatementError>;

    fn run_disk<'a>(
        params: Self::Params<'a>, store: &mut DiskStore
    ) -> Result<Vec<Self::Row>, DiskError>;
}


//------------ QueryOneStatement ---------------------------------------------

/// A storage access statement that returns exactly one row.
///
/// This is similar to [`QueryStatement`], but we expect the backend to return
/// exactly one row.
pub trait QueryOneStatement: Statement {
    /// The type of the returned row.
    type Row;

    /// Converts a PostgreSQL row into a statement row.
    fn psql_row(
        row: tokio_postgres::Row
    ) -> Result<Self::Row, StatementError>;

    /// Converts a SQLite row into a statement row.
    fn sqlite_row(
        row: &rusqlite::Row
    ) -> Result<Self::Row, StatementError>;

    fn run_disk<'a>(
        params: Self::Params<'a>, store: &mut DiskStore
    ) -> Result<Self::Row, DiskError>;
}


//------------ QueryOptStatement ---------------------------------------------

/// A storage access statement that returns one row optional row.
///
/// This is similar to [`QueryOneStatement`], but the queried for row not
/// existing is not an error.
pub trait QueryOptStatement: Statement {
    /// The type of the returned row.
    type Row;

    /// Converts a PostgreSQL row into a statement row.
    fn psql_row(
        row: tokio_postgres::Row
    ) -> Result<Self::Row, StatementError>;

    /// Converts a SQLite row into a statement row.
    fn sqlite_row(
        row: &rusqlite::Row
    ) -> Result<Self::Row, StatementError>;

    fn run_disk<'a>(
        params: Self::Params<'a>, store: &mut DiskStore
    ) -> Result<Option<Self::Row>, DiskError>;
}


//------------ Schema --------------------------------------------------------

/// A type that can initialize a store.
///
/// An implementation of this trait knows how to prepare the backend for
/// support for a certain store. For the database backends this means
/// creating all the tables and indexes and the file systems backend create
/// directories.
///
/// Note that the various methods should be prepared with the backend
/// already having been initialized.
///
/// Note further that the trait is currently `pub(crate)` due to the use of
/// an async trait method for the PostgreSQL backend.
#[allow(dead_code)] // XXX TODO
pub(crate) trait Schema {
    async fn psql_init(
        transaction: &mut tokio_postgres::Transaction
    ) -> Result<(), StoreError>;
}


//============ Helper Traits =================================================

//------------ Params --------------------------------------------------------

/// The input parameters for a statement.
///
/// This trait is a helper trait that is implemented for generic tuples that
/// converts them into types supported by the database backends.
///
/// As long as you just stick to tuples of types supported by both
/// [tokio_postgres] and [rusqlite], you don’t need to worry about this
/// trait.
pub trait Params<'a>: rusqlite::Params {
    /// The type for [tokio_postgres].
    ///
    /// We are using arrays of trait objects. Ideally we’d just provide the
    /// array length as a associated constant, but we are not allowed to use
    /// that in a return type definition, so we need to specify the actual
    /// type as an associated type.
    type PsqlParams<'p>:
        AsRef<[&'p (dyn tokio_postgres::types::ToSql + Sync)]>
        where Self: 'p;

    /// Returns the [tokio_postgres] parameters.
    fn as_psql(&self) -> Self::PsqlParams<'_>;
}

impl<'a, A: ToSql + 'a, B: ToSql + 'a> Params<'a> for (A, B) {
    type PsqlParams<'p> = [&'p (dyn tokio_postgres::types::ToSql + Sync); 2]
        where A: 'p, B: 'p;

    fn as_psql(&self) -> Self::PsqlParams<'_> {
        [&self.0, &self.1]
    }
}

impl<'a, A, B, C> Params<'a> for (A, B, C)
where A: ToSql + 'a, B: ToSql + 'a, C: ToSql + 'a
{
    type PsqlParams<'p> = [&'p (dyn tokio_postgres::types::ToSql + Sync); 3]
        where A: 'p, B: 'p, C: 'p;

    fn as_psql(&self) -> Self::PsqlParams<'_> {
        [&self.0, &self.1, &self.2]
    }
}


//------------ ToSql ---------------------------------------------------------

/// The `ToSql` traits of all database backends.
///
/// This trait is only here to shorten definitions.
pub trait ToSql:
    tokio_postgres::types::ToSql + rusqlite::types::ToSql + Sync
{ }

impl<T: tokio_postgres::types::ToSql + rusqlite::types::ToSql + Sync> ToSql
    for T
{ }


//============ Error Types ===================================================

//------------ StatementError ------------------------------------------------

/// An error happened when processing a statement.
#[derive(Debug)]
pub struct StatementError(Box<dyn error::Error>);

impl StatementError {
    pub fn custom(src: impl Into<Box<dyn error::Error>>) -> Self {
        Self(src.into())
    }
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for StatementError { }

