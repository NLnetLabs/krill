use std::{error, fmt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use url::Url;
use super::combined::{
    Error as SuperError,
    Transaction as SuperTransaction
};
use super::statements::{
    ManipulationStatement, QueryOneStatement, QueryOptStatement,
    QueryStatement,
};


//------------ Uri -----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Uri(UriInner);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum UriInner {
    Path(PathBuf),
    Memory,
}

impl Uri {
    pub fn parse_uri(uri: &Url) -> Result<Option<Self>, UriError> {
        if uri.scheme() == "memory" {
            if !uri.authority().is_empty() || !uri.path().is_empty() {
                return Err(UriError::InvalidMemory);
            }
            return Ok(Some(Uri(UriInner::Memory)))
        }
        if uri.scheme() == "sqlite" {
            if !uri.authority().is_empty() {
                return Err(UriError::HasAuthority(uri.authority().into()))
            }
            let path = PathBuf::from(uri.path());
            if !path.is_absolute() {
                return Err(UriError::RelativePath(path))
            }
            return Ok(Some(Uri(UriInner::Path(path))))
        }
        return Ok(None)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            UriInner::Path(path) => {
                write!(f, "sqlite://{}", path.display())
            }
            UriInner::Memory => {
                f.write_str("memory://")
            }
        }
    }
}


//------------ System --------------------------------------------------------

#[derive(Debug)]
pub struct System {
    stores: Mutex<HashMap<Uri, Store>>,
}

impl System {
    pub fn new(_tokio: &tokio::runtime::Handle) -> Self {
        Self {
            stores: Default::default()
        }
    }

    pub fn open(&self, uri: &Uri) -> Result<Store, Error> {
        let mut stores = self.stores.lock().expect("poisoned lock");

        // Since this basically only happens at start-up, the extra clone here
        // doesn’t really hurt.
        Ok(stores.entry(uri.clone()).or_insert_with(|| {
            Store::new(uri.clone())
        }).clone())
    }
}


//------------ Store ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Store(Arc<StoreInner>); 

#[derive(Debug)]
struct StoreInner {
    /// The URL of the store’s location.
    uri: Uri,

    /// A pool of clients for this store.
    ///
    /// This simply keeps clients for the same database when we are done with
    /// them so we can reuse them later.
    client_pool: Mutex<Vec<Client>>,
}

impl Store {
    fn new(uri: Uri) -> Self {
        Self(Arc::new(
            StoreInner {
                uri,
                client_pool: Default::default()
            }
        ))
    }

    pub fn execute<F, T>(
        &self, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let mut client = self.get_client()?;
        let res = client.execute(op);
        self.pool_client(client);
        res
    }

    fn get_client(&self) -> Result<Client, Error> {
        if let Some(client) = self.0.client_pool.lock().expect(
            "poisoned lock"
        ).pop() {
            return Ok(client)
        }

        Client::new(&self.0.uri)
    }

    fn pool_client(&self, client: Client) {
        self.0.client_pool.lock().expect("poisoned lock").push(client);
    }
}


//------------ Client --------------------------------------------------------

#[derive(Debug)]
struct Client {
    connection: rusqlite::Connection,
}

impl Client {
    fn new(uri: &Uri) -> Result<Self, Error> {
        let connection = match &uri.0 {
            UriInner::Path(path) => {
                rusqlite::Connection::open(path)?
            }
            UriInner::Memory => {
                rusqlite::Connection::open_in_memory()?
            }
        };
        Ok(Client { connection })
    }

    fn execute<F, T>(&mut self, op: F) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let mut transaction = self.transaction()?.into();
        let res = op(&mut transaction)?;
        if let Ok(transaction) = Transaction::try_from(transaction) {
            transaction.commit()?;
        };
        Ok(res)
    }

    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction {
            db: self.connection.transaction()?,
        })
    }
}


//------------ Transaction ---------------------------------------------------

#[derive(Debug)]
pub struct Transaction<'a> {
    db: rusqlite::Transaction<'a>,
}


impl<'a> Transaction<'a> {
    pub fn manipulate<S: ManipulationStatement>(
        &mut self, params: S::Params
    ) -> Result<u64, SuperError> {
        let mut statement = self.db.prepare_cached(S::SQLITE_QUERY)?;
        Ok(statement.execute(params).map(|res| {
            res.try_into().unwrap_or(u64::MAX)
        })?)
    }

    pub fn query<S: QueryStatement>(
        &mut self, params: S::Params
    ) -> Result<Vec<S::Row>, SuperError> {
        let mut statement = self.db.prepare_cached(S::SQLITE_QUERY)?;
        statement.query_map(
            params,
            |row| Ok(S::sqlite_row(row))
        )?.try_fold(
            Vec::new(),
            |mut vec, row| {
                let row = row??;
                if let Some(row) = row {
                    vec.push(row);
                }
                Ok(vec)
            }
        )
    }

    pub fn query_one<S: QueryOneStatement>(
        &mut self, params: S::Params
    ) -> Result<S::Row, SuperError> {
        let mut statement = self.db.prepare_cached(S::SQLITE_QUERY)?;
        Ok(statement.query_one(params, |row| Ok(S::sqlite_row(row)))??)
    }

    pub fn query_opt<S: QueryOptStatement>(
        &mut self, params: S::Params
    ) -> Result<Option<S::Row>, SuperError> {
        let mut statement = self.db.prepare_cached(S::SQLITE_QUERY)?;
        match statement.query_one(params, |row| Ok(S::sqlite_row(row))) {
            Ok(Ok(some)) => Ok(Some(some)),
            Ok(Err(err)) => Err(err.into()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into())
        }
    }

    fn commit(self) -> Result<(), Error> {
        Ok(self.db.commit()?)
    }
}


//------------ UriError ------------------------------------------------------

#[derive(Debug)]
pub enum UriError {
    HasAuthority(String),
    MissingPath,
    RelativePath(PathBuf),
    InvalidMemory,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HasAuthority(host) => {
                write!(f, "non-local path with host '{host}'")
            }
            Self::MissingPath => {
                write!(f, "missing path")
            }
            Self::RelativePath(path) => {
                write!(f, "{} is not absolute.", path.display())
            }
            Self::InvalidMemory => {
                f.write_str("invalid memory: URI")
            }
        }
    }
}

impl error::Error for UriError { }


//------------ Other Error Types ---------------------------------------------

pub type Error = rusqlite::Error;
pub type ExecuteError = rusqlite::Error;

