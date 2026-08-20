use std::fmt;
use std::any::TypeId;
use std::collections::hash_map;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use futures_util::TryStreamExt;
use tokio::runtime;
use url::Url;
use super::combined::{
    StoreError,
    Transaction as SuperTransaction
};
use super::statements::{
    ManipulationStatement, Params, QueryOneStatement, QueryOptStatement,
    QueryStatement, Statement
};


//------------ Uri -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    uri: Url,
    config: tokio_postgres::Config,
}

impl Uri {
    fn new(uri: Url, config: tokio_postgres::Config)-> Self {
        Self { uri, config }
    }

    pub fn parse_uri(uri: &Url) -> Result<Option<Uri>, UriError> {
        if uri.scheme() != "postgres" && uri.scheme() != "postresql" {
            return Ok(None)
        }
        let config = tokio_postgres::Config::from_str(uri.as_str())?;
        Ok(Some(Self::new(uri.clone(), config)))
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.uri.fmt(f)
    }
}


//------------ System --------------------------------------------------------

#[derive(Debug)]
pub struct System {
    tokio: runtime::Handle,

    stores: Mutex<HashMap<Url, Store>>,
}

impl System {
    pub fn new(tokio: &runtime::Handle) -> Self {
        Self {
            tokio: tokio.clone(),
            stores: Default::default()
        }
    }

    pub fn open(&self, uri: &Uri) -> Result<Store, Error> {
        let mut stores = self.stores.lock().expect("poisoned lock");

        // Since this basically only happens at start-up, the extra clone here
        // doesn’t really hurt.
        Ok(stores.entry(uri.uri.clone()).or_insert_with(|| {
            Store::new(uri.config.clone(), self.tokio.clone())
        }).clone())
    }
}


//------------ Store ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Store(Arc<StoreInner>); 

#[derive(Debug)]
struct StoreInner {
    /// The configuration for connecting to the location.
    config: tokio_postgres::Config,

    /// The Tokio runtime to execute queries on.
    tokio: runtime::Handle,

    /// A pool of clients for this store.
    ///
    /// This simply keeps clients for the same database when we are done with
    /// them so we can reuse them later.
    client_pool: Mutex<Vec<Client>>,
}

impl Store {
    fn new(
        config: tokio_postgres::Config, tokio: runtime::Handle
    ) -> Self {
        Self(Arc::new(StoreInner {
            config, tokio,
            client_pool: Default::default(),
        }))
    }

    pub fn execute<F, T>(
        &self, op: F
    ) -> Result<T, StoreError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, StoreError>
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
            if !client.is_closed() {
                return Ok(client)
            }
        }

        Client::new(&self.0.config, self.0.tokio.clone())
    }

    fn pool_client(&self, client: Client) {
        self.0.client_pool.lock().expect("poisoned lock").push(client);
    }
}


//------------ Client --------------------------------------------------------

#[derive(Debug)]
struct Client {
    client: tokio_postgres::Client,
    statements: HashMap<TypeId, tokio_postgres::Statement>,
    tokio: runtime::Handle,
}

impl Client {
    fn new(
        config: &tokio_postgres::Config,
        tokio: runtime::Handle
    ) -> Result<Self, Error> {
        let client = tokio.block_on(async {
            // TODO: TLS support? That would need configuration.
            let (client, connection) = config.connect(
                tokio_postgres::NoTls
            ).await?;
            let _ = tokio::spawn(connection);
            Ok(client)
        })?;
        Ok(Self {
            client,
            statements: HashMap::new(),
            tokio,
        })
    }

    fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    fn execute<F, T>(&mut self, op: F) -> Result<T, StoreError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, StoreError>
    {
        let mut transaction = self.transaction()?.into();
        let res = op(&mut transaction)?;
        if let Ok(transaction) = Transaction::try_from(transaction) {
            transaction.commit()?;
        };
        Ok(res)
    }

    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        let transaction = self.tokio.block_on(async {
            self.client.transaction().await
        })?;
        Ok(Transaction {
            db: transaction,
            statements: &mut self.statements,
            tokio: &self.tokio,
        })
    }
}


//------------ Transaction ---------------------------------------------------

pub struct Transaction<'a> {
    db: tokio_postgres::Transaction<'a>,
    statements: &'a mut HashMap<TypeId, tokio_postgres::Statement>,
    tokio: &'a runtime::Handle,
}

impl<'a> Transaction<'a> {
    pub fn manipulate<S: ManipulationStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<u64, StoreError> {
        self.tokio.block_on(async {
            let statement = Self::get_statement::<S>(
                &self.db, self.statements
            ).await?;
            Ok(self.db.execute(
                statement, params.as_psql().as_ref()
            ).await?)
        })
    }

    pub fn query<S: QueryStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<Vec<S::Row>, StoreError> {
        self.tokio.block_on(async {
            let statement = Self::get_statement::<S>(
                &self.db, self.statements
            ).await?;
            self.db.query_raw(
                statement, params.as_psql().as_ref().iter().copied()
            ).await?.map_err(
                StoreError::from
            ).try_filter_map(async move |row| {
                Ok(S::psql_row(row)?)
            }).try_collect::<Vec<_>>().await
        })
    }

    pub fn query_one<S: QueryOneStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<S::Row, StoreError> {
        self.tokio.block_on(async {
            let statement = Self::get_statement::<S>(
                &self.db, self.statements
            ).await?;
            self.db.query_one(
                statement, params.as_psql().as_ref()
            ).await.map_err(StoreError::from).and_then(|row| {
                Ok(S::psql_row(row)?)
            })
        })
    }

    pub fn query_opt<S: QueryOptStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<Option<S::Row>, StoreError> {
        self.tokio.block_on(async {
            let statement = Self::get_statement::<S>(
                &self.db, self.statements
            ).await?;
            self.db.query_opt(
                statement, params.as_psql().as_ref()
            ).await.map_err(StoreError::from).and_then(|opt_row| {
                match opt_row {
                    Some(row) => Ok(Some(S::psql_row(row)?)),
                    None => Ok(None)
                }
            })
        })
    }

    async fn get_statement<'s, S: Statement>(
        db: &tokio_postgres::Transaction<'_>,
        statements: &'s mut HashMap<TypeId, tokio_postgres::Statement>,
    ) -> Result<&'s tokio_postgres::Statement, Error> {
        match statements.entry(TypeId::of::<S>()) {
            hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            hash_map::Entry::Vacant(entry) => {
                let value = db.prepare(S::PSQL_QUERY).await?;
                Ok(entry.insert(value))
            }
        }
    }

    fn commit(self) -> Result<(), Error> {
        self.tokio.block_on(async {
            self.db.commit().await
        })
    }
}

impl<'a> fmt::Debug for Transaction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Transaction(...)")
    }
}


//------------ Error Types ---------------------------------------------------

pub type Error = tokio_postgres::Error;
pub type ExecuteError = tokio_postgres::Error;
pub type UriError = tokio_postgres::Error;

