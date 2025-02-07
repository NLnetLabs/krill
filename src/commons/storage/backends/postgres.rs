//! Storage uses a PostgreSQL database.
#![allow(dead_code)]
#![cfg(feature = "postgres")]

use std::{error, fmt, thread};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use bytes::BytesMut;
use postgres::{IsolationLevel, NoTls};
use postgres::types::{FromSql, IsNull, ToSql, Type};
use r2d2::{ManageConnection, Pool};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use url::Url;
use crate::commons::storage::{
    Key, Namespace, NamespaceBuf, Scope, Segment, SegmentBuf,
};
use super::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ Configuration -------------------------------------------------

const LOCK_TIMEOUT: Duration = Duration::from_secs(120);


//------------ Store ---------------------------------------------------------

/// A storage backend using a PostgreSQL database.
#[derive(Debug)]
pub struct Store {
    namespace: NamespaceBuf,
    executor: Pool<ConnectionManager>,
    timeouts: mpsc::Sender<TimeoutCommand>,
    ticket: AtomicU32,
}

impl Store {
    pub fn from_uri(
        uri: &Url, namespace: &Namespace
    ) -> Result<Option<Self>, Error> {
        if uri.scheme() != "postgresql" {
            return Ok(None)
        }

        let manager = ConnectionManager::new(uri)?;
        let pool = r2d2::Pool::new(manager)?;

        Ok(Some(Self {
            namespace: namespace.into(),
            executor: pool,
            timeouts: run_timeout_thread(),
            ticket: AtomicU32::new(0),
        }))
    }

    pub fn init(&self) -> Result<(), Error> {
        let mut client = self.executor.get()?;
        client.psql.execute("DROP TABLE IF EXISTS store", &[])?;
        client.psql.execute(
            r##"CREATE TABLE store (
                "namespace" VARCHAR NOT NULL,
                "scope" TEXT[] NOT NULL,
                "key" VARCHAR NOT NULL,
                "value" JSONB NOT NULL,
                PRIMARY KEY("namespace", "scope", "key")
            )"##,
            &[]
        )?;
        client.psql.execute("DROP TABLE IF EXISTS locks", &[])?;
        client.psql.execute(
            r##"CREATE TABLE locks (
                "namespace" VARCHAR NOT NULL,
                "scope" TEXT[] NOT NULL,
                PRIMARY KEY("namespace", "scope")
            )"##,
            &[]
        )?;
        Ok(())
    }

    pub fn execute<F, T>(
        &self, scope: &Scope, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let mut client = self.executor.get()?;

        // Register the timeout.
        let ticket = self.ticket.fetch_add(1, Ordering::SeqCst);
        self.timeouts.send(TimeoutCommand::Timeout(Timeout {
            token: client.psql.cancel_token(),
            discard: client.discard.clone(),
            ticket
        })).map_err(|_| Error::LostTimeoutThread)?;

        let res = (|| {
            let mut tran = client.psql.build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start().map_err(Error::from)?;

            // Lock the locks table.
            tran.execute(
                "LOCK TABLE locks IN ROW EXCLUSIVE MODE",
                &[]
            )?;

            // Insert the scope into the locks table. This will hang if the
            // row already exists.
            tran.execute(
                "INSERT INTO locks (namespace, scope) VALUES ($1, $2)",
                &[&self.namespace.as_ref(), scope],
            )?;

            // Now run the closure.
            //
            // If it returns an error, we roll back (just to be sure) and
            // return.
            let tran = Transaction {
                namespace: &self.namespace,
                transaction: tran,
            };
            let mut tran = SuperTransaction::from(tran);
            let res = match op(&mut tran) {
                Ok(res) => res,
                Err(err) => {
                    if let Ok(tran) = Transaction::try_from(tran) {
                        tran.transaction.rollback()?;
                    }
                    return Err(err)
                }
            };

            // Remove the scope from the locks table.
            if let Ok(mut tran) = Transaction::try_from(tran) {
                tran.transaction.execute(
                    "DELETE FROM locks WHERE namespace = $1 and scope = $2",
                    &[&self.namespace.as_ref(), scope],
                )?;

                tran.transaction.commit()?;
            }

            Ok(res)
        })();

        self.timeouts.send(
            TimeoutCommand::Cancel(ticket)
        ).map_err(|_| Error::LostTimeoutThread)?;

        res
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(
            self.executor.get()?.psql.query_opt(
                "SELECT DISTINCT namespace FROM store WHERE namespace = $1",
                &[&self.namespace.as_ref()],
            )?
            .is_none()
        )
    }

    pub fn get_any(&self, key: &Key) -> Result<Option<Value>, Error> {
        Ok(
            self.executor.get()?.psql.query_opt(
                "SELECT value FROM store \
                 WHERE namespace = $1 AND scope = $2 AND key = $3",
                &[&self.namespace.as_ref(), key.scope(), &key.name()],
            )?
            .and_then(|row| row.get(0))
        )
    }

    pub fn store_any(
        &self, key: &Key, value: &Value
    ) -> Result<(), Error> {
        self.executor.get()?.psql.execute(
            "INSERT INTO store (namespace, scope, key, value) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (namespace, scope, key) \
             DO UPDATE SET value = $4",
            &[&self.namespace.as_ref(), key.scope(), &key.name(), value],
        )?;
        Ok(())
    }

    pub fn migrate_namespace(
        &mut self, to: &Namespace
    ) -> Result<(), Error> {
        let mut client = self.executor.get()?;
        let mut transaction = client.psql.transaction()?;
        transaction.execute(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", &[]
        )?;

        if transaction.query_opt(
            "SELECT DISTINCT namespace FROM store WHERE namespace = $1",
            &[&self.namespace.as_ref()],
        )?.is_none() {
            transaction.rollback()?; // make sure transaction is finished
            return Err(Error::NamespaceMigration(format!(
                "original namespace {} not found in database",
                &self.namespace
            )));
        }

        if transaction.query_opt(
            "SELECT DISTINCT namespace FROM store WHERE namespace = $1",
            &[&to],
        )?.is_some() {
            transaction.rollback()?; // make sure transaction is finished
            return Err(Error::NamespaceMigration(format!(
                "target namespace {} already exists in database",
                &self.namespace
            )));
        }

        transaction.execute(
            "UPDATE store SET namespace = $2 WHERE namespace = $1",
            &[&self.namespace.as_ref(), &to],
        )?;
        transaction.commit()?;

        self.namespace = to.into();

        Ok(())
    }
}


//------------ Transaction ---------------------------------------------------

pub struct Transaction<'a> {
    namespace: &'a Namespace,
    transaction: postgres::Transaction<'a>,
}


/// # Reading
///
impl Transaction<'_> {
    pub fn has(&mut self, key: &Key) -> Result<bool, Error> {
        Ok(
            self.transaction.query_opt(
                "SELECT 1 FROM store WHERE \
                    namespace = $1 AND scope = $2 AND key = $3",
                &[&self.namespace, key.scope(), &key.name()],
            )?.is_some()
        )
    }

    pub fn has_scope(&mut self, scope: &Scope) -> Result<bool, Error> {
        // XXX Is there a reason why the length is an i32?
        Ok(
            self.transaction.query_opt(
                "SELECT DISTINCT scope FROM store WHERE \
                    namespace = $1 AND scope[:$3] = $2",
                &[&self.namespace, scope, &(scope.len() as i32)],
            )?.is_some()
        )
    }

    pub fn get<T: DeserializeOwned>(
        &mut self, key: &Key
    ) -> Result<Option<T>, Error> {
        let res = match self.get_any(key)? {
            Some(res) => res,
            None => return Ok(None)
        };
        Ok(Some(
            serde_json::from_value(res).map_err(|err| {
                Error::deserialize(key.clone(), err)
            })?
        ))
    }

    fn get_any(&mut self, key: &Key) -> Result<Option<Value>, Error> {
        Ok(
            self.transaction.query_opt(
                "SELECT value FROM store \
                 WHERE namespace = $1 AND scope = $2 AND key = $3",
                &[&self.namespace, key.scope(), &key.name()],
            )?
            .and_then(|row| row.get(0))
        )
    }

    pub fn list_keys(
        &mut self, scope: &Scope
    ) -> Result<Vec<Key>, Error> {
        Ok(
            self.transaction.query(
                "SELECT scope, key FROM store  \
                 WHERE namespace = $1 AND scope[:$3] = $2",
                &[&self.namespace, scope, &(scope.len() as i32)],
            )?
            .into_iter()
            .map(|row| {
                let scope = Scope::new(row.get(0));
                let name: SegmentBuf = row.get(1);
                Key::new_scoped(scope, name)
            })
            .collect::<Vec<Key>>()
        )
    }

    pub fn list_scopes(&mut self) -> Result<Vec<Scope>, Error> {
        Ok(
            self.transaction.query(
                "SELECT DISTINCT scope FROM store WHERE namespace = $1",
                &[&self.namespace],
            )?
            .into_iter()
            .flat_map(|row| Scope::new(row.get(0)).sub_scopes())
            .collect::<Vec<Scope>>()
        )
    }
}


/// # Writing
impl Transaction<'_> {
    pub fn store<T: Serialize>(
        &mut self, key: &Key, value: &T
    ) -> Result<(), Error> {
        let value = serde_json::to_value(value).map_err(|err| {
            Error::serialize(key.clone(), err)
        })?;
        self.store_any(key, &value)
    }

    fn store_any(&mut self, key: &Key, value: &Value) -> Result<(), Error> {
        self.transaction.execute(
            "INSERT INTO store (namespace, scope, key, value) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (namespace, scope, key) \
             DO UPDATE SET value = $4",
            &[&self.namespace, key.scope(), &key.name(), value],
        )?;
        Ok(())
    }

    pub fn move_value(&mut self, from: &Key, to: &Key) -> Result<(), Error> {
        self.transaction.execute(
            "UPDATE store SET scope = $4, key = $5 \
             WHERE namespace = $1 AND scope = $2 AND key = $3",
            &[
                &self.namespace,
                from.scope(),
                &from.name(),
                to.scope(),
                &to.name(),
            ],
        )?;

        Ok(())
    }

    pub fn move_scope(
        &mut self, from: &Scope, to: &Scope
    ) -> Result<(), Error> {
        self.transaction.execute(
            "UPDATE store SET scope = $3 WHERE namespace = $1 AND scope = $2",
            &[&self.namespace, from, to],
        )?;

        Ok(())
    }

    pub fn delete(&mut self, key: &Key) -> Result<(), Error> {
        self.transaction.execute(
            "DELETE FROM store \
             WHERE namespace = $1 AND scope = $2 AND key = $3",
            &[&self.namespace, key.scope(), &key.name()],
        )?;

        Ok(())
    }

    pub fn delete_scope(&mut self, scope: &Scope) -> Result<(), Error> {
        self.transaction.execute(
            "DELETE FROM store WHERE namespace = $1 AND scope = $2",
            &[&self.namespace, &scope],
        )?;

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.transaction.execute(
            "DELETE FROM store WHERE namespace = $1", &[&self.namespace]
        )?;

        Ok(())
    }
}


//--- Debug

impl fmt::Debug for Transaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("namespace", &self.namespace)
            .finish()
    }
}


//------------ ConnectionManager ---------------------------------------------

#[derive(Debug)]
pub struct ConnectionManager {
    config: postgres::Config,
}

impl ConnectionManager {
    fn new(uri: &Url) -> Result<Self, postgres::Error> {
        Ok(Self {
            config: uri.as_str().parse()?,
        })
    }
}

impl ManageConnection for ConnectionManager {
    type Connection = Connection;
    type Error = postgres::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        Ok(Connection::new(self.config.connect(NoTls)?))
    }

    fn is_valid(
        &self, client: &mut Self::Connection
    ) -> Result<(), Self::Error> {
        client.psql.simple_query("").map(|_| ())
    }

    fn has_broken(
        &self, client: &mut Self::Connection
    ) -> bool {
        client.has_broken()
    }
}


//------------ Connection ----------------------------------------------------

pub struct Connection {
    psql: postgres::Client,
    discard: Arc<AtomicBool>,
}

impl Connection {
    fn new(psql: postgres::Client) -> Self {
        Self {
            psql,
            discard: AtomicBool::new(false).into(),
        }
    }

    fn has_broken(&self) -> bool {
        self.discard.load(Ordering::Relaxed) || self.psql.is_closed()
    }
}


//------------ Timeout Thread ------------------------------------------------

fn run_timeout_thread() -> mpsc::Sender<TimeoutCommand> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut commands = VecDeque::<(Instant, Timeout)>::new();

        loop {
            let cmd = if let Some((first, _)) = commands.front() {
                // We have at least one command, wait until it times out.
                // Gracefully deal with the command having a timeout in the
                // past.
                match first.checked_duration_since(Instant::now()) {
                    Some(duration) => rx.recv_timeout(duration),
                    None => rx.recv().map_err(Into::into),
                }
            }
            else {
                // No commands, wait forever.
                rx.recv().map_err(Into::into)
            };

            match cmd {
                Ok(TimeoutCommand::Timeout(cmd)) => {
                    commands.push_back((Instant::now() + LOCK_TIMEOUT, cmd));
                }
                Ok(TimeoutCommand::Cancel(ticket)) => {
                    commands.retain(|(_, cmd)| cmd.ticket != ticket);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check that the first command is indeed in the past.
                    if let Some((first, _)) = commands.front() {
                        if *first > Instant::now() {
                            continue
                        }
                    }

                    // Now cancel the first command.
                    if let Some((_, cmd)) = commands.pop_front() {
                        // XXX This failing should probably cause some kind of
                        //     major meltdown
                        let _ = cmd.token.cancel_query(NoTls);
                        cmd.discard.store(true, Ordering::Relaxed);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
    });

    tx
}


//------------ TimeoutCommand ------------------------------------------------

enum TimeoutCommand {
    Timeout(Timeout),
    Cancel(u32),
}

struct Timeout {
    token: postgres::CancelToken,
    discard: Arc<AtomicBool>,
    ticket: u32,
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Postgres(postgres::error::Error),
    R2D2(r2d2::Error),
    LostTimeoutThread,
    Deserialize {
        key: Key,
        err: String,
    },
    Serialize {
        key: Key,
        err: String,
    },
    NamespaceMigration(String),
}

impl Error {
    fn deserialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Deserialize { key, err: err.to_string() }
    }

    fn serialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Serialize { key, err: err.to_string() }
    }
}

impl From<postgres::error::Error> for Error {
    fn from(src: postgres::error::Error) -> Self {
        Self::Postgres(src)
    }
}

impl From<postgres::error::Error> for SuperError {
    fn from(src: postgres::error::Error) -> Self {
        Error::Postgres(src).into()
    }
}

impl From<r2d2::Error> for Error {
    fn from(src: r2d2::Error) -> Self {
        Self::R2D2(src)
    }
}

impl From<r2d2::Error> for SuperError {
    fn from(src: r2d2::Error) -> Self {
        Error::from(src).into()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Postgres(inner) => inner.fmt(f),
            Error::R2D2(inner) => inner.fmt(f),
            Error::LostTimeoutThread => {
                f.write_str("PostgreSQL storage’s lock thread ended")
            }
            Error::Deserialize { key, err } => {
                write!(f,
                    "failed to deserialize value for key '{}': {}",
                    key, err
                )
            }
            Error::Serialize { key, err } => {
                write!(f,
                    "failed to serialize value for key '{}': {}",
                    key, err
                )
            }
            Error::NamespaceMigration(inner) => inner.fmt(f)
        }
    }
}


//------------ FromSql/ToSql impls -------------------------------------------

//--- Namespace

impl ToSql for &Namespace {
    fn to_sql(
        &self, ty: &Type, out: &mut BytesMut
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql_checked(ty, out)
    }
}


//--- Segment

impl ToSql for &Segment {
    fn to_sql(
        &self, ty: &Type, out: &mut BytesMut
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql_checked(ty, out)
    }
}


//--- SegmentBuf

impl ToSql for SegmentBuf {
    fn to_sql(
        &self, ty: &Type, out: &mut BytesMut
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn error::Error + Sync + Send>> {
        self.as_str().to_sql_checked(ty, out)
    }
}

impl<'a> FromSql<'a> for SegmentBuf {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn error::Error + Sync + Send>> {
        Ok(SegmentBuf::try_from(String::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <String as FromSql<'a>>::accepts(ty)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "needs PostgreSQL installed locally"]
    fn locks() {
        let store = Store::from_uri(
            &Url::parse("postgresql:///test?host=/var/run/postgresql/").unwrap(),
            Namespace::parse("test").unwrap(),
        ).unwrap().unwrap();
        store.init().unwrap();
    }
}

