//! Storage uses a PostgreSQL database.
#![allow(dead_code)]
#![cfg(feature = "postgres")]

use std::{error, fmt};
use bytes::BytesMut;
use postgres::{NoTls};
use postgres::types::{FromSql, IsNull, ToSql, Type};
use r2d2_postgres::r2d2;
use r2d2_postgres::PostgresConnectionManager;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use url::Url;
use crate::commons::storage::{
    Key, Namespace, NamespaceBuf, Scope, Segment, SegmentBuf,
};
use crate::commons::storage::store::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ Store ---------------------------------------------------------

/// A storage backend using a PostgreSQL database.
#[derive(Debug)]
pub struct Store {
    namespace: NamespaceBuf,
    executor: r2d2::Pool<PostgresConnectionManager<NoTls>>,
}

impl Store {
    pub fn from_uri(
        uri: &Url, namespace: &Namespace
    ) -> Result<Option<Self>, Error> {
        if uri.scheme() != "postgres" {
            return Ok(None)
        }

        let manager = PostgresConnectionManager::new(
            uri.as_str().parse().map_err(Error::Postgres)?,
            NoTls
        );
        let pool = r2d2::Pool::new(manager)?;

        Ok(Some(Self {
            namespace: namespace.into(),
            executor: pool,
        }))
    }

    pub fn execute<F, T>(
        &self, _scope: &Scope, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        const TRIES: usize = 10;
        let mut i = 0;

        loop {
            i += 1;
            let mut client = self.executor.get().map_err(Error::from)?;
            let mut tran = client.transaction().map_err(Error::from)?;
            tran.execute(
                "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", &[]
            ).map_err(Error::from)?;

            let tran = Transaction {
                namespace: &self.namespace,
                transaction: tran,
            };
            let mut tran = SuperTransaction::from(tran);
            match op(&mut tran) {
                Ok(res) => {
                    if let Ok(tran) = Transaction::try_from(tran) {
                        tran.transaction.commit().map_err(Error::from)?;
                    }
                    break Ok(res)
                }
                Err(err) => {
                    if let Ok(tran) = Transaction::try_from(tran) {
                        tran.transaction.rollback().map_err(Error::from)?;
                    }
                    if i == TRIES {
                        break Err(err);
                    }
                }
            }
        }
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(
            self.executor.get()?.query_opt(
                "SELECT DISTINCT namespace FROM store WHERE namespace = $1",
                &[&self.namespace.as_ref()],
            )?
            .is_none()
        )
    }

    pub fn get_any(&self, key: &Key) -> Result<Option<Value>, Error> {
        Ok(
            self.executor.get()?.query_opt(
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
        self.executor.get()?.execute(
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
        let mut transaction = client.transaction()?;
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
impl<'a> Transaction<'a> {
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
impl<'a> Transaction<'a> {
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

impl<'a> fmt::Debug for Transaction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("namespace", &self.namespace)
            .finish()
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Postgres(postgres::error::Error),
    R2D2(r2d2::Error),
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

impl From<r2d2::Error> for Error {
    fn from(src: r2d2::Error) -> Self {
        Self::R2D2(src)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Postgres(inner) => inner.fmt(f),
            Error::R2D2(inner) => inner.fmt(f),
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
