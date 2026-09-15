#![allow(unused)]

use std::{error, fmt, fs, io};
use std::fs::File;
use std::marker::PhantomData;
use std::path::PathBuf;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use super::combined::{
    Store, StoreError,
    Transaction as StoreTransaction,
};
use super::disk::{DiskStore, Error as DiskError};
use super::ident::Ident;
use super::statements::{
    ManipulationStatement, QueryOneStatement, QueryOptStatement,
    QueryStatement, Schema, Statement, StatementError
};


//------------ KeyValueStore -------------------------------------------------

/// A key-value store.
///
/// # Use within Krill
///
/// The following components use the key-value store directly:
///
/// * aggregate store, WAL store,
/// * queue,
/// * CA objects, CA status,
/// * OpenSSL signer.
#[derive(Debug)]
pub struct KeyValueStore {
    /// The low-level store this key-value store operates on.
    store: Store,

    /// The namespace of this store.
    namespace: Box<Ident>,
}

impl KeyValueStore {
    /// Opens a key-value store atop the given store with the given namespace.
    pub fn new(
        store: Store, namespace: impl Into<Box<Ident>>
    ) -> Result<Self, KeyValueError> {
        Ok(Self {
            store,
            namespace: namespace.into()
        })
    }

    /// Opens an upgrade key-value store.
    ///
    /// This is the same as [Self::new] but prefixes the namespace with
    /// `"upgrade_"`.
    pub fn new_upgrade(
        store: Store, namespace: &Ident
    ) -> Result<Self, KeyValueError> {
        Self::new(
            store,
            Self::prefixed_namespace(
                const { Ident::make("upgrade") }, namespace
            )
        )
    }

    pub fn init(&mut self) -> Result<(), KeyValueError> {
        Ok(self.store.init(Init { namespace: &self.namespace })?)
    }

    pub fn execute<F, T>(
        &self,
        scope: Option<&Ident>,
        op: F
    ) -> Result<T, KeyValueError>
    where
        F: Fn(&mut KeyValueTransaction) -> Result<T, KeyValueError>
    {
        Ok(self.store.execute(|tran| {
            let mut tran = KeyValueTransaction::new(tran, &self.namespace);
            op(&mut tran)
        })?)
    }
}

impl KeyValueStore {
    pub fn has(
        &self, scope: Option<&Ident>, key: &Ident,
    ) -> Result<bool, KeyValueError> {
        self.execute(scope, |tran| {
            tran.has(scope, key)
        })
    }

    pub fn has_scope(
        &self, scope: &Ident
    ) -> Result<bool, KeyValueError> {
        self.execute(None, |tran| {
            tran.has_scope(scope)
        })
    }

    pub fn list_keys(
        &self, scope: Option<&Ident>,
    ) -> Result<Vec<Box<Ident>>, KeyValueError> {
        self.execute(scope, |tran| {
            tran.list_keys(scope)
        })
    }

    pub fn list_scopes(&self) -> Result<Vec<Box<Ident>>, KeyValueError> {
        self.execute(None, |tran| {
            tran.list_scopes()
        })
    }

    pub fn get<T: DeserializeOwned + 'static>(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<T>, KeyValueError> {
        self.execute(scope, |tran| {
            tran.get(scope, key)
        })
    }

    pub fn store<T: Serialize>(
        &self, scope: Option<&Ident>, key: &Ident, value: &T
    ) -> Result<(), KeyValueError> {
        self.execute(scope, |tran| {
            tran.store(scope, key, value)
        })
    }

    pub fn store_new<T: Serialize>(
        &self, scope: Option<&Ident>, key: &Ident, value: &T
    ) -> Result<(), KeyValueError> {
        self.execute(scope, |tran| {
            if tran.has(scope, key)? {
                Err(KeyValueError::duplicate_key(scope, key))
            }
            else {
                tran.store(scope, key, value)
            }
        })
    }

    pub fn delete_key(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<(), KeyValueError> {
        self.execute(scope, |tran| {
            tran.delete_key(scope, key)
        })
    }

    pub fn delete_scope(
        &self, scope: &Ident
    ) -> Result<(), KeyValueError> {
        self.execute(None, |tran| { tran.delete_scope(scope) })
    }

    pub fn clear(&self) -> Result<(), KeyValueError> {
        self.execute(None, |tran| tran.clear())
    }
}


// # Migration Support
impl KeyValueStore {
    fn prefixed_namespace(
        namespace: &Ident,
        prefix: &Ident,
    ) -> Box<Ident> {
        Ident::builder(prefix).push_ident(
            const { Ident::make("_") }
        ).push_ident(
            namespace
        ).finish()
    }

    pub fn is_empty(
        store: &Store, namespace: &Ident
    ) -> Result<bool, KeyValueError> {
        store.execute(|tran| {
            KeyValueTransaction::new(tran, namespace).is_empty()
        })
    }

    pub fn is_upgrade_empty(
        store: &Store, namespace: &Ident
    ) -> Result<bool, KeyValueError> {
        Self::is_empty(
            store,
            &Self::prefixed_namespace(
                namespace, const { Ident::make("upgrade") }
            )
        )
    }

    /// Import all data from the given key-value store into this store.
    ///
    /// This copies data value by value with a separate transaction for each.
    pub fn import(
        &self,
        other: &Self,
    ) -> Result<(), KeyValueError> {
        let mut scopes: Vec<_>
            = other.list_scopes()?.into_iter().map(Some).collect();
        scopes.push(None);

        for scope in scopes {
            for key in other.list_keys(scope.as_deref())? {
                if let Some(value)
                    = other.get::<Value>(scope.as_deref(), &key)?
                {
                    self.store(scope.as_deref(), &key, &value)?
                }
            }
        }

        Ok(())
    }

    /// Archives the given namespace.
    ///
    /// The namespace is moved to a namespace prefixed with `"archive"`. If
    /// such a namespace already exists, it is removed.
    pub fn migrate_to_archive(
        store: &Store, namespace: &Ident
    ) -> Result<(), KeyValueError> {
        let archive_ns = Self::prefixed_namespace(
            namespace, const { Ident::make("archive") }
        );

        // Wipe any existing archive, before archiving this store.
        // We don't want to keep too much old data. See issue: #1088.
        Self::new(store.clone(), archive_ns.clone())?.clear()?;

        Self::migrate(
            &store, namespace, &archive_ns
        )?;
        Ok(())
    }

    /// Migrates an upgrade namespace to the normal namespace.
    ///
    /// This moves the namespace prefixed by `"upgrade"` to the namespace.
    /// Fails if the given namespace is not empty.
    pub fn migrate_to_current(
        store: &Store, namespace: &Ident
    ) -> Result<(), KeyValueError> {
        if !Self::is_empty(store, namespace)? {
            return Err(KeyValueError::Other(format!(
                "Abort migrate upgraded store for {namespace} to current. \
                The current store was not archived."
            )))
        }

        let upgrade_ns = Self::prefixed_namespace(
            namespace, const { Ident::make("upgrade") }
        );
        Self::migrate(store, &upgrade_ns, namespace)?;
        Ok(())
    }

    fn migrate(
        store: &Store, src_ns: &Ident, dst_ns: &Ident
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // src_ns
                &'a str, // dst_ns
            );

            const PSQL_QUERY: &'static str = "\
                ALTER TABLE $1 RENAME TO $2\
            ";
            const SQLITE_QUERY: &'static str = "\
                ALTER TABLE ?1 RENAME TO ?2\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (src_ns, dst_ns): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let src_path = store.namespace_path(src_ns);
                let dst_path = store.namespace_path(dst_ns);

                fs::rename(&src_path, &dst_path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "cannot rename dir from {} to {}",
                            src_path.display(),
                            dst_path.display(),
                        ),
                        err
                    )
                })?;
                Ok(1)
            }
        }


        // TODO: Check for locks.

        store.execute(|tran| {
            tran.manipulate::<Query>((src_ns.as_str(), dst_ns.as_str()))
        })?;
        Ok(())
    }
}

//------------ Init ----------------------------------------------------------

struct Init<'a> {
    namespace: &'a Ident
}

impl<'a> Schema for Init<'a> {
    async fn init_psql<'t>(
        self, transaction: &mut tokio_postgres::Transaction<'t>
    ) -> Result<(), StoreError> {
        // TODO: Check that the columns are present and of correct type.
        Ok(())
    }

    fn init_sqlite(
        self, transaction: rusqlite::Transaction
    ) -> Result<(), StoreError> {
        if transaction.table_exists(None, self.namespace.as_str())? {
            // TODO: Check that the columns are present and of correct type.
            Ok(())
        }
        else {
            transaction.execute(
                "CREATE TABLE ?1 ( \
                   scope TEXT, \
                   key TEXT NOT NULL, \
                   value TEXT NOT NULL, \
                   PRIMARY KEY(scope, key) \
                )",
                (self.namespace.as_str(),),
            )?;
            transaction.commit()?;
            Ok(())
        }
    }

    fn init_disk(
        self, store: &mut DiskStore
    ) -> Result<(), DiskError> {
        Ok(())
    }
}


//------------ KeyValueTransaction -------------------------------------------

#[derive(Debug)]
pub struct KeyValueTransaction<'a, 't> {
    tran: &'a mut StoreTransaction<'t>,
    namespace: &'a Ident,
}

impl<'a, 't> KeyValueTransaction<'a, 't> {
    fn new(
        tran: &'a mut StoreTransaction<'t>,
        namespace: &'a Ident,
    ) -> Self {
        Self { tran, namespace }
    }
}

/// # Reading
impl<'a, 't> KeyValueTransaction<'a, 't> {
    pub fn is_empty(&mut self) -> Result<bool, KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
            );

            const PSQL_QUERY: &'static str = "\
                SELECT COUNT(*) FROM $1\
            ";
            const SQLITE_QUERY: &'static str = "\
                SELECT COUNT(*) FROM $1\
            ";
        }

        impl QueryOneStatement for Query {
            type Row = bool;

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Self::Row, StatementError> {
                row.try_get::<_, i64>(
                    0
                ).map(|res| res == 0).map_err(StatementError::custom)
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Self::Row, StatementError> {
                row.get::<_, i64>(
                    0
                ).map(|res| res == 0).map_err(StatementError::custom)
            }

            fn run_disk<'a>(
                (namespace,): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Self::Row, DiskError> {
                let path = store.namespace_path(namespace);
                Ok(
                    path.read_dir().map(|mut d| {
                        d.next().is_none()
                    }).unwrap_or(true)
                )
            }
        }

        Ok(self.tran.query_one::<Query>((
            self.namespace.as_str(),
        ))?)
    }

    pub fn has(
        &mut self, scope: Option<&Ident>, key: &Ident,
    ) -> Result<bool, KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // scope
                &'a str  // key
            );

            const PSQL_QUERY: &'static str = "\
                SELECT 1 FROM $1 WHERE scope = $2 AND key = $3\
            ";

            const SQLITE_QUERY: &'static str = "\
                SELECT 1 FROM ?1 WHERE scope = ?2 AND key = ?3\
            ";
        }

        impl QueryOptStatement for Query {
            type Row = ();

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Self::Row, StatementError> {
                Ok(())
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Self::Row, StatementError> {
                Ok(())
            }

            fn run_disk<'a>(
                (namespace, scope, key): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Option<Self::Row>, DiskError> {
                store.key_path(
                    namespace, scope, key
                ).try_exists().map(|exists| {
                    exists.then_some(())
                }).map_err(|err| {
                    DiskError::io(
                        format!("failed to check existance of key '{key}'"),
                        err
                    )
                })
            }
        }

        Ok(self.tran.query_opt::<Query>((
            self.namespace.as_str(),
            scope.map(Ident::as_str),
            key.as_str()
        ))?.is_some())
    }

    pub fn has_scope(
        &mut self, scope: &Ident
    ) -> Result<bool, KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace,
                &'a str, // scope,
            );

            const PSQL_QUERY: &'static str = "\
                SELECT 1 FROM $1 WHERE AND scope = $2\
            ";

            const SQLITE_QUERY: &'static str = "\
                SELECT 1 FROM ?1 WHERE scope = ?2\
            ";
        }

        impl QueryOptStatement for Query {
            type Row = ();

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Self::Row, StatementError> {
                Ok(())
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Self::Row, StatementError> {
                Ok(())
            }

            fn run_disk<'a>(
                (namespace, scope): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Option<Self::Row>, DiskError> {
                // XXX Maybe this should also check whether the scope_path
                //     is a directory?
                store.scope_path(
                    namespace, Some(scope),
                ).try_exists().map(|exists| {
                    exists.then_some(())
                }).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to check existance of scope '{scope}'"
                        ),
                        err
                    )
                })
            }
        }

        Ok(self.tran.query_opt::<Query>((
            self.namespace.as_str(),
            scope.as_str(),
        ))?.is_some())
    }

    pub fn get<T: DeserializeOwned + 'static>(
        &mut self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<T>, KeyValueError> {
        struct Query<T>(PhantomData<T>);

        impl<T: 'static> Statement for Query<T> {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // scope
                &'a str  // key
            );

            const PSQL_QUERY: &'static str = "\
                SELECT value FROM $1 WHERE scope = $2 AND key = $3\
            ";

            const SQLITE_QUERY: &'static str = "\
                SELECT value FROM ?1 WHERE scope = ?2 AND key = ?3\
            ";
        }

        impl<T: DeserializeOwned + 'static> QueryOptStatement for Query<T> {
            type Row = T;

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Self::Row, StatementError> {
                row.try_get(
                    0
                ).map_err(StatementError::custom).and_then(|res| {
                    serde_json::from_value(res).map_err(
                        StatementError::custom
                    )
                })
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Self::Row, StatementError> {
                row.get(
                    0
                ).map_err(StatementError::custom).and_then(|res| {
                    serde_json::from_value(res).map_err(
                        StatementError::custom
                    )
                })
            }

            fn run_disk<'a>(
                (namespace, scope, key): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Option<Self::Row>, DiskError> {
                let path = store.key_path(namespace, scope, key);
                let file = match File::open(&path) {
                    Ok(file) => io::BufReader::new(file),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        return Ok(None)
                    }
                    Err(err) => {
                        return Err(DiskError::io(
                            format!("failed to open file '{}'",
                            path.display()),
                            err
                        ))
                    }
                };
                match serde_json::from_reader(file) {
                    Ok(value) => {
                        Ok(Some(value))
                    }
                    Err(err) => {
                        if err.is_io() {
                            Err(DiskError::io(
                                format!(
                                    "failed to read stored file '{}'",
                                    path.display()
                                ),
                                err.into()
                            ))
                        }
                        else {
                            Err(DiskError::other(
                                format!(
                                    "failed to deserialize value in file \
                                     '{}': {}",
                                    path.display(), err
                                )
                            ))
                        }
                    }
                }
            }
        }

        Ok(self.tran.query_opt::<Query<T>>((
            self.namespace.as_str(),
            scope.map(Ident::as_str),
            key.as_str()
        ))?)
    }

    pub fn list_keys(
        &mut self, scope: Option<&Ident>,
    ) -> Result<Vec<Box<Ident>>, KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // scope
            );

            const PSQL_QUERY: &'static str = "\
                SELECT key FROM $1 WHERE scope = $2\
            ";

            const SQLITE_QUERY: &'static str = "\
                SELECT key FROM ?1 WHERE scope = ?2\
            ";
        }

        impl QueryStatement for Query {
            type Row = Box<Ident>;

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Option<Self::Row>, StatementError> {
                row.try_get(
                    0
                ).map_err(StatementError::custom).and_then(|key| {
                    Ident::boxed_from_string(key).map_err(
                        StatementError::custom
                    )
                }).map(Some)
                
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Option<Self::Row>, StatementError> {
                row.get(
                    0
                ).map_err(StatementError::custom).and_then(|key| {
                    Ident::boxed_from_string(key).map_err(
                        StatementError::custom
                    )
                }).map(Some)
            }

            fn run_disk<'a>(
                (namespace, scope): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Vec<Self::Row>, DiskError> {
                let path = store.scope_path(namespace, scope);
                let mut res = Vec::new();
                let dir = match fs::read_dir(&path) {
                    Ok(dir) => dir,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        return Ok(res);
                    }
                    Err(err) => {
                        return Err(DiskError::io(
                            format!(
                                "failed to read directory '{}'", path.display()
                            ),
                            err
                        ));
                    }
                };
                for item in dir {
                    let item = match item {
                        Ok(item) => item,
                        Err(err) => {
                            return Err(DiskError::io(
                                format!(
                                    "failed to read directory '{}'",
                                    path.display()
                                ),
                                err
                            ));
                        }
                    };
                    let file_type = match item.file_type() {
                        Ok(file_type) => file_type,
                        Err(err) => {
                            return Err(DiskError::io(
                                format!(
                                    "failed to read directory '{}'",
                                    path.display()
                                ),
                                err
                            ));
                        }
                    };
                    if file_type.is_file() 
                        && let Some(name) =
                            item.file_name().into_string().ok().and_then(
                                |name|  Ident::boxed_from_string(name).ok()
                            )
                    {
                        res.push(name)
                    }
                }

                Ok(res)
            }
        }

        Ok(self.tran.query::<Query>((
            self.namespace.as_str(),
            scope.map(Ident::as_str),
        ))?)
    }

    pub fn list_scopes(&mut self) -> Result<Vec<Box<Ident>>, KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
            );

            const PSQL_QUERY: &'static str = "\
                SELECT scope FROM $1\
            ";

            const SQLITE_QUERY: &'static str = "\
                SELECT key FROM ?1\
            ";
        }

        impl QueryStatement for Query {
            type Row = Box<Ident>;

            fn psql_row(
                row: tokio_postgres::Row
            ) -> Result<Option<Self::Row>, StatementError> {
                row.try_get(
                    0
                ).map_err(StatementError::custom).and_then(|key| {
                    Ident::boxed_from_string(key).map_err(
                        StatementError::custom
                    )
                }).map(Some)
                
            }

            fn sqlite_row(
                row: &rusqlite::Row
            ) -> Result<Option<Self::Row>, StatementError> {
                row.get(
                    0
                ).map_err(StatementError::custom).and_then(|key| {
                    Ident::boxed_from_string(key).map_err(
                        StatementError::custom
                    )
                }).map(Some)
            }

            fn run_disk<'a>(
                (namespace,): Self::Params<'a>,
                store: &mut DiskStore,
            ) -> Result<Vec<Self::Row>, DiskError> {
                let path = store.namespace_path(namespace);
                let mut res = Vec::new();
                let dir = match fs::read_dir(&path) {
                    Ok(dir) => dir,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        return Ok(res);
                    }
                    Err(err) => {
                        return Err(DiskError::io(
                            format!(
                                "failed to read directory '{}'",
                                path.display()
                            ),
                            err
                        ));
                    }
                };
                for item in dir {
                    let item = match item {
                        Ok(item) => item,
                        Err(err) => {
                            return Err(DiskError::io(
                                format!(
                                    "failed to read directory '{}'",
                                    path.display()
                                ),
                                err
                            ));
                        }
                    };
                    let file_type = match item.file_type() {
                        Ok(file_type) => file_type,
                        Err(err) => {
                            return Err(DiskError::io(
                                format!(
                                    "failed to read directory '{}'",
                                    path.display()
                                ),
                                err
                            ));
                        }
                    };
                    if file_type.is_dir()
                        && let Some(name) =
                            item.file_name().into_string().ok().and_then(
                                |name| Ident::boxed_from_string(name).ok()
                            )
                    {
                        res.push(name)
                    }
                }

                Ok(res)

            }
        }

        Ok(self.tran.query::<Query>((
            self.namespace.as_str(),
        ))?)
    }
}

/// # Writing
impl<'a, 't> KeyValueTransaction<'a, 't> {
    pub fn store<T: Serialize>(
        &mut self, scope: Option<&Ident>, key: &Ident, value: &T
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // scope
                &'a str, // key
                &'a Value, // value
            );

            const PSQL_QUERY: &'static str = "\
                INSERT INTO $1 (scope, key, value) \
                VALUES ($2, $3, $4) ON CONFLICT (scope, key) \
                DO UPDATE SET value = $4\
            ";

            const SQLITE_QUERY: &'static str = "\
                INSERT INTO ?1 (scope, key, value) \
                VALUES (?2, ?3, ?4) ON CONFLICT (scope, key) \
                DO UPDATE SET value = ?4\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace, scope, key, value): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let path = store.key_path(namespace, scope, key);

                store.create_dirs(path.parent())?;

                let mut tempfile = store.tempfile()?;
                let res = serde_json::to_writer_pretty(
                    &mut io::BufWriter::new(&mut tempfile),
                    value
                );
                if let Err(err) = res {
                    if err.is_io() {
                        return Err(DiskError::io(
                            format!(
                                "failed to write temp file '{}' for key '{}'",
                                tempfile.as_ref().display(),
                                key
                            ),
                            err.into(),
                        ))
                    }
                    else {
                        return Err(DiskError::other(err))
                    }
                }

                // Move the temporary file to its final location.
                tempfile.persist(&path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to rename temp file '{}' to '{}'",
                            err.file.path().display(),
                            path.display()
                        ),
                        err.error,
                    )
                })?;

                Ok(1)
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
            scope.map(Ident::as_str),
            key.as_str(),
            &serde_json::to_value(value).map_err(StoreError::other)?,
        ))?;
        Ok(())
    }

    pub fn move_value(
        &mut self,
        from_scope: Option<&Ident>, from_key: &Ident,
        to_scope: Option<&Ident>, to_key: &Ident,
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // from_scope
                &'a str, // from_key
                Option<&'a str>, // to_scope
                &'a str, // to_key
            );

            const PSQL_QUERY: &'static str = "\
                UPDATE $1 SET scope = $4, key = $5 \
                WHERE scope = $2 AND key = $3\
            ";

            const SQLITE_QUERY: &'static str = "\
                UPDATE ?1 SET scope = ?4, key = ?5 \
                WHERE scope = ?2 AND key = ?3\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace, from_scope, from_key, to_scope, to_key):
                    Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let from_path = store.key_path(
                    namespace, from_scope, from_key
                );
                let to_path = store.key_path(
                    namespace, to_scope, to_key
                );

                store.create_dirs(to_path.parent())?;

                fs::rename(&from_path, &to_path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to move '{}' to '{}'",
                            from_path.display(),
                            to_path.display()
                        ),
                        err
                    )
                })?;
                store.remove_empty_dirs(from_path.parent());

                Ok(1)
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
            from_scope.map(Ident::as_str),
            from_key.as_str(),
            to_scope.map(Ident::as_str),
            to_key.as_str(),
        ))?;
        Ok(())
    }

    pub fn move_scope(
        &mut self, from_scope: &Ident, to_scope: &Ident,
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                &'a str, // from_scope
                &'a str, // to_scope
            );

            const PSQL_QUERY: &'static str = "\
                UPDATE $1 SET scope = $3 WHERE scope = $2\
            ";
            const SQLITE_QUERY: &'static str = "\
                UPDATE ?1 SET scope = ?3 WHERE scope = ?2\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace, from_scope, to_scope): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let from_path = store.scope_path(namespace, Some(from_scope));
                let to_path = store.scope_path(namespace, Some(to_scope));

                store.create_dirs(Some(&to_path))?;

                fs::rename(&from_path, &to_path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to move '{}' to '{}'",
                            from_path.display(),
                            to_path.display()
                        ),
                        err
                    )
                })?;
                store.remove_empty_dirs(Some(&from_path));

                Ok(1) // Not actually the correct result but we discard it
                      // anyway below.
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
            from_scope.as_str(),
            to_scope.as_str(),
        ))?;
        Ok(())
    }

    pub fn delete_key(
        &mut self, scope: Option<&Ident>, key: &Ident
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
                Option<&'a str>, // scope
                &'a str, // key
            );

            const PSQL_QUERY: &'static str = "\
                DELETE FROM $1 WHERE scope = $2 AND key = $3\
            ";
            const SQLITE_QUERY: &'static str = "\
                DELETE FROM ?1 WHERE scope = ?2 AND key = ?3\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace, scope, key): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let path = store.key_path(namespace, scope, key);

                fs::remove_file(&path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to delete file '{}'", path.display()
                        ),
                        err
                    )
                })?;
                store.remove_empty_dirs(path.parent());

                Ok(1)
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
            scope.map(Ident::as_str),
            key.as_str(),
        ))?;
        Ok(())
    }

    pub fn delete_scope(
        &mut self, scope: &Ident
    ) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace,
                &'a str, // scope,
            );

            const PSQL_QUERY: &'static str = "\
                DELETE FROM $1 WHERE scope = $2\
            ";
            const SQLITE_QUERY: &'static str = "\
                DELETE FROM ?1 WHERE scope = ?2\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace, scope): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let path = store.scope_path(namespace, Some(scope));

                fs::remove_dir_all(&path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to recursively delete directory '{}'",
                            path.display()
                        ),
                        err
                    )
                })?;
                store.remove_empty_dirs(path.parent());

                Ok(1) // Not actually the correct result but we discard it
                      // anyway below.
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
            scope.as_str(),
        ))?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), KeyValueError> {
        struct Query;

        impl Statement for Query {
            type Params<'a> = (
                &'a str, // namespace
            );

            const PSQL_QUERY: &'static str = "\
                DELETE FROM $1\
            ";
            const SQLITE_QUERY: &'static str = "\
                DELETE FROM ?1\
            ";
        }

        impl ManipulationStatement for Query {
            fn run_disk<'a>(
                (namespace,): Self::Params<'a>,
                store: &mut DiskStore
            ) -> Result<u64, DiskError> {
                let path = store.namespace_path(namespace);

                fs::remove_dir_all(&path).map_err(|err| {
                    DiskError::io(
                        format!(
                            "failed to recursively delete directory '{}'",
                            path.display()
                        ),
                        err
                    )
                })?;
                store.remove_empty_dirs(path.parent());

                Ok(1) // Not actually the correct result but we discard it
                      // anyway below.
            }
        }

        self.tran.manipulate::<Query>((
            self.namespace.as_str(),
        ))?;
        Ok(())
    }
}


//------------ Value ---------------------------------------------------------

pub type Value = serde_json::Value;


//------------ DiskStoreExt --------------------------------------------------

trait DiskStoreExt {
    fn namespace_path(
        &self, namespace: &str
    ) -> PathBuf;

    fn scope_path(
        &self, namespace: &str, scope: Option<&str>
    ) -> PathBuf {
        let mut res = self.namespace_path(namespace);
        if let Some(scope) = scope {
            res.push(scope);
        }
        res
    }

    fn key_path(
        &self, namespace: &str, scope: Option<&str>, key: &str
    ) -> PathBuf {
        let mut path = self.scope_path(namespace, scope);
        path.push(key);
        path
    }
}

impl DiskStoreExt for DiskStore<'_> {
    fn namespace_path(
        &self, namespace: &str,
    ) -> PathBuf {
        self.root().join(namespace)
    }
}


//============ Error Types ===================================================

//------------ KeyValueError -------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum KeyValueError {
    UnknownScheme(String),
    DuplicateKey(Option<Box<Ident>>, Box<Ident>),
    Inner(StoreError),
    Other(String),
}

impl KeyValueError {
    fn duplicate_key(scope: Option<&Ident>, key: &Ident) -> Self {
        Self::DuplicateKey(scope.map(Into::into), key.into())
    }
}

impl From<StoreError> for KeyValueError {
    fn from(e: StoreError) -> Self {
        KeyValueError::Inner(e)
    }
}

impl fmt::Display for KeyValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyValueError::UnknownScheme(e) => {
                write!(f, "Unknown Scheme: {e}")
            }
            KeyValueError::DuplicateKey(scope, key) => {
                match scope {
                    Some(scope) => {
                        write!(f, "Duplicate key {key} in scope {scope}")
                    }
                    None => {
                        write!(f, "Duplicate key {key} in global scope")
                    }
                }
            }
            KeyValueError::Inner(e) => write!(f, "Store error: {e}"),
            KeyValueError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

