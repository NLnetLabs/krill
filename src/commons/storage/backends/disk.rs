//! Filesystem-based storage.

use std::{fmt, fs, io, path};
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use tempfile::NamedTempFile;
use url::Url;
use crate::commons::storage::types::{
    Key, Namespace, Segment, SegmentBuf, Scope
};
use crate::commons::storage::store::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ Constants -----------------------------------------------------

pub const LOCK_FILE_NAME: &str = "lockfile.lock";
const LOCK_FILE_DIR: &Segment = Segment::make(".locks");


//------------ Store ---------------------------------------------------------

/// A storage backend that uses the filesystem for storing values.
///
/// The backend uses files under a root directory. Each namespace will have
/// its own directory under this root. In addition, the directory `.tmp` is
/// used as a temporary storage space. A key’s scope is translated into a
/// directory path under the namespace directory and its name is translated
/// into a file name with the extension `.json`. Values are stored in this
/// file as JSON objects.
///
/// A locking strategy based on the presence of files is employed as well.
///
/// # Note
///
/// The use of `.tmp` is a change from earlier versions which used `tmp`.
/// However, since this is a valid namespace, using this directory may lead
/// to surprises.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    tmp: PathBuf,
}

impl Store {
    pub fn from_uri(
        uri: &Url, namespace: &Namespace
    ) -> Result<Option<Self>, Error> {
        if uri.scheme() != "local" {
            return Ok(None)
        }

        let path = PathBuf::from(format!(
            "{}{}", uri.host_str().unwrap_or_default(), uri.path()
        ));
        let root = path.join(namespace.as_str());
        let tmp = path.join(".tmp");

        fs::create_dir_all(&tmp).map_err(|err| {
            Error::io(
                format!(
                    "failed to create temporary directory '{}'",
                    tmp.display()
                ),
                err
            )
        })?;

        Ok(Some(Self { root, tmp }))
    }

    pub fn execute<F, T>(&self, scope: &Scope, op: F) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let mut file_lock = FileLock::create(self.scope_lock_path(scope))?;
        let _write_lock = file_lock.write()?;
        op(&mut SuperTransaction::from(self))
    }

    /// Returns the path for the given key.
    fn key_path(&self, key: &Key) -> PathBuf {
        let mut path = self.scope_path(key.scope());
        path.push(key.name().as_str());
        path
    }

    /// Returns the path for the given scope.
    fn scope_path(&self, scope: &Scope) -> PathBuf {
        let mut path = self.root.to_path_buf();
        for segment in scope {
            path.push(segment.as_str());
        }
        path
    }

    /// Returns the lock file path for the given scope.
    fn scope_lock_path(&self, scope: &Scope) -> PathBuf {
        let mut path = self.root.join(LOCK_FILE_DIR.as_str());
        for segment in scope {
            path.push(segment.as_str());
        }
        path
    }

    /// Returns a scope for the given path.
    ///
    /// Assumes that the path refers to a directory.
    ///
    /// Returns `None` if `path` isn’t under the root directory or if it
    /// contains strange path components.
    fn path_scope(&self, path: &Path) -> Option<Scope> {
        let path = path.strip_prefix(&self.root).ok()?;

        let mut scope = Scope::global();
        for comp in path.components() {
            match comp {
                path::Component::Normal(segment) => {
                    scope.add_sub_scope(
                        Segment::parse(segment.to_str()?).ok()?
                    );
                }
                _ => return None
            }
        }
        Some(scope)
    }
}


/// # Reading
impl Store {
    /// Returns whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(
            self.root.read_dir().map(|mut d| {
                d.next().is_none()
            }).unwrap_or(true)
        )
    }

    /// Returns whether the store contains the given key.
    pub fn has(&self, key: &Key) -> Result<bool, Error> {
        Ok(self.key_path(key).try_exists().map_err(|err| {
            Error::io(
                format!("failed to check existance of key '{}'", key),
                err
            )
        })?)
    }

    /// Returns whether the store contains the given scope.
    pub fn has_scope(&self, scope: &Scope) -> Result<bool, Error> {
        Ok(self.scope_path(scope).try_exists().map_err(|err| {
            Error::io(
                format!("failed to check existance of scope '{}'", scope),
                err
            )
        })?)
    }

    /// Returns the contents of the stored value with the given key.
    ///
    /// If the value does not exist, returns `Ok(None)?.
    pub fn get<T: DeserializeOwned>(
        &self, key: &Key
    ) -> Result<Option<T>, Error> {
        let path = self.key_path(key);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(err) => {
                return Err(Error::io(
                    format!("failed to open file '{}'", path.display()),
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
                    Err(Error::io(
                        format!(
                            "failed to read stored file '{}'",
                            path.display()
                        ),
                        err.into()
                    ))
                }
                else {
                    Err(Error::deserialize(key.clone(), err))
                }
            }
        }
    }

    pub fn get_any(&self, key: &Key) -> Result<Option<Value>, Error> {
        self.get(key)
    }

    /// Returns all the keys in the given scope.
    ///
    /// This includes all keys directly under the given scope as well as
    /// all keys in sub-scopes.
    pub fn list_keys(&self, scope: &Scope) -> Result<Vec<Key>, Error> {
        let path = self.scope_path(scope);
        let mut res = Vec::new();
        self.list_dir_keys(&path, &mut res)?;
        Ok(res)
    }

    /// Adds all the keys in `path` to `res`.
    ///
    /// This is the recursive portion of `Self::list_keys`.
    fn list_dir_keys(
        &self, path: &Path, res: &mut Vec<Key>
    ) -> Result<(), Error> {
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => {
                return Err(Error::io(
                    format!(
                        "failed to read directory '{}'", path.display()
                    ),
                    err
                ));
            }
        };
        let scope = match self.path_scope(path) {
            Some(scope) => scope,
            None => return Ok(())
        };
        for item in dir {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    return Err(Error::io(
                        format!(
                            "failed to read directory '{}'", path.display()
                        ),
                        err
                    ));
                }
            };
            let file_type = match item.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    return Err(Error::io(
                        format!(
                            "failed to read directory '{}'", path.display()
                        ),
                        err
                    ));
                }
            };
            if file_type.is_dir() {
                self.list_dir_keys(&item.path(), res)?;
            }
            else if file_type.is_file() {
                if let Some(name) =
                    item.file_name().into_string().ok().and_then(|name| {
                        SegmentBuf::try_from(name).ok()
                    })
                {
                    res.push(Key::new_scoped(scope.clone(), name))
                }
            }
        }

        Ok(())
    }

    /// Returns all the scopes in the score.
    ///
    pub fn list_scopes(&self) -> Result<Vec<Scope>, Error> {
        let mut res = Vec::new();
        self.list_dir_scopes(&self.root, &mut res)?;
        Ok(res)
    }

    /// Adds all the scopes under `path` to `res`.
    ///
    /// This is the recursive portion of `Self::list_scopes`.
    fn list_dir_scopes(
        &self, path: &Path, res: &mut Vec<Scope>
    ) -> Result<(), Error> {
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => {
                return Err(Error::io(
                    format!(
                        "failed to read directory '{}'", path.display()
                    ),
                    err
                ));
            }
        };
        match self.path_scope(path) {
            Some(scope) => res.push(scope),
            None => return Ok(())
        };
        for item in dir {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    return Err(Error::io(
                        format!(
                            "failed to read directory '{}'", path.display()
                        ),
                        err
                    ));
                }
            };
            let file_type = match item.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    return Err(Error::io(
                        format!(
                            "failed to read directory '{}'", path.display()
                        ),
                        err
                    ));
                }
            };
            if file_type.is_dir() {
                self.list_dir_scopes(&item.path(), res)?;
            }
        }

        Ok(())
    }
}


/// # Writing
impl Store {
    /// Stores the provided value under the gvien key.
    ///
    /// Quielty overwrites a possibly already existing value.
    pub fn store<T: Serialize>(
        &self, key: &Key, value: &T
    ) -> Result<(), Error> {
        let path = self.key_path(key);

        if key.scope().first_segment() == Some(LOCK_FILE_DIR) {
            return Err(Error::invalid_key(key.clone()));
        }

        Self::create_dirs(path.parent())?;


        // Write to a temporary file first to ensure that the file can be
        // written entirely.
        //
        // tempfile ensures that the temporary file is cleaned up in case it
        // would be left behind because of some issue.
        let mut tmp_file = NamedTempFile::new_in(&self.tmp).map_err(|err| {
            Error::io(
                format!(
                    "writing temp file failed for key: '{}'",
                    key
                ),
                err,
            )
        })?;

        serde_json::to_writer_pretty(&mut tmp_file, value).map_err(|err| {
            if err.is_io() {
                Error::io(
                    format!(
                        "failed to write temp file '{}' for key '{}'",
                        tmp_file.as_ref().display(),
                        key
                    ),
                    err.into(),
                )
            }
            else {
                Error::serialize(key.clone(), err)
            }
        })?;

        // Move the temporary file to its final location.
        tmp_file.persist(&path).map_err(|err| {
            Error::io(
                format!(
                    "failed to rename temp file '{}' to '{}'",
                    err.file.path().display(),
                    path.display()
                ),
                err.error,
            )
        })?;

        Ok(())
    }

    pub fn store_any(&self, key: &Key, value: &Value) -> Result<(), Error> {
        self.store(key, value)
    }

    /// Moves a value from one key to another.
    pub fn move_value(&self, from: &Key, to: &Key) -> Result<(), Error> {
        let from_path = self.key_path(from);
        let to_path = self.key_path(to);

        Self::create_dirs(to_path.parent())?;

        fs::rename(&from_path, &to_path).map_err(|err| {
            Error::io(
                format!(
                    "failed to move '{}' to '{}'",
                    from_path.display(),
                    to_path.display()
                ),
                err
            )
        })?;
        self.remove_empty_dirs(from_path.parent());

        Ok(())
    }

    /// Moves an entire scope to a new scope.
    pub fn move_scope(
        &self, from: &Scope, to: &Scope
    ) -> Result<(), Error> {
        let from_path = self.scope_path(from);
        let to_path = self.scope_path(to);

        Self::create_dirs(Some(&to_path))?;

        fs::rename(from_path.as_path(), to_path.as_path()).map_err(|err| {
            Error::io(
                format!(
                    "failed to move '{}' to '{}'",
                    from_path.display(),
                    to_path.display()
                ),
                err
            )
        })?;
        self.remove_empty_dirs(Some(&from_path));

        Ok(())
    }

    /// Removes the stored value for a given key.
    pub fn delete(&self, key: &Key) -> Result<(), Error> {
        let path = self.key_path(key);

        fs::remove_file(&path).map_err(|err| {
            Error::io(
                format!(
                    "failed to delete file '{}'", path.display()
                ),
                err
            )
        })?;
        self.remove_empty_dirs(path.parent());

        Ok(())
    }

    /// Removes an entire scope.
    pub fn delete_scope(&self, scope: &Scope) -> Result<(), Error> {
        let path = self.scope_path(scope);

        fs::remove_dir_all(&path).map_err(|err| {
            Error::io(
                format!(
                    "failed to recursively delete directory '{}'",
                    path.display()
                ),
                err
            )
        })?;
        self.remove_empty_dirs(path.parent());

        Ok(())
    }

    /// Removes the entire store.
    pub fn clear(&self) -> Result<(), Error> {
        // XXX Not sure this is the best way to do this?
        if self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }

        Ok(())
    }

    pub fn migrate_namespace(
        &mut self, namespace: &Namespace
    ) -> Result<(), Error> {
        let root_parent = self.root.parent().ok_or_else(|| {
            Error::other(
                format!("cannot get parent dir for: {}", self.root.display())
            )
        })?;

        let new_root = root_parent.join(namespace.as_str());

        if new_root.exists() {
            // If the target directory already exists, then it must be empty.
            if new_root
                .read_dir()
                .map_err(|err| {
                    Error::io(
                        format!(
                            "cannot read directory '{}'",
                            new_root.display(),
                        ),
                        err
                    )
                })?
                .next()
                .is_some()
            {
                return Err(Error::other(format!(
                    "target dir {} already exists and is not empty",
                    new_root.display(),
                )));
            }
        }

        fs::rename(&self.root, &new_root).map_err(|err| {
            Error::io(
                format!(
                    "cannot rename dir from {} to {}",
                    self.root.display(),
                    new_root.display(),
                ),
                err
            )
        })?;
        self.root = new_root;
        Ok(())
    }

    /// Creates the given directory if necessary.
    fn create_dirs(path: Option<&Path>) -> Result<(), Error> {
        if let Some(path) = path {
            fs::create_dir_all(path).map_err(|err| {
                Error::io(
                    format!(
                        "Failed to create directory '{}'", path.display()
                    ),
                    err
                )
            })?;
        }
        Ok(())
    }

    /// Removes parent directories if they are empty.
    fn remove_empty_dirs(&self, path: Option<&Path>) {
        let path = match path {
            Some(path) => path,
            None => return
        };
        let mut ancestors = path.ancestors();
        while ancestors.next().and_then(|path| {
            fs::remove_dir(path).ok()
        }).is_some()
        { }
    }
}


//------------ Transaction ---------------------------------------------------

pub type Transaction<'a> = &'a Store;


//------------ FileLock ------------------------------------------------------

#[derive(Debug)]
struct FileLock {
    lock: fd_lock::RwLock<File>,
}

impl FileLock {
    fn create(path: PathBuf) -> Result<Self, Error> {
        let lock_path = path.join(LOCK_FILE_NAME);
        Store::create_dirs(Some(&path))?;

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        let lock_file = options.open(&lock_path).map_err(|err| {
            Error::io(
                format!(
                    "failed to open lock file '{}'", lock_path.display(),
                ),
                err
            )
        })?;

        Ok(FileLock { lock: fd_lock::RwLock::new(lock_file) })
    }

    fn write(&mut self) -> Result<fd_lock::RwLockWriteGuard<'_, File>, Error> {
        self.lock
            .write()
            .map_err(|e| Error::other(format!("Cannot get file lock: {}", e)))
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Io {
        context: Cow<'static, str>,
        err: io::Error,
    },
    Deserialize {
        key: Key,
        err: String,
    },
    Serialize {
        key: Key,
        err: String,
    },
    InvalidKey(Key),
    Other(String),
}

impl Error {
    fn io(context: impl Into<Cow<'static, str>>, err: io::Error) -> Self {
        Error::Io { context: context.into(), err }
    }

    fn deserialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Deserialize { key, err: err.to_string() }
    }

    fn serialize(key: Key, err: impl fmt::Display) -> Self {
        Error::Serialize { key, err: err.to_string() }
    }

    fn invalid_key(key: Key) -> Self {
        Error::InvalidKey(key)
    }

    fn other(info: impl Into<String>) -> Self {
        Error::Other(info.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io { context, err } => {
                write!(f, "{}: {}", context, err)
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
            Error::InvalidKey(key) => {
                write!(f, "invalid key '{}'", key)
            }
            Error::Other(s) => f.write_str(s)
        }
    }
}

