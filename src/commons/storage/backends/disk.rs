//! Filesystem-based storage.

use std::{error, fmt, fs, io};
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use tempfile::NamedTempFile;
use url::Url;
use crate::commons::storage::Ident;
use super::{
    Error as SuperError,
    Transaction as SuperTransaction
};


//------------ Constants -----------------------------------------------------

/// The directory under the root that contains temporary files.
const TMP_FILE_DIR: &str = ".tmp";

/// The directory under the root that contains the lock files.
const LOCK_FILE_DIR: &str = ".locks";

/// The name of the lock file for a scope.
pub const LOCK_FILE_NAME: &str = "lockfile.lock";


//------------ System --------------------------------------------------------

#[derive(Debug, Default)]
pub struct System(());

impl System {
    pub fn location(&self, uri: &Uri) -> Result<Location, Error> {
        Ok(Location { base: uri.path.clone() })
    }
}


//------------ Location ------------------------------------------------------

#[derive(Debug)]
pub struct Location {
    /// The base directory.
    ///
    /// All the namespaces plus a few extra repositories are under this
    /// directory.
    base: PathBuf,
}

impl Location {
    pub fn open(
        &self, namespace: &Ident,
    ) -> Result<Store, Error> {
        Store::new(&self.base, namespace)
    }

    pub fn is_empty(
        &self, namespace: &Ident,
    ) -> Result<bool, Error> {
        self.open(namespace)?.is_empty()
    }

    pub fn migrate(
        &self, src_ns: &Ident, dst_ns: &Ident
    ) -> Result<(), Error> {
        let src_store = self.open(src_ns)?;
        let dst_root = self.base.join(dst_ns.as_str());

        // Try removing the destination directory. If it isn’t there, that’s
        // fine. Otherwise we error out.
        if let Err(err) = fs::remove_dir(&dst_root) {
            if err.kind() != io::ErrorKind::NotFound {
                return Err(Error::other(format!(
                    "target dir {} exists and cannot be removed ({})",
                    dst_root.display(), err
                )));
            }
        }

        // The source store must not have any lock files.
        #[allow(clippy::collapsible_if)]
        if src_store.locks.exists() {
            if src_store.locks
                .read_dir()
                .map_err(|err| {
                    Error::io(
                        format!(
                            "cannot read directory '{}'",
                            src_store.locks.display(),
                        ),
                        err
                    )
                })?
                .next()
                .is_some()
            {
                return Err(Error::other(format!(
                    "store at '{}' has pending locks",
                    src_store.root.display(),
                )));
            }
        }

        fs::rename(&src_store.root, &dst_root).map_err(|err| {
            Error::io(
                format!(
                    "cannot rename dir from {} to {}",
                    src_store.root.display(),
                    dst_root.display(),
                ),
                err
            )
        })?;

        Ok(())
    }
}


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
/// In addition, the backend employes a locking strategy as a transaction
/// replacement. When executing on a given scope, a lock file is created
/// in a directory under `.locks/$(namespace)/$(scope)` with an advisory
/// lock on it.
///
/// # Notes
///
/// * The use of `.tmp` is a change from earlier versions which used `tmp`.
///   However, since this is a valid namespace, using this directory may
///   lead to surprises.
/// * The lock directory used to be under the namespace directory. This has
///   now been moved to a directory under the base directory so that there
///   is no collision with an actual scope starting with `.locks`.
#[derive(Debug)]
pub struct Store {
    /// The root path for the store.
    ///
    /// This will be a directory with the namespace name under the base
    /// directory.
    root: PathBuf,

    /// The path for temporary files within the store.
    ///
    /// This will be directly under the base directory and shared between
    /// namespaces.
    tmp: PathBuf,

    /// The path for lock files for this namespace.
    ///
    /// This will be a directory with the namespace name under the locks
    /// directory under the base_name.
    locks: PathBuf,
}

impl Store {
    fn new(
        path: &Path, namespace: &Ident,
    ) -> Result<Self, Error> {
        let root = path.join(namespace.as_str());
        let tmp = path.join(TMP_FILE_DIR);
        let mut locks = path.join(LOCK_FILE_DIR);
        locks.push(namespace.as_str());

        fs::create_dir_all(&tmp).map_err(|err| {
            Error::io(
                format!(
                    "failed to create temporary directory '{}'",
                    tmp.display()
                ),
                err
            )
        })?;

        Ok(Self { root, tmp, locks })
    }

    pub fn execute<F, T>(
        &self, scope: Option<&Ident>, op: F
    ) -> Result<T, SuperError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, SuperError>
    {
        let mut file_lock = FileLock::create(self.scope_lock_path(scope))?;
        let _write_lock = file_lock.write()?;
        op(&mut SuperTransaction::from(self))
    }

    /// Returns the path for the given key.
    fn key_path(&self, scope: Option<&Ident>, key: &Ident) -> PathBuf {
        let mut path = self.scope_path(scope);
        path.push(key.as_str());
        path
    }

    /// Returns the path for the given scope.
    fn scope_path(&self, scope: Option<&Ident>) -> PathBuf {
        let mut res = self.root.clone();
        if let Some(scope) = scope {
            res.push(scope.as_str());
        }
        res
    }

    /// Returns the lock file path for the given scope.
    fn scope_lock_path(&self, scope: Option<&Ident>) -> PathBuf {
        let mut res = self.locks.clone();
        if let Some(scope) = scope {
            res.push(scope.as_str());
        }
        res
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
    pub fn has(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<bool, Error> {
        self.key_path(scope, key).try_exists().map_err(|err| {
            Error::io(
                format!("failed to check existance of key '{key}'"),
                err
            )
        })
    }

    /// Returns whether the store contains the given scope.
    pub fn has_scope(&self, scope: &Ident) -> Result<bool, Error> {
        self.scope_path(Some(scope)).try_exists().map_err(|err| {
            Error::io(
                format!("failed to check existance of scope '{scope}'"),
                err
            )
        })
    }

    /// Returns the contents of the stored value with the given key.
    ///
    /// If the value does not exist, returns `Ok(None)?.
    pub fn get<T: DeserializeOwned>(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<T>, Error> {
        let path = self.key_path(scope, key);
        let file = match File::open(&path) {
            Ok(file) => io::BufReader::new(file),
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
                    Err(Error::deserialize(scope, key, err))
                }
            }
        }
    }

    pub fn get_any(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<Option<Value>, Error> {
        self.get(scope, key)
    }

    /// Returns all the keys in the given scope.
    pub fn list_keys(
        &self, scope: Option<&Ident>
    ) -> Result<Vec<Box<Ident>>, Error> {
        let path = self.scope_path(scope);
        let mut res = Vec::new();
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(res);
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
            if file_type.is_file() {
                if let Some(name) =
                    item.file_name().into_string().ok().and_then(|name| {
                        Ident::boxed_from_string(name).ok()
                    })
                {
                    res.push(name)
                }
            }
        }

        Ok(res)
    }

    /// Returns all the scopes in the score.
    ///
    pub fn list_scopes(&self) -> Result<Vec<Box<Ident>>, Error> {
        let mut res = Vec::new();
        let dir = match fs::read_dir(&self.root) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(res);
            }
            Err(err) => {
                return Err(Error::io(
                    format!(
                        "failed to read directory '{}'", self.root.display()
                    ),
                    err
                ));
            }
        };
        for item in dir {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    return Err(Error::io(
                        format!(
                            "failed to read directory '{}'",
                            self.root.display()
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
                            "failed to read directory '{}'",
                            self.root.display()
                        ),
                        err
                    ));
                }
            };
            if file_type.is_dir() {
                if let Some(name) =
                    item.file_name().into_string().ok().and_then(|name| {
                        Ident::boxed_from_string(name).ok()
                    })
                {
                    res.push(name)
                }
            }
        }

        Ok(res)
    }
}


/// # Writing
impl Store {
    /// Stores the provided value under the gvien key.
    ///
    /// Quietly overwrites a possibly already existing value.
    pub fn store<T: Serialize>(
        &self, scope: Option<&Ident>, key: &Ident, value: &T
    ) -> Result<(), Error> {
        let path = self.key_path(scope, key);

        Self::create_dirs(path.parent())?;

        // Write to a temporary file first to ensure that the file can be
        // written entirely.
        //
        // tempfile ensures that the temporary file is cleaned up in case it
        // would be left behind because of some issue.
        let mut tmp_file = NamedTempFile::new_in(&self.tmp).map_err(|err| {
            Error::io(
                format!(
                    "writing temp file failed for key: '{key}'"
                ),
                err,
            )
        })?;

        let res = serde_json::to_writer_pretty(
            &mut io::BufWriter::new(&mut tmp_file),
            value
        );
        if let Err(err) = res {
            if err.is_io() {
                return Err(Error::io(
                    format!(
                        "failed to write temp file '{}' for key '{}'",
                        tmp_file.as_ref().display(),
                        key
                    ),
                    err.into(),
                ))
            }
            else {
                return Err(Error::serialize(scope, key, err))
            }
        }

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

    pub fn store_any(
        &self, scope: Option<&Ident>, key: &Ident, value: &Value
    ) -> Result<(), Error> {
        self.store(scope, key, value)
    }

    /// Moves a value from one key to another.
    pub fn move_value(
        &self,
        from_scope: Option<&Ident>, from_key: &Ident,
        to_scope: Option<&Ident>, to_key: &Ident
    ) -> Result<(), Error> {
        let from_path = self.key_path(from_scope, from_key);
        let to_path = self.key_path(to_scope, to_key);

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
        &self, from: &Ident, to: &Ident
    ) -> Result<(), Error> {
        let from_path = self.scope_path(Some(from));
        let to_path = self.scope_path(Some(to));

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
    pub fn delete(
        &self, scope: Option<&Ident>, key: &Ident
    ) -> Result<(), Error> {
        let path = self.key_path(scope, key);

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
    pub fn delete_scope(&self, scope: &Ident) -> Result<(), Error> {
        let path = self.scope_path(Some(scope));

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
            .map_err(|e| Error::other(format!("Cannot get file lock: {e}")))
    }
}


//------------ Uri -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    path: PathBuf,
}

impl Uri {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn parse_uri(uri: &Url) -> Result<Option<Uri>, UriError> {
        if uri.scheme() != "file" && uri.scheme() != "local" {
            return Ok(None)
        }

        if !uri.authority().is_empty() {
            return Err(UriError::HasAuthority(uri.authority().into()))
        }

        Self::parse_str(uri.path()).map(Some)
    }

    pub fn parse_str(s: &str) -> Result<Uri, UriError> {
        let path = PathBuf::from(s);
        if !path.is_absolute() {
            return Err(UriError::RelativePath(path))
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "file://{}", self.path.display())
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
        scope: Option<Box<Ident>>,
        key: Box<Ident>,
        err: String,
    },
    Serialize {
        scope: Option<Box<Ident>>,
        key: Box<Ident>,
        err: String,
    },
    Other(String),
}

impl Error {
    fn io(context: impl Into<Cow<'static, str>>, err: io::Error) -> Self {
        Error::Io { context: context.into(), err }
    }

    fn deserialize(
        scope: Option<&Ident>, key: &Ident, err: impl fmt::Display
    ) -> Self {
        Error::Deserialize {
            scope: scope.map(Into::into),
            key: key.into(),
            err: err.to_string()
        }
    }

    fn serialize(
        scope: Option<&Ident>, key: &Ident, err: impl fmt::Display
    ) -> Self {
        Error::Serialize {
            scope: scope.map(Into::into),
            key: key.into(),
            err: err.to_string()
        }
    }

    fn other(info: impl Into<String>) -> Self {
        Error::Other(info.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io { context, err } => {
                write!(f, "{context}: {err}")
            }
            Error::Deserialize { scope, key, err } => {
                match scope {
                    Some(scope) => {
                        write!(f,
                            "failed to deserialize value for key '{key}' \
                            in scope '{scope}': {err}"
                        )
                    }
                    None => {
                        write!(f,
                            "failed to deserialize value for key '{key}' \
                            in global scope: {err}"
                        )
                    }
                }
            }
            Error::Serialize { scope, key, err } => {
                match scope {
                    Some(scope) => {
                        write!(f,
                            "failed to serialize value for key '{key}' \
                            in scope '{scope}': {err}"
                        )
                    }
                    None => {
                        write!(f,
                            "failed to serialize value for key '{key}' \
                            in global scope: {err}"
                        )
                    }
                }
            }
            Error::Other(s) => f.write_str(s)
        }
    }
}

impl error::Error for Error { }


//------------ UriError ------------------------------------------------------

#[derive(Debug)]
pub enum UriError {
    HasAuthority(String),
    MissingPath,
    RelativePath(PathBuf),
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
        }
    }
}

impl error::Error for UriError { }

