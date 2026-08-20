use std::{error, fmt, fs, io};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use url::Url;
use super::combined::{
    StoreError,
    Transaction as SuperTransaction
};
use super::statements::{
    ManipulationStatement, QueryOneStatement, QueryOptStatement,
    QueryStatement,
};


//------------ Constants -----------------------------------------------------

/// The directory under the root that contains temporary files.
const TMP_FILE_DIR: &str = ".tmp";


//------------ Uri -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    path: PathBuf,
}

impl Uri {
    pub fn parse_uri(uri: &Url) -> Result<Option<Self>, UriError> {
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


//------------ System --------------------------------------------------------

#[derive(Debug, Default)]
pub struct System(());

impl System {
    pub fn new(_tokio: &tokio::runtime::Handle) -> Self {
        Self(())
    }

    pub fn open(&self, uri: &Uri) -> Result<Store, Error> {
        Store::new(uri.path.clone())
    }
}


//------------ Store ---------------------------------------------------------

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
}

impl Store {
    fn new(
        root: PathBuf,
    ) -> Result<Self, Error> {
        let tmp = root.join(TMP_FILE_DIR);

        fs::create_dir_all(&tmp).map_err(|err| {
            Error::io(
                format!(
                    "failed to create temporary directory '{}'",
                    tmp.display()
                ),
                err
            )
        })?;

        Ok(Self { root, tmp })
    }

    pub fn execute<F, T>(
        &self, op: F
    ) -> Result<T, StoreError>
    where
        F: for<'a> Fn(&mut SuperTransaction<'a>) -> Result<T, StoreError>
    {
        op(&mut (Transaction::new(self).into()))
    }
}


//------------ Transaction ---------------------------------------------------

#[derive(Debug)]
pub struct Transaction<'a>(&'a Store);

impl<'a> Transaction<'a> {
    fn new(store: &'a Store) -> Self {
        Self(store)
    }

    pub fn manipulate<S: ManipulationStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<u64, StoreError> {
        Ok(S::run_disk(params, &mut DiskStore(self.0))?)
    }

    pub fn query<S: QueryStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<Vec<S::Row>, StoreError> {
        Ok(S::run_disk(params, &mut DiskStore(self.0))?)
    }

    pub fn query_one<S: QueryOneStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<S::Row, StoreError> {
        Ok(S::run_disk(params, &mut DiskStore(self.0))?)
    }

    pub fn query_opt<S: QueryOptStatement>(
        &mut self, params: S::Params<'_>
    ) -> Result<Option<S::Row>, StoreError> {
        Ok(S::run_disk(params, &mut DiskStore(self.0))?)
    }
}


//------------ DiskStore -----------------------------------------------------

pub struct DiskStore<'a>(&'a Store);

impl<'a> DiskStore<'a> {
    pub fn root(&self) -> &Path {
        &self.0.root
    }

    pub fn tmp(&self) -> &Path {
        &self.0.tmp
    }
}



//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Io {
        context: Cow<'static, str>,
        err: io::Error,
    },
    Other(Box<dyn error::Error>),
}

impl Error {
    pub fn io(context: impl Into<Cow<'static, str>>, err: io::Error) -> Self {
        Error::Io { context: context.into(), err }
    }

    pub fn other(info: impl Into<Box<dyn error::Error>>) -> Self {
        Error::Other(info.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io { context, err } => {
                write!(f, "{context}: {err}")
            }
            Error::Other(s) => s.fmt(f)
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


