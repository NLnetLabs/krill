use std::path::PathBuf;
use repo::file_store::{self, FileStore};


//------------ Repository ----------------------------------------------------

/// This type orchestrates publishing in both an RSYNC and RRDP (todo)
/// friendly format.
#[derive(Clone, Debug)]
pub struct Repository {
    // file_store
    fs: FileStore

    // XXX TODO: rrdp..
}

/// # Construct
///
impl Repository {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let fs = FileStore::new(work_dir)?;
        Ok( Repository { fs } )
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    FileStoreError(file_store::Error),
}

impl From<file_store::Error> for Error {
    fn from(e: file_store::Error) -> Self {
        Error::FileStoreError(e)
    }
}
