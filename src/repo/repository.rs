use std::path::PathBuf;
use rpki::uri;
use repo::publisher_store::PublisherStore;
use repo::file_store::FileStore;
use repo::publisher_store;
use repo::file_store;


//------------ Repository ----------------------------------------------------

/// This type orchestrates the management of publishers that are allowed to
/// publish, as well as making the published content available (1) on disk
/// in a format that lends itself to being exposed by rsyncd, and (2)
/// include it in notification, snapshot and delta filed for RRDP.
#[derive(Clone, Debug)]
pub struct Repository {
    // publisher_store
    ps: PublisherStore,
    // file_store
    fs: FileStore

    // XXX TODO: rrdp..
}

/// # Construct
///
impl Repository {
    pub fn new(work_dir: &PathBuf, base_uri: &uri::Rsync) -> Result<Self, Error> {
        let ps = PublisherStore::new(work_dir, base_uri)?;
        let fs = FileStore::new(work_dir)?;

        Ok( Repository { ps, fs } )
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    PublisherStoreError(publisher_store::Error),

    #[fail(display="{}", _0)]
    FileStoreError(file_store::Error),
}

impl From<publisher_store::Error> for Error {
    fn from(e: publisher_store::Error) -> Self {
        Error::PublisherStoreError(e)
    }
}

impl From<file_store::Error> for Error {
    fn from(e: file_store::Error) -> Self {
        Error::FileStoreError(e)
    }
}
