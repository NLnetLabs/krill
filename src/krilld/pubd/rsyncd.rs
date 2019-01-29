use std::{io, fs};
use std::path::PathBuf;
use rpki::uri;
use crate::api::publication;
use crate::krilld::pubd::RSYNC_FOLDER;
use crate::util::file::{self, CurrentFile, RecursorError};


//------------ FileStore -----------------------------------------------------

/// This type is responsible for publishing files on disk in a structure so
/// that an rscynd can be set up to serve this (RPKI) data. Note that the
/// rsync host name and module are part of the path, so make sure that the
/// rsyncd modules and paths are setup properly for each supported rsync
/// base uri used.
#[derive(Clone, Debug)]
pub struct FileStore {
    base_dir: PathBuf
}

/// # Construct
///
impl FileStore {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let mut rsync_dir = PathBuf::from(work_dir);
        rsync_dir.push(RSYNC_FOLDER);
        if ! rsync_dir.is_dir() {
            fs::create_dir_all(&rsync_dir)?;
        }
        Ok ( FileStore { base_dir: rsync_dir } )
    }
}

/// # Publishing
///
impl FileStore {
    /// Process a PublishQuery update
    pub fn publish(
        &mut self,
        delta: &publication::PublishDelta,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {
        self.verify_query(delta, base_uri)?;
        self.update_files(delta)?;

        Ok(())
    }

    pub fn list(
        &self,
        base_uri: &uri::Rsync
    ) -> Result<Vec<CurrentFile>, Error> {
        let path = self.path_for_publisher(base_uri);

        if !path.exists() {
            Ok(Vec::new())
        } else {
            file::crawl_incl_rsync_base(&path, base_uri)
                .map_err(|e| Error::RecursorError(e))
        }
    }

    /// Assert that all updates are confined to the given base_uri; i.e. do
    /// not allow publishers to update things outside of their own jail.
    ///
    /// Note this is done as a separate check, because there is a requirement
    /// that in case of any errors in an update, nothing is published. So,
    /// checking this first is a good enough form of a poor-man's transaction.
    fn verify_query(
        &self,
        delta: &publication::PublishDelta,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {

        for p in delta.publishes() {
            Self::assert_uri(base_uri, p.uri())?;
            if self.get_current_file_opt(p.uri()).is_some() {
                return Err(Error::ObjectAlreadyPresent(p.uri().clone()))
            }
        }

        for u in delta.updates() {
            Self::assert_uri(base_uri, u.uri())?;
            if let Some(cur) = self.get_current_file_opt(u.uri()) {
                if cur.hash() != u.hash() {
                    return Err(Error::NoObjectMatchingHash)
                }
            } else {
                return Err(Error::NoObjectPresent(u.uri().clone()))
            }
        }

        for w in delta.withdraws() {
            Self::assert_uri(base_uri, w.uri())?;
            if let Some(cur) = self.get_current_file_opt(w.uri()) {
                if cur.hash() != w.hash() {
                    return Err(Error::NoObjectMatchingHash)
                }
            } else {
                return Err(Error::NoObjectPresent(w.uri().clone()))
            }
        }

        debug!("Update is consistent with current state");
        Ok(())
    }

    /// Perform the actual updates on disk. This assumes that the updates
    /// have been verified. This can still blow up if there is an I/O issue
    /// writing to disk.
    fn update_files(
        &self,
        delta: &publication::PublishDelta
    ) -> Result<(), Error> {
        for p in delta.publishes() {
            debug!("Saving file for uri: {}", p.uri().to_string());
            file::save_with_rsync_uri(
                p.content(),
                &self.base_dir,
                p.uri()
            )?;
        }

        for u in delta.updates() {
            debug!("Updating file for uri: {}", u.uri().to_string());
            file::save_with_rsync_uri(
                u.content(),
                &self.base_dir,
                u.uri()
            )?;
        }

        for w in delta.withdraws() {
            debug!("Withdrawing file for uri: {}", w.uri().to_string());
            file::delete_with_rsync_uri(
                &self.base_dir,
                w.uri()
            )?;
        }

        Ok(())
    }

    fn assert_uri(base: &uri::Rsync, file: &uri::Rsync) -> Result<(), Error> {
        if base.module() == file.module() &&
            file.path().starts_with(base.path()) {
            Ok(())
        } else {
            Err(Error::OutsideBaseUri)
        }
    }

    fn get_current_file_opt(
        &self,
        file_uri: &uri::Rsync
    ) -> Option<CurrentFile> {
        match file::read_with_rsync_uri(&self.base_dir, file_uri) {
            Ok(bytes) => Some(CurrentFile::new(file_uri.clone(), bytes)),
            Err(_) => None
        }
    }

    // Returns the relative sub-dir that we should scan for this particular
    // publisher.
    fn path_for_publisher(&self, file_uri: &uri::Rsync) -> PathBuf {
        let mut path = self.base_dir.clone();
        let module = file_uri.module();
        path.push(PathBuf::from(module.authority()));
        path.push(PathBuf::from(module.module()));
        path.push(PathBuf::from(file_uri.path()));
        path
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    RecursorError(RecursorError),

    #[display(fmt="File already exists for uri (use update!): {}", _0)]
    ObjectAlreadyPresent(uri::Rsync),

    #[display(fmt="Np file present for uri: {}", _0)]
    NoObjectPresent(uri::Rsync),

    #[display(fmt="File does not match hash")]
    NoObjectMatchingHash,

    #[display(fmt="Publishing outside of base URI is not allowed.")]
    OutsideBaseUri,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<RecursorError> for Error {
    fn from(e: RecursorError) -> Self { Error::RecursorError(e) }
}
