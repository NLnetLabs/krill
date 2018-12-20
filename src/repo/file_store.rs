use std::{io, fs};
use std::path::PathBuf;
use rpki::uri;
use crate::file::{self, CurrentFile, RecursorError};
use crate::remote::publication::query::{PublishElement, PublishQuery};

pub const FS_FOLDER: &'static str = "rsync";

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
        rsync_dir.push(FS_FOLDER);
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
        update: &PublishQuery,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {
        self.verify_query(update, base_uri)?;
        self.update_files(update)?;

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
    fn verify_query(
        &self,
        update: &PublishQuery,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {
        for q in update.elements() {
            match q {
                PublishElement::Publish(p) => {
                    Self::assert_uri(base_uri, p.uri())?;
                    if self.get_current_file_opt(p.uri()).is_some() {
                        return Err(Error::ObjectAlreadyPresent(p.uri().clone()))
                    }
                },
                PublishElement::Update(u) => {
                    Self::assert_uri(base_uri, u.uri())?;
                    if let Some(cur) = self.get_current_file_opt(u.uri()) {
                        if cur.hash() != u.hash() {
                            return Err(Error::NoObjectMatchingHash)
                        }
                    } else {
                        return Err(Error::NoObjectPresent(u.uri().clone()))
                    }
                },
                PublishElement::Withdraw(w) => {
                    Self::assert_uri(base_uri, w.uri())?;
                    if let Some(cur) = self.get_current_file_opt(w.uri()) {
                        if cur.hash() != w.hash() {
                            return Err(Error::NoObjectMatchingHash)
                        }
                    } else {
                        return Err(Error::NoObjectPresent(w.uri().clone()))
                    }
                },
            }
        }

        debug!("Update is consistent with current state");
        Ok(())
    }

    /// Perform the actual updates on disk. This assumes that the updates
    /// have been verified.
    fn update_files(
        &self,
        update: &PublishQuery
    ) -> Result<(), Error> {
        for q in update.elements() {
            match q {
                PublishElement::Publish(p) => {
                    debug!("Saving file for uri: {}", p.uri().to_string());
                    file::save_with_rsync_uri(
                        p.object(),
                        &self.base_dir,
                        p.uri()
                    )?;
                },
                PublishElement::Update(u) => {
                    debug!("Updating file for uri: {}", u.uri().to_string());
                    file::save_with_rsync_uri(
                        u.object(),
                        &self.base_dir,
                        u.uri()
                    )?;
                },
                PublishElement::Withdraw(w) => {
                    debug!("Withdrawing file for uri: {}", w.uri().to_string());
                    file::delete_with_rsync_uri(
                        &self.base_dir,
                        w.uri()
                    )?;
                },
            }
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

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display="{}", _0)]
    RecursorError(RecursorError),

    #[fail(display="{}", _0)]
    UriError(uri::Error),

    #[fail(display="File already exists for uri (use update!): {}", _0)]
    ObjectAlreadyPresent(uri::Rsync),

    #[fail(display="Np file present for uri: {}", _0)]
    NoObjectPresent(uri::Rsync),

    #[fail(display="File does not match hash")]
    NoObjectMatchingHash,

    #[fail(display="Publishing outside of base URI is not allowed.")]
    OutsideBaseUri,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use test;

    #[test]
    fn should_store_list_withdraw_files() {
        test::test_with_tmp_dir(|d| {
            let mut file_store = FileStore { base_dir: d };

            // Using a port here to make sure that it works in mapping
            // the rsync URI to and from disk.
            let base_uri = test::rsync_uri
                ("rsync://host:10873/module/alice/");

            // Publish a file
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishQuery::build();
            builder.add(file.clone().as_publish());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            file_store.publish(&publish, &base_uri).unwrap();

            // See that it's the only one listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(1, files.len());
            assert!(files.contains(&file));

            // Update a file
            let file_update = CurrentFile::new(
                file.uri().clone(),
                Bytes::from("example updated content")
            );

            let mut builder = PublishQuery::build();
            builder.add(file_update.clone().as_update(file.content()));
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();
            file_store.publish(&publish, &base_uri).unwrap();

            // See that it's the only one listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(1, files.len());
            assert!(files.contains(&file_update));

            // Withdraw a file
            let mut builder = PublishQuery::build();
            builder.add(file_update.as_withdraw());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();
            file_store.publish(&publish, &base_uri).unwrap();

            // See that there are no files listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(0, files.len());
        });
    }

    #[test]
    fn should_not_allow_publishing_or_withdrawing_outside_of_base() {
        test::test_with_tmp_dir(|d| {
            let mut file_store = FileStore { base_dir: d };

            // Using a port here to make sure that it works in mapping
            // the rsync URI to and from disk.
            let base_uri = test::rsync_uri
                ("rsync://host:10873/module/alice/");

            // Publish a file
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/bob/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishQuery::build();
            builder.add(file.clone().as_publish());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            match file_store.publish(&publish, &base_uri) {
                Err(Error::OutsideBaseUri) => {},
                _ => { panic!("Expected Error::OutsideBaseUri") }
            }
        });
    }


}
