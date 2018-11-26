use std::io;
use std::io::{Read, Write};
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use bytes::Bytes;
use repo::file::CurrentFile;
use rpki::publication::query::PublishElement;
use rpki::publication::query::PublishQuery;
use rpki::uri;

#[derive(Clone, Debug)]
pub struct FileStore {
    base_dir: PathBuf
}

/// # Construct
///
impl FileStore {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let mut rsync_dir = PathBuf::from(work_dir);
        rsync_dir.push("rsync");
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
    pub fn update(
        &self,
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
        let path = self.file_path(base_uri);
        self.recurse_disk(&path)
    }

    fn recurse_disk(
        &self,
        path: &PathBuf
    ) -> Result<Vec<CurrentFile>, Error> {
        let mut res = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let mut other = self.recurse_disk(&path)?;
                res.append(& mut other);
            } else {
                if let Some(file) = self.read_file(&path)? {
                    res.push(file);
                }
            }
        }

        Ok(res)
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
                    if self.get_current_file_opt(p.uri())?.is_some() {
                        return Err(Error::PublishWrongUri(p.uri().clone()))
                    }
                },
                PublishElement::Update(u) => {
                    Self::assert_uri(base_uri, u.uri())?;
                    if let Some(cur) = self.get_current_file_opt(u.uri())? {
                        if cur.hash() != u.hash() {
                            return Err(Error::UpdateWrongHash)
                        }
                    } else {
                        return Err(Error::UpdateWrongUri(u.uri().clone()))
                    }
                },
                PublishElement::Withdraw(w) => {
                    Self::assert_uri(base_uri, w.uri())?;
                    if let Some(cur) = self.get_current_file_opt(w.uri())? {
                        if cur.hash() != w.hash() {
                            return Err(Error::WithdrawWrongHash)
                        }
                    } else {
                        return Err(Error::UpdateWrongUri(w.uri().clone()))
                    }
                },
            }
        }

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
                    self.save_file(p.uri(), p.object())?;
                },
                PublishElement::Update(u) => {
                    self.save_file(u.uri(), u.object())?;
                },
                PublishElement::Withdraw(w) => {
                    self.delete_file(w.uri())?;
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

    fn file_path(&self, file_uri: &uri::Rsync) -> PathBuf {
        let mut path = self.base_dir.clone();
        let module = file_uri.module();
        path.push(PathBuf::from(module.authority()));
        path.push(PathBuf::from(module.module()));
        path.push(PathBuf::from(file_uri.path()));
        path
    }

    /// Resolves a path on disk to an rsync uri (i.e. relative to base)
    fn file_uri(&self, path: &PathBuf) -> Result<uri::Rsync, Error> {
        let base_string = self.base_dir.to_string_lossy().to_string();
        let mut path_string = path.to_string_lossy().to_string();

        if path_string.as_str().starts_with(base_string.as_str()) {
            let rel = path_string.split_off(base_string.len());
            let uri = format!("rsync:/{}", rel);
            let uri = uri::Rsync::from_string(uri)?;
            Ok(uri)
        } else {
            panic!("This is a bug: we are looking for a file outside of our\
             base directory")
        }
    }

    fn save_file(
        &self,
        file_uri: &uri::Rsync,
        content: &Bytes
    ) -> Result<(), Error> {
        let path = self.file_path(file_uri);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut f = File::create(path)?;
        f.write(content)?;
        Ok(())
    }

    fn delete_file(
        &self,
        file_uri: &uri::Rsync
    ) -> Result<(), Error> {
        let path = self.file_path(file_uri);
        fs::remove_file(path)?;
        Ok(())
    }

    fn read_file(
        &self,
        path: &PathBuf
    ) -> Result<Option<CurrentFile>, Error> {
        match File::open(path) {
            Err(_)  => Ok(None),
            Ok(mut f) => {
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes)?;
                let content = Bytes::from(bytes);
                Ok(Some(
                    CurrentFile::new(
                        self.file_uri(path)?,
                        content
                )))
            }
        }
    }

    fn get_current_file_opt(
        &self,
        file_uri: &uri::Rsync
    ) -> Result<Option<CurrentFile>, Error> {
        let path = self.file_path(file_uri);
        self.read_file(&path)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display="{}", _0)]
    UriError(uri::Error),

    #[fail(display="File already exists for uri (use update!): {}", _0)]
    PublishWrongUri(uri::Rsync),

    #[fail(display="File sent for update has no entry for uri: {}", _0)]
    UpdateWrongUri(uri::Rsync),

    #[fail(display="File for update exists, but hash does not match")]
    UpdateWrongHash,

    #[fail(display="The withdraw URI is not known: {}", _0)]
    WithdrawWrongUri(uri::Rsync),

    #[fail(display="File for withdraw exists, but hash does not match")]
    WithdrawWrongHash,

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
            let file_store = FileStore { base_dir: d };

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

            file_store.update(&publish, &base_uri).unwrap();

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
            file_store.update(&publish, &base_uri).unwrap();

            // See that it's the only one listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(1, files.len());
            assert!(files.contains(&file_update));

            // Withdraw a file
            let mut builder = PublishQuery::build();
            builder.add(file_update.as_withdraw());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();
            file_store.update(&publish, &base_uri).unwrap();

            // See that there are no files listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(0, files.len());
        });
    }

    #[test]
    fn should_not_allow_publishing_or_withdrawing_outside_of_base() {
        test::test_with_tmp_dir(|d| {
            let file_store = FileStore { base_dir: d };

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

            match file_store.update(&publish, &base_uri) {
                Err(Error::OutsideBaseUri) => {},
                _ => { panic!("Expected Error::OutsideBaseUri") }
            }
        });
    }


}