use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use ext_serde;
use rpki::uri;
use storage::caching_ks::CachingDiskKeyStore;
use storage::keystore::{ self, Info, Key, KeyStore };


/// # Naming things in the keystore.
fn actor() -> String {
    "publication server".to_string()
}

//------------ Repository ----------------------------------------------------

/// This type stores all files for each configured publisher, and makes them
/// available to relying parties through RRDP, and by storing the files on
/// disk in a folder that may be exposed by an rsync daemon.
pub struct Repository {
    store: CachingDiskKeyStore
}

/// # Construct
///
impl Repository {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let mut repo_data_dir = PathBuf::from(work_dir);
        repo_data_dir.push("repo_data");
        if ! repo_data_dir.is_dir() {
            fs::create_dir_all(&repo_data_dir)?;
        }

        let store = CachingDiskKeyStore::new(repo_data_dir)?;
        Ok( Repository { store } )
    }
}

/// # Publishers
///
impl Repository {
    pub fn add_publisher(
        &mut self,
        repo_publisher: RepoPublisher
    ) -> Result<(), Error> {
        let key = Key::from_str(repo_publisher.publisher_handle.as_str());
        let inf = Info::now(
            actor(),
            format!("Added publisher: {}", repo_publisher.publisher_handle.as_str())
        );
        self.store.store(key, repo_publisher, inf)?;
        Ok(())
    }

    pub fn remove_publisher(
        &mut self,
        publisher_handle: &str
    ) -> Result<(), Error> {
        let key = Key::from_str(publisher_handle);
        let inf = Info::now(
            actor(),
            format!("Removed publisher: {}", publisher_handle)
        );
        self.store.archive(&key, inf)?;
        Ok(())
    }

    pub fn publishers(&self) -> Result<Vec<Arc<RepoPublisher>>, Error> {
        let mut res = Vec::new();

        for ref key in self.store.keys() {
            if let Some(arc) = self.store.get(key)? {
                res.push(arc);
            }
        }

        Ok(res)
    }
}


//------------ RepoPublisher -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoPublisher {
    publisher_handle:       String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:   uri::Rsync,

    files:      Vec<CurrentFile>
}

impl RepoPublisher {
    pub fn new(name: String, base_uri: uri::Rsync) -> Self {
        let files = Vec::new();
        RepoPublisher {
            publisher_handle: name,
            base_uri,
            files
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentFile {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    uri:     uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    content: Bytes
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
}



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test;

    #[test]
    fn should_add_and_remove_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut repo = Repository::new(&d).unwrap();
            let alice = RepoPublisher::new(
                "alice".to_string(),
                test::rsync_uri("rsync://host/module/alice/")
            );

            repo.add_publisher(alice).unwrap();

            let publishers = repo.publishers().unwrap();
            assert_eq!(1, publishers.len());

            repo.remove_publisher("alice").unwrap();

            let publishers = repo.publishers().unwrap();
            assert_eq!(0, publishers.len());
        })

    }

}