use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use ext_serde;
use rpki::uri;
use rpki::publication;
use storage::caching_ks::CachingDiskKeyStore;
use storage::keystore::{ self, Info, Key, KeyStore };
use rpki::publication::query::PublishQuery;
use rpki::publication::query::PublishElement;
use rpki::publication::query::Update;
use rpki::publication::query::Publish;
use rpki::publication::query::Withdraw;


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

    pub fn get_publisher(
        &self,
        publisher_handle: &str
    ) -> Result<Arc<RepoPublisher>, Error> {
        let key = Key::from_str(publisher_handle);
        if let Some(repo_publisher) = self.store.get(&key)? {
            Ok(repo_publisher)
        } else {
            Err(Error::UnknownPublisher(publisher_handle.to_string()))
        }
    }
}

/// # Publish / Withdraw
///
impl Repository {
    pub fn publish(
        &mut self,
        publisher_handle: &str,
        query: PublishQuery
    ) -> Result<(), Error> {
        let rp = self.get_publisher(publisher_handle)?;
        let updated_rp = rp.publish(query)?;
        let key = Key::from_str(&rp.publisher_handle);
        let inf = Info::now(
            actor(),
            "Updated files".to_string()
        );
        self.store.store(key, updated_rp, inf)?;
        Ok(())
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

    pub fn current_files(&self) -> &Vec<CurrentFile> {
        &self.files
    }

    fn process_update(
        list: &mut Vec<CurrentFile>,
        update: &Update
    ) -> Result<(), Error> {
        if let Some(entry) = list.iter().find(
            |f| {&f.uri == update.uri() }
        ) {
            if entry.hash != update.hash() {
                return Err(Error::UpdateWrongHash)
            }
        } else {
            return Err(Error::UpdateWrongUri(update.uri().clone()))
        }

        list.retain(|e| { &e.uri != update.uri() });
        let new_entry = CurrentFile::new(
            update.uri().clone(),
            update.object().clone()
        );
        list.push(new_entry);
        Ok(())

    }

    fn process_publish(
        list: &mut Vec<CurrentFile>,
        publish: &Publish
    ) -> Result<(), Error> {
        if let Some(entry) = list.iter().find(
            |f| {&f.uri == publish.uri() }
        ) {
            return Err(Error::PublishHasExistingUri(entry.uri.clone()))
        }
        let new_entry = CurrentFile::new(
            publish.uri().clone(),
            publish.object().clone()
        );
        list.push(new_entry);
        Ok(())
    }

    fn process_withdraw(
        list: &mut Vec<CurrentFile>,
        withdraw: &Withdraw
    ) -> Result<(), Error> {
        if let Some(entry) = list.iter().find(
            |f| {&f.uri == withdraw.uri() }
        ) {
            if entry.hash != withdraw.hash() {
                return Err(Error::WithdrawWrongHash)
            }
        } else {
            return Err(Error::WithdrawWrongUri(withdraw.uri().clone()))
        }

        list.retain(|e| { &e.uri != withdraw.uri() });
        Ok(())
    }

    fn assert_uri(base: &uri::Rsync, file: &uri::Rsync) -> Result<(), Error> {
        if base.module() == file.module() &&
           file.path().starts_with(base.path())
        {
            Ok(())
        } else {
            Err(Error::OutsideBaseUri)
        }

    }

    /// Returns a new RepoPublisher with an updated list of files.
    ///
    /// Note that RepoPublishers are stored as versioned immutable (Arc)
    /// in the keystore, and therefore a new instance is needed whenever
    /// there is a change.
    pub fn publish(&self, query: PublishQuery) -> Result<Self, Error> {

        let mut new_list = self.files.clone();

        for el in query.elements() {
            match el {
                PublishElement::Publish(p) => {
                    Self::assert_uri(&self.base_uri, p.uri())?;
                    Self::process_publish(&mut new_list, p)?;
                },
                PublishElement::Update(u) => {
                    Self::assert_uri(&self.base_uri, u.uri())?;
                    Self::process_update(&mut new_list, u)?;
                },
                PublishElement::Withdraw(w) => {
                    Self::assert_uri(&self.base_uri, w.uri())?;
                    Self::process_withdraw(&mut new_list, w)?;
                },
            }
        }

        Ok(RepoPublisher {
            publisher_handle: self.publisher_handle.clone(),
            base_uri: self.base_uri.clone(),
            files: new_list
        })
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
    /// The actual file content. Note that we may want to store this
    /// only on disk in future (look up by sha256 hash), to save memory.
    content: Bytes,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    /// The sha-256 hash of the file (as is used on the RPKI manifests and
    /// in the publication protocol for list, update and withdraw). Saving
    /// this rather than calculating on demand seems a small price for some
    /// performance gain.
    hash:    Bytes
}

impl CurrentFile {
    pub fn new(uri: uri::Rsync, content: Bytes) -> Self {
        let hash = publication::hash(&content);
        CurrentFile {uri, content, hash}
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Bytes {
        &self.content
    }

    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn as_publish(&self) -> PublishElement {
        Publish::publish(&self.content, self.uri.clone())
    }

    pub fn as_update(&self, old_content: &Bytes) -> PublishElement {
        Update::publish(old_content, &self.content, self.uri.clone())
    }

    pub fn as_withdraw(&self) -> PublishElement {
        Withdraw::publish(&self.content, self.uri.clone())
    }
}

impl PartialEq for CurrentFile {
    fn eq(&self, other: &CurrentFile) -> bool {
        self.uri == other.uri &&
        self.hash == other.hash &&
        self.content == other.content
    }
}

impl Eq for CurrentFile {}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="Unknown publisher: {}", _0)]
    UnknownPublisher(String),

    #[fail(display="File already exists for uri (use update!): {}", _0)]
    PublishHasExistingUri(uri::Rsync),

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

    #[test]
    fn should_add_list_remove_files() {
        test::test_with_tmp_dir(|d| {

            let mut repo = Repository::new(&d).unwrap();
            let alice = RepoPublisher::new(
                "alice".to_string(),
                test::rsync_uri("rsync://host/module/alice/")
            );

            repo.add_publisher(alice).unwrap();

            let alice = repo.get_publisher("alice").unwrap();
            let files = alice.current_files();
            assert_eq!(0, files.len());

            let file = CurrentFile::new(
                test::rsync_uri("rsync://host/module/alice/file.txt"),
                Bytes::from("example content")
            );

            //--------- Add a single file
            let mut builder = PublishQuery::build();
            builder.add(file.clone().as_publish());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            repo.publish("alice", publish.clone()).unwrap();

            let alice = repo.get_publisher("alice").unwrap();
            let files = alice.current_files();
            assert_eq!(1, files.len());

            // Can't publish the same thing again, should then update!
            assert!(repo.publish("alice", publish).is_err());

            //--------- Update a single file
            let file_update = CurrentFile::new(
                file.uri().clone(),
                Bytes::from("example updated content")
            );

            let mut builder = PublishQuery::build();
            builder.add(file_update.clone().as_update(file.content()));
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            repo.publish("alice", publish.clone()).unwrap();

            let alice = repo.get_publisher("alice").unwrap();
            let files = alice.current_files();
            assert_eq!(1, files.len());

            //--------- Withdraw a single file
            let mut builder = PublishQuery::build();
            builder.add(file_update.as_withdraw());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            repo.publish("alice", publish.clone()).unwrap();

            let alice = repo.get_publisher("alice").unwrap();
            let files = alice.current_files();
            assert_eq!(0, files.len());
        });
    }

    #[test]
    fn should_not_allow_publishing_or_withdrawing_outside_of_base() {
        test::test_with_tmp_dir(|d| {

            let mut repo = Repository::new(&d).unwrap();
            let alice = RepoPublisher::new(
                "alice".to_string(),
                test::rsync_uri("rsync://host/module/alice/")
            );

            repo.add_publisher(alice).unwrap();

            let alice = repo.get_publisher("alice").unwrap();
            let files = alice.current_files();
            assert_eq!(0, files.len());

            let file = CurrentFile::new(
                test::rsync_uri("rsync://host/module/bob/file.txt"),
                Bytes::from("example content")
            );

            //--------- Add a single file
            let mut builder = PublishQuery::build();
            builder.add(file.clone().as_publish());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            assert!(repo.publish("alice", publish.clone()).is_err());
        });
    }

}