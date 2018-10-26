//! Responsible for storing and retrieving Publisher information.
use std::fs;
use std::io;
use std::path::PathBuf;
use provisioning::publisher::Publisher;
use rpki::remote::idcert::IdCert;
use rpki::uri;
use rpki::oob::exchange::PublisherRequest;
use storage::keystore::{self, Info, Key, KeyStore};
use storage::caching_ks::CachingDiskKeyStore;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use rpki::oob::exchange::PublisherRequestError;


//------------ PublisherList -------------------------------------------------

/// This type contains all configured Publishers, allowed to publish at this
/// publication server. Essentially this wraps around the storage that
/// contains all current publishers, and keeps a full audit trail of changes
/// to this.
#[derive(Debug)]
pub struct PublisherList {
    store: CachingDiskKeyStore,
    base_uri: uri::Rsync,
}


impl PublisherList {
    pub fn new(
        work_dir: String,
        base_uri: uri::Rsync
    ) -> Result<Self, Error> {
        let meta_data = fs::metadata(&work_dir)?;
        if meta_data.is_dir() {

            let mut publisher_dir = PathBuf::from(work_dir);
            publisher_dir.push("publishers");
            if ! publisher_dir.is_dir() {
                fs::create_dir_all(&publisher_dir)?;
            }

            Ok(
                PublisherList {
                    store: CachingDiskKeyStore::new(publisher_dir)?,
                    base_uri
                }
            )
        } else {
            panic!("Invalid base_dir for DiskKeyStore")
        }
    }

    /// Adds a Publisher based on a PublisherRequest (from the RFC 8183 xml).
    ///
    /// Will return an error if the publisher already exists! Use
    /// update_publisher in case you want to update an existing publisher.
    pub fn add_publisher(
        &self,
        pr: PublisherRequest,
        actor: String
    ) -> Result<(), Error> {
        let (_, name, id_cert) = pr.into_parts();

        if name.contains("/") {
            return Err(
                Error::ForwardSlashInHandle(name))
        }

        if self.has_publisher(&name) {
            return Err(
                Error::DuplicatePublisher(name)
            )
        }

        let mut base_uri = self.base_uri.to_string();
        base_uri.push_str(name.as_ref());
        let base_uri = uri::Rsync::from_string(base_uri)?;

        let key = Key::from_str(name.as_ref());
        let info = Info::now(
            actor,
            format!("Added publisher: {}", &name)
        );
        let publisher = Publisher::new(name, base_uri, id_cert);

        self.store.store(key, publisher, info)?;

        Ok(())
    }

    /// Removes a publisher with a given name.
    ///
    /// Will return an error if ths publisher does not exist.
    pub fn remove_publisher(
        &self,
        name: &str,
        actor: String
    ) -> Result<(), Error> {
        match self.publisher(name)? {
            None => Err(Error::UnknownPublisher(name.to_string())),
            Some(_p) => {
                let key = Key::from_str(name);

                let info = Info::now(
                    actor,
                    format!("Removed publisher: {}", name)
                );

                self.store.archive(&key, info)?;
                Ok(())
            }
        }
    }


    /// Updates the IdCert for a known publisher.
    pub fn update_id_cert_publisher(
        &self,
        name: &str,
        id_cert: IdCert,
        actor: String
    ) -> Result<(), Error> {
        let publisher_opt = self.publisher(name)?;

        match publisher_opt {
            None => Err(Error::UnknownPublisher(name.to_string())),
            Some(publisher) => {
                let key = Key::from_str(name);
                let new_publisher = publisher.with_new_id_cert(id_cert);
                let info = Info::now(
                    actor,
                    "Updated the IdCert".to_string()
                );

                self.store.store(key, new_publisher, info)?;

                Ok(())
            }
        }
    }

    /// Returns whether a publisher exists for this name.
    pub fn has_publisher(&self, name: &str) -> bool {
        let key = Key::from_str(name);
        match self.store.version(&key) {
            Ok(Some(_)) => true,
            _ => false
        }
    }

    /// Returns an Optional Arc to a publisher for this name.
    pub fn publisher(
        &self,
        name: &str
    ) -> Result<Option<Arc<Publisher>>, Error> {
        let key = Key::from_str(name);
        self.store.get(&key).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Returns all current publishers. Note: using a Vec here is
    /// relatively expensive, however, it is easy to implement and debug, and
    /// this method is rarely needed - mainly for tests and to rebuild/update
    /// the publisher list at start up.
    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        let mut res = Vec::new();

        for ref k in self.store.keys() {
            if let Some(arc) = self.store.get(k)? {
                res.push(arc);
            }
        }

        Ok(res)
    }

}


/// # Initialise from disk
impl PublisherList {
    /// Synchronizes the list of Publisher based on request XML files on disk.
    /// Will add new publishers, remove removed publisher, and update the
    /// id_cert in case it was updated. Returns an error in case duplicate
    /// handler names are found in XML files in the directory.
    pub fn sync_from_dir(
        &self,
        dir: PathBuf,
        actor: String
    ) -> Result<(), Error> {
        // Find all the publisher requests on disk
        let prs_on_disk = self.prs_on_disk(dir)?;
        self.process_removed_publishers(&prs_on_disk, &actor)?;

        for (handle, pr) in prs_on_disk {
            match self.publisher(&handle)? {
                None => {
                    self.add_publisher(pr, actor.clone())?;
                }
                Some(p) => {
                    if p.id_cert() != pr.id_cert() {
                        let (_tag, name, id_cert) = pr.into_parts();
                        self.update_id_cert_publisher(
                            &name,
                            id_cert,
                            actor.clone()
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    fn process_removed_publishers(
        &self,
        prs_on_disk: &HashMap<String, PublisherRequest>,
        actor: &String
    ) -> Result<(), Error> {
        let current = self.publishers()?;
        for c in current {
            if prs_on_disk.get(c.name()).is_none() {
                self.remove_publisher(c.name(), actor.clone())?;
            }
        }
        Ok(())
    }

    fn prs_on_disk(
        &self,
        dir: PathBuf
    ) -> Result<HashMap<String, PublisherRequest>, Error> {
        let mut prs_on_disk = HashMap::new();
        for e in dir.read_dir()? {
            let file = e?;
            if let Some(file_name) = file.file_name().to_str() {
                if file_name.ends_with(".xml") {
                    let f = File::open(file.path().display().to_string())?;
                    let mut r = BufReader::new(f);

                    let pr = PublisherRequest::decode(r)?;

                    let handle = pr.handle().clone();
                    if prs_on_disk.get(&handle).is_some() {
                        return Err(Error::DuplicatePublisher(handle))
                    } else {
                        prs_on_disk.insert(pr.handle().clone(), pr);
                    }
                }
            }
        }
        Ok(prs_on_disk)
    }
}





//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display =
        "The '/' in publisher_handle ({}) is not supported - because we \
        are deriving the base directory for a publisher from this. This \
        behaviour may be updated in future.", _0)]
    ForwardSlashInHandle(String),

    #[fail(display = "Duplicate publisher with name: {}.", _0)]
    DuplicatePublisher(String),

    #[fail(display = "Unknown publisher with name: {}.", _0)]
    UnknownPublisher(String),

    #[fail(display = "Error in base URI: {}.", _0)]
    UriError(uri::Error),

    #[fail(display = "Invalide Publisher Request: {}.", _0)]
    PublisherRequestError(PublisherRequestError)
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
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

impl From<PublisherRequestError> for Error {
    fn from(e: PublisherRequestError) -> Self {
        Error::PublisherRequestError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use test;
    use std::fs::File;
    use std::io::Write;

    fn new_pl(dir: String) -> PublisherList {
        let uri = test::rsync_uri("rsync://host/module/");
        PublisherList::new(dir, uri).unwrap()
    }

    #[test]
    fn should_refuse_slash_in_publisher_handle() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);
            let pr = test::new_publisher_request("test/below");

            match pl.add_publisher(pr, "test".to_string()) {
                Err(Error::ForwardSlashInHandle(_)) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })
    }

    #[test]
    fn should_add_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);
            let name = "alice";
            let pr = test::new_publisher_request(name);
            let id_cert = pr.id_cert().clone();
            let actor = "test".to_string();

            pl.add_publisher(pr, actor).unwrap();

            assert!(pl.has_publisher(&name));

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = pl.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                name.to_string(),
                test::rsync_uri(&format!("rsync://host/module/{}", name)),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

    #[test]
    fn should_update_id_cert_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);
            let name = "alice";
            let pr = test::new_publisher_request(name);
            let actor = "test".to_string();

            pl.add_publisher(pr, actor.clone()).unwrap();

            // Make a new publisher request for alice, using a new cert
            let pr = test::new_publisher_request(name);
            let id_cert = pr.id_cert().clone();

            pl.update_id_cert_publisher(
                name,
                id_cert.clone(),
                actor.clone()
            ).unwrap();

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = pl.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                name.to_string(),
                test::rsync_uri(&format!("rsync://host/module/{}", name)),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

    #[test]
    fn should_remove_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);

            let name = "alice";
            let actor = "test".to_string();
            let pr = test::new_publisher_request(name);

            pl.add_publisher(pr, actor.clone()).unwrap();
            assert_eq!(1, pl.publishers().unwrap(). len());

            pl.remove_publisher(name, actor).unwrap();
            assert_eq!(0, pl.publishers().unwrap(). len());
        });
    }

    fn save_pr(base_dir: &str, file_name: &str, pr: &PublisherRequest) {
        let full_name = PathBuf::from(format!("{}/{}", base_dir, file_name));
        let mut f = File::create(full_name).unwrap();
        let xml = pr.encode_vec();
        f.write(xml.as_ref()).unwrap();
    }

    fn find_in_list(
        name: &str,
        publishers: &Vec<Arc<Publisher>>
    ) -> Option<Arc<Publisher>> {
        publishers.iter().find(|e| {e.name() == name }).map(|e| {e.clone()})
    }

    #[test]
    fn should_sync_publisher_requests() {
        test::test_with_tmp_dir(|d|{

            let pl_dir = test::create_sub_dir(&d);
            let mut pl = new_pl(pl_dir);

            let actor = "test".to_string();

            //
            // Start with two PRs for alice and bob
            let start_sync_dir = test::create_sub_dir(&d);
            let pr_alice = test::new_publisher_request("alice");
            let pr_bob   = test::new_publisher_request("bob");
            save_pr(&start_sync_dir, "alice.xml", &pr_alice);
            save_pr(&start_sync_dir, "bob.xml", &pr_bob);

            pl.sync_from_dir(
                PathBuf::from(start_sync_dir),
                actor.clone()
            ).unwrap();

            let publishers = pl.publishers().unwrap();
            assert_eq!(2, publishers.len());

            assert!(find_in_list("alice", &publishers).is_some());
            assert!(find_in_list("bob", &publishers).is_some());

            //
            // Now update
            //  remove alice
            //  update the id_cert for bob
            //  add carol
            let updated_sync_dir = test::create_sub_dir(&d);
            let pr_bob_2 = test::new_publisher_request("bob");
            let pr_carol = test::new_publisher_request("carol");
            save_pr(&updated_sync_dir, "bob.xml", &pr_bob_2);
            save_pr(&updated_sync_dir, "carol.xml", &pr_carol);
            pl.sync_from_dir(
                PathBuf::from(updated_sync_dir),
                actor.clone()
            ).unwrap();

            let publishers = pl.publishers().unwrap();
            assert_eq!(2, publishers.len());

            assert!(find_in_list("alice", &publishers).is_none());
            assert!(find_in_list("bob", &publishers).is_some());
            assert_eq!(
                find_in_list("bob", &publishers).unwrap().id_cert(),
                pr_bob_2.id_cert()
            );
            assert!(find_in_list("carol", &publishers).is_some());

            //
            // Now do a dir with a duplicate handle, this should
            // result in an error response
            let duplicates_sync_dir = test::create_sub_dir(&d);
            save_pr(&duplicates_sync_dir, "bob.xml", &pr_bob);
            save_pr(&duplicates_sync_dir, "bob-2.xml", &pr_bob_2);
            assert!(pl.sync_from_dir(
                PathBuf::from(duplicates_sync_dir),
                actor.clone()
            ).is_err());
        })
    }

}
