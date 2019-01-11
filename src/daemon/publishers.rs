//! Types for tracking configured publishers.

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use rpki::uri;
use crate::remote::id::IdCert;
use crate::remote::oob::{PublisherRequest, PublisherRequestError};
use crate::storage::keystore::{self, Info, Key, KeyStore};
use crate::storage::caching_ks::CachingDiskKeyStore;
use crate::util::ext_serde;

//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publisher {
    // The optional tag in the request. None maps to empty string.
    tag:         String,

    name:        String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:    uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
    service_uri: uri::Http,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert:     IdCert
}

impl Publisher {
    pub fn new(
        tag: Option<String>,
        name: String,
        base_uri: uri::Rsync,
        service_uri: uri::Http,
        id_cert: IdCert
    ) -> Self {

        let tag = match tag {
            None => "".to_string(),
            Some(t) => t
        };

        Publisher {
            tag,
            name,
            base_uri,
            service_uri,
            id_cert
        }
    }

    /// Returns a new Publisher that is the same as this Publisher, except
    /// that it has an updated IdCert
    pub fn with_new_id_cert(&self, id_cert: IdCert) -> Self {
        Publisher {
            tag: self.tag.clone(),
            name: self.name.clone(),
            base_uri: self.base_uri.clone(),
            service_uri: self.service_uri.clone(),
            id_cert
        }
    }
}

impl Publisher {
    pub fn tag(&self) -> Option<String> {
        let tag = &self.tag;
        if tag.is_empty() {
            None
        } else {
            Some(tag.clone())
        }
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn service_uri(&self) -> &uri::Http {
        &self.service_uri
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}

impl PartialEq for Publisher {
    fn eq(&self, other: &Publisher) -> bool {
        self.name == other.name &&
            self.base_uri == other.base_uri &&
            self.service_uri == other.service_uri &&
            self.id_cert.to_bytes() == other.id_cert.to_bytes()
    }
}

impl Eq for Publisher {}


//------------ PublisherList -------------------------------------------------

/// This type contains all configured Publishers, allowed to publish at this
/// publication server. Essentially this wraps around the storage that
/// contains all current publishers, and keeps a full audit trail of changes
/// to this.
#[derive(Clone, Debug)]
pub struct PublisherStore {
    store: CachingDiskKeyStore,
    base_uri: uri::Rsync,
}


impl PublisherStore {
    pub fn new(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync
    ) -> Result<Self, Error> {
        let mut publisher_dir = PathBuf::from(work_dir);
        publisher_dir.push("publishers");
        if ! publisher_dir.is_dir() {
            fs::create_dir_all(&publisher_dir)?;
        }

        Ok(
            PublisherStore {
                store: CachingDiskKeyStore::new(publisher_dir)?,
                base_uri: base_uri.clone()
            }
        )
    }

    /// Adds a Publisher based on a PublisherRequest (from the RFC 8183 xml).
    ///
    /// Will return an error if the publisher already exists! Use
    /// update_publisher in case you want to update an existing publisher.
    pub fn add_publisher(
        &mut self,
        pr: PublisherRequest,
        base_service_uri: &uri::Http,
        actor: &str
    ) -> Result<(), Error> {
        let (tag, name, id_cert) = pr.into_parts();

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
        base_uri.push_str("/");
        let base_uri = uri::Rsync::from_string(base_uri)?;

        let mut service_uri = base_service_uri.to_string();
        service_uri.push_str(name.as_ref());
        let service_uri = uri::Http::from_string(service_uri)?;

        let key = Key::from_str(name.as_ref());
        let info = Info::now(
            actor,
            &format!("Added publisher: {}", &name)
        );
        let publisher = Publisher::new(
            tag,
            name,
            base_uri,
            service_uri,
            id_cert
        );

        info!("Adding publisher: {}", publisher.name());
        self.store.store(key, publisher, info)?;

        Ok(())
    }

    /// Removes a publisher with a given name.
    ///
    /// Will return an error if ths publisher does not exist.
    pub fn remove_publisher(
        &mut self,
        name: impl AsRef<str>,
        actor: &str
    ) -> Result<(), Error> {
        let name = name.as_ref();
        match self.publisher(name)? {
            None => Err(Error::UnknownPublisher(name.to_string())),
            Some(_p) => {
                let key = Key::from_str(name);

                let info = Info::now(
                    actor,
                    &format!("Removed publisher: {}", name)
                );

                self.store.archive(&key, info)?;
                Ok(())
            }
        }
    }


    /// Updates the IdCert for a known publisher.
    pub fn update_id_cert_publisher(
        &mut self,
        name: &str,
        id_cert: IdCert,
        actor: &str
    ) -> Result<(), Error> {
        let publisher_opt = self.publisher(name)?;

        match publisher_opt {
            None => Err(Error::UnknownPublisher(name.to_string())),
            Some(publisher) => {
                let key = Key::from_str(name);
                let new_publisher = publisher.with_new_id_cert(id_cert);
                let info = Info::now(
                    actor,
                    "Updated the IdCert"
                );

                info!("Updated Id for publisher: {}", publisher.name());
                self.store.store(key, new_publisher, info)?;

                Ok(())
            }
        }
    }

    /// Returns whether a publisher exists for this name.
    pub fn has_publisher(&self, name: &str) -> bool {
        let key = Key::from_str(name);
        match self.store.version(&key) {
            Ok(Some(version)) => {
                if version > 0 {
                    true
                } else {
                    debug!("Publisher {} was archived.", name);
                    false
                }
            },
            _ => false
        }
    }

    /// Returns an Optional Arc to a publisher for this name.
    pub fn publisher(
        &self,
        name: impl AsRef<str>
    ) -> Result<Option<Arc<Publisher>>, Error> {
        let key = Key::from_str(name.as_ref());
        self.store.get(&key).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Returns an Arc to a publisher, and returns an error if the publisher
    /// does not exist.
    pub fn get_publisher(
        &self,
        name: impl AsRef<str>
    ) -> Result<Arc<Publisher>, Error> {
        let name = name.as_ref();
        match self.publisher(name)? {
            None => Err(Error::UnknownPublisher(name.to_string())),
            Some(p) => Ok(p)
        }
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
impl PublisherStore {
    /// Synchronizes the list of Publisher based on request XML files on disk.
    /// Will add new publishers, remove removed publisher, and update the
    /// id_cert in case it was updated. Returns an error in case duplicate
    /// handler names are found in XML files in the directory.
    pub fn sync_from_dir(
        &mut self,
        dir: &PathBuf,
        base_service_uri: &uri::Http,
        actor: &str
    ) -> Result<(), Error> {

        info!("Synchronizing publishers");
        // Find all the publisher requests on disk
        let prs_on_disk = self.prs_on_disk(dir)?;
        self.process_removed_publishers(&prs_on_disk, actor)?;

        for (handle, pr) in prs_on_disk {
            match self.publisher(&handle)? {
                None => {
                    self.add_publisher(pr, base_service_uri, actor)?;
                }
                Some(p) => {
                    if p.id_cert().to_bytes() != pr.id_cert().to_bytes() {
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
        &mut self,
        prs_on_disk: &HashMap<String, PublisherRequest>,
        actor: &str
    ) -> Result<(), Error> {
        let current = self.publishers()?;
        for c in current {
            if prs_on_disk.get(c.name()).is_none() {
                info!("Removing publisher: {}", c.name());
                self.remove_publisher(c.name(), actor)?;
            }
        }
        Ok(())
    }

    fn prs_on_disk(
        &self,
        dir: &PathBuf
    ) -> Result<HashMap<String, PublisherRequest>, Error> {
        let mut prs_on_disk = HashMap::new();
        for e in dir.read_dir()? {
            let file = e?;
            if let Some(file_name) = file.file_name().to_str() {
                if file_name.ends_with(".xml") {
                    let f = File::open(file.path().display().to_string())?;
                    let mut r = BufReader::new(f);

                    let pr = PublisherRequest::decode(r)?;
                    pr.validate()?;

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
    use crate::util::test;

    fn base_service_uri() -> uri::Http {
        test::http_uri("http://127.0.0.1:3000/rfc8181/")
    }

    fn test_publisher_store(dir: &PathBuf) -> PublisherStore {
        let uri = test::rsync_uri("rsync://host/module/");
        PublisherStore::new(dir, &uri).unwrap()
    }

    fn find_in_list(
        name: &str,
        publishers: &Vec<Arc<Publisher>>
    ) -> Option<Arc<Publisher>> {
        publishers.iter().find(|e| {e.name() == name }).map(|e| {e.clone()})
    }

    #[test]
    fn should_refuse_slash_in_publisher_handle() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);
            let pr = test::new_publisher_request("test/below");

            match ps.add_publisher(pr, &base_service_uri(), "test") {
                Err(Error::ForwardSlashInHandle(_)) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })
    }

    #[test]
    fn should_add_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);
            let name = "alice";
            let pr = test::new_publisher_request(name);
            let id_cert = pr.id_cert().clone();
            let actor = "test";

            ps.add_publisher(pr, &base_service_uri(), actor).unwrap();

            assert!(ps.has_publisher(&name));

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = ps.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                None,
                name.to_string(),
                test::rsync_uri(&format!("rsync://host/module/{}/", name)),
                test::http_uri(
                    &format!("http://127.0.0.1:3000/rfc8181/{}",name)),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

    #[test]
    fn should_update_id_cert_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);
            let name = "alice";
            let pr = test::new_publisher_request(name);
            let actor = "test";

            ps.add_publisher(pr, &base_service_uri(), actor).unwrap();

            // Make a new publisher request for alice, using a new cert
            let pr = test::new_publisher_request(name);
            let id_cert = pr.id_cert().clone();

            ps.update_id_cert_publisher(
                name,
                id_cert.clone(),
                actor.clone()
            ).unwrap();

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = ps.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                None,
                name.to_string(),
                test::rsync_uri(&format!("rsync://host/module/{}/", name)),
                test::http_uri(
                    &format!("http://127.0.0.1:3000/rfc8181/{}",name)),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

    #[test]
    fn should_remove_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let actor = "test";
            let pr = test::new_publisher_request(name);

            ps.add_publisher(pr, &base_service_uri(), actor).unwrap();
            assert_eq!(1, ps.publishers().unwrap(). len());

            ps.remove_publisher(name, actor).unwrap();
            assert_eq!(0, ps.publishers().unwrap(). len());
        });
    }


    #[test]
    fn should_sync_publisher_requests() {
        test::test_with_tmp_dir(|d|{

            let pl_dir = test::create_sub_dir(&d);
            let mut ps = test_publisher_store(&pl_dir);

            let actor = "test";

            //
            // Start with two PRs for alice and bob
            let start_sync_dir = test::create_sub_dir(&d);
            let pr_alice = test::new_publisher_request("alice");
            let pr_bob   = test::new_publisher_request("bob");
            test::save_file(
                &start_sync_dir,
                "alice.xml",
                &pr_alice.encode_vec()
            );
            test::save_file(
                &start_sync_dir,
                "bob.xml",
                &pr_bob.encode_vec()
            );

            ps.sync_from_dir(
                &PathBuf::from(start_sync_dir),
                &base_service_uri(),
                actor.clone()
            ).unwrap();

            let publishers = ps.publishers().unwrap();
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
            test::save_file(
                &updated_sync_dir,
                "bob.xml",
                &pr_bob_2.encode_vec()
            );
            test::save_file(
                &updated_sync_dir,
                "carol.xml",
                &pr_carol.encode_vec()
            );
            ps.sync_from_dir(
                &PathBuf::from(updated_sync_dir),
                &base_service_uri(),
                actor
            ).unwrap();

            let publishers = ps.publishers().unwrap();
            assert_eq!(2, publishers.len());

            assert!(find_in_list("alice", &publishers).is_none());
            assert!(find_in_list("bob", &publishers).is_some());
            assert_eq!(
                find_in_list("bob", &publishers).unwrap().id_cert().to_bytes(),
                pr_bob_2.id_cert().to_bytes()
            );
            assert!(find_in_list("carol", &publishers).is_some());

            //
            // Now do a dir with a duplicate handle, this should
            // result in an error response
            let duplicates_sync_dir = test::create_sub_dir(&d);
            test::save_file(
                &duplicates_sync_dir,
                "bob.xml",
                &pr_bob.encode_vec()
            );
            test::save_file(
                &duplicates_sync_dir,
                "bob-2.xml",
                &pr_bob_2.encode_vec()
            );
            assert!(ps.sync_from_dir(
                &PathBuf::from(duplicates_sync_dir),
                &base_service_uri(),
                actor.clone()
            ).is_err());
        })
    }
}

