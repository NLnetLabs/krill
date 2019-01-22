//! Types for tracking configured publishers.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use rpki::uri;
use daemon::api::requests;
use daemon::api::requests::PublisherRequestChoice;
use crate::remote::id::IdCert;
use crate::remote::rfc8183;
use crate::storage::keystore::{self, Info, Key, KeyStore};
use crate::storage::caching_ks::CachingDiskKeyStore;
use crate::util::ext_serde;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rfc8181PublisherDetails {
    // The optional tag in the request. None maps to empty string.
    tag:         String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert:     IdCert
}

impl Rfc8181PublisherDetails {
    pub fn tag(&self) -> &String {
        &self.tag
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}

impl Rfc8181PublisherDetails {
    pub fn new(tag: Option<String>, id_cert: IdCert) -> Self {
        let tag = tag.unwrap_or("".to_string());
        Rfc8181PublisherDetails { tag, id_cert }
    }
}

impl PartialEq for Rfc8181PublisherDetails {
    fn eq(&self, other: &Rfc8181PublisherDetails) -> bool {
        self.tag == other.tag &&
        self.id_cert.to_bytes() == other.id_cert.to_bytes()
    }
}

impl Eq for Rfc8181PublisherDetails {}


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publisher {
    handle:        String,

    /// The token used by the API
    token:         String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:    uri::Rsync,

    rfc8181: Option<Rfc8181PublisherDetails>
}

impl Publisher {
    pub fn new(
        handle:   String,
        token:    String,
        base_uri: uri::Rsync,
        rfc8181:  Option<Rfc8181PublisherDetails>
    ) -> Self {
        Publisher {
            handle,
            token,
            base_uri,
            rfc8181
        }
    }
}

impl Publisher {
    pub fn handle(&self) -> &String {
        &self.handle
    }

    pub fn token(&self) -> &String {
        &self.token
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn rfc8181(&self) -> &Option<Rfc8181PublisherDetails> {
        &self.rfc8181
    }
}

impl PartialEq for Publisher {
    fn eq(&self, other: &Publisher) -> bool {
        self.handle == other.handle &&
        self.base_uri == other.base_uri &&
        self.rfc8181 == other.rfc8181
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

    fn verify_handle(&self, handle: &str) -> Result<(), Error> {
        if handle.contains("/") {
            return Err(Error::ForwardSlashInHandle(handle.to_string()))
        }

        if self.has_publisher(handle) {
            return Err(Error::DuplicatePublisher(handle.to_string()))
        }

        Ok(())
    }

    fn publisher_base_uri(&self, handle: &str) -> Result<uri::Rsync, Error> {
        let base_uri = format!("{}{}/", self.base_uri.to_string(), handle);
        let base_uri = uri::Rsync::from_string(base_uri)?;
        Ok(base_uri)
    }

    /// Adds a Publisher based on a PublisherRequest (from the RFC 8183 xml).
    ///
    /// Will return an error if the publisher already exists! Use
    /// update_publisher in case you want to update an existing publisher.
    pub fn add_publisher(
        &mut self,
        prc: PublisherRequestChoice,
        handle_override: Option<&str>,
        actor: &str
    ) -> Result<(), Error> {

        let publisher = match prc {
            PublisherRequestChoice::Api(pr) => {
                if handle_override.is_some() {
                    return Err(Error::HandleOverrideNotAllowed)
                }
                let (handle, token) = pr.parts();
                self.verify_handle(&handle)?;
                let base_uri = self.publisher_base_uri(&handle)?;

                Publisher::new(
                    handle,
                    token,
                    base_uri,
                    None
                )
            },
            PublisherRequestChoice::Rfc8183(pr) => {
                let (tag, mut handle, id_cert) = pr.into_parts();

                match handle_override {
                    Some(handle_override) => {
                        handle = handle_override.to_string()
                    },
                    _ => {}
                }

                self.verify_handle(&handle)?;
                let base_uri = self.publisher_base_uri(&handle)?;
                let rfc8181 = Rfc8181PublisherDetails::new(tag, id_cert);

                let token = requests::generate_random_token();

                Publisher::new(
                    handle,
                    token,
                    base_uri,
                    Some(rfc8181)
                )
            }
        };

        let key = Key::from_str(&publisher.handle);
        let info = Info::now(
            actor,
            &format!("Added publisher: {}", &publisher.handle)
        );

        info!("Added publisher: {}", &publisher.handle);
        self.store.store(key, publisher, info)?;

        Ok(())
    }

    /// Removes a publisher with a given name.
    ///
    /// Will return an error if ths publisher does not exist.
    pub fn remove_publisher(
        &mut self,
        handle: impl AsRef<str>,
        actor: &str
    ) -> Result<(), Error> {
        let name = handle.as_ref();
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

    /// Returns whether a publisher exists for this name.
    pub fn has_publisher(&self, handle: &str) -> bool {
        let key = Key::from_str(handle);
        match self.store.version(&key) {
            Ok(Some(version)) => {
                if version > 0 {
                    true
                } else {
                    debug!("Publisher {} was archived.", handle);
                    false
                }
            },
            _ => false
        }
    }

    /// Returns an Optional Arc to a publisher for this name.
    pub fn publisher(
        &self,
        handle: impl AsRef<str>
    ) -> Result<Option<Arc<Publisher>>, Error> {
        let key = Key::from_str(handle.as_ref());
        self.store.get(&key).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Returns an Arc to a publisher, and returns an error if the publisher
    /// does not exist.
    pub fn get_publisher(
        &self,
        handle: impl AsRef<str>
    ) -> Result<Arc<Publisher>, Error> {
        let name = handle.as_ref();
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

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt ="{}", _0)]
    KeyStoreError(keystore::Error),

    #[display(fmt ="{}", _0)]
    IoError(io::Error),

    #[display(fmt =
    "The '/' in publisher_handle ({}) is not supported - because we \
        are deriving the base directory for a publisher from this. This \
        behaviour may be updated in future.", _0)]
    ForwardSlashInHandle(String),

    #[display(fmt = "Duplicate publisher with name: {}.", _0)]
    DuplicatePublisher(String),

    #[display(fmt = "Unknown publisher with name: {}.", _0)]
    UnknownPublisher(String),

    #[display(fmt = "Error in base URI: {}.", _0)]
    UriError(uri::Error),

    #[display(fmt = "Invalid Publisher Request: {}.", _0)]
    PublisherRequestError(rfc8183::PublisherRequestError),

    #[display(fmt = "Cannot override handle using path parameter for json api")]
    HandleOverrideNotAllowed
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

impl From<rfc8183::PublisherRequestError> for Error {
    fn from(e: rfc8183::PublisherRequestError) -> Self {
        Error::PublisherRequestError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::util::test;

    fn test_publisher_store(dir: &PathBuf) -> PublisherStore {
        let uri = test::rsync_uri("rsync://host/module/");
        PublisherStore::new(dir, &uri).unwrap()
    }

    #[test]
    fn should_refuse_slash_in_publisher_handle() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);
            let pr = test::new_publisher_request("test/below", &d);
            let prc = PublisherRequestChoice::Rfc8183(pr);

            let handle = "test/below";

            match ps.add_publisher(prc, Some(handle), "test") {
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

            let pr = test::new_publisher_request(name, &d);
            let id_cert = pr.id_cert().clone();

            let prc = PublisherRequestChoice::Rfc8183(pr);

            let actor = "test";

            ps.add_publisher(prc, Some(name), actor).unwrap();

            assert!(ps.has_publisher(&name));

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = ps.publisher(&name).unwrap().unwrap();

            let expected_rfc8181 = Rfc8181PublisherDetails::new(None, id_cert);

            assert_eq!(publisher_found.handle(), "alice");
            assert_eq!(
                publisher_found.base_uri().to_string().as_str(),
                "rsync://host/module/alice/");
            assert_eq!(publisher_found.rfc8181(), &Some(expected_rfc8181));

        })
    }

    #[test]
    fn should_not_add_publisher_twice() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);
            let name = "alice";
            let pr = test::new_publisher_request(name, &d);
            let prc = PublisherRequestChoice::Rfc8183(pr);
            let actor = "test";

            ps.add_publisher(prc, None, actor).unwrap();
            assert!(ps.has_publisher(&name));

            let pr = test::new_publisher_request(name, &d);
            let prc = PublisherRequestChoice::Rfc8183(pr);
            match ps.add_publisher(prc, None, actor) {
                Err(Error::DuplicatePublisher(_)) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })

    }

    #[test]
    fn should_remove_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let actor = "test";
            let pr = test::new_publisher_request(name, &d);
            let prc = PublisherRequestChoice::Rfc8183(pr);

            ps.add_publisher(prc, None, actor).unwrap();
            assert_eq!(1, ps.publishers().unwrap(). len());

            ps.remove_publisher(name, actor).unwrap();
            assert_eq!(0, ps.publishers().unwrap(). len());
        });
    }
}

