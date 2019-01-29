//! Types for tracking configured publishers.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use rpki::uri;
use crate::api::publishers;
use crate::remote::rfc8183;
use crate::storage::keystore::{self, Info, Key, KeyStore};
use crate::storage::caching_ks::CachingDiskKeyStore;


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

    fn verify_base_uri(&self, base_uri: &uri::Rsync) -> Result<(), Error> {
        let base_uri = base_uri.to_string();
        if base_uri.starts_with(self.base_uri.to_string().as_str()) &&
           base_uri.ends_with("/") {
            Ok(())
        } else {
            Err(Error::InvalidBaseUri)
        }
    }

    /// Adds a Publisher based on a PublisherRequest (from the RFC 8183 xml).
    ///
    /// Will return an error if the publisher already exists! Use
    /// update_publisher in case you want to update an existing publisher.
    pub fn add_publisher(
        &mut self,
        pbl: publishers::Publisher,
        actor: &str
    ) -> Result<(), Error> {
        self.verify_handle(pbl.handle())?;
        self.verify_base_uri(pbl.base_uri())?;

        let key = Key::from_str(pbl.handle());
        let info = Info::now(
            actor,
            &format!("Added publisher: {}", pbl.handle())
        );

        info!("Added publisher: {}", pbl.handle());
        self.store.store(key, pbl, info)?;

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
    ) -> Result<Option<Arc<publishers::Publisher>>, Error> {
        let key = Key::from_str(handle.as_ref());
        self.store.get(&key).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Returns an Arc to a publisher, and returns an error if the publisher
    /// does not exist.
    pub fn get_publisher(
        &self,
        handle: impl AsRef<str>
    ) -> Result<Arc<publishers::Publisher>, Error> {
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
    pub fn publishers(&self) -> Result<Vec<Arc<publishers::Publisher>>, Error> {
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
    HandleOverrideNotAllowed,

    #[display(fmt = "Base uri for publisher needs to be folder under base uri\
     for server, and must end with a '/'.")]
    InvalidBaseUri
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

            let name = "alice/bob";
            let base_uri = test::rsync_uri("rsync://host/module/alice/bob");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);

            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            match ps.add_publisher(pbl, "test") {
                Err(Error::ForwardSlashInHandle(_)) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })
    }

    #[test]
    fn should_refuse_base_uri_not_ending_with_slash() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let base_uri = test::rsync_uri("rsync://host/module/alice");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);

            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            match ps.add_publisher(pbl, "test") {
                Err(Error::InvalidBaseUri) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })
    }

    #[test]
    fn should_refuse_base_uri_outside_of_server_base() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let base_uri = test::rsync_uri("rsync://host/modu/alice/");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);

            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            match ps.add_publisher(pbl, "test") {
                Err(Error::InvalidBaseUri) => { }, // Ok
                _ => panic!("Should have seen error.")
            }
        })
    }

    #[test]
    fn should_add_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let base_uri = test::rsync_uri("rsync://host/module/alice/");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);
            let id_cert = pr.id_cert().clone();

            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            let actor = "test";
            ps.add_publisher(pbl, actor).unwrap();

            assert!(ps.has_publisher(&name));

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = ps.publisher(&name).unwrap().unwrap();

            let expected_rfc8181 = publishers::CmsAuthData::new(None, id_cert);

            assert_eq!(publisher_found.handle(), "alice");
            assert_eq!(publisher_found.base_uri(), &base_uri);
            assert_eq!(publisher_found.cms_auth_data(), &Some(expected_rfc8181));

        })
    }

    #[test]
    fn should_not_add_publisher_twice() {
        test::test_with_tmp_dir(|d| {
            let mut ps = test_publisher_store(&d);

            let name = "alice";
            let base_uri = test::rsync_uri("rsync://host/module/alice/");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);
            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            let actor = "test";
            ps.add_publisher(pbl.clone(), actor).unwrap();
            assert!(ps.has_publisher(&name));

            match ps.add_publisher(pbl, actor) {
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
            let base_uri = test::rsync_uri("rsync://host/module/alice/");
            let token = "secret";

            let pr = test::new_publisher_request(name, &d);
            let pbl = pr.into_publisher(token.to_string(), base_uri.clone());

            let actor = "test";
            ps.add_publisher(pbl, actor).unwrap();
            assert_eq!(1, ps.publishers().unwrap(). len());

            ps.remove_publisher(name, actor).unwrap();
            assert_eq!(0, ps.publishers().unwrap(). len());
        });
    }
}

