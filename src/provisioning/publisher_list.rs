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
        &mut self,
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


    /// Updates the IdCert for a known publisher.
    pub fn update_id_cert_publisher(
        &mut self,
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

}


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

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use test;
    use rpki::signing::PublicKeyAlgorithm;
    use rpki::signing::builder::IdCertBuilder;
    use rpki::signing::signer::Signer;
    use rpki::signing::softsigner::OpenSslSigner;

    fn rsync_uri(s: &str) -> uri::Rsync {
        uri::Rsync::from_str(s).unwrap()
    }

    fn new_id_cert() -> IdCert {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
    }

    fn new_pl(dir: String) -> PublisherList {
        let uri = rsync_uri("rsync://host/module/");
        PublisherList::new(dir, uri).unwrap()
    }

    #[test]
    fn should_refuse_slash_in_publisher_handle() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);
            let id_cert = new_id_cert();

            let pr = PublisherRequest::new(
                Some("test"),
                "test/below",
                id_cert);

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
            let id_cert = new_id_cert();


            let pr = PublisherRequest::new(
                Some("test"),
                "test",
                id_cert.clone());

            pl.add_publisher(pr, "test".to_string()).unwrap();

            let name = "test".to_string();
            assert!(pl.has_publisher(&name));

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = pl.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                "test".to_string(),
                rsync_uri("rsync://host/module/test"),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

    #[test]
    fn should_update_id_cert_publisher() {
        test::test_with_tmp_dir(|d| {
            let mut pl = new_pl(d);
            let id_cert = new_id_cert();


            let name = "test";
            let actor = "test_actor".to_string();

            let pr = PublisherRequest::new(
                Some("test"),
                name,
                id_cert
            );

            pl.add_publisher(pr, actor.clone()).unwrap();

            let id_cert = new_id_cert();

            pl.update_id_cert_publisher(
                name,
                id_cert.clone(),
                actor.clone()
            ).unwrap();

            // Get the Arc out of the Result<Option<Arc<Publisher>>, Error>
            let publisher_found = pl.publisher(&name).unwrap().unwrap();

            let expected_publisher = Publisher::new(
                "test".to_string(),
                rsync_uri("rsync://host/module/test"),
                id_cert
            );

            assert_eq!(publisher_found.as_ref(), &expected_publisher);
        })
    }

}

//    /// Removes a Publisher.
//    pub fn remove_publisher(
//        &mut self,
//        name: String
//    ) -> Result<VersionedEvent, Error> {
//        let event = VersionedEvent {
//            version: self.version,
//            event: Event::Removed(PublisherRemoved(name))
//        };
//
//        self.apply_event(&event)?;
//        Ok(event)
//    }
//
//
//
//    #[test]
//    fn should_remove_publisher() {
//        let mut cl = empty_publisher_list();
//        let id_cert = new_id_cert();
//
//        let pr = PublisherRequest::new(
//            Some("test"),
//            "test",
//            id_cert.clone());
//
//        cl.add_publisher(pr).unwrap();
//
//        assert_eq!(1, cl.publishers.len());
//
//        cl.remove_publisher("test".to_string()).unwrap();
//
//        assert_eq!(0, cl.publishers.len());
//    }
//
//}