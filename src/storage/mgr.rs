use std::sync::RwLock;
use storage::keystore;
use storage::keystore::{CachingDiskKeyStore, Key, KeyStore};
use provisioning::publisher_list::PublisherList;

/// An entity manager that knows where to find and keep the data structs
/// that we use, and that will ensure that updates are done through write
/// locks.
pub struct EntityManager {
    store: RwLock<CachingDiskKeyStore>
}

const PL_KEY: &'static str = "publisher_list.obj";

impl EntityManager {
    pub fn new(base_dir: String) -> Result<Self, Error> {
        Ok(
            EntityManager {
                store: RwLock::new(
                    CachingDiskKeyStore::new(base_dir)?
                )
            }
        )
    }
}

impl EntityManager {

    fn pl_key() -> Key {
        Key::from_str(PL_KEY)
    }

    /// Saves a new, or updates the existing publisher list.
    ///
    /// This will fail if in case the version of the previous publisher
    /// list is not exactly one behind the version of the new list.
    pub fn save_publish_list(&self, pl: PublisherList)
    -> Result<(), Error> {
        if let Some(old_pl) = self.get_publish_list()? {
            if old_pl.version() != pl.version() - 1 {
                return Err(
                    Error::ConcurrentModification(
                        pl.version(),
                        old_pl.version()))
            }
        }

        let mut ks = self.store.write().unwrap();
        ks.store(Self::pl_key(), pl)?;
        Ok(())
    }

    pub fn get_publish_list(&self)
    -> Result<Option<PublisherList>, Error> {
        let ks = self.store.read().unwrap();
        let pl_opt = ks.retrieve(&Self::pl_key())?;
        Ok(pl_opt)
    }

}


#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(
        display="Version conflict. New version is: {}, old was: {}", _0,_1)
    ]
    ConcurrentModification(usize, usize),
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
    use rpki::uri;
    use rpki::remote::idcert::IdCert;
    use rpki::signing::signer::Signer;
    use rpki::signing::softsigner::OpenSslSigner;
    use rpki::signing::PublicKeyAlgorithm;
    use rpki::signing::builder::IdCertBuilder;
    use rpki::oob::exchange::PublisherRequest;

    fn rsync_uri(s: &str) -> uri::Rsync {
        uri::Rsync::from_str(s).unwrap()
    }

    fn new_id_cert() -> IdCert {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
    }

    fn new_publisher_request(tag: Option<&str>, publisher_handle: &str)
    -> PublisherRequest {
        PublisherRequest::new(
            tag,
            publisher_handle,
            new_id_cert()
        )
    }


    #[test]
    fn should_store_and_retrieve_publisher_list() {
        test::test_with_tmp_dir(|d| {
            let em = EntityManager::new(d).unwrap();

            let pl = PublisherList::new(rsync_uri("rsync://host/mod/"));

            em.save_publish_list(pl.clone()).unwrap();

            let mut pl_1 = em.get_publish_list().unwrap().unwrap();

            assert_eq!(pl, pl_1);

            pl_1.add_publisher(
                new_publisher_request(Some("test"), "test")).unwrap();
            assert_eq!(1, pl_1.version());
            em.save_publish_list(pl_1).unwrap();

            let mut pl_2 = em.get_publish_list().unwrap().unwrap();
            pl_2.add_publisher(
                new_publisher_request(Some("test2"), "test2")).unwrap();
            assert_eq!(2, pl_2.version());
            em.save_publish_list(pl_2).unwrap();



        })
    }

}
