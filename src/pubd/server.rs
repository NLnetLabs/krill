//! An RPKI publication protocol server.

use std::path::PathBuf;
use std::sync::Arc;
use provisioning::identity::MyIdentity;
use provisioning::publisher_list;
use provisioning::publisher_list::PublisherList;
use rpki::uri;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::builder::IdCertBuilder;
use rpki::signing::signer::{CreateKeyError, KeyUseError, Signer};
use signing::softsigner;
use signing::softsigner::OpenSslSigner;
use storage::caching_ks::CachingDiskKeyStore;
use storage::keystore::{self, Info, Key, KeyStore};


/// # Some constants for naming resources in the keystore for clients.
fn actor() -> String {
    "publication server".to_string()
}

fn my_id_key() -> Key {
    Key::from_str("my_id")
}

fn my_id_msg() -> String {
    "initialised identity".to_string()
}


//------------ PubServer -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct PubServer {
    // keys
    //   -> keys by id
    signer: OpenSslSigner,

    // key value store
    store: CachingDiskKeyStore,
    //   my_id -> MyIdentity

    publisher_list: PublisherList
}

impl PubServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: String,
        base_uri: uri::Rsync
    ) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(PathBuf::from(&work_dir))?;
        let publisher_list = PublisherList::new(work_dir.clone(), base_uri)?;
        let signer = OpenSslSigner::new(work_dir)?;
        Ok(
            PubServer {
                signer,
                store,
                publisher_list
            }
        )
    }

    /// Initialises the identity of this publication server.
    pub fn init(&mut self) -> Result<(), Error> {
        let key_id = self.signer.create_key(&PublicKeyAlgorithm::RsaEncryption)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(actor(), id_cert, key_id);

        let key = my_id_key();
        let inf = Info::now(actor(), my_id_msg());
        self.store.store(key, my_id, inf)?;
        Ok(())
    }

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&my_id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }
}



//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="{}", _0)]
    PublisherListError(publisher_list::Error),

    #[fail(display="{}", _0)]
    SoftSignerError(softsigner::Error),


    #[fail(display="{:?}", _0)]
    CreateKeyError(CreateKeyError),

    #[fail(display="{:?}", _0)]
    KeyUseError(KeyUseError),
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
}

impl From<publisher_list::Error> for Error {
    fn from(e: publisher_list::Error) -> Self {
        Error::PublisherListError(e)
    }
}

impl From<softsigner::Error> for Error {
    fn from(e: softsigner::Error) -> Self {
        Error::SoftSignerError(e)
    }
}

impl From<CreateKeyError> for Error {
    fn from(e: CreateKeyError) -> Self {
        Error::CreateKeyError(e)
    }
}

impl From<KeyUseError> for Error {
    fn from(e: KeyUseError) -> Self {
        Error::KeyUseError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test;

    #[test]
    fn should_initialise_identity() {
        test::test_with_tmp_dir(|d| {
            let uri = test::rsync_uri("rsync://host/module/");
            let mut server = PubServer::new(
                d.clone(),
                uri.clone()
            ).unwrap();

            // A clean publication server has no identity.
            assert_eq!(None, server.my_identity().unwrap());

            // Calling init will generate the identity.
            server.init().unwrap();
            let id = server.my_identity().unwrap().unwrap();
            assert_eq!(actor().as_str(), id.name());

            // Starting a new server from the same workdir will have the
            // same identity.
            let server_2 = PubServer::new(d, uri).unwrap();
            let id_2 = server_2.my_identity().unwrap().unwrap();
            assert_eq!(id, id_2);
        });

    }
}

