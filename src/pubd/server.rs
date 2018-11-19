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
use provisioning::publisher::Publisher;


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
        base_uri: uri::Rsync,
        pub_xml_dir: PathBuf
    ) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(PathBuf::from(&work_dir))?;
        let mut publisher_list = PublisherList::new(
            work_dir.clone(),
            base_uri)?;
        publisher_list.sync_from_dir(pub_xml_dir, actor())?;
        let signer = OpenSslSigner::new(work_dir)?;
        Ok(
            PubServer {
                signer,
                store,
                publisher_list
            }
        )
    }


    /// Initialiase the publication server identity, if no identity had
    /// been set up. Does nothing otherwise.
    pub fn init_identity_if_empty(&mut self) -> Result<(), Error> {
        match self.my_identity()? {
            Some(_id) => Ok(()),
            None => self.init_identity()
        }
    }

    /// Initialises the identity of this publication server.
    pub fn init_identity(&mut self) -> Result<(), Error> {
        let key_id = self.signer.create_key(&PublicKeyAlgorithm::RsaEncryption)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(actor(), id_cert, key_id);

        let key = my_id_key();
        let inf = Info::now(actor(), my_id_msg());
        self.store.store(key, my_id, inf)?;
        Ok(())
    }

    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        self.publisher_list
            .publishers()
            .map_err(|e| { Error::PublisherListError(e) })
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
    use std::fs::File;
    use std::io::Write;
    use test;
    use pubc::client::PubClient;
    use rpki::oob::exchange::PublisherRequest;

    fn save_pr(base_dir: &PathBuf, file_name: &str, pr: &PublisherRequest) {
        let mut full_name = base_dir.clone();
        full_name.push(PathBuf::from
            (file_name));
        let mut f = File::create(full_name).unwrap();
        let xml = pr.encode_vec();
        f.write(xml.as_ref()).unwrap();
    }

    #[test]
    fn should_initialise_identity() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = PathBuf::from(test::create_sub_dir(&d));
            let uri = test::rsync_uri("rsync://host/module/");
            let mut server = PubServer::new(
                d.clone(),
                uri.clone(),
                xml_dir.clone()
            ).unwrap();

            // A clean publication server has no identity.
            assert_eq!(None, server.my_identity().unwrap());

            // Calling init will generate the identity.
            server.init_identity().unwrap();
            let id = server.my_identity().unwrap().unwrap();
            assert_eq!(actor().as_str(), id.name());

            // A new server with the same workdir will have the same identity.
            let server_2 = PubServer::new(d, uri, xml_dir).unwrap();
            let id_2 = server_2.my_identity().unwrap().unwrap();
            assert_eq!(id, id_2);
        });
    }

    #[test]
    fn should_sync_and_resync_publishers_from_disk() {
        test::test_with_tmp_dir(|d| {

            // Set up an xml dir with two requests
            let xml_dir = PathBuf::from(test::create_sub_dir(&d));

            let mut alice = PubClient::new(d.clone()).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let mut bob = PubClient::new(d.clone()).unwrap();
            bob.init("bob".to_string()).unwrap();
            let pr_bob = bob.publisher_request().unwrap();

            save_pr(&xml_dir, "alice.xml", &pr_alice);
            save_pr(&xml_dir, "bob.xml", &pr_bob);

            // Start up a server
            let uri = test::rsync_uri("rsync://host/module/");
            let server = PubServer::new(
                d.clone(),
                uri.clone(),
                xml_dir.clone()
            ).unwrap();

            // The server now has two configured publishers
            let publishers = server.publishers().unwrap();
            assert_eq!(2, publishers.len());

            // Create a new xml dir with only alice.xml
            let xml_dir = PathBuf::from(test::create_sub_dir(&d));
            save_pr(&xml_dir, "alice.xml", &pr_alice);

            // Start a new server (so that it re-syncs)
            let server = PubServer::new(
                d.clone(),
                uri.clone(),
                xml_dir.clone()
            ).unwrap();

            // Now we expect only one publisher for Alice
            let publishers = server.publishers().unwrap();
            assert_eq!(1, publishers.len());
            let p_alice = publishers
                .iter()
                .find(|p| { p.name() == "alice" })
                .unwrap();

            assert_eq!(
                pr_alice.id_cert().to_bytes(),
                p_alice.id_cert().to_bytes()
            );

            let p_old_alice = p_alice;

            // But we can update Alice's id cert, and add carol
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let mut carol = PubClient::new(d.clone()).unwrap();
            carol.init("carol".to_string()).unwrap();
            let pr_carol = carol.publisher_request().unwrap();

            save_pr(&xml_dir, "alice.xml", &pr_alice);
            save_pr(&xml_dir, "carol.xml", &pr_carol);

            let server = PubServer::new(
                d.clone(),
                uri.clone(),
                xml_dir.clone()
            ).unwrap();

            // Now we expect a different Alice and Carol
            let publishers = server.publishers().unwrap();
            assert_eq!(2, publishers.len());

            let p_alice = publishers
                .iter()
                .find(|p| { p.name() == "alice" })
                .unwrap();

            assert_eq!(
                pr_alice.id_cert().to_bytes(),
                p_alice.id_cert().to_bytes()
            );

            assert_ne!(
                p_old_alice.id_cert().to_bytes(),
                p_alice.id_cert().to_bytes()
            );

            // Prove that we also have carol
            publishers.iter().find(|p| { p.name() == "carol" }).unwrap();

            // However, initialising the server with two or more xml files
            // for the same handle results in an error.
            save_pr(&xml_dir, "alice-2.xml", &pr_alice);

            assert!(
                PubServer::new(
                    d.clone(),
                    uri.clone(),
                    xml_dir.clone()
                ).is_err()
            );
        });
    }



}

