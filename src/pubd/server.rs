//! An RPKI publication protocol server.

use std::path::PathBuf;
use std::sync::Arc;
use provisioning::info::MyIdentity;
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
use rpki::oob::exchange::RepositoryResponse;


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

    publisher_list: PublisherList,

    service_uri: uri::Http,
    notify_sia: uri::Http
}

/// # Set up and initialisation
impl PubServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: PathBuf,
        pub_xml_dir: PathBuf,
        base_uri: uri::Rsync,
        service_uri: uri::Http,
        rrdp_notification_uri: uri::Http
    ) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(PathBuf::from(&work_dir))?;
        let publisher_list = Self::init_publishers(
            &work_dir,
            pub_xml_dir,
            base_uri)?;
        let signer = OpenSslSigner::new(work_dir)?;

        Ok(
            PubServer {
                signer,
                store,
                publisher_list,
                service_uri,
                notify_sia: rrdp_notification_uri
            }
        )
    }

    /// Initialise the publication server identity, if no identity had
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

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&my_id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }
}

/// # Configure publishers
impl PubServer {
    /// Synchronize publishers from disk
    fn init_publishers(
        work_dir: &PathBuf,
        pub_xml_dir: PathBuf,
        base_uri: uri::Rsync
    ) -> Result<PublisherList, Error> {
        let mut publisher_list = PublisherList::new(
            work_dir.clone(),
            base_uri)?;
        publisher_list.sync_from_dir(pub_xml_dir, actor())?;
        Ok(publisher_list)
    }

    /// Returns all currently configured publishers.
    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        self.publisher_list
            .publishers()
            .map_err(|e| { Error::PublisherListError(e) })
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        publisher_name: &str
    ) -> Result<RepositoryResponse, Error> {

        if let Some(my_id) = self.my_identity()? {
            match self.publishers()?
                .iter()
                .find(|p| { p.name() == publisher_name }) {
                None => Err(Error::UnknownPublisher(publisher_name.to_string())),
                Some(p) => {
                    let tag = p.tag();
                    let publisher_handle = p.name().clone();
                    let id_cert = my_id.id_cert().clone();
                    let service_uri = self.service_uri.clone();
                    let sia_base = p.base_uri().clone();
                    let rrdp_notification_uri = self.notify_sia.clone();

                    Ok(
                        RepositoryResponse::new(
                            tag,
                            publisher_handle,
                            id_cert,
                            service_uri,
                            sia_base,
                            rrdp_notification_uri
                        )
                    )
                }
            }
        } else {
            Err(Error::Uninitialised)
        }
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

    #[fail(display="Unknown publisher: {}", _0)]
    UnknownPublisher(String),

    #[fail(display="Publication server is not initialised.")]
    Uninitialised,
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
    use pubc::client::PubClient;

    fn test_server(work_dir: &PathBuf, xml_dir: &PathBuf) -> PubServer {
        // Start up a server
        let uri = test::rsync_uri("rsync://host/module/");
        let service = test::http_uri("http://host/publish");
        let notify = test::http_uri("http://host/notify.xml");
        PubServer::new(
            work_dir.clone(),
            xml_dir.clone(),
            uri,
            service,
            notify
        ).unwrap()
    }

    #[test]
    fn should_initialise_identity() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = test::create_sub_dir(&d);

            let mut server = test_server(&d, &xml_dir);

            // A clean publication server has no identity.
            assert_eq!(None, server.my_identity().unwrap());

            // Calling init will generate the identity.
            server.init_identity().unwrap();
            let id = server.my_identity().unwrap().unwrap();
            assert_eq!(actor().as_str(), id.name());

            // A new server with the same workdir will have the same identity.
            let server_2 = test_server(&d, &xml_dir);
            let id_2 = server_2.my_identity().unwrap().unwrap();
            assert_eq!(id, id_2);
        });
    }

    #[test]
    fn should_sync_and_resync_publishers_from_disk() {
        test::test_with_tmp_dir(|d| {
            // Set up an xml dir with two requests
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(alice_dir).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(bob_dir).unwrap();
            bob.init("bob".to_string()).unwrap();
            let pr_bob = bob.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());
            test::save_file(&xml_dir, "bob.xml", &pr_bob.encode_vec());

            // Start up a server
            let server = test_server(&d, &xml_dir);

            // The server now has two configured publishers
            let publishers = server.publishers().unwrap();
            assert_eq!(2, publishers.len());

            // Create a new xml dir with only alice.xml
            let xml_dir = PathBuf::from(test::create_sub_dir(&d));
            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());

            // Start a new server (so that it re-syncs)
            let server = test_server(&d, &xml_dir);

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

            let carol_dir = test::create_sub_dir(&d);
            let mut carol = PubClient::new(carol_dir).unwrap();
            carol.init("carol".to_string()).unwrap();
            let pr_carol = carol.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());
            test::save_file(&xml_dir, "carol.xml", &pr_carol.encode_vec());

            let server = test_server(&d, &xml_dir);

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
            test::save_file(&xml_dir, "alice-2.xml", &pr_alice.encode_vec());

            let uri = test::rsync_uri("rsync://host/module/");
            let service = test::http_uri("http://host/publish");
            let notify = test::http_uri("http://host/notify.xml");

            assert!(
                PubServer::new(
                    d.clone(),
                    xml_dir.clone(),
                    uri,
                    service,
                    notify
                ).is_err()
            );
        });
    }

    #[test]
    fn should_have_response_for_publisher() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(alice_dir).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(bob_dir).unwrap();
            bob.init("bob".to_string()).unwrap();
            let pr_bob = bob.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());
            test::save_file(&xml_dir, "bob.xml", &pr_bob.encode_vec());

            let mut server = test_server(&d, &xml_dir);
            server.init_identity_if_empty().unwrap();
            let server_id = server.my_identity().unwrap().unwrap();

            let response = server.repository_response("alice").unwrap();

            let expected_sia = test::rsync_uri("rsync://host/module/alice");
            let expected_service = test::http_uri("http://host/publish");
            let expected_notify = test::http_uri("http://host/notify.xml");

            assert_eq!(&expected_sia, response.sia_base());
            assert_eq!(&expected_service, response.service_uri());
            assert_eq!(&expected_notify, response.rrdp_notification_uri());
            assert_eq!("alice", response.publisher_handle());
            assert_eq!(
                server_id.id_cert().to_bytes(),
                response.id_cert().to_bytes()
            );
        });
    }

}

