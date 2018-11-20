//! An RPKI publication protocol (command line) client, useful for testing,
//! in scenarios where a CA just writes its products to disk, and a separate
//! process is responsible for synchronising them to the repository.


use std::path::PathBuf;
use std::sync::Arc;
use rpki::oob::exchange::PublisherRequest;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::builder::IdCertBuilder;
use rpki::signing::signer::{CreateKeyError, KeyUseError, Signer};
use provisioning::info::MyIdentity;
use signing::softsigner;
use signing::softsigner::OpenSslSigner;
use storage::caching_ks::CachingDiskKeyStore;
use storage::keystore::{self, Info, Key, KeyStore};
use rpki::oob::exchange::RepositoryResponse;
use provisioning::info::ParentInfo;
use provisioning::info::MyRepoInfo;


/// # Some constants for naming resources in the keystore for clients.
fn actor() -> String {
    "publication client".to_string()
}

fn my_id_key() -> Key {
    Key::from_str("my_id")
}

fn my_parent_key() -> Key {
    Key::from_str("my_parent")
}

fn my_repo_key() -> Key {
    Key::from_str("my_repo")
}

fn my_id_msg() -> String {
    "initialised identity".to_string()
}

fn my_parent_msg() -> String {
    "updated parent info".to_string()
}

fn my_repo_msg() -> String {
    "update repo info".to_string()
}

//------------ PubClient -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct PubClient {
    // keys
    //   -> keys by id
    signer: OpenSslSigner,

    // key value store
    store: CachingDiskKeyStore,
    //   my_id     -> MyIdentity
    //   my_parent -> ParentInfo
    //   my_repo   -> MyRepoInfo

    //   -> my directory of interest
    //      (note: we do not keep this state in client, truth is on disk)
    // archive / log
    //   -> my exchanges with the server
}


impl PubClient {
    /// Creates a new publication client
    pub fn new(work_dir: PathBuf) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(work_dir.clone())?;
        let signer = OpenSslSigner::new(work_dir)?;
        Ok(
            PubClient {
                signer,
                store
            }
        )
    }


    /// Initialises a new publication client, using a new key pair, and
    /// returns a publisher request that can be sent to the server.
    pub fn init(&mut self, name: String) -> Result<(), Error> {
        let key_id = self.signer.create_key(&PublicKeyAlgorithm::RsaEncryption)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(name, id_cert, key_id);

        let key = my_id_key();
        let inf = Info::now(actor(), my_id_msg());
        self.store.store(key, my_id, inf)?;

        Ok(())
    }

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&my_id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Process the publication server parent response.
    pub fn process_repo_response(
        &mut self,
        response: RepositoryResponse
    ) -> Result<(), Error> {

        // Store parent info
        {
            let parent_val = ParentInfo::new(
                response.publisher_handle().clone(),
                response.id_cert().clone(),
                response.service_uri().clone()
            );
            let parent_info = Info::now(actor(), my_parent_msg());
            let parent_key = my_parent_key();

            self.store.store(parent_key, parent_val, parent_info)?;
        }

        // Store repo info
        {
            let repo_val = MyRepoInfo::new(
                response.sia_base().clone(),
                response.rrdp_notification_uri().clone()
            );
            let repo_info = Info::now(actor(), my_repo_msg());
            let repo_key = my_repo_key();

            self.store.store(repo_key, repo_val, repo_info)?;
        }

        Ok(())
    }

    pub fn publisher_request(&self) -> Result<PublisherRequest, Error> {
        match self.my_identity()? {
            None => Err(Error::Uninitialised),
            Some(arc) => {
                Ok(
                    PublisherRequest::new(
                        None,
                        arc.name(),
                        arc.id_cert().clone()
                    )
                )
            }
        }
    }
}

impl PartialEq for PubClient {
    fn eq(&self, other: &PubClient) -> bool {
        if let Ok(Some(my_id)) = self.my_identity() {
            if let Ok(Some(other_id)) = other.my_identity() {
                my_id == other_id
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Eq for PubClient { }


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display="This client is uninitialised.")]
    Uninitialised,

    #[fail(display="{}", _0)]
    SignerError(softsigner::Error),

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="{:?}", _0)]
    CreateKeyError(CreateKeyError),

    #[fail(display="{:?}", _0)]
    KeyUseError(KeyUseError),
}

impl From<softsigner::Error> for Error {
    fn from(e: softsigner::Error) -> Self {
        Error::SignerError(e)
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
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
    use pubd::server::PubServer;

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
    fn should_initialise_keep_state_and_reinitialise() {
        test::test_with_tmp_dir(|d| {
            // Set up a new client and initialise
            let mut client_1 = PubClient::new(d.clone()).unwrap();
            client_1.init("client".to_string()).unwrap();
            let pr_1 = client_1.publisher_request().unwrap();

            // Prove that a client starting from an initialised dir
            // comes up with the same state.
            let mut client_2 = PubClient::new(d.clone()).unwrap();
            let pr_2 = client_2.publisher_request().unwrap();
            assert_eq!(pr_1.handle(), pr_2.handle());
            assert_eq!(pr_1.id_cert().to_bytes(), pr_2.id_cert().to_bytes());
            assert_eq!(client_1, client_2);

            // But it can be re-initialised, with a new id cert
            client_2.init("client".to_string()).unwrap();
            let pr_2 = client_2.publisher_request().unwrap();
            assert_eq!(pr_1.handle(), pr_2.handle());
            assert_ne!(pr_1.id_cert().to_bytes(), pr_2.id_cert().to_bytes());
            assert_ne!(client_1, client_2);
        });
    }

    #[test]
    fn should_process_repo_response() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(alice_dir).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());

            let mut server = test_server(&d, &xml_dir);
            server.init_identity_if_empty().unwrap();

            let response = server.repository_response("alice").unwrap();

            alice.process_repo_response(response).unwrap();
        });
    }

}