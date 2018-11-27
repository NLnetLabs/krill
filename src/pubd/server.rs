//! An RPKI publication protocol server.

use std::path::PathBuf;
use std::sync::Arc;
use provisioning::publisher::Publisher;
use provisioning::publisher_store;
use provisioning::publisher_store::PublisherStore;
use repo::repository::{self, Repository};
use rpki::uri;
use rpki::oob::exchange::RepositoryResponse;
use pubd::responder::Responder;
use pubd::responder;


/// # Naming things in the keystore.
fn actor() -> String {
    "publication server".to_string()
}


//------------ PubServer -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct PubServer {
    // The component that manages server id, and wraps responses to clients
    responder: Responder,

    // The configured publishers
    publisher_store: PublisherStore,

    // The repository responsible for publishing rsync and rrdp
    repository: Repository,
}

/// # Set up and initialisation
impl PubServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: &PathBuf,
        pub_xml_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: uri::Http,
        rrdp_notification_uri: uri::Http
    ) -> Result<Self, Error> {
        let responder = Responder::init(
            work_dir,
            service_uri,
            rrdp_notification_uri)?;

        let publisher_store = Self::init_publishers(
            &work_dir,
            pub_xml_dir,
            base_uri)?;

        let repository = Repository::new(work_dir)?;

        Ok(
            PubServer {
                responder,
                repository,
                publisher_store
            }
        )
    }
}

/// # Configure publishers
impl PubServer {
    /// Synchronize publishers from disk
    fn init_publishers(
        work_dir: &PathBuf,
        pub_xml_dir: &PathBuf,
        base_uri: &uri::Rsync
    ) -> Result<PublisherStore, Error> {
        let mut publisher_store = PublisherStore::new(
            work_dir,
            base_uri)?;
        publisher_store.sync_from_dir(pub_xml_dir, actor())?;
        Ok(publisher_store)
    }

    /// Returns all currently configured publishers.
    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        self.publisher_store
            .publishers()
            .map_err(|e| { Error::PublisherStoreError(e) })
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        publisher_name: &str
    ) -> Result<RepositoryResponse, Error> {
        let publisher = self.publisher_store.get_publisher(publisher_name)?;
        self.responder
            .repository_response(publisher)
            .map_err(|e| Error::ResponderError(e))
    }
}

/// # Handle publisher requests
impl PubServer {

}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    ResponderError(responder::Error),

    #[fail(display="{}", _0)]
    PublisherStoreError(publisher_store::Error),

    #[fail(display="{}", _0)]
    RepositoryError(repository::Error),
}

impl From<responder::Error> for Error {
    fn from(e: responder::Error) -> Self {
        Error::ResponderError(e)
    }
}

impl From<publisher_store::Error> for Error {
    fn from(e: publisher_store::Error) -> Self {
        Error::PublisherStoreError(e)
    }
}

impl From<repository::Error> for Error {
    fn from(e: repository::Error) -> Self {
        Error::RepositoryError(e)
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
            work_dir,
            xml_dir,
            &uri,
            service,
            notify
        ).unwrap()
    }



    #[test]
    fn should_sync_and_resync_publishers_from_disk() {
        test::test_with_tmp_dir(|d| {
            // Set up an xml dir with two requests
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(&alice_dir).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(&bob_dir).unwrap();
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
            let mut carol = PubClient::new(&carol_dir).unwrap();
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
                    &d,
                    &xml_dir,
                    &uri,
                    service,
                    notify
                ).is_err()
            );
        });
    }

    #[test]
    fn
    should_initialise_publishers_from_xml_and_have_response() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(&alice_dir).unwrap();
            alice.init("alice".to_string()).unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(&bob_dir).unwrap();
            bob.init("bob".to_string()).unwrap();
            let pr_bob = bob.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());
            test::save_file(&xml_dir, "bob.xml", &pr_bob.encode_vec());

            let server = test_server(&d, &xml_dir);

            let response = server.repository_response("alice").unwrap();

            let expected_sia = test::rsync_uri("rsync://host/module/alice/");
            let expected_service = test::http_uri("http://host/publish");
            let expected_notify = test::http_uri("http://host/notify.xml");

            assert_eq!(&expected_sia, response.sia_base());
            assert_eq!(&expected_service, response.service_uri());
            assert_eq!(&expected_notify, response.rrdp_notification_uri());
            assert_eq!("alice", response.publisher_handle());
        });
    }

}

