//! An RPKI publication protocol server.

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::Captured;
use rpki::uri;
use rpki::x509::ValidationError;
use crate::provisioning::publisher::Publisher;
use crate::provisioning::publisher_store::{self, PublisherStore};
use crate::pubd::responder::{self, Responder};
use crate::repo::file_store;
use crate::repo::repository::{self, Repository};
use crate::repo::rrdp;
use crate::repo::rrdp::RRDP_FOLDER;
use crate::remote::oob::exchange::RepositoryResponse;
use crate::remote::publication::pubmsg::{Message, MessageError, QueryMessage};
use crate::remote::publication::reply::{
    ErrorReply, ReportError, ReportErrorCode
};
use crate::remote::sigmsg::SignedMessage;


/// # Naming things in the keystore.
const ACTOR: &'static str = "publication server";


//------------ PubServer -----------------------------------------------------

/// This is the publication server that is doing the actual RFC8181
/// protocol work, after some basic checks by done by the HTTP server.
///
/// It is responsible for validating and verifying RFC8181 query's and
/// constructing appropriate reply's.
#[derive(Clone, Debug)]
pub struct PubServer {
    // The component that manages server id, and wraps responses to clients
    responder: Responder,

    // The configured publishers
    publisher_store: PublisherStore,

    // The repository responsible for publishing rsync and rrdp
    repository: Repository,

    work_dir: PathBuf
}

/// # Set up and initialisation
impl PubServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: &PathBuf,
        pub_xml_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: &uri::Http,
        rrdp_base_uri: &uri::Http
    ) -> Result<Self, Error> {
        let publisher_store = Self::init_publishers(
            &work_dir,
            pub_xml_dir,
            service_uri,
            base_uri)?;

        let responder = Responder::init(
            work_dir,
            service_uri,
            rrdp_base_uri)?;

        let repository = Repository::new(rrdp_base_uri, work_dir)?;

        Ok(
            PubServer {
                responder,
                repository,
                publisher_store,
                work_dir: work_dir.clone()
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
        base_service_uri: &uri::Http,
        base_uri: &uri::Rsync
    ) -> Result<PublisherStore, Error> {
        let mut publisher_store = PublisherStore::new(
            work_dir,
            base_uri)?;
        publisher_store.sync_from_dir(
            pub_xml_dir,
            base_service_uri,
            ACTOR
        )?;
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

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push(RRDP_FOLDER);
        path
    }
}

/// # Handle publisher requests
///
impl PubServer {

    /// Handles an incoming SignedMessage, verifies it's validly signed by
    /// a known publisher and process the QueryMessage contained. Returns
    /// a signed response to the publisher.
    ///
    /// Note this returns an error for cases where we do not want to do any
    /// work in signing, like the publisher does not exist, or the
    /// signature is invalid. The daemon will need to map these to HTTP
    /// codes.
    ///
    /// Also note that if garbage is sent to the daemon, this garbage will
    /// fail to parse as a SignedMessage, and the daemon will just respond
    /// with an HTTP error response, without invoking any of this.
    pub fn handle_request(
        &mut self,
        sigmsg: SignedMessage,
        handle: &str
    ) -> Result<Captured, Error> {
        debug!("Handling request for: {}", handle);
        let publisher = self.publisher_store.get_publisher(handle)?;
        let base_uri = publisher.base_uri();
        sigmsg.validate(publisher.id_cert())?;
        debug!("Handler is known and request is validly signed");

        let res_msg = match Message::from_signed_message(&sigmsg) {
            Ok(msg) => {
                info!("Handling {} for {}.", msg.message_type(), handle);
                match msg.as_query() {
                    Ok(query) => self.handle_query(&query, base_uri),
                    Err(e) => Self::build_error(e)
                }
            },
            Err(e) => {
                Self::build_error(e)
            }
        };

        let sigres = self.responder.sign_msg(res_msg)?;
        Ok(sigres)
    }


    /// Handles a publish or list query for a publisher. Needs to know the
    /// base_uri for the publisher to enforce constraints, but can assume
    /// that the PubServer has already validated the incoming SignedMessage.
    ///
    /// Returns the appropriate Success or Error Reply in a Message, ready
    /// for wrapping into a SignedMessage.
    fn handle_query(
        &mut self,
        query: &QueryMessage,
        base_uri: &uri::Rsync
    ) -> Message {
        match query {
            QueryMessage::PublishQuery(publish) => {
                match self.repository.publish(publish, base_uri) {
                    Err(e) => {
                        Self::build_error(e)
                    },
                    Ok(success) => success
                }
            },
            QueryMessage::ListQuery(_list) => {
                match self.repository.list(base_uri) {
                    Err(e) => {
                        Self::build_error(e)
                    },
                    Ok(success) => success
                }
            }
        }
    }

    fn build_error(error: impl ToReportErrorCode + Debug) -> Message {
        let mut error_builder = ErrorReply::build();
        error_builder.add(
            ReportError::reply(
                error.to_report_error_code(),
                None // Finding the specific PDU is too much hard work.
            )
        );
        error_builder.build_message()
    }
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

    #[fail(display="{}", _0)]
    MessageError(MessageError),

    #[fail(display="{}", _0)]
    ValdiationError(ValidationError),
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

impl From<MessageError> for Error {
    fn from(e: MessageError) -> Self {
        Error::MessageError(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::ValdiationError(e)
    }
}


//------------ ToReportErrorCode ---------------------------------------------

trait ToReportErrorCode {
    fn to_report_error_code(&self) -> ReportErrorCode;
}

impl ToReportErrorCode for MessageError {
    fn to_report_error_code(&self) -> ReportErrorCode {
        ReportErrorCode::XmlError
    }
}

impl ToReportErrorCode for repository::Error {
    fn to_report_error_code(&self) -> ReportErrorCode {
        match self {
            repository::Error::FileStoreError(error) =>
                error.to_report_error_code(),
            repository::Error::RrdpError(error) =>
                error.to_report_error_code()
        }
    }
}

impl ToReportErrorCode for file_store::Error {
    fn to_report_error_code(&self) -> ReportErrorCode {
        match self {
            file_store::Error::ObjectAlreadyPresent(_) =>
                ReportErrorCode::ObjectAlreadyPresent,
            file_store::Error::NoObjectPresent(_) =>
                ReportErrorCode::NoObjectPresent,
            file_store::Error::NoObjectMatchingHash =>
                ReportErrorCode::NoObjectMatchingHash,
            file_store::Error::OutsideBaseUri =>
                ReportErrorCode::PermissionFailure,
            _ => ReportErrorCode::OtherError
        }
    }
}

impl ToReportErrorCode for rrdp::Error {
    fn to_report_error_code(&self) -> ReportErrorCode {
        ReportErrorCode::OtherError
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
        let service = test::http_uri("http://host/publish/");
        let rrdp_base = test::http_uri("http://host/rrdp/");
        PubServer::new(
            work_dir,
            xml_dir,
            &uri,
            &service,
            &rrdp_base
        ).unwrap()
    }



    #[test]
    fn should_sync_and_resync_publishers_from_disk() {
        test::test_with_tmp_dir(|d| {
            // Set up an xml dir with two requests
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(&alice_dir).unwrap();
            alice.init("alice").unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(&bob_dir).unwrap();
            bob.init("bob").unwrap();
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
            alice.init("alice").unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let carol_dir = test::create_sub_dir(&d);
            let mut carol = PubClient::new(&carol_dir).unwrap();
            carol.init("carol").unwrap();
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
            let rrdp_base = test::http_uri("http://host/rrdp");

            assert!(
                PubServer::new(
                    &d,
                    &xml_dir,
                    &uri,
                    &service,
                    &rrdp_base
                ).is_err()
            );
        });
    }

    #[test]
    fn should_initialise_publishers_from_xml_and_have_response() {
        test::test_with_tmp_dir(|d| {
            let xml_dir = test::create_sub_dir(&d);

            let alice_dir = test::create_sub_dir(&d);
            let mut alice = PubClient::new(&alice_dir).unwrap();
            alice.init("alice").unwrap();
            let pr_alice = alice.publisher_request().unwrap();

            let bob_dir = test::create_sub_dir(&d);
            let mut bob = PubClient::new(&bob_dir).unwrap();
            bob.init("bob").unwrap();
            let pr_bob = bob.publisher_request().unwrap();

            test::save_file(&xml_dir, "alice.xml", &pr_alice.encode_vec());
            test::save_file(&xml_dir, "bob.xml", &pr_bob.encode_vec());

            let server = test_server(&d, &xml_dir);

            let response = server.repository_response("alice").unwrap();

            let expected_sia = test::rsync_uri("rsync://host/module/alice/");
            let expected_service = test::http_uri("http://host/publish/alice");
            let expected_rrdp = test::http_uri
                ("http://host/rrdp/notification.xml");

            assert_eq!(&expected_sia, response.sia_base());
            assert_eq!(&expected_service, response.service_uri());
            assert_eq!(&expected_rrdp, response.rrdp_notification_uri());
            assert_eq!("alice", response.publisher_handle());
        });
    }

}

