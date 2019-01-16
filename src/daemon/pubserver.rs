//! An RPKI publication protocol server.

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::Captured;
use rpki::uri;
use rpki::x509::ValidationError;
use crate::daemon::api::auth::Authorizer;
use crate::daemon::publishers::{self, Publisher, PublisherStore};
use crate::daemon::repo::{self, Repository, RRDP_FOLDER};
use crate::daemon::responder::{self, Responder};
use crate::remote::oob::{PublisherRequest, RepositoryResponse};
use crate::remote::publication::pubmsg::{Message, MessageError, QueryMessage};
use crate::remote::publication::reply::{ErrorReply,ReportError, ReportErrorCode};
use crate::remote::sigmsg::SignedMessage;

/// # Naming things in the keystore.
const ACTOR: &'static str = "krill pubd";


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

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for authorisation checks
    authorizer: Authorizer
}

/// # Set up and initialisation
impl PubServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: &uri::Http,
        rrdp_base_uri: &uri::Http,
        authorizer: Authorizer
    ) -> Result<Self, Error> {
        let publisher_store = PublisherStore::new(work_dir, base_uri)?;

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
                work_dir: work_dir.clone(),
                authorizer
            }
        )
    }
}

impl PubServer {
    pub fn authorizer(&self) -> &Authorizer {
        &self.authorizer
    }
}

/// # Configure publishers
impl PubServer {
    /// Returns all currently configured publishers.
    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        self.publisher_store
            .publishers()
            .map_err(|e| { Error::PublisherStoreError(e) })
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &mut self,
        req: PublisherRequest,
        handle: &str,
    ) -> Result<(), Error> {
        self.publisher_store.add_publisher(
            req,
            handle,
            self.responder.base_service_uri(),
            ACTOR
        )?;
        Ok(())
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn remove_publisher(
        &mut self,
        name: impl AsRef<str>
    ) -> Result<(), Error> {
        self.publisher_store.remove_publisher(
            name,
            ACTOR
        )?;
        Ok(())
    }

    /// Returns an option for a publisher.
    pub fn publisher(
        &self,
        name: impl AsRef<str>
    ) -> Result<Option<Arc<Publisher>>, Error> {
        self.publisher_store.publisher(name)
            .map_err(|e| Error::PublisherStoreError(e))
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        name: impl AsRef<str>
    ) -> Result<RepositoryResponse, Error> {
        let publisher = self.publisher_store.get_publisher(name)?;
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
        sigmsg: &SignedMessage,
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

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    ResponderError(responder::Error),

    #[display(fmt="{}", _0)]
    PublisherStoreError(publishers::Error),

    #[display(fmt="{}", _0)]
    RepositoryError(repo::Error),

    #[display(fmt="{}", _0)]
    MessageError(MessageError),

    #[display(fmt="{}", _0)]
    ValidationError(ValidationError),
}

impl From<responder::Error> for Error {
    fn from(e: responder::Error) -> Self {
        Error::ResponderError(e)
    }
}

impl From<publishers::Error> for Error {
    fn from(e: publishers::Error) -> Self {
        Error::PublisherStoreError(e)
    }
}

impl From<repo::Error> for Error {
    fn from(e: repo::Error) -> Self {
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
        Error::ValidationError(e)
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

impl ToReportErrorCode for repo::Error {
    fn to_report_error_code(&self) -> ReportErrorCode {
        match self {
            repo::Error::ObjectAlreadyPresent(_) =>
                ReportErrorCode::ObjectAlreadyPresent,
            repo::Error::NoObjectPresent(_) =>
                ReportErrorCode::NoObjectPresent,
            repo::Error::NoObjectMatchingHash =>
                ReportErrorCode::NoObjectMatchingHash,
            repo::Error::OutsideBaseUri =>
                ReportErrorCode::PermissionFailure,
            _ => ReportErrorCode::OtherError
        }
    }
}


// Tested through integration tests