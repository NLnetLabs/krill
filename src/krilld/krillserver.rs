//! An RPKI publication protocol server.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::Captured;
use rpki::uri;
use crate::api::publication_data;
use crate::api::publisher_data;
use crate::api::publisher_data::PublisherHandle;
use crate::eventsourcing::KeyStore;
use crate::krilld::auth::Authorizer;
use crate::krilld::pubd::PubServer;
use crate::krilld::pubd;
use crate::krilld::pubd::publishers::Publisher;
use crate::remote::cmsproxy::{self, CmsProxy};
use crate::remote::rfc8183;
use crate::remote::sigmsg::SignedMessage;


//------------ KrillServer ---------------------------------------------------

/// This is the master krill server that is doing all the orchestration
/// for all the components, like:
/// * Admin tasks:
///    * Verify (admin) API access
///    * Manage known publishers
/// * CMS proxy:
///    * Decodes and validates CMS sent by known publishers using CMS
///    * Encodes and signs CMS responses for remote publishers using CMS
/// * Repository:
///    * Process publish / list requests by known publishers
///    * Updates the repository on disk
///    * Updates the RRDP files
pub struct KrillServer<S: KeyStore> {
    // The base URI for this service
    service_uri: uri::Http,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorisation checks
    authorizer: Authorizer,

    // Responsible for the RFC CMS decoding and encoding.
    cms_proxy: CmsProxy,

    // The configured publishers
    pubserver: PubServer<S>
}

/// # Set up and initialisation
impl<S: KeyStore> KrillServer<S> {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn build(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: uri::Http,
        rrdp_base_uri: &uri::Http,
        authorizer: Authorizer,
        store: S
    ) -> Result<Self, Error> {
        let cms_proxy = CmsProxy::build(work_dir)?;

        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let pubserver = PubServer::build(
            base_uri.clone(),
            rrdp_base_uri.clone(),
            repo_dir,
            store
        ).map_err(Error::PubServer)?;

        Ok(
            KrillServer {
                service_uri,
                work_dir: work_dir.clone(),
                authorizer,
                cms_proxy,
                pubserver
            }
        )
    }

    pub fn service_base_uri(&self) -> &uri::Http {
        &self.service_uri
    }
}

impl<S: KeyStore> KrillServer<S> {
    pub fn is_api_allowed(&self, token_opt: Option<String>) -> bool {
        self.authorizer.is_api_allowed(token_opt)
    }

    pub fn is_publication_api_allowed(
        &self,
        handle_opt: Option<String>,
        token_opt: Option<String>
    ) -> bool {
        match handle_opt {
            None => false,
            Some(handle_str) => {
                match token_opt {
                    None => false,
                    Some(token) => {
                        let handle = PublisherHandle::from(handle_str);
                        if let Ok(Some(pbl)) = self.publisher(&handle) {
                            pbl.token() == &token
                        } else {
                            false
                        }
                    }
                }
            }
        }
    }

}

/// # Configure publishers
impl<S: KeyStore> KrillServer<S> {

    /// Returns all currently configured publishers. (excludes deactivated)
    pub fn publishers(
        &self
    ) -> Result<Vec<PublisherHandle>, Error> {
        self.pubserver.list_publishers().map_err(Error::PubServer)
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &mut self,
        pbl_req: publisher_data::PublisherRequest
    ) -> Result<(), Error> {
        self.pubserver.create_publisher(pbl_req).map_err(Error::PubServer)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn deactivate_publisher(
        &mut self,
        handle: &PublisherHandle
    ) -> Result<(), Error> {
        self.pubserver.deactivate_publisher(handle).map_err(Error::PubServer)
    }

    /// Returns an option for a publisher.
    pub fn publisher(
        &self,
        handle: &PublisherHandle
    ) -> Result<Option<Arc<Publisher>>, Error> {
        self.pubserver.get_publisher(handle).map_err(Error::PubServer)
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        handle: &PublisherHandle
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        match self.pubserver.get_publisher(handle)? {
            None => Err(Error::NoIdCert),
            Some(publisher) => {
                let rrdp_notify = self.pubserver.rrdp_notification();
                self.cms_proxy
                    .repository_response(
                        &publisher,
                        self.service_base_uri(),
                        rrdp_notify)
                    .map_err(Error::CmsProxy)
            }
        }
    }

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push("rrdp");
        path
    }
}

/// # Handle publication requests
///
impl<S: KeyStore> KrillServer<S> {

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
    pub fn handle_rfc8181_request(
        &mut self,
        sigmsg: &SignedMessage,
        handle: &PublisherHandle
    ) -> Result<Captured, Error> {
        debug!("Handling request for: {}", handle.to_string());

        let publisher = match self.pubserver.get_publisher(handle)? {
            Some(publisher) => publisher,
            None => return Err(Error::NoIdCert)
        };

        let id_cert = match publisher.cms_auth_data() {
            Some(data) => data.id_cert(),
            None => return Err(Error::NoIdCert)
        };

        match self.cms_proxy.publish_request(sigmsg, id_cert) {
            Err(e)  => self.cms_proxy.wrap_error(&e).map_err(Error::CmsProxy),
            Ok(req) => {
                let reply = match req {
                    publication_data::PublishRequest::List => {
                        self.handle_list(handle)
                            .map(publication_data::PublishReply::List)
                    },
                    publication_data::PublishRequest::Delta(delta) => {
                        self.handle_delta(delta, handle)
                            .map(|_| publication_data::PublishReply::Success)
                    }
                };

                match reply {
                    Ok(reply) => {
                        self.cms_proxy.wrap_publish_reply(reply).map_err(Error::CmsProxy)
                    },
                    Err(Error::PubServer(e)) => {
                        self.cms_proxy.wrap_error(&e).map_err(Error::CmsProxy)
                    },
                    Err(e) => Err(e)
                }
            }
        }
    }

    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_delta(
        &mut self,
        delta: publication_data::PublishDelta,
        handle: &PublisherHandle
    ) -> Result<(), Error> {
        self.pubserver.publish(handle, delta).map_err(Error::PubServer)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(
        &self,
        handle: &PublisherHandle
    ) -> Result<publication_data::ListReply, Error> {
        self.pubserver.list(handle).map_err(Error::PubServer)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    CmsProxy(cmsproxy::Error),

    #[display(fmt="{}", _0)]
    PubServer(pubd::Error),

    #[display(fmt="No IdCert known for this publisher")]
    NoIdCert
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<cmsproxy::Error> for Error {
    fn from(e: cmsproxy::Error) -> Self { Error::CmsProxy(e) }
}

impl From<pubd::Error> for Error {
    fn from(e: pubd::Error) -> Self { Error::PubServer(e) }
}

// Tested through integration tests