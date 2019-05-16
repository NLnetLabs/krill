//! An RPKI publication protocol server.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bcder::Captured;
use rpki::uri;

use krill_ca::{CaServer, CaServerError};
use krill_commons::api::publication;
use krill_commons::api::admin;
use krill_commons::api::admin::PublisherHandle;
use krill_commons::api::ca::{TrustAnchorInfo, IncomingCertificate};
use krill_commons::util::softsigner::{OpenSslSigner, SignerError};
use krill_cms_proxy::api::{ClientInfo, ClientHandle};
use krill_cms_proxy::proxy;
use krill_cms_proxy::proxy::ProxyServer;
use krill_cms_proxy::rfc8183::RepositoryResponse;
use krill_cms_proxy::sigmsg::SignedMessage;
use krill_pubd::PubServer;
use krill_pubd::publishers::Publisher;

use crate::auth::Authorizer;


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
pub struct KrillServer {
    // The base URI for this service
    service_uri: uri::Https,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorisation checks
    authorizer: Authorizer,

    // The configured publishers
    pubserver: PubServer,

    // The configured publishers
    caserver: CaServer<OpenSslSigner>,

    // CMS+XML proxy server for non-Krill clients
    proxy_server: ProxyServer
}

/// # Set up and initialisation
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn build(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: uri::Https,
        rrdp_base_uri: &uri::Https,
        authorizer: Authorizer,
    ) -> Result<Self, Error> {
        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let pubserver = PubServer::build(
            base_uri.clone(),
            rrdp_base_uri.clone(),
            repo_dir,
            work_dir
        ).map_err(Error::PubServer)?;


        let proxy_server = ProxyServer::init(
            work_dir, &service_uri
        )?;

        let signer = OpenSslSigner::build(work_dir)?;
        let caserver = CaServer::build(work_dir, signer)?;

        Ok(
            KrillServer {
                service_uri,
                work_dir: work_dir.clone(),
                authorizer,
                pubserver,
                caserver,
                proxy_server
            }
        )
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }
}

impl KrillServer {
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
impl KrillServer {

    /// Returns all currently configured publishers. (excludes deactivated)
    pub fn publishers(
        &self
    ) -> Vec<PublisherHandle> {
        self.pubserver.list_publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &mut self,
        pbl_req: admin::PublisherRequest
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

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push("rrdp");
        path
    }
}

/// # Manage RFC8181 clients
///
impl KrillServer {
    pub fn rfc8181_clients(&self) ->Result<Vec<ClientInfo>, Error> {
        self.proxy_server.list_clients().map_err(Error::ProxyServer)
    }

    pub fn add_rfc8181_client(&self, client: ClientInfo) -> Result<(), Error> {
        self.proxy_server.add_client(client).map_err(Error::ProxyServer)
    }

    pub fn repository_response(&self, handle: &PublisherHandle) -> Result<RepositoryResponse, Error> {
        let client = ClientHandle::from(handle);
        let publisher = self.publisher(handle)?
            .ok_or_else(|| Error::ProxyServer(proxy::Error::UnknownClient(client.clone())))?;

        let sia_base = publisher.base_uri().clone();

        let service_uri = format!(
            "{}rfc8181/{}",
            self.service_uri.to_string(),
            &client
        );
        let service_uri = uri::Https::from_string(service_uri).unwrap();

        let rrdp_notification_uri = format!(
            "{}rrdp/notification.xml",
            self.service_uri.to_string(),
        );
        let rrdp_notification_uri = uri::Https::from_string(rrdp_notification_uri).unwrap();

        self.proxy_server.response(
            &client,
            service_uri,
            sia_base,
            rrdp_notification_uri
        ).map_err(Error::ProxyServer)
    }

    pub fn handle_rfc8181_req(
        &self,
        msg: SignedMessage,
        handle: ClientHandle
    ) -> Result<Captured, Error> {
        self.proxy_server.handle_rfc8181_req(msg, handle).map_err(Error::ProxyServer)
    }
}

/// # Admin Trust Anchor
///
impl KrillServer {
    pub fn trust_anchor(&self) ->  Option<TrustAnchorInfo> {
        self.caserver.get_trust_anchor_info().ok()
    }

    pub fn trust_anchor_cert(&self) -> Option<IncomingCertificate> {
        self.caserver.get_trust_anchor_cert().ok()
    }

    pub fn init_trust_anchor(&mut self) -> Result<(), Error> {
        let repo_info = self.pubserver.repo_info_for(&PublisherHandle::from("ta"))?;

        let ta_uri = format!("{}{}", self.service_uri.to_string(), "ta/ta.cer");
        let ta_uri = uri::Https::from_string(ta_uri).unwrap();

        let ta_aia = self.pubserver.ta_aia();

        self.caserver.init_ta(repo_info, ta_aia, vec![ta_uri]).map_err(Error::CaServerError)
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_delta(
        &self,
        delta: publication::PublishDelta,
        handle: &PublisherHandle
    ) -> Result<(), Error> {
        self.pubserver.publish(handle, delta).map_err(Error::PubServer)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(
        &self,
        handle: &PublisherHandle
    ) -> Result<publication::ListReply, Error> {
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
    PubServer(krill_pubd::Error),

    #[display(fmt="{}", _0)]
    ProxyServer(proxy::Error),

    #[display(fmt="{}", _0)]
    SignerError(SignerError),

    #[display(fmt="{}", _0)]
    CaServerError(CaServerError<OpenSslSigner>),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<krill_pubd::Error> for Error {
    fn from(e: krill_pubd::Error) -> Self { Error::PubServer(e) }
}

impl From<proxy::Error> for Error {
    fn from(e: proxy::Error) -> Self { Error::ProxyServer(e) }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self { Error::SignerError(e) }
}

impl From<CaServerError<OpenSslSigner>> for Error {
    fn from(e: CaServerError<OpenSslSigner>) -> Self { Error::CaServerError(e) }
}

// Tested through integration tests