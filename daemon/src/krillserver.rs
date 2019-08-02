//! An RPKI publication protocol server.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bcder::Captured;
use bytes::Bytes;
use rpki::uri;

use krill_commons::api::admin;
use krill_commons::api::admin::{
    AddChildRequest, AddParentRequest, CertAuthInit, CertAuthPubMode, Handle, ParentCaContact,
    Token, UpdateChildRequest,
};
use krill_commons::api::ca::{CertAuthInfo, CertAuthList, ChildCaInfo, RcvdCert, TrustAnchorInfo};
use krill_commons::api::publication::PublishRequest;
use krill_commons::api::{publication, Entitlements, IssuanceRequest, IssuanceResponse};
use krill_commons::remote::api::ClientInfo;
use krill_commons::remote::proxy;
use krill_commons::remote::proxy::ProxyServer;
use krill_commons::remote::rfc8181::ReplyMessage;
use krill_commons::remote::rfc8183::{ChildRequest, RepositoryResponse};
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::util::softsigner::{OpenSslSigner, SignerError};
use krill_pubd::publishers::Publisher;
use krill_pubd::PubServer;

use crate::auth::{Auth, Authorizer};
use crate::ca::ChildHandle;
use crate::ca::{self, ta_handle};
use crate::mq::EventQueueListener;
use crate::scheduler::Scheduler;

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

    // Publication server, with configured publishers
    pubserver: Arc<PubServer>,

    // Handles the internal TA and/or CAs
    caserver: Arc<ca::CaServer<OpenSslSigner>>,

    // CMS+XML proxy server for non-Krill clients
    proxy_server: ProxyServer,

    // Responsible for background tasks, e.g. re-publishing
    #[allow(dead_code)] // just need to keep this in scope
    scheduler: Scheduler,
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
        token: &Token,
    ) -> KrillRes<Self> {
        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let authorizer = Authorizer::new(token);

        let pubserver = Arc::new(
            PubServer::build(base_uri.clone(), rrdp_base_uri.clone(), repo_dir, work_dir)
                .map_err(Error::PubServer)?,
        );

        let proxy_server = ProxyServer::init(work_dir, &service_uri)?;

        let signer = OpenSslSigner::build(work_dir)?;

        let event_queue = Arc::new(EventQueueListener::in_mem());

        let caserver = Arc::new(ca::CaServer::build(work_dir, event_queue.clone(), signer)?);

        let scheduler = Scheduler::build(event_queue, caserver.clone(), pubserver.clone());

        Ok(KrillServer {
            service_uri,
            work_dir: work_dir.clone(),
            authorizer,
            pubserver,
            caserver,
            proxy_server,
            scheduler,
        })
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }
}

impl KrillServer {
    pub fn login(&self, token: Token) -> bool {
        self.authorizer.is_api_allowed(&token)
    }

    pub fn is_api_allowed(&self, auth: &Auth) -> bool {
        match auth {
            Auth::User(name) => name == "admin",
            Auth::Bearer(token) => self.authorizer.is_api_allowed(&token),
        }
    }

    pub fn is_publication_api_allowed(&self, handle: &Handle, auth: &Auth) -> bool {
        let allowed = match auth {
            Auth::User(name) => name == "admin",
            Auth::Bearer(token) => {
                if self.authorizer.is_api_allowed(&token) {
                    true
                } else if let Ok(Some(pbl)) = self.publisher(&handle) {
                    pbl.token() == token
                } else {
                    false
                }
            }
        };

        if allowed {
            debug!("Access to publication api allowed")
        } else {
            warn!(
                "Access to publication api disallowed for handle: {}, and auth: {}",
                handle, auth
            );
        }

        allowed
    }
}

/// # Configure publishers
impl KrillServer {
    /// Returns all currently configured publishers. (excludes deactivated)
    pub fn publishers(&self) -> Vec<Handle> {
        self.pubserver.list_publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(&mut self, pbl_req: admin::PublisherRequest) -> EmptyRes {
        self.pubserver
            .create_publisher(pbl_req)
            .map_err(Error::PubServer)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn deactivate_publisher(&mut self, handle: &Handle) -> EmptyRes {
        self.pubserver
            .deactivate_publisher(handle)
            .map_err(Error::PubServer)
    }

    /// Returns an option for a publisher.
    pub fn publisher(&self, handle: &Handle) -> Result<Option<Arc<Publisher>>, Error> {
        self.pubserver
            .get_publisher(handle)
            .map_err(Error::PubServer)
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
    pub fn rfc8181_clients(&self) -> Result<Vec<ClientInfo>, Error> {
        self.proxy_server.list_clients().map_err(Error::ProxyServer)
    }

    pub fn add_rfc8181_client(&self, client: ClientInfo) -> EmptyRes {
        self.proxy_server
            .add_client(client)
            .map_err(Error::ProxyServer)
    }

    pub fn repository_response(&self, handle: &Handle) -> Result<RepositoryResponse, Error> {
        let publisher = self
            .publisher(handle)?
            .ok_or_else(|| Error::ProxyServer(proxy::Error::UnknownClient(handle.clone())))?;

        let sia_base = publisher.base_uri().clone();

        let service_uri = format!("{}rfc8181/{}", self.service_uri.to_string(), handle);
        let service_uri = uri::Https::from_string(service_uri).unwrap();

        let rrdp_notification_uri =
            format!("{}rrdp/notification.xml", self.service_uri.to_string(),);
        let rrdp_notification_uri = uri::Https::from_string(rrdp_notification_uri).unwrap();

        self.proxy_server
            .response(handle, service_uri, sia_base, rrdp_notification_uri)
            .map_err(Error::ProxyServer)
    }

    pub fn handle_rfc8181_req(
        &self,
        msg: SignedMessage,
        handle: Handle,
    ) -> Result<Captured, Error> {
        debug!("Handling signed request for {}", &handle);
        match self.try_rfc8181_req(msg, handle) {
            Ok(captured) => Ok(captured),
            Err(Error::ProxyServer(e)) => {
                self.proxy_server.wrap_error(e).map_err(Error::ProxyServer)
            }
            Err(e) => Err(e),
        }
    }

    /// Try to handle the rfc8181 request, and error out in case of
    /// issues.
    fn try_rfc8181_req(&self, msg: SignedMessage, handle: Handle) -> Result<Captured, Error> {
        let req = self.proxy_server.convert_rfc8181_req(msg, &handle)?;
        let reply = match req {
            PublishRequest::List => ReplyMessage::ListReply(self.pubserver.list(&handle)?),
            PublishRequest::Delta(delta) => {
                self.pubserver.publish(&handle, delta)?;
                ReplyMessage::SuccessReply
            }
        };

        self.proxy_server
            .sign_reply(reply)
            .map_err(Error::ProxyServer)
    }
}

/// # Admin Trust Anchor
///
impl KrillServer {
    pub fn ta_info(&self) -> Option<TrustAnchorInfo> {
        match self.caserver.get_trust_anchor() {
            Ok(ta) => ta.as_ta_info().ok(),
            _ => None,
        }
    }

    pub fn trust_anchor_cert(&self) -> Option<RcvdCert> {
        self.ta_info().map(|ta| ta.cert().clone())
    }

    pub fn ta_init(&mut self) -> EmptyRes {
        let ta_handle = ta_handle();

        let repo_info = self.pubserver.repo_info_for(&ta_handle)?;

        let ta_uri = format!("{}{}", self.service_uri.to_string(), "ta/ta.cer");
        let ta_uri = uri::Https::from_string(ta_uri).unwrap();

        let ta_aia = self.pubserver.ta_aia();

        let token = self.caserver.random_token();

        // Add publisher
        let req = admin::PublisherRequest::new(
            ta_handle.clone(),
            token.clone(),
            repo_info.base_uri().clone(),
        );
        self.add_publisher(req)?;

        // Add TA
        self.caserver
            .init_ta(repo_info, ta_aia, vec![ta_uri])
            .map_err(Error::CaServerError)?;

        // Force initial  publication
        self.caserver.republish(&ta_handle)?;

        Ok(())
    }

    /// Adds a child to the TA and returns the ParentCaInfo that the child
    /// will to contact this TA for resource requests.
    pub fn ta_add_child(&self, req: AddChildRequest) -> KrillRes<ParentCaContact> {
        let contact = self.caserver.ta_add_child(req, &self.service_uri)?;
        Ok(contact)
    }

    pub fn ta_update_child(&self, child: ChildHandle, req: UpdateChildRequest) -> EmptyRes {
        self.caserver.ta_update_child(child, req)?;
        Ok(())
    }

    /// Show details for a child under the TA.
    pub fn ta_show_child(&self, child: &ChildHandle) -> KrillRes<Option<ChildCaInfo>> {
        let child = self.caserver.ta_show_child(child)?;
        Ok(child)
    }

    pub fn republish_all(&self) -> EmptyRes {
        self.caserver.republish_all()?;
        Ok(())
    }
}

/// # Admin CAS
///
impl KrillServer {
    pub fn cas(&self) -> CertAuthList {
        self.caserver.cas()
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be found.
    pub fn ca_info(&self, handle: &Handle) -> Option<CertAuthInfo> {
        self.caserver.get_ca(handle).map(|ca| ca.as_ca_info()).ok()
    }

    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub fn ca_child_req(&self, handle: &Handle) -> Option<ChildRequest> {
        self.caserver
            .get_ca(handle)
            .map(|ca| ca.child_request())
            .ok()
    }

    pub fn ca_init(&mut self, init: CertAuthInit) -> EmptyRes {
        let (handle, token, pub_mode) = init.unwrap();

        let repo_info = match pub_mode {
            CertAuthPubMode::Embedded => self.pubserver.repo_info_for(&handle)?,
        };
        let base_uri = repo_info.ca_repository("");

        // Create CA
        self.caserver.init_ca(&handle, token.clone(), repo_info)?;

        // Add publisher
        let req = admin::PublisherRequest::new(handle.clone(), token.clone(), base_uri);
        self.add_publisher(req)?;

        Ok(())
    }

    pub fn ca_add_parent(&self, handle: Handle, parent: AddParentRequest) -> EmptyRes {
        self.caserver.ca_add_parent(handle, parent)?;
        Ok(())
    }

    pub fn list(&self, parent: &Handle, child: &Handle, auth: Auth) -> KrillRes<Entitlements> {
        Ok(self.caserver.list(parent, child, &auth.into())?)
    }

    pub fn issue(
        &self,
        parent: &Handle,
        child: &Handle,
        issue_req: IssuanceRequest,
        auth: Auth,
    ) -> KrillRes<IssuanceResponse> {
        Ok(self.caserver.issue(parent, child, issue_req, auth.into())?)
    }

    pub fn rfc6492(&self, handle: Handle, msg: SignedMessage) -> KrillRes<Bytes> {
        Ok(self.caserver.rfc6492(&handle, msg)?)
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_delta(&self, delta: publication::PublishDelta, handle: &Handle) -> EmptyRes {
        self.pubserver
            .publish(handle, delta)
            .map_err(Error::PubServer)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, handle: &Handle) -> Result<publication::ListReply, Error> {
        self.pubserver.list(handle).map_err(Error::PubServer)
    }
}

//------------ Response Aliases ----------------------------------------------

type KrillRes<T> = Result<T, Error>;
type EmptyRes = KrillRes<()>;

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    PubServer(krill_pubd::Error),

    #[display(fmt = "{}", _0)]
    ProxyServer(proxy::Error),

    #[display(fmt = "{}", _0)]
    SignerError(SignerError),

    #[display(fmt = "{}", _0)]
    CaServerError(ca::ServerError<OpenSslSigner>),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<krill_pubd::Error> for Error {
    fn from(e: krill_pubd::Error) -> Self {
        Error::PubServer(e)
    }
}

impl From<proxy::Error> for Error {
    fn from(e: proxy::Error) -> Self {
        Error::ProxyServer(e)
    }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self {
        Error::SignerError(e)
    }
}

impl From<ca::ServerError<OpenSslSigner>> for Error {
    fn from(e: ca::ServerError<OpenSslSigner>) -> Self {
        Error::CaServerError(e)
    }
}

// Tested through integration tests
