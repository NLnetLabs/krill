//! An RPKI publication protocol server.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bcder::Captured;
use bytes::Bytes;
use chrono::Duration;
use rpki::cert::Cert;
use rpki::uri;

use crate::commons::api::CertAuthHistory;
use crate::commons::api::{
    AddChildRequest, AddParentRequest, CertAuthInfo, CertAuthInit, CertAuthList, CertAuthPubMode,
    ChildCaInfo, ChildHandle, Handle, ListReply, ParentCaContact, ParentHandle, PublishDelta,
    PublishRequest, PublisherRequest, RouteAuthorizationUpdates, TaCertDetails, Token,
    UpdateChildRequest,
};
use crate::commons::remote::api::ClientInfo;
use crate::commons::remote::proxy;
use crate::commons::remote::proxy::ProxyServer;
use crate::commons::remote::rfc8181::ReplyMessage;
use crate::commons::remote::rfc8183::{ChildRequest, RepositoryResponse};
use crate::commons::remote::sigmsg::SignedMessage;
use crate::commons::util::softsigner::{OpenSslSigner, SignerError};
use crate::daemon::auth::{Auth, Authorizer};
use crate::daemon::ca::{self, ta_handle};
use crate::daemon::config::Config;
use crate::daemon::mq::EventQueueListener;
use crate::daemon::scheduler::Scheduler;
use crate::pubd;
use crate::pubd::publishers::Publisher;
use crate::pubd::PubServer;

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
    pub fn build(config: &Config) -> KrillRes<Self> {
        let work_dir = &config.data_dir;
        let base_uri = &config.rsync_base;
        let service_uri = config.service_uri();
        let rrdp_base_uri = &config.rrdp_base_uri();
        let token = &config.auth_token;
        let ca_refresh_rate = config.ca_refresh;

        info!("Starting krill using service uri: {}", service_uri);

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

        if config.use_ta() {
            let ta_handle = ta_handle();
            if !caserver.has_ca(&ta_handle) {
                info!("Creating embedded Trust Anchor");

                let repo_info = pubserver.repo_info_for(&ta_handle)?;

                let ta_uri = config.ta_cert_uri();

                let ta_aia = format!("{}ta/ta.cer", config.rsync_base.to_string());
                let ta_aia = uri::Rsync::from_string(ta_aia).unwrap();
                let token = caserver.random_token();

                // Add publisher
                let req = PublisherRequest::new(
                    ta_handle.clone(),
                    token.clone(),
                    repo_info.base_uri().clone(),
                );

                pubserver.create_publisher(req).map_err(Error::PubServer)?;

                // Add TA
                caserver
                    .init_ta(repo_info, ta_aia, vec![ta_uri])
                    .map_err(Error::CaServerError)?;

                // Force initial  publication
                caserver.republish(&ta_handle)?;
            }
        }

        let scheduler = Scheduler::build(
            event_queue,
            caserver.clone(),
            pubserver.clone(),
            ca_refresh_rate,
        );

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
            trace!("Access to publication api allowed")
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
    pub fn add_publisher(&mut self, pbl_req: PublisherRequest) -> EmptyRes {
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
        path.push("repo/rrdp");
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

/// # Admin CA as parent
///
impl KrillServer {
    pub fn ta(&self) -> KrillRes<TaCertDetails> {
        let ta = self.caserver.get_ca(&ta_handle())?;
        if let ParentCaContact::Ta(ta) = ta.parent(&ta_handle()).unwrap() {
            Ok(ta.clone())
        } else {
            panic!("Found TA which was not initialized as TA.")
        }
    }

    pub fn trust_anchor_cert(&self) -> Option<Cert> {
        self.ta().ok().map(|details| details.cert().clone())
    }

    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub fn ca_add_child(
        &self,
        parent: &ParentHandle,
        req: AddChildRequest,
    ) -> KrillRes<ParentCaContact> {
        let contact = self.caserver.ca_add_child(parent, req, &self.service_uri)?;
        Ok(contact)
    }

    /// Update IdCert or resources of a child.
    pub fn ca_update_child(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
    ) -> EmptyRes {
        self.caserver.ca_update_child(parent, child, req)?;
        Ok(())
    }

    /// Show details for a child under the TA.
    pub fn ca_show_child(
        &self,
        parent: &ParentHandle,
        child: &ChildHandle,
    ) -> KrillRes<Option<ChildCaInfo>> {
        let child = self.caserver.ca_show_child(parent, child)?;
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

    /// Returns the history for a CA, or NONE in case of issues (i.e. it does not exist).
    pub fn ca_history(&self, handle: &Handle) -> Option<CertAuthHistory> {
        self.caserver.get_ca_history(handle).ok()
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
        let req = PublisherRequest::new(handle.clone(), token.clone(), base_uri);
        self.add_publisher(req)?;

        Ok(())
    }

    pub fn ca_add_parent(&self, handle: Handle, parent: AddParentRequest) -> EmptyRes {
        Ok(self.caserver.ca_add_parent(handle, parent)?)
    }

    pub fn ca_keyroll_init(&self, handle: Handle) -> EmptyRes {
        Ok(self
            .caserver
            .ca_keyroll_init(handle, Duration::seconds(0))?)
    }

    pub fn ca_keyroll_activate(&self, handle: Handle) -> EmptyRes {
        Ok(self
            .caserver
            .ca_keyroll_activate(handle, Duration::seconds(0))?)
    }

    pub fn rfc6492(&self, handle: Handle, msg: SignedMessage) -> KrillRes<Bytes> {
        Ok(self.caserver.rfc6492(&handle, msg)?)
    }
}

/// # Handle route authorization requests
///
impl KrillServer {
    pub fn ca_routes_update(&self, handle: Handle, updates: RouteAuthorizationUpdates) -> EmptyRes {
        Ok(self.caserver.ca_routes_update(handle, updates)?)
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_delta(&self, delta: PublishDelta, handle: &Handle) -> EmptyRes {
        self.pubserver
            .publish(handle, delta)
            .map_err(Error::PubServer)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, handle: &Handle) -> Result<ListReply, Error> {
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
    PubServer(pubd::Error),

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

impl From<pubd::Error> for Error {
    fn from(e: pubd::Error) -> Self {
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
