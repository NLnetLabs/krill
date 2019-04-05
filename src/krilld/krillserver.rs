//! An RPKI publication protocol server.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use rpki::uri;
use krill_commons::api::publication;
use krill_commons::api::admin;
use krill_commons::api::admin::PublisherHandle;
use crate::krilld::auth::Authorizer;
use crate::krilld::pubd::PubServer;
use crate::krilld::pubd;
use crate::krilld::pubd::publishers::Publisher;
use krill_cms_proxy::proxy::ProxyServer;
use krill_cms_proxy::proxy;
use krill_cms_proxy::api::ClientInfo;


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
    service_uri: uri::Http,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorisation checks
    authorizer: Authorizer,

    // The configured publishers
    pubserver: PubServer,

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
        service_uri: uri::Http,
        rrdp_base_uri: &uri::Http,
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

        Ok(
            KrillServer {
                service_uri,
                work_dir: work_dir.clone(),
                authorizer,
                pubserver,
                proxy_server
            }
        )
    }

    pub fn service_base_uri(&self) -> &uri::Http {
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
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_delta(
        &mut self,
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
    PubServer(pubd::Error),

    #[display(fmt="{}", _0)]
    ProxyServer(proxy::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<pubd::Error> for Error {
    fn from(e: pubd::Error) -> Self { Error::PubServer(e) }
}

impl From<proxy::Error> for Error {
    fn from(e: proxy::Error) -> Self { Error::ProxyServer(e) }
}

// Tested through integration tests