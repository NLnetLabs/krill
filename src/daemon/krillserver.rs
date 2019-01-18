//! An RPKI publication protocol server.
use std::path::PathBuf;
use std::sync::Arc;
use bcder::Captured;
use rpki::uri;
use crate::daemon::api::auth::Authorizer;
use crate::daemon::api::requests::PublishDelta;
use crate::daemon::api::requests::PublishRequest;
use crate::daemon::api::responses;
use crate::daemon::publishers::{self, Publisher, PublisherStore};
use crate::daemon::repo::{self, Repository, RRDP_FOLDER};
use crate::remote::cmsproxy::{self, CmsProxy};
use crate::remote::rfc8183::{PublisherRequest, RepositoryResponse};
use crate::remote::sigmsg::SignedMessage;

/// # Naming things in the keystore.
const ACTOR: &'static str = "krill pubd";


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
#[derive(Clone, Debug)]
pub struct KrillServer {
    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorisation checks
    authorizer: Authorizer,

    // Responsible for the RFC CMS decoding and encoding.
    cms_proxy: CmsProxy,

    // The configured publishers
    publisher_store: PublisherStore,

    // The repository responsible for publishing rsync and rrdp
    repository: Repository,
}

/// # Set up and initialisation
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub fn new(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: &uri::Http,
        rrdp_base_uri: &uri::Http,
        authorizer: Authorizer
    ) -> Result<Self, Error> {
        let cms_proxy = CmsProxy::new(work_dir, service_uri)?;
        let publisher_store = PublisherStore::new(work_dir, base_uri)?;
        let repository = Repository::new(rrdp_base_uri, work_dir)?;

        Ok(
            KrillServer {
                work_dir: work_dir.clone(),
                authorizer,
                cms_proxy,
                publisher_store,
                repository,
            }
        )
    }
}

impl KrillServer {
    pub fn authorizer(&self) -> &Authorizer {
        &self.authorizer
    }
}

/// # Configure publishers
impl KrillServer {
    /// Returns all currently configured publishers.
    pub fn publishers(&self) -> Result<Vec<Arc<Publisher>>, Error> {
        self.publisher_store
            .publishers()
            .map_err(|e| { Error::PublisherStore(e) })
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
            self.cms_proxy.base_service_uri(),
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
            .map_err(|e| Error::PublisherStore(e))
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        name: impl AsRef<str>
    ) -> Result<RepositoryResponse, Error> {
        let publisher = self.publisher_store.get_publisher(name)?;
        let rrdp_notification = self.repository.rrdp_notification_uri();
        self.cms_proxy
            .repository_response(publisher, rrdp_notification)
            .map_err(|e| Error::CmsProxy(e))
    }

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push(RRDP_FOLDER);
        path
    }
}

/// # Handle publisher requests
///
impl KrillServer {

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

        match self.cms_proxy.publish_request(sigmsg, publisher.id_cert()) {
            Err(e)  => self.cms_proxy.wrap_error(e).map_err(|e| Error::CmsProxy(e)),
            Ok(req) => {
                let reply = match req {
                    PublishRequest::List => {
                        self.handle_list(handle)
                    },
                    PublishRequest::Delta(delta) => {
                        self.handle_delta(delta, handle)
                    }
                };

                match reply {
                    Ok(reply) => self.cms_proxy.wrap_publish_reply(reply).map_err(|e| Error::CmsProxy(e)),
                    Err(Error::Repository(e)) => self.cms_proxy.wrap_error(e).map_err(|e| Error::CmsProxy(e)),
                    Err(e) => Err(e)
                }
            }
        }
    }

    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    pub fn handle_delta(
        &mut self,
        delta: PublishDelta,
        handle: &str
    ) -> Result<responses::PublishReply, Error> {
        let publisher = self.publisher_store.get_publisher(handle)?;
        let base_uri = publisher.base_uri();
        self.repository.publish(&delta, base_uri)
            .map_err(|e| Error::Repository(e))
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(
        &mut self,
        handle: &str
    ) -> Result<responses::PublishReply, Error> {
        let publisher = self.publisher_store.get_publisher(handle)?;
        let base_uri = publisher.base_uri();
        self.repository.list(base_uri).map_err(|e| Error::Repository(e))
    }

}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    CmsProxy(cmsproxy::Error),

    #[display(fmt="{}", _0)]
    PublisherStore(publishers::Error),

    #[display(fmt="{}", _0)]
    Repository(repo::Error),
}

impl From<cmsproxy::Error> for Error {
    fn from(e: cmsproxy::Error) -> Self {
        Error::CmsProxy(e)
    }
}

impl From<publishers::Error> for Error {
    fn from(e: publishers::Error) -> Self {
        Error::PublisherStore(e)
    }
}

impl From<repo::Error> for Error {
    fn from(e: repo::Error) -> Self {
        Error::Repository(e)
    }
}


// Tested through integration tests