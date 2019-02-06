//! An RPKI publication protocol server.
use std::path::PathBuf;
use std::sync::Arc;
use bcder::Captured;
use rpki::uri;
use crate::api::publication;
use crate::api::publishers;
use crate::krilld::auth::Authorizer;
use crate::krilld::pubd::{self, PublisherStore};
use crate::krilld::pubd::repo::{self, Repository};
use crate::remote::cmsproxy::{self, CmsProxy};
use crate::remote::rfc8183;
use crate::remote::sigmsg::SignedMessage;

/// # Naming things in the keystore.
const ACTOR: &str = "krill pubd";


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
    // The base URI for this service
    service_uri: uri::Http,

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
    pub fn build(
        work_dir: &PathBuf,
        base_uri: &uri::Rsync,
        service_uri: uri::Http,
        rrdp_base_uri: &uri::Http,
        authorizer: Authorizer
    ) -> Result<Self, Error> {
        let cms_proxy = CmsProxy::build(work_dir)?;
        let publisher_store = PublisherStore::build(work_dir, base_uri)?;
        let repository = Repository::build(rrdp_base_uri, work_dir)?;

        Ok(
            KrillServer {
                service_uri,
                work_dir: work_dir.clone(),
                authorizer,
                cms_proxy,
                publisher_store,
                repository,
            }
        )
    }

    pub fn service_base_uri(&self) -> &uri::Http {
        &self.service_uri
    }
}

impl KrillServer {
    pub fn allow_api(&self, token_opt: Option<String>) -> bool {
        self.authorizer.api_allowed(token_opt)
    }

    pub fn allow_publication_api(
        &self,
        handle_opt: Option<String>,
        token_opt: Option<String>
    ) -> bool {
        match handle_opt {
            None => false,
            Some(handle) => {
                match token_opt {
                    None => false,
                    Some(token) => {
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
    /// Returns all currently configured publishers.
    pub fn publishers(&self) -> Result<Vec<Arc<publishers::Publisher>>, Error> {
        self.publisher_store
            .publishers()
            .map_err(|e| { Error::PublisherStore(e) })
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &mut self,
        pbl: publishers::Publisher
    ) -> Result<(), Error> {

        self.publisher_store.add_publisher(
            pbl,
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
    ) -> Result<Option<Arc<publishers::Publisher>>, Error> {
        self.publisher_store.publisher(name)
            .map_err(Error::PublisherStore)
    }

    /// Returns a repository response for the given publisher.
    ///
    /// Returns an error if the publisher is unknown.
    pub fn repository_response(
        &self,
        name: impl AsRef<str>
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        let publisher = self.publisher_store.get_publisher(name)?;
        let rrdp_notification = self.repository.rrdp_notification_uri();
        self.cms_proxy
            .repository_response(
                &publisher,
                self.service_base_uri(),
                rrdp_notification)
            .map_err(Error::CmsProxy)
    }

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push("rrdp");
        path
    }
}

/// # Handle publication requests
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
    pub fn handle_rfc8181_request(
        &mut self,
        sigmsg: &SignedMessage,
        handle: &str
    ) -> Result<Captured, Error> {
        debug!("Handling request for: {}", handle);
        let publisher = self.publisher_store.get_publisher(handle)?;

        let id_cert = match publisher.cms_auth_data() {
            Some(details) => details.id_cert(),
            None => return Err(Error::NoIdCert)
        };

        match self.cms_proxy.publish_request(sigmsg, id_cert) {
            Err(e)  => self.cms_proxy.wrap_error(&e).map_err(Error::CmsProxy),
            Ok(req) => {
                let reply = match req {
                    publication::PublishRequest::List => {
                        self.handle_list(handle)
                            .map(publication::PublishReply::List)
                    },
                    publication::PublishRequest::Delta(delta) => {
                        self.handle_delta(delta, handle)
                            .map(|_| publication::PublishReply::Success)
                    }
                };

                match reply {
                    Ok(reply) => {
                        self.cms_proxy.wrap_publish_reply(reply).map_err(Error::CmsProxy)
                    },
                    Err(Error::Repository(e)) => {
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
        delta: publication::PublishDelta,
        handle: &str
    ) -> Result<(), Error> {
        let publisher = self.publisher_store.get_publisher(handle)?;
        let base_uri = publisher.base_uri();
        self.repository.publish(&delta, base_uri).map_err(Error::Repository)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(
        &self,
        handle: &str
    ) -> Result<publication::ListReply, Error> {
        let publisher = self.publisher_store.get_publisher(handle)?;
        let base_uri = publisher.base_uri();
        self.repository.list(base_uri).map_err(Error::Repository)
    }
}

// /// # Serve RRDP files
// ///
//impl KrillServer {
//    /// Gets the current notification
//    pub fn current_notification(&self) -> Result<repo::Notification, Error> {
//        unimplemented!()
//    }
//
//    /// Gets the current snapshot
//    pub fn current_snapshot(&self) -> Result<data::Snapshot, Error> {
//        unimplemented!()
//    }
//
//}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    CmsProxy(cmsproxy::Error),

    #[display(fmt="{}", _0)]
    PublisherStore(pubd::Error),

    #[display(fmt="{}", _0)]
    Repository(repo::Error),

    #[display(fmt="No IdCert known for this publisher")]
    NoIdCert
}

impl From<cmsproxy::Error> for Error {
    fn from(e: cmsproxy::Error) -> Self {
        Error::CmsProxy(e)
    }
}

impl From<pubd::Error> for Error {
    fn from(e: pubd::Error) -> Self {
        Error::PublisherStore(e)
    }
}

impl From<repo::Error> for Error {
    fn from(e: repo::Error) -> Self {
        Error::Repository(e)
    }
}


// Tested through integration tests