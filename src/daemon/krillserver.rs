//! An RPKI publication protocol server.
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::{io, thread};

use bytes::Bytes;
use chrono::Duration;
use rpki::cert::Cert;
use rpki::uri;

use crate::commons::api::{
    AddChildRequest, CaRepoDetails, CertAuthHistory, CertAuthInfo, CertAuthInit, CertAuthList,
    ChildCaInfo, ChildHandle, CurrentRepoState, Handle, ListReply, ParentCaContact, ParentCaReq,
    ParentHandle, PublishDelta, PublisherDetails, PublisherHandle, RepoInfo, RepositoryContact,
    RepositoryUpdate, RoaDefinition, RoaDefinitionUpdates, TaCertDetails, UpdateChildRequest,
};
use crate::commons::remote::rfc8183;
use crate::commons::util::softsigner::{OpenSslSigner, SignerError};
use crate::constants::*;
use crate::daemon::auth::{Auth, Authorizer};
use crate::daemon::ca::{self, ta_handle};
use crate::daemon::config::Config;
use crate::daemon::mq::EventQueueListener;
use crate::daemon::scheduler::Scheduler;
use crate::pubd;
use crate::pubd::PubServer;
use crate::publish::CaPublisher;

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
    pubserver: Option<Arc<PubServer>>,

    // Handles the internal TA and/or CAs
    caserver: Arc<ca::CaServer<OpenSslSigner>>,

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
        let rrdp_base_uri = &config.rrdp_service_uri();
        let token = &config.auth_token;
        let ca_refresh_rate = config.ca_refresh;

        info!("Starting {} v{}", KRILL_SERVER_APP, KRILL_VERSION);
        info!("{} uses service uri: {}", KRILL_SERVER_APP, service_uri);

        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let signer = OpenSslSigner::build(work_dir)?;
        let signer = Arc::new(RwLock::new(signer));

        let authorizer = Authorizer::new(token);

        let pubserver = {
            if config.repo_enabled {
                Some(PubServer::build(
                    &base_uri,
                    rrdp_base_uri.clone(),
                    work_dir,
                    signer.clone(),
                )?)
            } else {
                PubServer::remove_if_empty(
                    &base_uri,
                    rrdp_base_uri.clone(),
                    work_dir,
                    signer.clone(),
                )?
            }
        };
        let pubserver: Option<Arc<PubServer>> = pubserver.map(Arc::new);

        let event_queue = Arc::new(EventQueueListener::in_mem());
        let caserver = Arc::new(ca::CaServer::build(work_dir, event_queue.clone(), signer)?);

        if config.use_ta() {
            let ta_handle = ta_handle();
            if !caserver.has_ca(&ta_handle) {
                info!("Creating embedded Trust Anchor");

                let pubserver = pubserver.as_ref().ok_or_else(|| Error::NoEmbeddedRepo)?;
                let repo_info: RepoInfo = pubserver.repo_info_for(&ta_handle)?;

                let ta_uri = config.ta_cert_uri();

                let ta_aia = format!("{}ta/ta.cer", config.rsync_base.to_string());
                let ta_aia = uri::Rsync::from_string(ta_aia).unwrap();

                // Add TA
                caserver
                    .init_ta(repo_info.clone(), ta_aia, vec![ta_uri])
                    .map_err(Error::CaServerError)?;

                let ta = caserver.get_trust_anchor()?;

                // Add publisher
                let req =
                    rfc8183::PublisherRequest::new(None, ta_handle.clone(), ta.id_cert().clone());

                pubserver.create_publisher(req)?;

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
            scheduler,
        })
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }
}

/// # Authentication
impl KrillServer {
    pub fn is_api_allowed(&self, auth: &Auth) -> bool {
        self.authorizer.is_api_allowed(auth)
    }
}

/// # Configure publishers
impl KrillServer {
    fn get_embedded(&self) -> Result<&Arc<PubServer>, Error> {
        self.pubserver.as_ref().ok_or_else(|| Error::NoEmbeddedRepo)
    }

    /// Returns all currently configured publishers. (excludes deactivated)
    pub fn publishers(&self) -> Result<Vec<Handle>, Error> {
        self.get_embedded()?.publishers().map_err(Error::PubServer)
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &self,
        req: rfc8183::PublisherRequest,
    ) -> KrillRes<rfc8183::RepositoryResponse> {
        let publisher_handle = req.publisher_handle().clone();

        self.get_embedded()?
            .create_publisher(req)
            .map_err(Error::PubServer)?;

        self.repository_response(&publisher_handle)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn remove_publisher(&mut self, publisher: PublisherHandle) -> EmptyRes {
        self.get_embedded()?
            .remove_publisher(publisher)
            .map_err(Error::PubServer)
    }

    /// Returns a publisher.
    pub fn get_publisher(&self, publisher: &PublisherHandle) -> Result<PublisherDetails, Error> {
        self.get_embedded()?
            .get_publisher_details(publisher)
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
    pub fn repository_response(
        &self,
        publisher: &PublisherHandle,
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        let rfc8181_uri =
            uri::Https::from_string(format!("{}rfc8181/{}", self.service_uri, publisher)).unwrap();

        self.get_embedded()?
            .repository_response(rfc8181_uri, publisher)
            .map_err(Error::PubServer)
    }

    pub fn rfc8181(&self, publisher: PublisherHandle, msg_bytes: Bytes) -> KrillRes<Bytes> {
        self.get_embedded()?
            .rfc8181(publisher, msg_bytes)
            .map_err(Error::PubServer)
    }
}

/// # Being a parent
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

    /// Shows the parent contact for a child.
    pub fn ca_parent_contact(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
    ) -> KrillRes<ParentCaContact> {
        let contact = self
            .caserver
            .ca_parent_contact(parent, child, None, &self.service_uri)?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub fn ca_parent_response(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
    ) -> KrillRes<rfc8183::ParentResponse> {
        let contact = self
            .caserver
            .ca_parent_response(parent, child, None, &self.service_uri)?;
        Ok(contact)
    }

    /// Update IdCert or resources of a child.
    pub fn ca_child_update(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
    ) -> EmptyRes {
        self.caserver.ca_child_update(parent, child, req)?;
        Ok(())
    }

    /// Update IdCert or resources of a child.
    pub fn ca_child_remove(&self, handle: &Handle, child: ChildHandle) -> EmptyRes {
        self.caserver.ca_child_remove(handle, child)?;
        Ok(())
    }

    /// Show details for a child under the TA.
    pub fn ca_show_child(
        &self,
        parent: &ParentHandle,
        child: &ChildHandle,
    ) -> KrillRes<ChildCaInfo> {
        let child = self.caserver.ca_show_child(parent, child)?;
        Ok(child)
    }
}

/// # Being a child
///
impl KrillServer {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub fn ca_child_req(&self, handle: &Handle) -> KrillRes<rfc8183::ChildRequest> {
        self.caserver
            .get_ca(handle)
            .map(|ca| ca.child_request())
            .map_err(Error::CaServerError)
    }

    /// Adds a parent to a CA, will check first if the parent can be reached.
    pub fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq) -> EmptyRes {
        self.ca_parent_reachable(&handle, parent.handle(), parent.contact())?;
        Ok(self.caserver.ca_parent_add(handle, parent)?)
    }

    /// Updates a parent contact for a CA
    pub fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> EmptyRes {
        self.ca_parent_reachable(&handle, &parent, &contact)?;
        Ok(self.caserver.ca_parent_update(handle, parent, contact)?)
    }

    fn ca_parent_reachable(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
    ) -> EmptyRes {
        self.caserver
            .get_entitlements_from_parent_and_contact(handle, parent, contact)
            .map_err(|e| {
                Error::CaServerError(ca::ServerError::CertAuth(ca::Error::ParentNotResponsive(
                    e.to_string(),
                )))
            })?;
        Ok(())
    }

    pub fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle) -> EmptyRes {
        Ok(self.caserver.ca_parent_remove(handle, parent)?)
    }
}

/// # Bulk background operations CAS
///
impl KrillServer {
    /// Republish all CAs that need it.
    pub fn republish_all(&self) -> EmptyRes {
        self.caserver.republish_all()?;
        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub fn resync_all(&self) -> EmptyRes {
        let publisher = CaPublisher::new(self.caserver.clone(), self.pubserver.clone());

        for ca in self.caserver.cas().cas() {
            if let Err(e) = publisher.publish(ca.handle()) {
                error!("Failed to sync ca: {}. Got error: {}", ca.handle(), e)
            }
        }

        Ok(())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub fn refresh_all(&self) -> EmptyRes {
        let server = self.caserver.clone();
        thread::spawn(move || {
            server.refresh_all();
        });
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
    pub fn ca_info(&self, handle: &Handle) -> KrillRes<CertAuthInfo> {
        self.caserver
            .get_ca(handle)
            .map(|ca| ca.as_ca_info())
            .map_err(Error::CaServerError)
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the CA or the parent cannot be found.
    pub fn ca_my_parent_contact(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> KrillRes<ParentCaContact> {
        let ca = self.caserver.get_ca(handle)?;
        ca.parent(parent)
            .map(|p| p.clone())
            .map_err(|e| Error::CaServerError(ca::ServerError::CertAuth(e)))
    }

    /// Returns the history for a CA, or NONE in case of issues (i.e. it does not exist).
    pub fn ca_history(&self, handle: &Handle) -> Option<CertAuthHistory> {
        self.caserver.get_ca_history(handle).ok()
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be found.
    pub fn ca_publisher_req(&self, handle: &Handle) -> Option<rfc8183::PublisherRequest> {
        self.caserver
            .get_ca(handle)
            .map(|ca| ca.publisher_request())
            .ok()
    }

    pub fn ca_init(&mut self, init: CertAuthInit) -> EmptyRes {
        let handle = init.unpack();

        // Create CA
        self.caserver.init_ca(&handle)?;

        Ok(())
    }

    /// Return the info about the configured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub fn ca_repo_details(&self, handle: &Handle) -> KrillRes<CaRepoDetails> {
        let ca = self.caserver.get_ca(handle).map_err(Error::CaServerError)?;
        let contact = ca
            .get_repository_contact()
            .map_err(|e| Error::CaServerError(ca::ServerError::CertAuth(e)))?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    /// Returns the state of the current configured repo for a ca
    pub fn ca_repo_state(&self, handle: &Handle) -> KrillRes<CurrentRepoState> {
        let ca = self.caserver.get_ca(handle).map_err(Error::CaServerError)?;
        let contact = ca
            .get_repository_contact()
            .map_err(|e| Error::CaServerError(ca::ServerError::CertAuth(e)))?;
        Ok(self.repo_state(handle, contact.as_reponse_opt()))
    }

    /// Update the repository for a CA, or return an error. (see `CertAuth::repo_update`)
    pub fn ca_update_repo(&self, handle: Handle, update: RepositoryUpdate) -> EmptyRes {
        let contact = match update {
            RepositoryUpdate::Embedded => {
                // Add to embedded publication server if not present
                if self.get_embedded()?.get_publisher_details(&handle).is_err() {
                    let ca = self.caserver.get_ca(&handle)?;
                    let id_cert = ca.id_cert().clone();

                    // Add publisher
                    let req = rfc8183::PublisherRequest::new(None, handle.clone(), id_cert);
                    self.add_publisher(req)?;
                }

                RepositoryContact::embedded(self.get_embedded()?.repo_info_for(&handle)?)
            }
            RepositoryUpdate::Rfc8181(response) => {
                // first check that the new repo can be contacted
                if let CurrentRepoState::Error(msg) = self.repo_state(&handle, Some(&response)) {
                    return Err(Error::CaServerError(ca::ServerError::CertAuth(
                        ca::Error::NewRepoUpdateNotResponsive(msg),
                    )));
                }

                RepositoryContact::Rfc8181(response)
            }
        };

        Ok(self.caserver.update_repo(handle, contact)?)
    }

    fn repo_state(
        &self,
        handle: &Handle,
        repo: Option<&rfc8183::RepositoryResponse>,
    ) -> CurrentRepoState {
        match repo {
            None => match self.get_embedded() {
                Err(e) => CurrentRepoState::error(e),
                Ok(repo) => match repo.list(handle) {
                    Err(e) => CurrentRepoState::error(e),
                    Ok(list) => CurrentRepoState::list(list),
                },
            },
            Some(repo) => match self.caserver.send_rfc8181_list(handle, repo) {
                Err(e) => CurrentRepoState::error(e),
                Ok(list) => CurrentRepoState::list(list),
            },
        }
    }

    pub fn ca_update_id(&self, handle: Handle) -> EmptyRes {
        Ok(self.caserver.ca_update_id(handle)?)
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

    pub fn rfc6492(&self, handle: Handle, msg_bytes: Bytes) -> KrillRes<Bytes> {
        Ok(self.caserver.rfc6492(&handle, msg_bytes)?)
    }
}

/// # Handle route authorization requests
///
impl KrillServer {
    pub fn ca_routes_update(&self, handle: Handle, updates: RoaDefinitionUpdates) -> EmptyRes {
        Ok(self.caserver.ca_routes_update(handle, updates.into())?)
    }

    pub fn ca_routes_show(&self, handle: &Handle) -> Result<Vec<RoaDefinition>, Error> {
        let ca = self.caserver.get_ca(handle)?;
        Ok(ca.roa_definitions())
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    pub fn handle_delta(&self, publisher: PublisherHandle, delta: PublishDelta) -> EmptyRes {
        self.get_embedded()?
            .publish(publisher, delta)
            .map_err(Error::PubServer)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, publisher: &PublisherHandle) -> Result<ListReply, Error> {
        self.get_embedded()?
            .list(publisher)
            .map_err(Error::PubServer)
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
    SignerError(SignerError),

    #[display(fmt = "{}", _0)]
    CaServerError(ca::ServerError),

    #[display(fmt = "No embedded repository configured")]
    NoEmbeddedRepo,
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

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self {
        Error::SignerError(e)
    }
}

impl From<ca::ServerError> for Error {
    fn from(e: ca::ServerError) -> Self {
        Error::CaServerError(e)
    }
}

// Tested through integration tests
