//! An RPKI publication protocol server.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::Cert;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::actor::{Actor, ActorDef};
use crate::commons::api::{
    AddChildRequest, AllCertAuthIssues, CaCommandDetails, CaRepoDetails, CertAuthInfo, CertAuthInit, CertAuthIssues,
    CertAuthList, CertAuthStats, ChildAuthRequest, ChildCaInfo, ChildHandle, CommandHistory, CommandHistoryCriteria,
    Handle, ListReply, ParentCaContact, ParentCaReq, ParentHandle, ParentStatuses, PublicationServerUris, PublishDelta,
    PublisherDetails, PublisherHandle, RepoInfo, RepoStatus, RepositoryContact, RepositoryUpdate, ResourceSet,
    RoaDefinition, RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, ServerInfo, TaCertDetails,
    UpdateChildRequest,
};
use crate::commons::bgp::{BgpAnalyser, BgpAnalysisReport, BgpAnalysisSuggestion};
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use crate::commons::eventsourcing::CommandKey;
use crate::commons::remote::rfc8183;
use crate::commons::{KrillEmptyResult, KrillResult};
use crate::constants::*;
#[cfg(feature = "multi-user")]
use crate::daemon::auth::common::session::LoginSessionCache;
use crate::daemon::auth::providers::MasterTokenAuthProvider;
#[cfg(feature = "multi-user")]
use crate::daemon::auth::providers::{ConfigFileAuthProvider, OpenIDConnectAuthProvider};
use crate::daemon::auth::{Authorizer, LoggedInUser};
use crate::daemon::ca::{
    self, ta_handle, testbed_ca_handle, CaManager, ResourceTaggedAttestation, RouteAuthorizationUpdates,
    RtaContentRequest, RtaPrepareRequest,
};
use crate::daemon::config::{AuthType, Config};
use crate::daemon::http::HttpResponse;
use crate::daemon::mq::MessageQueue;
use crate::daemon::scheduler::Scheduler;
use crate::pubd::{RepoStats, RepositoryManager};
use crate::publish::CaPublisher;

//------------ KrillMode ----------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum KrillMode {
    Pubd,
    Ca,
    Mixed, // will be removed in future - used to support existing deployments
}

impl KrillMode {
    pub fn cas_enabled(&self) -> bool {
        match self {
            KrillMode::Ca | KrillMode::Mixed => true,
            KrillMode::Pubd => false,
        }
    }

    pub fn pubd_enabled(&self) -> bool {
        match self {
            KrillMode::Pubd | KrillMode::Mixed => true,
            KrillMode::Ca => false,
        }
    }
}

//------------ KrillServer ---------------------------------------------------

/// This is the master krill server that is doing all the orchestration
/// for all the components.
pub struct KrillServer {
    // The base URI for this service
    service_uri: uri::Https,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorization checks
    authorizer: Authorizer,

    // Publication server, with configured publishers
    repo_manager: Option<Arc<RepositoryManager>>,

    // Handles the internal TA and/or CAs
    ca_manager: Option<Arc<ca::CaManager>>,

    // Handles the internal TA and/or CAs
    bgp_analyser: Arc<BgpAnalyser>,

    // Responsible for background tasks, e.g. re-publishing
    #[allow(dead_code)] // just need to keep this in scope
    scheduler: Scheduler,

    // Time this server was started
    started: Time,

    // Global size constraints on things which can be posted
    post_limits: PostLimits,

    #[cfg(feature = "multi-user")]
    // Global login session cache
    login_session_cache: Arc<LoginSessionCache>,

    // System actor
    system_actor: Actor,
}

pub struct PostLimits {
    api: u64,
    rfc6492: u64,
    rfc8181: u64,
}

impl PostLimits {
    fn new(api: u64, rfc6492: u64, rfc8181: u64) -> Self {
        PostLimits { api, rfc8181, rfc6492 }
    }

    pub fn api(&self) -> u64 {
        self.api
    }
    pub fn rfc6492(&self) -> u64 {
        self.rfc6492
    }
    pub fn rfc8181(&self) -> u64 {
        self.rfc8181
    }
}

/// # Set up and initialization
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub async fn build(config: Arc<Config>, mut mode: KrillMode) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let service_uri = config.service_uri();

        info!("Starting {} v{}", KRILL_SERVER_APP, KRILL_VERSION);
        info!("{} uses service uri: {}", KRILL_SERVER_APP, service_uri);

        if config.testbed().is_some() {
            if mode == KrillMode::Ca {
                // Enable embedded repo for testbed. In future the testbed
                // will require separate components (krill-ta, krillpubd, krill)
                info!("Enabling TESTBED mode - ONLY USE THIS FOR TESTING AND TRAINING!");
                mode = KrillMode::Mixed
            } else {
                return Err(Error::custom(
                    "Krill TESTBED can only be used with krill, not krillpubd",
                ));
            }
        }

        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let signer = Arc::new(KrillSigner::build(work_dir)?);

        #[cfg(feature = "multi-user")]
        let login_session_cache = Arc::new(LoginSessionCache::new());

        // Construct the authorizer used to verify API access requests and to
        // tell Lagosta where to send end-users to login and logout.
        // TODO: remove the ugly duplication, however attempts to do so have so
        // far failed due to incompatible match arm types, or unknown size of
        // dyn AuthProvider, or concrete type needs to be known in async fn,
        // etc.
        let authorizer = match config.auth_type {
            AuthType::MasterToken => Authorizer::new(config.clone(), MasterTokenAuthProvider::new(config.clone()))?,
            #[cfg(feature = "multi-user")]
            AuthType::ConfigFile => Authorizer::new(
                config.clone(),
                ConfigFileAuthProvider::new(config.clone(), login_session_cache.clone())?,
            )?,
            #[cfg(feature = "multi-user")]
            AuthType::OpenIDConnect => Authorizer::new(
                config.clone(),
                OpenIDConnectAuthProvider::new(config.clone(), login_session_cache.clone())?,
            )?,
        };
        let system_actor = authorizer.actor_from_def(ACTOR_DEF_KRILL);

        // for now, support that existing embedded repositories are still supported.
        // this should be removed in future after people have had a chance to separate.
        let repo_manager = {
            if mode.pubd_enabled() {
                Some(RepositoryManager::build(config.clone(), signer.clone())?)
            } else {
                RepositoryManager::keep_if_used(config.clone(), signer.clone())?
            }
        };

        let repo_manager: Option<Arc<RepositoryManager>> = repo_manager.map(Arc::new);

        // Used to have a shared queue for the caserver and the background job scheduler.
        let event_queue = Arc::new(MessageQueue::default());

        let ca_manager = if mode.cas_enabled() {
            let ca_manager = Arc::new(ca::CaManager::build(config.clone(), event_queue.clone(), signer).await?);

            if let Some(testbed) = config.testbed() {
                let repo_manager = repo_manager.as_ref().ok_or(Error::RepositoryServerNotEnabled)?;

                let uris = testbed.publication_server_uris();

                if !repo_manager.initialized()? {
                    repo_manager.init(uris.clone())?;
                }

                let ta_handle = ta_handle();
                if !ca_manager.has_ca(&ta_handle)? {
                    info!("Creating embedded Trust Anchor");

                    let repo_info: RepoInfo = repo_manager.repo_info_for(&ta_handle)?;

                    let ta_uri = testbed.ta_uri().clone();
                    let ta_aia = testbed.ta_aia().clone();

                    // Add TA
                    ca_manager
                        .init_ta(repo_info, ta_aia, vec![ta_uri], &system_actor)
                        .await?;

                    let ta = ca_manager.get_trust_anchor().await?;

                    // Add publisher
                    let req = rfc8183::PublisherRequest::new(None, ta_handle.clone(), ta.id_cert().clone());

                    repo_manager.create_publisher(req, &system_actor)?;

                    let testbed_ca_handle = testbed_ca_handle();
                    if !ca_manager.has_ca(&testbed_ca_handle)? {
                        info!("Creating embedded Testbed CA");

                        // Add the new testbed CA
                        ca_manager.init_ca(&testbed_ca_handle)?;
                        let testbed_ca = ca_manager.get_ca(&testbed_ca_handle).await?;

                        // Add the new testbed publisher
                        let pub_req = rfc8183::PublisherRequest::new(
                            None,
                            testbed_ca_handle.clone(),
                            testbed_ca.id_cert().clone(),
                        );
                        repo_manager.create_publisher(pub_req, &system_actor)?;
                        let rfc8181_uri =
                            uri::Https::from_string(format!("{}rfc8181/{}", service_uri, testbed_ca_handle)).unwrap();
                        let repo_response = repo_manager.repository_response(rfc8181_uri, &testbed_ca_handle)?;
                        let repo_contact = RepositoryContact::rfc8181(repo_response);
                        ca_manager
                            .update_repo(testbed_ca_handle.clone(), repo_contact, &system_actor)
                            .await?;

                        // Establish the TA (parent) <-> testbed CA (child) relationship
                        let testbed_ca_resources = ResourceSet::all_resources();
                        let auth = ChildAuthRequest::Rfc8183(testbed_ca.child_request());
                        let child_req = AddChildRequest::new(testbed_ca_handle.clone(), testbed_ca_resources, auth);
                        let parent_ca_contact = ca_manager
                            .ca_add_child(&ta_handle, child_req, &service_uri, &system_actor)
                            .await?;
                        let parent_req = ParentCaReq::new(ta_handle.clone(), parent_ca_contact);
                        ca_manager
                            .ca_parent_add(testbed_ca_handle, parent_req, &system_actor)
                            .await?;
                    }
                }
            }
            Some(ca_manager)
        } else {
            None
        };

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_risdumps_enabled,
            &config.bgp_risdumps_v4_uri,
            &config.bgp_risdumps_v6_uri,
        ));

        let scheduler = Scheduler::build(
            event_queue,
            ca_manager.clone(),
            repo_manager.clone(),
            bgp_analyser.clone(),
            #[cfg(feature = "multi-user")]
            login_session_cache.clone(),
            &config,
            &system_actor,
        );

        let post_limits = PostLimits::new(
            config.post_limit_api,
            config.post_limit_rfc6492,
            config.post_limit_rfc8181,
        );

        Ok(KrillServer {
            service_uri,
            work_dir: work_dir.clone(),
            authorizer,
            repo_manager,
            ca_manager,
            bgp_analyser,
            scheduler,
            started: Time::now(),
            post_limits,
            #[cfg(feature = "multi-user")]
            login_session_cache,
            system_actor,
        })
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }

    pub fn server_info(&self) -> ServerInfo {
        ServerInfo::new(KRILL_VERSION, self.started)
    }
}

/// # Authentication and Access
impl KrillServer {
    pub fn system_actor(&self) -> &Actor {
        &self.system_actor
    }

    pub fn actor_from_request(&self, request: &hyper::Request<hyper::Body>) -> Actor {
        self.authorizer.actor_from_request(request)
    }

    pub fn actor_from_def(&self, actor_def: ActorDef) -> Actor {
        self.authorizer.actor_from_def(actor_def)
    }

    pub fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.authorizer.get_login_url()
    }

    pub fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        self.authorizer.login(request)
    }

    pub fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        self.authorizer.logout(request)
    }

    pub fn limit_api(&self) -> u64 {
        self.post_limits.api()
    }

    pub fn limit_rfc8181(&self) -> u64 {
        self.post_limits.rfc8181()
    }

    pub fn limit_rfc6492(&self) -> u64 {
        self.post_limits.rfc6492()
    }

    pub fn testbed_enabled(&self) -> bool {
        self.ca_manager
            .as_ref()
            .map(|ca_manager| ca_manager.testbed_enabled())
            .unwrap_or_else(|| false)
    }

    #[cfg(feature = "multi-user")]
    pub fn login_session_cache_size(&self) -> usize {
        self.login_session_cache.size()
    }
}

/// # Configure publishers
impl KrillServer {
    fn get_repo_manager(&self) -> KrillResult<&Arc<RepositoryManager>> {
        self.repo_manager.as_ref().ok_or(Error::RepositoryServerNotEnabled)
    }

    /// Returns the repository server stats
    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        self.get_repo_manager()?.repo_stats()
    }

    /// Returns all currently CONFIGured publishers. (excludes deactivated)
    pub fn publishers(&self) -> KrillResult<Vec<Handle>> {
        self.get_repo_manager()?.publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &self,
        req: rfc8183::PublisherRequest,
        actor: &Actor,
    ) -> KrillResult<rfc8183::RepositoryResponse> {
        let publisher_handle = req.publisher_handle().clone();
        self.get_repo_manager()?.create_publisher(req, actor)?;
        self.repository_response(&publisher_handle)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn remove_publisher(&mut self, publisher: PublisherHandle, actor: &Actor) -> KrillEmptyResult {
        self.get_repo_manager()?.remove_publisher(publisher, actor)
    }

    /// Returns a publisher.
    pub fn get_publisher(&self, publisher: &PublisherHandle) -> KrillResult<PublisherDetails> {
        self.get_repo_manager()?.get_publisher_details(publisher)
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
    pub fn repository_response(&self, publisher: &PublisherHandle) -> KrillResult<rfc8183::RepositoryResponse> {
        let rfc8181_uri = uri::Https::from_string(format!("{}rfc8181/{}", self.service_uri, publisher)).unwrap();
        self.get_repo_manager()?.repository_response(rfc8181_uri, publisher)
    }

    pub fn rfc8181(&self, publisher: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        self.get_repo_manager()?.rfc8181(publisher, msg_bytes)
    }
}

/// # Manage CAs
///
impl KrillServer {
    fn get_ca_manager(&self) -> KrillResult<&Arc<CaManager>> {
        self.ca_manager.as_ref().ok_or(Error::CaServerNotEnabled)
    }
}

/// # Being a parent
///
impl KrillServer {
    pub async fn ta(&self) -> KrillResult<TaCertDetails> {
        let ta = self.get_ca_manager()?.get_ca(&ta_handle()).await?;
        if let ParentCaContact::Ta(ta) = ta.parent(&ta_handle()).unwrap() {
            Ok(ta.clone())
        } else {
            panic!("Found TA which was not initialized as TA.")
        }
    }

    pub async fn trust_anchor_cert(&self) -> Option<Cert> {
        self.ta().await.ok().map(|details| details.cert().clone())
    }

    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub async fn ca_add_child(
        &self,
        parent: &ParentHandle,
        req: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<ParentCaContact> {
        let contact = self
            .get_ca_manager()?
            .ca_add_child(parent, req, &self.service_uri, actor)
            .await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(&self, parent: &ParentHandle, child: ChildHandle) -> KrillResult<ParentCaContact> {
        let contact = self
            .get_ca_manager()?
            .ca_parent_contact(parent, child, None, &self.service_uri)
            .await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_response(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
    ) -> KrillResult<rfc8183::ParentResponse> {
        let contact = self
            .get_ca_manager()?
            .ca_parent_response(parent, child, None, &self.service_uri)
            .await?;
        Ok(contact)
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_update(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.get_ca_manager()?
            .ca_child_update(parent, child, req, actor)
            .await?;
        Ok(())
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_remove(&self, handle: &Handle, child: ChildHandle, actor: &Actor) -> KrillEmptyResult {
        self.get_ca_manager()?.ca_child_remove(handle, child, actor).await?;
        Ok(())
    }

    /// Show details for a child under the TA.
    pub async fn ca_child_show(&self, parent: &ParentHandle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        let child = self.get_ca_manager()?.ca_show_child(parent, child).await?;
        Ok(child)
    }
}

/// # Being a child
///
impl KrillServer {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub async fn ca_child_req(&self, handle: &Handle) -> KrillResult<rfc8183::ChildRequest> {
        self.get_ca_manager()?.get_ca(handle).await.map(|ca| ca.child_request())
    }

    /// Adds a parent to a CA, will check first if the parent can be reached.
    pub async fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq, actor: &Actor) -> KrillEmptyResult {
        self.ca_parent_reachable(&handle, parent.handle(), parent.contact())
            .await
            .map_err(|_| Error::CaParentAddNotResponsive(handle.clone(), parent.handle().clone()))?;
        Ok(self.get_ca_manager()?.ca_parent_add(handle, parent, actor).await?)
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_parent_reachable(&handle, &parent, &contact).await?;
        Ok(self
            .get_ca_manager()?
            .ca_parent_update(handle, parent, contact, actor)
            .await?)
    }

    async fn ca_parent_reachable(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
    ) -> KrillEmptyResult {
        self.get_ca_manager()?
            .get_entitlements_from_parent_and_contact(handle, parent, contact)
            .await?;
        Ok(())
    }

    pub async fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle, actor: &Actor) -> KrillEmptyResult {
        Ok(self.get_ca_manager()?.ca_parent_remove(handle, parent, actor).await?)
    }

    pub async fn ca_parent_revoke(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillEmptyResult {
        Ok(self.get_ca_manager()?.ca_parent_revoke(handle, parent, actor).await?)
    }
}

/// # Stats and status of CAS
///
impl KrillServer {
    pub async fn cas_stats(&self) -> KrillResult<HashMap<Handle, CertAuthStats>> {
        let mut res = HashMap::new();

        for ca in self.ca_list(&self.system_actor)?.cas() {
            // can't fail really, but to be sure
            if let Ok(ca) = self.get_ca_manager()?.get_ca(ca.handle()).await {
                let roas = ca.roa_definitions();
                let roa_count = roas.len();
                let child_count = ca.children().count();

                let bgp_report = if ca.handle().as_str() == "ta" || ca.handle().as_str() == "testbed" {
                    BgpAnalysisReport::new(vec![])
                } else {
                    self.bgp_analyser.analyse(roas.as_slice(), &ca.all_resources()).await
                };

                res.insert(
                    ca.handle().clone(),
                    CertAuthStats::new(roa_count, child_count, bgp_report.into()),
                );
            }
        }

        Ok(res)
    }

    pub async fn all_ca_issues(&self, actor: &Actor) -> KrillResult<AllCertAuthIssues> {
        let mut all_issues = AllCertAuthIssues::default();
        for ca in self.ca_list(actor)?.cas() {
            let issues = self.ca_issues(ca.handle()).await?;
            if !issues.is_empty() {
                all_issues.add(ca.handle().clone(), issues);
            }
        }

        Ok(all_issues)
    }

    pub async fn ca_issues(&self, ca_handle: &Handle) -> KrillResult<CertAuthIssues> {
        let mut issues = CertAuthIssues::default();

        let status = self.ca_repo_status(ca_handle).await?;

        if let Some(error) = status.into_failure_opt() {
            issues.add_repo_issue(error)
        }

        let parent_statuses = self.get_ca_manager()?.ca_parent_statuses(ca_handle).await?;
        for (parent, status) in parent_statuses.into_iter() {
            if let Some(error) = status.into_failure_opt() {
                issues.add_parent_issue(parent, error)
            }
        }

        Ok(issues)
    }
}

/// # Bulk background operations CAS
///
impl KrillServer {
    /// Republish all CAs that need it.
    pub async fn republish_all(&self) -> KrillEmptyResult {
        self.get_ca_manager()?.republish_all().await?;
        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub async fn resync_all(&self, actor: &Actor) -> KrillEmptyResult {
        let publisher = CaPublisher::new(self.get_ca_manager()?.clone(), self.repo_manager.clone());

        for ca in self.ca_list(actor)?.cas() {
            if let Err(e) = publisher.publish(ca.handle()).await {
                error!("Failed to sync ca: {}. Got error: {}", ca.handle(), e)
            }
        }

        Ok(())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn cas_refresh_all(&self, actor: &Actor) -> KrillEmptyResult {
        self.get_ca_manager()?.cas_refresh_all(actor).await;
        Ok(())
    }
}

/// # Admin CAS
///
impl KrillServer {
    pub fn ca_list(&self, actor: &Actor) -> KrillResult<CertAuthList> {
        self.get_ca_manager()?.ca_list(actor)
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be found.
    pub async fn ca_info(&self, handle: &Handle) -> KrillResult<CertAuthInfo> {
        self.get_ca_manager()?.get_ca(handle).await.map(|ca| ca.as_ca_info())
    }

    // Deactivate the CA, the event will be picked up and trigger that
    // all keys are revoked and all objects withdrawn, and the CA is removed.
    pub async fn ca_deactivate(&self, ca_handle: &Handle, actor: &Actor) -> KrillResult<()> {
        let ca = self.get_ca_manager()?.get_ca(ca_handle).await?;
        for parent in ca.parents() {
            if let Err(e) = self.ca_parent_revoke(ca_handle, parent, actor).await {
                warn!(
                    "Removing CA '{}', but could not send revoke requests to parent '{}': {}",
                    ca_handle, parent, e
                );
            }

            if let ParentCaContact::Embedded = ca.parent(parent)? {
                self.ca_child_remove(parent, ca_handle.clone(), actor).await?;
            }
        }

        let publisher = CaPublisher::new(self.get_ca_manager()?.clone(), self.repo_manager.clone());
        if let Err(e) = publisher.clean_all_repos(&ca_handle).await {
            warn!(
                "Could not withdraw objects for deactivated CA '{}'. Error was: {}",
                ca_handle, e
            );
        }

        self.get_ca_manager()?.delete_ca(ca_handle, actor).await
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the CA or the parent cannot be found.
    pub async fn ca_my_parent_contact(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<ParentCaContact> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;
        ca.parent(parent).map(|p| p.clone())
    }

    pub async fn ca_my_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        self.get_ca_manager()?.ca_parent_statuses(ca).await
    }

    /// Returns the history for a CA, or NONE in case of issues (i.e. it does not exist).
    pub async fn ca_history(
        &self,
        handle: &Handle,
        crit: CommandHistoryCriteria,
    ) -> KrillResult<Option<CommandHistory>> {
        let server = self.get_ca_manager()?;
        Ok(server.get_ca_history(handle, crit).await.ok())
    }

    pub fn ca_command_details(&self, handle: &Handle, command: CommandKey) -> KrillResult<CaCommandDetails> {
        self.get_ca_manager()?.get_ca_command_details(handle, command)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be found.
    pub async fn ca_publisher_req(&self, handle: &Handle) -> KrillResult<rfc8183::PublisherRequest> {
        self.get_ca_manager()?
            .get_ca(handle)
            .await
            .map(|ca| ca.publisher_request())
    }

    pub async fn ca_init(&mut self, init: CertAuthInit) -> KrillEmptyResult {
        let handle = init.unpack();

        // Create CA
        self.get_ca_manager()?.init_ca(&handle)?;

        Ok(())
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub async fn ca_repo_details(&self, handle: &Handle) -> KrillResult<CaRepoDetails> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;
        let contact = ca.repository_contact()?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        self.get_ca_manager()?.ca_repo_status(ca).await
    }

    /// Update the repository for a CA, or return an error. (see `CertAuth::repo_update`)
    pub async fn ca_update_repo(&self, handle: Handle, update: RepositoryUpdate, actor: &Actor) -> KrillEmptyResult {
        let contact = match update {
            RepositoryUpdate::Embedded => {
                // Add to embedded publication server if not present
                if self.get_repo_manager()?.get_publisher_details(&handle).is_err() {
                    let id_cert = {
                        let ca = self.get_ca_manager()?.get_ca(&handle).await?;
                        ca.id_cert().clone()
                    };

                    // Add publisher
                    let req = rfc8183::PublisherRequest::new(None, handle.clone(), id_cert);
                    self.add_publisher(req, actor)?;
                }

                RepositoryContact::embedded(self.get_repo_manager()?.repo_info_for(&handle)?)
            }
            RepositoryUpdate::Rfc8181(response) => {
                // first check that the new repo can be contacted
                if let Err(error) = self
                    .get_ca_manager()?
                    .send_rfc8181_list(&handle, &response, false)
                    .await
                {
                    return Err(Error::CaRepoIssue(handle, error.to_error_response().msg().to_string()));
                }

                RepositoryContact::rfc8181(response)
            }
        };

        Ok(self.get_ca_manager()?.update_repo(handle, contact, actor).await?)
    }

    pub async fn ca_update_id(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self.get_ca_manager()?.ca_update_id(handle, actor).await?)
    }

    pub async fn ca_keyroll_init(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self
            .get_ca_manager()?
            .ca_keyroll_init(handle, Duration::seconds(0), actor)
            .await?)
    }

    pub async fn ca_keyroll_activate(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self
            .get_ca_manager()?
            .ca_keyroll_activate(handle, Duration::seconds(0), actor)
            .await?)
    }

    pub async fn rfc6492(&self, handle: Handle, msg_bytes: Bytes, actor: &Actor) -> KrillResult<Bytes> {
        Ok(self.get_ca_manager()?.rfc6492(&handle, msg_bytes, actor).await?)
    }
}

/// # Handle route authorization requests
///
impl KrillServer {
    pub async fn ca_routes_update(
        &self,
        handle: Handle,
        updates: RoaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        Ok(self
            .get_ca_manager()?
            .ca_routes_update(handle, updates.into(), actor)
            .await?)
    }

    pub async fn ca_routes_show(&self, handle: &Handle) -> KrillResult<Vec<RoaDefinition>> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;
        Ok(ca.roa_definitions())
    }

    pub async fn ca_routes_bgp_analysis(&self, handle: &Handle) -> KrillResult<BgpAnalysisReport> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let resources = ca.all_resources();
        Ok(self.bgp_analyser.analyse(definitions.as_slice(), &resources).await)
    }

    pub async fn ca_routes_bgp_dry_run(
        &self,
        handle: &Handle,
        updates: RoaDefinitionUpdates,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;

        let updates: RouteAuthorizationUpdates = updates.into();
        let updates = updates.into_explicit();
        let resources = updates.affected_prefixes();

        let (would_be_routes, _) = ca.update_authorizations(&updates)?;
        let roas: Vec<RoaDefinition> = would_be_routes
            .into_authorizations()
            .into_iter()
            .map(|a| a.into())
            .collect();

        Ok(self.bgp_analyser.analyse(roas.as_slice(), &resources).await)
    }

    pub async fn ca_routes_bgp_suggest(
        &self,
        handle: &Handle,
        scope: Option<ResourceSet>,
    ) -> KrillResult<BgpAnalysisSuggestion> {
        let ca = self.get_ca_manager()?.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let mut resources = ca.all_resources();

        if let Some(scope) = scope {
            resources = resources.intersection(&scope);
        }

        Ok(self.bgp_analyser.suggest(definitions.as_slice(), &resources).await)
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    pub fn handle_delta(&self, publisher: PublisherHandle, delta: PublishDelta) -> KrillEmptyResult {
        self.get_repo_manager()?.publish(publisher, delta)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.get_repo_manager()?.list(publisher)
    }
}

/// # Handle Repository Server requests
///
impl KrillServer {
    /// Create the publication server, will fail if it was already created.
    pub fn repository_init(&self, uris: PublicationServerUris) -> KrillResult<()> {
        self.get_repo_manager()?.init(uris)
    }

    /// Clear the publication server. Will fail if it still has publishers. Or if it does not exist
    pub fn repository_clear(&self) -> KrillResult<()> {
        self.get_repo_manager()?.repository_clear()
    }
}

/// # Handle Resource Tagged Attestation requests
///
impl KrillServer {
    /// List all known RTAs
    pub async fn rta_list(&self, ca: Handle) -> KrillResult<RtaList> {
        let ca = self.get_ca_manager()?.get_ca(&ca).await?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub async fn rta_show(&self, ca: Handle, name: RtaName) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.get_ca_manager()?.get_ca(&ca).await?;
        ca.rta_show(&name)
    }

    /// Sign an RTA - either a new, or a prepared RTA
    pub async fn rta_sign(
        &self,
        ca: Handle,
        name: RtaName,
        request: RtaContentRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.get_ca_manager()?.rta_sign(ca, name, request, actor).await
    }

    /// Prepare a multi
    pub async fn rta_multi_prep(
        &self,
        ca: Handle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<RtaPrepResponse> {
        self.get_ca_manager()?
            .rta_multi_prep(&ca, name.clone(), request, actor)
            .await?;
        let ca = self.get_ca_manager()?.get_ca(&ca).await?;
        ca.rta_prep_response(&name)
    }

    /// Co-sign an existing RTA
    pub async fn rta_multi_cosign(
        &self,
        ca: Handle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.get_ca_manager()?.rta_multi_cosign(ca, name, rta, actor).await
    }
}

// Tested through integration tests
