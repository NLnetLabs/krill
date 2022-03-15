//! An RPKI publication protocol server.
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use bytes::Bytes;
use chrono::Duration;

use rpki::{repository::cert::Cert, uri};

use crate::{
    commons::{
        actor::{Actor, ActorDef},
        api::{
            AddChildRequest, AllCertAuthIssues, AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates,
            AspaProvidersUpdate, CaCommandDetails, CaRepoDetails, CertAuthInfo, CertAuthInit, CertAuthIssues,
            CertAuthList, CertAuthStats, ChildCaInfo, ChildHandle, ChildrenConnectionStats, CommandHistory,
            CommandHistoryCriteria, Handle, ListReply, ParentCaContact, ParentCaReq, ParentHandle,
            PublicationServerUris, PublishDelta, PublisherDetails, PublisherHandle, RepositoryContact, ResourceSet,
            RoaDefinition, RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, ServerInfo, TaCertDetails,
            Timestamp, UpdateChildRequest,
        },
        bgp::{BgpAnalyser, BgpAnalysisReport, BgpAnalysisSuggestion},
        crypto::KrillSigner,
        eventsourcing::CommandKey,
        remote::rfc8183,
        KrillEmptyResult, KrillResult,
    },
    constants::*,
    daemon::{
        auth::{providers::AdminTokenAuthProvider, Authorizer, LoggedInUser},
        ca::{
            self, ta_handle, testbed_ca_handle, CaStatus, ResourceTaggedAttestation, RouteAuthorizationUpdates,
            RtaContentRequest, RtaPrepareRequest,
        },
        config::{AuthType, Config},
        http::HttpResponse,
        mq::TaskQueue,
        scheduler::Scheduler,
    },
    pubd::{RepoStats, RepositoryManager},
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::{
    common::session::LoginSessionCache,
    providers::{ConfigFileAuthProvider, OpenIDConnectAuthProvider},
};

//------------ KrillServer ---------------------------------------------------

/// This is the krill server that is doing all the orchestration for all components.
pub struct KrillServer {
    // The base URI for this service
    service_uri: uri::Https,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorization checks
    authorizer: Authorizer,

    // Publication server, with configured publishers
    repo_manager: Arc<RepositoryManager>,

    // Handles the internal TA and/or CAs
    ca_manager: Arc<ca::CaManager>,

    // Handles the internal TA and/or CAs
    bgp_analyser: Arc<BgpAnalyser>,

    // Shared message queue
    mq: Arc<TaskQueue>,

    // Time this server was started
    started: Timestamp,

    #[cfg(feature = "multi-user")]
    // Global login session cache
    login_session_cache: Arc<LoginSessionCache>,

    // System actor
    system_actor: Actor,

    pub config: Arc<Config>,
}

/// # Set up and initialization
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub async fn build(config: Arc<Config>) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let service_uri = config.service_uri();

        info!("Starting {} v{}", KRILL_SERVER_APP, KRILL_VERSION);
        info!("{} uses service uri: {}", KRILL_SERVER_APP, service_uri);

        if config.testbed().is_some() {
            info!("Enabling TESTBED mode - ONLY USE THIS FOR TESTING AND TRAINING!");
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
            AuthType::AdminToken => {
                Authorizer::new(config.clone(), AdminTokenAuthProvider::new(config.clone()).into())?
            }
            #[cfg(feature = "multi-user")]
            AuthType::ConfigFile => Authorizer::new(
                config.clone(),
                ConfigFileAuthProvider::new(config.clone(), login_session_cache.clone())?.into(),
            )?,
            #[cfg(feature = "multi-user")]
            AuthType::OpenIDConnect => Authorizer::new(
                config.clone(),
                OpenIDConnectAuthProvider::new(config.clone(), login_session_cache.clone())?.into(),
            )?,
        };
        let system_actor = authorizer.actor_from_def(ACTOR_DEF_KRILL);

        // for now, support that existing embedded repositories are still supported.
        // this should be removed in future after people have had a chance to separate.
        let repo_manager = Arc::new(RepositoryManager::build(config.clone(), signer.clone())?);

        // Used to have a shared queue for the caserver and the background job scheduler.
        let mq = Arc::new(TaskQueue::default());

        let ca_manager =
            Arc::new(ca::CaManager::build(config.clone(), mq.clone(), signer, system_actor.clone()).await?);

        ca_manager.resync_ca_statuses().await?;

        if let Some(testbed) = config.testbed() {
            let uris = testbed.publication_server_uris();

            if !repo_manager.initialized()? {
                repo_manager.init(uris.clone())?;
            }

            let ta_handle = ta_handle();
            if !ca_manager.has_ca(&ta_handle)? {
                info!("Creating embedded Trust Anchor");

                let ta_uri = testbed.ta_uri().clone();
                let ta_aia = testbed.ta_aia().clone();

                // Add TA and add as publisher
                ca_manager
                    .init_ta(ta_aia, vec![ta_uri], &repo_manager, &system_actor)
                    .await?;

                let testbed_ca_handle = testbed_ca_handle();
                if !ca_manager.has_ca(&testbed_ca_handle)? {
                    info!("Creating embedded Testbed CA");

                    // Add the new testbed CA
                    ca_manager.init_ca(&testbed_ca_handle)?;
                    let testbed_ca = ca_manager.get_ca(&testbed_ca_handle).await?;

                    // Add the new testbed publisher
                    let pub_req =
                        rfc8183::PublisherRequest::new(None, testbed_ca_handle.clone(), testbed_ca.id_cert().clone());
                    repo_manager.create_publisher(pub_req, &system_actor)?;

                    let repo_response = repo_manager.repository_response(&testbed_ca_handle)?;
                    let repo_contact = RepositoryContact::new(repo_response);
                    ca_manager
                        .update_repo(testbed_ca_handle.clone(), repo_contact, false, &system_actor)
                        .await?;

                    // Establish the TA (parent) <-> testbed CA (child) relationship
                    let testbed_ca_resources = ResourceSet::all_resources();

                    let (_, _, child_id_cert) = testbed_ca.child_request().unpack();

                    let child_req =
                        AddChildRequest::new(testbed_ca_handle.clone(), testbed_ca_resources, child_id_cert);
                    let parent_ca_contact = ca_manager
                        .ca_add_child(&ta_handle, child_req, &service_uri, &system_actor)
                        .await?;
                    let parent_req = ParentCaReq::new(ta_handle.clone(), parent_ca_contact);
                    ca_manager
                        .ca_parent_add_or_update(testbed_ca_handle, parent_req, &system_actor)
                        .await?;
                }
            }
        }

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_risdumps_enabled,
            &config.bgp_risdumps_v4_uri,
            &config.bgp_risdumps_v6_uri,
        ));

        Ok(KrillServer {
            service_uri,
            work_dir: work_dir.clone(),
            authorizer,
            repo_manager,
            ca_manager,
            bgp_analyser,
            mq,
            started: Timestamp::now(),
            #[cfg(feature = "multi-user")]
            login_session_cache,
            system_actor,
            config,
        })
    }

    pub fn build_scheduler(&self) -> Scheduler {
        Scheduler::build(
            self.mq.clone(),
            self.ca_manager.clone(),
            self.bgp_analyser.clone(),
            #[cfg(feature = "multi-user")]
            self.login_session_cache.clone(),
            self.config.clone(),
            self.system_actor.clone(),
        )
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

    pub async fn actor_from_request(&self, request: &hyper::Request<hyper::Body>) -> Actor {
        self.authorizer.actor_from_request(request).await
    }

    pub fn actor_from_def(&self, actor_def: ActorDef) -> Actor {
        self.authorizer.actor_from_def(actor_def)
    }

    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.authorizer.get_login_url().await
    }

    pub async fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        self.authorizer.login(request).await
    }

    pub async fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        self.authorizer.logout(request).await
    }

    pub fn testbed_enabled(&self) -> bool {
        self.ca_manager.testbed_enabled()
    }

    #[cfg(feature = "multi-user")]
    pub fn login_session_cache_size(&self) -> usize {
        self.login_session_cache.size()
    }
}

/// # Configure publishers
impl KrillServer {
    /// Returns the repository server stats
    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        self.repo_manager.repo_stats()
    }

    /// Returns all current publishers.
    pub fn publishers(&self) -> KrillResult<Vec<Handle>> {
        self.repo_manager.publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &self,
        req: rfc8183::PublisherRequest,
        actor: &Actor,
    ) -> KrillResult<rfc8183::RepositoryResponse> {
        let publisher_handle = req.publisher_handle().clone();
        self.repo_manager.create_publisher(req, actor)?;
        self.repository_response(&publisher_handle)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn remove_publisher(&self, publisher: PublisherHandle, actor: &Actor) -> KrillEmptyResult {
        self.repo_manager.remove_publisher(publisher, actor)
    }

    /// Returns a publisher.
    pub fn get_publisher(&self, publisher: &PublisherHandle) -> KrillResult<PublisherDetails> {
        self.repo_manager.get_publisher_details(publisher)
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
        self.repo_manager.repository_response(publisher)
    }

    pub fn rfc8181(&self, publisher: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        self.repo_manager.rfc8181(publisher, msg_bytes)
    }
}

/// # Being a parent
///
impl KrillServer {
    pub async fn ta(&self) -> KrillResult<TaCertDetails> {
        let ta = self.ca_manager.get_ca(&ta_handle()).await?;
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
            .ca_manager
            .ca_add_child(parent, req, &self.service_uri, actor)
            .await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(&self, parent: &ParentHandle, child: ChildHandle) -> KrillResult<ParentCaContact> {
        let contact = self
            .ca_manager
            .ca_parent_contact(parent, child, &self.service_uri)
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
            .ca_manager
            .ca_parent_response(parent, child, &self.service_uri)
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
        self.ca_manager.ca_child_update(parent, child, req, actor).await?;
        Ok(())
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_remove(&self, handle: &Handle, child: ChildHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.ca_child_remove(handle, child, actor).await?;
        Ok(())
    }

    /// Show details for a child under the CA.
    pub async fn ca_child_show(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        let child = self.ca_manager.ca_show_child(ca, child).await?;
        Ok(child)
    }

    /// Show children stats under the CA.
    pub async fn ca_stats_child_connections(&self, ca: &Handle) -> KrillResult<ChildrenConnectionStats> {
        self.ca_manager
            .get_ca_status(ca)
            .await
            .map(|status| status.get_children_connection_stats())
    }
}

/// # Being a child
///
impl KrillServer {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub async fn ca_child_req(&self, handle: &Handle) -> KrillResult<rfc8183::ChildRequest> {
        self.ca_manager.get_ca(handle).await.map(|ca| ca.child_request())
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_add_or_update(
        &self,
        ca: Handle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillEmptyResult {
        let parent = parent_req.handle();
        let contact = parent_req.contact();
        self.ca_manager
            .get_entitlements_from_contact(&ca, parent, contact, false)
            .await?;

        Ok(self.ca_manager.ca_parent_add_or_update(ca, parent_req, actor).await?)
    }

    pub async fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle, actor: &Actor) -> KrillEmptyResult {
        Ok(self.ca_manager.ca_parent_remove(handle, parent, actor).await?)
    }

    pub async fn ca_parent_revoke(&self, handle: &Handle, parent: &ParentHandle) -> KrillEmptyResult {
        Ok(self.ca_manager.ca_parent_revoke(handle, parent).await?)
    }
}

/// # Stats and status of CAS
///
impl KrillServer {
    pub async fn cas_stats(&self) -> KrillResult<HashMap<Handle, CertAuthStats>> {
        let mut res = HashMap::new();

        for ca in self.ca_list(&self.system_actor)?.cas() {
            // can't fail really, but to be sure
            if let Ok(ca) = self.ca_manager.get_ca(ca.handle()).await {
                let roas = ca.roa_definitions();
                let roa_count = roas.len();
                let child_count = ca.children().count();

                let bgp_report = if ca.handle().as_str() == "ta" || ca.handle().as_str() == "testbed" {
                    BgpAnalysisReport::new(vec![])
                } else {
                    self.bgp_analyser
                        .analyse(roas.as_slice(), &ca.all_resources(), None)
                        .await
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

        let ca_status = self.ca_manager.get_ca_status(ca_handle).await?;

        if let Some(error) = ca_status.repo().to_failure_opt() {
            issues.add_repo_issue(error)
        }

        for (parent, status) in ca_status.parents().iter() {
            if let Some(error) = status.to_failure_opt() {
                issues.add_parent_issue(parent.clone(), error)
            }
        }

        Ok(issues)
    }
}

/// # Synchronization operations for CAS
///
impl KrillServer {
    /// Republish all CAs that need it.
    pub async fn republish_all(&self) -> KrillEmptyResult {
        self.ca_manager.republish_all().await?;
        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub async fn cas_repo_sync_all(&self, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.cas_repo_sync_all(actor).await;
        Ok(())
    }

    /// Re-sync a specific CA with its repository
    pub async fn cas_repo_sync_single(&self, ca: &Handle) -> KrillEmptyResult {
        self.ca_manager.cas_repo_sync_single(ca).await?;
        Ok(())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn cas_refresh_all(&self, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.cas_refresh_all(self.started, actor).await;
        Ok(())
    }

    /// Refresh a specific CA with its parents
    pub async fn cas_refresh_single(&self, ca_handle: Handle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.cas_refresh_single(ca_handle, self.started, actor).await;
        Ok(())
    }
}

/// # Admin CAS
///
impl KrillServer {
    pub fn ca_list(&self, actor: &Actor) -> KrillResult<CertAuthList> {
        self.ca_manager.ca_list(actor)
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be found.
    pub async fn ca_info(&self, handle: &Handle) -> KrillResult<CertAuthInfo> {
        self.ca_manager.get_ca(handle).await.map(|ca| ca.as_ca_info())
    }

    /// Returns the CA status, or an error if none can be found.
    pub async fn ca_status(&self, ca: &Handle) -> KrillResult<Arc<CaStatus>> {
        self.ca_manager.get_ca_status(ca).await
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn ca_delete(&self, ca_handle: &Handle, actor: &Actor) -> KrillResult<()> {
        self.ca_manager.delete_ca(ca_handle, actor).await
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the CA or the parent cannot be found.
    pub async fn ca_my_parent_contact(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<ParentCaContact> {
        let ca = self.ca_manager.get_ca(handle).await?;
        ca.parent(parent).map(|p| p.clone())
    }

    /// Returns the history for a CA.
    pub async fn ca_history(&self, handle: &Handle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> {
        self.ca_manager.ca_history(handle, crit).await
    }

    pub fn ca_command_details(&self, handle: &Handle, command: CommandKey) -> KrillResult<CaCommandDetails> {
        self.ca_manager.ca_command_details(handle, command)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be found.
    pub async fn ca_publisher_req(&self, handle: &Handle) -> KrillResult<rfc8183::PublisherRequest> {
        self.ca_manager.get_ca(handle).await.map(|ca| ca.publisher_request())
    }

    pub fn ca_init(&self, init: CertAuthInit) -> KrillEmptyResult {
        let handle = init.unpack();
        self.ca_manager.init_ca(&handle)
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub async fn ca_repo_details(&self, handle: &Handle) -> KrillResult<CaRepoDetails> {
        let ca = self.ca_manager.get_ca(handle).await?;
        let contact = ca.repository_contact()?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    /// Update the repository for a CA, or return an error. (see `CertAuth::repo_update`)
    pub async fn ca_repo_update(&self, handle: Handle, contact: RepositoryContact, actor: &Actor) -> KrillEmptyResult {
        Ok(self.ca_manager.update_repo(handle, contact, true, actor).await?)
    }

    pub async fn ca_update_id(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self.ca_manager.ca_update_id(handle, actor).await?)
    }

    pub async fn ca_keyroll_init(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self
            .ca_manager
            .ca_keyroll_init(handle, Duration::seconds(0), actor)
            .await?)
    }

    pub async fn ca_keyroll_activate(&self, handle: Handle, actor: &Actor) -> KrillEmptyResult {
        Ok(self
            .ca_manager
            .ca_keyroll_activate(handle, Duration::seconds(0), actor)
            .await?)
    }

    pub async fn rfc6492(
        &self,
        handle: Handle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        Ok(self.ca_manager.rfc6492(&handle, msg_bytes, user_agent, actor).await?)
    }
}

/// # Handle ASPA requests
///
impl KrillServer {
    pub async fn ca_aspas_definitions_show(&self, ca: Handle) -> KrillResult<AspaDefinitionList> {
        Ok(self.ca_manager.ca_aspas_definitions_show(ca).await?)
    }

    pub async fn ca_aspas_definitions_update(
        &self,
        ca: Handle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        Ok(self.ca_manager.ca_aspas_definitions_update(ca, updates, actor).await?)
    }

    pub async fn ca_aspas_update_aspa(
        &self,
        ca: Handle,
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillEmptyResult {
        Ok(self
            .ca_manager
            .ca_aspas_update_aspa(ca, customer, update, actor)
            .await?)
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
        Ok(self.ca_manager.ca_routes_update(handle, updates.into(), actor).await?)
    }

    pub async fn ca_routes_show(&self, handle: &Handle) -> KrillResult<Vec<RoaDefinition>> {
        let ca = self.ca_manager.get_ca(handle).await?;
        Ok(ca.roa_definitions())
    }

    pub async fn ca_routes_bgp_analysis(&self, handle: &Handle) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let resources_held = ca.all_resources();
        Ok(self
            .bgp_analyser
            .analyse(definitions.as_slice(), &resources_held, None)
            .await)
    }

    pub async fn ca_routes_bgp_dry_run(
        &self,
        handle: &Handle,
        updates: RoaDefinitionUpdates,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle).await?;

        let updates: RouteAuthorizationUpdates = updates.into();
        let updates = updates.into_explicit();
        let resources_held = ca.all_resources();
        let limit = Some(updates.affected_prefixes());

        let (would_be_routes, _) = ca.update_authorizations(&updates)?;
        let roas: Vec<RoaDefinition> = would_be_routes
            .into_authorizations()
            .into_iter()
            .map(|a| a.into())
            .collect();

        Ok(self.bgp_analyser.analyse(roas.as_slice(), &resources_held, limit).await)
    }

    pub async fn ca_routes_bgp_suggest(
        &self,
        handle: &Handle,
        limit: Option<ResourceSet>,
    ) -> KrillResult<BgpAnalysisSuggestion> {
        let ca = self.ca_manager.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let resources_held = ca.all_resources();

        Ok(self
            .bgp_analyser
            .suggest(definitions.as_slice(), &resources_held, limit)
            .await)
    }

    /// Re-issue ROA objects so that they will use short subjects (see issue #700)
    pub async fn force_renew_roas(&self) -> KrillResult<()> {
        self.ca_manager.force_renew_roas_all(self.system_actor()).await
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    pub fn handle_delta(&self, publisher: PublisherHandle, delta: PublishDelta) -> KrillEmptyResult {
        self.repo_manager.publish(publisher, delta)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.repo_manager.list(publisher)
    }
}

/// # Handle Repository Server requests
///
impl KrillServer {
    /// Create the publication server, will fail if it was already created.
    pub fn repository_init(&self, uris: PublicationServerUris) -> KrillResult<()> {
        self.repo_manager.init(uris)
    }

    /// Clear the publication server. Will fail if it still has publishers. Or if it does not exist
    pub fn repository_clear(&self) -> KrillResult<()> {
        self.repo_manager.repository_clear()
    }

    /// Perform an RRDP session reset. Useful after a restart of the server as we can never be
    /// certain whether the previous state was the last public state seen by validators, or..
    /// the server was started using a back up.
    pub fn repository_session_reset(&self) -> KrillResult<()> {
        self.repo_manager.rrdp_session_reset()
    }
}

/// # Handle Resource Tagged Attestation requests
///
impl KrillServer {
    /// List all known RTAs
    pub async fn rta_list(&self, ca: Handle) -> KrillResult<RtaList> {
        let ca = self.ca_manager.get_ca(&ca).await?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub async fn rta_show(&self, ca: Handle, name: RtaName) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.ca_manager.get_ca(&ca).await?;
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
        self.ca_manager.rta_sign(ca, name, request, actor).await
    }

    /// Prepare a multi
    pub async fn rta_multi_prep(
        &self,
        ca: Handle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<RtaPrepResponse> {
        self.ca_manager
            .rta_multi_prep(&ca, name.clone(), request, actor)
            .await?;
        let ca = self.ca_manager.get_ca(&ca).await?;
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
        self.ca_manager.rta_multi_cosign(ca, name, rta, actor).await
    }
}

// Tested through integration tests
