//! An RPKI publication protocol server.
use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use bytes::Bytes;
use chrono::Duration;

use futures::future::try_join_all;

use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::{
        actor::{Actor, ActorDef},
        api::{
            self, AddChildRequest, AllCertAuthIssues, AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates,
            AspaProvidersUpdate, BgpSecCsrInfoList, BgpSecDefinitionUpdates, CaCommandDetails, CaRepoDetails,
            CertAuthInfo, CertAuthInit, CertAuthIssues, CertAuthList, CertAuthStats, ChildCaInfo,
            ChildrenConnectionStats, CommandHistory, CommandHistoryCriteria, ConfiguredRoa, ParentCaContact,
            ParentCaReq, PublicationServerUris, PublisherDetails, ReceivedCert, RepositoryContact, RoaConfiguration,
            RoaConfigurationUpdates, RoaPayload, RtaList, RtaName, RtaPrepResponse, ServerInfo, Timestamp,
            UpdateChildRequest,
        },
        bgp::{BgpAnalyser, BgpAnalysisReport, BgpAnalysisSuggestion},
        crypto::KrillSignerBuilder,
        error::Error,
        eventsourcing::CommandKey,
        KrillEmptyResult, KrillResult,
    },
    constants::*,
    daemon::{
        auth::{providers::AdminTokenAuthProvider, Authorizer, LoggedInUser},
        ca::{self, testbed_ca_handle, CaStatus, ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest},
        config::{AuthType, Config},
        http::HttpResponse,
        mq::TaskQueue,
        scheduler::Scheduler,
        ta::{ta_handle, TaCertDetails},
    },
    pubd::{RepoStats, RepositoryManager},
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::{
    common::session::LoginSessionCache,
    providers::{ConfigFileAuthProvider, OpenIDConnectAuthProvider},
};

use super::ca::CaManager;

//------------ KrillServer ---------------------------------------------------

/// This is the Krill server that is doing all the orchestration for all components.
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

        // Assumes that Config::verify() has already ensured that the signer configuration is valid and that
        // Config::resolve() has been used to update signer name references to resolve to the corresponding signer
        // configurations.
        let probe_interval = std::time::Duration::from_secs(config.signer_probe_retry_seconds);
        let signer = KrillSignerBuilder::new(work_dir, probe_interval, &config.signers)
            .with_default_signer(config.default_signer())
            .with_one_off_signer(config.one_off_signer())
            .build()?;
        let signer = Arc::new(signer);

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

        // Used to have a shared queue for the ca_manager, repo_manager and the background job scheduler.
        let mq = Arc::new(TaskQueue::default());

        // for now, support that existing embedded repositories are still supported.
        // this should be removed in future after people have had a chance to separate.
        let repo_manager = Arc::new(RepositoryManager::build(config.clone(), mq.clone(), signer.clone())?);

        let ca_manager =
            Arc::new(ca::CaManager::build(config.clone(), mq.clone(), signer, system_actor.clone()).await?);

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_risdumps_enabled,
            &config.bgp_risdumps_v4_uri,
            &config.bgp_risdumps_v6_uri,
        ));

        mq.server_started();

        let server = KrillServer {
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
            config: config.clone(),
        };

        // Check if we need to do any testbed or benchmarking set up.
        let testbed_handle = testbed_ca_handle();

        if let Some(testbed) = config.testbed() {
            if server.ca_manager.has_ca(&testbed_handle)? {
                if config.benchmark.is_some() {
                    info!("Resuming BENCHMARK mode - will NOT recreate CAs. If you wanted this, then wipe the data dir and restart.");
                } else {
                    info!("Resuming TESTBED mode - ONLY USE THIS FOR TESTING AND TRAINING!");
                }
            } else {
                // Will do some set up. Both TESTBED and BENCHMARK (which implies TESTBED and adds to it)
                // will need a testbed ca to be set up first. We will re-use the import functionality to
                // do all this.
                let testbed_ca = api::import::ImportCa::new(
                    testbed_handle,
                    vec![api::import::ImportParent::new(
                        ta_handle().into_converted(),
                        ResourceSet::all(),
                    )],
                    vec![],
                );

                let mut import_cas = vec![testbed_ca];

                match config.benchmark.as_ref() {
                    None => {
                        info!("Enabling TESTBED mode - ONLY USE THIS FOR TESTING AND TRAINING!");
                    }
                    Some(benchmark) => {
                        info!(
                            "Enabling BENCHMARK mode with {} CAs with {} ROas each - ONLY USE THIS FOR TESTING!",
                            benchmark.cas, benchmark.ca_roas
                        );

                        let testbed_parent: ParentHandle = testbed_ca_handle().into_converted();
                        for nr in 0..benchmark.cas {
                            let handle = CaHandle::new(format!("benchmark-{}", nr).into());

                            // derive resources for benchmark ca
                            let byte_2_ipv4 = nr / 256;
                            let byte_3_ipv4 = nr % 256;

                            let prefix_str = format!("10.{}.{}.0/24", byte_2_ipv4, byte_3_ipv4);
                            let resources = ResourceSet::from_strs("", &prefix_str, "")
                                .map_err(|e| Error::ResourceSetError(format!("cannot parse resources: {}", e)))?;

                            // Create ROA configs
                            let mut roas: Vec<RoaConfiguration> = vec![];
                            let asn_range_start = 64512;
                            for asn in asn_range_start..asn_range_start + benchmark.ca_roas {
                                let payload = RoaPayload::from_str(&format!("{} => {}", prefix_str, asn)).unwrap();
                                roas.push(payload.into());
                            }

                            import_cas.push(api::import::ImportCa::new(
                                handle,
                                vec![api::import::ImportParent::new(testbed_parent.clone(), resources)],
                                roas,
                            ))
                        }
                    }
                }

                let startup_structure = api::import::Structure::new(
                    testbed.ta_aia().clone(),
                    testbed.ta_uri().clone(),
                    testbed.publication_server_uris(),
                    import_cas,
                );
                server.cas_import(startup_structure).await?;
            }
        }

        Ok(server)
    }

    pub fn build_scheduler(&self) -> Scheduler {
        Scheduler::build(
            self.mq.clone(),
            self.ca_manager.clone(),
            self.repo_manager.clone(),
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
    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        self.repo_manager.publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(
        &self,
        req: idexchange::PublisherRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::RepositoryResponse> {
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
    pub fn repository_response(&self, publisher: &PublisherHandle) -> KrillResult<idexchange::RepositoryResponse> {
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
        let ta_handle = ta_handle();
        let ta = self.ca_manager.get_ca(&ta_handle).await?;

        let parent_handle = ParentHandle::new(ta_handle.into_name());

        if let ParentCaContact::Ta(ta) = ta.parent(&parent_handle).unwrap() {
            Ok(ta.clone())
        } else {
            panic!("Found TA which was not initialized as TA.")
        }
    }

    pub async fn trust_anchor_cert(&self) -> Option<ReceivedCert> {
        self.ta().await.ok().map(|details| details.cert().clone())
    }

    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub async fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_add_child(ca, req, &self.service_uri, actor).await
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(&self, ca: &CaHandle, child: ChildHandle) -> KrillResult<ParentCaContact> {
        self.ca_manager.ca_parent_contact(ca, child, &self.service_uri).await
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_response(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_parent_response(ca, child, &self.service_uri).await
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_update(ca, child, req, actor).await
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_remove(&self, ca: &CaHandle, child: ChildHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.ca_child_remove(ca, child, actor).await?;
        Ok(())
    }

    /// Show details for a child under the CA.
    pub async fn ca_child_show(&self, ca: &CaHandle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        let child = self.ca_manager.ca_show_child(ca, child).await?;
        Ok(child)
    }

    /// Show children stats under the CA.
    pub async fn ca_stats_child_connections(&self, ca: &CaHandle) -> KrillResult<ChildrenConnectionStats> {
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
    pub async fn ca_child_req(&self, ca: &CaHandle) -> KrillResult<idexchange::ChildRequest> {
        self.ca_manager.get_ca(ca).await.map(|ca| ca.child_request())
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_add_or_update(
        &self,
        ca: CaHandle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillEmptyResult {
        let parent = parent_req.handle();

        // Verify that we can get entitlements from the new parent before adding/updating it.
        let contact = ParentCaContact::for_rfc8183_parent_response(parent_req.response().clone())
            .map_err(|e| Error::CaParentResponseInvalid(ca.clone(), e.to_string()))?;
        self.ca_manager
            .get_entitlements_from_contact(&ca, parent, &contact, false)
            .await?;

        // Seems good. Add/update the parent.
        self.ca_manager.ca_parent_add_or_update(ca, parent_req, actor).await
    }

    pub async fn ca_parent_remove(&self, handle: CaHandle, parent: ParentHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.ca_parent_remove(handle, parent, actor).await
    }

    pub async fn ca_parent_revoke(&self, handle: &CaHandle, parent: &ParentHandle) -> KrillEmptyResult {
        self.ca_manager.ca_parent_revoke(handle, parent).await
    }
}

/// # Stats and status of CAS
///
impl KrillServer {
    pub async fn cas_stats(&self) -> KrillResult<HashMap<CaHandle, CertAuthStats>> {
        let mut res = HashMap::new();

        for ca in self.ca_list(&self.system_actor)?.cas() {
            // can't fail really, but to be sure
            if let Ok(ca) = self.ca_manager.get_ca(ca.handle()).await {
                let roas = ca.configured_roas();
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

    //
    pub async fn cas_import(&self, structure: api::import::Structure) -> KrillResult<()> {
        let actor = Arc::new(self.system_actor().clone());
        if !self.ca_list(&actor)?.cas().is_empty() || self.repo_manager.initialized()? {
            Err(Error::custom("Import CAs is only permitted when Krill is empty."))
        } else if let Err(e) = structure.validate_ca_hierarchy() {
            Err(Error::Custom(e))
        } else {
            info!("Bulk import {} CAs", structure.cas.len());

            info!("Initialising publication server");
            self.repo_manager.init(structure.publication_server_uris.clone())?;

            info!("Creating embedded Trust Anchor");
            self.ca_manager
                .init_ta(
                    structure.ta_aia.clone(),
                    vec![structure.ta_uri.clone()],
                    &self.repo_manager,
                    &actor,
                )
                .await?;

            // Set up each online TA child with local repo, do this in parallel.
            let mut import_fns = vec![];
            let service_uri = Arc::new(self.config.service_uri());
            for ca in structure.into_cas() {
                import_fns.push(tokio::spawn(Self::import_ca(
                    ca,
                    self.ca_manager.clone(),
                    self.repo_manager.clone(),
                    service_uri.clone(),
                    actor.clone(),
                )));
            }
            try_join_all(import_fns)
                .await
                .map_err(|e| Error::Custom(format!("Could not import CAs: {}", e)))?;

            Ok(())
        }
    }

    async fn import_ca(
        ca: api::import::ImportCa,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        service_uri: Arc<uri::Https>,
        actor: Arc<Actor>,
    ) -> KrillEmptyResult {
        // outline:
        // - init ca
        // - set up under repo
        // - set up under parent
        // - wait for resources
        // - recurse for children
        let (ca_handle, parents, roas) = ca.unpack();
        info!("Importing CA: '{}'", ca_handle);

        // init CA
        ca_manager.init_ca(&ca_handle)?;

        // Get Publisher Request
        let pub_req = {
            let ca = ca_manager.get_ca(&ca_handle).await?;
            idexchange::PublisherRequest::new(ca.id_cert().base64().clone(), ca_handle.convert(), None)
        };

        // Add Publisher
        repo_manager.create_publisher(pub_req, &actor)?;

        // Get Repository Contact for CA
        let repo_contact = {
            let repo_response = repo_manager.repository_response(&ca_handle.convert())?;
            RepositoryContact::for_response(repo_response).map_err(Error::rfc8183)?
        };

        // Add Repository to CA
        ca_manager
            .update_repo(&repo_manager, ca_handle.clone(), repo_contact, false, &actor)
            .await?;

        for import_parent in parents {
            let (parent, resources) = import_parent.unpack();

            // The parent should have been created. If it wasn't created yet, then we will
            // need to wait for it. Note that we can be sure that it will be created because
            // we verified that all parents are either "ta" (which is always created) or
            // another CA that appeared on the list before this CA.
            //
            // But.. you know.. just to be safe, let's not hang in here forever..
            let wait_ms = 100;
            let max_tries = 3000; // *100ms -> 5 mins, should be enough even on slow systems
            let mut tried = 0;
            let parent_as_ca: CaHandle = parent.convert();

            loop {
                tried += 1;
                if let Ok(parent) = ca_manager.get_ca(&parent_as_ca).await {
                    if parent.all_resources().contains(&resources) {
                        break;
                    } else {
                        info!(
                            "Parent {} does not (yet) have resources for {}. Will wait a bit and try again",
                            parent.handle(),
                            ca_handle
                        );
                    }
                } else {
                    info!(
                        "Parent {} for CA {} is not yet created. Will wait a bit and try again",
                        parent_as_ca, ca_handle
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                if tried >= max_tries {
                    return Err(Error::Custom(format!(
                        "Could not import CA {}. Parent: {} is not created",
                        ca_handle, parent_as_ca
                    )));
                }
            }

            // Add the CA as the child of parent and get the parent response
            let parent_response = {
                let ca = ca_manager.get_ca(&ca_handle).await?;
                let id_cert = ca.child_request().validate().map_err(Error::rfc8183)?;
                let child_req = AddChildRequest::new(ca_handle.convert(), resources, id_cert);

                ca_manager
                    .ca_add_child(&parent.convert(), child_req, &service_uri, &actor)
                    .await?
            };

            // Add the parent to the child and force sync
            {
                let parent_req = ParentCaReq::new(parent.clone(), parent_response);
                ca_manager
                    .ca_parent_add_or_update(ca_handle.clone(), parent_req, &actor)
                    .await?;

                // First sync will inform child of its entitlements and trigger that
                // CSR is created.
                ca_manager.ca_sync_parent(&ca_handle, &parent, &actor).await?;

                // Second sync will send that CSR to the parent
                ca_manager.ca_sync_parent(&ca_handle, &parent, &actor).await?;
            }
        }

        // Add ROA definitions
        let roa_updates = RoaConfigurationUpdates::new(roas, vec![]);
        ca_manager.ca_routes_update(ca_handle, roa_updates, &actor).await?;

        Ok(())
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

    pub async fn ca_issues(&self, ca: &CaHandle) -> KrillResult<CertAuthIssues> {
        let mut issues = CertAuthIssues::default();

        let ca_status = self.ca_manager.get_ca_status(ca).await?;

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
    pub async fn republish_all(&self, force: bool) -> KrillEmptyResult {
        let cas = self.ca_manager.republish_all(force).await?;
        for ca in cas {
            self.cas_repo_sync_single(&ca)?;
        }

        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub fn cas_repo_sync_all(&self, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_repo_sync_all(actor);
        Ok(())
    }

    /// Re-sync a specific CA with its repository
    pub fn cas_repo_sync_single(&self, ca: &CaHandle) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_repo_sync(ca.clone());
        Ok(())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn cas_refresh_all(&self) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_refresh_all().await;
        Ok(())
    }

    /// Refresh a specific CA with its parents
    pub async fn cas_refresh_single(&self, ca_handle: CaHandle) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_refresh_single(ca_handle).await;
        Ok(())
    }

    /// Schedule check suspend children for all CAs
    pub fn cas_schedule_suspend_all(&self) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_suspend_all();
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
    pub async fn ca_info(&self, ca: &CaHandle) -> KrillResult<CertAuthInfo> {
        self.ca_manager.get_ca(ca).await.map(|ca| ca.as_ca_info())
    }

    /// Returns the CA status, or an error if none can be found.
    pub async fn ca_status(&self, ca: &CaHandle) -> KrillResult<CaStatus> {
        self.ca_manager.get_ca_status(ca).await
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn ca_delete(&self, ca: &CaHandle, actor: &Actor) -> KrillResult<()> {
        self.ca_manager.delete_ca(self.repo_manager.as_ref(), ca, actor).await
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the CA or the parent cannot be found.
    pub async fn ca_my_parent_contact(&self, ca: &CaHandle, parent: &ParentHandle) -> KrillResult<ParentCaContact> {
        let ca = self.ca_manager.get_ca(ca).await?;
        ca.parent(parent).map(|p| p.clone())
    }

    /// Returns the history for a CA.
    pub async fn ca_history(&self, ca: &CaHandle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> {
        self.ca_manager.ca_history(ca, crit).await
    }

    pub fn ca_command_details(&self, ca: &CaHandle, command: CommandKey) -> KrillResult<CaCommandDetails> {
        self.ca_manager.ca_command_details(ca, command)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be found.
    pub async fn ca_publisher_req(&self, ca: &CaHandle) -> KrillResult<idexchange::PublisherRequest> {
        self.ca_manager.get_ca(ca).await.map(|ca| ca.publisher_request())
    }

    pub fn ca_init(&self, init: CertAuthInit) -> KrillEmptyResult {
        let handle = init.unpack();
        self.ca_manager.init_ca(&handle)
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub async fn ca_repo_details(&self, ca_handle: &CaHandle) -> KrillResult<CaRepoDetails> {
        let ca = self.ca_manager.get_ca(ca_handle).await?;
        let contact = ca.repository_contact()?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    /// Update the repository for a CA, or return an error. (see `CertAuth::repo_update`)
    pub async fn ca_repo_update(&self, ca: CaHandle, contact: RepositoryContact, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager
            .update_repo(self.repo_manager.as_ref(), ca, contact, true, actor)
            .await
    }

    pub async fn ca_update_id(&self, ca: CaHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.ca_update_id(ca, actor).await
    }

    pub async fn ca_keyroll_init(&self, ca: CaHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager.ca_keyroll_init(ca, Duration::seconds(0), actor).await
    }

    pub async fn ca_keyroll_activate(&self, ca: CaHandle, actor: &Actor) -> KrillEmptyResult {
        self.ca_manager
            .ca_keyroll_activate(ca, Duration::seconds(0), actor)
            .await
    }

    pub async fn rfc6492(
        &self,
        ca: CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        self.ca_manager.rfc6492(&ca, msg_bytes, user_agent, actor).await
    }
}

/// # Handle ASPA requests
///
impl KrillServer {
    pub async fn ca_aspas_definitions_show(&self, ca: CaHandle) -> KrillResult<AspaDefinitionList> {
        self.ca_manager.ca_aspas_definitions_show(ca).await
    }

    pub async fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_aspas_definitions_update(ca, updates, actor).await
    }

    pub async fn ca_aspas_update_aspa(
        &self,
        ca: CaHandle,
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_aspas_update_aspa(ca, customer, update, actor).await
    }
}

/// # Handle BGPSec requests
///
impl KrillServer {
    pub async fn ca_bgpsec_definitions_show(&self, ca: CaHandle) -> KrillResult<BgpSecCsrInfoList> {
        self.ca_manager.ca_bgpsec_definitions_show(ca).await
    }

    pub async fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ca_bgpsec_definitions_update(ca, updates, actor).await
    }
}

/// # Handle route authorization requests
///
impl KrillServer {
    pub async fn ca_routes_update(
        &self,
        ca: CaHandle,
        updates: RoaConfigurationUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_routes_update(ca, updates, actor).await
    }

    pub async fn ca_routes_show(&self, handle: &CaHandle) -> KrillResult<Vec<ConfiguredRoa>> {
        let ca = self.ca_manager.get_ca(handle).await?;

        Ok(ca.configured_roas())
    }

    pub async fn ca_routes_bgp_analysis(&self, handle: &CaHandle) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle).await?;
        let definitions = ca.configured_roas();
        let resources_held = ca.all_resources();
        Ok(self
            .bgp_analyser
            .analyse(definitions.as_slice(), &resources_held, None)
            .await)
    }

    pub async fn ca_routes_bgp_dry_run(
        &self,
        handle: &CaHandle,
        updates: RoaConfigurationUpdates,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle).await?;

        let updates = updates.into_explicit_max_length();
        let resources_held = ca.all_resources();
        let limit = Some(updates.affected_prefixes());

        let (would_be_routes, _) = ca.update_authorizations(&updates)?;
        let would_be_configurations = would_be_routes.roa_configurations();
        let configured_roas = ca.configured_roas_for_configs(would_be_configurations);

        Ok(self
            .bgp_analyser
            .analyse(&configured_roas, &resources_held, limit)
            .await)
    }

    pub async fn ca_routes_bgp_suggest(
        &self,
        handle: &CaHandle,
        limit: Option<ResourceSet>,
    ) -> KrillResult<BgpAnalysisSuggestion> {
        let ca = self.ca_manager.get_ca(handle).await?;
        let configured_roas = ca.configured_roas();
        let resources_held = ca.all_resources();

        Ok(self
            .bgp_analyser
            .suggest(configured_roas.as_slice(), &resources_held, limit)
            .await)
    }

    /// Re-issue ROA objects so that they will use short subjects (see issue #700)
    pub async fn force_renew_roas(&self) -> KrillResult<()> {
        self.ca_manager.force_renew_roas_all(self.system_actor()).await
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
    pub async fn rta_list(&self, ca: CaHandle) -> KrillResult<RtaList> {
        let ca = self.ca_manager.get_ca(&ca).await?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub async fn rta_show(&self, ca: CaHandle, name: RtaName) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.ca_manager.get_ca(&ca).await?;
        ca.rta_show(&name)
    }

    /// Sign an RTA - either a new, or a prepared RTA
    pub async fn rta_sign(
        &self,
        ca: CaHandle,
        name: RtaName,
        request: RtaContentRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.rta_sign(ca, name, request, actor).await
    }

    /// Prepare a multi
    pub async fn rta_multi_prep(
        &self,
        ca: CaHandle,
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
        ca: CaHandle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.rta_multi_cosign(ca, name, rta, actor).await
    }
}

// Tested through integration tests
