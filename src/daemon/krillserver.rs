//! An RPKI publication protocol server.
use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use bytes::Bytes;
use chrono::Duration;

use futures::future::join_all;

use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
        publication::{ListReply, PublishDelta},
    },
    repository::{cert::Cert, resources::ResourceSet},
    uri,
};

use crate::{
    commons::{
        actor::{Actor, ActorDef},
        api::{
            AddChildRequest, AllCertAuthIssues, AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates,
            AspaProvidersUpdate, CaCommandDetails, CaRepoDetails, CertAuthInfo, CertAuthInit, CertAuthIssues,
            CertAuthList, CertAuthStats, ChildCaInfo, ChildrenConnectionStats, CommandHistory, CommandHistoryCriteria,
            ParentCaContact, ParentCaReq, PublicationServerUris, PublisherDetails, RepositoryContact, RoaDefinition,
            RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, ServerInfo, TaCertDetails, Timestamp,
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
        ca::{
            self, ta_handle, testbed_ca_handle, CaStatus, ResourceTaggedAttestation, RouteAuthorization,
            RouteAuthorizationUpdates, RtaContentRequest, RtaPrepareRequest,
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

use super::ca::CaManager;

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

        if config.testbed().is_some() && config.benchmark.is_none() {
            info!("Enabling TESTBED mode - ONLY USE THIS FOR TESTING AND TRAINING!");
        }

        if config.benchmark.is_some() {
            if work_dir.join("cas").exists() {
                return Err(Error::Custom(format!(
                    "Cannot start BENCHMARK. Data dir '{}' MUST be empty!",
                    work_dir.to_string_lossy()
                )));
            } else {
                info!("Enabling BENCHMARK mode - ONLY USE THIS FOR TESTING!");
            }
        }

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

        // for now, support that existing embedded repositories are still supported.
        // this should be removed in future after people have had a chance to separate.
        let repo_manager = Arc::new(RepositoryManager::build(config.clone(), signer.clone())?);

        // Used to have a shared queue for the caserver and the background job scheduler.
        let mq = Arc::new(TaskQueue::default());

        let ca_manager =
            Arc::new(ca::CaManager::build(config.clone(), mq.clone(), signer, system_actor.clone()).await?);

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
                    let pub_req = idexchange::PublisherRequest::new(
                        testbed_ca.id_cert().clone(),
                        testbed_ca_handle.convert(),
                        None,
                    );
                    repo_manager.create_publisher(pub_req, &system_actor)?;

                    let repo_response = repo_manager.repository_response(&testbed_ca_handle.convert())?;
                    let repo_contact = RepositoryContact::new(repo_response);
                    ca_manager
                        .update_repo(testbed_ca_handle.clone(), repo_contact, false, &system_actor)
                        .await?;

                    // Establish the TA (parent) <-> testbed CA (child) relationship
                    let testbed_ca_resources = ResourceSet::all();

                    let (child_id_cert, _, _) = testbed_ca.child_request().unpack();

                    let child_req =
                        AddChildRequest::new(testbed_ca_handle.convert(), testbed_ca_resources, child_id_cert);
                    let parent_ca_contact = ca_manager
                        .ca_add_child(&ta_handle, child_req, &service_uri, &system_actor)
                        .await?;
                    let parent_req = ParentCaReq::new(ta_handle.convert(), parent_ca_contact);
                    ca_manager
                        .ca_parent_add_or_update(testbed_ca_handle.clone(), parent_req, &system_actor)
                        .await?;

                    // Force testbed-ta syncing now so that testbed will get its certificate
                    // immediately. We will need this if we have a benchmark config.

                    // First sync will inform testbed of its entitlements and trigger that
                    // CSR is created.
                    let ta_parent_handle = ta_handle.convert();

                    ca_manager
                        .ca_sync_parent(&testbed_ca_handle, &ta_parent_handle, &system_actor)
                        .await?;

                    // Second sync will send that CSR to the parent
                    ca_manager
                        .ca_sync_parent(&testbed_ca_handle, &ta_parent_handle, &system_actor)
                        .await?;
                }
            }
        }

        if let Some(benchmark) = &config.benchmark {
            // Create child CAs and ROAs per CA
            info!(
                "Will now create {} CAS with {} ROAs each",
                benchmark.cas, benchmark.ca_roas
            );

            let service_uri = Arc::new(service_uri.clone());
            let actor = Arc::new(system_actor.clone());

            let mut setup_benchmark_ca_fns = vec![];
            for nr in 0..benchmark.cas {
                setup_benchmark_ca_fns.push(tokio::spawn(Self::setup_benchmark_ca(
                    nr,
                    benchmark.ca_roas,
                    ca_manager.clone(),
                    repo_manager.clone(),
                    service_uri.clone(),
                    actor.clone(),
                )));
            }
            join_all(setup_benchmark_ca_fns).await;
        }

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_risdumps_enabled,
            &config.bgp_risdumps_v4_uri,
            &config.bgp_risdumps_v6_uri,
        ));

        mq.server_started();

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

/// # Support CA set up for testbed and benchmarking
///
impl KrillServer {
    /// Setup a benchmark CA
    ///
    async fn setup_benchmark_ca(
        nr: usize,
        nr_roas: usize,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        service_uri: Arc<uri::Https>,
        system_actor: Arc<Actor>,
    ) -> KrillResult<()> {
        // Set it up as a child under testbed
        let testbed_parent = testbed_ca_handle().into_converted();

        // We can do a pretty naive approach to give up to 65536 CAs
        // as /24 out of 10.0.0.0/8. And then let them create ROAs for
        // that prefix with private space ASNs (unless we need too many..)
        //
        // Config::verify() will ensure that we have at most 65535 CAs
        // and no more than 100 ROAs per CA.
        //
        // For now this should be fine - we can always come up with
        // more complicated setups in future (e.g. feed NRO stats and
        // BGP announcement info to generate some real world like hierarchy)

        let child_ca_handle = CaHandle::new(nr.to_string().into());

        let byte_2_ipv4 = nr / 256;
        let byte_3_ipv4 = nr % 256;

        let prefix_str = format!("10.{}.{}.0/24", byte_2_ipv4, byte_3_ipv4);
        let resources = ResourceSet::from_strs("", &prefix_str, "")
            .map_err(|e| Error::ResourceSetError(format!("cannot parse resources: {}", e)))?;

        Self::setup_test_ca(
            &child_ca_handle,
            &testbed_parent,
            resources,
            ca_manager.clone(),
            repo_manager.clone(),
            service_uri.clone(),
            system_actor.clone(),
        )
        .await?;

        // Now we can create ROAs

        let mut added: Vec<RouteAuthorization> = vec![];
        let asn_range_start = 64512;
        for asn in asn_range_start..asn_range_start + nr_roas {
            let def = RoaDefinition::from_str(&format!("{} => {}", prefix_str, asn)).unwrap();
            added.push(def.into());
        }
        let updates = RouteAuthorizationUpdates::new(added, vec![]);

        ca_manager
            .ca_routes_update(child_ca_handle, updates, &system_actor)
            .await?;

        Ok(())
    }

    /// Sets up a CA for the testbed, or benchmark.
    async fn setup_test_ca(
        ca_handle: &CaHandle,
        parent_handle: &ParentHandle,
        resources: ResourceSet,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        service_uri: Arc<uri::Https>,
        system_actor: Arc<Actor>,
    ) -> KrillResult<()> {
        if !ca_manager.has_ca(ca_handle)? {
            info!("Setup CA {}", ca_handle);

            // Add the new testbed CA
            ca_manager.init_ca(ca_handle)?;
            let ca = ca_manager.get_ca(ca_handle).await?;

            // Add the new testbed publisher
            let pub_req = idexchange::PublisherRequest::new(ca.id_cert().clone(), ca_handle.convert(), None);
            repo_manager.create_publisher(pub_req, &system_actor)?;

            let repo_response = repo_manager.repository_response(&ca_handle.convert())?;
            let repo_contact = RepositoryContact::new(repo_response);
            ca_manager
                .update_repo(ca_handle.clone(), repo_contact, false, &system_actor)
                .await?;

            // Establish the Parent <-> CA relationship
            let (child_id_cert, _, _) = ca.child_request().unpack();

            let child_req = AddChildRequest::new(ca_handle.convert(), resources, child_id_cert);
            let parent_ca_contact = ca_manager
                .ca_add_child(&parent_handle.convert(), child_req, &service_uri, &system_actor)
                .await?;
            let parent_req = ParentCaReq::new(parent_handle.clone(), parent_ca_contact);
            ca_manager
                .ca_parent_add_or_update(ca_handle.clone(), parent_req, &system_actor)
                .await?;

            // The task queue is not available yet, so force synchronising the testbed
            // with its parent now.

            // First sync will inform testbed of its entitlements and trigger that
            // CSR is created.
            ca_manager
                .ca_sync_parent(ca_handle, parent_handle, &system_actor)
                .await?;

            // Second sync will send that CSR to the parent
            ca_manager
                .ca_sync_parent(ca_handle, parent_handle, &system_actor)
                .await?;
        }
        Ok(())
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

    pub async fn trust_anchor_cert(&self) -> Option<Cert> {
        self.ta().await.ok().map(|details| details.cert().clone())
    }

    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub async fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<ParentCaContact> {
        let contact = self.ca_manager.ca_add_child(ca, req, &self.service_uri, actor).await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(&self, ca: &CaHandle, child: ChildHandle) -> KrillResult<ParentCaContact> {
        let contact = self.ca_manager.ca_parent_contact(ca, child, &self.service_uri).await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_response(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<idexchange::ParentResponse> {
        let contact = self.ca_manager.ca_parent_response(ca, child, &self.service_uri).await?;
        Ok(contact)
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_update(ca, child, req, actor).await?;
        Ok(())
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
        let contact = parent_req.contact();
        self.ca_manager
            .get_entitlements_from_contact(&ca, parent, contact, false)
            .await?;

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
    pub async fn republish_all(&self) -> KrillEmptyResult {
        self.ca_manager.republish_all().await?;
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
        self.ca_manager.delete_ca(ca, actor).await
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
        self.ca_manager.update_repo(ca, contact, true, actor).await
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

/// # Handle route authorization requests
///
impl KrillServer {
    pub async fn ca_routes_update(
        &self,
        ca: CaHandle,
        updates: RoaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_routes_update(ca, updates.into(), actor).await
    }

    pub async fn ca_routes_show(&self, handle: &CaHandle) -> KrillResult<Vec<RoaDefinition>> {
        let ca = self.ca_manager.get_ca(handle).await?;
        Ok(ca.roa_definitions())
    }

    pub async fn ca_routes_bgp_analysis(&self, handle: &CaHandle) -> KrillResult<BgpAnalysisReport> {
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
        handle: &CaHandle,
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
        handle: &CaHandle,
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
