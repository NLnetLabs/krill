//! An RPKI publication protocol server.
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use clap::crate_version;
use chrono::Duration;
use futures_util::future::try_join_all;
use log::info;

use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::daemon::http::auth::AuthInfo;
use crate::{
    commons::{
        actor::Actor,
        crypto::KrillSignerBuilder,
        error::Error,
        KrillEmptyResult, KrillResult,
    },
    constants::*,
    config::Config,
    server::{
        ca::{
            self, testbed_ca_handle, CaManager, CaStatus,
        },
        mq::{now, Task, TaskQueue},
        pubd::RepositoryManager,
        scheduler::Scheduler,
    },
};
use crate::api;
use crate::api::admin::{
    AddChildRequest, CertAuthInit, ParentCaContact, ParentCaReq,
    PublicationServerUris, PublisherDetails, RepoFileDeleteCriteria,
    RepositoryContact, UpdateChildRequest, 
};
use crate::api::aspa::{
    AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate,
    CustomerAsn,
};
use crate::api::bgp::{BgpAnalysisReport, BgpAnalysisSuggestion};
use crate::api::bgpsec::{BgpSecCsrInfoList, BgpSecDefinitionUpdates};
use crate::api::ca::{
    AllCertAuthIssues, CaRepoDetails, CertAuthInfo, CertAuthIssues,
    CertAuthList, CertAuthStats, ChildCaInfo, ChildrenConnectionStats,
    IdCertInfo, ReceivedCert, RtaList, RtaName,
    RtaPrepResponse,
};
use crate::api::history::{
    CommandDetails, CommandHistory, CommandHistoryCriteria
};
use crate::api::import::ImportChild;
use crate::api::pubd::RepoStats;
use crate::api::roa::{
    ConfiguredRoa, RoaConfiguration, RoaConfigurationUpdates, RoaPayload,
};
use crate::api::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
};
use crate::api::ta::{
    TaCertDetails, TrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::constants::{TA_NAME, ta_handle};
use crate::server::bgp::BgpAnalyser;


//------------ KrillManager ---------------------------------------------------

/// This is the Krill server that is doing all the orchestration for all
/// components.
pub struct KrillManager {
    // The base URI for this service
    service_uri: uri::Https,

    // Publication server, with configured publishers
    repo_manager: Arc<RepositoryManager>,

    // Handles the internal TA and/or CAs
    ca_manager: Arc<ca::CaManager>,

    // Handles the internal TA and/or CAs
    bgp_analyser: Arc<BgpAnalyser>,

    // Shared message queue
    mq: Arc<TaskQueue>,

    // System actor
    system_actor: Actor,

    pub config: Arc<Config>,
}

/// # Set up and initialization
impl KrillManager {
    /// Creates a new publication server. Note that state is preserved
    /// in the data storage.
    pub async fn build(config: Arc<Config>) -> KrillResult<Self> {
        let service_uri = config.service_uri();

        info!("Starting {} v{}", KRILL_SERVER_APP, crate_version!());
        info!("{} uses service uri: {}", KRILL_SERVER_APP, service_uri);

        // Assumes that Config::verify() has already ensured that the signer
        // configuration is valid and that Config::resolve() has been
        // used to update signer name references to resolve to the
        // corresponding signer configurations.
        let probe_interval =
            std::time::Duration::from_secs(config.signer_probe_retry_seconds);
        let signer = KrillSignerBuilder::new(
            &config.storage_uri,
            probe_interval,
            &config.signers,
        )
        .with_default_signer(config.default_signer())
        .with_one_off_signer(config.one_off_signer())
        .build()?;
        let signer = Arc::new(signer);

        let system_actor = ACTOR_DEF_KRILL;

        // Task queue Arc is shared between ca_manager, repo_manager and the
        // scheduler.
        let mq = Arc::new(TaskQueue::new(&config.storage_uri)?);

        // for now, support that existing embedded repositories are still
        // supported. this should be removed in future after people
        // have had a chance to separate.
        let repo_manager = Arc::new(RepositoryManager::build(
            config.clone(),
            mq.clone(),
            signer.clone(),
        )?);

        let ca_manager = Arc::new(
            ca::CaManager::build(
                config.clone(),
                mq.clone(),
                signer,
                system_actor.clone(),
            )
            .await?,
        );

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_api_enabled,
            config.bgp_api_uri.clone(),
        ));

        // When multi-node set ups with a shared queue are
        // supported then we can no longer safely reschedule
        // ALL running tests. See issue: #1112
        mq.reschedule_tasks_at_startup()?;

        mq.schedule(Task::QueueStartTasks, now())?;

        let server = KrillManager {
            service_uri,
            repo_manager,
            ca_manager,
            bgp_analyser,
            mq,
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
                // Will do some set up. Both TESTBED and BENCHMARK (which
                // implies TESTBED and adds to it) will need a
                // testbed ca to be set up first. We will re-use the import
                // functionality to do all this.
                let testbed_ca = api::import::ImportCa {
                    handle: testbed_handle,
                    parents: vec![api::import::ImportParent {
                        handle: ta_handle().into_converted(),
                        resources: ResourceSet::all(),
                    }],
                    roas: vec![],
                };

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

                        let testbed_parent: ParentHandle =
                            testbed_ca_handle().into_converted();
                        for nr in 0..benchmark.cas {
                            let handle = CaHandle::new(
                                format!("benchmark-{}", nr).into(),
                            );

                            // derive resources for benchmark ca
                            let byte_2_ipv4 = nr / 256;
                            let byte_3_ipv4 = nr % 256;

                            let prefix_str = format!(
                                "10.{}.{}.0/24",
                                byte_2_ipv4, byte_3_ipv4
                            );
                            let resources =
                                ResourceSet::from_strs("", &prefix_str, "")
                                    .map_err(|e| {
                                    Error::ResourceSetError(format!(
                                        "cannot parse resources: {}",
                                        e
                                    ))
                                })?;

                            // Create ROA configs
                            let mut roas: Vec<RoaConfiguration> = vec![];
                            let asn_range_start = 64512;
                            for asn in asn_range_start
                                ..asn_range_start + benchmark.ca_roas
                            {
                                let payload = RoaPayload::from_str(&format!(
                                    "{} => {}",
                                    prefix_str, asn
                                ))
                                .unwrap();
                                roas.push(payload.into());
                            }

                            import_cas.push(api::import::ImportCa {
                                handle,
                                parents: vec![api::import::ImportParent {
                                    handle: testbed_parent.clone(),
                                    resources,
                                }],
                                roas,
                            })
                        }
                    }
                }

                let startup_structure = api::import::Structure::for_testbed(
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
            self.config.clone(),
            self.system_actor.clone(),
        )
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }
}

/// # Access to components
impl KrillManager {
    pub fn system_actor(&self) -> &Actor {
        &self.system_actor
    }

    pub fn testbed_enabled(&self) -> bool {
        self.ca_manager.testbed_enabled()
    }
}

/// # Configure publishers
impl KrillManager {
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
    pub fn remove_publisher(
        &self,
        publisher: PublisherHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.repo_manager.remove_publisher(publisher, actor)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn delete_matching_files(
        &self,
        criteria: RepoFileDeleteCriteria,
    ) -> KrillEmptyResult {
        self.repo_manager.delete_matching_files(criteria)
    }

    /// Returns a publisher.
    pub fn get_publisher(
        &self,
        publisher: PublisherHandle,
    ) -> KrillResult<PublisherDetails> {
        self.repo_manager.get_publisher_details(publisher)
    }

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.config.repo_dir().to_path_buf();
        path.push("rrdp");
        path.to_path_buf()
    }
}

/// # Manage RFC8181 clients
impl KrillManager {
    pub fn repository_response(
        &self,
        publisher: &PublisherHandle,
    ) -> KrillResult<idexchange::RepositoryResponse> {
        self.repo_manager.repository_response(publisher)
    }

    pub fn rfc8181(
        &self,
        publisher: PublisherHandle,
        msg_bytes: Bytes,
    ) -> KrillResult<Bytes> {
        self.repo_manager.rfc8181(publisher, msg_bytes)
    }
}

/// # TA Support
impl KrillManager {
    pub fn ta_proxy_enabled(&self) -> bool {
        self.config.ta_proxy_enabled()
    }

    pub async fn ta_proxy_init(&self) -> KrillResult<()> {
        self.ca_manager.ta_proxy_init()
    }

    pub async fn ta_proxy_id(&self) -> KrillResult<IdCertInfo> {
        self.ca_manager.ta_proxy_id()
    }

    pub async fn ta_proxy_publisher_request(
        &self,
    ) -> KrillResult<idexchange::PublisherRequest> {
        self.ca_manager.ta_proxy_publisher_request()
    }

    pub async fn ta_proxy_repository_update(
        &self,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager
            .ta_proxy_repository_update(contact, actor)
    }

    pub async fn ta_proxy_repository_contact(
        &self,
    ) -> KrillResult<RepositoryContact> {
        self.ca_manager.ta_proxy_repository_contact()
    }

    pub async fn ta_proxy_signer_add(
        &self,
        info: TrustAnchorSignerInfo,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ta_proxy_signer_add(info, actor)
    }

    pub async fn ta_proxy_signer_update(
        &self,
        info: TrustAnchorSignerInfo,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ta_proxy_signer_update(info, actor)
    }

    pub async fn ta_proxy_signer_make_request(
        &self,
        actor: &Actor,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.ca_manager.ta_proxy_signer_make_request(actor)
    }

    pub async fn ta_proxy_signer_get_request(
        &self,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.ca_manager.ta_proxy_signer_get_request()
    }

    pub async fn ta_proxy_signer_process_response(
        &self,
        response: TrustAnchorSignedResponse,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager
            .ta_proxy_signer_process_response(response, actor)
    }

    pub async fn ta_proxy_children_add(
        &self,
        child_request: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        // TA as parent is handled a special case in the following
        self.ca_manager.ca_add_child(
            &ta_handle().convert(),
            child_request,
            &self.config.service_uri(),
            actor,
        )
    }

    pub async fn ta_cert_details(&self) -> KrillResult<TaCertDetails> {
        let proxy = self.ca_manager.get_trust_anchor_proxy()?;
        Ok(proxy.get_ta_details()?.clone())
    }

    pub async fn trust_anchor_cert(&self) -> Option<ReceivedCert> {
        self.ta_cert_details()
            .await
            .ok()
            .map(|details| details.into())
    }
}

/// # Being a parent
impl KrillManager {
    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub async fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_add_child(ca, req, &self.service_uri, actor)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<ParentCaContact> {
        self.ca_manager.ca_parent_contact(ca, child, &self.service_uri)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_response(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_parent_response(ca, child, &self.service_uri)
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_update(ca, child, req, actor)
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_remove(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_remove(ca, child, actor)
    }

    /// Show details for a child under the CA.
    pub async fn ca_child_show(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<ChildCaInfo> {
        self.ca_manager.ca_show_child(ca, child)
    }

    /// Export a child under the CA.
    pub async fn api_ca_child_export(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<ImportChild> {
        self.ca_manager.ca_child_export(ca, child)
    }

    /// Import a child under the CA.
    pub async fn api_ca_child_import(
        &self,
        ca: &CaHandle,
        child: ImportChild,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ca_child_import(ca, child, actor)
    }

    /// Show children stats under the CA.
    pub async fn ca_stats_child_connections(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<ChildrenConnectionStats> {
        self.ca_manager
            .get_ca_status(ca)
            .map(|status| status.get_children_connection_stats())
    }
}

/// # Being a child
impl KrillManager {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub async fn ca_child_req(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<idexchange::ChildRequest> {
        self.ca_manager
            .get_ca(ca)
            .map(|ca| ca.child_request())
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_add_or_update(
        &self,
        ca: CaHandle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillEmptyResult {
        // Verify that we can get entitlements from the new parent before
        // adding/updating it.
        let contact = ParentCaContact::try_from_rfc8183_parent_response(
            parent_req.response.clone(),
        )
        .map_err(|e| {
            Error::CaParentResponseInvalid(ca.clone(), e.to_string())
        })?;
        self.ca_manager.get_entitlements_from_contact(
            &ca, &parent_req.handle, &contact, false
        ).await?;

        // Seems good. Add/update the parent.
        self.ca_manager.ca_parent_add_or_update(ca, parent_req, actor)
    }

    pub async fn ca_parent_remove(
        &self,
        handle: CaHandle,
        parent: ParentHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_parent_remove(handle, parent, actor)
            .await
    }
}

/// # Stats and status of CAS
impl KrillManager {
    pub async fn cas_stats(
        &self,
    ) -> KrillResult<HashMap<CaHandle, CertAuthStats>> {
        let mut res = HashMap::new();

        for handle in self.ca_manager.ca_handles()? {
            // can't fail really, but to be sure
            if let Ok(ca) = self.ca_manager.get_ca(&handle) {
                let roas = ca.configured_roas();
                let roa_count = roas.len();
                let child_count = ca.children().count();

                let bgp_report = if ca.handle().as_str() == "ta"
                    || ca.handle().as_str() == "testbed"
                {
                    BgpAnalysisReport::new(vec![])
                } else {
                    self.bgp_analyser
                        .analyse(roas.as_slice(), &ca.all_resources(), None)
                        .await
                };

                res.insert(
                    ca.handle().clone(),
                    CertAuthStats {
                        roa_count,
                        child_count,
                        bgp_stats: bgp_report.into(),
                    },
                );
            }
        }

        Ok(res)
    }

    pub async fn cas_import(
        &self,
        structure: api::import::Structure,
    ) -> KrillResult<()> {
        let actor = Arc::new(self.system_actor().clone());

        // We need to know which CAs already exist. They should not be
        // imported again, but can serve as parents.
        let mut existing_cas = HashMap::new();
        for handle in self.ca_manager.ca_handles()? {
            let parent_handle = handle.convert();
            let resources =
                self.ca_manager.get_ca(&handle)?.all_resources();
            existing_cas.insert(parent_handle, resources);
        }
        structure.validate_ca_hierarchy(existing_cas)?;

        if let Some(publication_server_uris) =
            structure.publication_server.clone()
        {
            info!("Initialising publication server");
            self.repo_manager.init(publication_server_uris)?;
        }

        if let Some(import_ta) = structure.ta.clone() {
            if self.config.ta_proxy_enabled()
                && self.config.ta_signer_enabled()
            {
                info!("Creating embedded Trust Anchor");
                self.ca_manager
                    .ta_init_fully_embedded(
                        import_ta.ta_aia,
                        vec![import_ta.ta_uri],
                        import_ta.ta_key_pem,
                        &self.repo_manager,
                        &actor,
                    )
                    .await?;
            } else {
                return Err(Error::custom(
                    "Import TA requires ta_support_enabled = true and ta_signer_enabled = true",
                ));
            }
        }

        info!("Bulk import {} CAs", structure.cas.len());
        // Set up each online TA child with local repo, do this in parallel.
        let mut import_fns = vec![];
        let service_uri = Arc::new(self.config.service_uri());
        for ca in structure.cas {
            import_fns.push(tokio::spawn(Self::import_ca(
                ca,
                self.ca_manager.clone(),
                self.repo_manager.clone(),
                service_uri.clone(),
                actor.clone(),
            )));
        }
        try_join_all(import_fns).await.map_err(|e| {
            Error::Custom(format!("Could not import CAs: {}", e))
        })?;

        Ok(())
    }

    async fn import_ca(
        import: api::import::ImportCa,
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
        info!("Importing CA: '{}'", import.handle);

        // init CA
        ca_manager.init_ca(import.handle.clone())?;

        // Get Publisher Request
        let pub_req = {
            let ca = ca_manager.get_ca(&import.handle)?;
            idexchange::PublisherRequest::new(
                ca.id_cert().base64.clone(),
                import.handle.convert(),
                None,
            )
        };

        // Add Publisher
        repo_manager.create_publisher(pub_req, &actor)?;

        // Get Repository Contact for CA
        let repo_contact = {
            let repo_response =
                repo_manager.repository_response(&import.handle.convert())?;
            RepositoryContact::try_from_response(repo_response)
                .map_err(Error::rfc8183)?
        };

        // Add Repository to CA
        ca_manager
            .update_repo(
                &repo_manager,
                import.handle.clone(),
                repo_contact,
                false,
                &actor,
            )
            .await?;

        for import_parent in import.parents {
            // The parent should have been created. If it wasn't created yet,
            // then we will need to wait for it. Note that we can
            // be sure that it will be created because we verified
            // that all parents are either "ta" (which is always created) or
            // another CA that appeared on the list before this CA.
            //
            // But.. you know.. just to be safe, let's not hang in here
            // forever..
            let wait_ms = 100;
            let max_tries = 3000; // *100ms -> 5 mins, should be enough even on slow systems
            let mut tried = 0;
            let parent_as_ca: CaHandle = import_parent.handle.convert();

            // If the parent is the TA, then there is no need to wait.
            if import_parent.handle.as_str() != TA_NAME {
                loop {
                    tried += 1;
                    if let Ok(parent) = ca_manager.get_ca(&parent_as_ca)
                    {
                        if parent.all_resources().contains(
                            &import_parent.resources
                        ) {
                            break;
                        }
                        else {
                            info!(
                                "Parent {} does not (yet) have resources for {}. Will wait a bit and try again",
                                parent.handle(),
                                import.handle
                            );
                        }
                    } else {
                        info!(
                            "Parent {} for CA {} is not yet created. Will wait a bit and try again",
                            parent_as_ca, import.handle
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(
                        wait_ms,
                    ))
                    .await;
                    if tried >= max_tries {
                        return Err(Error::Custom(format!(
                            "Could not import CA {}. Parent: {} is not created",
                            import.handle, parent_as_ca
                        )));
                    }
                }
            }

            // Add the CA as the child of parent and get the parent response
            let response = {
                let ca = ca_manager.get_ca(&import.handle)?;
                let id_cert =
                    ca.child_request().validate().map_err(Error::rfc8183)?;
                let child_req = AddChildRequest {
                    handle: import.handle.convert(),
                    resources: import_parent.resources,
                    id_cert,
                };

                ca_manager
                    .ca_add_child(
                        &import_parent.handle.convert(),
                        child_req,
                        &service_uri,
                        &actor,
                    )?
            };

            // Add the parent to the child and force sync
            {
                let parent_req = ParentCaReq {
                    handle: import_parent.handle.clone(),
                    response
                };
                ca_manager.ca_parent_add_or_update(
                    import.handle.clone(),
                    parent_req,
                    &actor,
                )?;

                // First sync will inform child of its entitlements and
                // trigger that CSR is created.
                ca_manager.ca_sync_parent(
                    &import.handle, 0, &import_parent.handle, &actor
                ).await?;

                // Second sync will send that CSR to the parent
                ca_manager.ca_sync_parent(
                    &import.handle, 0, &import_parent.handle, &actor
                ).await?;

                // If the parent is a TA, then we will need to push a bit
                // more.. Normally this should be handled by
                // triggered tasks, but the task scheduler is
                // not running when we do this at startup.
                if import_parent.handle.as_str() == TA_NAME {
                    ca_manager.sync_ta_proxy_signer_if_possible()?;
                    ca_manager.ca_sync_parent(
                        &import.handle, 0, &import_parent.handle, &actor
                    ).await?;
                }
            }
        }

        // Add ROA definitions
        let roa_updates = RoaConfigurationUpdates {
            added: import.roas,
            removed: vec![]
        };
        ca_manager.ca_routes_update(import.handle, roa_updates, &actor)?;

        Ok(())
    }

    pub async fn all_ca_issues(
        &self,
        auth: &AuthInfo,
    ) -> KrillResult<AllCertAuthIssues> {
        let mut all_issues = AllCertAuthIssues::default();
        for ca in &self.ca_list(auth)?.cas {
            let issues = self.ca_issues(&ca.handle).await?;
            if !issues.is_empty() {
                all_issues.cas.insert(ca.handle.clone(), issues);
            }
        }

        Ok(all_issues)
    }

    pub async fn ca_issues(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<CertAuthIssues> {
        self.ca_manager.get_ca_issues(ca)
    }
}

/// # Synchronization operations for CAS
impl KrillManager {
    /// Republish all CAs that need it.
    pub async fn republish_all(&self, force: bool) -> KrillEmptyResult {
        let cas = self.ca_manager.republish_all(force).await?;
        for ca in cas {
            self.cas_repo_sync_single(&ca)?;
        }

        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub fn cas_repo_sync_all(&self, auth: &AuthInfo) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_repo_sync_all(auth)
    }

    /// Re-sync a specific CA with its repository
    pub fn cas_repo_sync_single(&self, ca: &CaHandle) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_repo_sync(ca.clone())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn cas_refresh_all(&self) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_refresh_all()
    }

    /// Refresh a specific CA with its parents
    pub async fn cas_refresh_single(
        &self,
        ca_handle: CaHandle,
    ) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_refresh_single(ca_handle)
    }

    /// Schedule check suspend children for all CAs
    pub fn cas_schedule_suspend_all(&self) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_suspend_all()
    }
}

/// # Admin CAS
impl KrillManager {
    pub fn ca_list(&self, auth: &AuthInfo) -> KrillResult<CertAuthList> {
        self.ca_manager.ca_list(auth)
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be
    /// found.
    pub async fn ca_info(&self, ca: &CaHandle) -> KrillResult<CertAuthInfo> {
        self.ca_manager.get_ca(ca).map(|ca| ca.as_ca_info())
    }

    pub fn ca_status(&self, ca: &CaHandle) -> KrillResult<CaStatus> {
        self.ca_manager.get_ca_status(ca)
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn ca_delete(
        &self,
        ca: &CaHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager
            .delete_ca(self.repo_manager.as_ref(), ca, actor)
            .await
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the
    /// CA or the parent cannot be found.
    pub async fn ca_my_parent_contact(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
    ) -> KrillResult<ParentCaContact> {
        let ca = self.ca_manager.get_ca(ca)?;
        ca.parent(parent).cloned()
    }

    /// Returns the history for a CA.
    pub async fn ca_history(
        &self,
        ca: &CaHandle,
        crit: CommandHistoryCriteria,
    ) -> KrillResult<CommandHistory> {
        self.ca_manager.ca_history(ca, crit)
    }

    pub fn ca_command_details(
        &self,
        ca: &CaHandle,
        version: u64,
    ) -> KrillResult<CommandDetails> {
        self.ca_manager.ca_command_details(ca, version)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be
    /// found.
    pub async fn ca_publisher_req(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<idexchange::PublisherRequest> {
        self.ca_manager
            .get_ca(ca)
            .map(|ca| ca.publisher_request())
    }

    pub fn ca_init(&self, init: CertAuthInit) -> KrillEmptyResult {
        self.ca_manager.init_ca(init.handle)
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub async fn ca_repo_details(
        &self,
        ca_handle: &CaHandle,
    ) -> KrillResult<CaRepoDetails> {
        let ca = self.ca_manager.get_ca(ca_handle)?;
        let contact = ca.repository_contact()?;
        Ok(CaRepoDetails { contact: contact.clone() })
    }

    /// Update the repository for a CA, or return an error. (see
    /// `CertAuth::repo_update`)
    pub async fn ca_repo_update(
        &self,
        ca: CaHandle,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .update_repo(self.repo_manager.as_ref(), ca, contact, true, actor)
            .await
    }

    pub async fn ca_update_id(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_update_id(ca, actor)
    }

    pub async fn ca_keyroll_init(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_keyroll_init(ca, Duration::seconds(0), actor)
    }

    pub async fn ca_keyroll_activate(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_keyroll_activate(ca, Duration::seconds(0), actor)
    }

    pub async fn rfc6492(
        &self,
        ca: CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        self.ca_manager.rfc6492(&ca, msg_bytes, user_agent, actor)
    }
}

/// # Handle ASPA requests
impl KrillManager {
    pub async fn ca_aspas_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<AspaDefinitionList> {
        self.ca_manager.ca_aspas_definitions_show(ca)
    }

    pub async fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_aspas_definitions_update(ca, updates, actor)
    }

    pub async fn ca_aspas_update_aspa(
        &self,
        ca: CaHandle,
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_aspas_update_aspa_providers(
            ca, customer, update, actor
        )
    }
}

/// # Handle BGPSec requests
impl KrillManager {
    pub async fn ca_bgpsec_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<BgpSecCsrInfoList> {
        self.ca_manager.ca_bgpsec_definitions_show(ca)
    }

    pub async fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ca_bgpsec_definitions_update(ca, updates, actor)
    }
}

/// # Handle route authorization requests
impl KrillManager {
    pub async fn ca_routes_update(
        &self,
        ca: CaHandle,
        updates: RoaConfigurationUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_routes_update(ca, updates, actor)
    }

    pub async fn ca_routes_show(
        &self,
        handle: &CaHandle,
    ) -> KrillResult<Vec<ConfiguredRoa>> {
        let ca = self.ca_manager.get_ca(handle)?;

        Ok(ca.configured_roas())
    }

    pub async fn ca_routes_bgp_analysis(
        &self,
        handle: &CaHandle,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle)?;
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
        mut updates: RoaConfigurationUpdates,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.ca_manager.get_ca(handle)?;

        updates.set_explicit_max_length();
        let resources_held = ca.all_resources();
        let limit = Some(updates.affected_prefixes());

        let would_be_routes = ca.get_updated_authorizations(&updates)?;
        let would_be_configurations = would_be_routes.roa_configurations();
        let configured_roas =
            ca.configured_roas_for_configs(would_be_configurations);

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
        let ca = self.ca_manager.get_ca(handle)?;
        let configured_roas = ca.configured_roas();
        let resources_held = ca.all_resources();

        Ok(self
            .bgp_analyser
            .suggest(configured_roas.as_slice(), &resources_held, limit)
            .await)
    }

    /// Re-issue ROA objects so that they will use short subjects (see issue
    /// #700)
    pub async fn force_renew_roas(&self) -> KrillResult<()> {
        self.ca_manager.force_renew_roas_all(self.system_actor())
    }
}

/// # Handle Repository Server requests
impl KrillManager {
    /// Create the publication server, will fail if it was already created.
    pub fn repository_init(
        &self,
        uris: PublicationServerUris,
    ) -> KrillResult<()> {
        self.repo_manager.init(uris)
    }

    /// Clear the publication server. Will fail if it still has publishers. Or
    /// if it does not exist
    pub fn repository_clear(&self) -> KrillResult<()> {
        self.repo_manager.repository_clear()
    }

    /// Perform an RRDP session reset. Useful after a restart of the server as
    /// we can never be certain whether the previous state was the last
    /// public state seen by validators, or.. the server was started using
    /// a back up.
    pub fn repository_session_reset(&self) -> KrillResult<()> {
        self.repo_manager.rrdp_session_reset()
    }
}

/// # Handle Resource Tagged Attestation requests
impl KrillManager {
    /// List all known RTAs
    pub async fn rta_list(&self, ca: CaHandle) -> KrillResult<RtaList> {
        let ca = self.ca_manager.get_ca(&ca)?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub async fn rta_show(
        &self,
        ca: CaHandle,
        name: RtaName,
    ) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.ca_manager.get_ca(&ca)?;
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
        self.ca_manager.rta_sign(ca, name, request, actor)
    }

    /// Prepare a multi
    pub async fn rta_multi_prep(
        &self,
        ca: CaHandle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<RtaPrepResponse> {
        self.ca_manager.rta_multi_prep(&ca, name.clone(), request, actor)?;
        let ca = self.ca_manager.get_ca(&ca)?;
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
        self.ca_manager.rta_multi_cosign(ca, name, rta, actor)
    }
}

// Tested through integration tests
