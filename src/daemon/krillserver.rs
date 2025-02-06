//! An RPKI publication protocol server.
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use chrono::Duration;


use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::daemon::auth::AuthInfo;
use crate::{
    commons::{
        actor::Actor,
        api::{
            self,
            import::{ExportChild, ImportChild},
            AddChildRequest, AllCertAuthIssues, AspaDefinitionList,
            AspaDefinitionUpdates, AspaProvidersUpdate, BgpSecCsrInfoList,
            BgpSecDefinitionUpdates, CaCommandDetails, CaRepoDetails,
            CertAuthInfo, CertAuthInit, CertAuthIssues, CertAuthList,
            CertAuthStats, ChildCaInfo, ChildrenConnectionStats,
            CommandHistory, CommandHistoryCriteria, ConfiguredRoa,
            CustomerAsn, IdCertInfo, ParentCaContact, ParentCaReq,
            PublicationServerUris, PublisherDetails, ReceivedCert,
            RepoFileDeleteCriteria, RepositoryContact, RoaConfiguration,
            RoaConfigurationUpdates, RoaPayload, RtaList, RtaName,
            RtaPrepResponse, UpdateChildRequest,
        },
        bgp::{BgpAnalyser, BgpAnalysisReport, BgpAnalysisSuggestion},
        crypto::KrillSignerBuilder,
        error::Error,
        KrillEmptyResult, KrillResult,
    },
    constants::*,
    daemon::{
        ca::{
            self, testbed_ca_handle, CaManager, CaStatus, CertAuth,
            ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
        },
        config::Config,
        mq::{now, Task, TaskQueue},
        scheduler::Scheduler,
    },
    pubd::{RepoStats, RepositoryManager},
    ta::{
        ta_handle, TaCertDetails, TrustAnchorSignedRequest,
        TrustAnchorSignedResponse, TrustAnchorSignerInfo, TA_NAME,
    },
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::Authorizer;



//------------ KrillServer ---------------------------------------------------

/// This is the Krill server that is doing all the orchestration for all
/// components.
pub struct KrillServer {
    // The base URI for this service
    service_uri: uri::Https,

    // Publication server, with configured publishers
    repo_manager: Arc<RepositoryManager>,

    // Handles the internal TA and/or CAs
    ca_manager: Arc<ca::CaManager>,

    // Shared message queue
    mq: Arc<TaskQueue>,

    // Auth info for our system actor
    system_actor: AuthInfo,

    pub config: Arc<Config>,
}

/// # Set up and initialization
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// in the data storage.
    pub fn build(config: Arc<Config>) -> KrillResult<Self> {
        let service_uri = config.service_uri();

        info!("Starting {} v{}", KRILL_SERVER_APP, KRILL_VERSION);
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
        let system_actor = AuthInfo::system(ACTOR_COMPONENT_KRILL);

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
                system_actor.actor().clone(),
            )?,
        );

        // When multi-node set ups with a shared queue are
        // supported then we can no longer safely reschedule
        // ALL running tests. See issue: #1112
        mq.reschedule_tasks_at_startup()?;

        mq.schedule(Task::QueueStartTasks, now())?;

        let server = KrillServer {
            service_uri,
            repo_manager,
            ca_manager,
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

                            import_cas.push(api::import::ImportCa::new(
                                handle,
                                vec![api::import::ImportParent::new(
                                    testbed_parent.clone(),
                                    resources,
                                )],
                                roas,
                            ))
                        }
                    }
                }

                let startup_structure = api::import::Structure::for_testbed(
                    testbed.ta_aia().clone(),
                    testbed.ta_uri().clone(),
                    testbed.publication_server_uris(),
                    import_cas,
                );
                server.cas_import(startup_structure)?;
            }
        }

        Ok(server)
    }

    pub fn build_scheduler(
        &self,
        #[cfg(feature = "multi-user")]
        authorizer: Arc<Authorizer>,
    ) -> Scheduler {
        Scheduler::build(
            self.mq.clone(),
            self.ca_manager.clone(),
            self.repo_manager.clone(),
            #[cfg(feature = "multi-user")]
            authorizer,
            self.config.clone(),
            self.system_actor.actor().clone(),
        )
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }

    pub fn system_actor(&self) -> &Actor {
        self.system_actor.actor()
    }

    pub fn testbed_enabled(&self) -> bool {
        self.ca_manager.testbed_enabled()
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
        publisher: &PublisherHandle,
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
impl KrillServer {
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
impl KrillServer {
    pub fn ta_proxy_enabled(&self) -> bool {
        self.config.ta_proxy_enabled()
    }

    pub fn ta_proxy_init(&self) -> KrillResult<()> {
        self.ca_manager.ta_proxy_init()
    }

    pub fn ta_proxy_id(&self) -> KrillResult<IdCertInfo> {
        self.ca_manager.ta_proxy_id()
    }

    pub fn ta_proxy_publisher_request(
        &self,
    ) -> KrillResult<idexchange::PublisherRequest> {
        self.ca_manager.ta_proxy_publisher_request()
    }

    pub fn ta_proxy_repository_update(
        &self,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ta_proxy_repository_update(contact, actor)
    }

    pub fn ta_proxy_repository_contact(
        &self,
    ) -> KrillResult<RepositoryContact> {
        self.ca_manager.ta_proxy_repository_contact()
    }

    pub fn ta_proxy_signer_add(
        &self,
        info: TrustAnchorSignerInfo,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ta_proxy_signer_add(info, actor)
    }

    pub fn ta_proxy_signer_make_request(
        &self,
        actor: &Actor,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.ca_manager.ta_proxy_signer_make_request(actor)
    }

    pub fn ta_proxy_signer_get_request(
        &self,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.ca_manager.ta_proxy_signer_get_request()
    }

    pub fn ta_proxy_signer_process_response(
        &self,
        response: TrustAnchorSignedResponse,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ta_proxy_signer_process_response(response, actor)
    }

    pub fn ta_proxy_children_add(
        &self,
        child_request: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        // TA as parent is handled a special case in the following
        self.ca_manager
            .ca_add_child(
                &ta_handle().convert(),
                child_request,
                &self.config.service_uri(),
                actor,
            )
    }

    pub fn ta_cert_details(&self) -> KrillResult<TaCertDetails> {
        let proxy = self.ca_manager.get_trust_anchor_proxy()?;
        Ok(proxy.get_ta_details()?.clone())
    }

    pub fn trust_anchor_cert(&self) -> Option<ReceivedCert> {
        self.ta_cert_details()
            .ok()
            .map(|details| details.into())
    }
}

/// # Being a parent
impl KrillServer {
    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_add_child(ca, req, &self.service_uri, actor)
    }

    /// Shows the parent contact for a child.
    pub fn ca_parent_contact(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<ParentCaContact> {
        self.ca_manager.ca_parent_contact(ca, child, &self.service_uri)
    }

    /// Shows the parent contact for a child.
    pub fn ca_parent_response(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
    ) -> KrillResult<idexchange::ParentResponse> {
        self.ca_manager.ca_parent_response(ca, child, &self.service_uri)
    }

    /// Update IdCert or resources of a child.
    pub fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_update(ca, child, req, actor)
    }

    /// Update IdCert or resources of a child.
    pub fn ca_child_remove(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_child_remove(ca, child, actor)?;
        Ok(())
    }

    /// Show details for a child under the CA.
    pub fn ca_child_show(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<ChildCaInfo> {
        self.ca_manager.ca_show_child(ca, child)
    }

    /// Export a child under the CA.
    pub fn api_ca_child_export(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<ExportChild> {
        self.ca_manager.ca_child_export(ca, child)
    }

    /// Import a child under the CA.
    pub fn api_ca_child_import(
        &self,
        ca: &CaHandle,
        child: ImportChild,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.ca_child_import(ca, child, actor)
    }

    /// Show children stats under the CA.
    pub fn ca_stats_child_connections(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<ChildrenConnectionStats> {
        self.ca_manager
            .get_ca_status(ca)
            .map(|status| status.get_children_connection_stats())
    }
}

/// # Being a child
impl KrillServer {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub fn ca_child_req(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<idexchange::ChildRequest> {
        self.ca_manager
            .get_ca(ca)
            .map(|ca| ca.child_request())
    }

    /// Updates a parent contact for a CA
    pub fn ca_parent_add_or_update(
        &self,
        ca: CaHandle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillEmptyResult {
        let parent = parent_req.handle();

        // Verify that we can get entitlements from the new parent before
        // adding/updating it.
        let contact = ParentCaContact::for_rfc8183_parent_response(
            parent_req.response().clone(),
        )
        .map_err(|e| {
            Error::CaParentResponseInvalid(ca.clone(), e.to_string())
        })?;
        self.ca_manager
            .get_entitlements_from_contact(&ca, parent, &contact, false)?;

        // Seems good. Add/update the parent.
        self.ca_manager
            .ca_parent_add_or_update(ca, parent_req, actor)
    }

    pub fn ca_parent_remove(
        &self,
        handle: CaHandle,
        parent: ParentHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_parent_remove(handle, parent, actor)
    }

    pub fn ca_parent_revoke(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_parent_revoke(handle, parent)
    }
}

/// # Stats and status of CAS
impl KrillServer {
    pub fn ca_count(&self) -> KrillResult<usize> {
        Ok(self.ca_list(&self.system_actor)?.cas().len())
    }

    pub fn cas_stats(
        &self,
    ) -> KrillResult<Vec<CaStats>> {
        let mut res = Vec::new();

        for handle in self.ca_manager.ca_handles()? {
            // can't fail really, but to be sure
            if let Ok(ca) = self.get_ca(&handle) {
                let status = self.ca_status(&handle)?;
                res.push(CaStats::new(ca, status));
            }
        }

        Ok(res)
    }

    pub fn cas_import(
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
                let (ta_aia, ta_uris, ta_key_pem, _ta_mft_nr_override) =
                    import_ta.unpack();
                self.ca_manager
                    .ta_init_fully_embedded(
                        ta_aia,
                        ta_uris,
                        ta_key_pem,
                        &self.repo_manager,
                        &actor,
                    )?;
            } else {
                return Err(Error::custom(
                    "Import TA requires ta_support_enabled = true and ta_signer_enabled = true",
                ));
            }
        }

        info!("Bulk import {} CAs", structure.cas.len());
        // Set up each online TA child with local repo, do this in parallel.
        // TODO todo: Do this in parallel.
        for ca in structure.into_cas() {
            Self::import_ca(
                ca,
                self.ca_manager.clone(),
                self.repo_manager.clone(),
                &self.service_uri,
                actor.clone(),
            )?;
        }

        /* This was:
        let mut import_fns = vec![];
        let service_uri = Arc::new(self.config.service_uri());
        for ca in structure.into_cas() {
            import_fns.push(tokio::spawn(Self::import_ca(
                ca,
                self.ca_manager.clone(),
                self.repo_manager.clone(),
                self.service_uri.clone(),
                actor.clone(),
            )));
        }
        try_join_all(import_fns).map_err(|e| {
            Error::Custom(format!("Could not import CAs: {}", e))
        })?;
        */

        Ok(())
    }

    fn import_ca(
        ca: api::import::ImportCa,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        service_uri: &uri::Https,
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
            let ca = ca_manager.get_ca(&ca_handle)?;
            idexchange::PublisherRequest::new(
                ca.id_cert().base64().clone(),
                ca_handle.convert(),
                None,
            )
        };

        // Add Publisher
        repo_manager.create_publisher(pub_req, &actor)?;

        // Get Repository Contact for CA
        let repo_contact = {
            let repo_response =
                repo_manager.repository_response(&ca_handle.convert())?;
            RepositoryContact::for_response(repo_response)
                .map_err(Error::rfc8183)?
        };

        // Add Repository to CA
        ca_manager
            .update_repo(
                &repo_manager,
                ca_handle.clone(),
                repo_contact,
                false,
                &actor,
            )?;

        for import_parent in parents {
            let (parent, resources) = import_parent.unpack();

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
            let parent_as_ca: CaHandle = parent.convert();

            // If the parent is the TA, then there is no need to wait.
            if parent.as_str() != TA_NAME {
                loop {
                    tried += 1;
                    if let Ok(parent) = ca_manager.get_ca(&parent_as_ca) {
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
                    std::thread::sleep(std::time::Duration::from_millis(
                        wait_ms,
                    ));
                    if tried >= max_tries {
                        return Err(Error::Custom(format!(
                            "Could not import CA {}. Parent: {} is not created",
                            ca_handle, parent_as_ca
                        )));
                    }
                }
            }

            // Add the CA as the child of parent and get the parent response
            let parent_response = {
                let ca = ca_manager.get_ca(&ca_handle)?;
                let id_cert =
                    ca.child_request().validate().map_err(Error::rfc8183)?;
                let child_req = AddChildRequest::new(
                    ca_handle.convert(),
                    resources,
                    id_cert,
                );

                ca_manager
                    .ca_add_child(
                        &parent.convert(),
                        child_req,
                        service_uri,
                        &actor,
                    )?
            };

            // Add the parent to the child and force sync
            {
                let parent_req =
                    ParentCaReq::new(parent.clone(), parent_response);
                ca_manager
                    .ca_parent_add_or_update(
                        ca_handle.clone(),
                        parent_req,
                        &actor,
                    )?;

                // First sync will inform child of its entitlements and
                // trigger that CSR is created.
                ca_manager
                    .ca_sync_parent(&ca_handle, 0, &parent, &actor)?;

                // Second sync will send that CSR to the parent
                ca_manager
                    .ca_sync_parent(&ca_handle, 0, &parent, &actor)?;

                // If the parent is a TA, then we will need to push a bit
                // more.. Normally this should be handled by
                // triggered tasks, but the task scheduler is
                // not running when we do this at startup.
                if parent.as_str() == TA_NAME {
                    ca_manager.sync_ta_proxy_signer_if_possible()?;
                    ca_manager
                        .ca_sync_parent(&ca_handle, 0, &parent, &actor)?;
                }
            }
        }

        // Add ROA definitions
        let roa_updates = RoaConfigurationUpdates::new(roas, vec![]);
        ca_manager
            .ca_routes_update(ca_handle, roa_updates, &actor)?;

        Ok(())
    }

    pub fn all_ca_issues(
        &self,
        auth: &AuthInfo,
    ) -> KrillResult<AllCertAuthIssues> {
        let mut all_issues = AllCertAuthIssues::default();
        for ca in self.ca_list(auth)?.cas() {
            let issues = self.ca_issues(ca.handle())?;
            if !issues.is_empty() {
                all_issues.add(ca.handle().clone(), issues);
            }
        }

        Ok(all_issues)
    }

    pub fn ca_issues(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<CertAuthIssues> {
        let mut issues = CertAuthIssues::default();

        let ca_status = self.ca_manager.get_ca_status(ca)?;

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
impl KrillServer {
    /// Republish all CAs that need it.
    pub fn republish_all(&self, force: bool) -> KrillEmptyResult {
        let cas = self.ca_manager.republish_all(force)?;
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
    pub fn cas_refresh_all(&self) -> KrillEmptyResult {
        self.ca_manager.cas_schedule_refresh_all()
    }

    /// Refresh a specific CA with its parents
    pub fn cas_refresh_single(
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
impl KrillServer {
    pub fn ca_list(&self, auth: &AuthInfo) -> KrillResult<CertAuthList> {
        self.ca_manager.ca_list(auth)
    }

    pub fn get_ca(&self, ca: &CaHandle) -> KrillResult<Ca> {
        self.ca_manager.get_ca(ca).map(|ca| Ca { ca })
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be
    /// found.
    pub fn ca_info(&self, ca: &CaHandle) -> KrillResult<CertAuthInfo> {
        self.ca_manager.get_ca(ca).map(|ca| ca.as_ca_info())
    }

    /// Returns the CA status, or an error if none can be found.
    pub fn ca_status(&self, ca: &CaHandle) -> KrillResult<CaStatus> {
        self.ca_manager.get_ca_status(ca)
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub fn ca_delete(
        &self,
        ca: &CaHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.delete_ca(self.repo_manager.as_ref(), ca, actor)
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the
    /// CA or the parent cannot be found.
    pub fn ca_my_parent_contact(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
    ) -> KrillResult<ParentCaContact> {
        let ca = self.ca_manager.get_ca(ca)?;
        ca.parent(parent).cloned()
    }

    /// Returns the history for a CA.
    pub fn ca_history(
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
    ) -> KrillResult<CaCommandDetails> {
        self.ca_manager.ca_command_details(ca, version)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be
    /// found.
    pub fn ca_publisher_req(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<idexchange::PublisherRequest> {
        self.ca_manager
            .get_ca(ca)
            .map(|ca| ca.publisher_request())
    }

    pub fn ca_init(&self, init: CertAuthInit) -> KrillEmptyResult {
        let handle = init.unpack();
        self.ca_manager.init_ca(&handle)
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub fn ca_repo_details(
        &self,
        ca_handle: &CaHandle,
    ) -> KrillResult<CaRepoDetails> {
        let ca = self.ca_manager.get_ca(ca_handle)?;
        let contact = ca.repository_contact()?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    /// Update the repository for a CA, or return an error. (see
    /// `CertAuth::repo_update`)
    pub fn ca_repo_update(
        &self,
        ca: CaHandle,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .update_repo(self.repo_manager.as_ref(), ca, contact, true, actor)
    }

    pub fn ca_update_id(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_update_id(ca, actor)
    }

    pub fn ca_keyroll_init(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_keyroll_init(ca, Duration::seconds(0), actor)
    }

    pub fn ca_keyroll_activate(
        &self,
        ca: CaHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_keyroll_activate(ca, Duration::seconds(0), actor)
    }

    pub fn rfc6492(
        &self,
        ca: CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        self.ca_manager
            .rfc6492(&ca, msg_bytes, user_agent, actor)
    }
}

/// # Handle ASPA requests
impl KrillServer {
    pub fn ca_aspas_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<AspaDefinitionList> {
        self.ca_manager.ca_aspas_definitions_show(ca)
    }

    pub fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_aspas_definitions_update(ca, updates, actor)
    }

    pub fn ca_aspas_update_aspa(
        &self,
        ca: CaHandle,
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_aspas_update_aspa(ca, customer, update, actor)
    }
}

/// # Handle BGPSec requests
impl KrillServer {
    pub fn ca_bgpsec_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<BgpSecCsrInfoList> {
        self.ca_manager.ca_bgpsec_definitions_show(ca)
    }

    pub fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager
            .ca_bgpsec_definitions_update(ca, updates, actor)
    }
}

/// # Handle route authorization requests
impl KrillServer {
    pub fn ca_routes_update(
        &self,
        ca: CaHandle,
        updates: RoaConfigurationUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_routes_update(ca, updates, actor)
    }

    pub fn ca_routes_show(
        &self,
        handle: &CaHandle,
    ) -> KrillResult<Vec<ConfiguredRoa>> {
        let ca = self.ca_manager.get_ca(handle)?;

        Ok(ca.configured_roas())
    }

    /// Re-issue ROA objects so that they will use short subjects (see issue
    /// #700)
    pub fn force_renew_roas(&self) -> KrillResult<()> {
        self.ca_manager
            .force_renew_roas_all(self.system_actor())
    }
}

/// # Handle Repository Server requests
impl KrillServer {
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
impl KrillServer {
    /// List all known RTAs
    pub fn rta_list(&self, ca: CaHandle) -> KrillResult<RtaList> {
        let ca = self.ca_manager.get_ca(&ca)?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub fn rta_show(
        &self,
        ca: CaHandle,
        name: RtaName,
    ) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.ca_manager.get_ca(&ca)?;
        ca.rta_show(&name)
    }

    /// Sign an RTA - either a new, or a prepared RTA
    pub fn rta_sign(
        &self,
        ca: CaHandle,
        name: RtaName,
        request: RtaContentRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.rta_sign(ca, name, request, actor)
    }

    /// Prepare a multi
    pub fn rta_multi_prep(
        &self,
        ca: CaHandle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<RtaPrepResponse> {
        self.ca_manager
            .rta_multi_prep(&ca, name.clone(), request, actor)?;
        let ca = self.ca_manager.get_ca(&ca)?;
        ca.rta_prep_response(&name)
    }

    /// Co-sign an existing RTA
    pub fn rta_multi_cosign(
        &self,
        ca: CaHandle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.ca_manager.rta_multi_cosign(ca, name, rta, actor)
    }
}


//------------ Ca ------------------------------------------------------------

pub struct Ca {
    ca: Arc<CertAuth>,
}

impl Ca {
    pub fn handle(&self) -> &CaHandle {
        self.ca.handle()
    }

    pub async fn routes_bgp_analysis(
        &self,
        analyser: &BgpAnalyser,
    ) -> BgpAnalysisReport {
        let definitions = self.ca.configured_roas();
        let resources_held = self.ca.all_resources();
        analyser.analyse(
            definitions.as_slice(), &resources_held, None
        ).await
    }

    pub async fn routes_bgp_dry_run(
        &self,
        updates: RoaConfigurationUpdates,
        analyser: &BgpAnalyser,
    ) -> KrillResult<BgpAnalysisReport> {
        let updates = updates.into_explicit_max_length();
        let resources_held = self.ca.all_resources();
        let limit = Some(updates.affected_prefixes());

        let (would_be_routes, _) = self.ca.update_authorizations(&updates)?;
        let would_be_configurations = would_be_routes.roa_configurations();
        let configured_roas =
            self.ca.configured_roas_for_configs(would_be_configurations);

        Ok(analyser.analyse(
            &configured_roas, &resources_held, limit
        ).await)
    }

    pub async fn routes_bgp_suggest(
        &self,
        limit: Option<ResourceSet>,
        analyser: &BgpAnalyser,
    ) -> KrillResult<BgpAnalysisSuggestion> {
        let configured_roas = self.ca.configured_roas();
        let resources_held = self.ca.all_resources();

        Ok(analyser.suggest(
            configured_roas.as_slice(), &resources_held, limit
        ).await)
    }
}


//------------ CaStats -------------------------------------------------------

pub struct CaStats {
    ca: Arc<CertAuth>,
    status: CaStatus,
    roas: Vec<ConfiguredRoa>,
}

impl CaStats {
    fn new(ca: Ca, status: CaStatus) -> Self {
        Self {
            roas: ca.ca.configured_roas(),
            ca: ca.ca,
            status
        }
    }

    pub fn handle(&self) -> &CaHandle {
        self.ca.handle()
    }

    pub fn roa_count(&self) -> usize {
        self.roas.len()
    }

    pub fn child_count(&self) -> usize {
        self.ca.child_count()
    }

    pub fn status(&self) -> &CaStatus {
        &self.status
    }

    pub async fn routes_bgp_analysis(
        &self,
        analyser: &BgpAnalyser,
    ) -> BgpAnalysisReport {
        let resources_held = self.ca.all_resources();
        analyser.analyse(
            self.roas.as_slice(), &resources_held, None
        ).await
    }

    pub async fn to_cert_auth_stats(
        &self,
        analyser: &BgpAnalyser,
    ) -> CertAuthStats {
        CertAuthStats::new(
            self.roa_count(),
            self.child_count(),
            self.routes_bgp_analysis(analyser).await.into()
        )
    }
}

