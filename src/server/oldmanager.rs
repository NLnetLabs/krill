//! An RPKI publication protocol server.

#![allow(dead_code, unused_imports)]

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
            self, CaManager, CaStatus,
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
    CaRepoDetails, CertAuthInfo, CertAuthIssues,
    CertAuthList, CertAuthStats, ChildCaInfo, ChildrenConnectionStats,
    IdCertInfo, RtaList, RtaName,
    RtaPrepResponse,
};
use crate::api::history::{
    CommandDetails, CommandHistory, CommandHistoryCriteria
};
use crate::api::import::ImportChild;
use crate::api::roa::{
    ConfiguredRoa, RoaConfiguration, RoaConfigurationUpdates, RoaPayload,
};
use crate::api::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
};
use crate::api::ta::{
    ApiTrustAnchorSignedRequest, TaCertDetails, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::constants::{TA_NAME, ta_handle};
use crate::server::bgp::BgpAnalyser;
use crate::server::runtime::KrillRuntime;


//------------ OldManager ---------------------------------------------------

/// This is the Krill server that is doing all the orchestration for all
/// components.
pub struct OldManager {
    krill: KrillRuntime,

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
impl OldManager {
    /// Creates a new publication server. Note that state is preserved
    /// in the data storage.
    #[allow(unreachable_code, unused_variables)]
    pub async fn build(config: Arc<Config>) -> KrillResult<Self> {
        let service_uri = config.service_uri();

        info!("Starting {} v{}", KRILL_SERVER_APP, crate_version!());
        info!("{KRILL_SERVER_APP} uses service uri: {service_uri}");

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

        let bgp_analyser = Arc::new(BgpAnalyser::new(&config));

        // When multi-node set ups with a shared queue are
        // supported then we can no longer safely reschedule
        // ALL running tests. See issue: #1112
        mq.reschedule_tasks_at_startup()?;

        mq.schedule(Task::QueueStartTasks, now())?;

        let server = OldManager {
            krill: todo!(),
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
                                format!("benchmark-{nr}").into(),
                            );

                            // derive resources for benchmark ca
                            let byte_2_ipv4 = nr / 256;
                            let byte_3_ipv4 = nr % 256;

                            let prefix_str = format!(
                                "10.{byte_2_ipv4}.{byte_3_ipv4}.0/24"
                            );
                            let resources =
                                ResourceSet::from_strs("", &prefix_str, "")
                                    .map_err(|e| {
                                    Error::ResourceSetError(format!(
                                        "cannot parse resources: {e}"
                                    ))
                                })?;

                            // Create ROA configs
                            let mut roas: Vec<RoaConfiguration> = vec![];
                            let asn_range_start = 64512;
                            for asn in asn_range_start
                                ..asn_range_start + benchmark.ca_roas
                            {
                                let payload = RoaPayload::from_str(&format!(
                                    "{prefix_str} => {asn}"
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
            self.bgp_analyser.clone(),
            self.config.clone(),
            self.system_actor.clone(),
        )
    }
}

/// # Access to components
impl OldManager {
    pub fn system_actor(&self) -> &Actor {
        &self.system_actor
    }

}

/// # Being a child
impl OldManager {
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
            &ca, &parent_req.handle, &contact, false, &self.krill,
        ).await?;

        // Seems good. Add/update the parent.
        self.ca_manager.ca_parent_add_or_update(
            ca, parent_req, actor, &self.krill,
        )
    }

    pub async fn ca_parent_remove(
        &self,
        handle: CaHandle,
        parent: ParentHandle,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager
            .ca_parent_remove(handle, parent, actor, &self.krill)
            .await
    }
}

/// # Stats and status of CAS
impl OldManager {

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
                        &self.krill,
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
                self.krill.clone(),
            )));
        }
        try_join_all(import_fns).await.map_err(|e| {
            Error::Custom(format!("Could not import CAs: {e}"))
        })?;

        Ok(())
    }

    async fn import_ca(
        import: api::import::ImportCa,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        _service_uri: Arc<uri::Https>,
        actor: Arc<Actor>,
        krill: KrillRuntime,
    ) -> KrillEmptyResult {
        // outline:
        // - init ca
        // - set up under repo
        // - set up under parent
        // - wait for resources
        // - recurse for children
        info!("Importing CA: '{}'", import.handle);

        // init CA
        ca_manager.init_ca(import.handle.clone(), &krill)?;

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
                &krill,
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
                        &actor,
                        &krill,
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
                    &krill,
                )?;

                // First sync will inform child of its entitlements and
                // trigger that CSR is created.
                ca_manager.ca_sync_parent(
                    &import.handle, 0, &import_parent.handle, &actor, &krill,
                ).await?;

                // Second sync will send that CSR to the parent
                ca_manager.ca_sync_parent(
                    &import.handle, 0, &import_parent.handle, &actor, &krill,
                ).await?;

                // If the parent is a TA, then we will need to push a bit
                // more.. Normally this should be handled by
                // triggered tasks, but the task scheduler is
                // not running when we do this at startup.
                if import_parent.handle.as_str() == TA_NAME {
                    ca_manager.sync_ta_proxy_signer_if_possible(&krill)?;
                    ca_manager.ca_sync_parent(
                        &import.handle, 0, &import_parent.handle, &actor,
                        &krill,
                    ).await?;
                }
            }
        }

        // Add ROA definitions
        let roa_updates = RoaConfigurationUpdates {
            added: import.roas,
            removed: vec![]
        };
        ca_manager.ca_routes_update(
            import.handle, roa_updates, &actor, &krill
        )?;

        Ok(())
    }
}

/// # Admin CAS
impl OldManager {

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
            .delete_ca(self.repo_manager.as_ref(), ca, actor, &self.krill)
            .await
    }

    /// Update the repository for a CA, or return an error. (see
    /// `CertAuth::repo_update`)
    pub async fn ca_repo_update(
        &self,
        ca: CaHandle,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.update_repo(
            self.repo_manager.as_ref(), ca, contact, true, actor, &self.krill
        ).await
    }
}

/// # Handle ASPA requests
impl OldManager {

    // Left for upgrade only.
    pub fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillEmptyResult {
        self.ca_manager.ca_aspas_definitions_update(
            ca, updates, actor, &self.krill
        )
    }
}

/// # Handle route authorization requests
impl OldManager {

    // Only for upgrade.
    /// Re-issue ROA objects so that they will use short subjects (see issue
    /// #700)
    pub async fn force_renew_roas(&self) -> KrillResult<()> {
        self.ca_manager.force_renew_roas_all(self.system_actor(), &self.krill)
    }
}

// Tested through integration tests
