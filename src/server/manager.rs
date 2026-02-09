//! The public part of the Krill RPKI server.
//!

use std::{error, fmt, thread};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use bytes::Bytes;
use chrono::Duration;
use hyper::StatusCode;
use log::info;
use rpki::ca::{idexchange, publication};
use rpki::repository::resources::ResourceSet;
use tokio::runtime::{Handle as TokioHandle};
use crate::api;
use crate::api::status::ErrorResponse;
use crate::commons::actor::Actor;
use crate::commons::error::KrillError;
use crate::commons::eventsourcing::AggregateStoreError;
use crate::config::Config;
use crate::constants::{TA_NAME, ta_handle, testbed_ca_handle};
use crate::server::ca::CaStatus;
use super::scheduler;
use super::mq::{Task, now};
use super::runtime::KrillRuntime;


//------------ StartupManager ------------------------------------------------

/// The Krill manager during the start-up phase.
///
/// This manager provides functionality that is only available before the
/// HTTP server is started and we are still running sync in a single thread.
pub struct StartupManager {
    runtime: KrillRuntime,
}

impl StartupManager {
    /// Creates a new manager from the provided config.
    ///
    /// While the Tokio runtime provided isn’t used, we need the handle
    /// already to pass it to the Krill runtime.
    pub fn new(
        config: Config, tokio: TokioHandle
    ) -> Result<Self, KrillError> {
        Ok(Self { runtime: KrillRuntime::new(config, tokio)? })
    }

    /// Promotes the startup manager into a full Krill manager.
    pub fn promote(self) -> KrillManager {
        KrillManager { krill_runtime: self.runtime }
    }

    /// Starts the scheduler in a separate thread.
    pub fn run_scheduler(&self) -> Result<(), KrillError> {
        // When multi-node set ups with a shared queue are
        // supported then we can no longer safely reschedule
        // ALL running tests. See issue: #1112
        self.runtime.tasks().reschedule_tasks_at_startup()?;
        self.runtime.tasks().schedule(Task::QueueStartTasks, now())?;

        let krill = self.runtime.clone();
        thread::spawn(|| scheduler::run(krill));
        Ok(())
    }

    /// Re-issue ROA objects so that they will use short subjects.
    ///
    /// See issue #700.
    pub fn force_renew_roas(&self) -> Result<(), KrillError> {
        self.runtime.ca_manager().force_renew_roas_all(
            self.runtime.system_actor(), &self.runtime
        )
    }

    /// Updates the APSA definitions of a CA.
    pub fn ca_aspas_definitions_update(
        &self,
        ca: idexchange::CaHandle,
        updates: api::aspa::AspaDefinitionUpdates,
    ) -> Result<(), KrillError> {
        self.runtime.ca_manager().ca_aspas_definitions_update(
            ca, updates, self.runtime.system_actor(), &self.runtime
        )
    }

    pub fn prepare_testbed(&self) -> Result<(), KrillError> {
        let Some(testbed) = self.runtime.config().testbed() else {
            return Ok(());
        };

        let testbed_handle = testbed_ca_handle();

        if self.runtime.ca_manager().has_ca(&testbed_handle)? {
            if self.runtime.config().benchmark.is_some() {
                info!(
                    "Resuming BENCHMARK mode - will NOT recreate CAs. If \
                     you want to recreate CAs, please wipe the data dir \
                     and restart."
                );
            } else {
                info!(
                    "Resuming TESTBED mode - ONLY USE THIS FOR TESTING \n
                     AND TRAINING!"
                );
            }
            return Ok(());
        }

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

        match self.runtime.config().benchmark.as_ref() {
            None => {
                info!(
                    "Enabling TESTBED mode - ONLY USE THIS FOR TESTING \
                     AND TRAINING!"
                );
            }
            Some(benchmark) => {
                info!(
                    "Enabling BENCHMARK mode with {} CAs with {} ROas \
                     each - ONLY USE THIS FOR TESTING!",
                    benchmark.cas, benchmark.ca_roas
                );

                let testbed_parent: idexchange::ParentHandle =
                    testbed_ca_handle().into_converted();
                for nr in 0..benchmark.cas {
                    let handle = idexchange::CaHandle::new(
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
                            KrillError::ResourceSetError(format!(
                                "cannot parse resources: {e}"
                            ))
                        })?;

                    // Create ROA configs
                    let mut roas: Vec<api::roa::RoaConfiguration> = vec![];
                    let asn_range_start = 64512;
                    for asn in
                        asn_range_start..asn_range_start + benchmark.ca_roas
                    {
                        let payload = api::roa::RoaPayload::from_str(
                            &format!("{prefix_str} => {asn}")
                        ).unwrap();
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

        cas_import(startup_structure, &self.runtime)
    }
}


//------------ KrillManager --------------------------------------------------

pub struct KrillManager {
    krill_runtime: KrillRuntime,
}

impl KrillManager {
    /// Returns a reference to the config.
    pub fn config(&self) -> &Config {
        self.krill_runtime.config()
    }

    /// Returns the system actor.
    pub fn system_actor(&self) -> &Actor {
        self.krill_runtime.system_actor()
    }
}


/// # Low-level flow control
///
/// The two methods in this section are hidden from users by the public
/// methods.
impl KrillManager {
    /// Runs a sync closure which provides an immediate result.
    ///
    /// The closure `op` is run on the sync runtime. It has access to the
    /// [`KrillManager`] via its sole argument. Whatever the closure returns
    /// is what this async method resolves into.
    ///
    /// If, for whatever reason, the closure does not run to completion,
    /// an error is returned.
    async fn run<F, T>(
        &self, op: F
    ) -> Result<T, RunError>
    where
        F: FnOnce(&KrillRuntime) -> Result<T, RunError> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = self.krill_runtime.clone();
        tokio::task::spawn_blocking(move || {
            op(&runtime)
        }).await?
    }
}


/// # Managing all CAs
///
impl KrillManager {
    /// Returns the handles of all CAs.
    pub async fn ca_handles(
        &self
    ) -> Result<Vec<idexchange::CaHandle>, RunError> {
        self.run(|runtime| Ok(runtime.ca_manager().ca_handles()?)).await
    }

    /// Triggers republising of all CAs that need it.
    pub async fn republish_all(&self, force: bool) -> Result<(), RunError> {
        self.run(move |runtime| -> Result<_, RunError> {
            let cas = runtime.ca_manager().republish_all(force, runtime)?;
            for ca in cas {
                runtime.ca_manager().cas_schedule_repo_sync(ca, runtime)?;
            }
            Ok(())
        }).await
    }

    /// Triggers all CAs to re-sync with their repositories
    pub async fn cas_repo_sync_all(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().cas_schedule_repo_sync_all(runtime)?)
        }).await
    }

    /// Triggers all CAs to re-sync with their parent CAs.
    pub async fn cas_refresh_all(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().cas_schedule_refresh_all(runtime)?)
        }).await
    }

    /// Schedules a check to suspend children for all CAs
    pub async fn cas_schedule_suspend_all(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().cas_schedule_suspend_all(runtime)?)
        }).await
    }

    /// Returns statistics for all CAs.
    pub async fn cas_stats(
        &self,
    ) -> Result<
        HashMap<idexchange::CaHandle, api::ca::CertAuthStats>,
        RunError
    > {
        self.run(|runtime| {
            let mut res = HashMap::new();

            for handle in runtime.ca_manager().ca_handles()? {
                // can't fail really, but to be sure
                if let Ok(ca) = runtime.ca_manager().get_ca(&handle) {
                    let roas = ca.configured_roas();
                    let roa_count = roas.len();
                    let child_count = ca.children().count();

                    let bgp_report = if ca.handle().as_str() == "ta"
                        || ca.handle().as_str() == "testbed"
                    {
                        api::bgp::BgpAnalysisReport::new(vec![])
                    }
                    else {
                        runtime.bgp_analyser().analyse(
                            roas.as_slice(), &ca.all_resources(), None
                        )
                    };

                    res.insert(
                        ca.handle().clone(),
                        api::ca::CertAuthStats {
                            roa_count,
                            child_count,
                            bgp_stats: bgp_report.into(),
                        },
                    );
                }
            }

            Ok(res)
        }).await
    }

    /// Returns the parent status for the given CA.
    pub async fn cas_status_map(
        &self,
    ) -> Result<HashMap<idexchange::CaHandle, CaStatus>, RunError> {
        self.run(|runtime| {
            let mut res = HashMap::new();

            for handle in runtime.ca_manager().ca_handles()? {
                if let Ok(ca_status) = runtime.ca_manager().get_ca_status(
                    &handle
                ) {
                    res.insert(handle, ca_status);
                }
            }

            Ok(res)
        }).await
    }

    pub async fn cas_import(
        &self,
        structure: api::import::Structure,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(cas_import(structure, runtime)?)
        }).await
    }
}


/// # Managing a single CA
///
impl KrillManager {
    /// Initialises a new CA.
    pub async fn ca_init(
        &self, init: api::admin::CertAuthInit
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().init_ca(init.handle, runtime)?)
        }).await
    }

    /// Returns the public information for a CA.
    pub async fn ca_info(
        &self, ca: idexchange::CaHandle
    ) -> Result<api::ca::CertAuthInfo, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca(&ca).map(|ca| ca.as_ca_info())?)
        }).await
    }

    /// Creates a new identity certificate for the CA.
    pub async fn ca_update_id(
        &self, ca: idexchange::CaHandle, actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_update_id(ca, &actor, runtime)?)
        }).await
    }

    /// Initiates a key roll for the given CA.
    pub async fn ca_keyroll_init(
        &self, ca: idexchange::CaHandle, actor: Actor
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_keyroll_init(
                ca, Duration::seconds(0), &actor, runtime
            )?)
        }).await
    }

    /// Activates an initiated key roll.
    pub async fn ca_keyroll_activate(
        &self, ca: idexchange::CaHandle, actor: Actor
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_keyroll_activate(
                ca, Duration::seconds(0), &actor, runtime
            )?)
        }).await
    }

    /// Returns the publisher request for a CA.
    pub async fn ca_publisher_req(
        &self,
        ca: idexchange::CaHandle,
    ) -> Result<idexchange::PublisherRequest, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca(&ca)?.publisher_request())
        }).await
    }

    /// Return informatiuon about the configured repository for a given CA.
    pub async fn ca_repo_details(
        &self, ca_handle: idexchange::CaHandle
    ) -> Result<api::ca::CaRepoDetails, RunError> {
        self.run(move |runtime| {
            let ca = runtime.ca_manager().get_ca(&ca_handle)?;
            let contact = ca.repository_contact()?;
            Ok(api::ca::CaRepoDetails { contact: contact.clone() })
        }).await
    }

    /// Updates the repository for a CA.
    pub async fn ca_repo_update(
        &self,
        ca: idexchange::CaHandle,
        contact: api::admin::RepositoryContact,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().update_repo(
                ca, contact, true, &actor, runtime
            )?)
        }).await
    }

    /// Trigger re-syncing with the repository.
    pub async fn ca_sync_repo(
        &self, ca: idexchange::CaHandle
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().cas_schedule_repo_sync(ca, runtime)?)
        }).await
    }

    /// Returns the repository status for the given CA.
    pub async fn ca_repo_status(
        &self, ca: idexchange::CaHandle
    ) -> Result<api::ca::RepoStatus, RunError> {
        self.run(move |runtime| -> Result<_, RunError> {
            Ok(runtime.ca_manager().get_ca_status(&ca)?.into_repo())
        }).await
    }

    /// Returns the parent status for the given CA.
    pub async fn ca_parent_status(
        &self, ca: idexchange::CaHandle
    ) -> Result<api::ca::ParentStatuses, RunError> {
        self.run(move |runtime| -> Result<_, RunError> {
            Ok(runtime.ca_manager().get_ca_status(&ca)?.into_parents())
        }).await
    }

    /// Triggers re-syncing with the parent CAs.
    pub async fn cas_refresh_single(
        &self, ca_handle: idexchange::CaHandle
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().cas_schedule_refresh_single(
                ca_handle, runtime
            )?)
        }).await
    }

    pub async fn ca_issues(
        &self,
        ca: idexchange::CaHandle,
    ) -> Result<api::ca::CertAuthIssues, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca_issues(&ca)?)
        }).await
    }

    /// Returns the history of a CA.
    pub async fn ca_history(
        &self,
        ca: idexchange::CaHandle,
        crit: api::history::CommandHistoryCriteria,
    ) -> Result<api::history::CommandHistory, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_history(&ca, crit)?)
        }).await
    }

    /// Returns the details for the given CA command.
    pub async fn ca_command_details(
        &self,
        ca: idexchange::CaHandle,
        version: u64,
    ) -> Result<Option<api::history::CommandDetails>, RunError> {
        self.run(move |runtime| {
            match runtime.ca_manager().ca_command_details(&ca, version) {
                Ok(res) => Ok(Some(res)),
                Err(KrillError::AggregateStoreError(
                    AggregateStoreError::UnknownCommand(..)
                )) => Ok(None),
                Err(err) => Err(err.into()),
            }
        }).await
    }

    /// Deletes a CA.
    ///
    /// A best effort to send revocation requests and withdraw all objects
    /// is done first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn ca_delete(
        &self,
        ca: idexchange::CaHandle,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().delete_ca(&ca, &actor, runtime)?)
        }).await
    }
}


/// # Managing parent CAs
///
impl KrillManager {
    /// Returns the child request.
    ///
    /// This request is passed to a potential parent CA to register this CA.
    pub async fn ca_child_req(
        &self, ca: idexchange::CaHandle
    ) -> Result<idexchange::ChildRequest, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca(&ca)?.child_request())
        }).await
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_add_or_update(
        &self,
        ca: idexchange::CaHandle,
        parent_req: api::admin::ParentCaReq,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            // Verify that we can get entitlements from the new parent before
            // adding/updating it.
            let contact =
                api::admin::ParentCaContact::try_from_rfc8183_parent_response(
                    parent_req.response.clone(),
            )
            .map_err(|e| {
                KrillError::CaParentResponseInvalid(ca.clone(), e.to_string())
            })?;
            runtime.ca_manager().get_entitlements_from_contact(
                &ca, &parent_req.handle, &contact, false, runtime,
            )?;

            // Seems good. Add/update the parent.
            Ok(runtime.ca_manager().ca_parent_add_or_update(
                ca, parent_req, &actor, runtime
            )?)
        }).await
    }

    pub async fn ca_parent_remove(
        &self,
        handle: idexchange::CaHandle,
        parent: idexchange::ParentHandle,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_parent_remove(
                handle, parent, &actor, runtime
            )?)
        }).await
    }

    /// Returns the parent contact for a CA’s parent.
    pub async fn ca_parent_contact(
        &self,
        ca: idexchange::CaHandle,
        parent: idexchange::ParentHandle,
    ) -> Result<api::admin::ParentCaContact, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca(&ca)?.parent(&parent)?.clone())
        }).await
    }
}


/// # Managing child CAs
///
impl KrillManager {
    /// Adds a child to a CA.
    ///
    /// Returns the parent response that the child will need to contact this
    /// CA for resource requests.
    pub async fn ca_add_child(
        &self,
        ca: idexchange::CaHandle,
        req: api::admin::AddChildRequest,
        actor: Actor
    ) -> Result<idexchange::ParentResponse, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_add_child(&ca, req, &actor, runtime)?)
        }).await
    }

    /// Return the parent response for a child CA.
    pub async fn ca_parent_response(
        &self,
        ca: idexchange::CaHandle,
        child: idexchange::ChildHandle,
    ) -> Result<idexchange::ParentResponse, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_parent_response(
                &ca, child, runtime.service_uri()
            )?)
        }).await
    }

    /// Updates the identity certificate or resources of a child CA.
    pub async fn ca_child_update(
        &self,
        ca: idexchange::CaHandle,
        child: idexchange::ChildHandle,
        req: api::admin::UpdateChildRequest,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_child_update(
                &ca, child, req, &actor, runtime
            )?)
        }).await
    }

    /// Removes a child CA.
    pub async fn ca_child_remove(
        &self,
        ca: idexchange::CaHandle,
        child: idexchange::ChildHandle,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_child_remove(
                &ca, child, &actor, runtime
            )?)
        }).await
    }

    /// Returns details for a child CA.
    pub async fn ca_child_show(
        &self,
        ca: idexchange::CaHandle,
        child: idexchange::ChildHandle,
    ) -> Result<api::ca::ChildCaInfo, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_show_child(&ca, &child)?)
        }).await
    }

    /// Exports a child CA.
    pub async fn ca_child_export(
        &self,
        ca: idexchange::CaHandle,
        child: idexchange::ChildHandle,
    ) -> Result<api::import::ImportChild, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_child_export(&ca, &child)?)
        }).await
    }

    /// Imports a child CA.
    pub async fn ca_child_import(
        &self,
        ca: idexchange::CaHandle,
        child: api::import::ImportChild,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_child_import(
                &ca, child, &actor, runtime
            )?)
        }).await
    }

    /// Returns child CA statistics.
    pub async fn ca_stats_child_connections(
        &self,
        ca: idexchange::CaHandle,
    ) -> Result<api::ca::ChildrenConnectionStats, RunError> {
        self.run(move |runtime| {
            Ok(
                runtime.ca_manager().get_ca_status(
                    &ca
                )?.get_children_connection_stats()
            )
        }).await
    }

    /// Handles a synchronization request by a child CA.
    pub async fn rfc6492(
        &self,
        ca: idexchange::CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: Actor,
    ) -> Result<Bytes, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().rfc6492(
                &ca, msg_bytes, user_agent, &actor, runtime
            )?)
        }).await
    }
}

/// # Managing ASPAs
///
impl KrillManager {
    /// Returns the current ASPA definitions for a CA.
    pub async fn ca_aspas_definitions_show(
        &self,
        ca: idexchange::CaHandle,
    ) -> Result<api::aspa::AspaDefinitionList, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_aspas_definitions_show(&ca)?)
        }).await
    }

    /// Updates the APSA definitions of a CA.
    pub async fn ca_aspas_definitions_update(
        &self,
        ca: idexchange::CaHandle,
        updates: api::aspa::AspaDefinitionUpdates,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_aspas_definitions_update(
                ca, updates, &actor, runtime
            )?)
        }).await
    }

    /// Updates the ASPA provider set for a single customer ASN.
    pub async fn ca_aspas_update_aspa(
        &self,
        ca: idexchange::CaHandle,
        customer: api::aspa::CustomerAsn,
        update: api::aspa::AspaProvidersUpdate,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_aspas_update_aspa_providers(
                ca, customer, update, &actor, runtime
            )?)
        }).await
    }
}


/// # Managing BGPsec router keys
///
impl KrillManager {
    /// Lists the currently configured BGPsec router keys for a CA.
    pub async fn ca_bgpsec_definitions_show(
        &self, ca: idexchange::CaHandle
    ) -> Result<api::bgpsec::BgpSecCsrInfoList, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_bgpsec_definitions_show(&ca)?)
        }).await
    }

    /// Updates the BGPsec router key definitions for a CA.
    pub async fn ca_bgpsec_definitions_update(
        &self,
        ca: idexchange::CaHandle,
        updates: api::bgpsec::BgpSecDefinitionUpdates,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_bgpsec_definitions_update(
                ca, updates, &actor, runtime
            )?)
        }).await
    }
}


/// # Managing ROAs
///
impl KrillManager {
    /// Returns the list of current ROA definitions for a CA.
    pub async fn ca_routes_show(
        &self, handle: idexchange::CaHandle
    ) -> Result<Vec<api::roa::ConfiguredRoa>, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().get_ca(&handle)?.configured_roas())
        }).await
    }

    /// Updates the ROA definitions of a CA.
    pub async fn ca_routes_update(
        &self,
        ca: idexchange::CaHandle,
        updates: api::roa::RoaConfigurationUpdates,
        actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ca_routes_update(
                ca, updates, &actor, runtime
            )?)
        }).await
    }

    /// Produces the BGP analysis for a CA.
    pub async fn ca_routes_bgp_analysis(
        &self,
        handle: idexchange::CaHandle,
    ) -> Result<api::bgp::BgpAnalysisReport, RunError> {
        self.run(move |runtime| {
            let ca = runtime.ca_manager().get_ca(&handle)?;
            let definitions = ca.configured_roas();
            let resources_held = ca.all_resources();
            Ok(runtime.bgp_analyser().analyse(
                definitions.as_slice(), &resources_held, None
            ))
        }).await
    }

    /// Performs a BGP analysis for the given changes to a CA.
    pub async fn ca_routes_bgp_dry_run(
        &self,
        handle: idexchange::CaHandle,
        mut updates: api::roa::RoaConfigurationUpdates,
    ) -> Result<api::bgp::BgpAnalysisReport, RunError> {
        self.run(move |runtime| {
            let ca = runtime.ca_manager().get_ca(&handle)?;

            updates.set_explicit_max_length();
            let resources_held = ca.all_resources();
            let limit = Some(updates.affected_prefixes());

            let would_be_routes = ca.get_updated_authorizations(&updates)?;
            let would_be_configurations = would_be_routes.roa_configurations();
            let configured_roas =
                ca.configured_roas_for_configs(would_be_configurations);

            Ok(runtime.bgp_analyser().analyse(
                &configured_roas, &resources_held, limit
            ))
        }).await
    }

    /// Produces suggestions for updates based on a BGP analysis.
    pub async fn ca_routes_bgp_suggest(
        &self,
        handle: idexchange::CaHandle,
        limit: Option<ResourceSet>,
    ) -> Result<api::bgp::BgpAnalysisSuggestion, RunError> {
        self.run(move |runtime| {
            let ca = runtime.ca_manager().get_ca(&handle)?;
            let configured_roas = ca.configured_roas();
            let resources_held = ca.all_resources();

            Ok(runtime.bgp_analyser().suggest(
                configured_roas.as_slice(), &resources_held, limit
            ))
        }).await
    }
}


/// # Publication server
///
impl KrillManager {
    /// Creates the publication server.
    ///
    /// Fails if there is an initialized publication server already.
    pub async fn repository_init(
        &self,
        uris: api::admin::PublicationServerUris,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().init(uris, runtime)?)
        }).await
    }

    /// Clears the publication server.
    ///
    /// This will fail if the server still has publishers or if it hasn’t
    /// been intialized yet.
    pub async fn repository_clear(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.repo_manager().repository_clear()?)
        }).await
    }

    /// Performs an RRDP session reset.
    ///
    /// This is useful after a restart of the server as we can never be
    /// certain whether the previous state was the last public state seen
    /// by validators, or when the server was started using a back up.
    pub async fn repository_session_reset(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.repo_manager().rrdp_session_reset()?)
        }).await
    }

    /// Converts the RRDP path portion of a HTTP request URI to a path.
    ///
    /// The `path` should contain everything after the `/rrdp/` portion of
    /// the URI’s path. If the path is in principle valid, i.e., could
    /// represent an RRDP resource generated by this RRDP sever, the method
    /// will return a file system path representing this path. This does not
    /// mean there will actually be a file there. The file may have been
    /// deleted or may have never existed at all. This is necessary since
    /// the RRDP server doesn’t track past files, only the currently valid
    /// set of resources.
    ///
    /// If the path is definitely not valid, returns `Ok(None)`. This should
    /// probably be translated into a 404 Not Found response.
    pub async fn resolve_rrdp_request_path(
        &self, path: String
    ) -> Result<Option<PathBuf>, RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().resolve_rrdp_request_path(&path)?)
        }).await
    }

    /// Processes an RFC 8181 publisher request.
    pub async fn rfc8181(
        &self,
        publisher: idexchange::PublisherHandle,
        msg_bytes: Bytes,
    ) -> Result<Bytes, RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().rfc8181(publisher, msg_bytes, runtime)?)
        }).await
    }
}

/// # Managing the publication server
///
impl KrillManager {
    /// Returns the repository server stats
    pub async fn repo_stats(
        &self
    ) -> Result<api::pubd::RepoStats, RunError> {
        self.run(|runtime| {
            Ok(runtime.repo_manager().repo_stats()?)
        }).await
    }

    /// Returns all list of the handles of all current publishers.
    pub async fn publishers(
        &self
    ) -> Result<Vec<idexchange::PublisherHandle>, RunError> {
        self.run(|runtime| {
            Ok(runtime.repo_manager().publishers()?)
        }).await
    }

    /// Returns details for the publisher with the given handle.
    pub async fn get_publisher(
        &self, publisher: idexchange::PublisherHandle,
    ) -> Result<api::admin::PublisherDetails, RunError> {
        self.run(|runtime| {
            Ok(runtime.repo_manager().get_publisher_details(publisher)?)
        }).await
    }

    pub async fn repository_response(
        &self, publisher: idexchange::PublisherHandle,
    ) -> Result<idexchange::RepositoryResponse, RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().repository_response(
                &publisher, runtime
            )?)
        }).await
    }

    /// Adds a new publishers:
    ///
    /// This errors out if the publisher already exists.
    pub async fn add_publisher(
        &self, req: idexchange::PublisherRequest, actor: Actor,
    ) -> Result<idexchange::RepositoryResponse, RunError> {
        self.run(move |runtime| {
            let publisher_handle = req.publisher_handle().clone();
            runtime.repo_manager().create_publisher(req, &actor)?;
            Ok(runtime.repo_manager().repository_response(
                &publisher_handle, runtime
            )?)
        }).await
    }

    /// Removes the publisher with the given handle.
    ///
    /// Returns an error if no publisher with such a handle exists.
    pub async fn remove_publisher(
        &self, publisher: idexchange::PublisherHandle, actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().remove_publisher(
                publisher, &actor, runtime
            )?)
        }).await
    }

    /// Deletes files matching the given criteria.
    pub async fn delete_matching_files(
        &self, criteria: api::admin::RepoFileDeleteCriteria,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.repo_manager().delete_matching_files(criteria)?)
        }).await
    }
}

/// # Managing the trust anchor
///
impl KrillManager {
    /// Initialises the trust anchor proxy.
    pub async fn ta_proxy_init(&self) -> Result<(), RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().ta_proxy_init(runtime)?)
        }).await
    }

    /// Returns the TAL for the trust anchor.
    pub async fn ta_tal(
        &self
    ) -> Result<String, RunError> {
        self.run(|runtime| {
            let proxy = runtime.ca_manager().get_trust_anchor_proxy()?;
            Ok(proxy.get_ta_details()?.tal.to_string())
        }).await
    }

    /// Returns the certificate of the trust anchor.
    pub async fn ta_cer(
        &self
    ) -> Result<Bytes, RunError> {
        self.run(|runtime| {
            let proxy = runtime.ca_manager().get_trust_anchor_proxy()?;
            Ok(proxy.get_ta_details()?.cert.to_bytes())
        }).await
    }

    /// Returns the trust anchor proxy ID certificate.
    pub async fn ta_proxy_id(&self) -> Result<api::ca::IdCertInfo, RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().ta_proxy_id()?)
        }).await
    }

    /// Returns the trust anchor proxy publisher request.
    pub async fn ta_proxy_publisher_request(
        &self,
    ) -> Result<idexchange::PublisherRequest, RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().ta_proxy_publisher_request()?)
        }).await
    }

    /// Updates the trust anchor repository contact.
    pub async fn ta_proxy_repository_update(
        &self, contact: api::admin::RepositoryContact, actor: Actor
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ta_proxy_repository_update(
                contact, &actor, runtime
            )?)
        }).await
    }

    /// Returns the current trust anchor repository contact.
    pub async fn ta_proxy_repository_contact(
        &self,
    ) -> Result<api::admin::RepositoryContact, RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().ta_proxy_repository_contact()?)
        }).await
    }

    /// Adds a trust anchor signer to the trust anchor proxy.
    pub async fn ta_proxy_signer_add(
        &self, info: api::ta::TrustAnchorSignerInfo, actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ta_proxy_signer_add(
                info, &actor, runtime
            )?)
        }).await
    }

    /// Updates the trust anchor signer connected to a trust anchor proxy.
    pub async fn ta_proxy_signer_update(
        &self, info: api::ta::TrustAnchorSignerInfo, actor: Actor,
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ta_proxy_signer_update(
                info, &actor, runtime
            )?)
        }).await
    }

    /// Creates a new trust anchor signer request.
    ///
    /// Returns an error if there is a pending request.
    pub async fn ta_proxy_signer_make_request(
        &self, actor: Actor,
    ) -> Result<api::ta::ApiTrustAnchorSignedRequest, RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ta_proxy_signer_make_request(
                &actor, runtime
            )?)
        }).await
    }

    /// Returns a currently pending trust anchor signer request.
    pub async fn ta_proxy_signer_get_request(
        &self,
    ) -> Result<api::ta::ApiTrustAnchorSignedRequest, RunError> {
        self.run(|runtime| {
            Ok(runtime.ca_manager().ta_proxy_signer_get_request(runtime)?)
        }).await
    }

    /// Processes a trust anchor signer response.
    pub async fn ta_proxy_signer_process_response(
        &self, response: api::ta::TrustAnchorSignedResponse, actor: Actor
    ) -> Result<(), RunError> {
        self.run(move |runtime| {
            Ok(runtime.ca_manager().ta_proxy_signer_process_response(
                response, &actor, runtime
            )?)
        }).await
    }

    /// Adds a child CA to the trust anchor proxy.
    pub async fn ta_proxy_children_add(
        &self,
        child_request: api::admin::AddChildRequest,
        actor: Actor,
    ) -> Result<idexchange::ParentResponse, RunError> {
        self.run(move |runtime| {
            // TA as parent is handled a special case in the following
            Ok(runtime.ca_manager().ca_add_child(
                &ta_handle().convert(),
                child_request,
                &actor,
                runtime
            )?)
        }).await
    }
}


//------------ cas_import ----------------------------------------------------

fn cas_import(
    structure: api::import::Structure,
    krill: &KrillRuntime,
) -> Result<(), KrillError> {
    let actor = krill.system_actor().clone();

    // We need to know which CAs already exist. They should not be
    // imported again, but can serve as parents.
    let mut existing_cas = HashMap::new();
    for handle in krill.ca_manager().ca_handles()? {
        let parent_handle = handle.convert();
        let resources = krill.ca_manager().get_ca(
            &handle
        )?.all_resources();
        existing_cas.insert(parent_handle, resources);
    }
    structure.validate_ca_hierarchy(existing_cas)?;

    if let Some(publication_server_uris) =
        structure.publication_server.clone()
    {
        info!("Initialising publication server");
        krill.repo_manager().init(publication_server_uris, krill)?;
    }

    if let Some(import_ta) = structure.ta.clone() {
        if krill.config().ta_proxy_enabled()
            && krill.config().ta_signer_enabled()
        {
            info!("Creating embedded Trust Anchor");
            krill.ca_manager().ta_init_fully_embedded(
                import_ta.ta_aia,
                vec![import_ta.ta_uri],
                import_ta.ta_key_pem,
                &actor,
                krill
            )?;
        } else {
            return Err(KrillError::custom(
                "Import TA requires ta_support_enabled = true \
                 and ta_signer_enabled = true",
            ));
        }
    }

    info!("Bulk import {} CAs", structure.cas.len());

    // XXX This used to be done in parallel. However, doing it in
    //     serial means we can be sure that a CA’s parents and the
    //     necessary resources already exist. We could potentially
    //     speed this up by creating sets of CAs that can be added
    //     in parallel, but import is rare enough that it probably
    //     doesn’t matter.

    for ca in structure.cas {
        import_ca(ca, krill)?;
    }
    Ok(())
}

fn import_ca(
    import: api::import::ImportCa,
    krill: &KrillRuntime,
) -> Result<(), KrillError> {
    // outline:
    // - init ca
    // - set up under repo
    // - set up under parent
    // - wait for resources
    // - recurse for children
    info!("Importing CA: '{}'", import.handle);

    let actor = krill.system_actor();

    // init CA
    krill.ca_manager().init_ca(import.handle.clone(), krill)?;

    // Get Publisher Request
    let pub_req = {
        let ca = krill.ca_manager().get_ca(&import.handle)?;
        idexchange::PublisherRequest::new(
            ca.id_cert().base64.clone(),
            import.handle.convert(),
            None,
        )
    };

    // Add Publisher
    krill.repo_manager().create_publisher(pub_req, actor)?;

    // Get Repository Contact for CA
    let repo_contact = {
        let repo_response = krill.repo_manager().repository_response(
            &import.handle.convert(), krill
        )?;
        api::admin::RepositoryContact::try_from_response(
            repo_response
        ).map_err(KrillError::rfc8183)?
    };

    // Add Repository to CA
    krill.ca_manager().update_repo(
        import.handle.clone(),
        repo_contact,
        false,
        actor,
        krill,
    )?;

    for import_parent in import.parents {
        // The parent should have been created. We can be sure of that
        // because we verified that all parents are either "ta" (which
        // is always created) or another CA that appeared on the list
        // before this CA.
        let parent_as_ca: idexchange::CaHandle =
            import_parent.handle.convert();

        // If the parent is the TA, then there is no need to wait.
        if import_parent.handle.as_str() != TA_NAME {
            let Ok(parent) = krill.ca_manager().get_ca(
                &parent_as_ca
            ) else {
                return Err(KrillError::Custom(format!(
                    "Could not import CA {}. Parent: {} is not created",
                    import.handle, parent_as_ca
                )))
            };

            if !parent.all_resources().contains(
                &import_parent.resources
            ) {
                return Err(KrillError::Custom(format!(
                    "Could not import CA {}. \
                     Parent: {} does not contain all resources.",
                    import.handle, parent_as_ca
                )))
            }
        }

        // Add the CA as the child of parent and get the parent response
        let response = {
            let ca = krill.ca_manager().get_ca(&import.handle)?;
            let id_cert = ca.child_request().validate().map_err(
                KrillError::rfc8183
            )?;
            let child_req = api::admin::AddChildRequest {
                handle: import.handle.convert(),
                resources: import_parent.resources,
                id_cert,
            };

            krill.ca_manager().ca_add_child(
                &import_parent.handle.convert(),
                child_req,
                actor,
                krill,
            )?
        };

        // Add the parent to the child and force sync
        {
            let parent_req = api::admin::ParentCaReq {
                handle: import_parent.handle.clone(),
                response
            };
            krill.ca_manager().ca_parent_add_or_update(
                import.handle.clone(),
                parent_req,
                actor,
                krill,
            )?;

            // First sync will inform child of its entitlements and
            // trigger that CSR is created.
            krill.ca_manager().ca_sync_parent(
                &import.handle, 0, &import_parent.handle, actor, krill,
            )?;

            // Second sync will send that CSR to the parent
            krill.ca_manager().ca_sync_parent(
                &import.handle, 0, &import_parent.handle, actor, krill,
            )?;

            // If the parent is a TA, then we will need to push a bit
            // more.. Normally this should be handled by
            // triggered tasks, but the task scheduler is
            // not running when we do this at startup.
            if import_parent.handle.as_str() == TA_NAME {
                krill.ca_manager().sync_ta_proxy_signer_if_possible(
                    krill
                )?;
                krill.ca_manager().ca_sync_parent(
                    &import.handle, 0, &import_parent.handle, actor,
                    krill,
                )?;
            }
        }
    }

    // Add ROA definitions
    let roa_updates = api::roa::RoaConfigurationUpdates {
        added: import.roas,
        removed: vec![]
    };
    krill.ca_manager().ca_routes_update(
        import.handle, roa_updates, actor, krill
    )?;

    Ok(())
}


//------------ RunError ------------------------------------------------------

/// An error happened when running an operation.
//
//  This is a separate type in preparation for refactoring error handling. For
//  now, it just wraps a `KrillError`.
#[derive(Debug)]
pub struct RunError(KrillError);

impl RunError {
    pub fn status(&self) -> StatusCode {
        self.0.status()
    }

    pub fn to_error_response(&self) -> ErrorResponse {
        self.0.to_error_response()
    }

    pub fn to_rfc8181_error_code(&self) -> publication::ReportErrorCode {
        self.0.to_rfc8181_error_code()
    }
}

impl From<KrillError> for RunError {
    fn from(src: KrillError) -> Self {
        Self(src)
    }
}

impl From<RunError> for KrillError {
    fn from(src: RunError) -> Self {
        src.0
    }
}

impl From<tokio::task::JoinError> for RunError {
    fn from(_: tokio::task::JoinError) -> Self {
        Self(KrillError::internal("task panicked"))
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for RunError { }

