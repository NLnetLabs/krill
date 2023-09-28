//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::{collections::HashMap, sync::Arc, time::Duration};

use kvx::Namespace;
use tokio::time::sleep;

use rpki::ca::{
    idexchange::{CaHandle, ParentHandle},
    provisioning::{ResourceClassName, RevocationRequest},
};
use url::Url;

use crate::{
    commons::{
        actor::Actor,
        api::Timestamp,
        bgp::BgpAnalyser,
        crypto::dispatch::signerinfo::SignerInfo,
        eventsourcing::{Aggregate, AggregateStore, WalStore, WalSupport},
        KrillResult,
    },
    constants::{
        CASERVER_NS, PROPERTIES_NS, PUBSERVER_CONTENT_NS, PUBSERVER_NS, SCHEDULER_INTERVAL_RENEW_MINS,
        SCHEDULER_INTERVAL_REPUBLISH_MINS, SCHEDULER_RESYNC_REPO_CAS_THRESHOLD, SCHEDULER_USE_JITTER_CAS_THRESHOLD,
        SIGNERS_NS,
    },
    daemon::{
        ca::{CaManager, CertAuth},
        config::Config,
        mq::{in_hours, in_minutes, in_seconds, in_weeks, now, Task, TaskQueue},
        properties::Properties,
    },
    pubd::{RepositoryAccess, RepositoryContent, RepositoryManager},
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::common::session::LoginSessionCache;

use super::mq::TaskResult;

pub struct Scheduler {
    tasks: Arc<TaskQueue>,
    ca_manager: Arc<CaManager>,
    repo_manager: Arc<RepositoryManager>,
    bgp_analyser: Arc<BgpAnalyser>,
    #[cfg(feature = "multi-user")]
    // Responsible for purging expired cached login tokens
    login_session_cache: Arc<LoginSessionCache>,
    config: Arc<Config>,
    system_actor: Actor,
    started: Timestamp,
}

impl Scheduler {
    pub fn build(
        tasks: Arc<TaskQueue>,
        ca_manager: Arc<CaManager>,
        repo_manager: Arc<RepositoryManager>,
        bgp_analyser: Arc<BgpAnalyser>,
        #[cfg(feature = "multi-user")] login_session_cache: Arc<LoginSessionCache>,
        config: Arc<Config>,
        system_actor: Actor,
    ) -> Self {
        Scheduler {
            tasks,
            ca_manager,
            repo_manager,
            bgp_analyser,
            #[cfg(feature = "multi-user")]
            login_session_cache,
            config,
            system_actor,
            started: Timestamp::now(),
        }
    }

    /// Run the scheduler in the background. It will sweep the message queue for tasks
    /// and re-schedule new tasks as needed.
    pub async fn run(&self) {
        loop {
            while let Some(running_task) = self.tasks.pop() {
                // remember the key so we can finish or re-schedule the task.
                let task_key = kvx::Key::from(&running_task);

                match serde_json::from_value(running_task.value) {
                    Err(e) => {
                        // If we cannot parse the value of this task, then we have a major
                        // issue. Essentially, this can only happen if we did a Krill upgrade
                        // to a new version that no longer understands existing tasks.
                        //
                        // So, if we ever change the content of tasks then we should make sure
                        // that Krill is either backward compatible, or the task queue is migrated
                        // on upgrade.
                        error!("Fatal error. Cannot parse task: {}. Error: {}", task_key, e);
                        return; // stops the server.
                    }
                    Ok(task) => {
                        if let Err(e) = match self.process_task(task).await {
                            Ok(result) => match result {
                                TaskResult::Done => self.tasks.finish(&task_key),
                                TaskResult::FollowUp(task, priority) => self.tasks.schedule(task, priority),
                                TaskResult::Reschedule(priority) => self.tasks.reschedule(&task_key, priority),
                            },
                            Err(e) => Err(e),
                        } {
                            // We really should not get any errors at this stage. If we do, then
                            // this is most likely because of an issue with the key value store.
                            // In this case we should probably just log the error and leave the
                            // task to be cleaned up later.
                            error!("Error processing task: {}. Error: {}", task_key, e);
                        }
                    }
                }
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Process a single task
    async fn process_task(&self, task: Task) -> KrillResult<TaskResult> {
        match task {
            Task::QueueStartTasks => self.queue_start_tasks().await, // return error and stop server on failure

            Task::SyncRepo {
                ca_handle: ca,
                ca_version,
            } => self.sync_repo(ca, ca_version).await,

            Task::SyncParent {
                ca_handle: ca,
                ca_version,
                parent,
            } => self.sync_parent(ca, ca_version, parent).await,

            Task::RenewTestbedTa => self.renew_testbed_ta().await,

            Task::SyncTrustAnchorProxySignerIfPossible => self.sync_ta_proxy_signer_if_possible().await,

            Task::SuspendChildrenIfNeeded { ca_handle: ca } => self.suspend_children_if_needed(ca).await,

            Task::RepublishIfNeeded => self.republish_if_needed().await,

            Task::RenewObjectsIfNeeded => self.renew_objects_if_needed().await,

            Task::RefreshAnnouncementsInfo => self.announcements_refresh().await,

            #[cfg(feature = "multi-user")]
            Task::SweepLoginCache => self.sweep_login_cache(),

            Task::UpdateSnapshots => self.update_snapshots(),

            Task::RrdpUpdateIfNeeded => self.update_rrdp_if_needed(),

            Task::ResourceClassRemoved {
                ca_handle: ca,
                ca_version,
                parent,
                rcn,
                revocation_requests,
            } => {
                self.resource_class_removed(ca, ca_version, parent, rcn, revocation_requests)
                    .await
            }

            Task::UnexpectedKey {
                ca_handle: ca,
                ca_version,
                rcn,
                revocation_request,
            } => self.unexpected_key(ca, ca_version, rcn, revocation_request).await,
        }
    }

    /// Queues missing tasks for background jobs when the server is started
    async fn queue_start_tasks(&self) -> KrillResult<TaskResult> {
        // The task queue is persistent starting with Krill 0.14.0
        //
        // Tasks should not disappear. But.. to make sure that:
        // a) krill is self-healing
        // b) this works on the first upgrade to 0.14.0
        //
        // We will add all MISSING tasks that we think will be needed.
        //
        // This works simplest by adding all task with the Existing::KeepOld
        // option of the queue.

        // If there are only a few CAs in this Krill instance, then we
        // will just want to re-sync them with their parents and repository
        // on start up.
        //
        // If there are many, then we apply some random delays (jitter)
        // to avoid a thundering herd. Note that the operator can always
        // choose to run bulk operations manually if they know that they
        // cannot wait.
        let ca_list = self.ca_manager.ca_list(&self.system_actor)?;
        let cas = ca_list.cas();
        debug!("Adding missing tasks at start up");

        // When multi-node set ups with a shared queue are
        // supported then we can no longer safely reschedule
        // ALL running tests. See issue: #1112
        self.tasks.reschedule_tasks_at_startup()?;

        // If we have many CAs then we need to apply some jitter
        // in the priority of CA to parent and CA to repository
        // syncs to avoid generating a thundering herd.

        let use_jitter = cas.len() >= SCHEDULER_USE_JITTER_CAS_THRESHOLD;

        for summary in cas {
            let ca = self.ca_manager.get_ca(summary.handle()).await?;
            let ca_handle = ca.handle();
            let ca_version = ca.version();

            trace!("Adding tasks for CA {}, using jitter: {}", ca.handle(), use_jitter);

            for parent in ca.parents() {
                self.tasks.schedule_missing(
                    Task::SyncParent {
                        ca_handle: ca_handle.clone(),
                        ca_version,
                        parent: parent.clone(),
                    },
                    self.config.ca_refresh_start_up(use_jitter),
                )?;
            }

            // Plan a sync with the repo. But only in case we only have a handful
            // of CAs.
            //
            // Note: if circumstances dictate a sync e.g. because ROAs are changed,
            // then it will be scheduled accordingly. Furthermore, users can use the
            // 'bulk' function to explicitly force schedule a sync.
            if cas.len() <= SCHEDULER_RESYNC_REPO_CAS_THRESHOLD {
                self.tasks.schedule_missing(
                    Task::SyncRepo {
                        ca_handle: ca_handle.clone(),
                        ca_version,
                    },
                    now(),
                )?;
            }

            // If suspension is enabled then plan a task for it. Since this is
            // a cheap no-op in most cases, we do not need jitter. If we do not
            // add this task then it will not be executed (obviously), but more
            // importantly.. by adding this task we ensure that it will keep being
            // re-scheduled when it's done.
            if self.config.suspend_child_after_inactive_seconds().is_some() {
                self.tasks.schedule_missing(
                    Task::SuspendChildrenIfNeeded {
                        ca_handle: ca_handle.clone(),
                    },
                    now(),
                )?;
            }
        }

        self.tasks.schedule_missing(Task::RepublishIfNeeded, now())?;
        self.tasks.schedule_missing(Task::RenewObjectsIfNeeded, now())?;
        self.tasks.schedule_missing(Task::RefreshAnnouncementsInfo, now())?;

        #[cfg(feature = "multi-user")]
        self.tasks.schedule_missing(Task::SweepLoginCache, in_minutes(1))?;

        // Plan updating snapshots soon after a restart.
        // This also ensures that this task gets triggered in long
        // running tests, such as functional_parent_child.rs.
        self.tasks.schedule_missing(Task::UpdateSnapshots, now())?;

        if self.config.testbed().is_some() {
            self.tasks.schedule_missing(Task::RenewTestbedTa, now())?;
        }

        Ok(TaskResult::Done)
    }

    async fn sync_repo(&self, ca: CaHandle, version: u64) -> KrillResult<TaskResult> {
        debug!("Synchronize CA {} with repository", ca);

        match self
            .ca_manager
            .cas_repo_sync_single(self.repo_manager.as_ref(), &ca, version)
            .await
        {
            Err(e) => {
                let next = self.config.requeue_remote_failed();

                error!(
                    "Failed to publish for '{}'. Will reschedule to: '{}'. Error: {}",
                    ca, next, e
                );

                Ok(TaskResult::Reschedule(next))
            }
            Ok(true) => Ok(TaskResult::Done),
            Ok(false) => {
                debug!("sync was premature, reschedule");
                let next = in_seconds(1);
                Ok(TaskResult::Reschedule(next))
            }
        }
    }

    /// Try to synchronize a CA with a specific parent, reschedule if this fails
    async fn sync_parent(&self, ca: CaHandle, ca_version: u64, parent: ParentHandle) -> KrillResult<TaskResult> {
        if self.ca_manager.has_ca(&ca)? {
            info!("Synchronize CA '{}' with its parent '{}'", ca, parent);
            match self
                .ca_manager
                .ca_sync_parent(&ca, ca_version, &parent, &self.system_actor)
                .await
            {
                Err(e) => {
                    let next = self.config.requeue_remote_failed();

                    error!(
                        "Failed to synchronize CA '{}' with its parent '{}'. Will reschedule to: '{}'. Error: {}",
                        ca, parent, next, e
                    );
                    Ok(TaskResult::Reschedule(next))
                }
                Ok(true) => {
                    let next = self.config.ca_refresh_next();
                    Ok(TaskResult::FollowUp(
                        Task::SyncParent {
                            ca_handle: ca,
                            ca_version,
                            parent,
                        },
                        next,
                    ))
                }
                Ok(false) => {
                    debug!("reschedule premature task");
                    let next = in_seconds(1);
                    Ok(TaskResult::Reschedule(next))
                }
            }
        } else {
            // Note: if one day we can have a notification extension to RFC 6492 then we will
            //       also be able to alert remote children.
            debug!(
                "Skipping parent sync fo CA '{}'. It is either a remote child, or a local CA that has been removed",
                ca
            );
            Ok(TaskResult::Done)
        }
    }

    /// Resync the testbed TA signer and proxy
    async fn renew_testbed_ta(&self) -> KrillResult<TaskResult> {
        if let Err(e) = self.ca_manager.ta_renew_testbed_ta().await {
            error!("There was an issue renewing the testbed TA: {}", e);
        }
        let weeks_to_resync = self.config.ta_timing.mft_next_update_weeks / 2;
        Ok(TaskResult::FollowUp(Task::RenewTestbedTa, in_weeks(weeks_to_resync)))
    }

    /// Try to synchronise the Trust Anchor Proxy with the *local* Signer - if it exists
    /// in this server.
    async fn sync_ta_proxy_signer_if_possible(&self) -> KrillResult<TaskResult> {
        debug!("Synchronise Trust Anchor Proxy with Signer - if Signer is local.");
        if let Err(e) = self.ca_manager.sync_ta_proxy_signer_if_possible().await {
            error!("There was an issue synchronising the TA Proxy and Signer: {}", e);
        }
        Ok(TaskResult::Done)
    }

    /// Try to suspend children for a CA
    async fn suspend_children_if_needed(&self, ca_handle: CaHandle) -> KrillResult<TaskResult> {
        debug!("Verify if CA '{}' has children that need to be suspended", ca_handle);
        self.ca_manager
            .ca_suspend_inactive_children(&ca_handle, self.started, &self.system_actor)
            .await;

        Ok(TaskResult::FollowUp(
            Task::SuspendChildrenIfNeeded { ca_handle },
            in_hours(1),
        ))
    }

    /// Let CAs that need it republish their CRL/MFT
    async fn republish_if_needed(&self) -> KrillResult<TaskResult> {
        // Note that CRL/MFT re-issuance is handled by the `CaObjects` companion
        // struct, rather than the event-sourced `CertAuth`. Meaning... that we
        // do not get to see an event in case there is an actual update and
        // therefore we get no triggered task to synchronise with the repository.
        //
        // Instead we get back a list of CAs that had changes, and we need to
        // schedule a synchronisation for each of them here.
        let cas = self.ca_manager.republish_all(false).await?; // can only fail on critical errors

        for ca_handle in cas {
            info!("Re-issued MFT and CRL for CA: {}", ca_handle);

            let ca_version = 0; // we use 0 because we don't need to wait for an updated CertAuth
            self.tasks.schedule(Task::SyncRepo { ca_handle, ca_version }, now())?;
        }

        // check again in a short while.. no jitter needed as this is a cheap operation
        // which is often a no-op.

        Ok(TaskResult::FollowUp(
            Task::RepublishIfNeeded,
            in_minutes(SCHEDULER_INTERVAL_REPUBLISH_MINS),
        ))
    }

    /// Update announcement info
    async fn announcements_refresh(&self) -> KrillResult<TaskResult> {
        if let Err(e) = self.bgp_analyser.update().await {
            error!("Failed to update BGP announcements: {}", e)
        }

        // check again in 10 minutes, note.. this is a no-op in case the actual update was less
        // then 1 hour ago. See BGP_RIS_REFRESH_MINUTES constant.
        Ok(TaskResult::FollowUp(Task::RefreshAnnouncementsInfo, in_minutes(10)))
    }

    /// Let CAs that need it re-issue signed objects
    async fn renew_objects_if_needed(&self) -> KrillResult<TaskResult> {
        self.ca_manager.renew_objects_all(&self.system_actor).await?; // only fails on fatal errors

        // check again in a short while.. note that this is usually a cheap no-op
        Ok(TaskResult::FollowUp(
            Task::RenewObjectsIfNeeded,
            in_minutes(SCHEDULER_INTERVAL_RENEW_MINS),
        ))
    }

    #[cfg(feature = "multi-user")]
    fn sweep_login_cache(&self) -> KrillResult<TaskResult> {
        if let Err(e) = self.login_session_cache.sweep() {
            error!("Background sweep of session decryption cache failed: {}", e);
        }

        Ok(TaskResult::FollowUp(Task::SweepLoginCache, in_minutes(1)))
    }

    // Call update_snapshots on all AggregateStores and WalStores
    fn update_snapshots(&self) -> KrillResult<TaskResult> {
        fn update_aggregate_store_snapshots<A: Aggregate>(storage_uri: &Url, namespace: &Namespace) {
            match AggregateStore::<A>::create(storage_uri, namespace, false) {
                Err(e) => {
                    // Note: this is highly unlikely.. probably something else is broken and Krill
                    //       would have panicked as a result already.
                    error!(
                        "Could not update snapshots for {} will try again in 24 hours. Error: {}",
                        namespace, e
                    );
                }
                Ok(store) => {
                    if let Err(e) = store.update_snapshots() {
                        // Note: this is highly unlikely.. probably something else is broken and Krill
                        //       would have panicked as a result already.
                        error!(
                            "Could not update snapshots for {} will try again in 24 hours. Error: {}",
                            namespace, e
                        );
                    } else {
                        info!("Updated snapshots for {}", namespace);
                    }
                }
            }
        }

        fn update_wal_store_snapshots<W: WalSupport>(storage_uri: &Url, namespace: &Namespace) {
            match WalStore::<W>::create(storage_uri, namespace) {
                Err(e) => {
                    // Note: this is highly unlikely.. probably something else is broken and Krill
                    //       would have panicked as a result already.
                    error!(
                        "Could not update snapshots for {} will try again in 24 hours. Error: {}",
                        namespace, e
                    );
                }
                Ok(store) => {
                    if let Err(e) = store.update_snapshots() {
                        // Note: this is highly unlikely.. probably something else is broken and Krill
                        //       would have panicked as a result already.
                        error!(
                            "Could not update snapshots for {} will try again in 24 hours. Error: {}",
                            namespace, e
                        );
                    }
                }
            }
        }

        update_aggregate_store_snapshots::<CertAuth>(&self.config.storage_uri, CASERVER_NS);
        update_aggregate_store_snapshots::<SignerInfo>(&self.config.storage_uri, SIGNERS_NS);
        update_aggregate_store_snapshots::<Properties>(&self.config.storage_uri, PROPERTIES_NS);
        update_aggregate_store_snapshots::<RepositoryAccess>(&self.config.storage_uri, PUBSERVER_NS);

        update_wal_store_snapshots::<RepositoryContent>(&self.config.storage_uri, PUBSERVER_CONTENT_NS);

        Ok(TaskResult::FollowUp(Task::UpdateSnapshots, in_hours(24)))
    }

    fn update_rrdp_if_needed(&self) -> KrillResult<TaskResult> {
        match self.repo_manager.update_rrdp_if_needed() {
            Err(e) => {
                error!("Could not update RRDP deltas! Error: {}", e);
                // Should we panic in this case? For now, just keep trying, this may
                // be an issue that gets resolved (permission? disk space?)
                Ok(TaskResult::Reschedule(in_hours(1)))
            }
            Ok(None) => {
                // update was done, or there were no staged changes
                Ok(TaskResult::Done)
            }
            Ok(Some(later_time)) => {
                // Update was NOT done. There are staged changes, but the rrdp update
                // interval has not yet passed. It can be done at later_time.
                Ok(TaskResult::Reschedule(later_time.into()))
            }
        }
    }

    async fn resource_class_removed(
        &self,
        ca_handle: CaHandle,
        ca_version: u64,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    ) -> KrillResult<TaskResult> {
        info!(
            "Trigger send revoke requests for removed RC for '{}' under '{}'",
            ca_handle, parent
        );

        let requests = HashMap::from([(rcn, revocation_requests)]);

        if let Ok(ca) = self.ca_manager.get_ca(&ca_handle).await {
            if ca.version() < ca_version {
                // premature, we need to wait for the CA to be committed.
                Ok(TaskResult::Reschedule(in_seconds(1)))
            } else if self
                .ca_manager
                .send_revoke_requests(&ca_handle, &parent, requests)
                .await
                .is_err()
            {
                debug!("Could not revoke key for resource class removed by parent - most likely already revoked.");
                Ok(TaskResult::Done)
            } else {
                debug!("Revoked keys for CA '{}' under parent '{}'", ca_handle, parent);
                Ok(TaskResult::Done)
            }
        } else {
            // Ignoring resource class removed task for removed CA
            Ok(TaskResult::Done)
        }
    }

    async fn unexpected_key(
        &self,
        ca_handle: CaHandle,
        ca_version: u64,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    ) -> KrillResult<TaskResult> {
        info!(
            "Trigger sending revocation requests for unexpected key with id '{}' in RC '{}'",
            revocation_request.key(),
            rcn
        );
        match self.ca_manager.get_ca(&ca_handle).await {
            Err(_e) => {
                // Can't get CA - most likely because it's gone.

                Ok(TaskResult::Done)
            }
            Ok(ca) => {
                if ca.version() < ca_version {
                    debug!("reschedule premature task");
                    let next = in_seconds(100);
                    Ok(TaskResult::Reschedule(next))
                } else {
                    if let Err(e) = self
                        .ca_manager
                        .send_revoke_unexpected_key(&ca_handle, rcn, revocation_request)
                        .await
                    {
                        warn!(
                            "Could not revoke surplus key, most likely already revoked by parent. Error was: {}",
                            e
                        );
                    }

                    Ok(TaskResult::Done)
                }
            }
        }
    }
}
