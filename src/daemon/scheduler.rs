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
        mq::{in_hours, in_minutes, now, Task, TaskQueue},
        properties::Properties,
    },
    pubd::{RepositoryAccess, RepositoryContent, RepositoryManager},
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::common::session::LoginSessionCache;

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
            while let Some(evt) = self.tasks.pop(now()) {
                if let Err(e) = match evt {
                    Task::QueueStartTasks => self.queue_start_tasks().await, // return error and stop server on failure

                    Task::SyncRepo { ca } => self.sync_repo(ca).await,

                    Task::SyncParent { ca, parent } => self.sync_parent(ca, parent).await,

                    Task::SyncTrustAnchorProxySignerIfPossible => self.sync_ta_proxy_signer_if_possible().await,

                    Task::SuspendChildrenIfNeeded { ca } => self.suspend_children_if_needed(ca).await,

                    Task::RepublishIfNeeded => self.republish_if_needed().await,

                    Task::RenewObjectsIfNeeded => self.renew_objects_if_needed().await,

                    Task::RefreshAnnouncementsInfo => self.announcements_refresh().await,

                    #[cfg(feature = "multi-user")]
                    Task::SweepLoginCache => self.sweep_login_cache(),

                    Task::UpdateSnapshots => self.update_snapshots(),

                    Task::RrdpUpdateIfNeeded => self.update_rrdp_if_needed(),

                    Task::ResourceClassRemoved {
                        ca,
                        parent,
                        rcn,
                        revocation_requests,
                    } => self.resource_class_removed(ca, parent, rcn, revocation_requests).await,

                    Task::UnexpectedKey {
                        ca,
                        rcn,
                        revocation_request,
                    } => self.unexpected_key(ca, rcn, revocation_request).await,
                } {
                    error!("Fatal error in scheduler: {}", e);
                    return;
                }
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Queues tasks for background jobs when the server is started
    async fn queue_start_tasks(&self) -> KrillResult<()> {
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

        debug!("Adding tasks at start up");

        let too_many_cas_resync_parent = cas.len() >= SCHEDULER_USE_JITTER_CAS_THRESHOLD;
        let too_many_cas_resync_repo = cas.len() >= SCHEDULER_RESYNC_REPO_CAS_THRESHOLD;

        for summary in cas {
            let ca = self.ca_manager.get_ca(summary.handle()).await?;

            let too_many_parents = ca.nr_parents() >= self.config.ca_refresh_parents_batch_size;

            // Plan a regular sync for each parent. Spread these out if there
            // are too many CAs or parents for a CA. In cases where there are only
            // a handful of CAs/parents, this 'ca_refresh_start_up' will be 'now'.
            //
            // Note: users can change the priority to 'now' by using the 'bulk' functions.
            let use_parent_sync_jitter = too_many_cas_resync_parent || too_many_parents;

            debug!(
                "Adding tasks for CA {}, using jitter: {}",
                ca.handle(),
                use_parent_sync_jitter
            );

            if !too_many_cas_resync_parent && too_many_parents {
                debug!(
                    "Will force jitter for sync between CA {} and parents. Nr of parents ({}) exceeds batch size ({})",
                    ca.handle(),
                    ca.nr_parents(),
                    self.config.ca_refresh_parents_batch_size
                )
            }

            for parent in ca.parents() {
                self.tasks.sync_parent(
                    ca.handle().clone(),
                    parent.clone(),
                    self.config.ca_refresh_start_up(use_parent_sync_jitter),
                );
            }

            // Plan a sync with the repo. But only in case we only have a handful
            // of CAs.
            //
            // Note: if circumstances dictate a sync e.g. because ROAs are changed,
            // then it will be scheduled accordingly. Furthermore, users can use the
            // 'bulk' function to explicitly force schedule a sync.
            if !too_many_cas_resync_repo {
                self.tasks.sync_repo(ca.handle().clone(), now());
            }

            // If suspension is enabled then plan a task for it. Since this is
            // a cheap no-op in most cases, we do not need jitter. If we do not
            // add this task then it will not be executed (obviously), but more
            // importantly.. by adding this task we ensure that it will keep being
            // re-scheduled when it's done.
            if self.config.suspend_child_after_inactive_seconds().is_some() {
                self.tasks.suspend_children(ca.handle().clone(), now())
            }
        }

        self.tasks.republish_if_needed(now());
        self.tasks.renew_if_needed(now());
        self.tasks.refresh_announcements_info(now());

        #[cfg(feature = "multi-user")]
        self.tasks.sweep_login_cache(in_minutes(1));

        // Plan updating snapshots soon after a restart.
        // This also ensures that this task gets triggered in long
        // running tests, such as functional_parent_child.rs.
        self.tasks.update_snapshots(now());

        Ok(())
    }

    async fn sync_repo(&self, ca: CaHandle) -> KrillResult<()> {
        debug!("Synchronize CA {} with repository", ca);

        if let Err(e) = self
            .ca_manager
            .cas_repo_sync_single(self.repo_manager.as_ref(), &ca)
            .await
        {
            let next = self.config.requeue_remote_failed();

            error!(
                "Failed to publish for '{}'. Will reschedule to: '{}'. Error: {}",
                ca, next, e
            );

            self.tasks.sync_repo(ca, next);
        }

        Ok(())
    }

    /// Try to synchronize a CA with a specific parent, reschedule if this fails
    async fn sync_parent(&self, ca: CaHandle, parent: ParentHandle) -> KrillResult<()> {
        if self.ca_manager.has_ca(&ca)? {
            info!("Synchronize CA '{}' with its parent '{}'", ca, parent);
            if let Err(e) = self.ca_manager.ca_sync_parent(&ca, &parent, &self.system_actor).await {
                let next = self.config.requeue_remote_failed();

                error!(
                    "Failed to synchronize CA '{}' with its parent '{}'. Will reschedule to: '{}'. Error: {}",
                    ca, parent, next, e
                );
                self.tasks.sync_parent(ca, parent, next);
            } else {
                let next = self.config.ca_refresh_next();
                self.tasks.sync_parent(ca, parent, next);
            }

            Ok(())
        } else {
            // Note: if one day we can have a notification extension to RFC 6492 then we will
            //       also be able to alert remote children.
            debug!(
                "Skipping parent sync fo CA '{}'. It is either a remote child, or a local CA that has been removed",
                ca
            );
            Ok(())
        }
    }

    /// Try to synchronise the Trust Anchor Proxy with the *local* Signer - if it exists
    /// in this server.
    async fn sync_ta_proxy_signer_if_possible(&self) -> KrillResult<()> {
        debug!("Synchronise Trust Anchor Proxy with Signer - if Signer is local.");
        if let Err(e) = self.ca_manager.sync_ta_proxy_signer_if_possible().await {
            error!("There was an issue synchronising the TA Proxy and Signer: {}", e);
        }
        Ok(())
    }

    /// Try to suspend children for a CA
    async fn suspend_children_if_needed(&self, ca_handle: CaHandle) -> KrillResult<()> {
        debug!("Verify if CA '{}' has children that need to be suspended", ca_handle);
        self.ca_manager
            .ca_suspend_inactive_children(&ca_handle, self.started, &self.system_actor)
            .await;

        self.tasks.suspend_children(ca_handle, in_hours(1));

        Ok(())
    }

    /// Let CAs that need it republish their CRL/MFT
    async fn republish_if_needed(&self) -> KrillResult<()> {
        let cas = self.ca_manager.republish_all(false).await?; // can only fail on critical errors

        for ca in cas {
            info!("Re-issued MFT and CRL for CA: {}", ca);
            self.tasks.sync_repo(ca, now());
        }

        // check again in a short while.. no jitter needed as this is a cheap operation
        // which is often a no-op.
        self.tasks
            .republish_if_needed(in_minutes(SCHEDULER_INTERVAL_REPUBLISH_MINS));

        Ok(())
    }

    /// Update announcement info
    async fn announcements_refresh(&self) -> KrillResult<()> {
        if let Err(e) = self.bgp_analyser.update().await {
            error!("Failed to update BGP announcements: {}", e)
        }

        // check again in 10 minutes, note.. this is a no-op in case the actual update was less
        // then 1 hour ago. See BGP_RIS_REFRESH_MINUTES constant.
        self.tasks.refresh_announcements_info(in_minutes(10));

        Ok(())
    }

    /// Let CAs that need it re-issue signed objects
    async fn renew_objects_if_needed(&self) -> KrillResult<()> {
        self.ca_manager.renew_objects_all(&self.system_actor).await?; // only fails on fatal errors

        // check again in a short while.. note that this is usually a cheap no-op
        self.tasks.renew_if_needed(in_minutes(SCHEDULER_INTERVAL_RENEW_MINS));

        Ok(())
    }

    #[cfg(feature = "multi-user")]
    fn sweep_login_cache(&self) -> KrillResult<()> {
        if let Err(e) = self.login_session_cache.sweep() {
            error!("Background sweep of session decryption cache failed: {}", e);
        }

        self.tasks.sweep_login_cache(in_minutes(1));

        Ok(())
    }

    // Call update_snapshots on all AggregateStores and WalStores
    fn update_snapshots(&self) -> KrillResult<()> {
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

        self.tasks.update_snapshots(in_hours(24));

        Ok(())
    }

    fn update_rrdp_if_needed(&self) -> KrillResult<()> {
        match self.repo_manager.update_rrdp_if_needed() {
            Err(e) => {
                error!("Could not update RRDP deltas! Error: {}", e);
                // Should we panic in this case? For now, just keep trying, this may
                // be an issue that gets resolved (permission? disk space?)
                self.tasks.update_rrdp_if_needed(in_hours(1));
            }
            Ok(None) => {
                // update was done, or there were no staged changes
            }
            Ok(Some(later_time)) => {
                // Update was NOT done. There are staged changes, but the rrdp update
                // interval has not yet passed. It can be done at later_time.
                self.tasks.update_rrdp_if_needed(later_time.into());
            }
        }

        Ok(())
    }

    async fn resource_class_removed(
        &self,
        ca: CaHandle,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    ) -> KrillResult<()> {
        info!(
            "Trigger send revoke requests for removed RC for '{}' under '{}'",
            ca, parent
        );

        let requests = HashMap::from([(rcn, revocation_requests)]);

        if self
            .ca_manager
            .send_revoke_requests(&ca, &parent, requests)
            .await
            .is_err()
        {
            warn!(
                "Could not revoke key for removed resource class. This is not \
                            an issue, because typically the parent will revoke our keys pro-actively, \
                            just before removing the resource class entitlements."
            );
        }

        Ok(())
    }

    async fn unexpected_key(
        &self,
        ca: CaHandle,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    ) -> KrillResult<()> {
        info!(
            "Trigger sending revocation requests for unexpected key with id '{}' in RC '{}'",
            revocation_request.key(),
            rcn
        );
        if let Err(e) = self
            .ca_manager
            .send_revoke_unexpected_key(&ca, rcn, revocation_request)
            .await
        {
            error!("Could not revoke unexpected surplus key at parent: {}", e);
        }

        Ok(())
    }
}
