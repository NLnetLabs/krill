//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use clokwerk::{self, ScheduleHandle, TimeUnits};
use tokio::{runtime::Runtime, time::sleep};

use rpki::repository::x509::Time;

use crate::{
    commons::{
        actor::Actor,
        api::{Handle, ParentHandle, Timestamp},
        bgp::BgpAnalyser,
        KrillResult,
    },
    constants::{
        test_mode_enabled, SCHEDULER_INTERVAL_RENEW_MINS, SCHEDULER_INTERVAL_REPUBLISH_MINS,
        SCHEDULER_REQUEUE_DELAY_SECONDS, SCHEDULER_USE_JITTER_CAS_PARENTS_THRESHOLD,
        SCHEDULER_USE_JITTER_CAS_THRESHOLD,
    },
    daemon::{
        ca::CaManager,
        config::Config,
        mq::{MessageQueue, QueueTask},
    },
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::common::session::LoginSessionCache;

pub struct Scheduler {
    mq: Arc<MessageQueue>,
    ca_manager: Arc<CaManager>,
    bgp_analyser: Arc<BgpAnalyser>,
    #[cfg(feature = "multi-user")]
    login_session_cache: Arc<LoginSessionCache>,
    config: Arc<Config>,
    system_actor: Actor,
    started: Timestamp,
    // #[cfg(feature = "multi-user")]
    // /// Responsible for purging expired cached login tokens
    // #[allow(dead_code)] // just need to keep this in scope
    // login_cache_sweeper_sh: ScheduleHandle,
}

impl Scheduler {
    pub fn build(
        mq: Arc<MessageQueue>,
        ca_manager: Arc<CaManager>,
        bgp_analyser: Arc<BgpAnalyser>,
        #[cfg(feature = "multi-user")] login_session_cache: Arc<LoginSessionCache>,
        config: Arc<Config>,
        system_actor: Actor,
    ) -> Self {
        // let cas_objects_renew = make_cas_objects_renew(ca_manager.clone(), actor.clone());

        // #[cfg(feature = "multi-user")]
        // let login_cache_sweeper_sh = make_login_cache_sweeper_sh(login_session_cache);

        Scheduler {
            mq,
            ca_manager,
            bgp_analyser,
            #[cfg(feature = "multi-user")]
            login_session_cache,
            config,
            system_actor,
            started: Timestamp::now(),
        }
    }

    /// Run the schedular in the background. It will sweep the message queue for tasks
    /// and re-schedule new tasks as needed.
    pub async fn run(&self) -> KrillResult<()> {
        loop {
            while let Some(evt) = self.mq.pop(Time::now()) {
                match evt {
                    QueueTask::ServerStarted => self.queue_start_tasks().await?, // return error and stop server on failure

                    QueueTask::SyncRepo { ca } => self.try_sync_repo(ca).await,

                    QueueTask::SyncParent { ca, parent } => self.try_sync_parent(ca, parent).await,

                    QueueTask::CheckSuspendChildren { ca } => self.suspend_children(ca).await,

                    QueueTask::RepublishIfNeeded => self.republish_if_needed().await?,

                    QueueTask::RenewObjectsIfNeeded => self.renew_objects_if_needed().await?,

                    QueueTask::AnnouncementInfoRefresh => self.announcements_refresh().await,

                    QueueTask::ResourceClassRemoved {
                        ca,
                        parent,
                        rcn,
                        revocation_requests,
                    } => {
                        info!(
                            "Trigger send revoke requests for removed RC for '{}' under '{}'",
                            ca, parent
                        );

                        let mut requests = HashMap::new();
                        requests.insert(rcn, revocation_requests);

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
                    }
                    QueueTask::UnexpectedKey {
                        ca,
                        rcn,
                        revocation_request,
                    } => {
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
                    }
                }
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Queues tasks for background jobs when the server is started
    async fn queue_start_tasks(&self) -> KrillResult<()> {
        // If there are only a few CAs in this krill instance, then we
        // will just want to re-sync them with their parents and repository
        // on start up.
        //
        // If there are many, then will apply some random delays (jitter)
        // to avoid a thundering herd. Note that the operator can always
        // choose to run bulk operations manually if they know that they
        // cannot wait.
        let ca_list = self.ca_manager.ca_list(&self.system_actor)?;
        let cas = ca_list.cas();

        let mut use_jitter = cas.len() >= SCHEDULER_USE_JITTER_CAS_THRESHOLD;

        for summary in cas {
            let ca = self.ca_manager.get_ca(summary.handle()).await?;

            use_jitter = use_jitter || ca.nr_parents() >= self.config.ca_refresh_parents_batch_size;

            // Plan a regular sync for each parent. Spread these out if there
            // are too many CAs or parents for a CA. In cases where there are only
            // a handful of CAs/parents, this 'ca_refresh_start_up' will be 'now'.
            // Note: users can override using the 'bulk' functions.
            for parent in ca.parents() {
                self.mq.schedule_sync_parent_at(
                    ca.handle().clone(),
                    parent.clone(),
                    self.config.ca_refresh_start_up(use_jitter),
                );
            }

            // Plan a sync with the repo. In case we only have a handful of CAs
            // then the result is that the sync is scheduled asap. Otherwise
            // spread the load.
            // Note: if circumstances dictate a sync before it's planned, e.g.
            // because ROAs are changed, then it will be rescheduled accordingly.
            // Note: users can override using the 'bulk' functions.
            self.mq
                .schedule_sync_repo_at(ca.handle().clone(), self.config.ca_refresh_start_up(use_jitter));

            // If suspension is enabled then plan a task for it. Since this is
            // a cheap no-op in most cases, we do not need jitter. If we do not
            // add this task then it will not be executed (obviously), but more
            // importantly.. by adding this task we ensure that it will keep being
            // re-scheduled when it's done.
            if self.config.suspend_child_after_inactive_seconds().is_some() {
                self.mq
                    .schedule_check_suspend_children_at(ca.handle().clone(), Time::now())
            }

            self.mq.schedule_republish_if_needed_at(Time::now());

            self.mq.schedule_announcements_info_refresh_at(Time::now());
        }

        Ok(())
    }

    async fn try_sync_repo(&self, ca: Handle) {
        debug!("Synchronize CA {} with repository", ca);

        if let Err(e) = self.ca_manager.cas_repo_sync_single(&ca).await {
            let next = self.config.requeue_remote_failed();

            error!(
                "Failed to publish for '{}'. Will reschedule to: '{}'. Error: {}",
                ca,
                next.to_rfc3339(),
                e
            );

            self.mq.schedule_sync_repo_at(ca, next);
        }
    }

    /// Try to synchronize a CA with a specific parent, reschedule if this fails
    async fn try_sync_parent(&self, ca: Handle, parent: ParentHandle) {
        info!("Synchronize CA '{}' with its parent '{}'", ca, parent);
        if let Err(e) = self.ca_manager.ca_sync_parent(&ca, &parent, &self.system_actor).await {
            let next = self.config.requeue_remote_failed();

            error!(
                "Failed to synchronize CA '{}' with its parent '{}'. Will reschedule to: '{}'. Error: {}",
                ca,
                parent,
                next.to_rfc3339(),
                e
            );
            self.mq.schedule_sync_parent_at(ca, parent, next);
        } else {
            let next = self.config.ca_refresh_next();
            self.mq.schedule_sync_parent_at(ca, parent, next);
        }
    }

    /// Try to suspend children for a CA
    async fn suspend_children(&self, ca_handle: Handle) {
        debug!("Verify if CA '{}' has children that need to be suspended", ca_handle);
        self.ca_manager
            .ca_suspend_inactive_children(&ca_handle, self.started, &self.system_actor)
            .await;

        self.mq
            .schedule_check_suspend_children_at(ca_handle, Time::now() + chrono::Duration::hours(1));
    }

    /// Let CAs that need it republish their CRL/MFT
    async fn republish_if_needed(&self) -> KrillResult<()> {
        let cas = self.ca_manager.republish_all().await?; // can only fail on critical errors

        for ca in cas {
            info!("Re-issued MFT and CRL for CA: {}", ca);
            self.mq.schedule_sync_repo(ca);
        }

        // check again in a short while.. no jitter needed as this is a cheap operation
        // which is often a no-op.
        self.mq.schedule_republish_if_needed_at(
            Time::now() + chrono::Duration::minutes(SCHEDULER_INTERVAL_REPUBLISH_MINS),
        );

        Ok(())
    }

    /// Update announcement info
    async fn announcements_refresh(&self) {
        if let Err(e) = self.bgp_analyser.update().await {
            error!("Failed to update BGP announcements: {}", e)
        }

        // check again in 10 minutes, note.. this is a no-op in case the actual update was less
        // then 1 hour ago. See BGP_RIS_REFRESH_MINUTES constant.
        self.mq
            .schedule_announcements_info_refresh_at(Time::now() + chrono::Duration::minutes(10))
    }

    /// Let CAs that need it re-issue signed objects
    async fn renew_objects_if_needed(&self) -> KrillResult<()> {
        self.ca_manager.renew_objects_all(&self.system_actor).await?; // only fails on fatal errors

        // check again in a short while.. note that this is usually a cheap no-op
        self.mq
            .schedule_renew_if_needed_at(Time::now() + chrono::Duration::minutes(SCHEDULER_INTERVAL_RENEW_MINS));

        Ok(())
    }
}

// #[allow(clippy::cognitive_complexity)]
// fn make_cas_event_triggers(event_queue: Arc<MessageQueue>, ca_manager: Arc<CaManager>, actor: Actor) -> ScheduleHandle {
//     let started = Timestamp::now();

//     SkippingScheduler::run(1, "scan for queued triggers", move || {
//         let rt = Runtime::new().unwrap();

//         rt.block_on(async {
//             while let Some(evt) = event_queue.pop(Time::now()) {
//                 match evt {
//                     QueueTask::ServerStarted => {
//                         info!("Will re-sync all CAs with their parents and repository after startup");
//                         ca_manager.cas_refresh_all(started, &actor).await;
//                         ca_manager.cas_repo_sync_all(&actor).await;
//                     }

//                     QueueTask::SyncRepo { ca } => try_sync_repo(&event_queue, ca_manager.clone(), ca).await,

//                     QueueTask::SyncParent { ca, parent } => {
//                         try_sync_parent(&event_queue, &ca_manager, ca, parent, &actor).await
//                     }

//                     QueueTask::ResourceClassRemoved {
//                         ca,
//                         parent,
//                         rcn,
//                         revocation_requests,
//                     } => {
//                         info!(
//                             "Trigger send revoke requests for removed RC for '{}' under '{}'",
//                             ca, parent
//                         );

//                         let mut requests = HashMap::new();
//                         requests.insert(rcn, revocation_requests);

//                         if ca_manager
//                             .send_revoke_requests(&ca, &parent, requests)
//                             .await
//                             .is_err()
//                         {
//                             warn!(
//                                 "Could not revoke key for removed resource class. This is not \
//                             an issue, because typically the parent will revoke our keys pro-actively, \
//                             just before removing the resource class entitlements."
//                             );
//                         }
//                     }
//                     QueueTask::UnexpectedKey {
//                         ca,
//                         rcn,
//                         revocation_request,
//                     } => {
//                         info!(
//                             "Trigger sending revocation requests for unexpected key with id '{}' in RC '{}'",
//                             revocation_request.key(),
//                             rcn
//                         );
//                         if let Err(e) = ca_manager
//                             .send_revoke_unexpected_key(&ca, rcn, revocation_request)
//                             .await
//                         {
//                             error!("Could not revoke unexpected surplus key at parent: {}", e);
//                         }
//                     }
//                 }
//             }
//         });
//     })
// }

// fn make_cas_objects_renew(ca_server: Arc<CaManager>, actor: Actor) -> ScheduleHandle {
//     SkippingScheduler::run(SCHEDULER_INTERVAL_SECONDS_ROA_RENEW, "CA ROA renewal", move || {
//         let rt = Runtime::new().unwrap();
//         rt.block_on(async {
//             debug!(
//                 "Triggering background renewal for about to expire objects issued by all CAs, note this may be a no-op"
//             );
//             if let Err(e) = ca_server.renew_objects_all(&actor).await {
//                 error!("Background re-issuing of about to expire objects failed: {}", e);
//             }
//         })
//     })
// }

// #[cfg(feature = "multi-user")]
// fn make_login_cache_sweeper_sh(cache: Arc<LoginSessionCache>) -> ScheduleHandle {
//     SkippingScheduler::run(60, "sweep session decryption cache", move || {
//         let rt = Runtime::new().unwrap();
//         rt.block_on(async {
//             if let Err(e) = cache.sweep() {
//                 error!("Background sweep of session decryption cache failed: {}", e);
//             }
//         })
//     })
// }

// struct SkippingScheduler;

// impl SkippingScheduler {
//     fn run<F>(seconds: u32, name: &'static str, f: F) -> ScheduleHandle
//     where
//         F: FnMut() + Clone + Send + 'static,
//     {
//         let lock = RunLock::new();

//         let mut scheduler = clokwerk::Scheduler::new();
//         scheduler.every(seconds.seconds()).run(move || {
//             if lock.is_running() {
//                 warn!(
//                     "Previous background job '{}' is still running, will skip and try again in {} seconds",
//                     name, seconds
//                 )
//             } else {
//                 lock.run();
//                 let mut f = f.clone();
//                 f();
//                 lock.done();
//             }
//         });

//         scheduler.watch_thread(Duration::from_millis(100))
//     }
// }

// struct RunLock {
//     state: RwLock<RunState>,
// }

// impl RunLock {
//     fn new() -> Self {
//         RunLock {
//             state: RwLock::new(RunState(false)),
//         }
//     }

//     fn run(&self) {
//         self.state.write().unwrap().run();
//     }

//     fn done(&self) {
//         self.state.write().unwrap().done();
//     }

//     fn is_running(&self) -> bool {
//         self.state.read().unwrap().is_running()
//     }
// }

// struct RunState(bool);

// impl RunState {
//     fn run(&mut self) {
//         self.0 = true;
//     }

//     fn done(&mut self) {
//         self.0 = false;
//     }

//     fn is_running(&self) -> bool {
//         self.0
//     }
// }

// mod tests {

//     #[test]
//     #[ignore = "takes too long, use for testing during development"]
//     fn test_skip_scheduler() {
//         use super::*;

//         struct Counter(u32);

//         impl Counter {
//             fn inc(&mut self) {
//                 self.0 += 1;
//             }

//             fn total(&self) -> u32 {
//                 self.0
//             }
//         }

//         let counter: Arc<RwLock<Counter>> = Arc::new(RwLock::new(Counter(0)));

//         let counter_sh = counter.clone();

//         let _schedule_handle = SkippingScheduler::run(1, "CA certificate refresh", move || {
//             let rt = Runtime::new().unwrap();
//             rt.block_on(async {
//                 counter_sh.write().unwrap().inc();
//                 tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//             });
//         });

//         std::thread::sleep(std::time::Duration::from_secs(11));

//         let total = counter.read().unwrap().total();

//         assert_eq!(total, 5);
//     }
// }
