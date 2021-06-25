//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::sync::{Arc, RwLock};
use std::time::Duration;

use clokwerk::{self, ScheduleHandle, TimeUnits};
use tokio::runtime::Runtime;

use rpki::repository::x509::Time;

use crate::{
    commons::{
        actor::Actor,
        api::{Handle, ParentHandle},
        bgp::BgpAnalyser,
    },
    constants::{
        test_mode_enabled, REQUEUE_DELAY_SECONDS, SCHEDULER_INTERVAL_SECONDS_REPUBLISH,
        SCHEDULER_INTERVAL_SECONDS_ROA_RENEW,
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
    /// Responsible for listening to events and executing triggered processes, such
    /// as publication of newly generated RPKI objects.
    #[allow(dead_code)] // just need to keep this in scope
    cas_event_triggers: ScheduleHandle,

    /// Responsible for periodically republishing so that MFTs and CRLs do not go stale.
    #[allow(dead_code)] // just need to keep this in scope
    cas_republish: ScheduleHandle,

    /// Responsible for periodically reissuing ROAs before they would expire.
    #[allow(dead_code)] // just need to keep this in scope
    cas_roas_renew: ScheduleHandle,

    /// Responsible for letting CA check with their parents whether their resource
    /// entitlements have changed *and* for the shrinking of issued certificates, if
    /// they are not renewed within the configured grace period.
    #[allow(dead_code)] // just need to keep this in scope
    cas_refresh: ScheduleHandle,

    /// Responsible for refreshing announcement information
    #[allow(dead_code)] // just need to keep this in scope
    announcements_refresh: ScheduleHandle,

    #[cfg(feature = "multi-user")]
    /// Responsible for purging expired cached login tokens
    #[allow(dead_code)] // just need to keep this in scope
    login_cache_sweeper_sh: ScheduleHandle,
}

impl Scheduler {
    pub fn build(
        event_queue: Arc<MessageQueue>,
        ca_manager: Arc<CaManager>,
        bgp_analyser: Arc<BgpAnalyser>,
        #[cfg(feature = "multi-user")] login_session_cache: Arc<LoginSessionCache>,
        config: &Config,
        actor: &Actor,
    ) -> Self {
        let cas_event_triggers = make_cas_event_triggers(event_queue.clone(), ca_manager.clone(), actor.clone());

        let cas_republish = make_cas_republish(ca_manager.clone(), event_queue);
        let cas_roas_renew = make_cas_roa_renew(ca_manager.clone(), actor.clone());
        let cas_refresh = make_cas_refresh(ca_manager, config.ca_refresh, actor.clone());

        let announcements_refresh = make_announcements_refresh(bgp_analyser);

        #[cfg(feature = "multi-user")]
        let login_cache_sweeper_sh = make_login_cache_sweeper_sh(login_session_cache);

        Scheduler {
            cas_event_triggers,
            cas_republish,
            cas_roas_renew,
            cas_refresh,
            announcements_refresh,
            #[cfg(feature = "multi-user")]
            login_cache_sweeper_sh,
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn make_cas_event_triggers(event_queue: Arc<MessageQueue>, ca_manager: Arc<CaManager>, actor: Actor) -> ScheduleHandle {
    SkippingScheduler::run(1, "scan for queued triggers", move || {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            for evt in event_queue.pop_all() {
                match evt {
                    QueueTask::ServerStarted => {
                        info!("Will re-sync all CAs with their parents and repository after startup");
                        ca_manager.cas_refresh_all(&actor).await;
                        ca_manager.cas_repo_sync_all(&actor).await;
                    }

                    QueueTask::SyncRepo { ca } => try_sync_repo(&event_queue, ca_manager.clone(), ca).await,
                    QueueTask::RescheduleSyncRepo { ca, due } => {
                        if Time::now() > due {
                            try_sync_repo(&event_queue, ca_manager.clone(), ca).await
                        } else {
                            event_queue.reschedule_sync_repo(ca, due);
                        }
                    }
                    QueueTask::SyncParent { ca, parent } => {
                        try_sync_parent(&event_queue, &ca_manager, ca, parent, &actor).await
                    }
                    QueueTask::RescheduleSyncParent { ca, parent, due } => {
                        if Time::now() > due {
                            try_sync_parent(&event_queue, &ca_manager, ca, parent, &actor).await
                        } else {
                            event_queue.reschedule_sync_parent(ca, parent, due);
                        }
                    }

                    QueueTask::ResourceClassRemoved {
                        ca,
                        parent,
                        revocation_requests,
                    } => {
                        info!(
                            "Trigger send revoke requests for removed RC for '{}' under '{}'",
                            ca, parent
                        );

                        if ca_manager
                            .send_revoke_requests(&ca, &parent, revocation_requests)
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
                        if let Err(e) = ca_manager
                            .send_revoke_unexpected_key(&ca, rcn, revocation_request)
                            .await
                        {
                            error!("Could not revoke unexpected surplus key at parent: {}", e);
                        }
                    }
                }
            }
        });
    })
}

fn requeue_time() -> Time {
    Time::now() + chrono::Duration::seconds(REQUEUE_DELAY_SECONDS)
}

fn requeue_time_test() -> Time {
    Time::now() + chrono::Duration::seconds(5)
}

async fn try_sync_repo(event_queue: &Arc<MessageQueue>, ca_manager: Arc<CaManager>, ca: Handle) {
    debug!("Synchronize CA {} with repository", ca);

    if let Err(e) = ca_manager.ca_repo_sync_all(&ca).await {
        let requeue_time = if test_mode_enabled() {
            requeue_time_test()
        } else {
            requeue_time()
        };

        error!("Failed to publish for '{}' will reschedule, error: {}", ca, e);
        event_queue.reschedule_sync_repo(ca, requeue_time);
    }
}

/// Try to synchronize a CA with its parents, reschedule if this fails
async fn try_sync_parent(
    event_queue: &Arc<MessageQueue>,
    ca_manager: &CaManager,
    ca: Handle,
    parent: ParentHandle,
    actor: &Actor,
) {
    info!("Synchronize CA '{}' with its parent '{}'", ca, parent);
    if let Err(e) = ca_manager.ca_sync_parent(&ca, &parent, actor).await {
        let requeue_time = if test_mode_enabled() {
            requeue_time_test()
        } else {
            requeue_time()
        };

        error!(
            "Failed to synchronize CA '{}' with its parent '{}', error: {}",
            ca, parent, e
        );
        event_queue.reschedule_sync_parent(ca, parent, requeue_time);
    }
}

fn make_cas_republish(ca_server: Arc<CaManager>, event_queue: Arc<MessageQueue>) -> ScheduleHandle {
    SkippingScheduler::run(
        SCHEDULER_INTERVAL_SECONDS_REPUBLISH,
        "CA certificate republish",
        move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                debug!("Triggering background republication for all CAs, note this may be a no-op");
                match ca_server.republish_all().await {
                    Err(e) => error!("Background republishing of MFT and CRLs failed: {}", e),
                    Ok(cas) => {
                        for ca in cas {
                            info!("Re-issued MFT and CRL for CA: {}", ca);
                            event_queue.schedule_sync_repo(ca);
                        }
                    }
                }
            })
        },
    )
}

fn make_cas_roa_renew(ca_server: Arc<CaManager>, actor: Actor) -> ScheduleHandle {
    SkippingScheduler::run(SCHEDULER_INTERVAL_SECONDS_ROA_RENEW, "CA ROA renewal", move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            debug!(
                "Triggering background renewal for about to expire ROAs issued by all CAs, note this may be a no-op"
            );
            if let Err(e) = ca_server.renew_roas_all(&actor).await {
                error!("Background re-issuing of about to expire ROAs failed: {}", e);
            }
        })
    })
}

fn make_cas_refresh(ca_server: Arc<CaManager>, refresh_rate: u32, actor: Actor) -> ScheduleHandle {
    SkippingScheduler::run(refresh_rate, "CA certificate refresh", move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            debug!("Triggering background refresh for all CAs");
            ca_server.cas_refresh_all(&actor).await;
        });
    })
}

fn make_announcements_refresh(bgp_analyser: Arc<BgpAnalyser>) -> ScheduleHandle {
    SkippingScheduler::run(5, "update RIS BGP info", move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = bgp_analyser.update().await {
                error!("Failed to update BGP announcements: {}", e)
            }
        })
    })
}

#[cfg(feature = "multi-user")]
fn make_login_cache_sweeper_sh(cache: Arc<LoginSessionCache>) -> ScheduleHandle {
    SkippingScheduler::run(60, "sweep session decryption cache", move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = cache.sweep() {
                error!("Background sweep of session decryption cache failed: {}", e);
            }
        })
    })
}

struct SkippingScheduler;

impl SkippingScheduler {
    fn run<F>(seconds: u32, name: &'static str, f: F) -> ScheduleHandle
    where
        F: FnMut() + Clone + Send + 'static,
    {
        let lock = RunLock::new();

        let mut scheduler = clokwerk::Scheduler::new();
        scheduler.every(seconds.seconds()).run(move || {
            if lock.is_running() {
                warn!(
                    "Previous background job '{}' is still running, will skip and try again in {} seconds",
                    name, seconds
                )
            } else {
                lock.run();
                let mut f = f.clone();
                f();
                lock.done();
            }
        });

        scheduler.watch_thread(Duration::from_millis(100))
    }
}

struct RunLock {
    state: RwLock<RunState>,
}

impl RunLock {
    fn new() -> Self {
        RunLock {
            state: RwLock::new(RunState(false)),
        }
    }

    fn run(&self) {
        self.state.write().unwrap().run();
    }

    fn done(&self) {
        self.state.write().unwrap().done();
    }

    fn is_running(&self) -> bool {
        self.state.read().unwrap().is_running()
    }
}

struct RunState(bool);

impl RunState {
    fn run(&mut self) {
        self.0 = true;
    }

    fn done(&mut self) {
        self.0 = false;
    }

    fn is_running(&self) -> bool {
        self.0
    }
}

mod tests {

    #[test]
    #[ignore = "takes too long, use for testing during development"]
    fn test_skip_scheduler() {
        use super::*;

        struct Counter(u32);

        impl Counter {
            fn inc(&mut self) {
                self.0 += 1;
            }

            fn total(&self) -> u32 {
                self.0
            }
        }

        let counter: Arc<RwLock<Counter>> = Arc::new(RwLock::new(Counter(0)));

        let counter_sh = counter.clone();

        let _schedule_handle = SkippingScheduler::run(1, "CA certificate refresh", move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                counter_sh.write().unwrap().inc();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
        });

        std::thread::sleep(std::time::Duration::from_secs(11));

        let total = counter.read().unwrap().total();

        assert_eq!(total, 5);
    }
}
