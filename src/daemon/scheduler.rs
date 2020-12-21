//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::sync::{Arc, RwLock};
use std::time::Duration;

use clokwerk::{self, ScheduleHandle, TimeUnits};
use tokio::runtime::Runtime;

use rpki::x509::Time;

use crate::commons::bgp::BgpAnalyser;
use crate::commons::{actor::Actor, api::Handle};
use crate::constants::test_mode_enabled;
#[cfg(feature = "multi-user")]
use crate::daemon::auth::common::session::LoginSessionCache;
use crate::daemon::ca::CaServer;
use crate::daemon::config::Config;
use crate::daemon::mq::{EventQueueListener, QueueEvent};
use crate::pubd::PubServer;
use crate::publish::CaPublisher;

pub struct Scheduler {
    /// Responsible for listening to events and executing triggered processes, such
    /// as publication of newly generated RPKI objects.
    #[allow(dead_code)] // just need to keep this in scope
    cas_event_triggers: Option<ScheduleHandle>,

    /// Responsible for periodically republishing so that MFTs and CRLs do not go stale.
    #[allow(dead_code)] // just need to keep this in scope
    cas_republish: Option<ScheduleHandle>,

    /// Responsible for letting CA check with their parents whether their resource
    /// entitlements have changed *and* for the shrinking of issued certificates, if
    /// they are not renewed within the configured grace period.
    #[allow(dead_code)] // just need to keep this in scope
    cas_refresh: Option<ScheduleHandle>,

    /// Responsible for refreshing announcement information
    #[allow(dead_code)] // just need to keep this in scope
    announcements_refresh: ScheduleHandle,

    /// Responsible for archiving old commands
    #[allow(dead_code)] // just need to keep this in scope
    archive_old_commands: ScheduleHandle,

    #[cfg(feature = "multi-user")]
    /// Responsible for purging expired cached login tokens
    #[allow(dead_code)] // just need to keep this in scope
    login_cache_sweeper_sh: ScheduleHandle,
}

impl Scheduler {
    pub fn build(
        event_queue: Arc<EventQueueListener>,
        caserver: Option<Arc<CaServer>>,
        pubserver: Option<Arc<PubServer>>,
        bgp_analyser: Arc<BgpAnalyser>,
        #[cfg(feature = "multi-user")] login_session_cache: Arc<LoginSessionCache>,
        config: &Config,
        actor: &Actor,
    ) -> Self {
        let mut cas_event_triggers = None;
        let mut cas_republish = None;
        let mut cas_refresh = None;

        if let Some(caserver) = caserver.as_ref() {
            cas_event_triggers = Some(make_cas_event_triggers(
                event_queue,
                caserver.clone(),
                pubserver.clone(),
                actor.clone(),
            ));

            cas_republish = Some(make_cas_republish(caserver.clone(), actor.clone()));
            cas_refresh = Some(make_cas_refresh(caserver.clone(), config.ca_refresh, actor.clone()));
        }

        let announcements_refresh = make_announcements_refresh(bgp_analyser);
        let archive_old_commands =
            make_archive_old_commands(caserver, pubserver, config.archive_threshold_days, actor.clone());
        #[cfg(feature = "multi-user")]
        let login_cache_sweeper_sh = make_login_cache_sweeper_sh(login_session_cache);

        Scheduler {
            cas_event_triggers,
            cas_republish,
            cas_refresh,
            announcements_refresh,
            archive_old_commands,
            #[cfg(feature = "multi-user")]
            login_cache_sweeper_sh,
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn make_cas_event_triggers(
    event_queue: Arc<EventQueueListener>,
    caserver: Arc<CaServer>,
    pubserver: Option<Arc<PubServer>>,
    actor: Actor,
) -> ScheduleHandle {
    SkippingScheduler::run(1, "scan for queued triggers", move || {
        let mut rt = Runtime::new().unwrap();

        rt.block_on( async {
            for evt in event_queue.pop_all() {
                match evt {
                    QueueEvent::ServerStarted => {
                        info!("Will re-sync all CAs with their parents and repository after startup");
                        caserver.cas_resync_all(&actor).await;
                        let publisher = CaPublisher::new(caserver.clone(), pubserver.clone());
                        match caserver.ca_list(&actor) {
                            Err(e) => error!("Unable to obtain CA list: {}", e),
                            Ok(list) => {
                                for ca in list.cas() {
                                    if publisher.publish(ca.handle(), &actor).await.is_err() {
                                        error!("Unable to synchronise CA '{}' with its repository after startup", ca.handle());
                                    } else {
                                        info!("CA '{}' is in sync with its repository", ca.handle());
                                    }
                                }
                            }
                        }
                    }

                    QueueEvent::Delta(handle, _version) => {
                        try_publish(&event_queue, caserver.clone(), pubserver.clone(), handle, &actor).await
                    }
                    QueueEvent::ReschedulePublish(handle, last_try) => {
                        if Time::five_minutes_ago().timestamp() > last_try.timestamp() {
                            try_publish(&event_queue, caserver.clone(), pubserver.clone(), handle, &actor).await
                        } else {
                            event_queue.push_back(QueueEvent::ReschedulePublish(handle, last_try));
                        }
                    }
                    QueueEvent::ResourceClassRemoved(handle, _, parent, revocations) => {
                        info!("Trigger send revoke requests for removed RC for '{}' under '{}'",handle,parent);

                        if caserver.send_revoke_requests(&handle, &parent, revocations, &actor).await.is_err() {
                            warn!("Could not revoke key for removed resource class. This is not \
                            an issue, because typically the parent will revoke our keys pro-actively, \
                            just before removing the resource class entitlements.");
                        }
                    }
                    QueueEvent::UnexpectedKey(handle, _, rcn, revocation) => {
                            info!(
                                "Trigger sending revocation requests for unexpected key with id '{}' in RC '{}'",
                                revocation.key(),
                                rcn
                            );
                            if let Err(e) = caserver
                                .send_revoke_unexpected_key(&handle, rcn, revocation, &actor).await {
                                error!("Could not revoke unexpected surplus key at parent: {}", e);
                            }
                    }
                    QueueEvent::ParentAdded(handle, _, parent) => {
                            info!(
                                "Get updates for '{}' from added parent '{}'.",
                                handle,
                                parent
                            );
                            if let Err(e) = caserver.get_updates_from_parent(&handle, &parent, &actor).await {
                                error!(
                                    "Error getting updates for '{}', from parent '{}',  error: '{}'",
                                    &handle, &parent, e
                                )
                            }
                    }
                    QueueEvent::RepositoryConfigured(ca, _) => {
                            info!("Repository configured for '{}'", ca);
                            if let Err(e) = caserver.get_delayed_updates(&ca, &actor).await {
                                error!(
                                    "Error getting updates after configuring repository for '{}',  error: '{}'",
                                    &ca, e
                                )
                            }
                    }

                    QueueEvent::RequestsPending(handle, _) => {
                            info!("Get updates for pending requests for '{}'.", handle);
                            if let Err(e) = caserver.send_all_requests(&handle, &actor).await {
                                error!(
                                    "Failed to send pending requests for '{}', error '{}'",
                                    &handle, e
                                );
                            }
                    }
                    QueueEvent::CleanOldRepo(handle, _) => {
                            let publisher = CaPublisher::new(caserver.clone(), pubserver.clone());
                            if let Err(e) = publisher.clean_up(&handle, &actor).await {
                                info!(
                                    "Could not clean up old repo for '{}', it may be that it's no longer available. Got error '{}'",
                                    &handle, e
                                );
                            }
                            if let Err(e) = caserver.remove_old_repo(&handle, &actor).await {
                                error!(
                                    "Failed to remove old repo from ca '{}', error '{}'",
                                    &handle, e
                                );
                            }
                    }
                }
            }
        });
    })
}

async fn try_publish(
    event_queue: &Arc<EventQueueListener>,
    caserver: Arc<CaServer>,
    pubserver: Option<Arc<PubServer>>,
    ca: Handle,
    actor: &Actor,
) {
    info!("Try to publish for '{}'", ca);
    let publisher = CaPublisher::new(caserver.clone(), pubserver);

    if let Err(e) = publisher.publish(&ca, actor).await {
        if test_mode_enabled() {
            error!("Failed to publish for '{}', error: {}", ca, e);
        } else {
            error!("Failed to publish for '{}' will reschedule, error: {}", ca, e);
            event_queue.push_back(QueueEvent::ReschedulePublish(ca, Time::now()));
        }
    }
}

fn make_cas_republish(caserver: Arc<CaServer>, actor: Actor) -> ScheduleHandle {
    SkippingScheduler::run(120, "CA certificate republish", move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            info!("Triggering background republication for all CAs");
            if let Err(e) = caserver.republish_all(&actor).await {
                error!("Background republishing failed: {}", e);
            };
        })
    })
}

fn make_cas_refresh(caserver: Arc<CaServer>, refresh_rate: u32, actor: Actor) -> ScheduleHandle {
    SkippingScheduler::run(refresh_rate, "CA certificate refresh", move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            info!("Triggering background refresh for all CAs");
            caserver.cas_resync_all(&actor).await;
        });
    })
}

fn make_announcements_refresh(bgp_analyser: Arc<BgpAnalyser>) -> ScheduleHandle {
    SkippingScheduler::run(5, "update RIS BGP info", move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = bgp_analyser.update().await {
                error!("Failed to update BGP announcements: {}", e)
            }
        })
    })
}

fn make_archive_old_commands(
    caserver: Option<Arc<CaServer>>,
    pubserver: Option<Arc<PubServer>>,
    archive_threshold_days: Option<i64>,
    actor: Actor,
) -> ScheduleHandle {
    SkippingScheduler::run(3600, "archive old commands", move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            if let Some(days) = archive_threshold_days {
                if let Some(caserver) = caserver.as_ref() {
                    if let Err(e) = caserver.archive_old_commands(days, &actor).await {
                        error!("Failed to archive old CA commands: {}", e)
                    }
                }

                if let Some(pubserver) = pubserver.as_ref() {
                    if let Err(e) = pubserver.archive_old_commands(days) {
                        error!("Failed to archive old Publication Server commands: {}", e)
                    }
                }
            }
        })
    })
}

#[cfg(feature = "multi-user")]
fn make_login_cache_sweeper_sh(cache: Arc<LoginSessionCache>) -> ScheduleHandle {
    SkippingScheduler::run(3600, "sweep logins", move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            debug!("Triggering background sweep of session decryption cache");

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
                    "Previous background job '{}' is still runing, will skip and try again in {} seconds",
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
            let mut rt = Runtime::new().unwrap();
            rt.block_on(async {
                counter_sh.write().unwrap().inc();
                tokio::time::delay_for(std::time::Duration::from_secs(2)).await;
            });
        });

        std::thread::sleep(std::time::Duration::from_secs(11));

        let total = counter.read().unwrap().total();

        assert_eq!(total, 5);
    }
}
