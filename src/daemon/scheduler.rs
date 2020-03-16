//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::sync::Arc;
use std::time::Duration;

use clokwerk::{self, ScheduleHandle, TimeUnits};
use tokio::runtime::Runtime;

use crate::commons::util::softsigner::OpenSslSigner;
use crate::daemon::ca::CaServer;
use crate::daemon::mq::{EventQueueListener, QueueEvent};
use crate::pubd::PubServer;
use crate::publish::CaPublisher;

pub struct Scheduler {
    /// Responsible for listening to events and executing triggered processes, such
    /// as publication of newly generated RPKI objects.
    #[allow(dead_code)] // just need to keep this in scope
    event_sh: ScheduleHandle,

    /// Responsible for periodically republishing so that MFTs and CRLs do not go stale.
    #[allow(dead_code)] // just need to keep this in scope
    republish_sh: ScheduleHandle,

    /// Responsible for letting CA check with their parents whether their resource
    /// entitlements have changed *and* for the shrinking of issued certificates, if
    /// they are not renewed within the configured grace period.
    #[allow(dead_code)] // just need to keep this in scope
    ca_refresh_sh: ScheduleHandle,
}

impl Scheduler {
    pub fn build(
        event_queue: Arc<EventQueueListener>,
        caserver: Arc<CaServer<OpenSslSigner>>,
        pubserver: Option<Arc<PubServer>>,
        ca_refresh_rate: u32,
    ) -> Self {
        let event_sh = make_event_sh(event_queue, caserver.clone(), pubserver);
        let republish_sh = make_republish_sh(caserver.clone());
        let ca_refresh_sh = make_ca_refresh_sh(caserver, ca_refresh_rate);

        Scheduler {
            event_sh,
            republish_sh,
            ca_refresh_sh,
        }
    }
}

fn make_event_sh(
    event_queue: Arc<EventQueueListener>,
    caserver: Arc<CaServer<OpenSslSigner>>,
    pubserver: Option<Arc<PubServer>>,
) -> ScheduleHandle {
    let mut scheduler = clokwerk::Scheduler::new();
    scheduler.every(1.seconds()).run(move || {
        while let Some(evt) = event_queue.pop() {
            let mut rt = Runtime::new().unwrap();
            match evt {
                QueueEvent::Delta(handle, version) => {
                    rt.block_on(async {
                        info!("Trigger publication for '{}' version '{}'", handle, version);
                        let publisher = CaPublisher::new(caserver.clone(), pubserver.clone());

                        if let Err(e) = publisher.publish(&handle).await {
                            error!("Failed to publish for CA: {}, error: {}", handle, e);
                        }
                    })
                }
                QueueEvent::ResourceClassRemoved(handle, _, parent, revocations) => {
                    rt.block_on(async {
                        info!(
                            "Trigger send revoke requests for removed RC for '{}' under '{}'",
                            handle,
                            parent
                        );
                        if caserver
                            .send_revoke_requests(&handle, &parent, revocations).await
                            .is_err()
                        {
                            warn!("Could not revoke key for removed resource class. This is not \
                            an issue, because typically the parent will revoke our keys pro-actively, \
                            just before removing the resource class entitlements.");
                        }
                    })
                }
                QueueEvent::UnexpectedKey(handle, _, rcn, revocation) => {
                    rt.block_on(async {
                        info!(
                            "Trigger sending revocation requests for unexpected key with id '{}' in RC '{}'",
                            revocation.key(),
                            rcn
                        );
                        if let Err(e) = caserver
                            .send_revoke_unexpected_key(&handle, rcn, revocation).await {
                            error!("Could not revoke unexpected surplus key at parent: {}", e);
                        }
                    })
                }
                QueueEvent::ParentAdded(handle, _, parent) => {
                    rt.block_on(async {
                        info!(
                            "Get updates for '{}' from added parent '{}'.",
                            handle,
                            parent
                        );
                        if let Err(e) = caserver.get_updates_from_parent(&handle, &parent).await {
                            error!(
                                "Error getting updates for '{}', from parent '{}',  error: '{}'",
                                &handle, &parent, e
                            )
                        }
                    })
                }
                QueueEvent::RepositoryConfigured(ca, _) => {
                    rt.block_on(async {
                        info!("Repository configured for '{}'", ca);
                        if let Err(e) = caserver.get_delayed_updates(&ca).await {
                            error!(
                                "Error getting updates after configuring repository for '{}',  error: '{}'",
                                &ca, e
                            )
                        }
                    })
                }

                QueueEvent::RequestsPending(handle, _) => {
                    rt.block_on(async {
                        info!("Get updates for pending requests for '{}'.", handle);
                        if let Err(e) = caserver.send_all_requests(&handle).await {
                            error!(
                                "Failed to send pending requests for '{}', error '{}'",
                                &handle, e
                            );
                        }
                    })
                }
                QueueEvent::CleanOldRepo(handle, _) => {
                    rt.block_on(async {
                        let publisher = CaPublisher::new(caserver.clone(), pubserver.clone());
                        if let Err(e) = publisher.clean_up(&handle).await {
                            info!(
                                "Could not clean up old repo for '{}', it may be that it's no longer available. Got error '{}'",
                                &handle, e
                            );
                        }
                        if let Err(e) = caserver.remove_old_repo(&handle) {
                            error!(
                                "Failed to remove old repo from ca '{}', error '{}'",
                                &handle, e
                            );
                        }
                    })
                }
            }
        }
    });
    scheduler.watch_thread(Duration::from_millis(100))
}

fn make_republish_sh(caserver: Arc<CaServer<OpenSslSigner>>) -> ScheduleHandle {
    let mut scheduler = clokwerk::Scheduler::new();
    scheduler.every(1.hours()).run(move || {
        info!("Triggering background republication for all CAs");
        if let Err(e) = caserver.republish_all() {
            error!("Background republishing failed: {}", e);
        }
    });
    scheduler.watch_thread(Duration::from_millis(100))
}

fn make_ca_refresh_sh(caserver: Arc<CaServer<OpenSslSigner>>, refresh_rate: u32) -> ScheduleHandle {
    let mut scheduler = clokwerk::Scheduler::new();
    scheduler.every(refresh_rate.seconds()).run(move || {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            info!("Triggering background refresh for all CAs");
            caserver.refresh_all().await
        })
    });
    scheduler.watch_thread(Duration::from_millis(100))
}
