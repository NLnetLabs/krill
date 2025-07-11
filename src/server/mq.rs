//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::fmt;
use std::str::FromStr;
use log::{debug, error, trace, warn};
use rpki::ca::idexchange::{CaHandle, ParentHandle};
use rpki::ca::provisioning::{ResourceClassName, RevocationRequest};
use rpki::repository::x509::Time;
use serde::{Deserialize, Serialize};
use url::Url;
use crate::api::ca::Timestamp;
use crate::commons::eventsourcing;
use crate::commons::{Error, KrillResult};
use crate::commons::eventsourcing::Aggregate;
use crate::commons::queue::{Queue, RunningTask, ScheduleMode};
use crate::commons::storage::{Key, Segment, SegmentBuf};
use crate::constants::{TASK_QUEUE_NS, ta_handle};
use crate::server::ca::{CertAuth, CertAuthEvent};
use crate::server::taproxy::{TrustAnchorProxy, TrustAnchorProxyEvent};


//------------ Task ---------------------------------------------------------

/// This type contains tasks with the details needed for triggered processing.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Task {
    // Triggers that the task queue is initialised with
    // with all relevant tasks. We use a separate task for
    // this so that this initialisation, which can take time,
    // can be deferred at startup.
    QueueStartTasks,

    // ------------- CA follow-up actions ------------------------

    // The following tasks are for triggered follow-up actions
    // for CAs. They include the CA handle as well as the minimal
    // version of the CA so that they can be rescheduled in case
    // they are picked up too soon (by another thread, before the
    // updated CA is fully committed).

    // Triggers that the CA synchronises its content with the
    // repository.
    SyncRepo {
        ca_handle: CaHandle,
        ca_version: u64,
    },

    SyncParent {
        ca_handle: CaHandle,
        ca_version: u64,
        parent: ParentHandle,
    },

    ResourceClassRemoved {
        ca_handle: CaHandle,
        ca_version: u64,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    },

    UnexpectedKey {
        ca_handle: CaHandle,
        ca_version: u64,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    },

    SyncTrustAnchorProxySignerIfPossible,

    SuspendChildrenIfNeeded {
        ca_handle: CaHandle,
    },

    RenewTestbedTa,

    RepublishIfNeeded,
    RenewObjectsIfNeeded,

    UpdateSnapshots,

    RrdpUpdateIfNeeded,

    // The following tasks are deprecated. They may, however, still be in the
    // task queue and currently the scheduler panics on unknown tasks, so we
    // need to keep it for now and just not do anything.
    SweepLoginCache,
    RefreshAnnouncementsInfo,
}

impl Task {
    fn name(&self) -> KrillResult<SegmentBuf> {
        match self {
            Task::SyncRepo { ca_handle: ca, .. } => {
                SegmentBuf::from_str(&format!("sync_repo_{ca}"))
            }
            Task::SyncParent {
                ca_handle: ca,
                parent,
                ..
            } => SegmentBuf::from_str(&format!(
                "sync_{ca}_with_parent_{parent}"
            )),
            Task::SuspendChildrenIfNeeded { ca_handle: ca } => {
                SegmentBuf::from_str(&format!(
                    "suspend_children_if_needed_{ca}"
                ))
            }
            Task::RepublishIfNeeded => {
                Ok(Segment::make("all_cas_republish_if_needed").to_owned())
            }
            Task::RenewObjectsIfNeeded => {
                Ok(Segment::make("all_cas_renew_objects_if_needed").to_owned())
            }
            Task::ResourceClassRemoved {
                ca_handle: ca,
                parent,
                rcn,
                ..
            } => SegmentBuf::from_str(&format!(
                "resource_class_removed_ca_{ca}_parent_{parent}_rcn_{rcn}"
            )),
            Task::UnexpectedKey {
                ca_handle: ca,
                rcn,
                revocation_request,
                ..
            } => SegmentBuf::from_str(&format!(
                "unexpected_key_{}_ca_{}_rcn_{}",
                revocation_request.key(),
                ca,
                rcn
            )),
            Task::UpdateSnapshots => {
                Ok(Segment::make("update_stored_snapshots").to_owned())
            }
            Task::RrdpUpdateIfNeeded => {
                Ok(Segment::make("update_rrdp_if_needed").to_owned())
            }
            Task::RenewTestbedTa => {
                Ok(Segment::make("renew_testbed_ta").to_owned())
            }
            Task::SyncTrustAnchorProxySignerIfPossible => {
                Ok(Segment::make("sync_ta_proxy_signer").to_owned())
            }
            Task::QueueStartTasks => {
                Ok(Segment::make("queue_start_tasks").to_owned())
            }
            Task::SweepLoginCache => {
                Ok(Segment::make("sweep_login_cache").to_owned())
            }
            Task::RefreshAnnouncementsInfo => {
                Ok(Segment::make("refresh_bgp_announcements_info").to_owned())
            }
        }
        .map_err(|e| Error::Custom(format!("could not create name: {e}")))
    }
}

impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Task::QueueStartTasks => write!(f, "Server just started"),
            Task::SyncRepo { ca_handle: ca, .. } => {
                write!(f, "synchronize repo for '{ca}'")
            }
            Task::SyncParent {
                ca_handle: ca,
                parent,
                ..
            } => {
                write!(f, "synchronize CA '{ca}' with parent '{parent}'")
            }
            Task::RenewTestbedTa => write!(f, "renew testbed TA"),
            Task::SyncTrustAnchorProxySignerIfPossible => {
                write!(f, "sync TA Proxy and Signer if both in this server.")
            }
            Task::SuspendChildrenIfNeeded { ca_handle: ca } => {
                write!(f, "verify if CA '{ca}' has children to suspend")
            }
            Task::RepublishIfNeeded => {
                write!(f, "let CAs republish their mft/crls if needed")
            }
            Task::RenewObjectsIfNeeded => {
                write!(f, "let CAs renew their signed objects if needed")
            }
            Task::UpdateSnapshots => {
                write!(f, "update repository content snapshot on disk")
            }
            Task::RrdpUpdateIfNeeded => {
                write!(f, "create new RRDP delta, if needed")
            }
            Task::ResourceClassRemoved { ca_handle: ca, .. } => {
                write!(f, "resource class removed for '{ca}' ")
            }
            Task::UnexpectedKey {
                ca_handle: ca, rcn, ..
            } => {
                write!(
                    f,
                    "unexpected key found for '{ca}' resource class: '{rcn}'"
                )
            }
            Task::SweepLoginCache => write!(f, "sweep up expired logins"),
            Task::RefreshAnnouncementsInfo => {
                write!(f, "refresh BGP announcements info")
            }
        }
    }
}

pub enum TaskResult {
    Done,                     // finished, nothing more to do
    FollowUp(Task, Priority), // finished, follow-up should be scheduled
    Reschedule(Priority),     // not finished, should be rescheduled
}

//------------ TaskQueue ----------------------------------------------------

#[derive(Debug)]
pub struct TaskQueue {
    q: Queue,
}

impl TaskQueue {
    pub fn new(storage_uri: &Url) -> KrillResult<Self> {
        Ok(TaskQueue {
            q: Queue::create(storage_uri, TASK_QUEUE_NS)?,
        })
    }
}
impl TaskQueue {
    pub fn pop(&self) -> Option<RunningTask> {
        trace!("Try to get a task off the queue");
        match self.q.claim_scheduled_pending_task() {
            Err(e) => {
                // Log error and return nothing.
                // We do this, because the key value store - if in future
                // a database is used - might be temporarily unavailable.
                // In that case we don't want Krill to crash on this, but
                // just keep trying to poll.
                error!("Could not get pending task from queue: {e}");
                None
            }
            Ok(None) => {
                trace!("No pending task found.");
                None
            }
            Ok(Some(pending)) => {
                trace!(
                    "fnd task: {} with priority: {}",
                    pending.name,
                    Priority::from_timestamp_ms(pending.timestamp_millis)
                );
                Some(pending)
            }
        }
    }

    /// Schedules a task for the given priority. If the equivalent task
    /// was already present, then it will get the highest of the two
    /// priorities.
    ///
    /// This will NOT finish any possible running task by the same
    /// name.
    pub fn schedule(
        &self,
        task: Task,
        priority: Priority,
    ) -> KrillResult<()> {
        self.schedule_task(
            task,
            ScheduleMode::ReplaceExistingSoonest,
            priority,
        )
    }

    /// Schedules a task for the given priority. If the equivalent task
    /// was already present, then it will get the highest of the two
    /// priorities.
    pub fn schedule_and_finish_existing(
        &self,
        task: Task,
        priority: Priority,
    ) -> KrillResult<()> {
        self.schedule_task(
            task,
            ScheduleMode::FinishOrReplaceExistingSoonest,
            priority,
        )
    }

    pub fn schedule_missing(
        &self,
        task: Task,
        priority: Priority,
    ) -> KrillResult<()> {
        self.schedule_task(task, ScheduleMode::IfMissing, priority)
    }

    fn schedule_task(
        &self,
        task: Task,
        mode: ScheduleMode,
        priority: Priority,
    ) -> KrillResult<()> {
        let task_name = task.name()?;
        debug!(
            "add task: {task_name} with priority: {priority}",
        );
        let json = serde_json::to_value(&task).map_err(|e| {
            Error::Custom(format!(
                "could not serialize task {task_name}. error: {e}"
            ))
        })?;

        self.q
            .schedule_task(task_name, json, Some(priority.to_millis()), mode)
            .map_err(Error::from)
    }

    /// Finish a running task, without rescheduling it.
    pub fn finish(&self, task: &Key) -> KrillResult<()> {
        debug!("Finish task: {task}");
        self.q.finish_running_task(task).map_err(Error::from)
    }

    /// Reschedule a running task, without finishing it.
    pub fn reschedule(
        &self,
        task: &Key,
        priority: Priority,
    ) -> KrillResult<()> {
        debug!("Reschedule task: {task} to: {priority}");
        self.q
            .reschedule_running_task(task, Some(priority.to_millis()))
            .map_err(Error::from)
    }

    /// Reschedule all running tasks to pending. This assumes that we only
    /// have a single active node. See issue #1112
    pub fn reschedule_tasks_at_startup(&self) -> KrillResult<()> {
        let keys = self.q.running_tasks_keys()?;

        let queue_started_key_name = Task::QueueStartTasks.name()?;

        if keys.len() > 1 {
            warn!("Rescheduling running tasks at startup, note that multi-node Krill servers are not yet supported.");
            for key in keys {
                if key.name() != queue_started_key_name.as_ref() {
                    warn!("  - rescheduling: {}", key.name());
                    self.q.reschedule_running_task(&key, None)?;
                }
            }
        }

        Ok(())
    }
}

/// Implement listening for CertAuth events.
impl TaskQueue {
    fn schedule_for_ca_event(
        &self,
        ca: &CertAuth,
        ca_version: u64,
        event: &CertAuthEvent,
    ) -> KrillResult<()> {
        let ca_handle = ca.handle().clone();

        debug!(
            "Seen event for CA {ca_handle} version {ca_version}: '{event}'"
        );

        match event {
            CertAuthEvent::RoasUpdated { .. }
            | CertAuthEvent::AspaObjectsUpdated { .. }
            | CertAuthEvent::ChildCertificatesUpdated { .. }
            | CertAuthEvent::BgpSecCertificatesUpdated { .. }
            | CertAuthEvent::ChildKeyRevoked { .. }
            | CertAuthEvent::KeyPendingToNew { .. }
            | CertAuthEvent::KeyPendingToActive { .. }
            | CertAuthEvent::KeyRollFinished { .. } => self.schedule(
                Task::SyncRepo {
                    ca_handle,
                    ca_version,
                },
                now(),
            ),

            CertAuthEvent::KeyRollActivated {
                resource_class_name,
                ..
            } => {
                if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                    // ensure that the revocation request for the old
                    // key is sent now.
                    self.schedule(
                        Task::SyncParent {
                            ca_handle: ca_handle.clone(),
                            ca_version,
                            parent: parent.clone(),
                        },
                        now(),
                    )?;
                }
                // update published objects - remove old mft and crl
                self.schedule(
                    Task::SyncRepo {
                        ca_handle,
                        ca_version,
                    },
                    now(),
                )
            }

            CertAuthEvent::ParentRemoved { .. } => self.schedule(
                Task::SyncRepo {
                    ca_handle,
                    ca_version,
                },
                now(),
            ),

            CertAuthEvent::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_requests,
            } => {
                self.schedule(
                    Task::SyncRepo {
                        ca_handle: ca_handle.clone(),
                        ca_version,
                    },
                    now(),
                )?;

                self.schedule(
                    Task::ResourceClassRemoved {
                        ca_handle,
                        ca_version,
                        parent: parent.clone(),
                        rcn: resource_class_name.clone(),
                        revocation_requests: revoke_requests.clone(),
                    },
                    now(),
                )
            }

            CertAuthEvent::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => self.schedule(
                Task::UnexpectedKey {
                    ca_handle: ca_handle.clone(),
                    ca_version,
                    rcn: resource_class_name.clone(),
                    revocation_request: revoke_req.clone(),
                },
                now(),
            ),

            CertAuthEvent::ParentAdded { parent, .. }
            | CertAuthEvent::ParentUpdated { parent, .. } => {
                if ca.repository_contact().is_ok() {
                    debug!(
                        "Parent {parent} added to CA {ca_handle}, scheduling sync"
                    );
                    self.schedule(
                        Task::SyncParent {
                            ca_handle: ca_handle.clone(),
                            ca_version,
                            parent: parent.clone(),
                        },
                        now(),
                    )
                } else {
                    // Postpone parent sync. I.e. it will be triggered below
                    // when the event for updating the
                    // repository is seen.
                    warn!(
                        "Synchronisation of CA '{ca_handle}' with parent '{parent}' postponed until repository is configured."
                    );
                    Ok(())
                }
            }
            CertAuthEvent::RepoUpdated { .. } => {
                for parent in ca.parents() {
                    self.schedule(
                        Task::SyncParent {
                            ca_handle: ca_handle.clone(),
                            ca_version,
                            parent: parent.clone(),
                        },
                        now(),
                    )?;
                }
                Ok(())
            }
            CertAuthEvent::CertificateRequested {
                resource_class_name,
                ..
            } => {
                debug!(
                    "CA {ca_handle} requested certificate for RC {resource_class_name}"
                );
                if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                    debug!(
                        "CA {ca_handle} will schedule sync for parent {parent} when CA is version {ca_version}"
                    );
                    self.schedule(
                        Task::SyncParent {
                            ca_handle: ca_handle.clone(),
                            ca_version,
                            parent: parent.clone(),
                        },
                        now(),
                    )?;
                }
                Ok(())
            }

            _ => Ok(()),
        }
    }
}

/// Implement pre-save listening for CertAuth events.
impl eventsourcing::PreSaveEventListener<CertAuth> for TaskQueue {
    fn listen(
        &self,
        ca: &CertAuth,
        events: &[CertAuthEvent],
    ) -> KrillResult<()> {
        for event in events {
            self.schedule_for_ca_event(ca, ca.version(), event)?;
        }
        Ok(())
    }
}

/// Implement post-save listening for CertAuth events.
///
/// Used for best effort signaling to local child CAs that a sync with
/// their parent is needed.
impl eventsourcing::PostSaveEventListener<CertAuth> for TaskQueue {
    fn listen(&self, ca: &CertAuth, events: &[CertAuthEvent]) {
        for event in events {
            match event {
                CertAuthEvent::ChildUpdatedResources { child, .. }
                | CertAuthEvent::ChildKeyRevoked { child, .. } => {
                    debug!("Schedule a sync from the child to this CA as their parent. This will be a no-op for remote children.");
                    if let Err(e) = self.schedule_and_finish_existing(
                        Task::SyncParent {
                            ca_handle: child.convert(),
                            ca_version: 0, /* no need to wait for updated
                                            * child */
                            parent: ca.handle().convert(),
                        },
                        now(),
                    ) {
                        error!(
                                "Could not schedule sync from {} to {}. Restart Krill or run 'krillc bulk refresh'. Error was: {}",
                                child,
                                ca.handle(),
                                e
                            );
                    }
                }

                _ => {
                    // nothing to do
                }
            }
        }
    }
}

/// Implement pre-save listening for TrustAnchorProxy events.
impl eventsourcing::PreSaveEventListener<TrustAnchorProxy> for TaskQueue {
    fn listen(
        &self,
        proxy: &TrustAnchorProxy,
        events: &[TrustAnchorProxyEvent],
    ) -> KrillResult<()> {
        for event in events {
            trace!("Seen TrustAnchorProxy event '{event}'");
            match event {
                TrustAnchorProxyEvent::ChildRequestAdded(
                    _child,
                    _request,
                ) => {
                    // schedule proxy -> signer sync
                    self.schedule(
                        Task::SyncTrustAnchorProxySignerIfPossible,
                        now(),
                    )?;
                }
                TrustAnchorProxyEvent::SignerResponseReceived(_response) => {
                    // schedule publication for the TA
                    self.schedule(
                        Task::SyncRepo {
                            ca_handle: ta_handle(),
                            ca_version: proxy.version(),
                        },
                        now(),
                    )?;
                }
                TrustAnchorProxyEvent::RepositoryAdded(_)
                | TrustAnchorProxyEvent::SignerAdded(_)
                | TrustAnchorProxyEvent::SignerUpdated(_)
                | TrustAnchorProxyEvent::SignerRequestMade(_)
                | TrustAnchorProxyEvent::ChildAdded(_)
                | TrustAnchorProxyEvent::ChildResponseGiven(_, _) => {
                    // No triggered actions needed
                }
            }
        }
        Ok(())
    }
}

/// Implement post-save listening for TrustAnchorProxy events.
impl eventsourcing::PostSaveEventListener<TrustAnchorProxy> for TaskQueue {
    fn listen(
        &self,
        _proxy: &TrustAnchorProxy,
        events: &[TrustAnchorProxyEvent],
    ) {
        for event in events {
            match event {
                TrustAnchorProxyEvent::SignerResponseReceived(response) => {
                    // Schedule child->ta sync(s) now that there is a
                    // response.
                    for ca in response.content().child_responses.keys() {
                        trace!(
                            "Received signed response for TA child {ca}"
                        );
                        if let Err(e) = self.schedule(
                            Task::SyncParent {
                                ca_handle: ca.convert(),
                                ca_version: 0,
                                parent: ta_handle().into_converted(),
                            },
                            now(),
                        ) {
                            error!(
                                "Could not schedule sync from {} to {}. Restart Krill or run 'krillc bulk refresh'. Error was: {}",
                                ca,
                                ta_handle(),
                                e
                            );
                        }
                    }
                }
                _ => {
                    // No triggered actions needed
                }
            }
        }
    }
}

//------------ Priority ------------------------------------------------------

/// Can be used as a priority value.
///
/// Meaning that the time value which is soonest has the highest priority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Priority(i64);

impl Priority {
    /// Convenience function, but note that we don't
    /// have ms granularity here, so this is rounded
    /// down to seconds.
    pub fn from_timestamp_ms(millis: u128) -> Self {
        Priority((millis / 1000) as i64)
    }

    pub fn to_millis(&self) -> u128 {
        (self.0 * 1000) as u128
    }
}

pub fn now() -> Priority {
    Time::now().into()
}

pub fn in_seconds(secs: i64) -> Priority {
    (Time::now() + chrono::Duration::seconds(secs)).into()
}

pub fn in_minutes(mins: i64) -> Priority {
    (Time::now() + chrono::Duration::minutes(mins)).into()
}

pub fn in_hours(hours: i64) -> Priority {
    (Time::now() + chrono::Duration::hours(hours)).into()
}

pub fn in_days(days: i64) -> Priority {
    (Time::now() + chrono::Duration::days(days)).into()
}

pub fn in_weeks(weeks: i64) -> Priority {
    in_days(7 * weeks)
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.0.cmp(&self.0) // is reverse cmp of inner 0
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Timestamp::from(self).into_rfc3339().fmt(f)
    }
}

impl From<&Priority> for Timestamp {
    fn from(p: &Priority) -> Self {
        Timestamp::new(p.0)
    }
}

impl From<Timestamp> for Priority {
    fn from(ts: Timestamp) -> Self {
        Priority(ts.into())
    }
}

impl From<Time> for Priority {
    fn from(time: Time) -> Self {
        Priority(time.timestamp())
    }
}
