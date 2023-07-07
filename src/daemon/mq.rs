//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::{fmt, sync::RwLock};

use priority_queue::PriorityQueue;

use rpki::{
    ca::{
        idexchange::{CaHandle, ParentHandle},
        provisioning::{ResourceClassName, RevocationRequest},
    },
    repository::x509::Time,
};

use crate::{
    commons::{api::Timestamp, eventsourcing},
    daemon::{
        ca::{CertAuth, CertAuthEvent},
        ta::{ta_handle, TrustAnchorProxy, TrustAnchorProxyEvent},
    },
};

//------------ Task ---------------------------------------------------------

/// This type contains tasks with the details needed for triggered processing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Task {
    QueueStartTasks,

    SyncRepo {
        ca: CaHandle,
    },

    SyncParent {
        ca: CaHandle,
        parent: ParentHandle,
    },

    SyncTrustAnchorProxySignerIfPossible,

    SuspendChildrenIfNeeded {
        ca: CaHandle,
    },

    RepublishIfNeeded,
    RenewObjectsIfNeeded,

    RefreshAnnouncementsInfo,

    UpdateSnapshots,

    RrdpUpdateIfNeeded,

    #[cfg(feature = "multi-user")]
    SweepLoginCache,

    ResourceClassRemoved {
        ca: CaHandle,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    },
    UnexpectedKey {
        ca: CaHandle,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    },
}

impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Task::QueueStartTasks => write!(f, "Server just started"),
            Task::SyncRepo { ca } => write!(f, "synchronize repo for '{}'", ca),
            Task::SyncParent { ca, parent } => write!(f, "synchronize CA '{}' with parent '{}'", ca, parent),
            Task::SyncTrustAnchorProxySignerIfPossible => write!(f, "sync TA Proxy and Signer if both in this server."),
            Task::SuspendChildrenIfNeeded { ca } => write!(f, "verify if CA '{}' has children to suspend", ca),
            Task::RepublishIfNeeded => write!(f, "let CAs republish their mft/crls if needed"),
            Task::RenewObjectsIfNeeded => write!(f, "let CAs renew their signed objects if needed"),
            Task::RefreshAnnouncementsInfo => write!(f, "check for new announcement info"),
            Task::UpdateSnapshots => write!(f, "update repository content snapshot on disk"),
            Task::RrdpUpdateIfNeeded => write!(f, "create new RRDP delta, if needed"),

            #[cfg(feature = "multi-user")]
            Task::SweepLoginCache => write!(f, "sweep up expired logins"),
            Task::ResourceClassRemoved { ca, .. } => {
                write!(f, "resource class removed for '{}' ", ca)
            }
            Task::UnexpectedKey { ca, rcn, .. } => {
                write!(f, "unexpected key found for '{}' resource class: '{}'", ca, rcn)
            }
        }
    }
}

//------------ TaskQueue ----------------------------------------------------

#[derive(Debug)]
pub struct TaskQueue {
    q: RwLock<PriorityQueue<Task, Priority>>,
}

impl Default for TaskQueue {
    fn default() -> Self {
        TaskQueue {
            q: RwLock::new(PriorityQueue::new()),
        }
    }
}

impl TaskQueue {
    pub fn pop(&self, due_before: Priority) -> Option<Task> {
        let mut q = self.q.write().unwrap();

        let has_item = if let Some((task, priority)) = q.peek() {
            let is_due = priority > &due_before;
            if is_due {
                debug!("Getting task with priority '{}': {}", priority, task);
            } else {
                trace!("Leaving task not due until '{}': {}", priority, task);
            }
            is_due
        } else {
            trace!("No pending tasks to pop from queue");
            false
        };

        if has_item {
            q.pop().map(|(item, _)| item)
        } else {
            None
        }
    }

    /// Schedules a task for the given priority. If the equivalent task
    /// was already present, then it will get the highest of the two
    /// priorities.
    ///
    /// Many tasks are planned with a high priority - e.g. if they are
    /// triggered through CA events. Other tasks may be planned for the
    /// future (e.g. sync with parent tomorrow). The latter can be moved
    /// forward when circumstances dictate.
    ///
    /// Recurring tasks will typically be re-added by the Scheduler when
    /// needed (and can then be moved forward if needed).
    fn schedule(&self, task: Task, priority: Priority) {
        let mut q = self.q.write().unwrap();

        let prio_opt = q.get_priority(&task).copied();

        match prio_opt {
            None => {
                debug!("Adding task: {}, with priority: {}", task, priority);
                q.push(task, priority);
            }
            Some(existing_priority) => {
                if existing_priority < priority {
                    debug!(
                        "Re-prioritising task: {} from: {} to: {}",
                        task, existing_priority, priority
                    );
                    q.change_priority(&task, priority);
                } else {
                    debug!("Keeping existing task: {} with higher priority: {}", task, priority);
                }
            }
        }
    }

    /// Drop all tasks for the removed CA
    pub fn remove_tasks_for_ca(&self, removed_ca: &CaHandle) {
        let mut q = self.q.write().unwrap();

        // If the [`PriorityQueue`] would have a `retain` function
        // then we would use that, but since it doesn't we need
        // to do this the slightly hard way..
        //
        // We get and copy all tasks for the removed CA first, and then
        // remove them in a follow-up loop. This is not the most efficient,
        // but.. it's easy to follow and we are very unlikely to have many pending
        // tasks for a removed CA. So, this is unlikely to be an issue.
        let mut tasks_to_remove = vec![];

        // Find matching tasks and clone them
        for (task, _) in q.iter() {
            match task {
                Task::SyncRepo { ca }
                | Task::SyncParent { ca, .. }
                | Task::SuspendChildrenIfNeeded { ca }
                | Task::ResourceClassRemoved { ca, .. }
                | Task::UnexpectedKey { ca, .. } => {
                    if ca == removed_ca {
                        tasks_to_remove.push(task.clone())
                    }
                }

                _ => {} // Not a CA specific task, ignore it and keep it
            }
        }

        // Remove the matched tasks from the queue.
        for task in tasks_to_remove {
            q.remove(&task);
        }
    }

    pub fn server_started(&self) {
        self.schedule(Task::QueueStartTasks, now());
    }

    pub fn sync_repo(&self, ca: CaHandle, priority: Priority) {
        self.schedule(Task::SyncRepo { ca }, priority);
    }

    pub fn sync_parent(&self, ca: CaHandle, parent: ParentHandle, priority: Priority) {
        self.schedule(Task::SyncParent { ca, parent }, priority);
    }

    pub fn sync_ta_proxy_signer_if_possible(&self) {
        self.schedule(Task::SyncTrustAnchorProxySignerIfPossible, now())
    }

    pub fn suspend_children(&self, ca: CaHandle, priority: Priority) {
        self.schedule(Task::SuspendChildrenIfNeeded { ca }, priority);
    }

    pub fn republish_if_needed(&self, priority: Priority) {
        self.schedule(Task::RepublishIfNeeded, priority);
    }

    pub fn renew_if_needed(&self, priority: Priority) {
        self.schedule(Task::RenewObjectsIfNeeded, priority);
    }

    pub fn refresh_announcements_info(&self, priority: Priority) {
        self.schedule(Task::RefreshAnnouncementsInfo, priority);
    }

    pub fn update_snapshots(&self, priority: Priority) {
        self.schedule(Task::UpdateSnapshots, priority)
    }

    pub fn update_rrdp_if_needed(&self, priority: Priority) {
        self.schedule(Task::RrdpUpdateIfNeeded, priority)
    }

    #[cfg(feature = "multi-user")]
    pub fn sweep_login_cache(&self, priority: Priority) {
        self.schedule(Task::SweepLoginCache, priority);
    }

    fn drop_sync_parent(&self, ca: CaHandle, parent: ParentHandle) {
        let mut q = self.q.write().unwrap();
        let sync = Task::SyncParent { ca, parent };
        q.remove(&sync);
    }
}

/// Implement listening for CertAuth events.
impl eventsourcing::PostSaveEventListener<CertAuth> for TaskQueue {
    fn listen(&self, ca: &CertAuth, events: &[CertAuthEvent]) {
        let handle = ca.handle();

        for event in events {
            trace!("Seen event for CA {}: '{}'", handle, event);

            match event {
                CertAuthEvent::RoasUpdated { .. }
                | CertAuthEvent::AspaObjectsUpdated { .. }
                | CertAuthEvent::ChildCertificatesUpdated { .. }
                | CertAuthEvent::BgpSecCertificatesUpdated { .. }
                | CertAuthEvent::ChildKeyRevoked { .. }
                | CertAuthEvent::KeyPendingToNew { .. }
                | CertAuthEvent::KeyPendingToActive { .. }
                | CertAuthEvent::KeyRollFinished { .. } => self.sync_repo(handle.clone(), now()),

                CertAuthEvent::KeyRollActivated {
                    resource_class_name, ..
                } => {
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        self.sync_parent(handle.clone(), parent.clone(), now());
                    }
                    self.sync_repo(handle.clone(), now());
                }

                CertAuthEvent::ParentRemoved { parent } => {
                    self.drop_sync_parent(handle.clone(), parent.clone());
                    self.sync_repo(handle.clone(), now());
                }

                CertAuthEvent::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_requests,
                } => {
                    self.sync_repo(handle.clone(), now());

                    self.schedule(
                        Task::ResourceClassRemoved {
                            ca: handle.clone(),
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
                        ca: handle.clone(),
                        rcn: resource_class_name.clone(),
                        revocation_request: revoke_req.clone(),
                    },
                    now(),
                ),

                CertAuthEvent::ParentAdded { parent, .. } => {
                    if ca.repository_contact().is_ok() {
                        debug!("Parent {} added to CA {}, scheduling sync", parent, handle);
                        self.sync_parent(handle.clone(), parent.clone(), now());
                    } else {
                        // Postpone parent sync. I.e. it will be triggered below when the event
                        // for updating the repository is seen.
                        warn!(
                            "Synchronisation of CA '{}' with parent '{}' postponed until repository is configured.",
                            handle, parent
                        );
                    }
                }
                CertAuthEvent::RepoUpdated { .. } => {
                    for parent in ca.parents() {
                        self.sync_parent(handle.clone(), parent.clone(), now());
                    }
                }
                CertAuthEvent::CertificateRequested {
                    resource_class_name, ..
                } => {
                    debug!("CA {} requested certificate for RC {}", handle, resource_class_name);
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        debug!("CA {} will schedule sync for parent {}", handle, parent);
                        self.sync_parent(handle.clone(), parent.clone(), now());
                    }
                }
                CertAuthEvent::ChildUpdatedResources { child, .. } => {
                    debug!("Schedule a sync from the child to this CA as their parent. This will be a no-op for remote children.");
                    self.sync_parent(child.convert(), handle.convert(), now());
                }

                _ => {}
            }
        }
    }
}

/// Implement listening for TrustAnchorProxy events.
impl eventsourcing::PostSaveEventListener<TrustAnchorProxy> for TaskQueue {
    fn listen(&self, _proxy: &TrustAnchorProxy, events: &[TrustAnchorProxyEvent]) {
        for event in events {
            trace!("Seen TrustAnchorProxy event '{}'", event);
            match event {
                TrustAnchorProxyEvent::ChildRequestAdded(_child, _request) => {
                    // schedule proxy -> signer sync
                    self.sync_ta_proxy_signer_if_possible();
                }
                TrustAnchorProxyEvent::SignerResponseReceived(response) => {
                    // schedule publication for the TA
                    self.sync_repo(ta_handle(), now());
                    // Schedule child->ta sync(s) now that there is a response.
                    for ca in response.content().child_responses.keys() {
                        debug!("Received signed response for TA child {}", ca);
                        self.sync_parent(ca.convert(), ta_handle().into_converted(), now());
                    }
                }
                TrustAnchorProxyEvent::RepositoryAdded(_)
                | TrustAnchorProxyEvent::SignerAdded(_)
                | TrustAnchorProxyEvent::SignerRequestMade(_)
                | TrustAnchorProxyEvent::ChildAdded(_)
                | TrustAnchorProxyEvent::ChildResponseGiven(_, _) => {
                    // No triggered actions needed
                }
            }
        }
    }
}

//------------ Priority ------------------------------------------------------

/// Can be used as a priority value for [`PriorityQueue`]. Meaning that the
/// time value which is soonest has the highest priority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Priority(i64);

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

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.0.cmp(&self.0) // is reverse cmp of inner 0
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.0.partial_cmp(&self.0) // is reverse cmp of inner 0
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Timestamp::from(self).to_rfc3339().fmt(f)
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
