//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::{fmt, sync::RwLock};

use priority_queue::PriorityQueue;
use rpki::repository::x509::Time;

use crate::{
    commons::{
        api::{Handle, ParentHandle, ResourceClassName, RevocationRequest, Timestamp},
        eventsourcing::{self, Event},
    },
    daemon::ca::{CaEvt, CaEvtDet, CertAuth},
};

//------------ QueueTask ----------------------------------------------------

/// This type contains tasks with the details needed for triggered processing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueueTask {
    ServerStarted,

    SyncRepo {
        ca: Handle,
    },

    SyncParent {
        ca: Handle,
        parent: ParentHandle,
    },

    CheckSuspendChildren {
        ca: Handle,
    },

    RepublishIfNeeded,
    RenewObjectsIfNeeded,

    AnnouncementInfoRefresh,

    ResourceClassRemoved {
        ca: Handle,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    },
    UnexpectedKey {
        ca: Handle,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    },
}

impl fmt::Display for QueueTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueueTask::ServerStarted => write!(f, "Server just started"),
            QueueTask::SyncRepo { ca } => write!(f, "synchronize repo for '{}'", ca),
            QueueTask::SyncParent { ca, parent } => write!(f, "synchronize CA '{}' with parent '{}'", ca, parent),
            QueueTask::CheckSuspendChildren { ca } => write!(f, "verify if CA '{}' has children to suspend", ca),
            QueueTask::RepublishIfNeeded => write!(f, "let CAs republish their mft/crls if needed"),
            QueueTask::RenewObjectsIfNeeded => write!(f, "let CAs renew their signed objects if needed"),
            QueueTask::AnnouncementInfoRefresh => write!(f, "check for new announcement info"),
            QueueTask::ResourceClassRemoved { ca, .. } => {
                write!(f, "resource class removed for '{}' ", ca)
            }
            QueueTask::UnexpectedKey { ca, rcn, .. } => {
                write!(f, "unexpected key found for '{}' resource class: '{}'", ca, rcn)
            }
        }
    }
}

#[derive(Debug)]
pub struct MessageQueue {
    q: RwLock<PriorityQueue<QueueTask, Priority>>,
}

impl Default for MessageQueue {
    fn default() -> Self {
        let mut q = PriorityQueue::new();
        q.push(QueueTask::ServerStarted, Priority::now());

        MessageQueue { q: RwLock::new(q) }
    }
}

impl MessageQueue {
    pub fn pop(&self, due_before: Time) -> Option<QueueTask> {
        let mut q = self.q.write().unwrap();

        let has_item = if let Some((_, priority)) = q.peek() {
            priority > &due_before.into()
        } else {
            false
        };

        if has_item {
            q.pop().map(|(item, _)| item)
        } else {
            None
        }
    }

    fn schedule(&self, task: QueueTask) {
        self.schedule_at(task, Time::now())
    }

    fn schedule_at(&self, task: QueueTask, due: Time) {
        let priority = due.into();

        let mut q = self.q.write().unwrap();

        if q.change_priority(&task, priority).is_none() {
            q.push(task, priority);
        }
    }

    /// Schedules that a CA synchronizes with its repositories.
    pub fn schedule_sync_repo(&self, ca: Handle) {
        self.schedule(QueueTask::SyncRepo { ca });
    }

    /// RE-Schedules that a CA synchronizes with its repositories. This function
    /// takes a time argument to indicate *when* the resynchronization should be
    /// attempted.
    pub fn schedule_sync_repo_at(&self, ca: Handle, due: Time) {
        self.schedule_at(QueueTask::SyncRepo { ca }, due);
    }

    pub fn schedule_sync_parent(&self, ca: Handle, parent: ParentHandle) {
        self.schedule(QueueTask::SyncParent { ca, parent });
    }

    pub fn schedule_sync_parent_at(&self, ca: Handle, parent: ParentHandle, due: Time) {
        self.schedule_at(QueueTask::SyncParent { ca, parent }, due);
    }

    pub fn schedule_check_suspend_children_at(&self, ca: Handle, due: Time) {
        self.schedule_at(QueueTask::CheckSuspendChildren { ca }, due);
    }

    pub fn schedule_republish_if_needed_at(&self, due: Time) {
        self.schedule_at(QueueTask::RepublishIfNeeded, due);
    }

    pub fn schedule_renew_if_needed_at(&self, due: Time) {
        self.schedule_at(QueueTask::RenewObjectsIfNeeded, due);
    }

    pub fn schedule_announcements_info_refresh_at(&self, due: Time) {
        self.schedule_at(QueueTask::AnnouncementInfoRefresh, due);
    }

    fn drop_sync_parent(&self, ca: Handle, parent: ParentHandle) {
        let mut q = self.q.write().unwrap();
        let sync = QueueTask::SyncParent { ca, parent };
        q.remove(&sync);
    }
}

/// Implement listening for CertAuth Published events.
impl eventsourcing::PostSaveEventListener<CertAuth> for MessageQueue {
    fn listen(&self, ca: &CertAuth, events: &[CaEvt]) {
        for event in events {
            trace!("Seen CertAuth event '{}'", event);

            let handle = event.handle();

            match event.details() {
                CaEvtDet::RoasUpdated { .. }
                | CaEvtDet::AspaObjectsUpdated { .. }
                | CaEvtDet::ChildCertificatesUpdated { .. }
                | CaEvtDet::ChildKeyRevoked { .. }
                | CaEvtDet::KeyPendingToNew { .. }
                | CaEvtDet::KeyPendingToActive { .. }
                | CaEvtDet::KeyRollFinished { .. } => self.schedule_sync_repo(handle.clone()),

                CaEvtDet::KeyRollActivated {
                    resource_class_name, ..
                } => {
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        self.schedule_sync_parent(handle.clone(), parent.clone());
                    }
                    self.schedule_sync_repo(handle.clone());
                }

                CaEvtDet::ParentRemoved { parent } => {
                    self.drop_sync_parent(handle.clone(), parent.clone());
                    self.schedule_sync_repo(handle.clone());
                }

                CaEvtDet::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_requests,
                } => {
                    self.schedule_sync_repo(handle.clone());

                    self.schedule(QueueTask::ResourceClassRemoved {
                        ca: handle.clone(),
                        parent: parent.clone(),
                        rcn: resource_class_name.clone(),
                        revocation_requests: revoke_requests.clone(),
                    })
                }

                CaEvtDet::UnexpectedKeyFound {
                    resource_class_name,
                    revoke_req,
                } => self.schedule(QueueTask::UnexpectedKey {
                    ca: handle.clone(),
                    rcn: resource_class_name.clone(),
                    revocation_request: revoke_req.clone(),
                }),

                CaEvtDet::ParentAdded { parent, .. } => {
                    self.schedule_sync_parent(handle.clone(), parent.clone());
                }
                CaEvtDet::RepoUpdated { .. } => {
                    for parent in ca.parents() {
                        self.schedule_sync_parent(handle.clone(), parent.clone());
                    }
                }
                CaEvtDet::CertificateRequested {
                    resource_class_name, ..
                } => {
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        self.schedule_sync_parent(handle.clone(), parent.clone());
                    }
                }

                _ => {}
            }
        }
    }
}

//------------ Priority ------------------------------------------------------

/// Can be used as a priority value for [`PriorityQueue`]. Meaning that the
/// time value which is soonest has the highest priority. So, in short reverse
/// order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Priority(i64);

impl Priority {
    fn now() -> Self {
        Time::now().into()
    }
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
