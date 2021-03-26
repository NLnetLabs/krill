//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::RwLock;

use rpki::x509::Time;

use crate::commons::api::{Handle, ParentHandle, ResourceClassName, RevocationRequest};
use crate::commons::eventsourcing::{self, Event};
use crate::daemon::ca::{CaEvt, CaEvtDet, CertAuth};

//------------ QueueTask ----------------------------------------------------

/// This type contains tasks with the details needed for triggered processing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueueTask {
    ServerStarted,

    SyncRepo(Handle),
    RescheduleSyncRepo(Handle, Time),

    SyncParent(Handle, ParentHandle),
    RescheduleSyncParent(Handle, ParentHandle, Time),

    ResourceClassRemoved(Handle, ParentHandle, HashMap<ResourceClassName, Vec<RevocationRequest>>),
    UnexpectedKey(Handle, ResourceClassName, RevocationRequest),
}

impl fmt::Display for QueueTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueueTask::ServerStarted => write!(f, "Server just started"),
            QueueTask::SyncRepo(ca) => write!(f, "synchronize repo for '{}'", ca),
            QueueTask::RescheduleSyncRepo(ca, time) => write!(
                f,
                "reschedule failed synchronize repo for '{}' at: {}",
                ca,
                time.to_rfc3339()
            ),
            QueueTask::SyncParent(ca, parent) => write!(f, "synchronize CA '{}' with parent '{}'", ca, parent),
            QueueTask::RescheduleSyncParent(ca, parent, time) => write!(
                f,
                "reschedule failed synchronize CA '{}' with parent '{}' for {}",
                ca,
                parent,
                time.to_rfc3339()
            ),
            QueueTask::ResourceClassRemoved(ca, _, _) => {
                write!(f, "resource class removed for '{}' ", ca)
            }
            QueueTask::UnexpectedKey(ca, rcn, _) => {
                write!(f, "unexpected key found for '{}' resource class: '{}'", ca, rcn)
            }
        }
    }
}

#[derive(Debug)]
pub struct MessageQueue {
    q: RwLock<VecDeque<QueueTask>>,
}

impl Default for MessageQueue {
    fn default() -> Self {
        let mut vec = VecDeque::new();
        vec.push_back(QueueTask::ServerStarted);
        MessageQueue { q: RwLock::new(vec) }
    }
}

impl MessageQueue {
    pub fn pop_all(&self) -> Vec<QueueTask> {
        let mut res = vec![];
        let mut q = self.q.write().unwrap();
        while let Some(evt) = q.pop_front() {
            res.push(evt);
        }
        res
    }

    fn schedule(&self, task: QueueTask) {
        let mut q = self.q.write().unwrap();
        q.push_back(task);
    }

    pub fn schedule_sync_repo(&self, ca: Handle) {
        self.schedule(QueueTask::SyncRepo(ca));
    }

    pub fn reschedule_sync_repo(&self, ca: Handle, time: Time) {
        self.schedule(QueueTask::RescheduleSyncRepo(ca, time));
    }

    pub fn schedule_sync_parent(&self, ca: Handle, parent: ParentHandle) {
        self.schedule(QueueTask::SyncParent(ca, parent));
    }

    pub fn reschedule_sync_parent(&self, ca: Handle, parent: ParentHandle, time: Time) {
        self.schedule(QueueTask::RescheduleSyncParent(ca, parent, time));
    }

    fn drop_sync_parent(&self, ca: &Handle, parent: &ParentHandle) {
        let mut q = self.q.write().unwrap();
        q.retain(|existing| match existing {
            QueueTask::SyncParent(ex_ca, ex_parent) | QueueTask::RescheduleSyncParent(ex_ca, ex_parent, _) => {
                ca != ex_ca || parent != ex_parent
            }
            _ => true,
        });
    }
}

unsafe impl Send for MessageQueue {}
unsafe impl Sync for MessageQueue {}

/// Implement listening for CertAuth Published events.
impl eventsourcing::PostSaveEventListener<CertAuth> for MessageQueue {
    fn listen(&self, ca: &CertAuth, events: &[CaEvt]) {
        for event in events {
            trace!("Seen CertAuth event '{}'", event);

            let handle = event.handle();

            match event.details() {
                CaEvtDet::RoasUpdated { .. }
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
                    self.drop_sync_parent(&handle, parent);
                    self.schedule_sync_repo(handle.clone());
                }

                CaEvtDet::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_reqs,
                } => {
                    self.schedule_sync_repo(handle.clone());

                    let mut revocations_map = HashMap::new();
                    revocations_map.insert(resource_class_name.clone(), revoke_reqs.clone());

                    self.schedule(QueueTask::ResourceClassRemoved(
                        handle.clone(),
                        parent.clone(),
                        revocations_map,
                    ))
                }

                CaEvtDet::UnexpectedKeyFound {
                    resource_class_name,
                    revoke_req,
                } => self.schedule(QueueTask::UnexpectedKey(
                    handle.clone(),
                    resource_class_name.clone(),
                    revoke_req.clone(),
                )),

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
