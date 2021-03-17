//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::fmt;
use std::sync::RwLock;
use std::{
    collections::{HashMap, VecDeque},
    sync::RwLockWriteGuard,
};

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

    pub fn schedule_sync_repo(&self, ca: Handle) {
        let mut q = self.q.write().unwrap();
        Self::push_back(&mut q, QueueTask::SyncRepo(ca));
    }

    pub fn reschedule_sync_repo(&self, ca: Handle, time: Time) {
        let mut q = self.q.write().unwrap();
        Self::push_back(&mut q, QueueTask::RescheduleSyncRepo(ca, time));
    }

    pub fn reschedule_sync_parent(&self, ca: Handle, parent: ParentHandle, time: Time) {
        let mut q = self.q.write().unwrap();
        Self::push_back(&mut q, QueueTask::RescheduleSyncParent(ca, parent, time));
    }

    /// Add a queue event to the back of the queue UNLESS there is
    /// already an equivalent event scheduled.
    pub fn push_back(q: &mut RwLockWriteGuard<VecDeque<QueueTask>>, evt: QueueTask) {
        match &evt {
            QueueTask::SyncRepo(ca) | QueueTask::RescheduleSyncRepo(ca, _) => {
                for existing in q.iter() {
                    match existing {
                        QueueTask::SyncRepo(existing_ca) | QueueTask::RescheduleSyncRepo(existing_ca, _) => {
                            if existing_ca == ca {
                                debug!(
                                    "Not (re-)scheduling publication for '{}', because event exists on queue",
                                    ca
                                );
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            }
            QueueTask::SyncParent(ca, parent) | QueueTask::RescheduleSyncParent(ca, parent, _) => {
                for existing in q.iter() {
                    match existing {
                        QueueTask::SyncParent(existing_ca, existing_parent)
                        | QueueTask::RescheduleSyncParent(existing_ca, existing_parent, _) => {
                            if existing_ca == ca && existing_parent == parent {
                                debug!(
                                    "Not (re-)scheduling sync for '{}' with parent '{}', because event exists on queue",
                                    ca, parent
                                );
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        q.push_back(evt);
    }

    pub fn push_sync_repo(q: &mut RwLockWriteGuard<VecDeque<QueueTask>>, ca: Handle) {
        Self::push_back(q, QueueTask::SyncRepo(ca))
    }

    pub fn push_sync_parent(q: &mut RwLockWriteGuard<VecDeque<QueueTask>>, ca: Handle, parent: ParentHandle) {
        Self::push_back(q, QueueTask::SyncParent(ca, parent))
    }

    pub fn drop_sync_parent(q: &mut RwLockWriteGuard<VecDeque<QueueTask>>, ca: &Handle, parent: &ParentHandle) {
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
        let mut queue = self.q.write().unwrap();

        for event in events {
            trace!("Seen CertAuth event '{}'", event);

            let handle = event.handle();

            match event.details() {
                CaEvtDet::RoasUpdated { .. }
                | CaEvtDet::ChildCertificatesUpdated { .. }
                | CaEvtDet::ChildKeyRevoked { .. }
                | CaEvtDet::KeyPendingToNew { .. }
                | CaEvtDet::KeyPendingToActive { .. }
                | CaEvtDet::KeyRollFinished { .. } => Self::push_sync_repo(&mut queue, handle.clone()),

                CaEvtDet::KeyRollActivated {
                    resource_class_name, ..
                } => {
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        Self::push_sync_parent(&mut queue, handle.clone(), parent.clone());
                    }
                    Self::push_sync_repo(&mut queue, handle.clone());
                }

                CaEvtDet::ParentRemoved { parent } => {
                    Self::drop_sync_parent(&mut queue, &handle, parent);
                    Self::push_sync_repo(&mut queue, handle.clone());
                }

                CaEvtDet::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_reqs,
                } => {
                    Self::push_sync_repo(&mut queue, handle.clone());

                    let mut revocations_map = HashMap::new();
                    revocations_map.insert(resource_class_name.clone(), revoke_reqs.clone());

                    Self::push_back(
                        &mut queue,
                        QueueTask::ResourceClassRemoved(handle.clone(), parent.clone(), revocations_map),
                    )
                }

                CaEvtDet::UnexpectedKeyFound {
                    resource_class_name,
                    revoke_req,
                } => Self::push_back(
                    &mut queue,
                    QueueTask::UnexpectedKey(handle.clone(), resource_class_name.clone(), revoke_req.clone()),
                ),

                CaEvtDet::ParentAdded { parent, .. } => {
                    Self::push_sync_parent(&mut queue, handle.clone(), parent.clone());
                }
                CaEvtDet::RepoUpdated { .. } => {
                    for parent in ca.parents() {
                        Self::push_sync_parent(&mut queue, handle.clone(), parent.clone());
                    }
                }
                CaEvtDet::CertificateRequested {
                    resource_class_name, ..
                } => {
                    if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                        Self::push_sync_parent(&mut queue, handle.clone(), parent.clone());
                    }
                }

                _ => {}
            }
        }
    }
}
