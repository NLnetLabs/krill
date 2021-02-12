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

//------------ QueueEvent ----------------------------------------------------

/// This type contains all the events of interest for a KrillServer, with
/// the details needed for triggered processing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueueEvent {
    ServerStarted,

    SyncRepo(Handle),
    RescheduleSyncRepo(Handle, Time),

    SyncParent(Handle, ParentHandle),
    RescheduleSyncParent(Handle, ParentHandle, Time),

    ResourceClassRemoved(Handle, ParentHandle, HashMap<ResourceClassName, Vec<RevocationRequest>>),
    UnexpectedKey(Handle, ResourceClassName, RevocationRequest),
    CleanOldRepo(Handle),
}

impl fmt::Display for QueueEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueueEvent::ServerStarted => write!(f, "Server just started"),
            QueueEvent::SyncRepo(ca) => write!(f, "synchronize repo for '{}'", ca),
            QueueEvent::RescheduleSyncRepo(ca, time) => write!(
                f,
                "reschedule failed synchronize repo for '{}' at: {}",
                ca,
                time.to_rfc3339()
            ),
            QueueEvent::SyncParent(ca, parent) => write!(f, "synchronize CA '{}' with parent '{}'", ca, parent),
            QueueEvent::RescheduleSyncParent(ca, parent, time) => write!(
                f,
                "reschedule failed synchronize CA '{}' with parent '{}' for {}",
                ca,
                parent,
                time.to_rfc3339()
            ),
            QueueEvent::ResourceClassRemoved(ca, _, _) => {
                write!(f, "resource class removed for '{}' ", ca)
            }
            QueueEvent::UnexpectedKey(ca, rcn, _) => {
                write!(f, "unexpected key found for '{}' resource class: '{}'", ca, rcn)
            }
            QueueEvent::CleanOldRepo(ca) => {
                write!(f, "clean up old repo *if it exists* for '{}'", ca)
            }
        }
    }
}

#[derive(Debug)]
pub struct MessageQueue {
    q: RwLock<VecDeque<QueueEvent>>,
}

impl Default for MessageQueue {
    fn default() -> Self {
        let mut vec = VecDeque::new();
        vec.push_back(QueueEvent::ServerStarted);
        MessageQueue { q: RwLock::new(vec) }
    }
}

impl MessageQueue {
    pub fn pop_all(&self) -> Vec<QueueEvent> {
        let mut res = vec![];
        let mut q = self.q.write().unwrap();
        while let Some(evt) = q.pop_front() {
            res.push(evt);
        }
        res
    }

    /// Add a queue event to the back of the queue UNLESS there is
    /// already an equivalent event scheduled.
    pub fn push_back(&self, evt: QueueEvent) {
        let mut q = self.q.write().unwrap();

        match &evt {
            QueueEvent::SyncRepo(ca) | QueueEvent::RescheduleSyncRepo(ca, _) => {
                for existing in q.iter() {
                    match existing {
                        QueueEvent::SyncRepo(existing_ca) | QueueEvent::RescheduleSyncRepo(existing_ca, _) => {
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
            QueueEvent::SyncParent(ca, parent) | QueueEvent::RescheduleSyncParent(ca, parent, _) => {
                for existing in q.iter() {
                    match existing {
                        QueueEvent::SyncParent(existing_ca, existing_parent)
                        | QueueEvent::RescheduleSyncParent(existing_ca, existing_parent, _) => {
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

    pub fn push_sync_repo(&self, ca: Handle) {
        self.push_back(QueueEvent::SyncRepo(ca))
    }

    pub fn push_sync_parent(&self, ca: Handle, parent: ParentHandle) {
        self.push_back(QueueEvent::SyncParent(ca, parent))
    }

    pub fn drop_sync_parent(&self, ca: &Handle, parent: &ParentHandle) {
        let mut q = self.q.write().unwrap();

        q.retain(|existing| match existing {
            QueueEvent::SyncParent(ex_ca, ex_parent) | QueueEvent::RescheduleSyncParent(ex_ca, ex_parent, _) => {
                ca != ex_ca || parent != ex_parent
            }
            _ => true,
        });
    }
}

unsafe impl Send for MessageQueue {}
unsafe impl Sync for MessageQueue {}

/// Implement listening for CertAuth Published events.
impl eventsourcing::EventListener<CertAuth> for MessageQueue {
    fn listen(&self, ca: &CertAuth, event: &CaEvt) {
        trace!("Seen CertAuth event '{}'", event);

        let handle = event.handle();

        match event.details() {
            CaEvtDet::RoasUpdated { .. }
            | CaEvtDet::ChildCertificatesUpdated { .. }
            | CaEvtDet::ChildKeyRevoked { .. }
            | CaEvtDet::KeyPendingToNew { .. }
            | CaEvtDet::KeyPendingToActive { .. }
            | CaEvtDet::KeyRollFinished { .. } => self.push_sync_repo(handle.clone()),

            CaEvtDet::KeyRollActivated {
                resource_class_name, ..
            } => {
                if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                    self.push_sync_parent(handle.clone(), parent.clone());
                }
                self.push_sync_repo(handle.clone());
            }

            CaEvtDet::ParentRemoved { parent } => {
                self.drop_sync_parent(&handle, parent);
                self.push_sync_repo(handle.clone());
            }

            CaEvtDet::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_reqs,
            } => {
                self.push_sync_repo(handle.clone());

                let mut revocations_map = HashMap::new();
                revocations_map.insert(resource_class_name.clone(), revoke_reqs.clone());

                self.push_back(QueueEvent::ResourceClassRemoved(
                    handle.clone(),
                    parent.clone(),
                    revocations_map,
                ))
            }

            CaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => self.push_back(QueueEvent::UnexpectedKey(
                handle.clone(),
                resource_class_name.clone(),
                revoke_req.clone(),
            )),

            CaEvtDet::ParentAdded { parent, .. } => {
                self.push_sync_parent(handle.clone(), parent.clone());
            }
            CaEvtDet::RepoUpdated { .. } => {
                for parent in ca.parents() {
                    self.push_sync_parent(handle.clone(), parent.clone());
                }
            }
            CaEvtDet::CertificateRequested {
                resource_class_name, ..
            } => {
                if let Ok(parent) = ca.parent_for_rc(resource_class_name) {
                    self.push_sync_parent(handle.clone(), parent.clone());
                }
            }

            CaEvtDet::CertificateReceived { .. } => {
                if ca.old_repository_contact().is_some() {
                    let evt = QueueEvent::CleanOldRepo(handle.clone());
                    self.push_back(evt);
                }
            }
            _ => {}
        }
    }
}
