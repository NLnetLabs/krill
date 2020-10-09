//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

use rpki::x509::Time;

use crate::commons::api::{Handle, ParentHandle, ResourceClassName, RevocationRequest};
use crate::commons::eventsourcing::{self, Event};
use crate::daemon::ca::{CertAuth, Evt, EvtDet};

//------------ QueueEvent ----------------------------------------------------

/// This type contains all the events of interest for a KrillServer, with
/// the details needed for triggered processing.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueueEvent {
    #[display(fmt = "delta for '{}' version '{}'", _0, _1)]
    Delta(Handle, u64),

    #[display(fmt = "parent added to '{}' version '{}'", _0, _1)]
    ParentAdded(Handle, u64, ParentHandle),

    #[display(fmt = "configured repository for '{}' version '{}'", _0, _1)]
    RepositoryConfigured(Handle, u64),

    #[display(fmt = "requests pending for '{}' version '{}'", _0, _1)]
    RequestsPending(Handle, u64),

    #[display(fmt = "resource class removed for '{}' version '{}'", _0, _1)]
    ResourceClassRemoved(
        Handle,
        u64,
        ParentHandle,
        HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ),

    #[display(fmt = "unexpected key found for '{}' version '{}' resource class: '{}'", _0, _1, _2)]
    UnexpectedKey(Handle, u64, ResourceClassName, RevocationRequest),

    #[display(fmt = "clean up old repo *if it exists* for '{}' version '{}'", _0, _1)]
    CleanOldRepo(Handle, u64),

    #[display(fmt = "reschedule failed publication for '{}'", _0)]
    ReschedulePublish(Handle, Time),

    #[display(fmt = "Server just started")]
    ServerStarted,
}

#[derive(Debug)]
pub struct EventQueueListener {
    q: RwLock<VecDeque<QueueEvent>>,
}

impl Default for EventQueueListener {
    fn default() -> Self {
        let mut vec = VecDeque::new();
        vec.push_back(QueueEvent::ServerStarted);
        EventQueueListener { q: RwLock::new(vec) }
    }
}

impl EventQueueListener {
    pub fn pop_all(&self) -> Vec<QueueEvent> {
        let mut res = vec![];
        let mut q = self.q.write().unwrap();
        while let Some(evt) = q.pop_front() {
            res.push(evt);
        }
        res
    }

    pub fn push_back(&self, evt: QueueEvent) {
        self.q.write().unwrap().push_back(evt)
    }
}

unsafe impl Send for EventQueueListener {}
unsafe impl Sync for EventQueueListener {}

/// Implement listening for CertAuth Published events.
impl eventsourcing::EventListener<CertAuth> for EventQueueListener {
    fn listen(&self, _ca: &CertAuth, event: &Evt) {
        trace!("Seen CertAuth event '{}'", event);

        let handle = event.handle();
        let version = event.version();

        match event.details() {
            EvtDet::ObjectSetUpdated(_, _)
            | EvtDet::ParentRemoved(_, _)
            | EvtDet::KeyPendingToNew(_, _, _)
            | EvtDet::KeyPendingToActive(_, _, _)
            | EvtDet::KeyRollFinished(_, _) => {
                let evt = QueueEvent::Delta(handle.clone(), version);
                self.push_back(evt);
            }
            EvtDet::ResourceClassRemoved(class_name, _delta, parent, revocations) => {
                self.push_back(QueueEvent::Delta(handle.clone(), version));

                let mut revocations_map = HashMap::new();
                revocations_map.insert(class_name.clone(), revocations.clone());

                self.push_back(QueueEvent::ResourceClassRemoved(
                    handle.clone(),
                    version,
                    parent.clone(),
                    revocations_map,
                ))
            }

            EvtDet::UnexpectedKeyFound(rcn, revocation) => self.push_back(QueueEvent::UnexpectedKey(
                handle.clone(),
                version,
                rcn.clone(),
                revocation.clone(),
            )),

            EvtDet::ParentAdded(parent, _contact) => {
                let evt = QueueEvent::ParentAdded(handle.clone(), version, parent.clone());
                self.push_back(evt);
            }
            EvtDet::RepoUpdated(_) => {
                let evt = QueueEvent::RepositoryConfigured(handle.clone(), version);
                self.push_back(evt);
            }
            EvtDet::CertificateRequested(_, _, _) => {
                let evt = QueueEvent::RequestsPending(handle.clone(), version);
                self.push_back(evt);
            }
            EvtDet::KeyRollActivated(_, _) => {
                let evt = QueueEvent::RequestsPending(handle.clone(), version);
                self.push_back(evt);
            }
            EvtDet::CertificateReceived(_, _, _) => {
                let evt = QueueEvent::CleanOldRepo(handle.clone(), version);
                self.push_back(evt);
            }
            _ => {}
        }
    }
}
