//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::RwLock;

use crate::commons::api::{Handle, ParentHandle, ResourceClassName, RevocationRequest};
use crate::commons::eventsourcing::{self, Event};
use crate::daemon::ca::{CertAuth, Evt, EvtDet, Signer};

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

    #[display(fmt = "requests pending for '{}' version '{}'", _0, _1)]
    RequestsPending(Handle, u64),

    #[display(fmt = "resource class removed for '{}' version '{}'", _0, _1)]
    ResourceClassRemoved(
        Handle,
        u64,
        ParentHandle,
        HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ),

    #[display(fmt = "clean up old repo *if it exists* for '{}' version '{}'", _0, _1)]
    CleanOldRepo(Handle, u64),
}

#[derive(Debug)]
pub struct EventQueueListener {
    q: RwLock<Box<dyn EventQueueStore>>,
}

impl EventQueueListener {
    pub fn in_mem() -> Self {
        EventQueueListener {
            q: RwLock::new(Box::new(MemoryEventQueue::new())),
        }
    }
}

impl EventQueueListener {
    pub fn pop(&self) -> Option<QueueEvent> {
        self.q.write().unwrap().pop()
    }

    fn push_back(&self, evt: QueueEvent) {
        self.q.write().unwrap().push_back(evt)
    }
}

// TODO: Is this unsafe here? I would think the RwLock is safe, but..
unsafe impl Send for EventQueueListener {}
unsafe impl Sync for EventQueueListener {}

/// Implement listening for CertAuth Published events.
impl<S: Signer> eventsourcing::EventListener<CertAuth<S>> for EventQueueListener {
    fn listen(&self, _ca: &CertAuth<S>, event: &Evt) {
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

            EvtDet::ParentAdded(parent, _contact) => {
                let evt = QueueEvent::ParentAdded(handle.clone(), version, parent.clone());
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

//------------ EventQueue ----------------------------------------------------

/// This trait provides the public contract for an EventQueue used by the
/// KrillServer. First implementation can be a simple in memory thing, but
/// we will need someting more robust, and possibly multi-master later.
///
/// The EventQueue should implement Eventlistener
trait EventQueueStore: fmt::Debug {
    fn pop(&self) -> Option<QueueEvent>;
    fn push_back(&self, evt: QueueEvent);
}

//------------ MemoryEventQueue ----------------------------------------------

/// In memory event queue implementation.
#[derive(Debug)]
struct MemoryEventQueue {
    q: RwLock<VecDeque<QueueEvent>>,
}

impl MemoryEventQueue {
    pub fn new() -> Self {
        MemoryEventQueue {
            q: RwLock::new(VecDeque::new()),
        }
    }
}

impl EventQueueStore for MemoryEventQueue {
    fn pop(&self) -> Option<QueueEvent> {
        let res = self.q.write().unwrap().pop_front();

        if let Some(evt) = res.as_ref() {
            trace!("Popping evt from schedule queue: {}", evt)
        }

        res
    }

    fn push_back(&self, evt: QueueEvent) {
        trace!("Pushing event to schedule queue: {}", evt);
        self.q.write().unwrap().push_back(evt);
    }
}
