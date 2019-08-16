//! A simple message queue, responsible for listening for (CA) events,
//! making them available for triggered processing, such as publishing
//! signed material, or asking a newly added parent for resource
//! entitlements.

use std::collections::VecDeque;
use std::fmt;
use std::sync::RwLock;

use krill_commons::api::admin::Handle;
use krill_commons::api::publication::PublishDelta;
use krill_commons::api::RevocationRequest;
use krill_commons::eventsourcing;

use crate::ca::{CertAuth, Evt, EvtDet, ParentHandle, Signer};

//------------ QueueEvent ----------------------------------------------------

/// This type contains all the events of interest for a KrillServer, with
/// the details needed for triggered processing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueueEvent {
    Delta(Handle, PublishDelta),
    ParentAdded(Handle, ParentHandle),
    RequestsPending(Handle, ParentHandle),
    ResourceClassRemoved(Handle, ParentHandle, Vec<RevocationRequest>),
}

#[derive(Debug)]
pub struct EventQueueListener {
    q: RwLock<Box<EventQueueStore>>,
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
        use krill_commons::eventsourcing::Event;

        let json = serde_json::to_string_pretty(&event).unwrap();
        debug!("Seen CertAuth event: {}", json);

        let handle = event.handle();
        match event.details() {
            EvtDet::Published(_, delta) => {
                let publish_delta = delta.values().fold(PublishDelta::empty(), |acc, el| {
                    acc + el.objects().clone().into()
                });

                let evt = QueueEvent::Delta(handle.clone(), publish_delta);
                self.push_back(evt);
            }
            EvtDet::ResourceClassRemoved(parent, _class_name, delta, revocations) => {
                self.push_back(QueueEvent::Delta(handle.clone(), delta.clone().into()));
                self.push_back(QueueEvent::ResourceClassRemoved(
                    handle.clone(),
                    parent.clone(),
                    revocations.clone(),
                ))
            }
            EvtDet::KeyRollFinished(_parent, _class_name, delta) => {
                let evt = QueueEvent::Delta(handle.clone(), delta.clone().into());
                self.push_back(evt);
            }

            EvtDet::ParentAdded(parent, _contact) => {
                let evt = QueueEvent::ParentAdded(handle.clone(), parent.clone());
                self.push_back(evt);
            }

            EvtDet::CertificateRequested(parent, _, _) => {
                let evt = QueueEvent::RequestsPending(handle.clone(), parent.clone());
                self.push_back(evt);
            }
            EvtDet::KeyRollActivated(parent, _, _) => {
                let evt = QueueEvent::RequestsPending(handle.clone(), parent.clone());
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
        self.q.write().unwrap().pop_front()
    }

    fn push_back(&self, evt: QueueEvent) {
        self.q.write().unwrap().push_back(evt);
    }
}
