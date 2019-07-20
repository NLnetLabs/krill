//! Deal with asynchronous scheduled processes, either triggered by an
//! event that occurred, or planned (e.g. re-publishing).

use std::sync::Arc;
use std::time::Duration;

use clokwerk::{self, ScheduleHandle, TimeUnits};

use mq::EventQueueListener;
use mq::QueueEvent;
use ca::caserver::CaServer;
use krill_commons::util::softsigner::OpenSslSigner;
use krill_commons::api::admin::Handle;
use krill_commons::api::ca::PublicationDelta;
use krill_pubd::PubServer;

pub struct Scheduler {
    #[allow(dead_code)] // just need to keep this in scope
    event_sh: ScheduleHandle,

    #[allow(dead_code)] // just need to keep this in scope
    republish_sh: ScheduleHandle
}

impl Scheduler {
    pub fn build(
        event_queue: Arc<EventQueueListener>,
        caserver: Arc<CaServer<OpenSslSigner>>,
        pubserver: Arc<PubServer>
    ) -> Self {
        let mut scheduler = clokwerk::Scheduler::new();
        scheduler.every(1.seconds()).run(move || {
            while let Some(evt) = event_queue.pop() {
                match evt {
                    QueueEvent::Delta(handle, delta) => {
                        publish(&handle, delta, &pubserver);
                    },
                    QueueEvent::ParentAdded(handle, _parent, _contact) => {
                        info!("Found parent for: {}", handle);
                    }
                }
            }
        });
        let event_sh =  scheduler.watch_thread(Duration::from_millis(100));

        let mut scheduler = clokwerk::Scheduler::new();
        scheduler.every(1.hours()).run(move || {
            caserver.republish_all(); // TODO: one by one and keep results
        });
        let republish_sh = scheduler.watch_thread(Duration::from_millis(100));

        Scheduler {
            event_sh, republish_sh
        }
    }
}

fn publish(
    handle: &Handle,
    delta: PublicationDelta,
    pubserver: &PubServer
) {
    match pubserver.publish(handle, delta.into()) {
        Ok(()) => info!("Published for CA: {}", handle),
        Err(e) => error!("Failed to publish for CA: {}, error: {}", handle, e)
    }
}