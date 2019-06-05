use clokwerk::{Scheduler, ScheduleHandle, TimeUnits};
use std::time::Duration;
use krill_commons::util::httpclient;
use krill_commons::api::admin::Token;

/// This type is responsible for periodically calling the
/// API to republish all CAs. Only CAs that *need* to republish
/// will do so (i.e. if there are no changes, and the nextUpdate
/// is still comfortably far in the future, this is a no-op).
///
/// This is done by calling the actual HTTPS end-point. While
/// this may seem somewhat convoluted, this eliminates the need
/// for this type to share state with the main application.
pub struct Republisher {
    // Responsible for background tasks, e.g. re-publishing
    #[allow(dead_code)] // just need to keep this in scope
    tasks_thread: ScheduleHandle
}

impl Republisher {
    pub fn new(publish_trigger_uri: String, token: &Token) -> Self {

        let token = token.clone();

        let mut scheduler = Scheduler::new();
        scheduler.every(5.seconds()).run(move || {
            if let Err(e) = httpclient::post_empty(
                &publish_trigger_uri,
                Some(&token)
            ) {
                error!("Could not publish: {}", e);
            }
        });

        Republisher {
            tasks_thread: scheduler.watch_thread(Duration::from_millis(100))
        }
    }
}