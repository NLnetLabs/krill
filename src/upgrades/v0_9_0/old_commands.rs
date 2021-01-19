use rpki::x509::Time;

use std::fmt;

use crate::commons::{
    api::{Handle, StorableCaCommand},
    eventsourcing::Command,
};

use super::old_events::OldEvt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredCaCommand {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    details: StorableCaCommand,
    effect: StoredEffect,
}

impl fmt::Display for OldStoredCaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA command")
    }
}

impl Command for OldStoredCaCommand {
    type Event = OldEvt;
    type StorableDetails = StorableCaCommand;

    fn handle(&self) -> &Handle {
        &self.handle
    }

    fn version(&self) -> Option<u64> {
        Some(self.version)
    }

    fn actor(&self) -> &str {
        &self.actor
    }

    fn store(&self) -> Self::StorableDetails {
        self.details.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEffect {
    Error(String),
    Events(Vec<u64>),
}
