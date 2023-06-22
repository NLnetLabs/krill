use std::{fmt, str::FromStr};

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::commons::eventsourcing::WithStorableDetails;

//------------ OldStoredCommand ----------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredCommand<S: WithStorableDetails> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    #[serde(deserialize_with = "S::deserialize")]
    details: S,
    effect: OldStoredEffect,
}

impl<S: WithStorableDetails> OldStoredCommand<S> {
    pub fn time(&self) -> Time {
        self.time
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn effect(&self) -> &OldStoredEffect {
        &self.effect
    }
}

//------------ StoredEffect --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum OldStoredEffect {
    Error { msg: String },
    Success { events: Vec<u64> },
}

impl OldStoredEffect {
    pub fn events(&self) -> Option<&Vec<u64>> {
        match self {
            OldStoredEffect::Error { .. } => None,
            OldStoredEffect::Success { events } => Some(events),
        }
    }
}

//------------ OldCommandKey -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCommandKey {
    pub sequence: u64,
    pub timestamp_secs: i64,
    pub label: Label,
}

pub type Label = String;

impl fmt::Display for OldCommandKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "command--{}--{}--{}", self.timestamp_secs, self.sequence, self.label)
    }
}

impl FromStr for OldCommandKey {
    type Err = CommandKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("--").collect();
        if parts.len() != 4 || parts[0] != "command" {
            Err(CommandKeyError(s.to_string()))
        } else {
            let timestamp_secs = i64::from_str(parts[1]).map_err(|_| CommandKeyError(s.to_string()))?;
            let sequence = u64::from_str(parts[2]).map_err(|_| CommandKeyError(s.to_string()))?;
            // strip .json if present on the label part
            let label = {
                let end = parts[3].to_string();
                let last = if end.ends_with(".json") {
                    end.len() - 5
                } else {
                    end.len()
                };
                (end[0..last]).to_string()
            };

            Ok(OldCommandKey {
                sequence,
                timestamp_secs,
                label,
            })
        }
    }
}

//------------ CommandKeyError -----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandKeyError(String);

impl fmt::Display for CommandKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid command key: {}", self.0)
    }
}
