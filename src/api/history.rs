//! Inspecting the command history.

use std::{collections::BTreeMap, fmt};
use chrono::{DateTime, SecondsFormat};
use rpki::ca::idexchange::{
    ChildHandle, MyHandle, ParentHandle, PublisherHandle, ServiceUri,
};
use rpki::ca::provisioning::ResourceClassName;
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use rpki::repository::x509::Time;
use rpki::rrdp::Hash;
use serde::{Deserialize, Serialize};
use crate::commons::eventsourcing::{
    Event, InitEvent, StoredEffect,
};
use super::admin::StorableParentContact;
use super::ca::ResourceSetSummary;


//------------ CommandHistory ------------------------------------------------

/// An excerpt of the command history of an object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistory {
    /// The offset of the first command included.
    pub offset: usize,

    /// The total number of commands for the object.
    pub total: usize,

    /// The list of included commands.
    pub commands: Vec<CommandHistoryRecord>,
}

impl fmt::Display for CommandHistory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "time::command::version::success")?;

        for command in &self.commands {
            let success_string = match &command.effect {
                CommandHistoryResult::Init() => "INIT".to_string(),
                CommandHistoryResult::Ok() => "OK".to_string(),
                CommandHistoryResult::Error(msg) => {
                    format!("ERROR -> {msg}")
                }
            };
            writeln!(
                f,
                "{}::{}::{}::{}",
                command.time().to_rfc3339_opts(SecondsFormat::Secs, true),
                command.summary.msg,
                command.version,
                success_string
            )?;
        }

        Ok(())
    }
}


//------------ CommandHistoryRecord ------------------------------------------

/// A description of a command that was processed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryRecord {
    /// The actor that created the command.
    pub actor: String,

    /// The Unix timestamp in milliseconds of when the command was created.
    //
    // XXX We should probably have a newtype for a millisecond timestamp
    //     to make the resolution more obvious.
    pub timestamp: i64,

    /// The handle of the entity the command applies to.
    pub handle: MyHandle,

    /// The version of the entity the command was applied to.
    pub version: u64,

    /// The summary of the command.
    pub summary: CommandSummary,

    /// The effect of processing the command.
    pub effect: CommandHistoryResult,
}

impl CommandHistoryRecord {
    /// Returns whether the record matches the given criteria.
    pub fn matches(&self, crit: &CommandHistoryCriteria) -> bool {
        crit.matches_timestamp(self.timestamp)
            && crit.matches_version(self.version)
            && crit.matches_label(&self.summary.label)
    }

    /// Converts the timestamp into a time.
    ///
    /// Note that the returned value has second resolution while the timestamp
    /// has millisecond resolution.
    pub fn time(&self) -> Time {
        DateTime::from_timestamp(
            self.timestamp / 1000, 0
        ).expect("timestamp out-of-range").into()
    }
}


//------------ CommandHistoryResult ------------------------------------------

/// The result of processing a command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CommandHistoryResult {
    /// The command resulted in initializing a new object.
    Init(),

    /// The command was successfully processed.
    Ok(),

    /// The command resulted in an error with the given message.
    Error(String),
}

impl<E, I> From<StoredEffect<E, I>> for CommandHistoryResult
where E: Event, I: InitEvent {
    fn from(effect: StoredEffect<E, I>) -> Self {
        match effect {
            StoredEffect::Error { msg, .. } => {
                CommandHistoryResult::Error(msg)
            }
            StoredEffect::Success { .. } => CommandHistoryResult::Ok(),
            StoredEffect::Init { .. } => CommandHistoryResult::Init(),
        }
    }
}


//------------ CommandSummary ------------------------------------------------

/// Generic command summary.
///
/// This type is used to show a command summary in the history in a way that
/// supports internationalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandSummary {
    /// The human-readable summary of the command.
    ///
    /// This message is stable for each command and can be used as the basis
    /// for i18n processing.
    pub msg: String,

    /// The name of the command.
    pub label: String,

    /// The arguments of the command.
    pub args: BTreeMap<String, String>,
}

impl CommandSummary {
    /// Creates a new summary with the given label and message.
    pub fn new(label: &str, msg: impl fmt::Display) -> Self {
        CommandSummary {
            msg: msg.to_string(),
            label: label.to_string(),
            args: BTreeMap::new(),
        }
    }

    /// Adds an argument to the summary.
    pub fn arg(mut self, key: &str, val: impl fmt::Display) -> Self {
        self.args.insert(key.to_string(), val.to_string());
        self
    }

    pub fn child(self, child: &ChildHandle) -> Self {
        self.arg("child", child)
    }

    pub fn parent(self, parent: &ParentHandle) -> Self {
        self.arg("parent", parent)
    }

    pub fn publisher(self, publisher: &PublisherHandle) -> Self {
        self.arg("publisher", publisher)
    }

    pub fn id_key(self, id: &str) -> Self {
        self.arg("id_key", id)
    }

    pub fn resources(self, resources: &ResourceSet) -> Self {
        let summary = ResourceSetSummary::from(resources);
        self.arg("resources", resources)
            .arg("asn_blocks", summary.asn_blocks)
            .arg("ipv4_blocks", summary.ipv4_blocks)
            .arg("ipv6_blocks", summary.ipv6_blocks)
    }

    pub fn rcn(self, rcn: &ResourceClassName) -> Self {
        self.arg("class_name", rcn)
    }

    pub fn key(self, ki: KeyIdentifier) -> Self {
        self.arg("key", ki)
    }

    pub fn id_cert_hash(self, hash: &Hash) -> Self {
        self.arg("id_cert_hash", hash)
    }

    pub fn parent_contact(
        self,
        contact: &StorableParentContact,
    ) -> Self {
        self.arg("parent_contact", contact)
    }

    pub fn seconds(self, seconds: i64) -> Self {
        self.arg("seconds", seconds)
    }

    pub fn added(self, nr: usize) -> Self {
        self.arg("added", nr)
    }

    pub fn removed(self, nr: usize) -> Self {
        self.arg("removed", nr)
    }

    pub fn service_uri(self, service_uri: &ServiceUri) -> Self {
        self.arg("service_uri", service_uri)
    }

    pub fn rta_name(self, name: &str) -> Self {
        self.arg("rta_name", name)
    }
}


//------------ CommandHistoryCriteria ----------------------------------------

/// Limits the scope when finding commands to show in the history.
#[derive(Clone, Debug, Deserialize, Default, Eq, PartialEq, Serialize)]
pub struct CommandHistoryCriteria {
    /// Only include commands before the given timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,

    /// Only include commands after the given timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<i64>,

    /// Only include commands after the given version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_version: Option<u64>,

    /// Only include commands with the given labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_includes: Option<Vec<String>>,

    /// Exclude commands with the given labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_excludes: Option<Vec<String>>,

    /// Start a command list at the given offset.
    pub offset: usize,

    /// Limit the number of returned items to the given number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_limit: Option<usize>,
}

impl CommandHistoryCriteria {
    /// Returns whether the given timestamp is included in the criteria.
    fn matches_timestamp(&self, stamp: i64) -> bool {
        if let Some(before) = self.before {
            if stamp > before {
                return false;
            }
        }
        if let Some(after) = self.after {
            if stamp < after {
                return false;
            }
        }
        true
    }

    /// Returns whether the given version is included in the criteria.
    fn matches_version(&self, version: u64) -> bool {
        match self.after_version {
            None => true,
            Some(seq_crit) => version > seq_crit,
        }
    }

    /// Returns whether the given label is included in the criteria.
    fn matches_label(&self, label: &String) -> bool {
        if let Some(includes) = &self.label_includes {
            if !includes.contains(label) {
                return false;
            }
        }
        if let Some(excludes) = &self.label_excludes {
            if excludes.contains(label) {
                return false;
            }
        }

        true
    }
}


//------------ CommandDetails ------------------------------------------------

/// Generic command details.
///
/// This type is used to show command details in the history in a way that
/// supports internationalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandDetails {
    /// The actor that created the command.
    pub actor: String,

    /// The time the command was created.
    pub time: Time,

    /// The handle of the entity the command applies to.
    pub handle: MyHandle,

    /// The version of the entity the command was applied to.
    pub version: u64,

    /// The human-readable summary of the command.
    ///
    /// This message is stable for each command and can be used as the basis
    /// for i18n processing.
    pub msg: String,

    /// The raw details of the command as stored.
    pub details: serde_json::Value,

    /// The effect of processing the command.
    pub effect: CommandEffect
}

impl fmt::Display for CommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Time:   {}",
            self.time.to_rfc3339_opts(SecondsFormat::Secs, true)
        )?;
        writeln!(f, "Actor:  {}", self.actor)?;
        writeln!(f, "Action: {}", self.msg)?;

        match &self.effect {
            CommandEffect::Error { msg, .. } => {
                writeln!(f, "Error:  {msg}")?
            }
            CommandEffect::Success { events } => {
                writeln!(f, "Changes:")?;
                for evt in events {
                    writeln!(f, "  {}", evt.msg)?;
                }
            }
            CommandEffect::Init { init } => {
                writeln!(f, "{}", init.msg)?;
            }
        }

        Ok(())
    }
}


//------------ CommandEffect -------------------------------------------------

/// The effect of processing a command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "snake_case",
    tag = "result",
)]
pub enum CommandEffect {
    /// The command resulted in an error with the given message.
    Error { msg: String },

    /// The command was successfully processed resulting in the given events.
    Success { events: Vec<CommandEffectEvent> },

    /// The command resulted in initializing a new object.
    Init { init: CommandEffectEvent },
}


//------------ CommandEffectEvent --------------------------------------------

/// Details about an event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandEffectEvent {
    /// The human-readable summary of the event.
    ///
    /// This message is stable for each command and can be used as the basis
    /// for i18n processing.
    pub msg: String,

    /// The raw details of the event as stored.
    pub details: serde_json::Value,
}


