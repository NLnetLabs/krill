use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime};
use chrono::{SecondsFormat, Utc};

use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::{
    ArgKey, ArgVal, ChildHandle, Handle, Label, Message, ParentHandle, PublisherHandle, RequestResourceLimit,
    ResourceClassName, ResourceSet, RevocationRequest, RoaDefinitionUpdates, RtaName, StorableParentContact,
};
use crate::commons::eventsourcing::{CommandKey, CommandKeyError, StoredCommand, WithStorableDetails};
use crate::commons::remote::rfc8183::ServiceUri;
use crate::daemon::ca;

//------------ CaCommandDetails ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaCommandDetails {
    command: StoredCommand<StorableCaCommand>,
    result: CaCommandResult,
}

impl CaCommandDetails {
    pub fn new(command: StoredCommand<StorableCaCommand>, result: CaCommandResult) -> Self {
        CaCommandDetails { command, result }
    }

    pub fn command(&self) -> &StoredCommand<StorableCaCommand> {
        &self.command
    }

    pub fn effect(&self) -> &CaCommandResult {
        &self.result
    }
}

impl fmt::Display for CaCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = self.command();
        writeln!(
            f,
            "Time:   {}",
            command.time().to_rfc3339_opts(SecondsFormat::Secs, true)
        )?;
        writeln!(f, "Action: {}", command.details().summary().msg)?;

        match self.effect() {
            CaCommandResult::Error(msg) => writeln!(f, "Error:  {}", msg)?,
            CaCommandResult::Events(evts) => {
                writeln!(f, "Changes:")?;
                for evt in evts {
                    writeln!(f, "  {}", evt.details().to_string())?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CaCommandResult {
    Error(String),
    Events(Vec<ca::CaEvt>),
}

impl CaCommandResult {
    pub fn error(msg: String) -> Self {
        CaCommandResult::Error(msg)
    }
    pub fn events(events: Vec<ca::CaEvt>) -> Self {
        CaCommandResult::Events(events)
    }
}

//------------ CommandHistory ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistory {
    offset: usize,
    total: usize,
    commands: Vec<CommandHistoryRecord>,
}

impl CommandHistory {
    pub fn new(offset: usize, total: usize, commands: Vec<CommandHistoryRecord>) -> Self {
        CommandHistory {
            offset,
            total,
            commands,
        }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn commands(&self) -> &Vec<CommandHistoryRecord> {
        &self.commands
    }
}

impl fmt::Display for CommandHistory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "time::command::key::success")?;

        for command in self.commands() {
            let success_string = match &command.effect {
                StoredEffect::Error(msg) => format!("ERROR -> {}", msg),
                StoredEffect::Events(_) => "OK".to_string(),
            };
            writeln!(
                f,
                "{}::{} ::{}::{}",
                command.time().to_rfc3339_opts(SecondsFormat::Secs, true),
                command.summary.msg,
                command.key,
                success_string
            )?;
        }

        Ok(())
    }
}

//------------ CommandHistoryRecord ------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Does not include the full stored command details, but only
/// the summary which is shown in the history response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryRecord {
    pub key: String,
    pub actor: String,
    pub timestamp: i64,
    pub handle: Handle,
    pub version: u64,
    pub sequence: u64,
    pub summary: CommandSummary,
    pub effect: StoredEffect,
}

impl CommandHistoryRecord {
    pub fn time(&self) -> Time {
        let seconds = self.timestamp / 1000;
        let time = NaiveDateTime::from_timestamp(seconds, 0);
        Time::from(DateTime::from_utc(time, Utc))
    }

    pub fn resulting_version(&self) -> u64 {
        if let Some(versions) = self.effect.events() {
            if let Some(last) = versions.last() {
                *last
            } else {
                self.version
            }
        } else {
            self.version
        }
    }

    pub fn command_key(&self) -> Result<CommandKey, CommandKeyError> {
        CommandKey::from_str(&self.key)
    }
}

//------------ StoredEffect --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEffect {
    Error(String),
    Events(Vec<u64>),
}

impl StoredEffect {
    pub fn successful(&self) -> bool {
        match self {
            StoredEffect::Error(_) => false,
            StoredEffect::Events(_) => true,
        }
    }

    pub fn events(&self) -> Option<&Vec<u64>> {
        match self {
            StoredEffect::Error(_) => None,
            StoredEffect::Events(vec) => Some(vec),
        }
    }
}

//------------ CommandSummary ------------------------------------------------

/// Generic command summary used to show command details in history in a way
/// that support internationalisation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandSummary {
    pub msg: Message,
    pub label: Label,
    pub args: BTreeMap<ArgKey, ArgVal>,
}

impl CommandSummary {
    pub fn new(label: &str, msg: impl fmt::Display) -> Self {
        CommandSummary {
            msg: msg.to_string(),
            label: label.to_string(),
            args: BTreeMap::new(),
        }
    }

    pub fn with_arg(mut self, key: &str, val: impl fmt::Display) -> Self {
        self.args.insert(key.to_string(), val.to_string());
        self
    }

    pub fn with_child(self, child: &ChildHandle) -> Self {
        self.with_arg("child", child)
    }

    pub fn with_parent(self, parent: &ParentHandle) -> Self {
        self.with_arg("parent", parent)
    }

    pub fn with_publisher(self, publisher: &PublisherHandle) -> Self {
        self.with_arg("publisher", publisher)
    }

    pub fn with_id_ski(self, id_opt: Option<&String>) -> Self {
        self.with_arg("id_key", id_opt.map(|v| v.as_str()).unwrap_or("<none>"))
    }

    pub fn with_resources(self, resources: &ResourceSet) -> Self {
        let summary = resources.summary();
        self.with_arg("resources", resources)
            .with_arg("asn_blocks", summary.asn_bloks())
            .with_arg("ipv4_blocks", summary.ipv4_bloks())
            .with_arg("ipv6_blocks", summary.ipv6_bloks())
    }

    pub fn with_rcn(self, rcn: &ResourceClassName) -> Self {
        self.with_arg("class_name", rcn)
    }

    pub fn with_key(self, ki: &KeyIdentifier) -> Self {
        self.with_arg("key", ki)
    }

    pub fn with_parent_contact(self, contact: &StorableParentContact) -> Self {
        self.with_arg("parent_contact", contact)
    }

    pub fn with_seconds(self, seconds: i64) -> Self {
        self.with_arg("seconds", seconds)
    }

    pub fn with_added(self, nr: usize) -> Self {
        self.with_arg("added", nr)
    }

    pub fn with_removed(self, nr: usize) -> Self {
        self.with_arg("removed", nr)
    }

    pub fn with_service_uri_opt(self, service_uri_opt: Option<&ServiceUri>) -> Self {
        match service_uri_opt {
            None => self,
            Some(uri) => self.with_arg("service_uri", uri),
        }
    }

    pub fn with_rta_name(self, name: &str) -> Self {
        self.with_arg("rta_name", name)
    }
}

//------------ CommandHistoryCriteria ----------------------------------------

/// Used to limit the scope when finding commands to show in the history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label_includes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label_excludes: Option<Vec<String>>,

    offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows_limit: Option<usize>,
}

impl CommandHistoryCriteria {
    pub fn set_excludes(&mut self, labels: &[&str]) {
        self.label_excludes = Some(labels.iter().map(|s| (*s).to_string()).collect());
    }

    pub fn set_includes(&mut self, labels: &[&str]) {
        self.label_includes = Some(labels.iter().map(|s| (*s).to_string()).collect());
    }

    pub fn set_after(&mut self, timestamp: i64) {
        self.after = Some(timestamp);
    }

    pub fn set_before(&mut self, timestamp: i64) {
        self.before = Some(timestamp);
    }

    pub fn set_after_sequence(&mut self, sequence: u64) {
        self.after_sequence = Some(sequence)
    }

    pub fn set_rows(&mut self, rows: usize) {
        self.rows_limit = Some(rows);
    }

    pub fn set_unlimited_rows(&mut self) {
        self.rows_limit = None
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn matches_timestamp_secs(&self, stamp: i64) -> bool {
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

    pub fn matches_sequence(&self, sequence: u64) -> bool {
        match self.after_sequence {
            None => true,
            Some(seq_crit) => sequence > seq_crit,
        }
    }

    #[allow(clippy::ptr_arg)]
    pub fn matches_label(&self, label: &Label) -> bool {
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

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn rows_limit(&self) -> Option<usize> {
        self.rows_limit
    }
}

impl Default for CommandHistoryCriteria {
    fn default() -> Self {
        CommandHistoryCriteria {
            before: None,
            after: None,
            after_sequence: None,
            label_includes: None,
            label_excludes: None,
            offset: 0,
            rows_limit: Some(100),
        }
    }
}

//------------ StorableCaCommand -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum StorableCaCommand {
    MakeTrustAnchor,
    ChildAdd(ChildHandle, Option<String>, ResourceSet),
    ChildUpdateResources(ChildHandle, ResourceSet),
    ChildUpdateId(ChildHandle, String),
    ChildCertify(ChildHandle, ResourceClassName, RequestResourceLimit, KeyIdentifier),
    ChildRevokeKey(ChildHandle, RevocationRequest),
    ChildRemove(ChildHandle),
    GenerateNewIdKey,
    AddParent(ParentHandle, StorableParentContact),
    UpdateParentContact(ParentHandle, StorableParentContact),
    RemoveParent(ParentHandle),
    UpdateResourceClasses(ParentHandle, BTreeMap<ResourceClassName, ResourceSet>),
    UpdateRcvdCert(ResourceClassName, ResourceSet),
    KeyRollInitiate(i64),
    KeyRollActivate(i64),
    KeyRollFinish(ResourceClassName),
    RoaDefinitionUpdates(RoaDefinitionUpdates),
    Republish,
    RepoUpdate(Option<ServiceUri>),
    RepoRemoveOld,
    RtaPrepare(RtaName),
    RtaSign(RtaName),
    RtaCoSign(RtaName),
    Deactivate,
}

impl WithStorableDetails for StorableCaCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableCaCommand::MakeTrustAnchor => CommandSummary::new("cmd-ca-make-ta", &self),
            StorableCaCommand::ChildAdd(child, opt_ski, res) => CommandSummary::new("cmd-ca-child-add", &self)
                .with_child(child)
                .with_id_ski(opt_ski.as_ref())
                .with_resources(res),
            StorableCaCommand::ChildUpdateResources(child, res) => {
                CommandSummary::new("cmd-ca-child-update-res", &self)
                    .with_child(child)
                    .with_resources(res)
            }
            StorableCaCommand::ChildUpdateId(child, id) => CommandSummary::new("cmd-ca-child-update-id", &self)
                .with_child(child)
                .with_id_ski(Some(id)),
            StorableCaCommand::ChildCertify(child, rcn, _limit, ki) => {
                CommandSummary::new("cmd-ca-child-certify", &self)
                    .with_child(child)
                    .with_rcn(rcn)
                    .with_key(ki)
            }
            StorableCaCommand::ChildRemove(child) => {
                CommandSummary::new("cmd-ca-child-remove", &self).with_child(child)
            }
            StorableCaCommand::ChildRevokeKey(child, revoke_request) => {
                CommandSummary::new("cmd-ca-child-revoke", &self)
                    .with_child(child)
                    .with_rcn(revoke_request.class_name())
                    .with_key(revoke_request.key())
            }
            StorableCaCommand::GenerateNewIdKey => CommandSummary::new("cmd-ca-generate-new-id", &self),
            StorableCaCommand::AddParent(parent, contact) => CommandSummary::new("cmd-ca-parent-add", &self)
                .with_parent(parent)
                .with_parent_contact(contact),
            StorableCaCommand::UpdateParentContact(parent, contact) => {
                CommandSummary::new("cmd-ca-parent-update", &self)
                    .with_parent(parent)
                    .with_parent_contact(contact)
            }
            StorableCaCommand::RemoveParent(parent) => {
                CommandSummary::new("cmd-ca-parent-remove", &self).with_parent(parent)
            }
            StorableCaCommand::UpdateResourceClasses(parent, _) => {
                CommandSummary::new("cmd-ca-parent-entitlements", &self).with_parent(parent)
            }
            StorableCaCommand::UpdateRcvdCert(rcn, res) => CommandSummary::new("cmd-ca-rcn-receive", &self)
                .with_rcn(rcn)
                .with_resources(res),
            StorableCaCommand::KeyRollInitiate(seconds) => {
                CommandSummary::new("cmd-ca-keyroll-init", &self).with_seconds(*seconds)
            }
            StorableCaCommand::KeyRollActivate(seconds) => {
                CommandSummary::new("cmd-ca-keyroll-activate", &self).with_seconds(*seconds)
            }
            StorableCaCommand::KeyRollFinish(rcn) => CommandSummary::new("cmd-ca-keyroll-finish", &self).with_rcn(rcn),
            StorableCaCommand::RoaDefinitionUpdates(updates) => CommandSummary::new("cmd-ca-roas-updated", &self)
                .with_added(updates.added().len())
                .with_removed(updates.removed().len()),
            StorableCaCommand::Republish => CommandSummary::new("cmd-ca-publish", &self),
            StorableCaCommand::RepoUpdate(service_uri_opt) => {
                CommandSummary::new("cmd-ca-repo-update", &self).with_service_uri_opt(service_uri_opt.as_ref())
            }
            StorableCaCommand::RepoRemoveOld => CommandSummary::new("cmd-ca-repo-clean", &self),

            // RTA
            StorableCaCommand::RtaPrepare(name) => CommandSummary::new("cmd-ca-rta-prepare", &self).with_rta_name(name),
            StorableCaCommand::RtaSign(name) => CommandSummary::new("cmd-ca-rta-sign", &self).with_rta_name(name),
            StorableCaCommand::RtaCoSign(name) => CommandSummary::new("cmd-ca-rta-cosign", &self).with_rta_name(name),

            // Deactivation
            StorableCaCommand::Deactivate => CommandSummary::new("cmd-ca-deactivate", &self),
        }
    }
}

impl fmt::Display for StorableCaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // ------------------------------------------------------------
            // Becoming a trust anchor
            // ------------------------------------------------------------
            StorableCaCommand::MakeTrustAnchor => write!(f, "Turn into Trust Anchor"),

            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
            StorableCaCommand::ChildAdd(child, id_ski_opt, res) => write!(
                f,
                "Add child '{}' with RFC8183 key '{}' and resources '{}'",
                child,
                id_ski_opt.as_ref().map(|ski| ski.as_str()).unwrap_or_else(|| "<none>"),
                res.summary()
            ),
            StorableCaCommand::ChildUpdateResources(child, resources) => {
                write!(f, "Update resources for child '{}' to: {}", child, resources.summary())
            }
            StorableCaCommand::ChildUpdateId(child, id_ski) => {
                write!(f, "Update child '{}' RFC 8183 key '{}'", child, id_ski)
            }
            StorableCaCommand::ChildCertify(child, _rcn, _limit, key) => {
                write!(f, "Issue certificate to child '{}' for key '{}'", child, key)
            }
            StorableCaCommand::ChildRevokeKey(child, req) => write!(
                f,
                "Revoke certificates for child '{}' for key '{}' in RC {}",
                child,
                req.key(),
                req.class_name()
            ),
            StorableCaCommand::ChildRemove(child) => write!(f, "Remove child '{}' and revoke&remove its certs", child),

            // ------------------------------------------------------------
            // Being a child (only allowed if this CA is not self-signed)
            // ------------------------------------------------------------
            StorableCaCommand::GenerateNewIdKey => write!(f, "Generate a new RFC8183 ID."),
            StorableCaCommand::AddParent(parent, contact) => write!(f, "Add parent '{}' as '{}'", parent, contact),
            StorableCaCommand::UpdateParentContact(parent, contact) => {
                write!(f, "Update contact for parent '{}' to '{}'", parent, contact)
            }
            StorableCaCommand::RemoveParent(parent) => write!(f, "Remove parent '{}'", parent),

            StorableCaCommand::UpdateResourceClasses(parent, classes) => {
                let mut summary = format!("Update entitlements under parent '{}': ", parent);

                for (class_name, resource_set) in classes.iter() {
                    summary.push_str(&format!("{} => {} ", class_name, resource_set.summary()))
                }

                write!(f, "{}", summary)
            }
            // Process a new certificate received from a parent.
            StorableCaCommand::UpdateRcvdCert(rcn, resources) => write!(
                f,
                "Update received cert in RC '{}', with resources '{}'",
                rcn,
                resources.summary()
            ),

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            StorableCaCommand::KeyRollInitiate(duration) => {
                write!(f, "Initiate key roll for keys older than '{}' seconds", duration)
            }
            StorableCaCommand::KeyRollActivate(duration) => {
                write!(f, "Activate new keys staging longer than '{}' seconds", duration)
            }

            StorableCaCommand::KeyRollFinish(rcn) => write!(f, "Retire old revoked key in RC '{}'", rcn),

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            StorableCaCommand::RoaDefinitionUpdates(updates) => write!(
                f,
                "Update ROAs add: {} remove: '{}'",
                updates.added().len(),
                updates.removed().len()
            ),

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            StorableCaCommand::Republish => write!(f, "Republish"),
            StorableCaCommand::RepoUpdate(service_uri_opt) => match service_uri_opt {
                None => write!(f, "Update repo to embedded server"),
                Some(uri) => write!(f, "Update repo to server at: {}", uri),
            },
            StorableCaCommand::RepoRemoveOld => write!(f, "Clean up old repository"),

            // ------------------------------------------------------------
            // RTA
            // ------------------------------------------------------------
            StorableCaCommand::RtaPrepare(name) => write!(f, "RTA Prepare {}", name),
            StorableCaCommand::RtaSign(name) => write!(f, "RTA Sign {}", name),
            StorableCaCommand::RtaCoSign(name) => write!(f, "RTA Co-Sign {}", name),

            // ------------------------------------------------------------
            // Deactivate
            // ------------------------------------------------------------
            StorableCaCommand::Deactivate => write!(f, "Deactivate CA"),
        }
    }
}

//------------ StorableRepositoryCommand -----------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum StorableRepositoryCommand {
    AddPublisher(PublisherHandle, String),
    RemovePublisher(PublisherHandle),
    Publish(PublisherHandle, usize, usize, usize),
    SessionReset,
}

impl WithStorableDetails for StorableRepositoryCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableRepositoryCommand::AddPublisher(publisher, ski) => CommandSummary::new("pubd-publisher-add", &self)
                .with_publisher(publisher)
                .with_id_ski(Some(ski)),
            StorableRepositoryCommand::RemovePublisher(publisher) => {
                CommandSummary::new("pubd-publisher-remove", &self).with_publisher(publisher)
            }
            StorableRepositoryCommand::Publish(publisher, published, updated, withdrawn) => {
                CommandSummary::new("pubd-publish", &self)
                    .with_publisher(publisher)
                    .with_arg("published", published)
                    .with_arg("updated", updated)
                    .with_arg("withdrawn", withdrawn)
            }
            StorableRepositoryCommand::SessionReset => CommandSummary::new("pubd-session-reset", &self),
        }
    }
}

impl fmt::Display for StorableRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableRepositoryCommand::AddPublisher(pbl, ski) => {
                write!(f, "Added publisher '{}' with RFC8183 key '{}'", pbl, ski)
            }
            StorableRepositoryCommand::RemovePublisher(pbl) => write!(f, "Removed publisher '{}'", pbl),
            StorableRepositoryCommand::Publish(pbl, published, updated, withdrawn) => write!(
                f,
                "Published for '{}': {} published, {} updated, {} withdrawn",
                pbl, published, updated, withdrawn
            ),
            StorableRepositoryCommand::SessionReset => write!(f, "Publication server session reset"),
        }
    }
}
