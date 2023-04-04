use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};

use rpki::{
    ca::{
        idexchange::{ChildHandle, MyHandle, ParentHandle, PublisherHandle, ServiceUri},
        provisioning::{RequestResourceLimit, ResourceClassName, RevocationRequest},
    },
    crypto::KeyIdentifier,
    repository::{resources::ResourceSet, x509::Time},
    rrdp::Hash,
};

use crate::{
    commons::{
        api::{
            ArgKey, ArgVal, AspaCustomer, AspaProvidersUpdate, Label, Message, RoaConfigurationUpdates, RtaName,
            StorableParentContact,
        },
        eventsourcing::{CommandKey, CommandKeyError, StoredCommand, WithStorableDetails},
    },
    daemon::ca::{self, DropReason},
};

use super::{AspaDefinitionUpdates, ResourceSetSummary};

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
            CaCommandResult::Events(events) => {
                writeln!(f, "Changes:")?;
                for evt in events {
                    writeln!(f, "  {}", evt.details())?;
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
                StoredEffect::Error { msg } => format!("ERROR -> {}", msg),
                StoredEffect::Success { .. } => "OK".to_string(),
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
    pub handle: MyHandle,
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
#[serde(rename_all = "snake_case", tag = "result")]
pub enum StoredEffect {
    Error { msg: String },
    Success { events: Vec<u64> },
}

impl StoredEffect {
    pub fn successful(&self) -> bool {
        match self {
            StoredEffect::Error { .. } => false,
            StoredEffect::Success { .. } => true,
        }
    }

    pub fn events(&self) -> Option<&Vec<u64>> {
        match self {
            StoredEffect::Error { .. } => None,
            StoredEffect::Success { events } => Some(events),
        }
    }
}

//------------ CommandSummary ------------------------------------------------

/// Generic command summary used to show command details in history in a way
/// that support internationalization.
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

    pub fn with_id_ski(self, id: &str) -> Self {
        self.with_arg("id_key", id)
    }

    pub fn with_resources(self, resources: &ResourceSet) -> Self {
        let summary = ResourceSetSummary::from(resources);
        self.with_arg("resources", resources)
            .with_arg("asn_blocks", summary.asn_blocks())
            .with_arg("ipv4_blocks", summary.ipv4_blocks())
            .with_arg("ipv6_blocks", summary.ipv6_blocks())
    }

    pub fn with_rcn(self, rcn: &ResourceClassName) -> Self {
        self.with_arg("class_name", rcn)
    }

    pub fn with_key(self, ki: KeyIdentifier) -> Self {
        self.with_arg("key", ki)
    }

    pub fn with_id_cert_hash(self, hash: &Hash) -> Self {
        self.with_arg("id_cert_hash", hash)
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

    pub fn with_service_uri(self, service_uri: &ServiceUri) -> Self {
        self.with_arg("service_uri", service_uri)
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
#[serde(tag = "type")]
pub enum StorableCaCommand {
    ChildAdd {
        child: ChildHandle,
        ski: String,
        resources: ResourceSet,
    },
    ChildUpdateResources {
        child: ChildHandle,
        resources: ResourceSet,
    },
    ChildUpdateId {
        child: ChildHandle,
        ski: String,
    },
    ChildCertify {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        limit: RequestResourceLimit,
        ki: KeyIdentifier,
    },
    ChildRevokeKey {
        child: ChildHandle,
        revoke_req: RevocationRequest,
    },
    ChildRemove {
        child: ChildHandle,
    },
    ChildSuspendInactive {
        child: ChildHandle,
    },
    ChildUnsuspend {
        child: ChildHandle,
    },
    GenerateNewIdKey,
    AddParent {
        parent: ParentHandle,
        contact: StorableParentContact,
    },
    UpdateParentContact {
        parent: ParentHandle,
        contact: StorableParentContact,
    },
    RemoveParent {
        parent: ParentHandle,
    },
    UpdateResourceEntitlements {
        parent: ParentHandle,
        entitlements: Vec<StorableRcEntitlement>,
    },
    UpdateRcvdCert {
        resource_class_name: ResourceClassName,
        resources: ResourceSet,
    },
    DropResourceClass {
        resource_class_name: ResourceClassName,
        reason: DropReason,
    },
    KeyRollInitiate {
        older_than_seconds: i64,
    },
    KeyRollActivate {
        staged_for_seconds: i64,
    },
    KeyRollFinish {
        resource_class_name: ResourceClassName,
    },
    RoaDefinitionUpdates {
        updates: RoaConfigurationUpdates,
    },
    ReissueBeforeExpiring,
    ForceReissue,
    AspasUpdate {
        updates: AspaDefinitionUpdates,
    },
    AspasUpdateExisting {
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
    },
    AspaRemove {
        customer: AspaCustomer,
    },
    BgpSecDefinitionUpdates, // details in events
    RepoUpdate {
        service_uri: ServiceUri,
    },
    RtaPrepare {
        name: RtaName,
    },
    RtaSign {
        name: RtaName,
    },
    RtaCoSign {
        name: RtaName,
    },
    Deactivate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorableRcEntitlement {
    pub resource_class_name: ResourceClassName,
    pub resources: ResourceSet,
}

impl WithStorableDetails for StorableCaCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableCaCommand::ChildAdd { child, ski, resources } => CommandSummary::new("cmd-ca-child-add", self)
                .with_child(child)
                .with_id_ski(ski.as_ref())
                .with_resources(resources),
            StorableCaCommand::ChildUpdateResources { child, resources } => {
                CommandSummary::new("cmd-ca-child-update-res", self)
                    .with_child(child)
                    .with_resources(resources)
            }
            StorableCaCommand::ChildUpdateId { child, ski } => CommandSummary::new("cmd-ca-child-update-id", self)
                .with_child(child)
                .with_id_ski(ski),
            StorableCaCommand::ChildCertify {
                child,
                resource_class_name,
                ki,
                ..
            } => CommandSummary::new("cmd-ca-child-certify", self)
                .with_child(child)
                .with_rcn(resource_class_name)
                .with_key(*ki),
            StorableCaCommand::ChildRemove { child } => {
                CommandSummary::new("cmd-ca-child-remove", self).with_child(child)
            }
            StorableCaCommand::ChildSuspendInactive { child } => {
                CommandSummary::new("cmd-ca-child-suspend-inactive", self).with_child(child)
            }
            StorableCaCommand::ChildUnsuspend { child } => {
                CommandSummary::new("cmd-ca-child-unsuspend", self).with_child(child)
            }
            StorableCaCommand::ChildRevokeKey { child, revoke_req } => CommandSummary::new("cmd-ca-child-revoke", self)
                .with_child(child)
                .with_rcn(revoke_req.class_name())
                .with_key(revoke_req.key()),
            StorableCaCommand::GenerateNewIdKey => CommandSummary::new("cmd-ca-generate-new-id", self),
            StorableCaCommand::AddParent { parent, contact } => CommandSummary::new("cmd-ca-parent-add", self)
                .with_parent(parent)
                .with_parent_contact(contact),
            StorableCaCommand::UpdateParentContact { parent, contact } => {
                CommandSummary::new("cmd-ca-parent-update", self)
                    .with_parent(parent)
                    .with_parent_contact(contact)
            }
            StorableCaCommand::RemoveParent { parent } => {
                CommandSummary::new("cmd-ca-parent-remove", self).with_parent(parent)
            }
            StorableCaCommand::UpdateResourceEntitlements { parent, .. } => {
                CommandSummary::new("cmd-ca-parent-entitlements", self).with_parent(parent)
            }
            StorableCaCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => CommandSummary::new("cmd-ca-rcn-receive", self)
                .with_rcn(resource_class_name)
                .with_resources(resources),
            StorableCaCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => CommandSummary::new("cmd-ca-rc-drop", self)
                .with_rcn(resource_class_name)
                .with_arg("reason", reason),

            // Key rolls
            StorableCaCommand::KeyRollInitiate { older_than_seconds } => {
                CommandSummary::new("cmd-ca-keyroll-init", self).with_seconds(*older_than_seconds)
            }
            StorableCaCommand::KeyRollActivate { staged_for_seconds } => {
                CommandSummary::new("cmd-ca-keyroll-activate", self).with_seconds(*staged_for_seconds)
            }
            StorableCaCommand::KeyRollFinish { resource_class_name } => {
                CommandSummary::new("cmd-ca-keyroll-finish", self).with_rcn(resource_class_name)
            }

            // ROA
            StorableCaCommand::RoaDefinitionUpdates { updates } => CommandSummary::new("cmd-ca-roas-updated", self)
                .with_added(updates.added().len())
                .with_removed(updates.removed().len()),

            // ASPA
            StorableCaCommand::AspasUpdate { .. } => CommandSummary::new("cmd-ca-aspas-update", self),
            StorableCaCommand::AspasUpdateExisting { .. } => CommandSummary::new("cmd-ca-aspas-update-existing", self),
            StorableCaCommand::AspaRemove { .. } => CommandSummary::new("cmd-ca-aspas-remove", self),

            // BGPSec
            StorableCaCommand::BgpSecDefinitionUpdates => CommandSummary::new("cmd-bgpsec-update", self),

            // REPO
            StorableCaCommand::RepoUpdate { service_uri } => {
                CommandSummary::new("cmd-ca-repo-update", self).with_service_uri(service_uri)
            }

            StorableCaCommand::ReissueBeforeExpiring => CommandSummary::new("cmd-ca-reissue-before-expiring", self),
            StorableCaCommand::ForceReissue => CommandSummary::new("cmd-ca-force-reissue", self),

            // RTA
            StorableCaCommand::RtaPrepare { name } => {
                CommandSummary::new("cmd-ca-rta-prepare", self).with_rta_name(name)
            }
            StorableCaCommand::RtaSign { name } => CommandSummary::new("cmd-ca-rta-sign", self).with_rta_name(name),
            StorableCaCommand::RtaCoSign { name } => CommandSummary::new("cmd-ca-rta-cosign", self).with_rta_name(name),

            // Deactivation
            StorableCaCommand::Deactivate => CommandSummary::new("cmd-ca-deactivate", self),
        }
    }
}

impl fmt::Display for StorableCaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
            StorableCaCommand::ChildAdd { child, ski, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(
                    f,
                    "Add child '{}' with RFC8183 key '{}' and resources '{}'",
                    child, ski, summary
                )
            }
            StorableCaCommand::ChildUpdateResources { child, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f, "Update resources for child '{}' to: {}", child, summary)
            }
            StorableCaCommand::ChildUpdateId { child, ski } => {
                write!(f, "Update child '{}' RFC 8183 key '{}'", child, ski)
            }
            StorableCaCommand::ChildCertify { child, ki, .. } => {
                write!(f, "Issue certificate to child '{}' for key '{}'", child, ki)
            }
            StorableCaCommand::ChildRevokeKey { child, revoke_req } => write!(
                f,
                "Revoke certificates for child '{}' for key '{}' in RC {}",
                child,
                revoke_req.key(),
                revoke_req.class_name()
            ),
            StorableCaCommand::ChildRemove { child } => {
                write!(f, "Remove child '{}' and revoke & remove its certs", child)
            }
            StorableCaCommand::ChildSuspendInactive { child } => {
                write!(f, "Suspend inactive child '{}': stop publishing its certs", child)
            }
            StorableCaCommand::ChildUnsuspend { child } => {
                write!(f, "Unsuspend child '{}': publish its unexpired certs", child)
            }

            // ------------------------------------------------------------
            // Being a child (only allowed if this CA is not self-signed)
            // ------------------------------------------------------------
            StorableCaCommand::GenerateNewIdKey => write!(f, "Generate a new RFC8183 ID."),
            StorableCaCommand::AddParent { parent, contact } => write!(f, "Add parent '{}' as '{}'", parent, contact),
            StorableCaCommand::UpdateParentContact { parent, contact } => {
                write!(f, "Update contact for parent '{}' to '{}'", parent, contact)
            }
            StorableCaCommand::RemoveParent { parent } => write!(f, "Remove parent '{}'", parent),

            StorableCaCommand::UpdateResourceEntitlements { parent, entitlements } => {
                write!(f, "Update entitlements under parent '{}': ", parent)?;

                for entitlement in entitlements.iter() {
                    write!(f, "{} => {} ", entitlement.resource_class_name, entitlement.resources)?;
                }

                Ok(())
            }
            // Process a new certificate received from a parent.
            StorableCaCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => {
                let summary = ResourceSetSummary::from(resources);
                write!(
                    f,
                    "Update received cert in RC '{}', with resources '{}'",
                    resource_class_name, summary
                )
            }
            StorableCaCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => write!(
                f,
                "Removing resource class '{}' because of reason: {}",
                resource_class_name, reason
            ),

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            StorableCaCommand::KeyRollInitiate { older_than_seconds } => {
                write!(
                    f,
                    "Initiate key roll for keys older than '{}' seconds",
                    older_than_seconds
                )
            }
            StorableCaCommand::KeyRollActivate { staged_for_seconds } => {
                write!(
                    f,
                    "Activate new keys staging longer than '{}' seconds",
                    staged_for_seconds
                )
            }

            StorableCaCommand::KeyRollFinish { resource_class_name } => {
                write!(f, "Retire old revoked key in RC '{}'", resource_class_name)
            }

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            StorableCaCommand::RoaDefinitionUpdates { updates } => {
                write!(f, "Update ROAs",)?;
                if !updates.added().is_empty() {
                    write!(f, "  ADD:",)?;
                    for addition in updates.added() {
                        write!(f, " {}", addition)?;
                    }
                }
                if !updates.removed().is_empty() {
                    write!(f, "  REMOVE:",)?;
                    for rem in updates.removed() {
                        write!(f, " {}", rem)?;
                    }
                }
                Ok(())
            }
            StorableCaCommand::ReissueBeforeExpiring => {
                write!(f, "Automatically re-issue objects before they would expire")
            }
            StorableCaCommand::ForceReissue => {
                write!(f, "Force re-issuance of objects")
            }

            // ------------------------------------------------------------
            // ASPA Support
            // ------------------------------------------------------------
            StorableCaCommand::AspasUpdate { updates } => {
                write!(f, "{}", updates)
            }
            StorableCaCommand::AspasUpdateExisting { customer, update } => {
                write!(f, "update ASPA for customer AS: {} {}", customer, update)
            }
            StorableCaCommand::AspaRemove { customer } => {
                write!(f, "Remove ASPA for customer AS: {}", customer)
            }

            // ------------------------------------------------------------
            // BGPSec Support
            // ------------------------------------------------------------
            StorableCaCommand::BgpSecDefinitionUpdates => write!(f, "Update BGPSec definitions"),

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            StorableCaCommand::RepoUpdate { service_uri } => write!(f, "Update repo to server at: {}", service_uri),

            // ------------------------------------------------------------
            // RTA
            // ------------------------------------------------------------
            StorableCaCommand::RtaPrepare { name } => write!(f, "RTA Prepare {}", name),
            StorableCaCommand::RtaSign { name } => write!(f, "RTA Sign {}", name),
            StorableCaCommand::RtaCoSign { name } => write!(f, "RTA Co-Sign {}", name),

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
#[serde(rename_all = "snake_case", tag = "type")]
pub enum StorableRepositoryCommand {
    AddPublisher { name: PublisherHandle },
    RemovePublisher { name: PublisherHandle },
}

impl WithStorableDetails for StorableRepositoryCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableRepositoryCommand::AddPublisher { name } => {
                CommandSummary::new("pubd-publisher-add", self).with_publisher(name)
            }
            StorableRepositoryCommand::RemovePublisher { name } => {
                CommandSummary::new("pubd-publisher-remove", self).with_publisher(name)
            }
        }
    }
}

impl fmt::Display for StorableRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableRepositoryCommand::AddPublisher { name } => {
                write!(f, "Added publisher '{}'", name)
            }
            StorableRepositoryCommand::RemovePublisher { name } => write!(f, "Removed publisher '{}'", name),
        }
    }
}
