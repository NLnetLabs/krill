use std::collections::HashMap;
use std::fmt;

use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::{
    ArgKey, ArgVal, ChildHandle, Handle, Label, Message, ParentHandle, PublisherHandle,
    RequestResourceLimit, ResourceClassName, ResourceSet, RevocationRequest, RoaDefinitionUpdates,
    StorableParentContact,
};
use crate::commons::eventsourcing::WithStorableDetails;
use crate::commons::remote::rfc8183::ServiceUri;

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

//------------ CommandHistoryRecord ------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Does not include the full stored command details, but only
/// the summary which is shown in the history response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryRecord {
    pub actor: String,
    pub time: Time,
    pub handle: Handle,
    pub version: u64,
    pub sequence: u64,
    pub summary: CommandSummary,
    pub effect: StoredEffect,
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
}

//------------ CommandSummary ------------------------------------------------

/// Generic command summary used to show command details in history in a way
/// that support internationalisation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandSummary {
    pub msg: Message,
    pub label: Label,
    pub args: HashMap<ArgKey, ArgVal>,
}

impl CommandSummary {
    pub fn new(label: &str, msg: impl fmt::Display) -> Self {
        CommandSummary {
            msg: msg.to_string(),
            label: label.to_string(),
            args: HashMap::new(),
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
        self.with_arg("resources", resources)
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
}

//------------ CommandHistoryCriteria ----------------------------------------

/// Used to limit the scope when finding commands to show in the history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label_includes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label_excludes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<usize>,
}

impl CommandHistoryCriteria {
    pub fn exclude(mut self, labels: &[&str]) -> Self {
        self.label_excludes = Some(labels.iter().map(|s| (*s).to_string()).collect());
        self
    }

    pub fn paginate(mut self, offset: usize, rows: usize) -> Self {
        self.offset = Some(offset);
        self.rows = Some(rows);
        self
    }

    pub fn should_include(&self, record: &CommandHistoryRecord) -> bool {
        if let Some(actor) = &self.actor {
            if &record.actor != actor {
                return false;
            }
        }
        if let Some(before) = &self.before {
            if record.time.timestamp() > before.timestamp() {
                return false;
            }
        }
        if let Some(after) = &self.after {
            if record.time.timestamp() < after.timestamp() {
                return false;
            }
        }
        if let Some(includes) = &self.label_includes {
            if !includes.contains(&record.summary.label) {
                return false;
            }
        }
        if let Some(excludes) = &self.label_excludes {
            if excludes.contains(&record.summary.label) {
                return false;
            }
        }
        if let Some(result) = self.result {
            if result != record.effect.successful() {
                return false;
            }
        }
        true
    }

    pub fn offset(&self) -> usize {
        self.offset.unwrap_or_else(|| 0)
    }

    pub fn rows(&self) -> Option<usize> {
        self.rows
    }
}

impl Default for CommandHistoryCriteria {
    fn default() -> Self {
        CommandHistoryCriteria {
            actor: None,
            before: None,
            after: None,
            label_includes: None,
            label_excludes: None,
            offset: None,
            rows: None,
            result: None,
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
    ChildCertify(
        ChildHandle,
        ResourceClassName,
        RequestResourceLimit,
        KeyIdentifier,
    ),
    ChildRevokeKey(ChildHandle, RevocationRequest),
    ChildRemove(ChildHandle),
    GenerateNewIdKey,
    AddParent(ParentHandle, StorableParentContact),
    UpdateParentContact(ParentHandle, StorableParentContact),
    RemoveParent(ParentHandle),
    UpdateResourceClasses(ParentHandle, HashMap<ResourceClassName, ResourceSet>),
    UpdateRcvdCert(ResourceClassName, ResourceSet),
    KeyRollInitiate(i64),
    KeyRollActivate(i64),
    KeyRollFinish(ResourceClassName),
    RoaDefinitionUpdates(RoaDefinitionUpdates),
    Republish,
    RepoUpdate(Option<ServiceUri>),
    RepoRemoveOld,
}

impl WithStorableDetails for StorableCaCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableCaCommand::MakeTrustAnchor => CommandSummary::new("cmd-ca-make-ta", &self),
            StorableCaCommand::ChildAdd(child, opt_ski, res) => {
                CommandSummary::new("cmd-ca-child-add", &self)
                    .with_child(child)
                    .with_id_ski(opt_ski.as_ref())
                    .with_resources(res)
            }
            StorableCaCommand::ChildUpdateResources(child, res) => {
                CommandSummary::new("cmd-ca-child-update-res", &self)
                    .with_child(child)
                    .with_resources(res)
            }
            StorableCaCommand::ChildUpdateId(child, id) => {
                CommandSummary::new("cmd-ca-child-update-id", &self)
                    .with_child(child)
                    .with_id_ski(Some(id))
            }
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
            StorableCaCommand::GenerateNewIdKey => {
                CommandSummary::new("cmd-ca-generate-new-id", &self)
            }
            StorableCaCommand::AddParent(parent, contact) => {
                CommandSummary::new("cmd-ca-parent-add", &self)
                    .with_parent(parent)
                    .with_parent_contact(contact)
            }
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
            StorableCaCommand::UpdateRcvdCert(rcn, res) => {
                CommandSummary::new("cmd-ca-rcn-receive", &self)
                    .with_rcn(rcn)
                    .with_resources(res)
            }
            StorableCaCommand::KeyRollInitiate(seconds) => {
                CommandSummary::new("cmd-ca-keyroll-init", &self).with_seconds(*seconds)
            }
            StorableCaCommand::KeyRollActivate(seconds) => {
                CommandSummary::new("cmd-ca-keyroll-activate", &self).with_seconds(*seconds)
            }
            StorableCaCommand::KeyRollFinish(rcn) => {
                CommandSummary::new("cmd-ca-keyroll-finish", &self).with_rcn(rcn)
            }
            StorableCaCommand::RoaDefinitionUpdates(updates) => {
                CommandSummary::new("cmd-ca-roas-updated", &self)
                    .with_added(updates.added().len())
                    .with_removed(updates.removed().len())
            }
            StorableCaCommand::Republish => CommandSummary::new("cmd-ca-publish", &self),
            StorableCaCommand::RepoUpdate(service_uri_opt) => {
                CommandSummary::new("cmd-ca-repo-update", &self)
                    .with_service_uri_opt(service_uri_opt.as_ref())
            }
            StorableCaCommand::RepoRemoveOld => CommandSummary::new("cmd-ca-repo-clean", &self),
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
                id_ski_opt
                    .as_ref()
                    .map(|ski| ski.as_str())
                    .unwrap_or_else(|| "<none>"),
                res
            ),
            StorableCaCommand::ChildUpdateResources(child, resources) => {
                write!(f, "Update child '{}' resources to: {}", child, resources)
            }
            StorableCaCommand::ChildUpdateId(child, id_ski) => {
                write!(f, "Update child '{}' RFC 8183 key '{}'", child, id_ski)
            }
            StorableCaCommand::ChildCertify(child, _rcn, _limit, key) => {
                write!(f, "Issue certificate to child '{}' for key '{}", child, key)
            }
            StorableCaCommand::ChildRevokeKey(child, req) => write!(
                f,
                "Revoke certificates for child '{}' for key '{}' in RC {}",
                child,
                req.key(),
                req.class_name()
            ),
            StorableCaCommand::ChildRemove(child) => {
                write!(f, "Remove child '{}' and revoke&remove its certs", child)
            }

            // ------------------------------------------------------------
            // Being a child (only allowed if this CA is not self-signed)
            // ------------------------------------------------------------
            StorableCaCommand::GenerateNewIdKey => write!(f, "Generate a new RFC8183 ID."),
            StorableCaCommand::AddParent(parent, contact) => {
                write!(f, "Add parent '{}' as '{}'", parent, contact)
            }
            StorableCaCommand::UpdateParentContact(parent, contact) => {
                write!(f, "Update contact for parent '{}' to '{}'", parent, contact)
            }
            StorableCaCommand::RemoveParent(parent) => write!(f, "Remove parent '{}'", parent),

            StorableCaCommand::UpdateResourceClasses(parent, classes) => {
                let mut summary = format!("Update entitlements under parent '{}': ", parent);

                for (class_name, resource_set) in classes.iter() {
                    summary.push_str(&format!("{} => {} ", class_name, resource_set))
                }

                write!(f, "{}", summary)
            }
            // Process a new certificate received from a parent.
            StorableCaCommand::UpdateRcvdCert(rcn, resources) => write!(
                f,
                "Update received cert in RC '{}', with resources '{}'",
                rcn, resources
            ),

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            StorableCaCommand::KeyRollInitiate(duration) => write!(
                f,
                "Initiate key roll for keys older than '{}' seconds",
                duration
            ),
            StorableCaCommand::KeyRollActivate(duration) => write!(
                f,
                "Activate new keys staging longer than '{}' seconds",
                duration
            ),

            StorableCaCommand::KeyRollFinish(rcn) => {
                write!(f, "Retire old revoked key in RC '{}'", rcn)
            }

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
}

impl WithStorableDetails for StorableRepositoryCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableRepositoryCommand::AddPublisher(publisher, ski) => {
                CommandSummary::new("pubd-publisher-add", &self)
                    .with_publisher(publisher)
                    .with_id_ski(Some(ski))
            }
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
        }
    }
}

impl fmt::Display for StorableRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableRepositoryCommand::AddPublisher(pbl, ski) => {
                write!(f, "Added publisher '{}' with RFC8183 key '{}'", pbl, ski)
            }
            StorableRepositoryCommand::RemovePublisher(pbl) => {
                write!(f, "Removed publisher '{}'", pbl)
            }
            StorableRepositoryCommand::Publish(pbl, published, updated, withdrawn) => write!(
                f,
                "Published for '{}': {} published, {} updated, {} withdrawn",
                pbl, published, updated, withdrawn
            ),
        }
    }
}
