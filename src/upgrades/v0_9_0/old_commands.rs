use rpki::{crypto::KeyIdentifier, x509::Time};

use std::{collections::BTreeMap, fmt};

use crate::{
    commons::{
        api::{
            ChildHandle, Handle, ParentHandle, PublisherHandle, RequestResourceLimit, ResourceClassName, ResourceSet,
            RevocationRequest, RoaDefinitionUpdates, RtaName, StorableCaCommand, StorableParentContact,
            StorableRcEntitlement, StorableRepositoryCommand, StoredEffect,
        },
        eventsourcing::{Command, StoredCommand, WithStorableDetails},
        remote::rfc8183::ServiceUri,
    },
    daemon::ca::StoredCaCommand,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredCaCommand {
    pub actor: String,
    pub time: Time,
    pub handle: Handle,
    pub version: u64,  // version of aggregate this was applied to (successful or not)
    pub sequence: u64, // command sequence (i.e. also incremented for failed commands)
    pub details: OldStorableCaCommand,
    pub effect: OldStoredEffect,
}

impl OldStoredCaCommand {
    pub fn into_ca_command(self) -> StoredCaCommand {
        let (actor, time, handle, version, sequence, details, effect) = (
            self.actor,
            self.time,
            self.handle,
            self.version,
            self.sequence,
            self.details.into(),
            self.effect.into(),
        );

        StoredCaCommand::new(actor, time, handle, version, sequence, details, effect)
    }

    pub fn set_events(&mut self, events: Vec<u64>) {
        self.effect = OldStoredEffect::Events(events);
    }
}

impl fmt::Display for OldStoredCaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA command")
    }
}

impl Command for OldStoredCaCommand {
    type StorableDetails = OldStorableCaCommand;

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
pub enum OldStoredEffect {
    Error(String),
    Events(Vec<u64>),
}

impl OldStoredEffect {
    pub fn events(&self) -> Option<&Vec<u64>> {
        match self {
            OldStoredEffect::Events(evts) => Some(evts),
            OldStoredEffect::Error(_) => None,
        }
    }
}

impl From<OldStoredEffect> for StoredEffect {
    fn from(old: OldStoredEffect) -> Self {
        match old {
            OldStoredEffect::Error(msg) => StoredEffect::Error(msg),
            OldStoredEffect::Events(evts) => StoredEffect::Events(evts),
        }
    }
}

//------------ StorableCaCommand -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldStorableCaCommand {
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

impl WithStorableDetails for OldStorableCaCommand {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        unimplemented!("not needed for migration")
    }
}

impl From<OldStorableCaCommand> for StorableCaCommand {
    fn from(old: OldStorableCaCommand) -> Self {
        match old {
            OldStorableCaCommand::MakeTrustAnchor => StorableCaCommand::MakeTrustAnchor,
            OldStorableCaCommand::ChildAdd(child, ski, resources) => {
                StorableCaCommand::ChildAdd { child, ski, resources }
            }
            OldStorableCaCommand::ChildUpdateResources(child, resources) => {
                StorableCaCommand::ChildUpdateResources { child, resources }
            }
            OldStorableCaCommand::ChildUpdateId(child, ski) => StorableCaCommand::ChildUpdateId { child, ski },
            OldStorableCaCommand::ChildCertify(child, resource_class_name, limit, ki) => {
                StorableCaCommand::ChildCertify {
                    child,
                    resource_class_name,
                    limit,
                    ki,
                }
            }
            OldStorableCaCommand::ChildRevokeKey(child, revoke_req) => {
                StorableCaCommand::ChildRevokeKey { child, revoke_req }
            }
            OldStorableCaCommand::ChildRemove(child) => StorableCaCommand::ChildRemove { child },

            OldStorableCaCommand::GenerateNewIdKey => StorableCaCommand::GenerateNewIdKey,

            OldStorableCaCommand::AddParent(parent, contact) => StorableCaCommand::AddParent { parent, contact },
            OldStorableCaCommand::UpdateParentContact(parent, contact) => {
                StorableCaCommand::UpdateParentContact { parent, contact }
            }
            OldStorableCaCommand::RemoveParent(parent) => StorableCaCommand::RemoveParent { parent },

            OldStorableCaCommand::UpdateResourceClasses(parent, map) => {
                let entitlements = map
                    .into_iter()
                    .map(|(resource_class_name, resources)| StorableRcEntitlement {
                        resource_class_name,
                        resources,
                    })
                    .collect();
                StorableCaCommand::UpdateResourceEntitlements { parent, entitlements }
            }
            OldStorableCaCommand::UpdateRcvdCert(resource_class_name, resources) => StorableCaCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            },

            OldStorableCaCommand::KeyRollInitiate(older_than_seconds) => {
                StorableCaCommand::KeyRollInitiate { older_than_seconds }
            }
            OldStorableCaCommand::KeyRollActivate(staged_for_seconds) => {
                StorableCaCommand::KeyRollActivate { staged_for_seconds }
            }
            OldStorableCaCommand::KeyRollFinish(resource_class_name) => {
                StorableCaCommand::KeyRollFinish { resource_class_name }
            }
            OldStorableCaCommand::RoaDefinitionUpdates(updates) => StorableCaCommand::RoaDefinitionUpdates { updates },
            OldStorableCaCommand::Republish => StorableCaCommand::Republish,
            OldStorableCaCommand::RepoUpdate(service_uri) => StorableCaCommand::RepoUpdate { service_uri },
            OldStorableCaCommand::RepoRemoveOld => StorableCaCommand::RepoRemoveOld,
            OldStorableCaCommand::RtaPrepare(name) => StorableCaCommand::RtaPrepare { name },
            OldStorableCaCommand::RtaSign(name) => StorableCaCommand::RtaSign { name },
            OldStorableCaCommand::RtaCoSign(name) => StorableCaCommand::RtaCoSign { name },
            OldStorableCaCommand::Deactivate => StorableCaCommand::Deactivate,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredRepositoryCommand {
    pub actor: String,
    pub time: Time,
    pub handle: Handle,
    pub version: u64,  // version of aggregate this was applied to (successful or not)
    pub sequence: u64, // command sequence (i.e. also incremented for failed commands)
    pub details: OldStorableRepositoryCommand,
    pub effect: OldStoredEffect,
}

impl OldStoredRepositoryCommand {
    pub fn into_pubd_command(self) -> StoredCommand<StorableRepositoryCommand> {
        StoredCommand::new(
            self.actor,
            self.time,
            self.handle,
            self.version,
            self.sequence,
            self.details.into(),
            self.effect.into(),
        )
    }
}

impl fmt::Display for OldStoredRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA command")
    }
}

impl Command for OldStoredRepositoryCommand {
    type StorableDetails = OldStorableRepositoryCommand;

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
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldStorableRepositoryCommand {
    AddPublisher(PublisherHandle, String),
    RemovePublisher(PublisherHandle),
    Publish(PublisherHandle, usize, usize, usize),
    SessionReset,
}

impl WithStorableDetails for OldStorableRepositoryCommand {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        unimplemented!("not needed for migration")
    }
}

impl From<OldStorableRepositoryCommand> for StorableRepositoryCommand {
    fn from(old: OldStorableRepositoryCommand) -> Self {
        match old {
            OldStorableRepositoryCommand::AddPublisher(name, _) => StorableRepositoryCommand::AddPublisher { name },
            OldStorableRepositoryCommand::RemovePublisher(name) => StorableRepositoryCommand::RemovePublisher { name },
            _ => unimplemented!("no need to migrate"),
        }
    }
}
