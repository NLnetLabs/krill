use rpki::{crypto::KeyIdentifier, x509::Time};

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

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
    pubd::RepositoryManager,
    upgrades::{UpgradeError, UpgradeResult},
};

use super::old_events::DerivedEmbeddedCaMigrationInfo;

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
    pub fn into_ca_command(
        self,
        repo_manager: &Option<RepositoryManager>,
        derived_embedded_ca_info_map: &HashMap<Handle, DerivedEmbeddedCaMigrationInfo>,
    ) -> UpgradeResult<StoredCaCommand> {
        let (actor, time, handle, version, sequence, details, effect) = (
            self.actor,
            self.time,
            self.handle,
            self.version,
            self.sequence,
            self.details,
            self.effect.into(),
        );

        let details = match details {
            OldStorableCaCommand::RepoUpdate(service_uri_opt) => {
                let service_uri = match service_uri_opt {
                    Some(service_uri) => service_uri,
                    None => repo_manager
                        .as_ref()
                        .ok_or(UpgradeError::KrillError(
                            crate::commons::error::Error::RepositoryServerNotEnabled,
                        ))?
                        .repository_response(&handle)?
                        .service_uri()
                        .clone(),
                };
                StorableCaCommand::RepoUpdate { service_uri }
            }
            OldStorableCaCommand::ChildAdd(child, id_ski_opt, resources) => {
                let ski = match id_ski_opt {
                    Some(ski) => ski,
                    None => derived_embedded_ca_info_map
                        .get(&child)
                        .ok_or_else(|| {
                            UpgradeError::Custom(format!(
                                "Cannot upgrade CA history for {}, child {} is no longer present",
                                handle, child
                            ))
                        })?
                        .child_request
                        .id_cert()
                        .ski_hex(),
                };

                StorableCaCommand::ChildAdd { child, ski, resources }
            }

            _ => details.into(),
        };

        Ok(StoredCaCommand::new(
            actor, time, handle, version, sequence, details, effect,
        ))
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
            OldStoredEffect::Events(events) => Some(events),
            OldStoredEffect::Error(_) => None,
        }
    }
}

impl From<OldStoredEffect> for StoredEffect {
    fn from(old: OldStoredEffect) -> Self {
        match old {
            OldStoredEffect::Error(msg) => StoredEffect::Error { msg },
            OldStoredEffect::Events(events) => StoredEffect::Success { events },
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
    AddParent(ParentHandle, OldStorableParentContact),
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
        unreachable!("not needed for migration")
    }
}

impl From<OldStorableCaCommand> for StorableCaCommand {
    fn from(old: OldStorableCaCommand) -> Self {
        match old {
            OldStorableCaCommand::MakeTrustAnchor => StorableCaCommand::MakeTrustAnchor,
            OldStorableCaCommand::ChildAdd(_child, _ski, _resources) => {
                unreachable!("migrated differently")
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

            OldStorableCaCommand::AddParent(parent, contact) => StorableCaCommand::AddParent {
                parent,
                contact: contact.into(),
            },
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
            OldStorableCaCommand::RepoUpdate(_service_uri) => {
                unreachable!("migrated differently getting the service uri for embedded repo")
            }
            OldStorableCaCommand::RepoRemoveOld => unreachable!("This command is not migrated"),
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
        unreachable!("not needed for migration")
    }
}

impl From<OldStorableRepositoryCommand> for StorableRepositoryCommand {
    fn from(old: OldStorableRepositoryCommand) -> Self {
        match old {
            OldStorableRepositoryCommand::AddPublisher(name, _) => StorableRepositoryCommand::AddPublisher { name },
            OldStorableRepositoryCommand::RemovePublisher(name) => StorableRepositoryCommand::RemovePublisher { name },
            _ => unreachable!("no need to migrate these old commands"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OldStorableParentContact {
    Ta,
    Embedded,
    Rfc6492,
}

impl From<OldStorableParentContact> for StorableParentContact {
    fn from(old: OldStorableParentContact) -> Self {
        match old {
            OldStorableParentContact::Ta => StorableParentContact::Ta,
            _ => StorableParentContact::Rfc6492,
        }
    }
}
