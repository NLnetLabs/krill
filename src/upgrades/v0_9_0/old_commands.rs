use rpki::{crypto::KeyIdentifier, x509::Time};

use std::{collections::BTreeMap, fmt};

use crate::{
    commons::{
        api::{
            ChildHandle, Handle, ParentHandle, RequestResourceLimit, ResourceClassName, ResourceSet, RevocationRequest,
            RoaDefinitionUpdates, RtaName, StorableCaCommand, StorableParentContact, StoredEffect,
        },
        eventsourcing::{Command, WithStorableDetails},
        remote::rfc8183::ServiceUri,
    },
    daemon::ca::StoredCaCommand,
};

use super::old_events::OldEvt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredCaCommand {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    details: OldStorableCaCommand,
    effect: OldStoredEffect,
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

    pub fn set_command_version(&mut self, affected_version: u64) {
        self.version = affected_version;
    }

    pub fn effect(&self) -> &OldStoredEffect {
        &self.effect
    }

    pub fn time(&self) -> Time {
        self.time
    }
}

impl fmt::Display for OldStoredCaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA command")
    }
}

impl Command for OldStoredCaCommand {
    type Event = OldEvt;
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
            OldStorableCaCommand::ChildAdd(child, id_ski, resources) => {
                StorableCaCommand::ChildAdd(child, id_ski, resources)
            }
            OldStorableCaCommand::ChildUpdateResources(child, resources) => {
                StorableCaCommand::ChildUpdateResources(child, resources)
            }
            OldStorableCaCommand::ChildUpdateId(child, ski) => StorableCaCommand::ChildUpdateId(child, ski),
            OldStorableCaCommand::ChildCertify(child, rcn, limit, ki) => {
                StorableCaCommand::ChildCertify(child, rcn, limit, ki)
            }
            OldStorableCaCommand::ChildRevokeKey(child, revoke_req) => {
                StorableCaCommand::ChildRevokeKey(child, revoke_req)
            }
            OldStorableCaCommand::ChildRemove(child) => StorableCaCommand::ChildRemove(child),

            OldStorableCaCommand::GenerateNewIdKey => StorableCaCommand::GenerateNewIdKey,

            OldStorableCaCommand::AddParent(parent, contact) => StorableCaCommand::AddParent(parent, contact),
            OldStorableCaCommand::UpdateParentContact(parent, contact) => {
                StorableCaCommand::UpdateParentContact(parent, contact)
            }
            OldStorableCaCommand::RemoveParent(parent) => StorableCaCommand::RemoveParent(parent),

            OldStorableCaCommand::UpdateResourceClasses(parent, map) => {
                StorableCaCommand::UpdateResourceClasses(parent, map)
            }
            OldStorableCaCommand::UpdateRcvdCert(rcn, resources) => StorableCaCommand::UpdateRcvdCert(rcn, resources),

            OldStorableCaCommand::KeyRollInitiate(seconds) => StorableCaCommand::KeyRollInitiate(seconds),
            OldStorableCaCommand::KeyRollActivate(seconds) => StorableCaCommand::KeyRollActivate(seconds),
            OldStorableCaCommand::KeyRollFinish(rcn) => StorableCaCommand::KeyRollFinish(rcn),
            OldStorableCaCommand::RoaDefinitionUpdates(roa_updates) => {
                StorableCaCommand::RoaDefinitionUpdates(roa_updates)
            }
            OldStorableCaCommand::Republish => StorableCaCommand::Republish,
            OldStorableCaCommand::RepoUpdate(service_uri) => StorableCaCommand::RepoUpdate(service_uri),
            OldStorableCaCommand::RepoRemoveOld => StorableCaCommand::RepoRemoveOld,
            OldStorableCaCommand::RtaPrepare(rta_name) => StorableCaCommand::RtaPrepare(rta_name),
            OldStorableCaCommand::RtaSign(rta_name) => StorableCaCommand::RtaSign(rta_name),
            OldStorableCaCommand::RtaCoSign(rta_name) => StorableCaCommand::RtaCoSign(rta_name),
            OldStorableCaCommand::Deactivate => StorableCaCommand::Deactivate,
        }
    }
}
