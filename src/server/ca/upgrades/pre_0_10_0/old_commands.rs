use serde::{Deserialize, Serialize};
use rpki::{
    ca::{
        idexchange::{ChildHandle, ParentHandle, ServiceUri},
        provisioning::{
            RequestResourceLimit, ResourceClassName, RevocationRequest,
        },
    },
    crypto::KeyIdentifier,
    repository::resources::ResourceSet,
};

use crate::api::admin::StorableParentContact;
use crate::api::ca::RtaName;
use crate::api::roa::RoaConfigurationUpdates;
use crate::commons::eventsourcing::WithStorableDetails;
use crate::server::ca::commands::{
    CertAuthStorableCommand, StorableRcEntitlement
};
use crate::server::ca::rc::DropReason;
use crate::server::ca::upgrades::pre_0_14_0::aspa::{
    Pre0_14_0AspaProvidersUpdate, Pre0_14_0ProviderAs,
};
use super::aspa::Pre0_10_0AspaDefinition;


//------------ Pre0_10_0CertAuthStorableCommand ----------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Pre0_10_0CertAuthStorableCommand {
    Init,
    ChildAdd {
        child: ChildHandle,
        ski: String,
        resources: ResourceSet,
    },
    ChildImport {
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
        updates: Pre0_10AspaDefinitionUpdates,
    },
    AspasUpdateExisting {
        customer: Pre0_14_0ProviderAs, // was using string notation
        update: Pre0_14_0AspaProvidersUpdate,
    },
    AspaRemove {
        customer: Pre0_14_0ProviderAs, // was using string notation
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
pub struct Pre0_10AspaDefinitionUpdates {
    add_or_replace: Vec<Pre0_10_0AspaDefinition>,
    remove: Vec<Pre0_14_0ProviderAs>, // was using string notation
}

impl From<Pre0_10_0CertAuthStorableCommand> for CertAuthStorableCommand {
    fn from(old: Pre0_10_0CertAuthStorableCommand) -> Self {
        match old {
            Pre0_10_0CertAuthStorableCommand::Init => CertAuthStorableCommand::Init,
            Pre0_10_0CertAuthStorableCommand::ChildAdd { child, ski, resources } => {
                CertAuthStorableCommand::ChildAdd { child, ski, resources }
            }
            Pre0_10_0CertAuthStorableCommand::ChildImport { child, ski, resources } => {
                CertAuthStorableCommand::ChildImport { child, ski, resources }
            }
            Pre0_10_0CertAuthStorableCommand::ChildUpdateResources { child, resources } => {
                CertAuthStorableCommand::ChildUpdateResources { child, resources }
            }
            Pre0_10_0CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                CertAuthStorableCommand::ChildUpdateId { child, ski }
            }
            Pre0_10_0CertAuthStorableCommand::ChildCertify {
                child,
                resource_class_name,
                limit,
                ki,
            } => CertAuthStorableCommand::ChildCertify {
                child,
                resource_class_name,
                limit,
                ki,
            },
            Pre0_10_0CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => {
                CertAuthStorableCommand::ChildRevokeKey { child, revoke_req }
            }
            Pre0_10_0CertAuthStorableCommand::ChildRemove { child } => CertAuthStorableCommand::ChildRemove { child },
            Pre0_10_0CertAuthStorableCommand::ChildSuspendInactive { child } => {
                CertAuthStorableCommand::ChildSuspendInactive { child }
            }
            Pre0_10_0CertAuthStorableCommand::ChildUnsuspend { child } => {
                CertAuthStorableCommand::ChildUnsuspend { child }
            }
            Pre0_10_0CertAuthStorableCommand::GenerateNewIdKey => CertAuthStorableCommand::GenerateNewIdKey,
            Pre0_10_0CertAuthStorableCommand::AddParent { parent, contact } => {
                CertAuthStorableCommand::AddParent { parent, contact }
            }
            Pre0_10_0CertAuthStorableCommand::UpdateParentContact { parent, contact } => {
                CertAuthStorableCommand::UpdateParentContact { parent, contact }
            }
            Pre0_10_0CertAuthStorableCommand::RemoveParent { parent } => {
                CertAuthStorableCommand::RemoveParent { parent }
            }
            Pre0_10_0CertAuthStorableCommand::UpdateResourceEntitlements { parent, entitlements } => {
                CertAuthStorableCommand::UpdateResourceEntitlements { parent, entitlements }
            }
            Pre0_10_0CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            },
            Pre0_10_0CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            },
            Pre0_10_0CertAuthStorableCommand::KeyRollInitiate { older_than_seconds } => {
                CertAuthStorableCommand::KeyRollInitiate { older_than_seconds }
            }
            Pre0_10_0CertAuthStorableCommand::KeyRollActivate { staged_for_seconds } => {
                CertAuthStorableCommand::KeyRollActivate { staged_for_seconds }
            }
            Pre0_10_0CertAuthStorableCommand::KeyRollFinish { resource_class_name } => {
                CertAuthStorableCommand::KeyRollFinish { resource_class_name }
            }
            Pre0_10_0CertAuthStorableCommand::RoaDefinitionUpdates { updates } => {
                CertAuthStorableCommand::RoaDefinitionUpdates { updates }
            }
            Pre0_10_0CertAuthStorableCommand::ReissueBeforeExpiring => CertAuthStorableCommand::ReissueBeforeExpiring,
            Pre0_10_0CertAuthStorableCommand::ForceReissue => CertAuthStorableCommand::ForceReissue,
            Pre0_10_0CertAuthStorableCommand::AspasUpdate { .. } => unimplemented!("must not be migrated"),
            Pre0_10_0CertAuthStorableCommand::AspasUpdateExisting { .. } => unimplemented!("must not be migrated"),
            Pre0_10_0CertAuthStorableCommand::AspaRemove { .. } => unimplemented!("must not be migrated"),
            Pre0_10_0CertAuthStorableCommand::BgpSecDefinitionUpdates => {
                CertAuthStorableCommand::BgpSecDefinitionUpdates
            }
            Pre0_10_0CertAuthStorableCommand::RepoUpdate { service_uri } => {
                CertAuthStorableCommand::RepoUpdate { service_uri }
            }
            Pre0_10_0CertAuthStorableCommand::RtaPrepare { name } => CertAuthStorableCommand::RtaPrepare { name },
            Pre0_10_0CertAuthStorableCommand::RtaSign { name } => CertAuthStorableCommand::RtaSign { name },
            Pre0_10_0CertAuthStorableCommand::RtaCoSign { name } => CertAuthStorableCommand::RtaCoSign { name },
            Pre0_10_0CertAuthStorableCommand::Deactivate => CertAuthStorableCommand::Deactivate,
        }
    }
}

impl WithStorableDetails for Pre0_10_0CertAuthStorableCommand {
    fn summary(&self) -> crate::api::history::CommandSummary {
        CertAuthStorableCommand::from(self.clone()).summary()
    }

    fn make_init() -> Self {
        unimplemented!("not used in migration")
    }
}
