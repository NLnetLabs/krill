//------------ StorableCaCommand -------------------------------------------

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

use crate::{
    commons::{
        api::{
            CertAuthStorableCommand, CustomerAsn, RoaConfigurationUpdates,
            RtaName, StorableParentContact, StorableRcEntitlement,
        },
        eventsourcing::WithStorableDetails,
    },
    daemon::ca::DropReason,
    upgrades::pre_0_14_0::Pre0_14_0AspaProvidersUpdate,
};

use super::Pre0_14_0AspaDefinition;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Pre0_14_0CertAuthStorableCommand {
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
        updates: Pre0_14_0AspaDefinitionUpdates,
    },
    AspasUpdateExisting {
        customer: CustomerAsn,
        update: Pre0_14_0AspaProvidersUpdate,
    },
    AspaRemove {
        customer: CustomerAsn,
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
pub struct Pre0_14_0AspaDefinitionUpdates {
    add_or_replace: Vec<Pre0_14_0AspaDefinition>,
    remove: Vec<rpki::resources::Asn>,
}

impl From<Pre0_14_0CertAuthStorableCommand> for CertAuthStorableCommand {
    fn from(old: Pre0_14_0CertAuthStorableCommand) -> Self {
        match old {
            Pre0_14_0CertAuthStorableCommand::Init => CertAuthStorableCommand::Init,
            Pre0_14_0CertAuthStorableCommand::ChildAdd { child, ski, resources } => {
                CertAuthStorableCommand::ChildAdd { child, ski, resources }
            }
            Pre0_14_0CertAuthStorableCommand::ChildImport { child, ski, resources } => {
                CertAuthStorableCommand::ChildImport { child, ski, resources }
            }
            Pre0_14_0CertAuthStorableCommand::ChildUpdateResources { child, resources } => {
                CertAuthStorableCommand::ChildUpdateResources { child, resources }
            }
            Pre0_14_0CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                CertAuthStorableCommand::ChildUpdateId { child, ski }
            }
            Pre0_14_0CertAuthStorableCommand::ChildCertify {
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
            Pre0_14_0CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => {
                CertAuthStorableCommand::ChildRevokeKey { child, revoke_req }
            }
            Pre0_14_0CertAuthStorableCommand::ChildRemove { child } => CertAuthStorableCommand::ChildRemove { child },
            Pre0_14_0CertAuthStorableCommand::ChildSuspendInactive { child } => {
                CertAuthStorableCommand::ChildSuspendInactive { child }
            }
            Pre0_14_0CertAuthStorableCommand::ChildUnsuspend { child } => {
                CertAuthStorableCommand::ChildUnsuspend { child }
            }
            Pre0_14_0CertAuthStorableCommand::GenerateNewIdKey => CertAuthStorableCommand::GenerateNewIdKey,
            Pre0_14_0CertAuthStorableCommand::AddParent { parent, contact } => {
                CertAuthStorableCommand::AddParent { parent, contact }
            }
            Pre0_14_0CertAuthStorableCommand::UpdateParentContact { parent, contact } => {
                CertAuthStorableCommand::UpdateParentContact { parent, contact }
            }
            Pre0_14_0CertAuthStorableCommand::RemoveParent { parent } => {
                CertAuthStorableCommand::RemoveParent { parent }
            }
            Pre0_14_0CertAuthStorableCommand::UpdateResourceEntitlements { parent, entitlements } => {
                CertAuthStorableCommand::UpdateResourceEntitlements { parent, entitlements }
            }
            Pre0_14_0CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            },
            Pre0_14_0CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            },
            Pre0_14_0CertAuthStorableCommand::KeyRollInitiate { older_than_seconds } => {
                CertAuthStorableCommand::KeyRollInitiate { older_than_seconds }
            }
            Pre0_14_0CertAuthStorableCommand::KeyRollActivate { staged_for_seconds } => {
                CertAuthStorableCommand::KeyRollActivate { staged_for_seconds }
            }
            Pre0_14_0CertAuthStorableCommand::KeyRollFinish { resource_class_name } => {
                CertAuthStorableCommand::KeyRollFinish { resource_class_name }
            }
            Pre0_14_0CertAuthStorableCommand::RoaDefinitionUpdates { updates } => {
                CertAuthStorableCommand::RoaDefinitionUpdates { updates }
            }
            Pre0_14_0CertAuthStorableCommand::ReissueBeforeExpiring => CertAuthStorableCommand::ReissueBeforeExpiring,
            Pre0_14_0CertAuthStorableCommand::ForceReissue => CertAuthStorableCommand::ForceReissue,
            Pre0_14_0CertAuthStorableCommand::AspasUpdate { .. } => unimplemented!("must not be migrated"),
            Pre0_14_0CertAuthStorableCommand::AspasUpdateExisting { .. } => unimplemented!("must not be migrated"),
            Pre0_14_0CertAuthStorableCommand::AspaRemove { .. } => unimplemented!("must not be migrated"),
            Pre0_14_0CertAuthStorableCommand::BgpSecDefinitionUpdates => {
                CertAuthStorableCommand::BgpSecDefinitionUpdates
            }
            Pre0_14_0CertAuthStorableCommand::RepoUpdate { service_uri } => {
                CertAuthStorableCommand::RepoUpdate { service_uri }
            }
            Pre0_14_0CertAuthStorableCommand::RtaPrepare { name } => CertAuthStorableCommand::RtaPrepare { name },
            Pre0_14_0CertAuthStorableCommand::RtaSign { name } => CertAuthStorableCommand::RtaSign { name },
            Pre0_14_0CertAuthStorableCommand::RtaCoSign { name } => CertAuthStorableCommand::RtaCoSign { name },
            Pre0_14_0CertAuthStorableCommand::Deactivate => CertAuthStorableCommand::Deactivate,
        }
    }
}

impl WithStorableDetails for Pre0_14_0CertAuthStorableCommand {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        CertAuthStorableCommand::from(self.clone()).summary()
    }

    fn make_init() -> Self {
        unimplemented!("not used in migration")
    }
}
