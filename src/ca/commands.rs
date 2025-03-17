//! The commands issued to an RPKI CA.

use std::fmt;
use std::sync::Arc;
use chrono::Duration;
use rpki::ca::idexchange::{ChildHandle, ParentHandle, ServiceUri};
use rpki::ca::provisioning::{
    IssuanceRequest, ResourceClassListResponse as Entitlements,
    RequestResourceLimit, ResourceClassName, RevocationRequest,
    RevocationResponse,
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use serde::{Deserialize, Serialize};
use crate::commons::api::admin::{
    ParentCaContact, RepositoryContact, ResourceClassNameMapping,
    StorableParentContact,
};
use crate::commons::api::aspa::{
    AspaDefinitionUpdates, AspaProvidersUpdate, CustomerAsn,
};
use crate::commons::api::bgpsec::BgpSecDefinitionUpdates;
use crate::commons::api::ca::{
    IdCertInfo, ReceivedCert,  ResourceSetSummary,RtaName
};
use crate::commons::api::history::CommandSummary;
use crate::commons::api::import::ImportChild;
use crate::commons::api::roa::RoaConfigurationUpdates;
use crate::commons::api::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
};
use crate::commons::crypto::KrillSigner;
use crate::commons::eventsourcing::{
    self, InitCommandDetails, SentCommand, SentInitCommand,
    WithStorableDetails,
};
use crate::daemon::config::Config;
use super::events::CertAuthEvent;
use super::rc::DropReason;


//------------ CertAuthInitCommand -----------------------------------------

pub type CertAuthInitCommand = SentInitCommand<CertAuthInitCommandDetails>;


//------------ CertAuthInitCommandDetails ----------------------------------

/// The details for the init command for a `CertAuth` instance.
#[derive(Clone, Debug)]
pub struct CertAuthInitCommandDetails {
    /// The signer to use for initializing the CA.
    pub signer: Arc<KrillSigner>,
}

impl InitCommandDetails for CertAuthInitCommandDetails {
    type StorableDetails = CertAuthStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        CertAuthStorableCommand::make_init()
    }
}

impl fmt::Display for CertAuthInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

//------------ CertAuthCommand ---------------------------------------------

pub type CertAuthCommand = SentCommand<CertAuthCommandDetails>;

//------------ CertAuthCommandDetails --------------------------------------

/// The details for the commands for a `CertAuth` instance.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CertAuthCommandDetails {
    //--- Child commands.
    //
    // These relate to child CAs of this CA.

    /// Add a new child under this parent CA
    ChildAdd(ChildHandle, IdCertInfo, ResourceSet),

    /// Import a child under this parent CA
    ChildImport(ImportChild, Arc<Config>, Arc<KrillSigner>),

    /// Update the resource entitlements for an existing child.
    ChildUpdateResources(ChildHandle, ResourceSet),

    /// Update the IdCert used by the child for the provisioning protocol.
    ChildUpdateId(ChildHandle, IdCertInfo),

    /// Update the mapping of resource classes.
    ChildUpdateResourceClassNameMapping(
        ChildHandle,
        ResourceClassNameMapping,
    ),

    /// Process an issuance request sent by an existing child.
    ChildCertify(ChildHandle, IssuanceRequest, Arc<Config>, Arc<KrillSigner>),

    /// Process a revoke request by an existing child.
    ChildRevokeKey(ChildHandle, RevocationRequest),

    /// Remove a child.
    ///
    /// This also revokes, and removes issued certs, and republishes.
    ChildRemove(ChildHandle),

    /// Suspend a child.
    ///
    /// This is done by a background process which checks for inactive
    /// children.
    ///
    /// When a child is inactive it is assumed that it no longer maintains
    /// its repository. The certificate(s) issued to the child will be
    /// removed (and revoked) until the child is seen again and unsuspended.
    ChildSuspendInactive(ChildHandle),

    /// Unsuspend a child.
    ///
    /// This happens when it contacts the server again. Mark itas active
    /// once again and republish existing certificates provided that they
    /// are not expired, or about to expire, and do not claim resources no
    /// longer associated with this child.
    ChildUnsuspend(ChildHandle),

    //--- Parent commands
    //
    // These relate to the parent CAs of this CA.

    /// Update our own ID key and cert.
    ///
    /// Note that this will break communications with RFC6492 parents. This
    /// command is added, because we need it for testing that we can update
    /// this ID for parents, and children. In practice however, one may not
    /// want to use this until RFC8183 is extended with some words/ on how
    /// to re-do the ID exchange.
    GenerateNewIdKey(Arc<KrillSigner>),

    /// Add a parent to this CA.
    ///
    /// A CA can have multiple parents.
    AddParent(ParentHandle, ParentCaContact),

    /// Update a parent's contact
    UpdateParentContact(ParentHandle, ParentCaContact),

    /// Remove a parent.
    ///
    /// This frees up the handle for future (re-)use.
    RemoveParent(ParentHandle),

    /// Process new entitlements from a parent.
    ///
    /// Remove/create/update resource classes and certificate requests or key
    /// revocation requests as needed.
    UpdateEntitlements(ParentHandle, Entitlements, Arc<KrillSigner>),

    /// Process a new certificate received from a parent.
    UpdateRcvdCert(
        ResourceClassName,
        ReceivedCert,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    /// Drop a resource class under a parent.
    ///
    /// This is usually done because of issues obtaining a certificate for it.
    DropResourceClass(ResourceClassName, DropReason, Arc<KrillSigner>),

    //--- Key rolls

    /// Initiate a key roll for all resource classes under each parent.
    ///
    /// A key roll is only initiated for resource classes where there is a
    /// current active key only, i.e. there is no roll in progress, and this
    /// key's age exceeds the given duration.
    KeyRollInitiate(Duration, Arc<KrillSigner>),

    /// Activate a rolled key.
    ///
    /// For all resource classes with a 'new' key with an age exceeding the
    /// duration:
    ///
    /// * Promote the new key to current key
    /// * Publish all objects under the new current key
    /// * Promote the current key to old key
    /// * Publish a mft and crl only under the old key
    /// * Issue a revoke request for the old key
    ///
    /// RFC6489 dictates that 24 hours must be observed. However, shorter
    /// time frames can be used for testing, and in case of emergency
    /// rolls.
    KeyRollActivate(Duration, Arc<Config>, Arc<KrillSigner>),

    /// Finish the keyroll.
    ///
    /// This should happen after the parent confirmed that a key for a parent
    /// and resource class has been revoked. I.e. remove the old key, and
    /// withdraw the crl and mft for it.
    KeyRollFinish(ResourceClassName, RevocationResponse),

    //--- Route authorizations

    /// Update the authorizations for a CA.
    ///
    /// Note: ROA *objects* will be created by the CA itself. The command
    /// just contains the intent for which announcements should be
    /// authorized.
    RouteAuthorizationsUpdate(
        RoaConfigurationUpdates,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    /// Re-issue all ROA objects which would otherwise expire soon.
    ///
    /// The threshold for “soon” is configurable, four weeks by default.
    /// Note that this command is intended to be sent by the scheduler -
    /// once a day is fine - and will only be stored if there are any
    /// updates to be done.
    RouteAuthorizationsRenew(Arc<Config>, Arc<KrillSigner>),

    /// Re-issue all ROA objects regardless of their expiration time.
    RouteAuthorizationsForceRenew(Arc<Config>, Arc<KrillSigner>),

    //--- ASPA

    /// Update ASPA definitions
    AspasUpdate(AspaDefinitionUpdates, Arc<Config>, Arc<KrillSigner>),

    /// Update an existing AspaProviders for the given AspaCustomer
    AspasUpdateExisting(
        CustomerAsn,
        AspaProvidersUpdate,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    /// Re-issue any and all ASPA objects which would otherwise expire soon.
    ///
    /// The threshold for “soon” is configurable, four weeks by default.
    /// 
    /// This command is intended to be sent by the scheduler – once a day is
    /// fine – and will only be stored if there are any updates to be done.
    AspasRenew(Arc<Config>, Arc<KrillSigner>),


    //--- BGPsec router keys

    /// Update BgpSecDefinitions
    BgpSecUpdateDefinitions(
        BgpSecDefinitionUpdates,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    /// Re-issue any and all BGPsec certificates which are soon to expire.
    BgpSecRenew(Arc<Config>, Arc<KrillSigner>),


    //--- Publishing

    // Update the repository where this CA publishes.
    RepoUpdate(RepositoryContact, Arc<KrillSigner>),


    //--- RTA

    /// Sign a new RTA
    RtaSign(RtaName, RtaContentRequest, Arc<KrillSigner>),

    /// Prepare a multi-signed RTA
    RtaMultiPrepare(RtaName, RtaPrepareRequest, Arc<KrillSigner>),

    /// Co-sign an existing multi-signed RTA
    RtaCoSign(RtaName, ResourceTaggedAttestation, Arc<KrillSigner>),
}

impl eventsourcing::CommandDetails for CertAuthCommandDetails {
    type Event = CertAuthEvent;
    type StorableDetails = CertAuthStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl fmt::Display for CertAuthCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        CertAuthStorableCommand::from(self.clone()).fmt(f)
    }
}


//------------ StorableCaCommand --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CertAuthStorableCommand {
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
    ChildUpdateResourceClassNameMapping {
        child: ChildHandle,
        mapping: ResourceClassNameMapping,
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
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
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

impl From<CertAuthCommandDetails> for CertAuthStorableCommand {
    fn from(d: CertAuthCommandDetails) -> Self {
        match d {
            CertAuthCommandDetails::ChildAdd(child, id_cert, resources) => {
                CertAuthStorableCommand::ChildAdd {
                    child,
                    ski: id_cert.public_key.key_identifier().to_string(),
                    resources,
                }
            }
            CertAuthCommandDetails::ChildImport(import_child, _, _) => {
                CertAuthStorableCommand::ChildImport {
                    child: import_child.name,
                    ski: import_child
                        .id_cert
                        .public_key()
                        .key_identifier()
                        .to_string(),
                    resources: import_child.resources,
                }
            }
            CertAuthCommandDetails::ChildUpdateResources(
                child,
                resources,
            ) => CertAuthStorableCommand::ChildUpdateResources {
                child,
                resources,
            },
            CertAuthCommandDetails::ChildUpdateId(child, id_cert) => {
                CertAuthStorableCommand::ChildUpdateId {
                    child,
                    ski: id_cert.public_key.key_identifier().to_string(),
                }
            }
            CertAuthCommandDetails::ChildUpdateResourceClassNameMapping(
                child,
                mapping,
            ) => {
                CertAuthStorableCommand::ChildUpdateResourceClassNameMapping {
                    child,
                    mapping,
                }
            }
            CertAuthCommandDetails::ChildCertify(child, req, _, _) => {
                let (resource_class_name, limit, csr) = req.unpack();
                let ki = csr.public_key().key_identifier();
                CertAuthStorableCommand::ChildCertify {
                    child,
                    resource_class_name,
                    limit,
                    ki,
                }
            }
            CertAuthCommandDetails::ChildRevokeKey(child, revoke_req) => {
                CertAuthStorableCommand::ChildRevokeKey { child, revoke_req }
            }
            CertAuthCommandDetails::ChildRemove(child) => {
                CertAuthStorableCommand::ChildRemove { child }
            }
            CertAuthCommandDetails::ChildSuspendInactive(child) => {
                CertAuthStorableCommand::ChildSuspendInactive { child }
            }
            CertAuthCommandDetails::ChildUnsuspend(child) => {
                CertAuthStorableCommand::ChildUnsuspend { child }
            }
            CertAuthCommandDetails::GenerateNewIdKey(_) => {
                CertAuthStorableCommand::GenerateNewIdKey
            }
            CertAuthCommandDetails::AddParent(parent, contact) => {
                CertAuthStorableCommand::AddParent {
                    parent,
                    contact: contact.into(),
                }
            }
            CertAuthCommandDetails::UpdateParentContact(parent, contact) => {
                CertAuthStorableCommand::UpdateParentContact {
                    parent,
                    contact: contact.into(),
                }
            }
            CertAuthCommandDetails::RemoveParent(parent) => {
                CertAuthStorableCommand::RemoveParent { parent }
            }
            CertAuthCommandDetails::UpdateEntitlements(
                parent,
                cmd_entitlements,
                _,
            ) => {
                let mut entitlements = vec![];
                for entitlement in cmd_entitlements.classes() {
                    entitlements.push(StorableRcEntitlement {
                        resource_class_name: entitlement.class_name().clone(),
                        resources: entitlement.resource_set().clone(),
                    });
                }

                CertAuthStorableCommand::UpdateResourceEntitlements {
                    parent,
                    entitlements,
                }
            }
            CertAuthCommandDetails::UpdateRcvdCert(
                resource_class_name,
                rcvd_cert,
                _,
                _,
            ) => CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources: rcvd_cert.resources.clone(),
            },
            CertAuthCommandDetails::DropResourceClass(
                resource_class_name,
                reason,
                _,
            ) => CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            },
            CertAuthCommandDetails::KeyRollInitiate(older_than, _) => {
                CertAuthStorableCommand::KeyRollInitiate {
                    older_than_seconds: older_than.num_seconds(),
                }
            }
            CertAuthCommandDetails::KeyRollActivate(staged_for, _, _) => {
                CertAuthStorableCommand::KeyRollActivate {
                    staged_for_seconds: staged_for.num_seconds(),
                }
            }
            CertAuthCommandDetails::KeyRollFinish(resource_class_name, _) => {
                CertAuthStorableCommand::KeyRollFinish {
                    resource_class_name,
                }
            }
            CertAuthCommandDetails::RouteAuthorizationsUpdate(
                updates,
                _,
                _,
            ) => CertAuthStorableCommand::RoaDefinitionUpdates { updates },
            CertAuthCommandDetails::RouteAuthorizationsRenew(_, _) => {
                CertAuthStorableCommand::ReissueBeforeExpiring
            }
            CertAuthCommandDetails::RouteAuthorizationsForceRenew(_, _) => {
                CertAuthStorableCommand::ForceReissue
            }
            CertAuthCommandDetails::AspasUpdate(updates, _, _) => {
                CertAuthStorableCommand::AspasUpdate { updates }
            }
            CertAuthCommandDetails::AspasUpdateExisting(
                customer,
                update,
                _,
                _,
            ) => CertAuthStorableCommand::AspasUpdateExisting {
                customer,
                update,
            },
            CertAuthCommandDetails::AspasRenew(_, _) => {
                CertAuthStorableCommand::ReissueBeforeExpiring
            }
            CertAuthCommandDetails::BgpSecUpdateDefinitions(_, _, _) => {
                CertAuthStorableCommand::BgpSecDefinitionUpdates
            }
            CertAuthCommandDetails::BgpSecRenew(_, _) => {
                CertAuthStorableCommand::ReissueBeforeExpiring
            }
            CertAuthCommandDetails::RepoUpdate(contact, _) => {
                CertAuthStorableCommand::RepoUpdate {
                    service_uri: contact.server_info.service_uri.clone(),
                }
            }
            CertAuthCommandDetails::RtaMultiPrepare(name, _, _) => {
                CertAuthStorableCommand::RtaPrepare { name }
            }
            CertAuthCommandDetails::RtaSign(name, _, _) => {
                CertAuthStorableCommand::RtaSign { name }
            }
            CertAuthCommandDetails::RtaCoSign(name, _, _) => {
                CertAuthStorableCommand::RtaCoSign { name }
            }
        }
    }
}

impl WithStorableDetails for CertAuthStorableCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            CertAuthStorableCommand::Init => {
                CommandSummary::new("cmd-ca-init", self)
            }
            CertAuthStorableCommand::ChildAdd { child, ski, resources } => {
                CommandSummary::new("cmd-ca-child-add", self)
                    .child(child)
                    .id_key(ski.as_ref())
                    .resources(resources)
            }
            CertAuthStorableCommand::ChildImport { child, ski, resources } => {
                CommandSummary::new("cmd-ca-child-import", self)
                    .child(child)
                    .id_key(ski)
                    .resources(resources)
            }
            CertAuthStorableCommand::ChildUpdateResources {
                child, resources
            } => {
                CommandSummary::new("cmd-ca-child-update-res", self)
                    .child(child)
                    .resources(resources)
            }
            CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                CommandSummary::new("cmd-ca-child-update-id", self)
                    .child(child)
                    .id_key(ski)
            }
            CertAuthStorableCommand::ChildUpdateResourceClassNameMapping { 
                child, mapping
            } => {
                CommandSummary::new("cmd-ca-child-update-rcn-mapping", self)
                    .child(child)
                    .arg("parent_rcn", &mapping.name_in_parent)
                    .arg("child_rcn", &mapping.name_for_child)
            }
            CertAuthStorableCommand::ChildCertify {
                child,
                resource_class_name,
                ki,
                ..
            } => {
                CommandSummary::new("cmd-ca-child-certify", self)
                    .child(child)
                    .rcn(resource_class_name)
                    .key(*ki)
            }
            CertAuthStorableCommand::ChildRemove { child } => {
                CommandSummary::new("cmd-ca-child-remove", self).child(child)
            }
            CertAuthStorableCommand::ChildSuspendInactive { child } => {
                CommandSummary::new(
                    "cmd-ca-child-suspend-inactive", self
                ).child(child)
            }
            CertAuthStorableCommand::ChildUnsuspend { child } => {
                CommandSummary::new(
                    "cmd-ca-child-unsuspend", self
                ).child(child)
            }
            CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => {
                CommandSummary::new("cmd-ca-child-revoke", self)
                    .child(child)
                    .rcn(revoke_req.class_name())
                    .key(revoke_req.key())
            }
            CertAuthStorableCommand::GenerateNewIdKey => {
                CommandSummary::new("cmd-ca-generate-new-id", self)
            }
            CertAuthStorableCommand::AddParent { parent, contact } => {
                CommandSummary::new("cmd-ca-parent-add", self)
                    .parent(parent)
                    .parent_contact(contact)
            }
            CertAuthStorableCommand::UpdateParentContact {
                parent, contact
            } => {
                CommandSummary::new("cmd-ca-parent-update", self)
                    .parent(parent)
                    .parent_contact(contact)
            }
            CertAuthStorableCommand::RemoveParent { parent } => {
                CommandSummary::new("cmd-ca-parent-remove", self)
                    .parent(parent)
            }
            CertAuthStorableCommand::UpdateResourceEntitlements {
                parent, .. 
            } => {
                CommandSummary::new("cmd-ca-parent-entitlements", self)
                    .parent(parent)
            }
            CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => {
                CommandSummary::new("cmd-ca-rcn-receive", self)
                    .rcn(resource_class_name)
                    .resources(resources)
            }
            CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => {
                CommandSummary::new("cmd-ca-rc-drop", self)
                    .rcn(resource_class_name)
                    .arg("reason", reason)
            }
            CertAuthStorableCommand::KeyRollInitiate {
                older_than_seconds
            } => {
                CommandSummary::new("cmd-ca-keyroll-init", self)
                    .seconds(*older_than_seconds)
            }
            CertAuthStorableCommand::KeyRollActivate {
                staged_for_seconds
            } => {
                CommandSummary::new("cmd-ca-keyroll-activate", self)
                    .seconds(*staged_for_seconds)
            }
            CertAuthStorableCommand::KeyRollFinish {
                resource_class_name
            } => {
                CommandSummary::new("cmd-ca-keyroll-finish", self)
                    .rcn(resource_class_name)
            }
            CertAuthStorableCommand::RoaDefinitionUpdates { updates } => {
                CommandSummary::new("cmd-ca-roas-updated", self)
                    .added(updates.added.len())
                    .removed(updates.removed.len())
            }
            CertAuthStorableCommand::AspasUpdate { .. } => {
                CommandSummary::new("cmd-ca-aspas-update", self)
            }
            CertAuthStorableCommand::AspasUpdateExisting { .. } => {
                CommandSummary::new("cmd-ca-aspas-update-existing", self)
            }
            CertAuthStorableCommand::AspaRemove { .. } => {
                CommandSummary::new("cmd-ca-aspas-remove", self)
            }
            CertAuthStorableCommand::BgpSecDefinitionUpdates => {
                CommandSummary::new("cmd-bgpsec-update", self)
            }
            CertAuthStorableCommand::RepoUpdate { service_uri } => {
                CommandSummary::new("cmd-ca-repo-update", self)
                    .service_uri(service_uri)
            }
            CertAuthStorableCommand::ReissueBeforeExpiring => {
                CommandSummary::new("cmd-ca-reissue-before-expiring", self)
            }
            CertAuthStorableCommand::ForceReissue => {
                CommandSummary::new("cmd-ca-force-reissue", self)
            }
            CertAuthStorableCommand::RtaPrepare { name } => {
                CommandSummary::new("cmd-ca-rta-prepare", self).rta_name(name)
            }
            CertAuthStorableCommand::RtaSign { name } => {
                CommandSummary::new("cmd-ca-rta-sign", self).rta_name(name)
            }
            CertAuthStorableCommand::RtaCoSign { name } => {
                CommandSummary::new("cmd-ca-rta-cosign", self).rta_name(name)
            }
            CertAuthStorableCommand::Deactivate => {
                CommandSummary::new("cmd-ca-deactivate", self)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl fmt::Display for CertAuthStorableCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertAuthStorableCommand::Init => write!(f, "Create CA"),
            CertAuthStorableCommand::ChildAdd { child, ski, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f,
                    "Add child '{child}' with RFC8183 key '{ski}' and \
                    resources '{summary}'"
                )
            }
            CertAuthStorableCommand::ChildImport {
                child, ski, resources
            } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f,
                    "Import child '{child}' with RFC8183 key '{ski}' \
                     and resources '{summary}'"
                )
            }
            CertAuthStorableCommand::ChildUpdateResources {
                child, resources
            } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f,
                    "Update resources for child '{child}' to: {summary}"
                )
            }
            CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                write!(f, "Update child '{child}' RFC 8183 key '{ski}'")
            }
            CertAuthStorableCommand::ChildUpdateResourceClassNameMapping {
                child, mapping
            } => {
                write!(f,
                    "Update child '{}' map parent RC '{}' to '{}' for child",
                    child, mapping.name_in_parent, mapping.name_for_child
                )
            }
            CertAuthStorableCommand::ChildCertify { child, ki, .. } => {
                write!(f,
                    "Issue certificate to child '{}' for key '{}'",
                    child, ki
                )
            }
            CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => {
                write!(f,
                    "Revoke certificates for child '{}' for key '{}' \
                     in RC {}",
                    child,
                    revoke_req.key(),
                    revoke_req.class_name()
                )
            }
            CertAuthStorableCommand::ChildRemove { child } => {
                write!(f,
                    "Remove child '{}' and revoke & remove its certs",
                    child
                )
            }
            CertAuthStorableCommand::ChildSuspendInactive { child } => {
                write!(f,
                    "Suspend inactive child '{}': stop publishing its certs",
                    child
                )
            }
            CertAuthStorableCommand::ChildUnsuspend { child } => {
                write!(f,
                    "Unsuspend child '{}': publish its unexpired certs",
                    child
                )
            }
            CertAuthStorableCommand::GenerateNewIdKey => {
                write!(f, "Generate a new RFC8183 ID.")
            }
            CertAuthStorableCommand::AddParent { parent, contact } => {
                write!(f, "Add parent '{}' as '{}'", parent, contact)
            }
            CertAuthStorableCommand::UpdateParentContact {
                parent, contact
            } => {
                write!(f,
                    "Update contact for parent '{}' to '{}'",
                    parent, contact
                )
            }
            CertAuthStorableCommand::RemoveParent { parent } => {
                write!(f, "Remove parent '{}'", parent)
            }
            CertAuthStorableCommand::UpdateResourceEntitlements {
                parent, entitlements
            } => {
                write!(f,
                    "Update entitlements under parent '{}': ",
                    parent
                )?;
                for entitlement in entitlements.iter() {
                    write!(f,
                        "{} => {} ",
                        entitlement.resource_class_name,
                        entitlement.resources
                    )?;
                }
                Ok(())
            }
            CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f,
                    "Update received cert in RC '{}', with resources '{}'",
                    resource_class_name, summary
                )
            }
            CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => {
                write!(f,
                    "Removing resource class '{}' because of reason: {}",
                    resource_class_name, reason
                )
            }
            CertAuthStorableCommand::KeyRollInitiate {
                older_than_seconds
            } => {
                write!(f,
                    "Initiate key roll for keys older than '{}' seconds",
                    older_than_seconds
                )
            }
            CertAuthStorableCommand::KeyRollActivate {
                staged_for_seconds
            } => {
                write!(f,
                    "Activate new keys staging longer than '{}' seconds",
                    staged_for_seconds
                )
            }
            CertAuthStorableCommand::KeyRollFinish {
                resource_class_name
            } => {
                write!(f,
                    "Retire old revoked key in RC '{}'",
                    resource_class_name
                )
            }
            CertAuthStorableCommand::RoaDefinitionUpdates { updates } => {
                write!(f, "Update ROAs",)?;
                if !updates.added.is_empty() {
                    write!(f, "  ADD:",)?;
                    for addition in &updates.added {
                        write!(f, " {}", addition)?;
                    }
                }
                if !updates.removed.is_empty() {
                    write!(f, "  REMOVE:",)?;
                    for rem in &updates.removed {
                        write!(f, " {}", rem)?;
                    }
                }
                Ok(())
            }
            CertAuthStorableCommand::ReissueBeforeExpiring => {
                write!(f,
                    "Automatically re-issue objects before they would expire"
                )
            }
            CertAuthStorableCommand::ForceReissue => {
                write!(f, "Force re-issuance of objects")
            }
            CertAuthStorableCommand::AspasUpdate { updates } => {
                write!(f, "{}", updates)
            }
            CertAuthStorableCommand::AspasUpdateExisting {
                customer, update
            } => {
                write!(f,
                    "update ASPA for customer AS: {} {}",
                    customer, update
                )
            }
            CertAuthStorableCommand::AspaRemove { customer } => {
                write!(f, "Remove ASPA for customer AS: {}", customer)
            }
            CertAuthStorableCommand::BgpSecDefinitionUpdates => {
                write!(f, "Update BGPSec definitions")
            }
            CertAuthStorableCommand::RepoUpdate { service_uri } => {
                write!(f, "Update repo to server at: {}", service_uri)
            }
            CertAuthStorableCommand::RtaPrepare { name } => {
                write!(f, "RTA Prepare {}", name)
            }
            CertAuthStorableCommand::RtaSign { name } => {
                write!(f, "RTA Sign {}", name)
            }
            CertAuthStorableCommand::RtaCoSign { name } => {
                write!(f, "RTA Co-Sign {}", name)
            }
            CertAuthStorableCommand::Deactivate => {
                write!(f, "Deactivate CA")
            }
        }
    }
}


//------------ StorableCaCommand --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorableRcEntitlement {
    pub resource_class_name: ResourceClassName,
    pub resources: ResourceSet,
}

