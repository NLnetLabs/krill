use std::{fmt, sync::Arc};

use chrono::Duration;

use rpki::{
    ca::{
        idexchange::{CaHandle, ChildHandle, ParentHandle, ServiceUri},
        provisioning::{
            IssuanceRequest, ResourceClassListResponse as Entitlements,
            RequestResourceLimit, ResourceClassName, RevocationRequest,
            RevocationResponse,
        },
    },
    repository::resources::ResourceSet,
};
use rpki::crypto::KeyIdentifier;
use serde::{Deserialize, Serialize};

use crate::{
    commons::{
        actor::Actor,
        crypto::KrillSigner,
        eventsourcing::{
            self, InitCommandDetails, SentCommand, SentInitCommand,
            StoredCommand, WithStorableDetails,
        },
    },
    daemon::{
        ca::{
            CertAuth, CertAuthEvent,
            ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
        },
        config::Config,
    },
};
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

pub type DropReason = String;

//------------ CertAuthInitCommand -----------------------------------------

pub type CertAuthInitCommand = SentInitCommand<CertAuthInitCommandDetails>;

//------------ CertAuthInitCommandDetails ----------------------------------

#[derive(Clone, Debug)]
pub struct CertAuthInitCommandDetails {
    signer: Arc<KrillSigner>,
}

impl CertAuthInitCommandDetails {
    pub fn new(signer: Arc<KrillSigner>) -> Self {
        CertAuthInitCommandDetails { signer }
    }

    pub fn signer(&self) -> &KrillSigner {
        &self.signer
    }
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

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CertAuthCommandDetails {
    // ------------------------------------------------------------
    // Being a parent
    // ------------------------------------------------------------

    // Add a new child under this parent CA
    ChildAdd(ChildHandle, IdCertInfo, ResourceSet),

    // Import a child under this parent CA
    ChildImport(ImportChild, Arc<Config>, Arc<KrillSigner>),

    // Update the resource entitlements for an existing child.
    ChildUpdateResources(ChildHandle, ResourceSet),

    // Update the IdCert used by the child for the RFC 6492 RPKI
    // provisioning protocol.
    ChildUpdateId(ChildHandle, IdCertInfo),

    // Update the mapping the parent uses to map its own resource
    // class name to another name for the child.
    ChildUpdateResourceClassNameMapping(
        ChildHandle,
        ResourceClassNameMapping,
    ),

    // Process an issuance request sent by an existing child.
    ChildCertify(ChildHandle, IssuanceRequest, Arc<Config>, Arc<KrillSigner>),

    // Process a revoke request by an existing child.
    ChildRevokeKey(ChildHandle, RevocationRequest),

    // Remove child (also revokes, and removes issued certs, and
    // republishes)
    ChildRemove(ChildHandle),

    // Suspend a child (done by a background process which checks for
    // inactive children) When a child is inactive it is assumed that
    // they no longer maintain their repository. The certificate(s)
    // issued to the child will be removed (and revoked) until the child
    // is seen again and unsuspended (see below).
    ChildSuspendInactive(ChildHandle),

    // Unsuspend a child (when it contacts the server again). I.e. mark it
    // as active once again and republish existing certificates provided
    // that they are not expired, or about to expire, and do not claim
    // resources no longer associated with this child.
    ChildUnsuspend(ChildHandle),

    // ------------------------------------------------------------
    // Being a child (only allowed if this CA is not self-signed)
    // ------------------------------------------------------------

    // Update our own ID key and cert. Note that this will break
    // communications with RFC6492 parents. This command is added,
    // because we need it for testing that we can update this ID
    // for parents, and children. In practice however, one may not
    // want to use this until RFC8183 is extended with some words
    // on how to re-do the ID exchange.
    GenerateNewIdKey(Arc<KrillSigner>),

    // Add a parent to this CA. Can have multiple parents.
    AddParent(ParentHandle, ParentCaContact),
    // Update a parent's contact
    UpdateParentContact(ParentHandle, ParentCaContact),
    // Remove a parent, freeing up its handle for future (re-)use.
    RemoveParent(ParentHandle),

    // Process new entitlements from a parent and remove/create/update
    // ResourceClasses and certificate requests or key revocation requests
    // as needed.
    UpdateEntitlements(ParentHandle, Entitlements, Arc<KrillSigner>),

    // Process a new certificate received from a parent.
    UpdateRcvdCert(
        ResourceClassName,
        ReceivedCert,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    // Drop a resource class under a parent because of issues
    // obtaining a certificate for it.
    DropResourceClass(ResourceClassName, DropReason, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Key rolls
    // ------------------------------------------------------------

    // Initiate a key roll for all resource classes under each parent, where
    // there is a current active key only, i.e. there is no roll in
    // progress, and this key's age exceeds the given duration.
    KeyRollInitiate(Duration, Arc<KrillSigner>),

    // For all resource classes with a 'new' key with an age exceeding the
    // duration:
    //  - Promote the new key to current key
    //  - Publish all objects under the new current key
    //  - Promote the current key to old key
    //  - Publish a mft and crl only under the old key
    //  - Issue a revoke request for the old key
    //
    // RFC6489 dictates that 24 hours MUST be observed. However, shorter
    // time frames can be used for testing, and in case of emergency
    // rolls.
    KeyRollActivate(Duration, Arc<Config>, Arc<KrillSigner>),

    // Finish the keyroll after the parent confirmed that a key for a parent
    // and resource class has been revoked. I.e. remove the old key, and
    // withdraw the crl and mft for it.
    KeyRollFinish(ResourceClassName, RevocationResponse),

    // ------------------------------------------------------------
    // ROA Support
    // ------------------------------------------------------------

    // Update the authorizations for a CA.
    // Note: ROA *objects* will be created by the CA itself. The command
    // just contains the intent for which announcements should be
    // authorized.
    RouteAuthorizationsUpdate(
        RoaConfigurationUpdates,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    // Re-issue any and all ROA objects which would otherwise expire in
    // some time (default 4 weeks, configurable). Note that this command
    // is intended to be sent by the scheduler - once a day is fine - and
    // will only be stored if there are any updates to be done.
    RouteAuthorizationsRenew(Arc<Config>, Arc<KrillSigner>),

    // Re-issue all ROA objects regardless of their expiration time.
    RouteAuthorizationsForceRenew(Arc<Config>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // ASPA Support
    // ------------------------------------------------------------

    // Update AspaDefinitions, adding new, replacing existing, or
    // removing surplus.
    AspasUpdate(AspaDefinitionUpdates, Arc<Config>, Arc<KrillSigner>),

    // Updates an existing AspaProviders for the given AspaCustomer
    AspasUpdateExisting(
        CustomerAsn,
        AspaProvidersUpdate,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    // Re-issue any and all ASPA objects which would otherwise expire in
    // some time (default 4 weeks, configurable). Note that this command
    // is intended to be sent by the scheduler - once a day is fine - and
    // will only be stored if there are any updates to be done.
    AspasRenew(Arc<Config>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // BGPSec Support
    // ------------------------------------------------------------

    // Update BgpSecDefinitions
    BgpSecUpdateDefinitions(
        BgpSecDefinitionUpdates,
        Arc<Config>,
        Arc<KrillSigner>,
    ),

    // Re-issue any and all BgpSec certificates which would otherwise
    // expire in some time.
    BgpSecRenew(Arc<Config>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Publishing
    // ------------------------------------------------------------

    // Update the repository where this CA publishes
    RepoUpdate(RepositoryContact, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Resource Tagged Attestations
    // ------------------------------------------------------------

    // Sign a new RTA
    RtaSign(RtaName, RtaContentRequest, Arc<KrillSigner>),

    // Prepare a multi-signed RTA
    RtaMultiPrepare(RtaName, RtaPrepareRequest, Arc<KrillSigner>),

    // Co-sign an existing multi-signed RTA
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

impl From<CertAuthCommandDetails> for CertAuthStorableCommand {
    fn from(d: CertAuthCommandDetails) -> Self {
        match d {
            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
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

            // ------------------------------------------------------------
            // Being a child
            // ------------------------------------------------------------
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

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
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

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
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

            // ------------------------------------------------------------
            // ASPA Support
            // ------------------------------------------------------------
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

            // ------------------------------------------------------------
            // BGPSec Support
            // ------------------------------------------------------------
            CertAuthCommandDetails::BgpSecUpdateDefinitions(_, _, _) => {
                CertAuthStorableCommand::BgpSecDefinitionUpdates
            }
            CertAuthCommandDetails::BgpSecRenew(_, _) => {
                CertAuthStorableCommand::ReissueBeforeExpiring
            }

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            CertAuthCommandDetails::RepoUpdate(contact, _) => {
                CertAuthStorableCommand::RepoUpdate {
                    service_uri: contact.server_info.service_uri.clone(),
                }
            }

            // ------------------------------------------------------------
            // Resource Tagged Attestations
            // ------------------------------------------------------------
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

impl CertAuthCommandDetails {
    /// Adds a child to this CA. Will return an error in case you try
    /// to give the child resources not held by the CA.
    pub fn child_add(
        handle: &CaHandle,
        child_handle: ChildHandle,
        id_cert: IdCertInfo,
        resources: ResourceSet,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildAdd(
                child_handle,
                id_cert,
                resources,
            ),
            actor,
        )
    }

    pub fn child_import(
        handle: &CaHandle,
        child: ImportChild,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildImport(child, config, signer),
            actor,
        )
    }

    pub fn child_update_resources(
        handle: &CaHandle,
        child_handle: ChildHandle,
        resources: ResourceSet,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildUpdateResources(
                child_handle,
                resources,
            ),
            actor,
        )
    }

    pub fn child_update_id(
        handle: &CaHandle,
        child_handle: ChildHandle,
        id_cert: IdCertInfo,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildUpdateId(child_handle, id_cert),
            actor,
        )
    }

    pub fn child_update_resource_class_name_mapping(
        handle: &CaHandle,
        child_handle: ChildHandle,
        mapping: ResourceClassNameMapping,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildUpdateResourceClassNameMapping(
                child_handle,
                mapping,
            ),
            actor,
        )
    }

    /// Certify a child. Will return an error in case the child is
    /// unknown, or in case resources are not held by the child.
    pub fn child_certify(
        handle: &CaHandle,
        child_handle: ChildHandle,
        request: IssuanceRequest,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildCertify(
                child_handle,
                request,
                config,
                signer,
            ),
            actor,
        )
    }

    /// Revoke a key for a child.
    pub fn child_revoke_key(
        handle: &CaHandle,
        child_handle: ChildHandle,
        request: RevocationRequest,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildRevokeKey(child_handle, request),
            actor,
        )
    }

    pub fn child_remove(
        handle: &CaHandle,
        child_handle: ChildHandle,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildRemove(child_handle),
            actor,
        )
    }

    pub fn child_suspend_inactive(
        handle: &CaHandle,
        child_handle: ChildHandle,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildSuspendInactive(child_handle),
            actor,
        )
    }

    pub fn child_unsuspend(
        handle: &CaHandle,
        child_handle: ChildHandle,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::ChildUnsuspend(child_handle),
            actor,
        )
    }

    pub fn update_id(
        handle: &CaHandle,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::GenerateNewIdKey(signer),
            actor,
        )
    }

    pub fn add_parent(
        handle: &CaHandle,
        parent: ParentHandle,
        info: ParentCaContact,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::AddParent(parent, info),
            actor,
        )
    }

    pub fn update_parent(
        handle: &CaHandle,
        parent: ParentHandle,
        info: ParentCaContact,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::UpdateParentContact(parent, info),
            actor,
        )
    }

    pub fn remove_parent(
        handle: &CaHandle,
        parent: ParentHandle,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RemoveParent(parent),
            actor,
        )
    }

    pub fn update_entitlements(
        handle: &CaHandle,
        parent: ParentHandle,
        entitlements: Entitlements,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::UpdateEntitlements(
                parent,
                entitlements,
                signer,
            ),
            actor,
        )
    }

    pub fn upd_received_cert(
        handle: &CaHandle,
        class_name: ResourceClassName,
        cert: ReceivedCert,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::UpdateRcvdCert(
                class_name, cert, config, signer,
            ),
            actor,
        )
    }

    pub fn drop_resource_class(
        handle: &CaHandle,
        class_name: ResourceClassName,
        reason: DropReason,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::DropResourceClass(
                class_name, reason, signer,
            ),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // Key Rolls
    //-------------------------------------------------------------------------------

    pub fn key_roll_init(
        handle: &CaHandle,
        duration: Duration,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::KeyRollInitiate(duration, signer),
            actor,
        )
    }

    pub fn key_roll_activate(
        handle: &CaHandle,
        staging: Duration,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::KeyRollActivate(staging, config, signer),
            actor,
        )
    }

    pub fn key_roll_finish(
        handle: &CaHandle,
        rcn: ResourceClassName,
        res: RevocationResponse,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::KeyRollFinish(rcn, res),
            actor,
        )
    }

    pub fn update_repo(
        handle: &CaHandle,
        contact: RepositoryContact,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RepoUpdate(contact, signer),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // Route Authorizations
    //-------------------------------------------------------------------------------
    pub fn route_authorizations_update(
        handle: &CaHandle,
        updates: RoaConfigurationUpdates,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RouteAuthorizationsUpdate(
                updates, config, signer,
            ),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // Autonomous System Provider Authorization
    //-------------------------------------------------------------------------------
    pub fn aspas_definitions_update(
        ca: &CaHandle,
        updates: AspaDefinitionUpdates,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            ca.clone(),
            None,
            CertAuthCommandDetails::AspasUpdate(updates, config, signer),
            actor,
        )
    }

    pub fn aspas_update_aspa(
        ca: &CaHandle,
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            ca.clone(),
            None,
            CertAuthCommandDetails::AspasUpdateExisting(
                customer, update, config, signer,
            ),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // BGPSec
    //-------------------------------------------------------------------------------
    pub fn bgpsec_update_definitions(
        ca: &CaHandle,
        updates: BgpSecDefinitionUpdates,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            ca.clone(),
            None,
            CertAuthCommandDetails::BgpSecUpdateDefinitions(
                updates, config, signer,
            ),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // Resource Tagged Attestations
    //-------------------------------------------------------------------------------
    pub fn rta_sign(
        handle: &CaHandle,
        name: RtaName,
        request: RtaContentRequest,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RtaSign(name, request, signer),
            actor,
        )
    }

    pub fn rta_multi_prep(
        handle: &CaHandle,
        name: RtaName,
        request: RtaPrepareRequest,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RtaMultiPrepare(name, request, signer),
            actor,
        )
    }

    pub fn rta_multi_sign(
        handle: &CaHandle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> CertAuthCommand {
        eventsourcing::SentCommand::new(
            handle.clone(),
            None,
            CertAuthCommandDetails::RtaCoSign(name, rta, signer),
            actor,
        )
    }
}


//------------ CaCommandDetails ----------------------------------------------
pub type CaCommandDetails = StoredCommand<CertAuth>;


//------------ StorableCaCommand -------------------------------------------

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorableRcEntitlement {
    pub resource_class_name: ResourceClassName,
    pub resources: ResourceSet,
}

impl WithStorableDetails for CertAuthStorableCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            CertAuthStorableCommand::Init => CommandSummary::new("cmd-ca-init", self),
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
            CertAuthStorableCommand::ChildUpdateResources { child, resources } => {
                CommandSummary::new("cmd-ca-child-update-res", self)
                    .child(child)
                    .resources(resources)
            }
            CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                CommandSummary::new("cmd-ca-child-update-id", self)
                    .child(child)
                    .id_key(ski)
            }
            CertAuthStorableCommand::ChildUpdateResourceClassNameMapping { child, mapping } => {
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
            } => CommandSummary::new("cmd-ca-child-certify", self)
                .child(child)
                .rcn(resource_class_name)
                .key(*ki),
            CertAuthStorableCommand::ChildRemove { child } => {
                CommandSummary::new("cmd-ca-child-remove", self).child(child)
            }
            CertAuthStorableCommand::ChildSuspendInactive { child } => {
                CommandSummary::new("cmd-ca-child-suspend-inactive", self).child(child)
            }
            CertAuthStorableCommand::ChildUnsuspend { child } => {
                CommandSummary::new("cmd-ca-child-unsuspend", self).child(child)
            }
            CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => {
                CommandSummary::new("cmd-ca-child-revoke", self)
                    .child(child)
                    .rcn(revoke_req.class_name())
                    .key(revoke_req.key())
            }
            CertAuthStorableCommand::GenerateNewIdKey => CommandSummary::new("cmd-ca-generate-new-id", self),
            CertAuthStorableCommand::AddParent { parent, contact } => CommandSummary::new("cmd-ca-parent-add", self)
                .parent(parent)
                .parent_contact(contact),
            CertAuthStorableCommand::UpdateParentContact { parent, contact } => {
                CommandSummary::new("cmd-ca-parent-update", self)
                    .parent(parent)
                    .parent_contact(contact)
            }
            CertAuthStorableCommand::RemoveParent { parent } => {
                CommandSummary::new("cmd-ca-parent-remove", self).parent(parent)
            }
            CertAuthStorableCommand::UpdateResourceEntitlements { parent, .. } => {
                CommandSummary::new("cmd-ca-parent-entitlements", self).parent(parent)
            }
            CertAuthStorableCommand::UpdateRcvdCert {
                resource_class_name,
                resources,
            } => CommandSummary::new("cmd-ca-rcn-receive", self)
                .rcn(resource_class_name)
                .resources(resources),
            CertAuthStorableCommand::DropResourceClass {
                resource_class_name,
                reason,
            } => CommandSummary::new("cmd-ca-rc-drop", self)
                .rcn(resource_class_name)
                .arg("reason", reason),

            // Key rolls
            CertAuthStorableCommand::KeyRollInitiate { older_than_seconds } => {
                CommandSummary::new("cmd-ca-keyroll-init", self).seconds(*older_than_seconds)
            }
            CertAuthStorableCommand::KeyRollActivate { staged_for_seconds } => {
                CommandSummary::new("cmd-ca-keyroll-activate", self).seconds(*staged_for_seconds)
            }
            CertAuthStorableCommand::KeyRollFinish { resource_class_name } => {
                CommandSummary::new("cmd-ca-keyroll-finish", self).rcn(resource_class_name)
            }

            // ROA
            CertAuthStorableCommand::RoaDefinitionUpdates { updates } => {
                CommandSummary::new("cmd-ca-roas-updated", self)
                    .added(updates.added.len())
                    .removed(updates.removed.len())
            }

            // ASPA
            CertAuthStorableCommand::AspasUpdate { .. } => CommandSummary::new("cmd-ca-aspas-update", self),
            CertAuthStorableCommand::AspasUpdateExisting { .. } => {
                CommandSummary::new("cmd-ca-aspas-update-existing", self)
            }
            CertAuthStorableCommand::AspaRemove { .. } => CommandSummary::new("cmd-ca-aspas-remove", self),

            // BGPSec
            CertAuthStorableCommand::BgpSecDefinitionUpdates => CommandSummary::new("cmd-bgpsec-update", self),

            // REPO
            CertAuthStorableCommand::RepoUpdate { service_uri } => {
                CommandSummary::new("cmd-ca-repo-update", self).service_uri(service_uri)
            }

            CertAuthStorableCommand::ReissueBeforeExpiring => {
                CommandSummary::new("cmd-ca-reissue-before-expiring", self)
            }
            CertAuthStorableCommand::ForceReissue => CommandSummary::new("cmd-ca-force-reissue", self),

            // RTA
            CertAuthStorableCommand::RtaPrepare { name } => {
                CommandSummary::new("cmd-ca-rta-prepare", self).rta_name(name)
            }
            CertAuthStorableCommand::RtaSign { name } => {
                CommandSummary::new("cmd-ca-rta-sign", self).rta_name(name)
            }
            CertAuthStorableCommand::RtaCoSign { name } => {
                CommandSummary::new("cmd-ca-rta-cosign", self).rta_name(name)
            }

            // Deactivation
            CertAuthStorableCommand::Deactivate => CommandSummary::new("cmd-ca-deactivate", self),
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl fmt::Display for CertAuthStorableCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // ------------------------------------------------------------
            // Initialisation
            // ------------------------------------------------------------
            CertAuthStorableCommand::Init => write!(f, "Create CA"),

            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
            CertAuthStorableCommand::ChildAdd { child, ski, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(
                    f,
                    "Add child '{}' with RFC8183 key '{}' and resources '{}'",
                    child, ski, summary
                )
            }
            CertAuthStorableCommand::ChildImport { child, ski, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(
                    f,
                    "Import child '{}' with RFC8183 key '{}' and resources '{}'",
                    child, ski, summary
                )
            }
            CertAuthStorableCommand::ChildUpdateResources { child, resources } => {
                let summary = ResourceSetSummary::from(resources);
                write!(f, "Update resources for child '{}' to: {}", child, summary)
            }
            CertAuthStorableCommand::ChildUpdateId { child, ski } => {
                write!(f, "Update child '{}' RFC 8183 key '{}'", child, ski)
            }
            CertAuthStorableCommand::ChildUpdateResourceClassNameMapping { child, mapping } => {
                write!(
                    f,
                    "Update child '{}' map parent RC '{}' to '{}' for child",
                    child, mapping.name_in_parent, mapping.name_for_child
                )
            }
            CertAuthStorableCommand::ChildCertify { child, ki, .. } => {
                write!(f, "Issue certificate to child '{}' for key '{}'", child, ki)
            }
            CertAuthStorableCommand::ChildRevokeKey { child, revoke_req } => write!(
                f,
                "Revoke certificates for child '{}' for key '{}' in RC {}",
                child,
                revoke_req.key(),
                revoke_req.class_name()
            ),
            CertAuthStorableCommand::ChildRemove { child } => {
                write!(f, "Remove child '{}' and revoke & remove its certs", child)
            }
            CertAuthStorableCommand::ChildSuspendInactive { child } => {
                write!(f, "Suspend inactive child '{}': stop publishing its certs", child)
            }
            CertAuthStorableCommand::ChildUnsuspend { child } => {
                write!(f, "Unsuspend child '{}': publish its unexpired certs", child)
            }

            // ------------------------------------------------------------
            // Being a child (only allowed if this CA is not self-signed)
            // ------------------------------------------------------------
            CertAuthStorableCommand::GenerateNewIdKey => write!(f, "Generate a new RFC8183 ID."),
            CertAuthStorableCommand::AddParent { parent, contact } => {
                write!(f, "Add parent '{}' as '{}'", parent, contact)
            }
            CertAuthStorableCommand::UpdateParentContact { parent, contact } => {
                write!(f, "Update contact for parent '{}' to '{}'", parent, contact)
            }
            CertAuthStorableCommand::RemoveParent { parent } => write!(f, "Remove parent '{}'", parent),

            CertAuthStorableCommand::UpdateResourceEntitlements { parent, entitlements } => {
                write!(f, "Update entitlements under parent '{}': ", parent)?;

                for entitlement in entitlements.iter() {
                    write!(f, "{} => {} ", entitlement.resource_class_name, entitlement.resources)?;
                }

                Ok(())
            }
            // Process a new certificate received from a parent.
            CertAuthStorableCommand::UpdateRcvdCert {
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
            CertAuthStorableCommand::DropResourceClass {
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
            CertAuthStorableCommand::KeyRollInitiate { older_than_seconds } => {
                write!(
                    f,
                    "Initiate key roll for keys older than '{}' seconds",
                    older_than_seconds
                )
            }
            CertAuthStorableCommand::KeyRollActivate { staged_for_seconds } => {
                write!(
                    f,
                    "Activate new keys staging longer than '{}' seconds",
                    staged_for_seconds
                )
            }

            CertAuthStorableCommand::KeyRollFinish { resource_class_name } => {
                write!(f, "Retire old revoked key in RC '{}'", resource_class_name)
            }

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
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
                write!(f, "Automatically re-issue objects before they would expire")
            }
            CertAuthStorableCommand::ForceReissue => {
                write!(f, "Force re-issuance of objects")
            }

            // ------------------------------------------------------------
            // ASPA Support
            // ------------------------------------------------------------
            CertAuthStorableCommand::AspasUpdate { updates } => {
                write!(f, "{}", updates)
            }
            CertAuthStorableCommand::AspasUpdateExisting { customer, update } => {
                write!(f, "update ASPA for customer AS: {} {}", customer, update)
            }
            CertAuthStorableCommand::AspaRemove { customer } => {
                write!(f, "Remove ASPA for customer AS: {}", customer)
            }

            // ------------------------------------------------------------
            // BGPSec Support
            // ------------------------------------------------------------
            CertAuthStorableCommand::BgpSecDefinitionUpdates => write!(f, "Update BGPSec definitions"),

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            CertAuthStorableCommand::RepoUpdate { service_uri } => {
                write!(f, "Update repo to server at: {}", service_uri)
            }

            // ------------------------------------------------------------
            // RTA
            // ------------------------------------------------------------
            CertAuthStorableCommand::RtaPrepare { name } => write!(f, "RTA Prepare {}", name),
            CertAuthStorableCommand::RtaSign { name } => write!(f, "RTA Sign {}", name),
            CertAuthStorableCommand::RtaCoSign { name } => write!(f, "RTA Co-Sign {}", name),

            // ------------------------------------------------------------
            // Deactivate
            // ------------------------------------------------------------
            CertAuthStorableCommand::Deactivate => write!(f, "Deactivate CA"),
        }
    }
}

