use std::{fmt, sync::Arc};

use chrono::Duration;

use rpki::{
    ca::{
        idexchange::{CaHandle, ChildHandle, ParentHandle},
        provisioning::{
            IssuanceRequest, ResourceClassListResponse as Entitlements, ResourceClassName, RevocationRequest,
            RevocationResponse,
        },
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{
            AspaCustomer, AspaDefinitionUpdates, AspaProvidersUpdate, BgpSecDefinitionUpdates, IdCertInfo,
            ParentCaContact, ReceivedCert, RepositoryContact, RtaName, StorableCaCommand, StorableRcEntitlement,
        },
        crypto::KrillSigner,
        eventsourcing::{self, StoredCommand},
    },
    daemon::{
        ca::{CaEvt, ResourceTaggedAttestation, RoaDefinitionKeyUpdates, RtaContentRequest, RtaPrepareRequest},
        config::Config,
    },
};

//------------ StoredCaCommand ---------------------------------------------

pub type StoredCaCommand = StoredCommand<StorableCaCommand>;

//------------ Command -----------------------------------------------------

pub type Cmd = eventsourcing::SentCommand<CmdDet>;

pub type DropReason = String;

//------------ CommandDetails ----------------------------------------------

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CmdDet {
    // ------------------------------------------------------------
    // Being a TA
    // ------------------------------------------------------------
    MakeTrustAnchor(Vec<uri::Https>, uri::Rsync, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Being a parent
    // ------------------------------------------------------------

    // Add a new child under this parent CA
    ChildAdd(ChildHandle, IdCertInfo, ResourceSet),

    // Update the resource entitlements for an existing child.
    ChildUpdateResources(ChildHandle, ResourceSet),

    // Update the IdCert used by the child for the RFC 6492 RPKI
    // provisioning protocol.
    ChildUpdateId(ChildHandle, IdCertInfo),

    // Process an issuance request sent by an existing child.
    ChildCertify(ChildHandle, IssuanceRequest, Arc<Config>, Arc<KrillSigner>),

    // Process a revoke request by an existing child.
    ChildRevokeKey(ChildHandle, RevocationRequest),

    // Remove child (also revokes, and removes issued certs, and republishes)
    ChildRemove(ChildHandle),

    // Suspend a child (done by a background process which checks for inactive children)
    // When a child is inactive it is assumed that they no longer maintain their repository.
    // The certificate(s) issued to the child will be removed (and revoked) until
    // the child is seen again and unsuspended (see below).
    ChildSuspendInactive(ChildHandle),

    // Unsuspend a child (when it contacts the server again). I.e. mark it as active once
    // again and republish existing certificates provided that they are not expired, or
    // about to expire, and do not claim resources no longer associated with this child.
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
    UpdateRcvdCert(ResourceClassName, ReceivedCert, Arc<Config>, Arc<KrillSigner>),

    // Drop a resource class under a parent because of issues
    // obtaining a certificate for it.
    DropResourceClass(ResourceClassName, DropReason, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Key rolls
    // ------------------------------------------------------------

    // Initiate a key roll for all resource classes under each parent, where there is
    // a current active key only, i.e. there is no roll in progress, and this key's age
    // exceeds the given duration.
    KeyRollInitiate(Duration, Arc<KrillSigner>),

    // For all resource classes with a 'new' key with an age exceeding the duration:
    //  - Promote the new key to current key
    //  - Publish all objects under the new current key
    //  - Promote the current key to old key
    //  - Publish a mft and crl only under the old key
    //  - Issue a revoke request for the old key
    //
    // RFC6489 dictates that 24 hours MUST be observed. However, shorter time frames can
    // be used for testing, and in case of emergency rolls.
    KeyRollActivate(Duration, Arc<Config>, Arc<KrillSigner>),

    // Finish the keyroll after the parent confirmed that a key for a parent and resource
    // class has been revoked. I.e. remove the old key, and withdraw the crl and mft for it.
    KeyRollFinish(ResourceClassName, RevocationResponse),

    // ------------------------------------------------------------
    // ROA Support
    // ------------------------------------------------------------

    // Update the authorizations for a CA.
    // Note: ROA *objects* will be created by the CA itself. The command just
    // contains the intent for which announcements should be authorized.
    RouteAuthorizationsUpdate(RoaDefinitionKeyUpdates, Arc<Config>, Arc<KrillSigner>),

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
    AspasUpdateExisting(AspaCustomer, AspaProvidersUpdate, Arc<Config>, Arc<KrillSigner>),

    // Re-issue any and all ASPA objects which would otherwise expire in
    // some time (default 4 weeks, configurable). Note that this command
    // is intended to be sent by the scheduler - once a day is fine - and
    // will only be stored if there are any updates to be done.
    AspasRenew(Arc<Config>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // BGPSec Support
    // ------------------------------------------------------------

    // Update BgpSecDefinitions
    BgpSecUpdateDefinitions(BgpSecDefinitionUpdates, Arc<Config>, Arc<KrillSigner>),

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

impl eventsourcing::CommandDetails for CmdDet {
    type Event = CaEvt;
    type StorableDetails = StorableCaCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl fmt::Display for CmdDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableCaCommand::from(self.clone()).fmt(f)
    }
}

impl From<CmdDet> for StorableCaCommand {
    fn from(d: CmdDet) -> Self {
        match d {
            // ------------------------------------------------------------
            // Being a TA
            // ------------------------------------------------------------
            CmdDet::MakeTrustAnchor(_, _, _) => StorableCaCommand::MakeTrustAnchor,

            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
            CmdDet::ChildAdd(child, id_cert, resources) => StorableCaCommand::ChildAdd {
                child,
                ski: id_cert.public_key().key_identifier().to_string(),
                resources,
            },
            CmdDet::ChildUpdateResources(child, resources) => {
                StorableCaCommand::ChildUpdateResources { child, resources }
            }
            CmdDet::ChildUpdateId(child, id_cert) => StorableCaCommand::ChildUpdateId {
                child,
                ski: id_cert.public_key().key_identifier().to_string(),
            },
            CmdDet::ChildCertify(child, req, _, _) => {
                let (resource_class_name, limit, csr) = req.unpack();
                let ki = csr.public_key().key_identifier();
                StorableCaCommand::ChildCertify {
                    child,
                    resource_class_name,
                    limit,
                    ki,
                }
            }
            CmdDet::ChildRevokeKey(child, revoke_req) => StorableCaCommand::ChildRevokeKey { child, revoke_req },
            CmdDet::ChildRemove(child) => StorableCaCommand::ChildRemove { child },
            CmdDet::ChildSuspendInactive(child) => StorableCaCommand::ChildSuspendInactive { child },
            CmdDet::ChildUnsuspend(child) => StorableCaCommand::ChildUnsuspend { child },

            // ------------------------------------------------------------
            // Being a child
            // ------------------------------------------------------------
            CmdDet::GenerateNewIdKey(_) => StorableCaCommand::GenerateNewIdKey,
            CmdDet::AddParent(parent, contact) => StorableCaCommand::AddParent {
                parent,
                contact: contact.into(),
            },
            CmdDet::UpdateParentContact(parent, contact) => StorableCaCommand::UpdateParentContact {
                parent,
                contact: contact.into(),
            },
            CmdDet::RemoveParent(parent) => StorableCaCommand::RemoveParent { parent },
            CmdDet::UpdateEntitlements(parent, cmd_entitlements, _) => {
                let mut entitlements = vec![];
                for entitlement in cmd_entitlements.classes() {
                    entitlements.push(StorableRcEntitlement {
                        resource_class_name: entitlement.class_name().clone(),
                        resources: entitlement.resource_set().clone(),
                    });
                }

                StorableCaCommand::UpdateResourceEntitlements { parent, entitlements }
            }
            CmdDet::UpdateRcvdCert(resource_class_name, rcvd_cert, _, _) => StorableCaCommand::UpdateRcvdCert {
                resource_class_name,
                resources: rcvd_cert.resources().clone(),
            },
            CmdDet::DropResourceClass(resource_class_name, reason, _) => StorableCaCommand::DropResourceClass {
                resource_class_name,
                reason,
            },

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            CmdDet::KeyRollInitiate(older_than, _) => StorableCaCommand::KeyRollInitiate {
                older_than_seconds: older_than.num_seconds(),
            },
            CmdDet::KeyRollActivate(staged_for, _, _) => StorableCaCommand::KeyRollActivate {
                staged_for_seconds: staged_for.num_seconds(),
            },
            CmdDet::KeyRollFinish(resource_class_name, _) => StorableCaCommand::KeyRollFinish { resource_class_name },

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            CmdDet::RouteAuthorizationsUpdate(updates, _, _) => StorableCaCommand::RoaDefinitionUpdates {
                updates: updates.into(),
            },
            CmdDet::RouteAuthorizationsRenew(_, _) => StorableCaCommand::ReissueBeforeExpiring,
            CmdDet::RouteAuthorizationsForceRenew(_, _) => StorableCaCommand::ForceReissue,

            // ------------------------------------------------------------
            // ASPA Support
            // ------------------------------------------------------------
            CmdDet::AspasUpdate(updates, _, _) => StorableCaCommand::AspasUpdate { updates },
            CmdDet::AspasUpdateExisting(customer, update, _, _) => {
                StorableCaCommand::AspasUpdateExisting { customer, update }
            }
            CmdDet::AspasRenew(_, _) => StorableCaCommand::ReissueBeforeExpiring,

            // ------------------------------------------------------------
            // BGPSec Support
            // ------------------------------------------------------------
            CmdDet::BgpSecUpdateDefinitions(_, _, _) => StorableCaCommand::BgpSecDefinitionUpdates,
            CmdDet::BgpSecRenew(_, _) => StorableCaCommand::ReissueBeforeExpiring,

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            CmdDet::RepoUpdate(contact, _) => StorableCaCommand::RepoUpdate {
                service_uri: contact.server_info().service_uri().clone(),
            },

            // ------------------------------------------------------------
            // Resource Tagged Attestations
            // ------------------------------------------------------------
            CmdDet::RtaMultiPrepare(name, _, _) => StorableCaCommand::RtaPrepare { name },
            CmdDet::RtaSign(name, _, _) => StorableCaCommand::RtaSign { name },
            CmdDet::RtaCoSign(name, _, _) => StorableCaCommand::RtaCoSign { name },
        }
    }
}

impl CmdDet {
    /// Turns this CA into a TrustAnchor
    pub fn make_trust_anchor(
        handle: &CaHandle,
        uris: Vec<uri::Https>,
        rsync_uri: uri::Rsync,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::MakeTrustAnchor(uris, rsync_uri, signer), actor)
    }

    /// Adds a child to this CA. Will return an error in case you try
    /// to give the child resources not held by the CA.
    pub fn child_add(
        handle: &CaHandle,
        child_handle: ChildHandle,
        id_cert: IdCertInfo,
        resources: ResourceSet,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildAdd(child_handle, id_cert, resources), actor)
    }

    pub fn child_update_resources(
        handle: &CaHandle,
        child_handle: ChildHandle,
        resources: ResourceSet,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildUpdateResources(child_handle, resources),
            actor,
        )
    }

    pub fn child_update_id(handle: &CaHandle, child_handle: ChildHandle, id_cert: IdCertInfo, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUpdateId(child_handle, id_cert), actor)
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
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildCertify(child_handle, request, config, signer),
            actor,
        )
    }

    /// Revoke a key for a child.
    pub fn child_revoke_key(
        handle: &CaHandle,
        child_handle: ChildHandle,
        request: RevocationRequest,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildRevokeKey(child_handle, request), actor)
    }

    pub fn child_remove(handle: &CaHandle, child_handle: ChildHandle, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildRemove(child_handle), actor)
    }

    pub fn child_suspend_inactive(handle: &CaHandle, child_handle: ChildHandle, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildSuspendInactive(child_handle), actor)
    }

    pub fn child_unsuspend(handle: &CaHandle, child_handle: ChildHandle, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUnsuspend(child_handle), actor)
    }

    pub fn update_id(handle: &CaHandle, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::GenerateNewIdKey(signer), actor)
    }

    pub fn add_parent(handle: &CaHandle, parent: ParentHandle, info: ParentCaContact, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::AddParent(parent, info), actor)
    }

    pub fn update_parent(handle: &CaHandle, parent: ParentHandle, info: ParentCaContact, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::UpdateParentContact(parent, info), actor)
    }

    pub fn remove_parent(handle: &CaHandle, parent: ParentHandle, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RemoveParent(parent), actor)
    }

    pub fn update_entitlements(
        handle: &CaHandle,
        parent: ParentHandle,
        entitlements: Entitlements,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateEntitlements(parent, entitlements, signer),
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
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateRcvdCert(class_name, cert, config, signer),
            actor,
        )
    }

    pub fn drop_resource_class(
        handle: &CaHandle,
        class_name: ResourceClassName,
        reason: DropReason,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::DropResourceClass(class_name, reason, signer),
            actor,
        )
    }

    //-------------------------------------------------------------------------------
    // Key Rolls
    //-------------------------------------------------------------------------------

    pub fn key_roll_init(handle: &CaHandle, duration: Duration, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollInitiate(duration, signer), actor)
    }

    pub fn key_roll_activate(
        handle: &CaHandle,
        staging: Duration,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollActivate(staging, config, signer), actor)
    }

    pub fn key_roll_finish(handle: &CaHandle, rcn: ResourceClassName, res: RevocationResponse, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollFinish(rcn, res), actor)
    }

    pub fn update_repo(handle: &CaHandle, contact: RepositoryContact, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RepoUpdate(contact, signer), actor)
    }

    //-------------------------------------------------------------------------------
    // Route Authorizations
    //-------------------------------------------------------------------------------
    pub fn route_authorizations_update(
        handle: &CaHandle,
        updates: RoaDefinitionKeyUpdates,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::RouteAuthorizationsUpdate(updates, config, signer),
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
    ) -> Cmd {
        eventsourcing::SentCommand::new(ca, None, CmdDet::AspasUpdate(updates, config, signer), actor)
    }

    pub fn aspas_update_aspa(
        ca: &CaHandle,
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            ca,
            None,
            CmdDet::AspasUpdateExisting(customer, update, config, signer),
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
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            ca,
            None,
            CmdDet::BgpSecUpdateDefinitions(updates, config, signer),
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
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaSign(name, request, signer), actor)
    }

    pub fn rta_multi_prep(
        handle: &CaHandle,
        name: RtaName,
        request: RtaPrepareRequest,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaMultiPrepare(name, request, signer), actor)
    }

    pub fn rta_multi_sign(
        handle: &CaHandle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaCoSign(name, rta, signer), actor)
    }
}
