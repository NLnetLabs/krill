use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use chrono::Duration;

use rpki::uri;

use crate::commons::{actor::Actor, api::{
    ChildHandle, Entitlements, Handle, IssuanceRequest, ParentCaContact, ParentHandle, RcvdCert, RepositoryContact,
    ResourceClassName, ResourceSet, RevocationRequest, RevocationResponse, RtaName, StorableCaCommand,
}};
use crate::commons::crypto::IdCert;
use crate::commons::crypto::KrillSigner;
use crate::commons::eventsourcing;
use crate::daemon::ca::{
    Evt, ResourceTaggedAttestation, RouteAuthorizationUpdates, RtaContentRequest, RtaPrepareRequest,
};
use crate::daemon::config::Config;

//------------ Command -----------------------------------------------------

pub type Cmd = eventsourcing::SentCommand<CmdDet>;

//------------ CommandDetails ----------------------------------------------

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CmdDet {
    // ------------------------------------------------------------
    // Being a TA
    // ------------------------------------------------------------
    MakeTrustAnchor(Vec<uri::Https>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Being a parent
    // ------------------------------------------------------------

    // Add a new child under this parent CA
    ChildAdd(ChildHandle, Option<IdCert>, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    ChildUpdateResources(ChildHandle, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    ChildUpdateId(ChildHandle, IdCert),
    // Process an issuance request by an existing child.
    ChildCertify(ChildHandle, IssuanceRequest, Arc<Config>, Arc<KrillSigner>),
    // Process a revoke request by an existing child.
    ChildRevokeKey(ChildHandle, RevocationRequest, Arc<Config>, Arc<KrillSigner>),
    // Remove child (also revokes, and removes issued certs, and republishes)
    ChildRemove(ChildHandle, Arc<Config>, Arc<KrillSigner>),

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
    UpdateResourceClasses(ParentHandle, Entitlements, Arc<KrillSigner>),
    // Process a new certificate received from a parent.
    UpdateRcvdCert(ResourceClassName, RcvdCert, Arc<Config>, Arc<KrillSigner>),

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
    RouteAuthorizationsUpdate(RouteAuthorizationUpdates, Arc<Config>, Arc<KrillSigner>),

    // ------------------------------------------------------------
    // Publishing
    // ------------------------------------------------------------

    // Republish, if needed, may be a no-op if everything is still fresh.
    Republish(Arc<Config>, Arc<KrillSigner>),

    // Update the repository where this CA publishes
    RepoUpdate(RepositoryContact, Arc<Config>, Arc<KrillSigner>),

    // Clean up the old pending to withdraw repo.
    RepoRemoveOld(Arc<KrillSigner>),

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
    type Event = Evt;
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
            CmdDet::MakeTrustAnchor(_, _) => StorableCaCommand::MakeTrustAnchor,

            // ------------------------------------------------------------
            // Being a parent
            // ------------------------------------------------------------
            CmdDet::ChildAdd(child, id_cert_opt, res) => {
                StorableCaCommand::ChildAdd(child, id_cert_opt.map(|c| c.ski_hex()), res)
            }
            CmdDet::ChildUpdateResources(child, res) => StorableCaCommand::ChildUpdateResources(child, res),
            CmdDet::ChildUpdateId(child, id) => StorableCaCommand::ChildUpdateId(child, id.ski_hex()),
            CmdDet::ChildCertify(child, req, _, _) => {
                let (rcn, limit, csr) = req.unpack();
                let ki = csr.public_key().key_identifier();
                StorableCaCommand::ChildCertify(child, rcn, limit, ki)
            }
            CmdDet::ChildRevokeKey(child, req, _, _) => StorableCaCommand::ChildRevokeKey(child, req),
            CmdDet::ChildRemove(child, _, _) => StorableCaCommand::ChildRemove(child),

            // ------------------------------------------------------------
            // Being a child
            // ------------------------------------------------------------
            CmdDet::GenerateNewIdKey(_) => StorableCaCommand::GenerateNewIdKey,
            CmdDet::AddParent(parent, contact) => StorableCaCommand::AddParent(parent, contact.into()),
            CmdDet::UpdateParentContact(parent, contact) => {
                StorableCaCommand::UpdateParentContact(parent, contact.into())
            }
            CmdDet::RemoveParent(parent) => StorableCaCommand::RemoveParent(parent),
            CmdDet::UpdateResourceClasses(parent, entitlements, _) => {
                let mut classes = BTreeMap::new();
                for entitlement in entitlements.classes() {
                    classes.insert(entitlement.class_name().clone(), entitlement.resource_set().clone());
                }

                StorableCaCommand::UpdateResourceClasses(parent, classes)
            }
            CmdDet::UpdateRcvdCert(rcn, rcvd_cert, _, _) => {
                StorableCaCommand::UpdateRcvdCert(rcn, rcvd_cert.resources().clone())
            }

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            CmdDet::KeyRollInitiate(duration, _) => StorableCaCommand::KeyRollInitiate(duration.num_seconds()),
            CmdDet::KeyRollActivate(duration, _, _) => StorableCaCommand::KeyRollActivate(duration.num_seconds()),
            CmdDet::KeyRollFinish(rcn, _) => StorableCaCommand::KeyRollFinish(rcn),

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            CmdDet::RouteAuthorizationsUpdate(updates, _, _) => StorableCaCommand::RoaDefinitionUpdates(updates.into()),

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            CmdDet::Republish(_, _) => StorableCaCommand::Republish,
            CmdDet::RepoUpdate(update, _, _) => {
                let service_uri_opt = match update {
                    RepositoryContact::Embedded(_) => None,
                    RepositoryContact::Rfc8181(res) => Some(res.service_uri().clone()),
                };
                StorableCaCommand::RepoUpdate(service_uri_opt)
            }
            CmdDet::RepoRemoveOld(_) => StorableCaCommand::RepoRemoveOld,

            // ------------------------------------------------------------
            // Resource Tagged Attestations
            // ------------------------------------------------------------
            CmdDet::RtaMultiPrepare(name, _, _) => StorableCaCommand::RtaPrepare(name),
            CmdDet::RtaSign(name, _, _) => StorableCaCommand::RtaSign(name),
            CmdDet::RtaCoSign(name, _, _) => StorableCaCommand::RtaCoSign(name),
        }
    }
}

impl CmdDet {
    /// Turns this CA into a TrustAnchor
    pub fn make_trust_anchor(handle: &Handle, uris: Vec<uri::Https>, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::MakeTrustAnchor(uris, signer), actor)
    }

    /// Adds a child to this CA. Will return an error in case you try
    /// to give the child resources not held by the CA.
    pub fn child_add(
        handle: &Handle,
        child_handle: Handle,
        child_id_cert: Option<IdCert>,
        child_resources: ResourceSet,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildAdd(child_handle, child_id_cert, child_resources),
            actor,
        )
    }

    pub fn child_update_resources(handle: &Handle, child_handle: ChildHandle, resources: ResourceSet, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUpdateResources(child_handle, resources), actor)
    }

    pub fn child_update_id(handle: &Handle, child_handle: ChildHandle, id: IdCert, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUpdateId(child_handle, id), actor)
    }

    /// Certify a child. Will return an error in case the child is
    /// unknown, or in case resources are not held by the child.
    pub fn child_certify(
        handle: &Handle,
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
            actor
        )
    }

    /// Revoke a key for a child.
    pub fn child_revoke_key(
        handle: &Handle,
        child_handle: ChildHandle,
        request: RevocationRequest,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildRevokeKey(child_handle, request, config, signer),
            actor
        )
    }

    pub fn child_remove(
        handle: &Handle,
        child_handle: ChildHandle,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildRemove(child_handle, config, signer), actor)
    }

    pub fn update_id(handle: &Handle, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::GenerateNewIdKey(signer), actor)
    }

    pub fn add_parent(handle: &Handle, parent: ParentHandle, info: ParentCaContact, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::AddParent(parent, info), actor)
    }

    pub fn update_parent(handle: &Handle, parent: ParentHandle, info: ParentCaContact, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::UpdateParentContact(parent, info), actor)
    }

    pub fn remove_parent(handle: &Handle, parent: ParentHandle, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RemoveParent(parent), actor)
    }

    pub fn upd_resource_classes(
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateResourceClasses(parent, entitlements, signer),
            actor
        )
    }

    pub fn upd_received_cert(
        handle: &Handle,
        class_name: ResourceClassName,
        cert: RcvdCert,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::UpdateRcvdCert(class_name, cert, config, signer), actor)
    }

    //-------------------------------------------------------------------------------
    // Key Rolls
    //-------------------------------------------------------------------------------

    pub fn key_roll_init(handle: &Handle, duration: Duration, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollInitiate(duration, signer), actor)
    }

    pub fn key_roll_activate(handle: &Handle, staging: Duration, config: Arc<Config>, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollActivate(staging, config, signer), actor)
    }

    pub fn key_roll_finish(handle: &Handle, rcn: ResourceClassName, res: RevocationResponse, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollFinish(rcn, res), actor)
    }

    pub fn publish(handle: &Handle, config: Arc<Config>, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::Republish(config, signer), actor)
    }

    pub fn update_repo(
        handle: &Handle,
        contact: RepositoryContact,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RepoUpdate(contact, config, signer), actor)
    }

    pub fn remove_old_repo(handle: &Handle, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RepoRemoveOld(signer), actor)
    }

    //-------------------------------------------------------------------------------
    // Route Authorizations
    //-------------------------------------------------------------------------------
    pub fn route_authorizations_update(
        handle: &Handle,
        updates: RouteAuthorizationUpdates,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RouteAuthorizationsUpdate(updates, config, signer), actor)
    }

    //-------------------------------------------------------------------------------
    // Resource Tagged Attestations
    //-------------------------------------------------------------------------------
    pub fn rta_sign(handle: &Handle, name: RtaName, request: RtaContentRequest, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaSign(name, request, signer), actor)
    }

    pub fn rta_multi_prep(handle: &Handle, name: RtaName, request: RtaPrepareRequest, signer: Arc<KrillSigner>, actor: &Actor) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaMultiPrepare(name, request, signer), actor)
    }

    pub fn rta_multi_sign(
        handle: &Handle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> Cmd {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RtaCoSign(name, rta, signer), actor)
    }
}
