use std::fmt;
use std::sync::{Arc, RwLock};

use chrono::Duration;

use rpki::uri;

use crate::commons::api::{
    ChildHandle, Entitlements, Handle, IssuanceRequest, ParentCaContact, ParentHandle, RcvdCert,
    RepositoryContact, ResourceClassName, ResourceSet, RevocationRequest, RevocationResponse,
    UpdateChildRequest,
};
use crate::commons::eventsourcing;
use crate::commons::remote::id::IdCert;
use crate::daemon::ca::{Evt, RouteAuthorizationUpdates, Signer};

//------------ Command -----------------------------------------------------

pub type Cmd<S> = eventsourcing::SentCommand<CmdDet<S>>;

//------------ StorableCaCommand -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum StorableCaCommand {
    MakeTrustAnchor,
    ChildAdd(ChildHandle, Option<IdCert>, ResourceSet),
    ChildUpdate(ChildHandle, UpdateChildRequest),
    ChildCertify(ChildHandle, IssuanceRequest),
    ChildRevokeKey(ChildHandle, RevocationRequest),
    ChildRemove(ChildHandle),
    GenerateNewIdKey,
    AddParent(ParentHandle, ParentCaContact),
    UpdateParentContact(ParentHandle, ParentCaContact),
    RemoveParent(ParentHandle),
    UpdateResourceClasses(ParentHandle, Entitlements),
    UpdateRcvdCert(ResourceClassName, RcvdCert),
    KeyRollInitiate(i64),
    KeyRollActivate(i64),
    KeyRollFinish(ResourceClassName),
    RouteAuthorizationsUpdate(RouteAuthorizationUpdates),
    Republish,
    RepoUpdate(RepositoryContact),
    RepoRemoveOld,
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
            StorableCaCommand::ChildAdd(child, id_cert_opt, res) => write!(
                f,
                "Add child '{}' with RFC8183 key '{}' and resources '{}'",
                child,
                id_cert_opt
                    .as_ref()
                    .map(|c| c.ski_hex())
                    .unwrap_or_else(|| "<none>".to_string()),
                res
            ),
            StorableCaCommand::ChildUpdate(child, update_req) => {
                write!(f, "Update child '{}' with {}", child, update_req)
            }
            StorableCaCommand::ChildCertify(child, req) => {
                write!(f, "Certify child '{}' for request '{}'", child, req)
            }
            StorableCaCommand::ChildRevokeKey(child, req) => {
                write!(f, "Revoke child '{}' request '{}'", child, req)
            }
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

            StorableCaCommand::UpdateResourceClasses(parent, entitlements) => write!(
                f,
                "Update entitlements under parent '{}' to '{}",
                parent, entitlements
            ),
            // Process a new certificate received from a parent.
            StorableCaCommand::UpdateRcvdCert(rcn, rcvd_cert) => write!(
                f,
                "Update received cert in RC '{}', with resources '{}'",
                rcn,
                rcvd_cert.resources()
            ),

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            StorableCaCommand::KeyRollInitiate(duration) => {
                write!(f, "Initiate key roll for keys older than '{}'", duration)
            }
            StorableCaCommand::KeyRollActivate(duration) => {
                write!(f, "Activate new keys older than '{}' in key roll", duration)
            }

            StorableCaCommand::KeyRollFinish(rcn) => {
                write!(f, "Retire old revoked key in RC '{}'", rcn)
            }

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            StorableCaCommand::RouteAuthorizationsUpdate(updates) => {
                write!(f, "Update ROAs '{}'", updates)
            }

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            StorableCaCommand::Republish => write!(f, "Republish (if needed)"),
            StorableCaCommand::RepoUpdate(update) => match update {
                RepositoryContact::Embedded(_) => write!(f, "Update repo to embedded server"),
                RepositoryContact::Rfc8181(res) => {
                    write!(f, "Update repo to server at: {}", res.service_uri())
                }
            },
            StorableCaCommand::RepoRemoveOld => write!(f, "Clean up old repository (if present)."),
        }
    }
}

//------------ CommandDetails ----------------------------------------------

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CmdDet<S: Signer> {
    // ------------------------------------------------------------
    // Being a TA
    // ------------------------------------------------------------
    MakeTrustAnchor(Vec<uri::Https>, Arc<RwLock<S>>),

    // ------------------------------------------------------------
    // Being a parent
    // ------------------------------------------------------------

    // Add a new child under this parent CA
    ChildAdd(ChildHandle, Option<IdCert>, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    ChildUpdate(ChildHandle, UpdateChildRequest),
    // Process an issuance request by an existing child.
    ChildCertify(ChildHandle, IssuanceRequest, Arc<RwLock<S>>),
    // Process a revoke request by an existing child.
    ChildRevokeKey(ChildHandle, RevocationRequest, Arc<RwLock<S>>),
    // Remove child (also revokes, and removes issued certs, and republishes)
    ChildRemove(ChildHandle, Arc<RwLock<S>>),

    // ------------------------------------------------------------
    // Being a child (only allowed if this CA is not self-signed)
    // ------------------------------------------------------------

    // Update our own ID key and cert. Note that this will break
    // communications with RFC6492 parents. This command is added,
    // because we need it for testing that we can update this ID
    // for parents, and children. In practice however, one may not
    // want to use this until RFC8183 is extended with some words
    // on how to re-do the ID exchange.
    GenerateNewIdKey(Arc<RwLock<S>>),

    // Add a parent to this CA. Can have multiple parents.
    AddParent(ParentHandle, ParentCaContact),
    // Update a parent's contact
    UpdateParentContact(ParentHandle, ParentCaContact),
    // Remove a parent, freeing up its handle for future (re-)use.
    RemoveParent(ParentHandle),

    // Process new entitlements from a parent and remove/create/update
    // ResourceClasses and certificate requests or key revocation requests
    // as needed.
    UpdateResourceClasses(ParentHandle, Entitlements, Arc<RwLock<S>>),
    // Process a new certificate received from a parent.
    UpdateRcvdCert(ResourceClassName, RcvdCert, Arc<RwLock<S>>),

    // ------------------------------------------------------------
    // Key rolls
    // ------------------------------------------------------------

    // Initiate a key roll for all resource classes under each parent, where there is
    // a current active key only, i.e. there is no roll in progress, and this key's age
    // exceeds the given duration.
    KeyRollInitiate(Duration, Arc<RwLock<S>>),

    // For all resource classes with a 'new' key with an age exceeding the duration:
    //  - Promote the new key to current key
    //  - Publish all objects under the new current key
    //  - Promote the current key to old key
    //  - Publish a mft and crl only under the old key
    //  - Issue a revoke request for the old key
    //
    // RFC6489 dictates that 24 hours MUST be observed. However, shorter time frames can
    // be used for testing, and in case of emergency rolls.
    KeyRollActivate(Duration, Arc<RwLock<S>>),

    // Finish the keyroll after the parent confirmed that a key for a parent and resource
    // class has been revoked. I.e. remove the old key, and withdraw the crl and mft for it.
    KeyRollFinish(ResourceClassName, RevocationResponse),

    // ------------------------------------------------------------
    // ROA Support
    // ------------------------------------------------------------
    RouteAuthorizationsUpdate(RouteAuthorizationUpdates, Arc<RwLock<S>>),

    // ------------------------------------------------------------
    // Publishing
    // ------------------------------------------------------------

    // Republish, if needed, may be a no-op if everything is still fresh.
    Republish(Arc<RwLock<S>>),

    // Update the repository where this CA publishes
    RepoUpdate(RepositoryContact, Arc<RwLock<S>>),

    // Clean up the old pending to withdraw repo.
    RepoRemoveOld(Arc<RwLock<S>>),
}

impl<S: Signer> eventsourcing::CommandDetails for CmdDet<S> {
    type Event = Evt;
    type StorableDetails = StorableCaCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl<S: Signer> fmt::Display for CmdDet<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableCaCommand::from(self.clone()).fmt(f)
    }
}

impl<S: Signer> From<CmdDet<S>> for StorableCaCommand {
    fn from(d: CmdDet<S>) -> Self {
        match d {
            CmdDet::MakeTrustAnchor(_, _) => StorableCaCommand::MakeTrustAnchor,
            CmdDet::ChildAdd(child, id_cert_opt, res) => {
                StorableCaCommand::ChildAdd(child, id_cert_opt, res)
            }

            CmdDet::ChildUpdate(child, update_req) => {
                StorableCaCommand::ChildUpdate(child, update_req)
            }
            CmdDet::ChildCertify(child, req, _) => StorableCaCommand::ChildCertify(child, req),
            CmdDet::ChildRevokeKey(child, req, _) => StorableCaCommand::ChildRevokeKey(child, req),
            CmdDet::ChildRemove(child, _) => StorableCaCommand::ChildRemove(child),
            CmdDet::GenerateNewIdKey(_) => StorableCaCommand::GenerateNewIdKey,
            CmdDet::AddParent(parent, contact) => StorableCaCommand::AddParent(parent, contact),
            CmdDet::UpdateParentContact(parent, contact) => {
                StorableCaCommand::UpdateParentContact(parent, contact)
            }
            CmdDet::RemoveParent(parent) => StorableCaCommand::RemoveParent(parent),
            CmdDet::UpdateResourceClasses(parent, entitlements, _) => {
                StorableCaCommand::UpdateResourceClasses(parent, entitlements)
            }
            CmdDet::UpdateRcvdCert(rcn, rcvd_cert, _) => {
                StorableCaCommand::UpdateRcvdCert(rcn, rcvd_cert)
            }
            CmdDet::KeyRollInitiate(duration, _) => {
                StorableCaCommand::KeyRollInitiate(duration.num_seconds())
            }
            CmdDet::KeyRollActivate(duration, _) => {
                StorableCaCommand::KeyRollActivate(duration.num_seconds())
            }
            CmdDet::KeyRollFinish(rcn, _) => StorableCaCommand::KeyRollFinish(rcn),
            CmdDet::RouteAuthorizationsUpdate(updates, _) => {
                StorableCaCommand::RouteAuthorizationsUpdate(updates)
            }
            CmdDet::Republish(_) => StorableCaCommand::Republish,
            CmdDet::RepoUpdate(update, _) => StorableCaCommand::RepoUpdate(update),
            CmdDet::RepoRemoveOld(_) => StorableCaCommand::RepoRemoveOld,
        }
    }
}

impl<S: Signer> CmdDet<S> {
    /// Turns this CA into a TrustAnchor
    pub fn make_trust_anchor(
        handle: &Handle,
        uris: Vec<uri::Https>,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::MakeTrustAnchor(uris, signer))
    }

    /// Adds a child to this CA. Will return an error in case you try
    /// to give the child resources not held by the CA.
    pub fn child_add(
        handle: &Handle,
        child_handle: Handle,
        child_id_cert: Option<IdCert>,
        child_resources: ResourceSet,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildAdd(child_handle, child_id_cert, child_resources),
        )
    }

    pub fn child_update(
        handle: &Handle,
        child_handle: ChildHandle,
        req: UpdateChildRequest,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUpdate(child_handle, req))
    }

    /// Certify a child. Will return an error in case the child is
    /// unknown, or in case resources are not held by the child.
    pub fn child_certify(
        handle: &Handle,
        child_handle: ChildHandle,
        request: IssuanceRequest,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildCertify(child_handle, request, signer),
        )
    }

    /// Revoke a key for a child.
    pub fn child_revoke_key(
        handle: &Handle,
        child_handle: ChildHandle,
        request: RevocationRequest,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildRevokeKey(child_handle, request, signer),
        )
    }

    pub fn child_remove(
        handle: &Handle,
        child_handle: ChildHandle,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildRemove(child_handle, signer))
    }

    pub fn update_id(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::GenerateNewIdKey(signer))
    }

    pub fn add_parent(handle: &Handle, parent: ParentHandle, info: ParentCaContact) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::AddParent(parent, info))
    }

    pub fn update_parent(handle: &Handle, parent: ParentHandle, info: ParentCaContact) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::UpdateParentContact(parent, info))
    }

    pub fn remove_parent(handle: &Handle, parent: ParentHandle) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RemoveParent(parent))
    }

    pub fn upd_resource_classes(
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateResourceClasses(parent, entitlements, signer),
        )
    }

    pub fn upd_received_cert(
        handle: &Handle,
        class_name: ResourceClassName,
        cert: RcvdCert,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateRcvdCert(class_name, cert, signer),
        )
    }

    //-------------------------------------------------------------------------------
    // Key Rolls
    //-------------------------------------------------------------------------------

    pub fn key_roll_init(handle: &Handle, duration: Duration, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollInitiate(duration, signer))
    }

    pub fn key_roll_activate(handle: &Handle, staging: Duration, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollActivate(staging, signer))
    }

    pub fn key_roll_finish(
        handle: &Handle,
        rcn: ResourceClassName,
        res: RevocationResponse,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollFinish(rcn, res))
    }

    pub fn publish(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::Republish(signer))
    }

    pub fn update_repo(
        handle: &Handle,
        contact: RepositoryContact,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RepoUpdate(contact, signer))
    }

    pub fn remove_old_repo(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::RepoRemoveOld(signer))
    }

    //-------------------------------------------------------------------------------
    // Route Authorizations
    //-------------------------------------------------------------------------------
    pub fn route_authorizations_update(
        handle: &Handle,
        updates: RouteAuthorizationUpdates,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::RouteAuthorizationsUpdate(updates, signer),
        )
    }
}
