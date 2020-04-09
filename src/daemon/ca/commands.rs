use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use chrono::Duration;

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::commons::api::{
    ChildHandle, Entitlements, Handle, IssuanceRequest, ParentCaContact, ParentHandle, RcvdCert,
    RepositoryContact, RequestResourceLimit, ResourceClassName, ResourceSet, RevocationRequest,
    RevocationResponse, RoaDefinitionUpdates,
};
use crate::commons::eventsourcing;
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc8183::ServiceUri;
use crate::daemon::ca::{Evt, RouteAuthorizationUpdates, Signer};

//------------ Command -----------------------------------------------------

pub type Cmd<S> = eventsourcing::SentCommand<CmdDet<S>>;

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorableParentContact {
    #[display(fmt = "This CA is a TA")]
    Ta,

    #[display(fmt = "Embedded parent")]
    Embedded,

    #[display(fmt = "RFC 6492 Parent")]
    Rfc6492,
}

impl From<ParentCaContact> for StorableParentContact {
    fn from(parent: ParentCaContact) -> Self {
        match parent {
            ParentCaContact::Ta(_) => StorableParentContact::Ta,
            ParentCaContact::Embedded => StorableParentContact::Embedded,
            ParentCaContact::Rfc6492(_) => StorableParentContact::Rfc6492,
        }
    }
}

//------------ StorableCaCommand -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum StorableCaCommand {
    MakeTrustAnchor,
    ChildAdd(ChildHandle, Option<String>, ResourceSet),
    ChildUpdateResources(ChildHandle, ResourceSet),
    ChildUpdateId(ChildHandle),
    ChildCertify(
        ChildHandle,
        ResourceClassName,
        RequestResourceLimit,
        KeyIdentifier,
    ),
    ChildRevokeKey(ChildHandle, RevocationRequest),
    ChildRemove(ChildHandle),
    GenerateNewIdKey,
    AddParent(ParentHandle, StorableParentContact),
    UpdateParentContact(ParentHandle, StorableParentContact),
    RemoveParent(ParentHandle),
    UpdateResourceClasses(ParentHandle, HashMap<ResourceClassName, ResourceSet>),
    UpdateRcvdCert(ResourceClassName, ResourceSet),
    KeyRollInitiate(i64),
    KeyRollActivate(i64),
    KeyRollFinish(ResourceClassName),
    RoaDefinitionUpdates(RoaDefinitionUpdates),
    Republish,
    RepoUpdate(Option<ServiceUri>),
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
            StorableCaCommand::ChildAdd(child, id_ski_opt, res) => write!(
                f,
                "Add child '{}' with RFC8183 key '{}' and resources '{}'",
                child,
                id_ski_opt
                    .as_ref()
                    .map(|ski| ski.as_str())
                    .unwrap_or_else(|| "<none>"),
                res
            ),
            StorableCaCommand::ChildUpdateResources(child, resources) => {
                write!(f, "Update child '{}' resources to: {}", child, resources)
            }
            StorableCaCommand::ChildUpdateId(child) => {
                write!(f, "Update child '{}' ID certificate", child)
            }
            StorableCaCommand::ChildCertify(child, _rcn, _limit, key) => {
                write!(f, "Issue certificate to child '{}' for key '{}", child, key)
            }
            StorableCaCommand::ChildRevokeKey(child, req) => write!(
                f,
                "Revoke certificates for child '{}' for key '{}' in RC {}",
                child,
                req.key(),
                req.class_name()
            ),
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

            StorableCaCommand::UpdateResourceClasses(parent, classes) => {
                let mut summary = format!("Update entitlements under parent '{}': ", parent);

                for (class_name, resource_set) in classes.iter() {
                    summary.push_str(&format!("{} => {} ", class_name, resource_set))
                }

                write!(f, "{}", summary)
            }
            // Process a new certificate received from a parent.
            StorableCaCommand::UpdateRcvdCert(rcn, resources) => write!(
                f,
                "Update received cert in RC '{}', with resources '{}'",
                rcn, resources
            ),

            // ------------------------------------------------------------
            // Key rolls
            // ------------------------------------------------------------
            StorableCaCommand::KeyRollInitiate(duration) => write!(
                f,
                "Initiate key roll for keys older than '{}' seconds",
                duration
            ),
            StorableCaCommand::KeyRollActivate(duration) => write!(
                f,
                "Activate new keys staging longer than '{}' seconds",
                duration
            ),

            StorableCaCommand::KeyRollFinish(rcn) => {
                write!(f, "Retire old revoked key in RC '{}'", rcn)
            }

            // ------------------------------------------------------------
            // ROA Support
            // ------------------------------------------------------------
            StorableCaCommand::RoaDefinitionUpdates(updates) => write!(
                f,
                "Update ROAs add: {} remove: '{}'",
                updates.added().len(),
                updates.removed().len()
            ),

            // ------------------------------------------------------------
            // Publishing
            // ------------------------------------------------------------
            StorableCaCommand::Republish => write!(f, "Republish"),
            StorableCaCommand::RepoUpdate(service_uri_opt) => match service_uri_opt {
                None => write!(f, "Update repo to embedded server"),
                Some(uri) => write!(f, "Update repo to server at: {}", uri),
            },
            StorableCaCommand::RepoRemoveOld => write!(f, "Clean up old repository"),
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
    ChildUpdateResources(ChildHandle, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    ChildUpdateId(ChildHandle, IdCert),
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
                StorableCaCommand::ChildAdd(child, id_cert_opt.map(|c| c.ski_hex()), res)
            }
            CmdDet::ChildUpdateResources(child, res) => {
                StorableCaCommand::ChildUpdateResources(child, res)
            }
            CmdDet::ChildUpdateId(child, _) => StorableCaCommand::ChildUpdateId(child),
            CmdDet::ChildCertify(child, req, _) => {
                let (rcn, limit, csr) = req.unpack();
                let ki = csr.public_key().key_identifier();
                StorableCaCommand::ChildCertify(child, rcn, limit, ki)
            }
            CmdDet::ChildRevokeKey(child, req, _) => StorableCaCommand::ChildRevokeKey(child, req),
            CmdDet::ChildRemove(child, _) => StorableCaCommand::ChildRemove(child),
            CmdDet::GenerateNewIdKey(_) => StorableCaCommand::GenerateNewIdKey,
            CmdDet::AddParent(parent, contact) => {
                StorableCaCommand::AddParent(parent, contact.into())
            }
            CmdDet::UpdateParentContact(parent, contact) => {
                StorableCaCommand::UpdateParentContact(parent, contact.into())
            }
            CmdDet::RemoveParent(parent) => StorableCaCommand::RemoveParent(parent),
            CmdDet::UpdateResourceClasses(parent, entitlements, _) => {
                let mut classes = HashMap::new();
                for entitlement in entitlements.classes() {
                    classes.insert(
                        entitlement.class_name().clone(),
                        entitlement.resource_set().clone(),
                    );
                }

                StorableCaCommand::UpdateResourceClasses(parent, classes)
            }
            CmdDet::UpdateRcvdCert(rcn, rcvd_cert, _) => {
                StorableCaCommand::UpdateRcvdCert(rcn, rcvd_cert.resources().clone())
            }
            CmdDet::KeyRollInitiate(duration, _) => {
                StorableCaCommand::KeyRollInitiate(duration.num_seconds())
            }
            CmdDet::KeyRollActivate(duration, _) => {
                StorableCaCommand::KeyRollActivate(duration.num_seconds())
            }
            CmdDet::KeyRollFinish(rcn, _) => StorableCaCommand::KeyRollFinish(rcn),
            CmdDet::RouteAuthorizationsUpdate(updates, _) => {
                StorableCaCommand::RoaDefinitionUpdates(updates.into())
            }
            CmdDet::Republish(_) => StorableCaCommand::Republish,
            CmdDet::RepoUpdate(update, _) => {
                let service_uri_opt = match update {
                    RepositoryContact::Embedded(_) => None,
                    RepositoryContact::Rfc8181(res) => Some(res.service_uri().clone()),
                };
                StorableCaCommand::RepoUpdate(service_uri_opt)
            }
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

    pub fn child_update_resources(
        handle: &Handle,
        child_handle: ChildHandle,
        resources: ResourceSet,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::ChildUpdateResources(child_handle, resources),
        )
    }

    pub fn child_update_id(handle: &Handle, child_handle: ChildHandle, id: IdCert) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::ChildUpdateId(child_handle, id))
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
