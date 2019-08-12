use std::sync::{Arc, RwLock};

use chrono::Duration;

use krill_commons::api::admin::{Handle, ParentCaContact, UpdateChildRequest};
use krill_commons::api::ca::{RcvdCert, ResourceSet};
use krill_commons::api::{Entitlements, IssuanceRequest, RevocationRequest, RevocationResponse};
use krill_commons::eventsourcing;
use krill_commons::remote::id::IdCert;

use crate::ca::{ChildHandle, Evt, ParentHandle, ResourceClassName, Signer};

//------------ Command -----------------------------------------------------

pub type Cmd<S> = eventsourcing::SentCommand<CmdDet<S>>;

//------------ CommandDetails ----------------------------------------------

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CmdDet<S: Signer> {
    // ------------------------------------------------------------
    // Being a parent
    // ------------------------------------------------------------

    // Add a new child under this parent CA
    AddChild(ChildHandle, Option<IdCert>, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    UpdateChild(ChildHandle, UpdateChildRequest),
    // Process an issuance request by an existing child.
    CertifyChild(ChildHandle, IssuanceRequest, Arc<RwLock<S>>),
    // Process a revoke request by an existing child.
    RevokeKeyForChild(ChildHandle, RevocationRequest, Arc<RwLock<S>>),

    // ------------------------------------------------------------
    // Being a child (only allowed if this CA is not self-signed)
    // ------------------------------------------------------------

    // Add a parent to this CA. Can have multiple parents.
    AddParent(ParentHandle, ParentCaContact),
    // Process new entitlements from a parent and create issue/revoke requests as needed.
    UpdateEntitlements(ParentHandle, Entitlements, Arc<RwLock<S>>),
    // Process a new certificate received from a parent.
    UpdateRcvdCert(ParentHandle, ResourceClassName, RcvdCert, Arc<RwLock<S>>),

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
    KeyRollFinish(ParentHandle, RevocationResponse),

    // ------------------------------------------------------------
    // Publishing
    // ------------------------------------------------------------
    Republish(Arc<RwLock<S>>),
}

impl<S: Signer> eventsourcing::CommandDetails for CmdDet<S> {
    type Event = Evt;
}

impl<S: Signer> CmdDet<S> {
    /// Adds a child to this CA. Will return an error in case you try
    /// to give the child resources not held by the CA. And until issue
    /// #25 is implemented, returns an error when the CA is not a TA.
    pub fn add_child(
        handle: &Handle,
        child_handle: Handle,
        child_id_cert: Option<IdCert>,
        child_resources: ResourceSet,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::AddChild(child_handle, child_id_cert, child_resources),
        )
    }

    pub fn update_child(
        handle: &Handle,
        child_handle: ChildHandle,
        req: UpdateChildRequest,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::UpdateChild(child_handle, req))
    }

    /// Certify a child. Will return an error in case the child is
    /// unknown, or in case resources are not held by the child.
    pub fn certify_child(
        handle: &Handle,
        child_handle: ChildHandle,
        request: IssuanceRequest,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::CertifyChild(child_handle, request, signer),
        )
    }

    /// Revoke a key for a child.
    pub fn revoke_key_for_child(
        handle: &Handle,
        child_handle: ChildHandle,
        request: RevocationRequest,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::RevokeKeyForChild(child_handle, request, signer),
        )
    }

    pub fn add_parent(handle: &Handle, parent: ParentHandle, info: ParentCaContact) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::AddParent(parent, info))
    }

    pub fn upd_entitlements(
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateEntitlements(parent, entitlements, signer),
        )
    }

    pub fn upd_received_cert(
        handle: &Handle,
        parent: ParentHandle,
        class_name: ResourceClassName,
        cert: RcvdCert,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateRcvdCert(parent, class_name, cert, signer),
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
        parent: ParentHandle,
        res: RevocationResponse,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollFinish(parent, res))
    }

    pub fn publish(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::Republish(signer))
    }
}
