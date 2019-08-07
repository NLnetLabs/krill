use std::sync::{Arc, RwLock};

use chrono::Duration;

use krill_commons::api::admin::{Handle, ParentCaContact, Token, UpdateChildRequest};
use krill_commons::api::ca::{RcvdCert, ResourceSet};
use krill_commons::api::{Entitlements, IssuanceRequest};
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
    AddChild(ChildHandle, Token, Option<IdCert>, ResourceSet),
    // Update some details for an existing child, e.g. resources.
    UpdateChild(ChildHandle, UpdateChildRequest),
    // Process an issuance request by an existing child.
    CertifyChild(ChildHandle, IssuanceRequest, Token, Arc<RwLock<S>>),

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
    KeyRollActivate(Duration),

    // Finish the keyroll after the parent confirmed that a key for a parent and resource
    // class has been revoked. I.e. remove the old key, and withdraw the crl and mft for it.
    KeyRollFinish(ParentHandle, ResourceClassName),

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
        child_token: Token,
        child_id_cert: Option<IdCert>,
        child_resources: ResourceSet,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::AddChild(child_handle, child_token, child_id_cert, child_resources),
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
        handle: &ParentHandle,
        child_handle: Handle,
        request: IssuanceRequest,
        token: Token,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::CertifyChild(child_handle, request, token, signer),
        )
    }

    pub fn add_parent(handle: &Handle, name: &str, info: ParentCaContact) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::AddParent(Handle::from(name), info))
    }

    pub fn upd_entitlements(
        handle: &Handle,
        parent: &ParentHandle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateEntitlements(parent.clone(), entitlements, signer),
        )
    }

    pub fn upd_received_cert(
        handle: &Handle,
        parent: &ParentHandle,
        class_name: &str,
        cert: RcvdCert,
        signer: Arc<RwLock<S>>,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateRcvdCert(parent.clone(), class_name.to_string(), cert, signer),
        )
    }

    //----- Key Rolls
    pub fn init_roll(handle: &Handle, duration: Duration, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::KeyRollInitiate(duration, signer))
    }

    pub fn publish(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::Republish(signer))
    }
}
