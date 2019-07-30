use std::sync::{Arc, RwLock};

use krill_commons::api::admin::{Handle, ParentCaContact, Token};
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
    // Being a parent
    AddChild(ChildHandle, Token, Option<IdCert>, ResourceSet),
    UpdateChild(
        ChildHandle,
        Option<Token>,
        Option<IdCert>,
        Option<ResourceSet>,
    ),
    CertifyChild(ChildHandle, IssuanceRequest, Token, Arc<RwLock<S>>),

    // Being a child
    AddParent(ParentHandle, ParentCaContact),
    UpdateEntitlements(ParentHandle, Entitlements, Arc<RwLock<S>>),
    UpdateRcvdCert(ParentHandle, ResourceClassName, RcvdCert, Arc<RwLock<S>>),

    // General
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

    pub fn update_child_resources(
        handle: &Handle,
        child_handle: ChildHandle,
        child_resources: ResourceSet,
    ) -> Cmd<S> {
        eventsourcing::SentCommand::new(
            handle,
            None,
            CmdDet::UpdateChild(child_handle, None, None, Some(child_resources)),
        )
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

    pub fn publish(handle: &Handle, signer: Arc<RwLock<S>>) -> Cmd<S> {
        eventsourcing::SentCommand::new(handle, None, CmdDet::Republish(signer))
    }
}
