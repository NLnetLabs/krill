use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::PublicKeyFormat;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use krill_commons::api::admin::{Handle, ParentCaContact, Token};
use krill_commons::api::ca::{
    CertifiedKey, ChildCaDetails, ObjectsDelta, PublicationDelta, RcvdCert, RepoInfo, ResourceSet,
    TrustAnchorLocator,
};
use krill_commons::api::{IssuanceRequest, IssuanceResponse};
use krill_commons::eventsourcing::StoredEvent;
use krill_commons::remote::id::IdCert;

use crate::ca::signing::Signer;
use crate::ca::{
    CaType, ChildHandle, Error, KeyStatus, ParentHandle, ResourceClass, ResourceClassName, Result,
    Rfc8183Id,
};

//------------ Ini -----------------------------------------------------------

pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IniDet(Token, Rfc8183Id, RepoInfo, CaType);

impl IniDet {
    pub fn token(&self) -> &Token {
        &self.0
    }

    pub fn unwrap(self) -> (Token, Rfc8183Id, RepoInfo, CaType) {
        (self.0, self.1, self.2, self.3)
    }
}

impl IniDet {
    pub fn init<S: Signer>(
        handle: &Handle,
        token: Token,
        info: RepoInfo,
        signer: Arc<RwLock<S>>,
    ) -> Result<Ini> {
        let mut signer = signer.write().unwrap();
        let id = Rfc8183Id::generate(signer.deref_mut())?;
        Ok(Ini::new(handle, 0, IniDet(token, id, info, CaType::Child)))
    }

    pub fn init_ta<S: Signer>(
        handle: &Handle,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
        signer: Arc<RwLock<S>>,
    ) -> Result<Ini> {
        let mut signer = signer.write().unwrap();

        let id = Rfc8183Id::generate(signer.deref_mut())?;

        let key = signer
            .create_key(PublicKeyFormat::default())
            .map_err(|e| Error::SignerError(e.to_string()))?;

        let token = Token::random(signer.deref());

        let resources = ResourceSet::all_resources();
        let ta_cert = Self::mk_ta_cer(&info, &resources, &key, signer.deref())?;
        let tal = TrustAnchorLocator::new(ta_uris, &ta_cert);
        let resources = ResourceSet::try_from(&ta_cert).unwrap(); // cannot have inherit

        let key = CertifiedKey::new(key, RcvdCert::new(ta_cert, ta_aia, resources));

        Ok(Ini::new(
            handle,
            0,
            IniDet(token, id, info, CaType::Ta(key, tal)),
        ))
    }

    fn mk_ta_cer<S: Signer>(
        repo_info: &RepoInfo,
        resources: &ResourceSet,
        key: &S::KeyId,
        signer: &S,
    ) -> Result<Cert> {
        let serial: Serial = Serial::random(signer).map_err(Error::signer)?;

        let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
        let name = pub_key.to_subject_name();

        let mut cert = TbsCert::new(
            serial,
            name.clone(),
            Validity::new(Time::now(), Time::years_from_now(100)),
            Some(name),
            pub_key.clone(),
            KeyUsage::Ca,
            Overclaim::Refuse,
        );

        cert.set_basic_ca(Some(true));

        cert.set_ca_repository(Some(repo_info.ca_repository("")));
        cert.set_rpki_manifest(Some(repo_info.rpki_manifest("", &pub_key.key_identifier())));
        cert.set_rpki_notify(Some(repo_info.rpki_notify()));

        cert.set_as_resources(Some(resources.to_as_resources()));
        cert.set_v4_resources(Some(resources.to_ip_resources_v4()));
        cert.set_v6_resources(Some(resources.to_ip_resources_v6()));

        cert.into_cert(signer.deref(), key).map_err(Error::signer)
    }
}

//------------ Evt ---------------------------------------------------------

pub type Evt = StoredEvent<EvtDet>;

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EvtDet {
    // Being a parent Events
    ChildAdded(ChildHandle, ChildCaDetails),
    CertificateIssued(ChildHandle, IssuanceResponse),
    ChildUpdatedToken(ChildHandle, Token),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResourceClass(ChildHandle, ResourceClassName, ResourceSet),
    ChildRemovedResourceClass(ChildHandle, ResourceClassName),

    // Being a child Events
    ParentAdded(ParentHandle, ParentCaContact),
    ResourceClassAdded(ParentHandle, ResourceClassName, ResourceClass),
    ResourceClassRemoved(ParentHandle, ResourceClassName, ObjectsDelta),
    CertificateRequested(ParentHandle, IssuanceRequest, KeyStatus),
    CertificateReceived(ParentHandle, ResourceClassName, KeyStatus, RcvdCert),
    PendingKeyActivated(ParentHandle, ResourceClassName, RcvdCert),

    // Publishing
    Published(ParentHandle, ResourceClassName, KeyStatus, PublicationDelta),
    TaPublished(PublicationDelta),
}

impl EvtDet {
    /// This marks a parent as added to the CA.
    pub(super) fn parent_added(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        info: ParentCaContact,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ParentAdded(parent_handle, info))
    }

    /// This marks a resource class as added under a parent for the CA.
    pub(super) fn resource_class_added(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        class_name: ResourceClassName,
        resource_class: ResourceClass,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassAdded(parent_handle, class_name, resource_class),
        )
    }

    /// This marks a resource class as removed, and all its (possible) objects as withdrawn
    pub(super) fn resource_class_removed(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        class_name: ResourceClassName,
        delta: ObjectsDelta,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassRemoved(parent_handle, class_name, delta),
        )
    }

    /// This marks that a certificate has been requested. This does not result
    /// in any status change inside the CA and is intended to be picked up by
    /// a listener which will contact the parent of this CA. If that listener
    /// then gets a new certificate, it will send a command to the CA with
    /// the new certificate to mark it as received, and take other
    /// appropriate actions (key life cycle, publication).
    pub(super) fn certificate_requested(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        request: IssuanceRequest,
        key_status: KeyStatus,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::CertificateRequested(parent, request, key_status),
        )
    }

    /// This marks a certificate as received for the key of the given status
    /// in a given resource class under a parent.
    pub(super) fn certificate_received(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        class_name: ResourceClassName,
        key_status: KeyStatus,
        rcvd_cert: RcvdCert,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::CertificateReceived(parent, class_name, key_status, rcvd_cert),
        )
    }

    /// This marks the pending key as activated. This occurs when a resource
    /// class that was initialised with a pending key has received the
    /// certificate for the pending key.
    ///
    /// Note that key roll management is going to be implemented in the near
    /// future and then there will also be appropriate events for all the
    /// stages in a key roll.
    pub(super) fn pending_activated(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        class_name: ResourceClassName,
        received: RcvdCert,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::PendingKeyActivated(parent, class_name, received),
        )
    }

    pub(super) fn child_added(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        details: ChildCaDetails,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildAdded(child, details))
    }

    pub(super) fn child_updated_token(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        token: Token,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildUpdatedToken(child, token))
    }

    pub(super) fn child_updated_cert(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        id_cert: IdCert,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildUpdatedIdCert(child, id_cert))
    }

    pub(super) fn child_updated_resources(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        class_name: ResourceClassName,
        resources: ResourceSet,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ChildUpdatedResourceClass(child, class_name, resources),
        )
    }

    pub(super) fn certificate_issued(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        response: IssuanceResponse,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::CertificateIssued(child, response))
    }

    /// This marks a delta as published for a key under a resource class
    /// under a parent CA.
    pub(super) fn published(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        class_name: ResourceClassName,
        key_status: KeyStatus,
        delta: PublicationDelta,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::Published(parent, class_name, key_status, delta),
        )
    }

    pub(super) fn published_ta(handle: &Handle, version: u64, delta: PublicationDelta) -> Evt {
        StoredEvent::new(handle, version, EvtDet::TaPublished(delta))
    }
}
