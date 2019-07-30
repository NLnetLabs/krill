use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::PublicKeyFormat;
use rpki::csr::Csr;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use krill_commons::api::admin::{Handle, ParentCaContact, Token};
use krill_commons::api::ca::{
    CertifiedKey, ChildCa, PublicationDelta, RcvdCert, RepoInfo, ResourceSet, TrustAnchorLocator,
};
use krill_commons::api::{IssuanceRequest, IssuanceResponse, RequestResourceLimit};
use krill_commons::eventsourcing::StoredEvent;

use crate::ca::signing::Signer;
use ca::{CaType, Error, KeyStatus, ParentHandle, ResourceClassName, Result};
use ca::{ResourceClass, Rfc8183Id};

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
        let key = CertifiedKey::new(key, RcvdCert::new(ta_cert, ta_aia));

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

        cert.set_as_resources(Some(resources.asn().clone()));
        cert.set_v4_resources(Some(resources.v4().deref().clone()));
        cert.set_v6_resources(Some(resources.v6().deref().clone()));

        cert.into_cert(signer.deref(), key).map_err(Error::signer)
    }
}

//------------ Evt ---------------------------------------------------------

pub type Evt = StoredEvent<EvtDet>;

//------------ CertIssued ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertIssued {
    child: Handle,
    response: IssuanceResponse,
}

impl CertIssued {
    pub fn new(child: Handle, response: IssuanceResponse) -> Self {
        CertIssued { child, response }
    }
    pub fn unwrap(self) -> (Handle, IssuanceResponse) {
        (self.child, self.response)
    }
}

//------------ CertRequested -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertRequested {
    parent: ParentHandle,
    key_status: KeyStatus,
    request: IssuanceRequest,
}

impl CertRequested {
    pub fn new(parent: ParentHandle, key_status: KeyStatus, request: IssuanceRequest) -> Self {
        CertRequested {
            parent,
            key_status,
            request,
        }
    }

    pub fn unwrap(self) -> (ParentHandle, KeyStatus, IssuanceRequest) {
        (self.parent, self.key_status, self.request)
    }
    pub fn parent(&self) -> &ParentHandle {
        &self.parent
    }
    pub fn class_name(&self) -> &str {
        self.request.class_name()
    }
    pub fn status(&self) -> KeyStatus {
        self.key_status
    }
    pub fn limit(&self) -> &RequestResourceLimit {
        self.request.limit()
    }
    pub fn csr(&self) -> &Csr {
        self.request.csr()
    }
}

impl Into<IssuanceRequest> for CertRequested {
    fn into(self) -> IssuanceRequest {
        self.request
    }
}

//------------ CertReceived ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertReceived {
    parent: ParentHandle,
    class_name: ResourceClassName,
    key_status: KeyStatus,
    cert: RcvdCert,
}

impl CertReceived {
    pub fn new(
        parent: ParentHandle,
        class_name: ResourceClassName,
        key_status: KeyStatus,
        cert: RcvdCert,
    ) -> Self {
        CertReceived {
            parent,
            class_name,
            key_status,
            cert,
        }
    }
}

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EvtDet {
    // Being a parent Events
    ChildAdded(ChildCa),
    CertificateIssued(CertIssued),

    // Being a child Events
    ParentAdded(ParentHandle, ParentCaContact),
    ResourceClassAdded(ParentHandle, ResourceClassName, ResourceClass),

    // Certificate Events
    CertificateRequested(CertRequested),
    CertificateReceived(CertReceived),

    // Key Life Cycle Events
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
        class_name: String,
        resource_class: ResourceClass,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassAdded(parent_handle, class_name, resource_class),
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
        cert_issue_req: CertRequested,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::CertificateRequested(cert_issue_req),
        )
    }

    /// This marks a certificate as received for the key of the given status
    /// in a given resource class under a parent.
    pub(super) fn certificate_received(
        handle: &Handle,
        version: u64,
        received: CertReceived,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::CertificateReceived(received))
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

    pub(super) fn child_added(handle: &Handle, version: u64, child: ChildCa) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildAdded(child))
    }

    pub(super) fn certificate_issued(
        handle: &Handle,
        version: u64,
        cert_issued: CertIssued,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::CertificateIssued(cert_issued))
    }

    pub(super) fn published_ta(handle: &Handle, version: u64, delta: PublicationDelta) -> Evt {
        StoredEvent::new(handle, version, EvtDet::TaPublished(delta))
    }
}
