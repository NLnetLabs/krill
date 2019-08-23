use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::PublicKeyFormat;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use krill_commons::api::admin::{Handle, ParentCaContact, Token};
use krill_commons::api::ca::{
    CertifiedKey, ChildCaDetails, ObjectsDelta, PublicationDelta, RcvdCert, RepoInfo,
    ResourceClassName, ResourceSet, RevokedObject, TrustAnchorLocator,
};
use krill_commons::api::{
    IssuanceRequest, IssuanceResponse, RevocationRequest, RevocationResponse, RouteAuthorization,
};
use krill_commons::eventsourcing::StoredEvent;
use krill_commons::remote::id::IdCert;
use krill_commons::util::softsigner::KeyId;

use crate::ca::signing::Signer;
use crate::ca::{ChildHandle, Error, ParentHandle, ResourceClass, Result, Rfc8183Id};
use ca::RoaInfo;

//------------ TaIniDetails --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub struct Ta {
    key: CertifiedKey,
    tal: TrustAnchorLocator,
}

impl Ta {
    pub fn new(key: CertifiedKey, tal: TrustAnchorLocator) -> Self {
        Ta { key, tal }
    }

    pub fn unpack(self) -> (CertifiedKey, TrustAnchorLocator) {
        (self.key, self.tal)
    }
}

//------------ Ini -----------------------------------------------------------

pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IniDet(Token, Rfc8183Id, RepoInfo, Option<Ta>);

impl IniDet {
    pub fn token(&self) -> &Token {
        &self.0
    }

    pub fn unwrap(self) -> (Token, Rfc8183Id, RepoInfo, Option<Ta>) {
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
        Ok(Ini::new(handle, 0, IniDet(token, id, info, None)))
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

        let ta = Ta::new(key, tal);

        Ok(Ini::new(handle, 0, IniDet(token, id, info, Some(ta))))
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

//------------ RouteAuthorizationUpdate ------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteAuthorizationUpdate {
    authorization: RouteAuthorization,
    roas: HashMap<ResourceClassName, RoaInfo>,
}

impl RouteAuthorizationUpdate {
    pub fn new(
        authorization: RouteAuthorization,
        roas: HashMap<ResourceClassName, RoaInfo>,
    ) -> Self {
        RouteAuthorizationUpdate {
            authorization,
            roas,
        }
    }

    pub fn unpack(self) -> (RouteAuthorization, HashMap<ResourceClassName, RoaInfo>) {
        (self.authorization, self.roas)
    }

    pub fn authorization(&self) -> &RouteAuthorization {
        &self.authorization
    }

    pub fn roas(&self) -> &HashMap<ResourceClassName, RoaInfo> {
        &self.roas
    }
}

//------------ RouteAuthorizationRemoval -----------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteAuthorizationRemoval {
    authorization: RouteAuthorization,
    roas: HashMap<ResourceClassName, RevokedObject>,
}

impl RouteAuthorizationRemoval {
    pub fn new(
        authorization: RouteAuthorization,
        roas: HashMap<ResourceClassName, RevokedObject>,
    ) -> Self {
        RouteAuthorizationRemoval {
            authorization,
            roas,
        }
    }

    pub fn unpack(
        self,
    ) -> (
        RouteAuthorization,
        HashMap<ResourceClassName, RevokedObject>,
    ) {
        (self.authorization, self.roas)
    }

    pub fn authorization(&self) -> &RouteAuthorization {
        &self.authorization
    }

    pub fn roas(&self) -> &HashMap<ResourceClassName, RevokedObject> {
        &self.roas
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
    ChildCertificateIssued(ChildHandle, IssuanceResponse),
    ChildKeyRevoked(ChildHandle, RevocationResponse),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResourceClass(ChildHandle, ResourceClassName, ResourceSet),
    ChildRemovedResourceClass(ChildHandle, ResourceClassName),

    // Being a child Events
    ParentAdded(ParentHandle, ParentCaContact),
    ResourceClassAdded(ResourceClassName, ResourceClass),
    ResourceClassRemoved(
        ResourceClassName,
        ObjectsDelta,
        ParentHandle,
        Vec<RevocationRequest>,
    ),
    CertificateRequested(ResourceClassName, IssuanceRequest, KeyId),
    CertificateReceived(ResourceClassName, KeyId, RcvdCert),

    // Key roll
    KeyRollPendingKeyAdded(ResourceClassName, KeyId),
    KeyRollActivated(ResourceClassName, RevocationRequest),
    KeyRollFinished(ResourceClassName, ObjectsDelta),

    // Route Authorizations
    RouteAuthorizationUpdated(RouteAuthorizationUpdate),
    RouteAuthorizationRemoved(RouteAuthorizationRemoval),

    // Publishing
    Published(ResourceClassName, HashMap<KeyId, PublicationDelta>),
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
        class_name: ResourceClassName,
        resource_class: ResourceClass,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassAdded(class_name, resource_class),
        )
    }

    /// This marks a resource class as removed, and all its (possible) objects as withdrawn
    pub(super) fn resource_class_removed(
        handle: &Handle,
        version: u64,
        class_name: ResourceClassName,
        delta: ObjectsDelta,
        parent: ParentHandle,
        revocations: Vec<RevocationRequest>,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassRemoved(class_name, delta, parent, revocations),
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

    pub(super) fn child_certificate_issued(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        response: IssuanceResponse,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ChildCertificateIssued(child, response),
        )
    }

    pub(super) fn child_revoke_key(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        response: RevocationResponse,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildKeyRevoked(child, response))
    }

    pub(super) fn published(
        handle: &Handle,
        version: u64,
        class_name: ResourceClassName,
        deltas: HashMap<KeyId, PublicationDelta>,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::Published(class_name, deltas))
    }
}
