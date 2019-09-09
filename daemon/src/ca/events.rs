use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::{KeyIdentifier, PublicKeyFormat};
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use krill_commons::api::{
    AddedObject, CurrentObject, Handle, IssuanceRequest, IssuanceResponse, ObjectName,
    ObjectsDelta, ParentCaContact, RcvdCert, RepoInfo, ResourceClassName, ResourceSet, Revocation,
    RevocationRequest, RevocationResponse, RevokedObject, RouteAuthorization, TaCertDetails, Token,
    TrustAnchorLocator, UpdatedObject, WithdrawnObject,
};
use krill_commons::eventsourcing::StoredEvent;
use krill_commons::remote::id::IdCert;

use crate::ca::signing::Signer;
use crate::ca::{
    CertifiedKey, ChildDetails, ChildHandle, CurrentObjectSetDelta, Error, ParentHandle,
    ResourceClass, Result, Rfc8183Id, RoaInfo,
};

//------------ Ini -----------------------------------------------------------

pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IniDet(Token, Rfc8183Id, RepoInfo, Option<TaCertDetails>);

impl IniDet {
    pub fn token(&self) -> &Token {
        &self.0
    }

    pub fn unwrap(self) -> (Token, Rfc8183Id, RepoInfo, Option<TaCertDetails>) {
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
        ta_uris: Vec<uri::Https>,
        signer: Arc<RwLock<S>>,
    ) -> Result<Ini> {
        let mut signer = signer.write().unwrap();
        let token = Token::random(signer.deref());
        let id = Rfc8183Id::generate(signer.deref_mut())?;

        let ta = {
            let resources = ResourceSet::all_resources();
            let ta_cert = {
                let key = signer
                    .create_key(PublicKeyFormat::default())
                    .map_err(|e| Error::SignerError(e.to_string()))?;

                Self::mk_ta_cer(&info, &resources, &key, signer.deref())?
            };

            let tal = TrustAnchorLocator::new(ta_uris, &ta_cert);

            TaCertDetails::new(ta_cert, resources, tal)
        };

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

        let ns = ResourceClassName::default().to_string();

        cert.set_ca_repository(Some(repo_info.ca_repository(&ns)));
        cert.set_rpki_manifest(Some(
            repo_info.rpki_manifest(&ns, &pub_key.key_identifier()),
        ));
        cert.set_rpki_notify(Some(repo_info.rpki_notify()));

        cert.set_as_resources(Some(resources.to_as_resources()));
        cert.set_v4_resources(Some(resources.to_ip_resources_v4()));
        cert.set_v6_resources(Some(resources.to_ip_resources_v6()));

        cert.into_cert(signer.deref(), key).map_err(Error::signer)
    }
}

//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoaUpdates {
    updated: HashMap<RouteAuthorization, RoaInfo>,
    removed: HashMap<RouteAuthorization, RevokedObject>,
}

impl Default for RoaUpdates {
    fn default() -> Self {
        RoaUpdates {
            updated: HashMap::new(),
            removed: HashMap::new(),
        }
    }
}

impl RoaUpdates {
    pub fn new(
        updated: HashMap<RouteAuthorization, RoaInfo>,
        removed: HashMap<RouteAuthorization, RevokedObject>,
    ) -> Self {
        RoaUpdates { updated, removed }
    }

    pub fn contains_changes(&self) -> bool {
        !(self.updated.is_empty() && self.removed.is_empty())
    }

    pub fn update(&mut self, auth: RouteAuthorization, roa: RoaInfo) {
        self.updated.insert(auth, roa);
    }

    pub fn remove(&mut self, auth: RouteAuthorization, revoke: RevokedObject) {
        self.removed.insert(auth, revoke);
    }

    pub fn added(&self) -> Vec<AddedObject> {
        let mut res = vec![];
        for (auth, info) in self.updated.iter() {
            if info.replaces().is_none() {
                let object = CurrentObject::from(info.roa());
                let name = ObjectName::from(auth);
                res.push(AddedObject::new(name, object));
            }
        }
        res
    }

    pub fn updated(&self) -> Vec<UpdatedObject> {
        let mut res = vec![];
        for (auth, info) in self.updated.iter() {
            if let Some(replaced) = info.replaces() {
                let object = CurrentObject::from(info.roa());
                let name = ObjectName::from(auth);
                res.push(UpdatedObject::new(name, object, replaced.hash().clone()));
            }
        }
        res
    }

    pub fn withdrawn(&self) -> Vec<WithdrawnObject> {
        let mut res = vec![];
        for (auth, revoked) in self.removed.iter() {
            let name = ObjectName::from(auth);
            let hash = revoked.hash().clone();
            res.push(WithdrawnObject::new(name, hash));
        }
        res
    }

    pub fn revocations(&self) -> Vec<Revocation> {
        let mut res = vec![];
        for info in self.updated.values() {
            if let Some(old) = info.replaces() {
                res.push(old.revocation())
            }
        }

        for revoked in self.removed.values() {
            res.push(revoked.revocation())
        }

        res
    }

    pub fn unpack(
        self,
    ) -> (
        HashMap<RouteAuthorization, RoaInfo>,
        HashMap<RouteAuthorization, RevokedObject>,
    ) {
        (self.updated, self.removed)
    }
}

//------------ Evt ---------------------------------------------------------

pub type Evt = StoredEvent<EvtDet>;

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EvtDet {
    // Being a parent Events
    ChildAdded(ChildHandle, ChildDetails),
    ChildCertificateIssued(ChildHandle, IssuanceResponse),
    ChildKeyRevoked(ChildHandle, RevocationResponse),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResources(ChildHandle, ResourceSet, Time),

    // Being a child Events
    ParentAdded(ParentHandle, ParentCaContact),
    ResourceClassAdded(ResourceClassName, ResourceClass),
    ResourceClassRemoved(
        ResourceClassName,
        ObjectsDelta,
        ParentHandle,
        Vec<RevocationRequest>,
    ),
    CertificateRequested(ResourceClassName, IssuanceRequest, KeyIdentifier),
    CertificateReceived(ResourceClassName, KeyIdentifier, RcvdCert),

    // Key life cycle
    KeyRollPendingKeyAdded(ResourceClassName, KeyIdentifier),
    KeyPendingToNew(ResourceClassName, CertifiedKey, ObjectsDelta),
    KeyPendingToActive(ResourceClassName, CertifiedKey, ObjectsDelta),
    KeyRollActivated(ResourceClassName, RevocationRequest),
    KeyRollFinished(ResourceClassName, ObjectsDelta),

    // Route Authorizations
    RouteAuthorizationAdded(RouteAuthorization),
    RouteAuthorizationRemoved(RouteAuthorization),
    RoasUpdated(ResourceClassName, RoaUpdates),

    // Publishing
    ObjectSetUpdated(
        ResourceClassName,
        HashMap<KeyIdentifier, CurrentObjectSetDelta>,
    ),
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
        details: ChildDetails,
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
        resources: ResourceSet,
        force: bool,
    ) -> Evt {
        let grace = if force { Time::now() } else { Time::tomorrow() };

        StoredEvent::new(
            handle,
            version,
            EvtDet::ChildUpdatedResources(child, resources, grace),
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

    pub(super) fn current_set_updated(
        handle: &Handle,
        version: u64,
        rcn: ResourceClassName,
        deltas: HashMap<KeyIdentifier, CurrentObjectSetDelta>,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ObjectSetUpdated(rcn, deltas))
    }
}
