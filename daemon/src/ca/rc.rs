use std::ops::Deref;
use std::sync::{Arc, RwLock};

use chrono::Duration;

use rpki::crypto::PublicKeyFormat;
use rpki::csr::Csr;
use rpki::uri;
use rpki::x509::Time;

use krill_commons::api::ca::{
    CertifiedKey, CurrentObjects, KeyRef, ObjectsDelta, PendingKey, PublicationDelta, RcvdCert,
    RepoInfo, ResourceClassInfo, ResourceClassKeysInfo,
};
use krill_commons::api::{EntitlementClass, IssuanceRequest, RequestResourceLimit};
use krill_commons::util::softsigner::SignerKeyId;

use crate::ca::{
    self, Error, EvtDet, ParentHandle, ResourceClassName, Result, SignSupport, Signer,
};

/// A CA may have multiple parents, e.g. two RIRs, and it may not get all its
/// resource entitlements in one set, but in a number of so-called "resource
/// classes".
///
/// Each ResourceClass has a namespace, which can be anything, but for Krill
/// is based on the name of the parent ca, and the name of the resource class
/// under that parent.
///
/// Furthermore a resource class manages the key life cycle, and certificates
/// for each key, as well as products that need to be issued by the 'current'
/// key for this class. The key life cycle has the following stages:
///
/// - Pending Key
///
/// This is a newly generated key, for which a certificate has been requested,
/// but it is not yet received. This key is not published.
///
/// Pending keys can only be created for new Resource Classes, or when there
/// is no key roll in progress: i.e. the Resource Class contains a 'current'
/// key only.
///
/// - New Key
///
/// When a certificate is received for a pending key, it is promoted to a 'new'
/// key. If there are no other keys in this resource class, then this key can
/// be promoted to 'current' key immediately - see below.
///
/// If there is already an current key, then the new key status should be
/// observed for at least 24 hours. New keys publish a manifest and a ROA, but
/// no other products.
///
/// - Current Key
///
/// A current key publishes a manifest and CRL, and all the products pertaining
/// to the Internet Number Resources in this resource class.
///
/// If a resource class contains a current key only, a key roll can be
/// initiated: a pending key is created and a certificate is requested, when
/// the certificate is received the pending key is promoted to 'new' key, and
/// a staging period of at least 24 hours is started. Note that the MFT and
/// CRL for both keys are published under the same namespace, but only the
/// current key publishes additional objects.
///
/// When the staging period is over the new key can be promoted to current
/// key. When this happens the current key is promoted to the stage 'revoke'
/// key - see below. And the 'new' key become the 'current' key.
///
/// - Revoke Key
///
/// A revoke key only publishes a manifest and CRL, but no additional
/// products. When a revoke key is created a revocation request is generated
/// for the parent. The moment confirmation is received from the parent, the
/// 'revoke' key is dropped, and its content is withdrawn.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceClass {
    name_space: String,
    last_key_change: Time,
    keys: ResourceClassKeys,
}

impl ResourceClass {
    /// Creates a new ResourceClass with a single pending key only.
    pub fn create(name_space: String, pending_key: SignerKeyId) -> Self {
        ResourceClass {
            name_space,
            last_key_change: Time::now(),
            keys: ResourceClassKeys::create(pending_key),
        }
    }

    pub fn name_space(&self) -> &str {
        &self.name_space
    }

    /// Adds a request to an existing key for future reference.
    pub fn add_request(&mut self, key_id: SignerKeyId, req: IssuanceRequest) {
        self.keys.add_request(key_id, req);
    }

    pub fn objects(&self) -> CurrentObjects {
        self.keys.objects()
    }

    /// Returns withdraws for all current objects, for when this resource class
    /// needs to be removed.
    pub fn withdraw(&self, base_repo: &RepoInfo) -> ObjectsDelta {
        let base_repo = base_repo.ca_repository(self.name_space());
        self.keys.withdraw(base_repo)
    }

    /// Returns event details for receiving the certificate and publishing for it.
    pub fn update_received_cert<S: Signer>(
        &self,
        rcvd_cert: RcvdCert,
        base_repo: &RepoInfo,
        parent: ParentHandle,
        class_name: ResourceClassName,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<EvtDet>> {
        self.keys.update_received_cert(
            parent,
            rcvd_cert,
            base_repo,
            class_name,
            &self.name_space,
            signer,
        )
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behaviour.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(self.name_space.clone(), self.keys.as_info())
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Request certificates for any key that needs it.
    pub fn request_certs<S: Signer>(
        &self,
        parent: ParentHandle,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &Arc<RwLock<S>>,
    ) -> Result<Vec<EvtDet>> {
        self.keys
            .request_certs(parent, entitlement, base_repo, &self.name_space, signer)
    }

    /// This function returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        self.keys.cert_requests()
    }
}

/// # Publishing
///
impl ResourceClass {
    /// Applies a publication delta to the appropriate key in this resource class.
    pub fn apply_delta(&mut self, delta: PublicationDelta, key_id: SignerKeyId) {
        self.keys.apply_delta(delta, key_id);
    }
}

/// # Key Life Cycle and Receiving Certificates
///
impl ResourceClass {
    /// This function marks a certificate as received.
    pub fn received_cert(&mut self, key_id: SignerKeyId, cert: RcvdCert) {
        // if there is a pending key, then we need to do some promotions..
        match &mut self.keys {
            ResourceClassKeys::Pending(pending) => {
                let current = CertifiedKey::new(pending.key_id().clone(), cert);
                self.last_key_change = Time::now();
                self.keys = ResourceClassKeys::Active(current);
            }
            ResourceClassKeys::Active(current) => {
                current.set_incoming_cert(cert);
            }
            ResourceClassKeys::RollPending(pending, current) => {
                if pending.key_id() == &key_id {
                    let new = CertifiedKey::new(pending.key_id().clone(), cert);
                    self.last_key_change = Time::now();
                    self.keys = ResourceClassKeys::RollNew(new, current.clone());
                } else {
                    current.set_incoming_cert(cert);
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.set_incoming_cert(cert);
                } else {
                    current.set_incoming_cert(cert);
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.set_incoming_cert(cert);
                } else {
                    old.set_incoming_cert(cert);
                }
            }
        }
    }

    /// Adds a pending key.
    pub fn pending_key_added(&mut self, key_id: SignerKeyId) {
        match &self.keys {
            ResourceClassKeys::Active(current) => {
                let pending = PendingKey::new(key_id);
                self.keys = ResourceClassKeys::RollPending(pending, current.clone())
            }
            _ => unimplemented!("Should never create event to add key when roll in progress")
        }
    }

    pub fn keyroll_initiate<S: Signer>(
        &self,
        parent: ParentHandle,
        class_name: ResourceClassName,
        base_repo: &RepoInfo,
        duration: Duration,
        signer: &mut S,
    ) -> ca::Result<Vec<EvtDet>> {
        if self.last_key_change + duration > Time::now() {
            return Ok(vec![]);
        }

        self.keys.keyroll_initiate(
            parent,
            class_name,
            base_repo,
            &self.name_space,
            signer
        )
    }
}

//------------ ResourceClassKeys ---------------------------------------------

/// This type contains the keys for a resource class and guards that keys
/// are created, activated, rolled and retired properly.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ResourceClassKeys {
    Pending(PendingKey),
    Active(CurrentKey),
    RollPending(PendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldKey),
}

type NewKey = CertifiedKey;
type CurrentKey = CertifiedKey;
type OldKey = CertifiedKey;

impl ResourceClassKeys {
    fn create(pending_key: SignerKeyId) -> Self {
        ResourceClassKeys::Pending(PendingKey::new(pending_key))
    }

    fn add_request(&mut self, key_id: SignerKeyId, req: IssuanceRequest) {
        match self {
            ResourceClassKeys::Pending(pending) => pending.add_request(req),
            ResourceClassKeys::Active(current) => current.add_request(req),
            ResourceClassKeys::RollPending(pending, current) => {
                if pending.key_id() == &key_id {
                    pending.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.add_request(req)
                } else {
                    old.add_request(req)
                }
            }
        }
    }

    fn objects(&self) -> CurrentObjects {
        let mut objects = CurrentObjects::default();

        match self {
            ResourceClassKeys::Pending(_pending) => {}
            ResourceClassKeys::Active(current) => {
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollPending(_pending, current) => {
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollNew(new, current) => {
                objects = objects + new.current_set().objects().clone();
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollOld(current, old) => {
                objects = objects + current.current_set().objects().clone();
                objects = objects + old.current_set().objects().clone();
            }
        }

        objects
    }

    fn withdraw(&self, base_repo: uri::Rsync) -> ObjectsDelta {
        let mut delta = ObjectsDelta::new(base_repo);
        for withdraw in self.objects().withdraw() {
            delta.withdraw(withdraw)
        }
        delta
    }

    fn find_matching_key_for_rcvd_cert<S: Signer>(
        &self,
        cert: &RcvdCert,
        signer: &S,
    ) -> ca::Result<CertifiedKey> {
        match self {
            ResourceClassKeys::Pending(pending) => {
                self.matches_key_id(pending.key_id(), cert, signer)?;
                Ok(CertifiedKey::new(pending.key_id().clone(), cert.clone()))
            }
            ResourceClassKeys::Active(current) => {
                self.matches_key_id(current.key_id(), cert, signer)?;
                Ok(current.clone())
            }
            ResourceClassKeys::RollPending(pending, current) => {
                if self.matches_key_id(pending.key_id(), cert, signer).is_ok() {
                    Ok(CertifiedKey::new(pending.key_id().clone(), cert.clone()))
                } else {
                    self.matches_key_id(current.key_id(), cert, signer)?;
                    Ok(current.clone())
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if self.matches_key_id(new.key_id(), cert, signer).is_ok() {
                    Ok(new.clone())
                } else {
                    self.matches_key_id(current.key_id(), cert, signer)?;
                    Ok(current.clone())
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if self.matches_key_id(current.key_id(), cert, signer).is_ok() {
                    Ok(current.clone())
                } else {
                    self.matches_key_id(old.key_id(), cert, signer)?;
                    Ok(old.clone())
                }
            }
        }
    }

    /// Helper to match a key_id to a pub key.
    fn matches_key_id<S: Signer>(
        &self,
        key_id: &SignerKeyId,
        cert: &RcvdCert,
        signer: &S,
    ) -> ca::Result<()> {
        let cert = cert.cert();
        let pub_key = cert.subject_public_key_info();

        if let Ok(info) = signer.get_key_info(key_id) {
            if &info == pub_key {
                return Ok(());
            }
        }

        Err(ca::Error::NoKeyMatch(KeyRef::from(cert)))
    }

    fn update_received_cert<S: Signer>(
        &self,
        parent: ParentHandle,
        rcvd_cert: RcvdCert,
        base_repo: &RepoInfo,
        class_name: ResourceClassName,
        name_space: &str,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<EvtDet>> {
        let mut res = vec![];

        let certified_key =
            self.find_matching_key_for_rcvd_cert(&rcvd_cert, signer.read().unwrap().deref())?;

        res.push(EvtDet::CertificateReceived(
            parent.clone(),
            class_name.clone(),
            certified_key.key_id().clone(),
            rcvd_cert,
        ));

        let ca_repo = base_repo.ca_repository(name_space);
        let delta = ObjectsDelta::new(ca_repo);

        let delta = SignSupport::publish(signer, &certified_key, base_repo, name_space, delta)
            .map_err(Error::signer)?;

        res.push(EvtDet::Published(
            parent,
            class_name,
            certified_key.key_id().clone(),
            delta,
        ));

        Ok(res)
    }

    fn apply_delta(&mut self, delta: PublicationDelta, key_id: SignerKeyId) {
        match self {
            ResourceClassKeys::Pending(_pending) => unimplemented!("Cannot apply delta to pending"),
            ResourceClassKeys::Active(current) => current.apply_delta(delta),
            ResourceClassKeys::RollPending(_pending, current) => current.apply_delta(delta),
            ResourceClassKeys::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.apply_delta(delta)
                } else {
                    current.apply_delta(delta)
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.apply_delta(delta)
                } else {
                    old.apply_delta(delta)
                }
            }
        }
    }

    pub fn request_certs<S: Signer>(
        &self,
        parent: ParentHandle,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &Arc<RwLock<S>>,
    ) -> Result<Vec<EvtDet>> {
        let mut keys_for_requests = vec![];
        match self {
            ResourceClassKeys::Pending(pending) => {
                keys_for_requests.push(pending.key_id());
            }
            ResourceClassKeys::Active(current) => {
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollPending(pending, current) => {
                keys_for_requests.push(pending.key_id());
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if new.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(new.key_id());
                }
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
                if old.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(old.key_id());
                }
            }
        }

        let mut res = vec![];

        let signer = signer.read().unwrap();

        for key_id in keys_for_requests.into_iter() {
            let req = self.create_issuance_req(
                base_repo,
                name_space,
                entitlement.class_name(),
                key_id,
                signer.deref(),
            )?;

            res.push(EvtDet::CertificateRequested(
                parent.clone(),
                req,
                key_id.clone(),
            ));
        }

        Ok(res)
    }

    /// Returns all open certificate requests
    fn cert_requests(&self) -> Vec<IssuanceRequest> {
        let mut res = vec![];
        match self {
            ResourceClassKeys::Pending(pending) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::Active(current) => {
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollPending(pending, current) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if let Some(r) = new.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
                if let Some(r) = old.request() {
                    res.push(r.clone())
                }
            }
        }
        res
    }

    /// Creates a Csr for the given key. Note that this parses the encoded
    /// key. This is not the most efficient way, but makes storing and
    /// serializing the Csr in an event possible (the Captured cannot be
    /// stored).
    fn create_issuance_req<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        name_space: &str,
        class_name: &str,
        key: &SignerKeyId,
        signer: &S,
    ) -> Result<IssuanceRequest> {
        let pub_key = signer.get_key_info(key).map_err(Error::signer)?;

        let enc = Csr::construct(
            signer,
            key,
            &base_repo.ca_repository(name_space),
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(Error::signer)?;

        let csr = Csr::decode(enc.as_slice()).map_err(Error::signer)?;

        Ok(IssuanceRequest::new(
            class_name.to_string(),
            RequestResourceLimit::default(),
            csr,
        ))
    }

    fn as_info(&self) -> ResourceClassKeysInfo {
        match self.clone() {
            ResourceClassKeys::Pending(p) => ResourceClassKeysInfo::Pending(p),
            ResourceClassKeys::Active(c) => ResourceClassKeysInfo::Active(c),
            ResourceClassKeys::RollPending(p, c) => ResourceClassKeysInfo::RollPending(p, c),
            ResourceClassKeys::RollNew(n, c) => ResourceClassKeysInfo::RollNew(n, c),
            ResourceClassKeys::RollOld(c, o) => ResourceClassKeysInfo::RollOld(c, o),
        }
    }
}

/// # Key Rolls
///
impl ResourceClassKeys {
    /// Initiates a key roll if the current state is 'Active'. This will return event details
    /// for a newly create pending key and requested certificate for it.
    fn keyroll_initiate<S: Signer>(
        &self,
        parent: ParentHandle,
        class_name: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &mut S,
    ) -> ca::Result<Vec<EvtDet>> {
        match self {
            ResourceClassKeys::Active(_current) => {
                let key_id = {
                    signer
                        .create_key(PublicKeyFormat::default())
                        .map_err(Error::signer)?
                };

                let issuance_req =
                    self.create_issuance_req(base_repo, name_space, &class_name, &key_id, signer)?;

                Ok(vec![
                    EvtDet::KeyrollPendingKeyAdded(
                        parent.clone(),
                        class_name.clone(),
                        key_id.clone(),
                    ),
                    EvtDet::CertificateRequested(parent, issuance_req, key_id),
                ])
            }
            _ => Ok(vec![]),
        }
    }
}
