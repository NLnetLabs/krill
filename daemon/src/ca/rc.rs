use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use chrono::Duration;

use rpki::crypto::PublicKeyFormat;
use rpki::csr::Csr;
use rpki::uri;
use rpki::x509::Time;

use krill_commons::api::ca::{
    CertifiedKey, CurrentObjects, KeyRef, ObjectsDelta, OldKey, PendingKey, PublicationDelta,
    RcvdCert, RepoInfo, ResourceClassInfo, ResourceClassKeysInfo,
};
use krill_commons::api::{
    EntitlementClass, IssuanceRequest, RequestResourceLimit, RevocationRequest,
};
use krill_commons::util::softsigner::KeyId;

use crate::ca::{
    self, Error, EvtDet, ParentHandle, ResourceClassName, Result, SignSupport, Signer,
};
use ca::TA_NAME;

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
/// key for this class.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceClass {
    name_space: String,
    last_key_change: Time,
    keys: ResourceClassKeys,
}

/// # Creating new instances
///
impl ResourceClass {
    /// Creates a new ResourceClass with a single pending key only.
    pub fn create(name_space: String, pending_key: KeyId) -> Self {
        ResourceClass {
            name_space,
            last_key_change: Time::now(),
            keys: ResourceClassKeys::create(pending_key),
        }
    }

    pub fn for_ta(key: CertifiedKey) -> Self {
        ResourceClass {
            name_space: TA_NAME.to_string(),
            last_key_change: Time::now(),
            keys: ResourceClassKeys::for_ta(key),
        }
    }
}

/// # Data Access
///
impl ResourceClass {
    pub fn name_space(&self) -> &str {
        &self.name_space
    }

    /// Adds a request to an existing key for future reference.
    pub fn add_request(&mut self, key_id: KeyId, req: IssuanceRequest) {
        self.keys.add_request(key_id, req);
    }

    /// Returns all objects for all keys
    pub fn objects(&self) -> CurrentObjects {
        self.keys.objects()
    }

    /// Returns the current certificate, if there is any
    pub fn current_certificate(&self) -> Option<&RcvdCert> {
        self.current_key().map(|k| k.incoming_cert())
    }

    /// Returns a reference to current key for this RC, if there is any.
    pub fn current_key(&self) -> Option<&CurrentKey> {
        match &self.keys {
            ResourceClassKeys::Active(current)
            | ResourceClassKeys::RollPending(_, current)
            | ResourceClassKeys::RollNew(_, current)
            | ResourceClassKeys::RollOld(current, _) => Some(current),
            _ => None,
        }
    }

    pub fn get_current_key(&self) -> Result<&CurrentKey> {
        self.current_key()
            .ok_or_else(|| Error::ResourceClassNoCurrentKey)
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

    /// Request certificates for any key that needs it.
    pub fn make_request_events<S: Signer>(
        &self,
        parent: ParentHandle,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &S,
    ) -> Result<Vec<EvtDet>> {
        self.keys
            .request_certs(parent, entitlement, base_repo, &self.name_space, signer)
    }

    /// This function returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        self.keys.cert_requests()
    }

    /// Returns the revocation request for the old key, if it exists.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        self.keys.revoke_request()
    }
}

/// # Publishing
///
impl ResourceClass {
    /// Applies a publication delta to the appropriate key in this resource class.
    pub fn apply_delta(&mut self, delta: PublicationDelta, key_id: KeyId) {
        self.keys.apply_delta(delta, key_id);
    }

    /// Republish all keys in this class (that want it).
    pub fn republish<S: Signer>(
        &self,
        repo_info: &RepoInfo,
        class_name: ResourceClassName,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<EvtDet> {
        let name_space = &self.name_space;

        let mut deltas: HashMap<KeyId, PublicationDelta> = HashMap::new();

        match &self.keys {
            ResourceClassKeys::Pending(_) => {}
            ResourceClassKeys::RollPending(_, current) | ResourceClassKeys::Active(current) => {
                publish_key_if_needed(current, repo_info, name_space, signer, &mut deltas)?;
            }
            ResourceClassKeys::RollNew(new, current) => {
                publish_key_if_needed(new, repo_info, name_space, signer.clone(), &mut deltas)?;
                publish_key_if_needed(current, repo_info, name_space, signer, &mut deltas)?;
            }
            ResourceClassKeys::RollOld(current, old) => {
                publish_key_if_needed(current, repo_info, name_space, signer.clone(), &mut deltas)?;
                publish_key_if_needed(old, repo_info, name_space, signer, &mut deltas)?;
            }
        };

        // lil' helper
        fn publish_key_if_needed<S: Signer>(
            key: &CertifiedKey,
            repo_info: &RepoInfo,
            name_space: &str,
            signer: Arc<RwLock<S>>,
            deltas: &mut HashMap<KeyId, PublicationDelta>,
        ) -> ca::Result<()> {
            if key.needs_publication() {
                let key_id = key.key_id();
                let ca_repo = repo_info.ca_repository(name_space);
                let objects_delta = ObjectsDelta::new(ca_repo);
                let delta =
                    SignSupport::publish(signer, key, repo_info, name_space, objects_delta, vec![])
                        .map_err(Error::signer)?;
                deltas.insert(key_id.clone(), delta);
            }
            Ok(())
        }

        Ok(EvtDet::Published(class_name, deltas))
    }
}

/// # Removing a resource class
///
impl ResourceClass {
    /// Returns withdraws for all current objects, for when this resource class
    /// needs to be removed.
    pub fn withdraw(&self, base_repo: &RepoInfo) -> ObjectsDelta {
        let base_repo = base_repo.ca_repository(self.name_space());
        self.keys.withdraw(base_repo)
    }

    /// Returns revocation requests for all certified keys in this resource class.
    pub fn revoke<S: Signer>(
        &self,
        class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<Vec<RevocationRequest>> {
        self.keys.revoke(class_name, signer)
    }
}

/// # Key Life Cycle and Receiving Certificates
///
impl ResourceClass {
    /// This function marks a certificate as received.
    pub fn received_cert(&mut self, key_id: KeyId, cert: RcvdCert) {
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
    pub fn pending_key_added(&mut self, key_id: KeyId) {
        match &self.keys {
            ResourceClassKeys::Active(current) => {
                let pending = PendingKey::new(key_id);
                self.keys = ResourceClassKeys::RollPending(pending, current.clone())
            }
            _ => panic!("Should never create event to add key when roll in progress"),
        }
    }

    /// Activates the new key
    pub fn new_key_activated(&mut self, revoke_req: RevocationRequest) {
        match &self.keys {
            ResourceClassKeys::RollNew(new, current) => {
                let old_key = OldKey::new(current.clone(), revoke_req);
                self.keys = ResourceClassKeys::RollOld(new.clone(), old_key);
            }
            _ => panic!("Should never create event to activate key when no roll in progress"),
        }
    }

    /// Removes the old key, we return the to the state where there is one active key.
    pub fn old_key_removed(&mut self) {
        match &self.keys {
            ResourceClassKeys::RollOld(current, _old) => {
                self.keys = ResourceClassKeys::Active(current.clone());
            }
            _ => panic!("Should never create event to remove old key, when there is none"),
        }
    }

    /// Initiate a key roll
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

        self.keys
            .keyroll_initiate(parent, class_name, base_repo, &self.name_space, signer)
    }

    /// Activate a new key, if it's been longer than the staging period.
    pub fn keyroll_activate<S: Signer>(
        &self,
        parent: ParentHandle,
        class_name: ResourceClassName,
        staging: Duration,
        signer: &S,
    ) -> ca::Result<Vec<EvtDet>> {
        if self.last_key_change + staging > Time::now() {
            return Ok(vec![]);
        }

        self.keys.keyroll_activate(parent, class_name, signer)
    }

    /// Finish a key roll, withdraw the old key
    pub fn keyroll_finish(
        &self,
        parent: ParentHandle,
        class_name: ResourceClassName,
        base_repo: &RepoInfo,
    ) -> ca::Result<EvtDet> {
        let withdraws = match &self.keys {
            ResourceClassKeys::RollOld(_current, old) => {
                Some(old.current_set().objects().withdraw())
            }
            _ => None,
        }
        .ok_or_else(|| Error::InvalidKeyStatus)?;

        let mut objects_delta = ObjectsDelta::new(base_repo.ca_repository(self.name_space()));
        for withdraw in withdraws.into_iter() {
            objects_delta.withdraw(withdraw);
        }

        Ok(EvtDet::KeyRollFinished(parent, class_name, objects_delta))
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

impl ResourceClassKeys {
    fn create(pending_key: KeyId) -> Self {
        ResourceClassKeys::Pending(PendingKey::new(pending_key))
    }

    fn for_ta(key: CurrentKey) -> Self {
        ResourceClassKeys::Active(key)
    }

    fn add_request(&mut self, key_id: KeyId, req: IssuanceRequest) {
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

    /// Withdraw all objects in all keys
    fn withdraw(&self, base_repo: uri::Rsync) -> ObjectsDelta {
        let mut delta = ObjectsDelta::new(base_repo);
        for withdraw in self.objects().withdraw() {
            delta.withdraw(withdraw)
        }
        delta
    }

    /// Revoke all current keys
    fn revoke<S: Signer>(
        &self,
        class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<Vec<RevocationRequest>> {
        match self {
            ResourceClassKeys::Pending(_pending) => Ok(vec![]), // nothing to revoke
            ResourceClassKeys::Active(current) | ResourceClassKeys::RollPending(_, current) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_current])
            }
            ResourceClassKeys::RollNew(new, current) => {
                let revoke_new = Self::revoke_key(class_name.clone(), new.key_id(), signer)?;
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_new, revoke_current])
            }
            ResourceClassKeys::RollOld(current, old) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                let revoke_old = old.revoke_req().clone();
                Ok(vec![revoke_current, revoke_old])
            }
        }
    }

    fn revoke_key<S: Signer>(
        class_name: ResourceClassName,
        key_id: &KeyId,
        signer: &S,
    ) -> ca::Result<RevocationRequest> {
        let ki = signer
            .get_key_info(key_id)
            .map_err(Error::signer)?
            .key_identifier();

        Ok(RevocationRequest::new(class_name, ki))
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
                    Ok(old.key().clone())
                }
            }
        }
    }

    /// Helper to match a key_id to a pub key.
    fn matches_key_id<S: Signer>(
        &self,
        key_id: &KeyId,
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

        let delta =
            SignSupport::publish(signer, &certified_key, base_repo, name_space, delta, vec![])
                .map_err(Error::signer)?;

        let mut delta_map = HashMap::new();
        delta_map.insert(certified_key.key_id().clone(), delta);

        res.push(EvtDet::Published(class_name, delta_map));

        Ok(res)
    }

    fn apply_delta(&mut self, delta: PublicationDelta, key_id: KeyId) {
        match self {
            ResourceClassKeys::Pending(_pending) => panic!("Should never have delta for pending"),
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

    fn request_certs<S: Signer>(
        &self,
        parent: ParentHandle,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &S,
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

        for key_id in keys_for_requests.into_iter() {
            let req = self.create_issuance_req(
                base_repo,
                name_space,
                entitlement.class_name(),
                key_id,
                signer,
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
        key: &KeyId,
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

    /// Returns the revoke request if there is an old key.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        match self {
            ResourceClassKeys::RollOld(_current, old) => Some(old.revoke_req()),
            _ => None,
        }
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
                    EvtDet::KeyRollPendingKeyAdded(
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

    /// Marks the new key as current, and the current key as old, and requests revocation of
    /// the old key.
    // TODO: When ROAs are supported, now is also the time to republish all objects under the
    //       new current key, and withdraw them from the old key.
    fn keyroll_activate<S: Signer>(
        &self,
        parent: ParentHandle,
        class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<Vec<EvtDet>> {
        match self {
            ResourceClassKeys::RollNew(_new, current) => {
                let revoke_req = Self::revoke_key(class_name.clone(), current.key_id(), signer)?;
                Ok(vec![EvtDet::KeyRollActivated(
                    parent, class_name, revoke_req,
                )])
            }
            _ => Ok(vec![]),
        }
    }
}
