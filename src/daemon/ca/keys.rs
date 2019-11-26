use std::ops::{Deref, DerefMut};

use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::crypto::{KeyIdentifier, PublicKeyFormat};
use rpki::csr::Csr;
use rpki::x509::Time;

use crate::commons::api::{
    CertifiedKeyInfo, EntitlementClass, IssuanceRequest, PendingKeyInfo, RcvdCert, RepoInfo,
    RequestResourceLimit, ResourceClassKeysInfo, ResourceClassName, ResourceSet, RevocationRequest,
};
use crate::daemon::ca::{
    self, CurrentObjectSet, CurrentObjectSetDelta, Error, EvtDet, Result, Signer,
};

//------------ CertifiedKey --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    current_set: CurrentObjectSet,
    request: Option<IssuanceRequest>,
}

impl CertifiedKey {
    pub fn create<S: Signer>(incoming_cert: RcvdCert, signer: &S) -> ca::Result<Self> {
        let key_id = incoming_cert.cert().subject_key_identifier();
        let current_set = CurrentObjectSet::create(&incoming_cert, signer)?;

        Ok(CertifiedKey {
            key_id,
            incoming_cert,
            current_set,
            request: None,
        })
    }

    pub fn as_info(&self) -> CertifiedKeyInfo {
        CertifiedKeyInfo::new(self.key_id, self.incoming_cert.clone())
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn incoming_cert(&self) -> &RcvdCert {
        &self.incoming_cert
    }
    pub fn set_incoming_cert(&mut self, incoming_cert: RcvdCert) {
        self.request = None;
        self.incoming_cert = incoming_cert;
    }

    pub fn current_set(&self) -> &CurrentObjectSet {
        &self.current_set
    }

    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }

    pub fn wants_update(&self, new_resources: &ResourceSet, new_not_after: Time) -> bool {
        // If resources have changed, then we need to request a new certificate.
        if self.incoming_cert.resources() != new_resources {
            debug!(
                "Resources have changed from:\n{}\nto:\n{}\n",
                self.incoming_cert.resources(),
                new_resources
            );
            return true;
        }

        // If the validity time eligibility has changed, then we *may* want to ask for a new
        // certificate, but only if:
        // a) our current certificate expires *after* the eligible time, because we probably should
        //    know..
        // b) the new not after time is significantly better than our current time, because we
        //    do not want to ask for new certificates every hour if the parent uses a simple
        //    strategy like: not-after = now + 1 year..
        //
        // See issue #95

        let not_after = self.incoming_cert().cert().validity().not_after();

        let not_after = not_after.timestamp_millis();
        let new_not_after = new_not_after.timestamp_millis();

        if not_after == new_not_after {
            debug!(
                "No change in not after time for certificate for key '{}'",
                self.key_id
            );
            false
        } else if not_after < new_not_after {
            warn!(
                "Parent reduced not after time for certificate for key '{}'",
                self.key_id
            );
            true
        } else if (new_not_after as f64 / not_after as f64) > 1.1_f64 {
            debug!(
                "Parent increased not after time >10% for certificate for key '{}'",
                self.key_id
            );
            true
        } else {
            debug!("New not after time less than 10% after current time for for certificate for key '{}', not requesting a new certificate.", self.key_id);
            false
        }
    }

    pub fn close_to_next_update(&self) -> bool {
        self.current_set.next_update() < Time::now() + Duration::hours(8)
    }

    pub fn with_new_cert(mut self, cert: RcvdCert) -> Self {
        self.incoming_cert = cert;
        self
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta) {
        self.current_set.apply_delta(delta)
    }
}

pub type NewKey = CertifiedKey;
pub type CurrentKey = CertifiedKey;

//------------ PendingKey ----------------------------------------------------

/// A Pending Key in a resource class. Should usually have an open
/// IssuanceRequest, and will be move to a 'new' or 'current' CertifiedKey
/// when a certificate is received.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKey {
    key_id: KeyIdentifier,
    request: Option<IssuanceRequest>,
}

impl PendingKey {
    pub fn new(key_id: KeyIdentifier) -> Self {
        PendingKey {
            key_id,
            request: None,
        }
    }

    pub fn as_info(&self) -> PendingKeyInfo {
        PendingKeyInfo::new(self.key_id)
    }

    pub fn unwrap(self) -> (KeyIdentifier, Option<IssuanceRequest>) {
        (self.key_id, self.request)
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }
    pub fn clear_request(&mut self) {
        self.request = None
    }
}

//------------ OldKey --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldKey {
    key: CertifiedKey,
    revoke_req: RevocationRequest,
}

impl OldKey {
    pub fn new(key: CertifiedKey, revoke_req: RevocationRequest) -> Self {
        OldKey { key, revoke_req }
    }

    pub fn key(&self) -> &CertifiedKey {
        &self.key
    }
    pub fn revoke_req(&self) -> &RevocationRequest {
        &self.revoke_req
    }
}

impl Deref for OldKey {
    type Target = CertifiedKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl DerefMut for OldKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key
    }
}

//------------ KeyState ------------------------------------------------------

/// This type contains the keys for a resource class and guards that keys
/// are created, activated, rolled and retired properly.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Pending(PendingKey),
    Active(CurrentKey),
    RollPending(PendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldKey),
}

impl KeyState {
    pub fn create(pending_key: KeyIdentifier) -> Self {
        KeyState::Pending(PendingKey::new(pending_key))
    }

    pub fn add_request(&mut self, key_id: KeyIdentifier, req: IssuanceRequest) {
        match self {
            KeyState::Pending(pending) => pending.add_request(req),
            KeyState::Active(current) => current.add_request(req),
            KeyState::RollPending(pending, current) => {
                if pending.key_id() == &key_id {
                    pending.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            KeyState::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.add_request(req)
                } else {
                    old.add_request(req)
                }
            }
        }
    }

    /// Revoke all current keys
    pub fn revoke<S: Signer>(
        &self,
        class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<Vec<RevocationRequest>> {
        match self {
            KeyState::Pending(_pending) => Ok(vec![]), // nothing to revoke
            KeyState::Active(current) | KeyState::RollPending(_, current) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_current])
            }
            KeyState::RollNew(new, current) => {
                let revoke_new = Self::revoke_key(class_name.clone(), new.key_id(), signer)?;
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_new, revoke_current])
            }
            KeyState::RollOld(current, old) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                let revoke_old = old.revoke_req().clone();
                Ok(vec![revoke_current, revoke_old])
            }
        }
    }

    fn revoke_key<S: Signer>(
        class_name: ResourceClassName,
        key_id: &KeyIdentifier,
        signer: &S,
    ) -> ca::Result<RevocationRequest> {
        let ki = signer
            .get_key_info(key_id)
            .map_err(Error::signer)?
            .key_identifier();

        Ok(RevocationRequest::new(class_name, ki))
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta, key_id: KeyIdentifier) {
        match self {
            KeyState::Pending(_pending) => panic!("Should never have delta for pending"),
            KeyState::Active(current) => current.apply_delta(delta),
            KeyState::RollPending(_pending, current) => current.apply_delta(delta),
            KeyState::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.apply_delta(delta)
                } else {
                    current.apply_delta(delta)
                }
            }
            KeyState::RollOld(current, old) => {
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
        rcn: ResourceClassName,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &S,
    ) -> Result<Vec<EvtDet>> {
        let mut keys_for_requests = vec![];
        match self {
            KeyState::Pending(pending) => {
                keys_for_requests.push(pending.key_id());
            }
            KeyState::Active(current) => {
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            KeyState::RollPending(pending, current) => {
                keys_for_requests.push(pending.key_id());
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            KeyState::RollNew(new, current) => {
                if new.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(new.key_id());
                }
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            KeyState::RollOld(current, old) => {
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
                entitlement.class_name().clone(),
                key_id,
                signer,
            )?;

            res.push(EvtDet::CertificateRequested(rcn.clone(), req, *key_id));
        }

        Ok(res)
    }

    pub fn request_certs_new_repo<S: Signer>(
        &self,
        rcn: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &S,
    ) -> Result<Vec<EvtDet>> {
        let mut res = vec![];

        let keys = match self {
            KeyState::Pending(pending) => vec![pending.key_id()],
            KeyState::Active(current) => vec![current.key_id()],
            KeyState::RollPending(pending, current) => vec![pending.key_id(), current.key_id()],
            KeyState::RollNew(new, current) => vec![new.key_id(), current.key_id()],
            KeyState::RollOld(current, old) => vec![current.key_id(), old.key_id()],
        };

        for ki in keys {
            let req = self.create_issuance_req(base_repo, name_space, rcn.clone(), ki, signer)?;
            res.push(EvtDet::CertificateRequested(rcn.clone(), req, *ki));
        }

        Ok(res)
    }

    /// Returns all open certificate requests
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        let mut res = vec![];
        match self {
            KeyState::Pending(pending) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
            }
            KeyState::Active(current) => {
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            KeyState::RollPending(pending, current) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            KeyState::RollNew(new, current) => {
                if let Some(r) = new.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            KeyState::RollOld(current, old) => {
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

    /// Creates a Csr for the given key.
    fn create_issuance_req<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        name_space: &str,
        class_name: ResourceClassName,
        key: &KeyIdentifier,
        signer: &S,
    ) -> Result<IssuanceRequest> {
        let pub_key = signer.get_key_info(key).map_err(Error::signer)?;

        let enc = Csr::construct(
            signer,
            key,
            &base_repo.ca_repository(name_space).join(&[]), // force trailing slash
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(Error::signer)?;

        let csr = Csr::decode(enc.as_slice()).map_err(Error::signer)?;

        Ok(IssuanceRequest::new(
            class_name,
            RequestResourceLimit::default(),
            csr,
        ))
    }

    /// Returns the revoke request if there is an old key.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        match self {
            KeyState::RollOld(_current, old) => Some(old.revoke_req()),
            _ => None,
        }
    }

    pub fn as_info(&self) -> ResourceClassKeysInfo {
        match self.clone() {
            KeyState::Pending(p) => ResourceClassKeysInfo::Pending(p.as_info()),
            KeyState::Active(c) => ResourceClassKeysInfo::Active(c.as_info()),
            KeyState::RollPending(p, c) => {
                ResourceClassKeysInfo::RollPending(p.as_info(), c.as_info())
            }
            KeyState::RollNew(n, c) => ResourceClassKeysInfo::RollNew(n.as_info(), c.as_info()),
            KeyState::RollOld(c, o) => ResourceClassKeysInfo::RollOld(c.as_info(), o.as_info()),
        }
    }
}

/// # Key Life Cycle
///
impl KeyState {
    /// Initiates a key roll if the current state is 'Active'. This will return event details
    /// for a newly create pending key and requested certificate for it.
    pub fn keyroll_initiate<S: Signer>(
        &self,
        class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &mut S,
    ) -> ca::Result<Vec<EvtDet>> {
        match self {
            KeyState::Active(_current) => {
                let key_id = {
                    signer
                        .create_key(PublicKeyFormat::default())
                        .map_err(Error::signer)?
                };

                let issuance_req = self.create_issuance_req(
                    base_repo,
                    name_space,
                    parent_class_name,
                    &key_id,
                    signer,
                )?;

                Ok(vec![
                    EvtDet::KeyRollPendingKeyAdded(class_name.clone(), key_id),
                    EvtDet::CertificateRequested(class_name, issuance_req, key_id),
                ])
            }
            _ => Ok(vec![]),
        }
    }

    /// Marks the new key as current, and the current key as old, and requests revocation of
    /// the old key.
    pub fn keyroll_activate<S: Signer>(
        &self,
        class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<EvtDet> {
        match self {
            KeyState::RollNew(_new, current) => {
                let revoke_req = Self::revoke_key(parent_class_name, current.key_id(), signer)?;
                Ok(EvtDet::KeyRollActivated(class_name, revoke_req))
            }
            _ => Err(Error::ResourceClassNoNewKey),
        }
    }

    /// Returns true if there is a new key
    pub fn has_new_key(&self) -> bool {
        match self {
            KeyState::RollNew(_, _) => true,
            _ => false,
        }
    }
}
