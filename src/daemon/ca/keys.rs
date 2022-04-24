use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

use rpki::{
    ca::{
        idexchange::{Handle, RepoInfo},
        provisioning::{
            IssuanceRequest, RequestResourceLimit, ResourceClassEntitlements, ResourceClassName, RevocationRequest,
        },
        resourceset::ResourceSet,
    },
    repository::{crypto::KeyIdentifier, x509::Time},
};

use crate::{
    commons::{
        api::{
            ActiveInfo, CertifiedKeyInfo, PendingInfo, PendingKeyInfo, RcvdCert, ResourceClassKeysInfo, RollNewInfo,
            RollOldInfo, RollPendingInfo,
        },
        crypto::KrillSigner,
        error::Error,
        KrillResult,
    },
    daemon::ca::CaEvtDet,
};

//------------ CertifiedKey --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    request: Option<IssuanceRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepoInfo>,
}

impl CertifiedKey {
    pub fn new(key_id: KeyIdentifier, incoming_cert: RcvdCert, request: Option<IssuanceRequest>) -> Self {
        CertifiedKey {
            key_id,
            incoming_cert,
            request,
            old_repo: None,
        }
    }

    pub fn create(incoming_cert: RcvdCert) -> Self {
        let key_id = incoming_cert.subject_key_identifier();
        CertifiedKey {
            key_id,
            incoming_cert,
            request: None,
            old_repo: None,
        }
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

    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }

    pub fn set_old_repo(&mut self, repo: RepoInfo) {
        self.old_repo = Some(repo)
    }

    pub fn wants_update(
        &self,
        handle: &Handle,
        rcn: &ResourceClassName,
        new_resources: &ResourceSet,
        new_not_after: Time,
    ) -> bool {
        // If resources have changed, then we need to request a new certificate.
        let resources_diff = new_resources.difference(self.incoming_cert.resources());

        if !resources_diff.is_empty() {
            info!(
                "Will request new certificate for CA '{}' under RC '{}'. Resources have changed: '{}'",
                handle, rcn, resources_diff
            );
            return true;
        }

        // If the remaining validity time eligibility has changed by more than 10% then we will
        // want to request a new certificate.
        //
        // We use this 10% margin to avoid ending up in endless request loops - in particular
        // in cases where the parent uses a simple strategy like: not-after = now + 1 year for
        // every list request we send. See issue #95.
        //
        // As it turns out there can also be timing issues with remaining time *reduction*. This
        // is rather odd - as the parent is not really expected to reduce the time compared to
        // what they issued to us before. But if it does happen (on every request like above)
        // then we still want to avoid ending up in request loops. See issue #775

        let not_after = self.incoming_cert().cert().validity().not_after();

        let now = Time::now().timestamp();
        let remaining_seconds_on_current = not_after.timestamp() - now;
        let remaining_seconds_on_eligible = new_not_after.timestamp() - now;

        if remaining_seconds_on_eligible <= 0 {
            // eligible remaining time is in the past!
            //
            // This is rather odd. The parent should just exclude the resource class in the
            // eligible entitlements instead. So, we will essentially just ignore this until
            // they do.
            warn!(
                "Will NOT request certificate for CA '{}' under RC '{}', the eligible not after time is set in the past: {}",
                handle,
                rcn,
                new_not_after.to_rfc3339()
            );
            false
        } else if remaining_seconds_on_current == remaining_seconds_on_eligible {
            debug!(
                "Will not request new certificate for CA '{}' under RC '{}'. Resources and not after time are unchanged.",
                handle,
                rcn,
            );
            false
        } else if remaining_seconds_on_current > 0
            && (remaining_seconds_on_eligible as f64 / remaining_seconds_on_current as f64) < 0.9_f64
        {
            warn!(
                "Parent of CA '{}' *reduced* not after time for certificate under RC '{}'. This is odd, but.. requesting new certificate.",
                handle, rcn,
            );
            true
        } else if remaining_seconds_on_current <= 0
            || (remaining_seconds_on_eligible as f64 / remaining_seconds_on_current as f64) > 1.1_f64
        {
            info!(
                "Will request new certificate for CA '{}' under RC '{}'. Not after time increased to: {}",
                handle,
                rcn,
                new_not_after.to_rfc3339()
            );
            true
        } else {
            debug!(
                "Will not request new certificate for CA '{}' under RC '{}'. Remaining not after time changed by less than 10%. From: {} To: {}",
                handle,
                rcn,
                not_after.to_rfc3339(),
                new_not_after.to_rfc3339()
            );
            false
        }
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
        PendingKey { key_id, request: None }
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
    pub fn revoke(&self, class_name: ResourceClassName, signer: &KrillSigner) -> KrillResult<Vec<RevocationRequest>> {
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

    fn revoke_key(
        class_name: ResourceClassName,
        key_id: &KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<RevocationRequest> {
        let ki = signer.get_key_info(key_id).map_err(Error::signer)?.key_identifier();

        Ok(RevocationRequest::new(class_name, ki))
    }

    pub fn make_entitlement_events(
        &self,
        handle: &Handle,
        rcn: ResourceClassName,
        entitlement: &ResourceClassEntitlements,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let mut keys_for_requests = vec![];

        match self {
            KeyState::Pending(pending) => {
                keys_for_requests.push((base_repo, pending.key_id()));
            }
            KeyState::Active(current) => {
                if current.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = current.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, current.key_id()));
                }
            }
            KeyState::RollPending(pending, current) => {
                keys_for_requests.push((base_repo, pending.key_id()));
                if current.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = current.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, current.key_id()));
                }
            }
            KeyState::RollNew(new, current) => {
                if new.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = new.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, new.key_id()));
                }
                if current.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = current.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, current.key_id()));
                }
            }
            KeyState::RollOld(current, old) => {
                if current.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = current.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, current.key_id()));
                }
                if old.wants_update(handle, &rcn, entitlement.resource_set(), entitlement.not_after()) {
                    let repo = old.old_repo.as_ref().unwrap_or(base_repo);
                    keys_for_requests.push((repo, current.key_id()));
                }
            }
        }

        let mut res = vec![];

        for (base_repo, key_id) in keys_for_requests.into_iter() {
            let req =
                self.create_issuance_req(base_repo, name_space, entitlement.class_name().clone(), key_id, signer)?;

            res.push(CaEvtDet::CertificateRequested {
                resource_class_name: rcn.clone(),
                req,
                ki: *key_id,
            });
        }

        for key in entitlement
            .issued_certs()
            .iter()
            .map(|c| c.cert().subject_key_identifier())
        {
            if !self.knows_key(key) {
                let revoke_req = RevocationRequest::new(entitlement.class_name().clone(), key);
                res.push(CaEvtDet::UnexpectedKeyFound {
                    resource_class_name: rcn.clone(),
                    revoke_req,
                });
            }
        }

        Ok(res)
    }

    pub fn request_certs_new_repo(
        &self,
        rcn: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
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
            res.push(CaEvtDet::CertificateRequested {
                resource_class_name: rcn.clone(),
                req,
                ki: *ki,
            });
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
    fn create_issuance_req(
        &self,
        base_repo: &RepoInfo,
        name_space: &str,
        class_name: ResourceClassName,
        key: &KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<IssuanceRequest> {
        let csr = signer.sign_csr(base_repo, name_space, key)?;
        Ok(IssuanceRequest::new(class_name, RequestResourceLimit::default(), csr))
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
            KeyState::Pending(p) => ResourceClassKeysInfo::Pending(PendingInfo {
                _pending_key: p.as_info(),
            }),
            KeyState::Active(c) => ResourceClassKeysInfo::Active(ActiveInfo {
                _active_key: c.as_info(),
            }),
            KeyState::RollPending(p, c) => ResourceClassKeysInfo::RollPending(RollPendingInfo {
                _pending_key: p.as_info(),
                _active_key: c.as_info(),
            }),
            KeyState::RollNew(n, c) => ResourceClassKeysInfo::RollNew(RollNewInfo {
                _new_key: n.as_info(),
                _active_key: c.as_info(),
            }),
            KeyState::RollOld(c, o) => ResourceClassKeysInfo::RollOld(RollOldInfo {
                _old_key: o.as_info(),
                _active_key: c.as_info(),
            }),
        }
    }
}

/// # Key Life Cycle
///
impl KeyState {
    /// Initiates a key roll if the current state is 'Active'. This will return event details
    /// for a newly create pending key and requested certificate for it.
    pub fn keyroll_initiate(
        &self,
        resource_class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        match self {
            KeyState::Active(_current) => {
                let pending_key_id = signer.create_key()?;

                let req =
                    self.create_issuance_req(base_repo, name_space, parent_class_name, &pending_key_id, signer)?;

                Ok(vec![
                    CaEvtDet::KeyRollPendingKeyAdded {
                        resource_class_name: resource_class_name.clone(),
                        pending_key_id,
                    },
                    CaEvtDet::CertificateRequested {
                        resource_class_name,
                        req,
                        ki: pending_key_id,
                    },
                ])
            }
            _ => Ok(vec![]),
        }
    }

    /// Marks the new key as current, and the current key as old, and requests revocation of
    /// the old key.
    pub fn keyroll_activate(
        &self,
        resource_class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        signer: &KrillSigner,
    ) -> KrillResult<CaEvtDet> {
        match self {
            KeyState::RollNew(_new, current) => {
                let revoke_req = Self::revoke_key(parent_class_name, current.key_id(), signer)?;
                Ok(CaEvtDet::KeyRollActivated {
                    resource_class_name,
                    revoke_req,
                })
            }
            _ => Err(Error::KeyUseNoNewKey),
        }
    }

    /// Returns the new key, iff there is a key roll in progress and there is a new key.
    pub fn new_key(&self) -> Option<&CertifiedKey> {
        match self {
            KeyState::RollNew(new, _) => Some(new),
            _ => None,
        }
    }

    fn knows_key(&self, key_id: KeyIdentifier) -> bool {
        match self {
            KeyState::Pending(pending) => pending.key_id == key_id,
            KeyState::Active(current) => current.key_id == key_id,
            KeyState::RollPending(pending, current) => pending.key_id == key_id || current.key_id == key_id,
            KeyState::RollNew(new, current) => new.key_id == key_id || current.key_id == key_id,
            KeyState::RollOld(current, old) => current.key_id == key_id || old.key_id == key_id,
        }
    }
}

/// # Migrate repositories
///
impl KeyState {
    /// Mark an old_repo for the current key, so that a new repo can be introduced in a pending
    /// key and a keyroll can be done.
    pub fn set_old_repo_if_in_active_state(&mut self, repo: RepoInfo) {
        if let KeyState::Active(current) = self {
            current.set_old_repo(repo);
        }
    }
}
