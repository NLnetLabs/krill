//! CA key management.

use log::{debug, info, warn};
use rpki::ca::idexchange::{CaHandle, RepoInfo};
use rpki::ca::provisioning::{
    IssuanceRequest, RequestResourceLimit, ResourceClassEntitlements,
    ResourceClassName, RevocationRequest,
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::{resources::ResourceSet, x509::Time};
use serde::{Deserialize, Serialize};
use crate::api::ca::{
    ActiveInfo, CertifiedKeyInfo, PendingInfo, PendingKeyInfo, ReceivedCert,
    ResourceClassKeysInfo, RollNewInfo, RollOldInfo, RollPendingInfo,
};
use crate::commons::KrillResult;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use super::events::CertAuthEvent;


//------------ CertifiedKey --------------------------------------------------

/// A Key that is certified.
///
/// This means that the key has received an incoming certificate and has at
/// least a manifest and CRL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertifiedKey {
    /// The key identifier.
    key_id: KeyIdentifier,

    /// The certificate received from the parent for the key.
    incoming_cert: ReceivedCert,

    /// A request for a new certificate if there currently is one.
    request: Option<IssuanceRequest>,

    /// The old repository for the certifcate if we move to a new one.
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepoInfo>,
}

impl CertifiedKey {
    /// Creates a new certified key from an incoming certificate.
    pub fn create(incoming_cert: ReceivedCert) -> Self {
        Self {
            key_id: incoming_cert.key_identifier(),
            incoming_cert,
            request: None,
            old_repo: None,
        }
    }

    /// Creates a value from its components.
    ///
    /// This is only used for upgrade code.
    pub fn new(
        key_id: KeyIdentifier,
        incoming_cert: ReceivedCert,
        request: Option<IssuanceRequest>,
        old_repo: Option<RepoInfo>
    ) -> Self {
        Self { key_id, incoming_cert, request, old_repo }
    }

    /// Returns the key identifier of the key.
    pub fn key_id(&self) -> KeyIdentifier {
        self.key_id
    }

    /// Returns a reference to the certificate received for the key.
    pub fn incoming_cert(&self) -> &ReceivedCert {
        &self.incoming_cert
    }

    /// Updates the certificate received for the key.
    pub fn set_incoming_cert(&mut self, cert: ReceivedCert) {
        self.incoming_cert = cert
    }

    /// Returns the certified key info for this certified key.
    pub fn to_info(&self) -> CertifiedKeyInfo {
        CertifiedKeyInfo {
            key_id: self.key_id,
            incoming_cert: self.incoming_cert.clone(),
            request: None
        }
    }

    /// Returns whether the key needs to be updated.
    fn wants_update(
        &self,
        handle: &CaHandle,
        rcn: &ResourceClassName,
        new_resources: &ResourceSet,
        new_not_after: Time,
    ) -> bool {
        // If we did not have a trailing slash for the id-ad-caRepository,
        // then we should make a new CSR which will include it. See
        // issue #1030.
        if !self.incoming_cert.ca_repository().ends_with("/") {
            return true;
        }

        // If resources have changed, then we need to request a new
        // certificate.
        let resources_diff = new_resources.difference(
            &self.incoming_cert.resources
        );
        if !resources_diff.is_empty() {
            info!(
                "Will request new certificate for CA '{handle}' \
                 under RC '{rcn}'. \
                 Resources have changed: '{resources_diff}'",
            );
            return true;
        }

        // If the remaining validity time eligibility has changed by more than
        // 10% then we will want to request a new certificate.
        //
        // We use this 10% margin to avoid ending up in endless request loops
        // - in particular in cases where the parent uses a simple
        // strategy like: not-after = now + 1 year for every list
        // request we send. See issue #95.
        //
        // As it turns out there can also be timing issues with remaining time
        // *reduction*. This is rather odd - as the parent is not
        // really expected to reduce the time compared to
        // what they issued to us before. But if it does happen (on every
        // request like above) then we still want to avoid ending up
        // in request loops. See issue #775

        let not_after = self.incoming_cert.validity.not_after();

        let now = Time::now().timestamp();
        let remaining_seconds_on_current = not_after.timestamp() - now;
        let remaining_seconds_on_eligible = new_not_after.timestamp() - now;

        if remaining_seconds_on_eligible <= 0 {
            // eligible remaining time is in the past!
            //
            // This is rather odd. The parent should just exclude the resource
            // class in the eligible entitlements instead. So, we
            // will essentially just ignore this until they do.
            warn!(
                "Will NOT request certificate for CA '{}' under RC '{}', \
                 the eligible not after time is set in the past: {}",
                handle,
                rcn,
                new_not_after.to_rfc3339()
            );
            false
        }
        else if remaining_seconds_on_current == remaining_seconds_on_eligible {
            debug!(
                "Will not request new certificate for CA '{}' \
                 under RC '{}'. Resources and not after time are unchanged.",
                handle,
                rcn,
            );
            false
        }
        else if remaining_seconds_on_current > 0
            && (remaining_seconds_on_eligible as f64
                / remaining_seconds_on_current as f64)
                < 0.9_f64
        {
            warn!(
                "Parent of CA '{}' *reduced* not after time for certificate \
                 under RC '{}'. This is odd, but requesting new certificate.",
                handle, rcn,
            );
            true
        }
        else if remaining_seconds_on_current <= 0
            || (remaining_seconds_on_eligible as f64
                / remaining_seconds_on_current as f64)
                > 1.1_f64
            || (remaining_seconds_on_eligible
                - remaining_seconds_on_current >= 604_800)
        {
            info!(
                "Will request new certificate for CA '{}' under RC '{}'. \
                 Not-after time increased to: {}",
                handle,
                rcn,
                new_not_after.to_rfc3339()
            );
            true
        }
        // XXX We’re using the fact that a TA certificate usually contains
        //     all resources to identify a TA certificate here.
        else if self.incoming_cert().resources == ResourceSet::all() {
            debug!(
                "It is technically too early for a new update, but \
                 requesting one anyway since it is the TA"
            );
            true
        }
        else {
            debug!(
                "Will not request new certificate for CA '{}' under RC '{}'. \
                 Remaining not after time changed by less than 10%. \
                 From {} to {}",
                handle,
                rcn,
                not_after.to_rfc3339(),
                new_not_after.to_rfc3339()
            );
            false
        }
    }
}


//------------ NewKey --------------------------------------------------------

/// Type alias for the new key during a key roll.
type NewKey = CertifiedKey;


//------------ CurrentKey ----------------------------------------------------

/// Type alias for the currently active key.
pub type CurrentKey = CertifiedKey;


//------------ PendingKey ----------------------------------------------------

/// A key waiting for a certificate from the parent.
///
/// This key should usually have an open [`IssuanceRequest`], and will be
/// moved to a 'new' or 'current' [`CertifiedKey`] when a certificate is
/// received.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKey {
    /// The key identifier of the key.
    key_id: KeyIdentifier,

    /// The issuance request sent to the parent.
    request: Option<IssuanceRequest>,
}

impl PendingKey {
    /// Creates a new pending key for a key identifier.
    pub fn new(key_id: KeyIdentifier) -> Self {
        PendingKey {
            key_id,
            request: None,
        }
    }

    /// Returns the key info for this key.
    pub fn to_info(&self) -> PendingKeyInfo {
        PendingKeyInfo { key_id: self.key_id }
    }

    /// Returns the key identifier for this key.
    pub fn key_id(&self) -> KeyIdentifier {
        self.key_id
    }
}


//------------ OldKey --------------------------------------------------------

/// A key that is not in use any more but has not been revoked by the parent.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldKey {
    /// The key that is to be revoked.
    key: CertifiedKey,

    /// The revocation request.
    revoke_req: RevocationRequest,
}

impl OldKey {
    /// Creates an old key for the given key and revocation request.
    pub fn new(key: CertifiedKey, revoke_req: RevocationRequest) -> Self {
        OldKey { key, revoke_req }
    }

    /// Sets the parent’s certificate for the key.
    pub fn set_incoming_cert(&mut self, cert: ReceivedCert) {
        self.key.set_incoming_cert(cert)
    }

    pub fn _revoke_req(&self) -> &RevocationRequest {
        &self.revoke_req
    }
}


//------------ KeyState ------------------------------------------------------

/// The current set of keys for a resource class.
///
/// The type guards that keys are created, activated, rolled and retired
/// properly.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// An initial key is pending to be certified by the parent.
    Pending(PendingKey),

    /// A single key is currently active.
    Active(CurrentKey),

    /// A key roll has been started.
    ///
    /// The new key is pending to be certified by the parent.
    RollPending(PendingKey, CurrentKey),

    /// A new key has been issued by the parent.
    RollNew(NewKey, CurrentKey),

    /// The old key has not yet been revoked by the parent.
    RollOld(CurrentKey, OldKey),
}

impl KeyState {
    /// Creates a new key state using the given key as pending key.
    pub fn create(pending_key: KeyIdentifier) -> Self {
        KeyState::Pending(PendingKey::new(pending_key))
    }

    /// Adds an issuance request for the given key.
    pub fn apply_issuance_request(
        &mut self,
        key_id: KeyIdentifier,
        req: IssuanceRequest,
    ) {
        match self {
            KeyState::Pending(pending) => {
                pending.request = Some(req)
            }
            KeyState::Active(current) => {
                current.request = Some(req)
            }
            KeyState::RollPending(pending, current) => {
                if pending.key_id == key_id {
                    pending.request = Some(req)
                }
                else {
                    current.request = Some(req)
                }
            }
            KeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.request = Some(req)
                }
                else {
                    current.request = Some(req)
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id == key_id {
                    current.request = Some(req)
                }
                else {
                    old.key.request = Some(req)
                }
            }
        }
    }

    /// Returns revocation requests for all currently certified keys.
    pub fn revoke(
        &self,
        class_name: ResourceClassName,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<RevocationRequest>> {
        match self {
            KeyState::Pending(_pending) => {
                // nothing to revoke
                Ok(vec![])
            }
            KeyState::Active(current) | KeyState::RollPending(_, current) => {
                Ok(vec![
                    Self::revoke_key(class_name, current.key_id, signer)?,
                ])
            }
            KeyState::RollNew(new, current) => {
                Ok(vec![
                    Self::revoke_key(
                        class_name.clone(),
                        new.key_id,
                        signer,
                    )?,
                    Self::revoke_key(class_name, current.key_id, signer)?,
                ])
            }
            KeyState::RollOld(current, old) => {
                Ok(vec![
                    Self::revoke_key(class_name, current.key_id, signer)?,
                    old.revoke_req.clone()
                ])
            }
        }
    }

    /// Returns a revocation request for a single key.
    fn revoke_key(
        class_name: ResourceClassName,
        key_id: KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<RevocationRequest> {
        Ok(RevocationRequest::new(
            class_name,
            signer.get_key_info(
                &key_id
            ).map_err(Error::signer)?.key_identifier()
        ))
    }

    /// Appends the key-related events for a resource class.
    ///
    /// Creates events for requesting certificates and revoking keys based
    /// on the current key state and the entitlements provided by the parent.
    #[allow(clippy::too_many_arguments)]
    pub fn append_entitlement_events(
        &self,
        handle: &CaHandle,
        rcn: ResourceClassName,
        entitlement: &ResourceClassEntitlements,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<()> {
        // Collect pairs of repos and key IDs for certificate requests.
        let mut keys_for_requests = vec![];

        match self {
            KeyState::Pending(pending) => {
                keys_for_requests.push((base_repo, pending.key_id));
            }
            KeyState::Active(current) => {
                if current.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        current.old_repo.as_ref().unwrap_or(base_repo),
                        current.key_id,
                    ));
                }
            }
            KeyState::RollPending(pending, current) => {
                keys_for_requests.push((base_repo, pending.key_id));
                if current.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        current.old_repo.as_ref().unwrap_or(base_repo),
                        current.key_id,
                    ));
                }
            }
            KeyState::RollNew(new, current) => {
                if new.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        new.old_repo.as_ref().unwrap_or(base_repo),
                        new.key_id,
                    ));
                }
                if current.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        current.old_repo.as_ref().unwrap_or(base_repo),
                        current.key_id
                    ));
                }
            }
            KeyState::RollOld(current, old) => {
                if current.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        current.old_repo.as_ref().unwrap_or(base_repo),
                        current.key_id,
                    ));
                }
                if old.key.wants_update(
                    handle,
                    &rcn,
                    entitlement.resource_set(),
                    entitlement.not_after(),
                ) {
                    keys_for_requests.push((
                        old.key.old_repo.as_ref().unwrap_or(base_repo),
                        current.key_id,
                    ));
                }
            }
        }

        for (base_repo, key_id) in keys_for_requests.into_iter() {
            events.push(CertAuthEvent::CertificateRequested {
                resource_class_name: rcn.clone(),
                req: self.create_issuance_req(
                    base_repo,
                    name_space,
                    entitlement.class_name().clone(),
                    &key_id,
                    signer,
                )?,
                ki: key_id,
            });
        }

        for key in entitlement
            .issued_certs()
            .iter()
            .map(|c| c.cert().subject_key_identifier())
        {
            if !self.knows_key(key) {
                let revoke_req = RevocationRequest::new(
                    entitlement.class_name().clone(),
                    key,
                );
                events.push(CertAuthEvent::UnexpectedKeyFound {
                    resource_class_name: rcn.clone(),
                    revoke_req,
                });
            }
        }

        Ok(())
    }

    /* Unused but maybe we need it again later?
    pub fn request_certs_new_repo(
        &self,
        rcn: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut res = vec![];

        let keys = match self {
            KeyState::Pending(pending) => vec![pending.key_id()],
            KeyState::Active(current) => vec![current.key_id()],
            KeyState::RollPending(pending, current) => {
                vec![pending.key_id(), current.key_id()]
            }
            KeyState::RollNew(new, current) => {
                vec![new.key_id(), current.key_id()]
            }
            KeyState::RollOld(current, old) => {
                vec![current.key_id(), old.key_id()]
            }
        };

        for ki in keys {
            let req = self.create_issuance_req(
                base_repo,
                name_space,
                rcn.clone(),
                ki,
                signer,
            )?;
            res.push(CertAuthEvent::CertificateRequested {
                resource_class_name: rcn.clone(),
                req,
                ki: *ki,
            });
        }

        Ok(res)
    }
    */

    /// Creates a certificate signing request for the given key.
    fn create_issuance_req(
        &self,
        base_repo: &RepoInfo,
        name_space: &str,
        class_name: ResourceClassName,
        key: &KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<IssuanceRequest> {
        let csr = signer.sign_csr(base_repo, name_space, key)?;
        Ok(IssuanceRequest::new(
            class_name,
            RequestResourceLimit::default(),
            csr,
        ))
    }

    /// Returns whether the given key is one of ours.
    fn knows_key(&self, key_id: KeyIdentifier) -> bool {
        match self {
            KeyState::Pending(pending) => pending.key_id == key_id,
            KeyState::Active(current) => current.key_id == key_id,
            KeyState::RollPending(pending, current) => {
                pending.key_id == key_id || current.key_id == key_id
            }
            KeyState::RollNew(new, current) => {
                new.key_id == key_id || current.key_id == key_id
            }
            KeyState::RollOld(current, old) => {
                current.key_id == key_id || old.key.key_id == key_id
            }
        }
    }

    /// Returns all open certificate requests
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        let mut res = vec![];
        match self {
            KeyState::Pending(pending) => {
                if let Some(r) = pending.request.as_ref() {
                    res.push(r.clone())
                }
            }
            KeyState::Active(current) => {
                if let Some(r) = current.request.as_ref() {
                    res.push(r.clone())
                }
            }
            KeyState::RollPending(pending, current) => {
                if let Some(r) = pending.request.as_ref() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request.as_ref() {
                    res.push(r.clone())
                }
            }
            KeyState::RollNew(new, current) => {
                if let Some(r) = new.request.as_ref() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request.as_ref() {
                    res.push(r.clone())
                }
            }
            KeyState::RollOld(current, old) => {
                if let Some(r) = current.request.as_ref() {
                    res.push(r.clone())
                }
                if let Some(r) = old.key.request.as_ref() {
                    res.push(r.clone())
                }
            }
        }
        res
    }

    /// Returns the revoke request if there is an old key.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        match self {
            KeyState::RollOld(_current, old) => Some(&old.revoke_req),
            _ => None,
        }
    }

    pub fn to_info(&self) -> ResourceClassKeysInfo {
        match self.clone() {
            KeyState::Pending(p) => {
                ResourceClassKeysInfo::Pending(PendingInfo {
                    pending_key: p.to_info(),
                })
            }
            KeyState::Active(c) => {
                ResourceClassKeysInfo::Active(ActiveInfo {
                    active_key: c.to_info(),
                })
            }
            KeyState::RollPending(p, c) => {
                ResourceClassKeysInfo::RollPending(RollPendingInfo {
                    pending_key: p.to_info(),
                    active_key: c.to_info(),
                })
            }
            KeyState::RollNew(n, c) => {
                ResourceClassKeysInfo::RollNew(RollNewInfo {
                    new_key: n.to_info(),
                    active_key: c.to_info(),
                })
            }
            KeyState::RollOld(c, o) => {
                ResourceClassKeysInfo::RollOld(RollOldInfo {
                    old_key: o.key.to_info(),
                    active_key: c.to_info(),
                })
            }
        }
    }
}

/// # Key Life Cycle
///
impl KeyState {
    /// Initiates a key roll if the current state is 'Active'.
    ///
    /// Adds the events for a newly create pending key and requested
    /// certificate to `events`. Returns whether a key roll was actually
    /// started.
    pub fn append_keyroll_initiate(
        &self,
        resource_class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<bool> {
        match self {
            KeyState::Active(_current) => {
                let pending_key_id = signer.create_key()?;

                let req = self.create_issuance_req(
                    base_repo,
                    name_space,
                    parent_class_name,
                    &pending_key_id,
                    signer,
                )?;

                events.push(CertAuthEvent::KeyRollPendingKeyAdded {
                    resource_class_name: resource_class_name.clone(),
                    pending_key_id,
                });
                events.push(CertAuthEvent::CertificateRequested {
                    resource_class_name,
                    req,
                    ki: pending_key_id,
                });
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Activates a key roll.
    ///
    /// Marks the new key as current, and the current key as old, and requests
    /// revocation of the old key.
    pub fn append_keyroll_activate(
        &self,
        resource_class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<()> {
        match self {
            KeyState::RollNew(new, current) => {
                if new.request.is_some() || current.request.is_some() {
                    Err(Error::KeyRollActivatePendingRequests)
                }
                else {
                    let revoke_req = Self::revoke_key(
                        parent_class_name,
                        current.key_id,
                        signer,
                    )?;
                    events.push(CertAuthEvent::KeyRollActivated {
                        resource_class_name,
                        revoke_req,
                    });
                    Ok(())
                }
            }
            _ => Err(Error::KeyUseNoNewKey),
        }
    }

    /// Returns the new key if available.
    ///
    /// A new key is available, if there is a key roll in progress and there
    /// is a new key.
    pub fn new_key(&self) -> Option<&CertifiedKey> {
        match self {
            KeyState::RollNew(new, _) => Some(new),
            _ => None,
        }
    }
}

/// # Migrate repositories
///
impl KeyState {
    /// Mark an old_repo for the current key.
    ///
    /// This allows introducing a new repo in a pending key and starting a
    /// keyroll.
    ///
    /// If there currently is a key roll ongoing or we don’t have an active
    /// key yet, does nothing.
    pub fn set_old_repo_if_in_active_state(&mut self, repo: RepoInfo) {
        if let KeyState::Active(current) = self {
            current.old_repo = Some(repo);
        }
    }
}
