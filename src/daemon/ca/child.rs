use std::collections::HashMap;

use rpki::{
    ca::{idexchange::ChildHandle, provisioning::ResourceClassName},
    crypto::KeyIdentifier,
    repository::resources::ResourceSet,
};

use crate::{
    commons::{
        api::{ChildCaInfo, ChildState, IdCertInfo, IssuedCertificate, ReceivedCert, SuspendedCert, UnsuspendedCert},
        crypto::{KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{ca::ChildCertificateUpdates, config::IssuanceTimingConfig},
};

//------------ UsedKeyState ------------------------------------------------

/// Tracks the state of a key used by a child CA. This is needed because
/// RFC 6492 dictates that keys cannot be re-used across resource classes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum UsedKeyState {
    Current(ResourceClassName),
    Revoked,
}

//------------ ChildInfo ---------------------------------------------------

/// Contains information about a child CA needed by a parent [CertAuth](ca.CertAuth).
///
/// Note that the actual [IssuedCert] corresponding to the [KeyIdentifier]
/// and [ResourceClassName] are kept in the parent's [ResourceClass].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildDetails {
    #[serde(default)]
    state: ChildState,
    id_cert: IdCertInfo,
    resources: ResourceSet,
    used_keys: HashMap<KeyIdentifier, UsedKeyState>,
}

impl ChildDetails {
    pub fn new(id_cert: IdCertInfo, resources: ResourceSet) -> Self {
        ChildDetails {
            state: ChildState::Active,
            id_cert,
            resources,
            used_keys: HashMap::new(),
        }
    }

    pub fn is_suspended(&self) -> bool {
        self.state == ChildState::Suspended
    }

    pub fn suspend(&mut self) {
        self.state = ChildState::Suspended;
    }

    pub fn unsuspend(&mut self) {
        self.state = ChildState::Active;
    }

    pub fn id_cert(&self) -> &IdCertInfo {
        &self.id_cert
    }

    pub fn set_id_cert(&mut self, id_cert: IdCertInfo) {
        self.id_cert = id_cert;
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn set_resources(&mut self, resources: ResourceSet) {
        self.resources = resources;
    }

    pub fn issued(&self, rcn: &ResourceClassName) -> Vec<KeyIdentifier> {
        let mut res = vec![];

        for (ki, used_key_state) in self.used_keys.iter() {
            if let UsedKeyState::Current(found_rcn) = used_key_state {
                if found_rcn == rcn {
                    res.push(*ki)
                }
            }
        }

        res
    }

    pub fn is_issued(&self, ki: &KeyIdentifier) -> bool {
        matches!(self.used_keys.get(ki), Some(UsedKeyState::Current(_)))
    }

    pub fn add_issue_response(&mut self, rcn: ResourceClassName, ki: KeyIdentifier) {
        self.used_keys.insert(ki, UsedKeyState::Current(rcn));
    }

    pub fn add_revoke_response(&mut self, ki: KeyIdentifier) {
        self.used_keys.insert(ki, UsedKeyState::Revoked);
    }

    /// Returns an error in case the key is already in use in another class.
    pub fn verify_key_allowed(&self, ki: &KeyIdentifier, rcn: &ResourceClassName) -> KrillResult<()> {
        if let Some(last_response) = self.used_keys.get(ki) {
            let allowed = match last_response {
                UsedKeyState::Revoked => false,
                UsedKeyState::Current(found) => found == rcn,
            };
            if !allowed {
                return Err(Error::KeyUseAttemptReuse);
            }
        }
        Ok(())
    }
}

impl From<ChildDetails> for ChildCaInfo {
    fn from(details: ChildDetails) -> Self {
        ChildCaInfo::new(details.state, details.id_cert, details.resources)
    }
}

//------------ Children ----------------------------------------------------

/// The collection of children under a parent [`CertAuth`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Children {
    inner: HashMap<ChildHandle, ChildDetails>,
}

//------------ ChildCertificates -------------------------------------------

/// The collection of certificates issued under a [ResourceClass](ca.ResourceClass).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificates {
    #[serde(alias = "inner")] // Note: we cannot remove this unless we migrate existing json on upgrade.
    issued: HashMap<KeyIdentifier, IssuedCertificate>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    suspended: HashMap<KeyIdentifier, SuspendedCert>,
}

impl ChildCertificates {
    pub fn is_empty(&self) -> bool {
        self.issued.is_empty() && self.suspended.is_empty()
    }

    pub fn certificate_issued(&mut self, issued: IssuedCertificate) {
        let ki = issued.key_identifier();
        self.issued.insert(ki, issued);
    }

    pub fn certificate_unsuspended(&mut self, unsuspended: UnsuspendedCert) {
        let ki = unsuspended.key_identifier();
        self.suspended.remove(&ki);
        self.issued.insert(ki, unsuspended.into_converted());
    }

    pub fn certificate_suspended(&mut self, suspended: SuspendedCert) {
        let ki = suspended.key_identifier();
        self.issued.remove(&ki);
        self.suspended.insert(ki, suspended);
    }

    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.issued.remove(key);
        self.suspended.remove(key);
    }

    pub fn get_issued(&self, ki: &KeyIdentifier) -> Option<&IssuedCertificate> {
        self.issued.get(ki)
    }

    pub fn get_suspended(&self, ki: &KeyIdentifier) -> Option<&SuspendedCert> {
        self.suspended.get(ki)
    }

    pub fn current(&self) -> impl Iterator<Item = &IssuedCertificate> {
        self.issued.values()
    }

    /// Re-issue everything when activating a new key
    pub fn activate_key(
        &self,
        signing_cert: &ReceivedCert,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ChildCertificateUpdates> {
        let mut updates = ChildCertificateUpdates::default();
        for issued in self.issued.values() {
            updates.issue(self.re_issue(issued, None, signing_cert, issuance_timing, signer)?);
        }
        // Also re-issue suspended certificates, they may yet become unsuspended at some point
        for suspended in self.suspended.values() {
            updates.suspend(
                self.re_issue(&suspended.convert(), None, signing_cert, issuance_timing, signer)?
                    .into_converted(),
            );
        }
        Ok(updates)
    }

    /// Shrink any overclaiming certificates.
    ///
    /// NOTE: We need to pro-actively shrink child certificates to avoid invalidating them.
    ///       But, if we gain additional resources it is up to child to request a new certificate
    ///       with those resources.
    pub fn shrink_overclaiming(
        &self,
        received_cert: &ReceivedCert,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ChildCertificateUpdates> {
        let mut updates = ChildCertificateUpdates::default();

        let updated_resources = received_cert.resources();

        for issued in self.issued.values() {
            if let Some(reduced_set) = issued.reduced_applicable_resources(updated_resources) {
                if reduced_set.is_empty() {
                    // revoke
                    updates.remove(issued.key_identifier());
                } else {
                    // re-issue
                    updates.issue(self.re_issue(issued, Some(reduced_set), received_cert, issuance_timing, signer)?);
                }
            }
        }

        // Also shrink suspended, in case they would come back
        for suspended in self.suspended.values() {
            if let Some(reduced_set) = suspended.reduced_applicable_resources(updated_resources) {
                if reduced_set.is_empty() {
                    // revoke
                    updates.remove(suspended.key_identifier());
                } else {
                    // re-issue shrunk suspended
                    //
                    // Note: this will not be published yet, but remain suspended
                    //       until the child contacts us again, or is manually
                    //       un-suspended.
                    updates.suspend(
                        self.re_issue(
                            &suspended.convert(),
                            Some(reduced_set),
                            received_cert,
                            issuance_timing,
                            signer,
                        )?
                        .into_converted(),
                    );
                }
            }
        }

        Ok(updates)
    }

    /// Re-issue an issued certificate to replace an earlier
    /// one which is about to be outdated or has changed resources.
    fn re_issue(
        &self,
        previous: &IssuedCertificate,
        updated_resources: Option<ResourceSet>,
        signing_cert: &ReceivedCert,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCertificate> {
        let csr_info = previous.csr_info().clone();
        let resource_set = updated_resources.unwrap_or_else(|| previous.resources().clone());
        let limit = previous.limit().clone();

        let re_issued = SignSupport::make_issued_cert(
            csr_info,
            &resource_set,
            limit,
            signing_cert,
            issuance_timing.new_child_cert_validity(),
            signer,
        )?;

        Ok(re_issued)
    }

    pub fn expiring(&self, issuance_timing: &IssuanceTimingConfig) -> Vec<&IssuedCertificate> {
        self.issued
            .values()
            .filter(|issued| issued.validity().not_after() < issuance_timing.new_child_cert_issuance_threshold())
            .collect()
    }

    pub fn overclaiming(&self, resources: &ResourceSet) -> Vec<&IssuedCertificate> {
        self.issued
            .values()
            .filter(|issued| !resources.contains(issued.resources()))
            .collect()
    }
}
