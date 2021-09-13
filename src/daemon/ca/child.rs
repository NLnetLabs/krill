use std::collections::HashMap;

use chrono::Duration;

use rpki::repository::{crypto::KeyIdentifier, x509::Time};

use crate::{
    commons::{
        api::{
            ChildCaInfo, ChildHandle, ChildState, IssuedCert, ResourceClassName, ResourceSet, SuspendedCert,
            UnsuspendedCert,
        },
        crypto::IdCert,
        error::Error,
        KrillResult,
    },
    daemon::config::IssuanceTimingConfig,
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
    id_cert: IdCert,
    resources: ResourceSet,
    used_keys: HashMap<KeyIdentifier, UsedKeyState>,
}

impl ChildDetails {
    pub fn new(id_cert: IdCert, resources: ResourceSet) -> Self {
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

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn set_id_cert(&mut self, id_cert: IdCert) {
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
        ChildCaInfo::new(details.state, (&details.id_cert).into(), details.resources)
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificates {
    #[serde(alias = "inner")] // Note: we cannot remove this unless we migrate existing json on upgrade.
    issued: HashMap<KeyIdentifier, IssuedCert>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    suspended: HashMap<KeyIdentifier, SuspendedCert>,
}

impl ChildCertificates {
    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        let ki = issued.cert().subject_key_identifier();
        self.issued.insert(ki, issued);
    }

    pub fn certificate_unsuspended(&mut self, issued: UnsuspendedCert) {
        let ki = issued.cert().subject_key_identifier();
        self.suspended.remove(&ki);
        self.issued.insert(ki, issued);
    }

    pub fn certificate_suspended(&mut self, suspended: SuspendedCert) {
        let ki = suspended.cert().subject_key_identifier();
        self.issued.remove(&ki);
        self.suspended.insert(ki, suspended);
    }

    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.issued.remove(key);
        self.suspended.remove(key);
    }

    pub fn get_issued(&self, ki: &KeyIdentifier) -> Option<&IssuedCert> {
        self.issued.get(ki)
    }

    pub fn get_suspended(&self, ki: &KeyIdentifier) -> Option<&SuspendedCert> {
        self.suspended.get(ki)
    }

    pub fn current(&self) -> impl Iterator<Item = &IssuedCert> {
        self.issued.values()
    }

    pub fn expiring(&self, issuance_timing: &IssuanceTimingConfig) -> Vec<&IssuedCert> {
        self.issued
            .values()
            .filter(|issued| {
                issued.validity().not_after()
                    < Time::now() + Duration::weeks(issuance_timing.timing_child_certificate_reissue_weeks_before)
            })
            .collect()
    }

    pub fn overclaiming(&self, resources: &ResourceSet) -> Vec<&IssuedCert> {
        self.issued
            .values()
            .filter(|issued| !resources.contains(issued.resource_set()))
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IssuedCert> {
        self.issued.values()
    }
}

impl Default for ChildCertificates {
    fn default() -> Self {
        ChildCertificates {
            issued: HashMap::new(),
            suspended: HashMap::new(),
        }
    }
}
