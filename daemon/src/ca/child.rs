use std::collections::HashMap;

use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use krill_commons::api::{
    ChildCaInfo, IssuanceResponse, IssuedCert, ResourceClassName, ResourceSet, RevocationResponse,
};
use krill_commons::remote::id::IdCert;

use crate::ca;
use crate::ca::ChildHandle;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum LastResponse {
    Issuance(IssuanceResponse),
    Revoke(RevocationResponse),
}

impl LastResponse {}

//------------ ChildInfo ---------------------------------------------------

/// Contains information about a child CA needed by a parent [CertAuth](ca.CertAuth).
///
/// Note that the actual [IssuedCert] corresponding to the [KeyIdentifier]
/// and [ResourceClassName] are kept in the parent's [ResourceClass].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChildDetails {
    id_cert: Option<IdCert>,
    resources: ResourceSet,
    shrink_pending: Option<Time>,
    used_keys: HashMap<KeyIdentifier, LastResponse>,
}

impl ChildDetails {
    pub fn new(id_cert: Option<IdCert>, resources: ResourceSet) -> Self {
        ChildDetails {
            id_cert,
            resources,
            shrink_pending: None,
            used_keys: HashMap::new(),
        }
    }

    pub fn id_cert(&self) -> Option<&IdCert> {
        self.id_cert.as_ref()
    }

    pub fn set_id_cert(&mut self, id_cert: IdCert) {
        self.id_cert = Some(id_cert);
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn set_resources(&mut self, resources: ResourceSet, grace: Time) {
        if !resources.contains(&self.resources) {
            self.shrink_pending = Some(grace);
        }

        self.resources = resources;
    }

    pub fn shrink_pending(&self) -> Option<Time> {
        self.shrink_pending
    }

    pub fn overclaims(&self) -> Vec<&IssuanceResponse> {
        let mut res = vec![];

        if let Some(pending) = self.shrink_pending {
            if pending <= Time::now() {
                for last_response in self.used_keys.values() {
                    if let LastResponse::Issuance(issuance) = last_response {
                        if !self.resources.contains(issuance.resource_set()) {
                            res.push(issuance)
                        }
                    }
                }
            }
        }

        res
    }

    pub fn issued(&self, rcn: &ResourceClassName) -> Vec<IssuedCert> {
        let mut res = vec![];

        for last_response in self.used_keys.values() {
            if let LastResponse::Issuance(issuance) = last_response {
                if issuance.class_name() == rcn {
                    res.push(issuance.issued().clone())
                }
            }
        }

        res
    }

    pub fn issuance_response(&self, ki: &KeyIdentifier) -> Option<&IssuanceResponse> {
        match self.used_keys.get(ki) {
            None => None,
            Some(last_response) => {
                if let LastResponse::Issuance(issuance) = last_response {
                    Some(issuance)
                } else {
                    None
                }
            }
        }
    }

    /// Determine the 'until' time for certificates that would be issued for this
    /// child.
    ///
    /// We issue certificates for one year, however, we do not want to re-issue
    /// every five minutes because one year from *now* is a new value any time
    /// the child CA asks.
    ///
    /// Therefore we want to use the latest not_after on any issued certificate
    /// to this child if unless it's less than 12 weeks from *now*.
    pub fn not_after(&self, rcn: &ResourceClassName) -> Time {
        let mut not_after = Time::now();

        for last_response in self.used_keys.values() {
            if let LastResponse::Issuance(issued) = last_response {
                if issued.class_name() == rcn {
                    let issued_not_after = issued.not_after();
                    if issued_not_after > not_after {
                        not_after = issued_not_after;
                    }
                }
            }
        }

        if not_after < Time::now() + chrono::Duration::weeks(12) {
            not_after = Time::next_year();
        }

        not_after
    }

    /// Sets the the status of pending_shrink to None, in case there
    /// was a pending shrink and all resources on all current certificates
    /// are contained within the entitled resources.
    fn check_pending_fulfilled(&mut self) {
        if self.shrink_pending.is_some() {
            let mut issued_resources = ResourceSet::default();
            for last_response in self.used_keys.values() {
                if let LastResponse::Issuance(issued) = last_response {
                    issued_resources = issued_resources.union(issued.resource_set());
                }
            }
            if self.resources.contains(&issued_resources) {
                self.shrink_pending = None;
            }
        }
    }

    pub fn add_issue_response(&mut self, response: IssuanceResponse) {
        let ki = response.issued().cert().subject_key_identifier();
        self.used_keys.insert(ki, LastResponse::Issuance(response));
        self.check_pending_fulfilled();
    }

    pub fn add_revoke_response(&mut self, response: RevocationResponse) {
        let ki = *response.key();
        self.used_keys.insert(ki, LastResponse::Revoke(response));
        self.check_pending_fulfilled();
    }

    /// Returns an error in case the key is already in use in another class.
    pub fn verify_key_allowed(
        &self,
        ki: &KeyIdentifier,
        rcn: &ResourceClassName,
    ) -> ca::Result<()> {
        if let Some(last_response) = self.used_keys.get(ki) {
            let allowed = match last_response {
                LastResponse::Revoke(_) => false,
                LastResponse::Issuance(res) => res.class_name() == rcn,
            };
            if !allowed {
                return Err(ca::Error::ResourceClassKeyReused);
            }
        }
        Ok(())
    }
}

impl Into<ChildCaInfo> for ChildDetails {
    fn into(self) -> ChildCaInfo {
        let mut issued_resources = ResourceSet::default();
        for last_response in self.used_keys.values() {
            if let LastResponse::Issuance(issued) = last_response {
                issued_resources = issued_resources.union(issued.resource_set());
            }
        }
        ChildCaInfo::new(self.id_cert, self.resources, issued_resources)
    }
}

//------------ Children ----------------------------------------------------

/// The collection of children under a parent [`CertAuth`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Children {
    inner: HashMap<ChildHandle, ChildDetails>,
}

//------------ Certificates ------------------------------------------------

/// The collection of certificates issued under a [ResourceClass](ca.ResourceClass).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Certificates {
    inner: HashMap<KeyIdentifier, IssuedCert>,
}

impl Certificates {
    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.inner
            .insert(issued.cert().subject_key_identifier(), issued);
    }

    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.inner.remove(key);
    }

    pub fn get(&self, ki: &KeyIdentifier) -> Option<&IssuedCert> {
        self.inner.get(ki)
    }

    pub fn current(&self) -> impl Iterator<Item = &IssuedCert> {
        self.inner.values()
    }
}

impl Default for Certificates {
    fn default() -> Self {
        Certificates {
            inner: HashMap::new(),
        }
    }
}
