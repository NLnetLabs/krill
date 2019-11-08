use std::collections::HashMap;

use chrono::Duration;

use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::{ChildCaInfo, ChildHandle, IssuedCert, ResourceClassName, ResourceSet};
use crate::commons::remote::id::IdCert;
use crate::constants::CHILD_CERTIFICATE_REISSUE_WEEKS;
use crate::daemon::ca;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum LastResponse {
    Current(ResourceClassName),
    Revoked,
}

impl LastResponse {}

//------------ ChildInfo ---------------------------------------------------

/// Contains information about a child CA needed by a parent [CertAuth](ca.CertAuth).
///
/// Note that the actual [IssuedCert] corresponding to the [KeyIdentifier]
/// and [ResourceClassName] are kept in the parent's [ResourceClass].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    pub fn issued(&self, rcn: &ResourceClassName) -> Vec<KeyIdentifier> {
        let mut res = vec![];

        for (ki, last_response) in self.used_keys.iter() {
            if let LastResponse::Current(found_rcn) = last_response {
                if found_rcn == rcn {
                    res.push(*ki)
                }
            }
        }

        res
    }

    pub fn is_issued(&self, ki: &KeyIdentifier) -> bool {
        if let Some(LastResponse::Current(_)) = self.used_keys.get(ki) {
            true
        } else {
            false
        }
    }

    pub fn add_issue_response(&mut self, rcn: ResourceClassName, ki: KeyIdentifier) {
        self.used_keys.insert(ki, LastResponse::Current(rcn));
    }

    pub fn add_revoke_response(&mut self, ki: KeyIdentifier) {
        self.used_keys.insert(ki, LastResponse::Revoked);
    }

    /// Returns an error in case the key is already in use in another class.
    pub fn verify_key_allowed(
        &self,
        ki: &KeyIdentifier,
        rcn: &ResourceClassName,
    ) -> ca::Result<()> {
        if let Some(last_response) = self.used_keys.get(ki) {
            let allowed = match last_response {
                LastResponse::Revoked => false,
                LastResponse::Current(found) => found == rcn,
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
        ChildCaInfo::new(self.id_cert, self.resources)
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
    inner: HashMap<KeyIdentifier, IssuedCert>,
}

impl ChildCertificates {
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

    pub fn expiring(&self) -> Vec<&IssuedCert> {
        self.inner
            .values()
            .filter(|issued| {
                issued.validity().not_after()
                    < Time::now() + Duration::weeks(CHILD_CERTIFICATE_REISSUE_WEEKS)
            })
            .collect()
    }

    pub fn overclaiming(&self, resources: &ResourceSet) -> Vec<&IssuedCert> {
        self.inner
            .values()
            .filter(|issued| !resources.contains(issued.resource_set()))
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IssuedCert> {
        self.inner.values()
    }
}

impl Default for ChildCertificates {
    fn default() -> Self {
        ChildCertificates {
            inner: HashMap::new(),
        }
    }
}
