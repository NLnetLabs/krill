//! Managing child CAs.

use std::collections::HashMap;
use rpki::ca::provisioning::ResourceClassName;
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use serde::{Deserialize, Serialize};
use crate::commons::KrillResult;
use crate::commons::crypto::{KrillSigner, SignSupport};
use crate::commons::error::Error;
use crate::daemon::config::IssuanceTimingConfig;
use crate::commons::api::ca::{
    ChildCaInfo, ChildState, IdCertInfo, IssuedCertificate, ReceivedCert,
    SuspendedCert, UnsuspendedCert,
};


//------------ UsedKeyState --------------------------------------------------

/// Tracks the state of a key used by a child CA.
///
/// This is needed because RFC 6492 dictates that keys cannot be re-used
/// across resource classes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum UsedKeyState {
    /// The key is used by the given resource class.
    ///
    /// Multiple keys are possible during a key rollover.
    #[serde(alias = "current")]
    InUse(ResourceClassName),

    /// The key has been revoked.
    Revoked,
}


//------------ ChildInfo -----------------------------------------------------

/// Information about a child CA needed by a parent CA.
///
/// Note that the actual [`IssuedCert`] corresponding to the [`KeyIdentifier`]
/// and [`ResourceClassName`] are kept in the parent's resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildDetails {
    /// The state of the child.
    #[serde(default)]
    pub state: ChildState,

    /// The ID certificate to communicate with the child CA.
    pub id_cert: IdCertInfo,

    /// The resources the child CA is entitled to.
    pub resources: ResourceSet,

    /// The set of keys used by the child.
    pub used_keys: HashMap<KeyIdentifier, UsedKeyState>,

    /// Mapping of the resource class names used by the child to the parents.
    ///
    /// Parent and child usually use the same name, but
    /// we need this mapping in case a delegated child CA was exported
    /// somewhere and then imported into Krill. In such cases the
    /// resource class names that were used for the child may not match
    /// the internal resource class names used. See issue: 1133
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rcn_map: HashMap<ResourceClassName, ResourceClassName>,
}

impl ChildDetails {
    /// Creates the child details from the ID certificate and resources.
    ///
    /// Sets the state to active and both the used keys and RCN map to empty.
    pub fn new(id_cert: IdCertInfo, resources: ResourceSet) -> Self {
        ChildDetails {
            state: ChildState::Active,
            id_cert,
            resources,
            used_keys: HashMap::new(),
            rcn_map: HashMap::new(),
        }
    }

    /// Returns the child info for this child.
    pub fn to_info(&self) -> ChildCaInfo {
        ChildCaInfo {
            state: self.state,
            id_cert: self.id_cert.clone(),
            entitled_resources: self.resources.clone(),
        }
    }

    /// Convert the internal resource class name to that used by the parent.
    ///
    /// The method takes the resource class name used internally and returns
    /// the name to be used when talking to the parent. If the internal name
    /// is part of the `rcn_map`, this name is used. Otherwise the internal
    /// name is also the parent name.
    pub fn name_for_parent_rcn(
        &self, name_in_parent: &ResourceClassName,
    ) -> ResourceClassName {
        self.rcn_map.get(name_in_parent).unwrap_or(name_in_parent).clone()
    }

    /// Convert the parent’s resource class name to that used internally.
    ///
    /// The method thakes the resource class name as used by the parent and
    /// returns the name we use internally. If the parent name is part of the
    /// `rcn_map`, this name is used. Otherwise the parent name is also the
    /// internal name.
    pub fn parent_name_for_rcn(
        &self,
        name_in_child: &ResourceClassName,
    ) -> ResourceClassName {
        self.rcn_map.iter()
            .find(|(_k, v)| *v == name_in_child)
            .map(|(k, _v)| k.clone())
            .unwrap_or_else(|| name_in_child.clone())
    }

    /// Returns all keys that ae issued for the given parent resource class.
    pub fn issued(
        &self,
        parent_rcn: &ResourceClassName,
    ) -> Vec<KeyIdentifier> {
        let mut res = vec![];

        for (ki, used_key_state) in self.used_keys.iter() {
            if let UsedKeyState::InUse(found_rcn) = used_key_state {
                if found_rcn == parent_rcn {
                    res.push(*ki)
                }
            }
        }

        res
    }

    /// Returns whether the given key is currently issued.
    pub fn is_issued(&self, ki: &KeyIdentifier) -> bool {
        matches!(self.used_keys.get(ki), Some(UsedKeyState::InUse(_)))
    }

    /// Returns an error in case the key is already in use in another class.
    pub fn verify_key_allowed(
        &self,
        ki: &KeyIdentifier,
        parent_rcn: &ResourceClassName,
    ) -> KrillResult<()> {
        if let Some(last_response) = self.used_keys.get(ki) {
            let allowed = match last_response {
                UsedKeyState::Revoked => false,
                UsedKeyState::InUse(found) => found == parent_rcn,
            };
            if !allowed {
                return Err(Error::KeyUseAttemptReuse);
            }
        }
        Ok(())
    }
}


//------------ ChildCertificates -------------------------------------------

/// The collection of certificates issued under a resource class.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificates {
    #[serde(alias = "inner")]
    // Note: we cannot remove this unless we migrate existing json on
    // upgrade.
    issued: HashMap<KeyIdentifier, IssuedCertificate>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
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

    pub fn get_issued(
        &self,
        ki: &KeyIdentifier,
    ) -> Option<&IssuedCertificate> {
        self.issued.get(ki)
    }

    pub fn get_suspended(
        &self,
        ki: &KeyIdentifier,
    ) -> Option<&SuspendedCert> {
        self.suspended.get(ki)
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
            updates.issue(self.re_issue(
                issued,
                None,
                signing_cert,
                issuance_timing,
                signer,
            )?);
        }
        // Also re-issue suspended certificates, they may yet become
        // unsuspended at some point
        for suspended in self.suspended.values() {
            updates.suspend(
                self.re_issue(
                    &suspended.to_converted(),
                    None,
                    signing_cert,
                    issuance_timing,
                    signer,
                )?
                .into_converted(),
            );
        }
        Ok(updates)
    }

    /// Shrink any overclaiming certificates.
    ///
    /// NOTE: We need to pro-actively shrink child certificates to avoid
    /// invalidating them.       But, if we gain additional resources it
    /// is up to child to request a new certificate       with those
    /// resources.
    pub fn shrink_overclaiming(
        &self,
        received_cert: &ReceivedCert,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ChildCertificateUpdates> {
        let mut updates = ChildCertificateUpdates::default();

        let updated_resources = &received_cert.resources;

        for issued in self.issued.values() {
            if let Some(reduced_set) =
                issued.reduced_applicable_resources(updated_resources)
            {
                if reduced_set.is_empty() {
                    // revoke
                    updates.remove(issued.key_identifier());
                } else {
                    // re-issue
                    updates.issue(self.re_issue(
                        issued,
                        Some(reduced_set),
                        received_cert,
                        issuance_timing,
                        signer,
                    )?);
                }
            }
        }

        // Also shrink suspended, in case they would come back
        for suspended in self.suspended.values() {
            if let Some(reduced_set) =
                suspended.reduced_applicable_resources(updated_resources)
            {
                if reduced_set.is_empty() {
                    // revoke
                    updates.remove(suspended.key_identifier());
                } else {
                    // re-issue shrunk suspended
                    //
                    // Note: this will not be published yet, but remain
                    // suspended       until the child
                    // contacts us again, or is manually
                    //       un-suspended.
                    updates.suspend(
                        self.re_issue(
                            &suspended.to_converted(),
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
        let csr_info = previous.csr_info.clone();
        let resource_set =
            updated_resources.unwrap_or_else(|| previous.resources.clone());
        let limit = previous.limit.clone();

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
}


//------------ ChildCertificateUpdates -------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificateUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issued: Vec<IssuedCertificate>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<KeyIdentifier>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suspended: Vec<SuspendedCert>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unsuspended: Vec<UnsuspendedCert>,
}

impl ChildCertificateUpdates {
    pub fn new(
        issued: Vec<IssuedCertificate>,
        removed: Vec<KeyIdentifier>,
        suspended: Vec<SuspendedCert>,
        unsuspended: Vec<UnsuspendedCert>,
    ) -> Self {
        ChildCertificateUpdates {
            issued,
            removed,
            suspended,
            unsuspended,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.issued.is_empty()
            && self.removed.is_empty()
            && self.suspended.is_empty()
            && self.unsuspended.is_empty()
    }

    /// Add an issued certificate to the current set of issued certificates.
    /// Note that this is typically a newly issued certificate, but it can
    /// also be a previously issued certificate which had been suspended and
    /// is now unsuspended.
    pub fn issue(&mut self, new: IssuedCertificate) {
        self.issued.push(new);
    }

    /// Remove certificates for a key identifier. This will ensure that they
    /// are revoked.
    pub fn remove(&mut self, ki: KeyIdentifier) {
        self.removed.push(ki);
    }

    /// List all currently issued (not suspended) certificates.
    pub fn issued(&self) -> &Vec<IssuedCertificate> {
        &self.issued
    }

    /// List all removals (revocations).
    pub fn removed(&self) -> &Vec<KeyIdentifier> {
        &self.removed
    }

    /// Suspend a certificate
    pub fn suspend(&mut self, suspended_cert: SuspendedCert) {
        self.suspended.push(suspended_cert);
    }

    /// List all suspended certificates in this update.
    pub fn suspended(&self) -> &Vec<SuspendedCert> {
        &self.suspended
    }

    /// Unsuspend a certificate
    pub fn unsuspend(&mut self, unsuspended_cert: UnsuspendedCert) {
        self.unsuspended.push(unsuspended_cert);
    }

    /// List all unsuspended certificates in this update.
    pub fn unsuspended(&self) -> &Vec<UnsuspendedCert> {
        &self.unsuspended
    }

    pub fn unpack(
        self,
    ) -> (
        Vec<IssuedCertificate>,
        Vec<KeyIdentifier>,
        Vec<SuspendedCert>,
        Vec<UnsuspendedCert>,
    ) {
        (self.issued, self.removed, self.suspended, self.unsuspended)
    }
}

