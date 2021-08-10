use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::repository::{
    cert::Cert,
    crypto::KeyIdentifier,
    x509::{Time, Validity},
};

use crate::{
    commons::{
        api::{
            EntitlementClass, Handle, HexEncodedHash, IssuanceRequest, IssuedCert, ParentHandle, RcvdCert,
            ReplacedObject, RepoInfo, RequestResourceLimit, ResourceClassInfo, ResourceClassName, ResourceSet,
            Revocation, RevocationRequest,
        },
        crypto::{CsrInfo, KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::events::{ChildCertificateUpdates, RoaUpdates},
        ca::{
            self, ta_handle, CaEvtDet, CertifiedKey, ChildCertificates, CurrentKey, KeyState, NewKey, OldKey,
            PendingKey, Roas, Routes,
        },
        config::{Config, IssuanceTimingConfig},
    },
};

//------------ ResourceClass -----------------------------------------------

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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClass {
    name: ResourceClassName,
    name_space: String,

    parent_handle: ParentHandle,
    parent_rc_name: ResourceClassName,

    roas: Roas,
    certificates: ChildCertificates,

    last_key_change: Time,
    key_state: KeyState,
}

/// # Creating new instances
///
impl ResourceClass {
    /// Creates a new ResourceClass with a single pending key only.
    pub fn create(
        name: ResourceClassName,
        name_space: String,
        parent_handle: ParentHandle,
        parent_rc_name: ResourceClassName,
        pending_key: KeyIdentifier,
    ) -> Self {
        ResourceClass {
            name,
            name_space,
            parent_handle,
            parent_rc_name,
            roas: Roas::default(),
            certificates: ChildCertificates::default(),
            last_key_change: Time::now(),
            key_state: KeyState::create(pending_key),
        }
    }

    pub fn for_ta(parent_rc_name: ResourceClassName, pending_key: KeyIdentifier) -> Self {
        ResourceClass {
            name: parent_rc_name.clone(),
            name_space: parent_rc_name.to_string(),
            parent_handle: ta_handle(),
            parent_rc_name,
            roas: Roas::default(),
            certificates: ChildCertificates::default(),
            last_key_change: Time::now(),
            key_state: KeyState::create(pending_key),
        }
    }
}

/// # Data Access
///
impl ResourceClass {
    pub fn name_space(&self) -> &str {
        &self.name_space
    }

    /// Returns the name of the parent where we got this RC from.
    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }

    /// Returns the name that the parent uses for this RC.
    pub fn parent_rc_name(&self) -> &ResourceClassName {
        &self.parent_rc_name
    }

    /// Adds a request to an existing key for future reference.
    pub fn add_request(&mut self, key_id: KeyIdentifier, req: IssuanceRequest) {
        self.key_state.add_request(key_id, req);
    }

    /// Returns the current certificate, if there is any
    pub fn current_certificate(&self) -> Option<&RcvdCert> {
        self.current_key().map(|k| k.incoming_cert())
    }

    /// Returns the current resources for this resource class
    pub fn current_resources(&self) -> Option<&ResourceSet> {
        self.current_certificate().map(|c| c.resources())
    }

    /// Returns a reference to current key for this RC, if there is any.
    pub fn current_key(&self) -> Option<&CurrentKey> {
        match &self.key_state {
            KeyState::Active(current)
            | KeyState::RollPending(_, current)
            | KeyState::RollNew(_, current)
            | KeyState::RollOld(current, _) => Some(current),
            _ => None,
        }
    }

    pub fn get_current_key(&self) -> KrillResult<&CurrentKey> {
        self.current_key().ok_or(Error::KeyUseNoCurrentKey)
    }

    pub fn key_roll_possible(&self) -> bool {
        matches!(&self.key_state, KeyState::Active(_))
    }

    /// Gets the new key for a key roll, or returns an error if there is none.
    pub fn get_new_key(&self) -> KrillResult<&NewKey> {
        if let KeyState::RollNew(new_key, _) = &self.key_state {
            Ok(new_key)
        } else {
            Err(Error::KeyUseNoNewKey)
        }
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behavior.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(
            self.name_space.clone(),
            self.parent_handle.clone(),
            self.key_state.as_info(),
        )
    }
}

/// # Support repository migrations
///
impl ResourceClass {
    pub fn set_old_repo(&mut self, repo: &RepoInfo) {
        self.key_state.set_old_repo_if_in_active_state(repo);
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Returns event details for receiving the certificate.
    pub fn update_received_cert(
        &self,
        handle: &Handle,
        rcvd_cert: RcvdCert,
        routes: &Routes,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        // If this is for a pending key, then we need to promote this key

        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();

        match &self.key_state {
            KeyState::Pending(pending) => {
                if rcvd_cert_ki != pending.key_id() {
                    Err(Error::KeyUseNoMatch(rcvd_cert_ki))
                } else {
                    info!(
                        "Received certificate for CA '{}' under RC '{}', with resources: '{}' valid until: '{}'",
                        handle,
                        self.name,
                        rcvd_cert.resources(),
                        rcvd_cert.validity().not_after().to_rfc3339()
                    );

                    let current_key = CertifiedKey::create(rcvd_cert);
                    
                    let updates = self.roas.update(routes, &current_key, config, signer)?;

                    let mut events = vec![
                        CaEvtDet::KeyPendingToActive {
                            resource_class_name: self.name.clone(),
                            current_key,
                        }
                    ];

                    if updates.contains_changes() {
                        events.push(CaEvtDet::RoasUpdated {
                            resource_class_name: self.name.clone(),
                            updates,
                        })
                    }

                    Ok(events)
                }
            }
            KeyState::Active(current) => {
                self.update_rcvd_cert_current(handle, current, rcvd_cert, routes, config, signer)
            }
            KeyState::RollPending(pending, current) => {
                if rcvd_cert_ki == pending.key_id() {
                    let new_key = CertifiedKey::create(rcvd_cert);
                    Ok(vec![CaEvtDet::KeyPendingToNew {
                        resource_class_name: self.name.clone(),
                        new_key,
                    }])
                } else {
                    self.update_rcvd_cert_current(handle, current, rcvd_cert, routes, config, signer)
                }
            }
            KeyState::RollNew(new, current) => {
                if rcvd_cert_ki == new.key_id() {
                    Ok(vec![CaEvtDet::CertificateReceived {
                        resource_class_name: self.name.clone(),
                        ki: rcvd_cert_ki,
                        rcvd_cert,
                    }])
                } else {
                    self.update_rcvd_cert_current(handle, current, rcvd_cert, routes, config, signer)
                }
            }
            KeyState::RollOld(current, _old) => {
                // We will never request a new certificate for an old key
                self.update_rcvd_cert_current(handle, current, rcvd_cert, routes, config, signer)
            }
        }
    }

    fn update_rcvd_cert_current(
        &self,
        handle: &Handle,
        current_key: &CurrentKey,
        rcvd_cert: RcvdCert,
        routes: &Routes,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let ki = rcvd_cert.cert().subject_key_identifier();
        if ki != current_key.key_id() {
            return Err(ca::Error::KeyUseNoMatch(ki));
        }

        let rcvd_resources = rcvd_cert.resources();

        let mut res = vec![CaEvtDet::CertificateReceived {
            resource_class_name: self.name.clone(),
            ki,
            rcvd_cert: rcvd_cert.clone(),
        }];

        let rcvd_resources_diff = rcvd_resources.difference(current_key.incoming_cert().resources());

        if !rcvd_resources_diff.is_empty() {
            info!(
                "Received new certificate under CA '{}' under RC '{}' with changed resources: '{}', valid until: {}",
                handle,
                self.name,
                rcvd_resources_diff,
                rcvd_cert.validity().not_after().to_rfc3339()
            );

            // Check whether child certificates should be shrunk
            //
            // NOTE: We need to pro-actively shrink child certificates to avoid invalidating them.
            //       But, if we gain additional resources it is up to child to request a new certificate
            //       with those resources.
            //
            let mut updates = ChildCertificateUpdates::default();
            for issued in self.certificates.overclaiming(rcvd_resources) {
                let remaining_resources = issued.resource_set().intersection(rcvd_resources);
                if remaining_resources.is_empty() {
                    // revoke
                    updates.remove(issued.subject_key_identifier());
                } else {
                    // re-issue
                    let re_issued = self.re_issue(
                        issued,
                        Some(remaining_resources),
                        current_key,
                        None,
                        &config.issuance_timing,
                        signer,
                    )?;
                    updates.issue(re_issued);
                }
            }
            if !updates.is_empty() {
                res.push(CaEvtDet::ChildCertificatesUpdated {
                    resource_class_name: self.name.clone(),
                    updates,
                });
            }

            // Check whether ROAs need to be re-issued.
            let updated_key = CertifiedKey::create(rcvd_cert);
            let updates = self.roas.update(routes, &updated_key, config, signer)?;
            if !updates.is_empty() {
                res.push(CaEvtDet::RoasUpdated {
                    resource_class_name: self.name.clone(),
                    updates,
                });
            }
        } else {
            info!(
                "Received new certificate for CA '{}' under RC '{}', valid until: {}",
                handle,
                self.name,
                rcvd_cert.validity().not_after().to_rfc3339()
            )
        }

        Ok(res)
    }

    /// Request certificates for any key that needs it.
    /// Also, create revocation events for any unexpected keys to recover from
    /// issues where the parent believes we have keys that we do not know. This
    /// can happen in corner cases where re-initialization of Krill as a child
    /// is done without proper revocation at the parent, or as is the case with
    /// ARIN - Krill is sometimes told to just drop all resources.
    pub fn make_entitlement_events(
        &self,
        handle: &Handle,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        self.key_state.make_entitlement_events(
            handle,
            self.name.clone(),
            entitlement,
            base_repo,
            &self.name_space,
            signer,
        )
    }

    /// Request new certificates for all keys when the base repo changes.
    pub fn make_request_events_new_repo(
        &self,
        base_repo: &RepoInfo,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        self.key_state
            .request_certs_new_repo(self.name.clone(), base_repo, &self.name_space, signer)
    }

    /// This function returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        self.key_state.cert_requests()
    }

    /// Returns the revocation request for the old key, if it exists.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        self.key_state.revoke_request()
    }

    pub fn has_pending_requests(&self) -> bool {
        !self.cert_requests().is_empty() || self.revoke_request().is_some()
    }
}

/// # Removing a resource class
///
impl ResourceClass {
    /// Returns revocation requests for all certified keys in this resource class.
    pub fn revoke(&self, signer: &KrillSigner) -> KrillResult<Vec<RevocationRequest>> {
        self.key_state.revoke(self.parent_rc_name.clone(), signer)
    }
}

/// # Key Life Cycle and Receiving Certificates
///
impl ResourceClass {
    /// This function marks a certificate as received.
    pub fn received_cert(&mut self, key_id: KeyIdentifier, cert: RcvdCert) {
        // if there is a pending key, then we need to do some promotions..
        match &mut self.key_state {
            KeyState::Pending(_pending) => panic!("Would have received KeyPendingToActive event"),
            KeyState::Active(current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollPending(_pending, current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.set_incoming_cert(cert);
                } else {
                    current.set_incoming_cert(cert);
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.set_incoming_cert(cert);
                } else {
                    old.set_incoming_cert(cert);
                }
            }
        }
    }

    /// Adds a pending key.
    pub fn pending_key_id_added(&mut self, key_id: KeyIdentifier) {
        match &self.key_state {
            KeyState::Active(current) => {
                let pending = PendingKey::new(key_id);
                self.key_state = KeyState::RollPending(pending, current.clone())
            }
            _ => panic!("Should never create event to add key when roll in progress"),
        }
    }

    /// Moves a pending key to new
    pub fn pending_key_to_new(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::RollPending(_pending, current) => {
                self.key_state = KeyState::RollNew(new, current.clone());
            }
            _ => panic!("Cannot move pending to new, if state is not roll pending"),
        }
    }

    /// Moves a pending key to current
    pub fn pending_key_to_active(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::Pending(_pending) => {
                self.key_state = KeyState::Active(new);
            }
            _ => panic!("Cannot move pending to active, if state is not pending"),
        }
    }

    /// Activates the new key
    pub fn new_key_activated(&mut self, revoke_req: RevocationRequest) {
        match &self.key_state {
            KeyState::RollNew(new, current) => {
                let old_key = OldKey::new(current.clone(), revoke_req);
                self.key_state = KeyState::RollOld(new.clone(), old_key);
            }
            _ => panic!("Should never create event to activate key when no roll in progress"),
        }
    }

    /// Removes the old key, we return the to the state where there is one active key.
    pub fn old_key_removed(&mut self) {
        match &self.key_state {
            KeyState::RollOld(current, _old) => {
                self.key_state = KeyState::Active(current.clone());
            }
            _ => panic!("Should never create event to remove old key, when there is none"),
        }
    }

    /// Initiate a key roll
    pub fn keyroll_initiate(
        &self,
        base_repo: &RepoInfo,
        duration: Duration,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        if duration > Duration::seconds(0) && self.last_key_change + duration > Time::now() {
            return Ok(vec![]);
        }

        self.key_state.keyroll_initiate(
            self.name.clone(),
            self.parent_rc_name.clone(),
            base_repo,
            &self.name_space,
            signer,
        )
    }

    /// Activate a new key, if it's been longer than the staging period.
    pub fn keyroll_activate(
        &self,
        staging_time: Duration,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        if let Some(new_key) = self.key_state.new_key() {
            if staging_time > Duration::seconds(0) && self.last_key_change + staging_time > Time::now() {
                Ok(vec![])
            } else {
                let key_activated =
                    self.key_state
                        .keyroll_activate(self.name.clone(), self.parent_rc_name.clone(), signer)?;

                let roa_updates = self.roas.activate_key(new_key, issuance_timing, signer)?;
                let roas_updated = CaEvtDet::RoasUpdated {
                    resource_class_name: self.name.clone(),
                    updates: roa_updates,
                };

                let mut cert_updates = ChildCertificateUpdates::default();
                for issued in self.certificates.iter() {
                    // re-issue
                    let re_issued = self.re_issue(issued, None, new_key, None, issuance_timing, signer)?;
                    cert_updates.issue(re_issued);
                }
                let certs_updated = CaEvtDet::ChildCertificatesUpdated {
                    resource_class_name: self.name.clone(),
                    updates: cert_updates,
                };

                Ok(vec![key_activated, roas_updated, certs_updated])
            }
        } else {
            Ok(vec![])
        }
    }

    /// Finish a key roll, withdraw the old key
    pub fn keyroll_finish(&self) -> KrillResult<CaEvtDet> {
        match &self.key_state {
            KeyState::RollOld(_current, _old) => Ok(CaEvtDet::KeyRollFinished {
                resource_class_name: self.name.clone(),
            }),
            _ => Err(Error::KeyUseNoOldKey),
        }
    }
}

/// # Issuing certificates
///
impl ResourceClass {
    /// Makes a single CA certificate and wraps it in an issuance response.
    ///
    /// Will use the intersection of the requested child resources, and the
    /// resources actually held by the this resource class. An error will be
    /// returned if a ResourceRequestLimit was used that includes resources
    /// that are not in this intersection.
    ///
    /// Note that this certificate still needs to be added to this RC by
    /// calling the update_certs function.
    pub fn issue_cert(
        &self,
        csr: CsrInfo,
        child_resources: &ResourceSet,
        limit: RequestResourceLimit,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCert> {
        let signing_key = self.get_current_key()?;
        let parent_resources = signing_key.incoming_cert().resources();
        let resources = parent_resources.intersection(child_resources);
        let replaces = self.certificates.get(&csr.key_id()).map(ReplacedObject::from);

        let issued = SignSupport::make_issued_cert(
            csr,
            &resources,
            limit,
            replaces,
            signing_key,
            issuance_timing.timing_child_certificate_valid_weeks,
            signer,
        )?;

        Ok(issued)
    }

    fn re_issue(
        &self,
        previous: &IssuedCert,
        updated_resources: Option<ResourceSet>,
        signing_key: &CertifiedKey,
        csr_info_opt: Option<CsrInfo>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCert> {
        let (_uri, limit, resource_set, cert) = previous.clone().unpack();
        let csr = csr_info_opt.unwrap_or_else(|| CsrInfo::from(&cert));
        let resource_set = updated_resources.unwrap_or(resource_set);
        let replaced = ReplacedObject::new(Revocation::from(&cert), HexEncodedHash::from(&cert));

        let re_issued = SignSupport::make_issued_cert(
            csr,
            &resource_set,
            limit,
            Some(replaced),
            signing_key,
            issuance_timing.timing_child_certificate_valid_weeks,
            signer,
        )?;

        Ok(re_issued)
    }

    /// Stores an [IssuedCert](krill_commons.api.ca.IssuedCert)
    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.certificates.certificate_issued(issued);
    }

    /// Returns an issued certificate for a key, if it exists
    pub fn issued(&self, ki: &KeyIdentifier) -> Option<&IssuedCert> {
        self.certificates.get(ki)
    }

    /// Removes a revoked key.
    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.certificates.key_revoked(key);
    }
}

/// # ROAs
///
impl ResourceClass {
    /// Renew all ROAs under the current for which the not-after time closer
    /// than the given number of weeks
    pub fn renew_roas(&self, issuance_timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<RoaUpdates> {
        let key = self.get_current_key()?;
        self.roas.renew(key, issuance_timing, signer)
    }

    /// Publish all ROAs under the new key
    pub fn active_key_roas(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let key = self.get_new_key()?;
        self.roas.activate_key(key, issuance_timing, signer)
    }

    /// Updates the ROAs in accordance with the current authorizations, and
    /// the target resources and key determined by the PublishMode.
    pub fn update_roas(
        &self,
        routes: &Routes,
        new_resources: Option<&ResourceSet>,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let key = self.get_current_key()?;
        let resources = new_resources.unwrap_or_else(|| key.incoming_cert().resources());
        let routes = routes.filter(resources);
        self.roas.update(&routes, key, config, signer)
    }

    /// Marks the ROAs as updated from a RoaUpdated event.
    pub fn roas_updated(&mut self, updates: RoaUpdates) {
        self.roas.updated(updates);
    }
}

/// # Resource Tagged Attestations (RTA)
///
impl ResourceClass {
    /// Create an EE certificate to be used on an RTA,
    /// returns None if there is no overlap in resources
    /// between the desired resources on the RTA and this
    /// ResourceClass current resources.
    pub fn create_rta_ee(
        &self,
        resources: &ResourceSet,
        validity: Validity,
        key: KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<Cert> {
        let current = self
            .current_key()
            .ok_or_else(|| Error::custom("No current key to sign RTA with"))?;

        if !current.incoming_cert().resources().contains(resources) {
            return Err(Error::custom("Resources for RTA not held"));
        }

        let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
        let ee = SignSupport::make_rta_ee_cert(resources, &current, validity, pub_key, signer)?;

        Ok(ee)
    }
}
