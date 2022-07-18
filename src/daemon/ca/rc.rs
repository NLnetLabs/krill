use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::{
    ca::{
        idexchange::{CaHandle, ParentHandle, RepoInfo},
        provisioning::{
            IssuanceRequest, RequestResourceLimit, ResourceClassEntitlements, ResourceClassName, RevocationRequest,
        },
    },
    crypto::KeyIdentifier,
    repository::{
        cert::Cert,
        resources::ResourceSet,
        x509::{Time, Validity},
    },
};

use crate::{
    commons::{
        api::{DelegatedCertificate, ReceivedCert, ResourceClassInfo, SuspendedCert, UnsuspendedCert},
        crypto::{CsrInfo, KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::events::RoaUpdates,
        ca::{
            self, ta_handle, AspaObjects, AspaObjectsUpdates, CaEvtDet, CertifiedKey, ChildCertificates, CurrentKey,
            KeyState, NewKey, OldKey, PendingKey, Roas, Routes,
        },
        config::{Config, IssuanceTimingConfig},
    },
};

use super::{AspaDefinitions, BgpSecCertificateUpdates, BgpSecCertificates, BgpSecDefinitions};

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

    #[serde(skip_serializing_if = "Roas::is_empty", default)]
    roas: Roas,

    #[serde(skip_serializing_if = "AspaObjects::is_empty", default)]
    aspas: AspaObjects,

    #[serde(skip_serializing_if = "BgpSecCertificates::is_empty", default)]
    bgpsec_certificates: BgpSecCertificates,

    #[serde(skip_serializing_if = "ChildCertificates::is_empty", default)]
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
            aspas: AspaObjects::default(),
            certificates: ChildCertificates::default(),
            bgpsec_certificates: BgpSecCertificates::default(),
            last_key_change: Time::now(),
            key_state: KeyState::create(pending_key),
        }
    }

    pub fn for_ta(parent_rc_name: ResourceClassName, pending_key: KeyIdentifier) -> Self {
        ResourceClass {
            name: parent_rc_name.clone(),
            name_space: parent_rc_name.to_string(),
            parent_handle: ta_handle().into_converted(),
            parent_rc_name,
            roas: Roas::default(),
            aspas: AspaObjects::default(),
            certificates: ChildCertificates::default(),
            bgpsec_certificates: BgpSecCertificates::default(),
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
    pub fn current_certificate(&self) -> Option<&ReceivedCert> {
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
    pub fn set_old_repo(&mut self, repo: RepoInfo) {
        self.key_state.set_old_repo_if_in_active_state(repo);
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Returns event details for receiving the certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn update_received_cert(
        &self,
        handle: &CaHandle,
        rcvd_cert: ReceivedCert,
        all_routes: &Routes,
        all_aspas: &AspaDefinitions,
        all_bgpsecs: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        // If this is for a pending key, then we need to promote this key

        let rcvd_cert_ki = rcvd_cert.key_identifier();

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

                    let roa_updates = self.roas.update(all_routes, &current_key, config, signer)?;
                    let aspa_updates = self.aspas.update(all_aspas, &current_key, config, signer)?;
                    let bgpsec_updates = self
                        .bgpsec_certificates
                        .update(all_bgpsecs, &current_key, config, signer)?;

                    let mut events = vec![CaEvtDet::KeyPendingToActive {
                        resource_class_name: self.name.clone(),
                        current_key,
                    }];

                    if roa_updates.contains_changes() {
                        events.push(CaEvtDet::RoasUpdated {
                            resource_class_name: self.name.clone(),
                            updates: roa_updates,
                        })
                    }

                    if aspa_updates.contains_changes() {
                        events.push(CaEvtDet::AspaObjectsUpdated {
                            resource_class_name: self.name.clone(),
                            updates: aspa_updates,
                        })
                    }

                    if bgpsec_updates.contains_changes() {
                        events.push(CaEvtDet::BgpSecCertificatesUpdated {
                            resource_class_name: self.name.clone(),
                            updates: bgpsec_updates,
                        })
                    }

                    Ok(events)
                }
            }
            KeyState::Active(current) => self.update_rcvd_cert_current(
                handle,
                current,
                rcvd_cert,
                all_routes,
                all_aspas,
                all_bgpsecs,
                config,
                signer,
            ),
            KeyState::RollPending(pending, current) => {
                if rcvd_cert_ki == pending.key_id() {
                    let new_key = CertifiedKey::create(rcvd_cert);
                    Ok(vec![CaEvtDet::KeyPendingToNew {
                        resource_class_name: self.name.clone(),
                        new_key,
                    }])
                } else {
                    self.update_rcvd_cert_current(
                        handle,
                        current,
                        rcvd_cert,
                        all_routes,
                        all_aspas,
                        all_bgpsecs,
                        config,
                        signer,
                    )
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
                    self.update_rcvd_cert_current(
                        handle,
                        current,
                        rcvd_cert,
                        all_routes,
                        all_aspas,
                        all_bgpsecs,
                        config,
                        signer,
                    )
                }
            }
            KeyState::RollOld(current, _old) => {
                // We will never request a new certificate for an old key
                self.update_rcvd_cert_current(
                    handle,
                    current,
                    rcvd_cert,
                    all_routes,
                    all_aspas,
                    all_bgpsecs,
                    config,
                    signer,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_rcvd_cert_current(
        &self,
        handle: &CaHandle,
        current_key: &CurrentKey,
        rcvd_cert: ReceivedCert,
        all_routes: &Routes,
        all_aspas: &AspaDefinitions,
        all_bgpsecs: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let ki = rcvd_cert.key_identifier();
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

            // Prep certified key for updated received certificate
            let updated_key = CertifiedKey::create(rcvd_cert);

            // Shrink any overclaiming child certificates
            let updates = self
                .certificates
                .shrink_overclaiming(&updated_key, &config.issuance_timing, signer)?;
            if !updates.is_empty() {
                res.push(CaEvtDet::ChildCertificatesUpdated {
                    resource_class_name: self.name.clone(),
                    updates,
                });
            }

            // Re-issue ROAs based on updated resources.
            // Note that route definitions will not have changed in this case, but the decision logic is all the same.
            {
                let updates = self.roas.update(all_routes, &updated_key, config, signer)?;
                if !updates.is_empty() {
                    res.push(CaEvtDet::RoasUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    });
                }
            }

            // Re-issue ASPA objects based on updated resources.
            // Note that aspa definitions will not have changed in this case, but the decision logic is all the same.
            {
                let updates = self.aspas.update(all_aspas, &updated_key, config, signer)?;
                if !updates.is_empty() {
                    res.push(CaEvtDet::AspaObjectsUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    })
                }
            }

            // Re-issue BGPSec certificates based on updated resources.
            // Note that definitions will not have changed in this case, but the decision logic is all the same.
            {
                let updates = self
                    .bgpsec_certificates
                    .update(all_bgpsecs, &updated_key, config, signer)?;
                if !updates.is_empty() {
                    res.push(CaEvtDet::BgpSecCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    })
                }
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
        handle: &CaHandle,
        entitlement: &ResourceClassEntitlements,
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
    pub fn received_cert(&mut self, key_id: KeyIdentifier, cert: ReceivedCert) {
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

                let mut events = vec![key_activated];

                let roa_updates = self.roas.renew(true, new_key, issuance_timing, signer)?;
                if !roa_updates.is_empty() {
                    let roas_updated = CaEvtDet::RoasUpdated {
                        resource_class_name: self.name.clone(),
                        updates: roa_updates,
                    };
                    events.push(roas_updated);
                }

                let aspa_updates = self.aspas.renew(new_key, None, issuance_timing, signer)?;
                if !aspa_updates.is_empty() {
                    let aspas_updated = CaEvtDet::AspaObjectsUpdated {
                        resource_class_name: self.name.clone(),
                        updates: aspa_updates,
                    };
                    events.push(aspas_updated);
                }

                let cert_updates = self.certificates.activate_key(new_key, issuance_timing, signer)?;
                if !cert_updates.is_empty() {
                    let certs_updated = CaEvtDet::ChildCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates: cert_updates,
                    };
                    events.push(certs_updated);
                }

                let bgpsec_updates = self.bgpsec_certificates.renew(new_key, None, issuance_timing, signer)?;
                if !bgpsec_updates.is_empty() {
                    events.push(CaEvtDet::BgpSecCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates: bgpsec_updates,
                    });
                }

                Ok(events)
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
    ) -> KrillResult<DelegatedCertificate> {
        let signing_key = self.get_current_key()?;
        let parent_resources = signing_key.incoming_cert().resources();
        let resources = parent_resources.intersection(child_resources);

        let issued = SignSupport::make_issued_cert(
            csr,
            &resources,
            limit,
            signing_key,
            issuance_timing.timing_child_certificate_valid_weeks,
            signer,
        )?;

        Ok(issued)
    }

    /// Stores an [IssuedCert](krill_commons.api.ca.IssuedCert)
    pub fn certificate_issued(&mut self, issued: DelegatedCertificate) {
        self.certificates.certificate_issued(issued);
    }

    pub fn certificate_unsuspended(&mut self, unsuspended: UnsuspendedCert) {
        self.certificates.certificate_unsuspended(unsuspended);
    }

    pub fn certificate_suspended(&mut self, suspended: SuspendedCert) {
        self.certificates.certificate_suspended(suspended);
    }

    /// Returns an issued certificate for a key, if it exists
    pub fn delegated(&self, ki: &KeyIdentifier) -> Option<&DelegatedCertificate> {
        self.certificates.get_issued(ki)
    }

    /// Returns a suspended certificate for a key, if it exists
    pub fn suspended(&self, ki: &KeyIdentifier) -> Option<&SuspendedCert> {
        self.certificates.get_suspended(ki)
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
    pub fn renew_roas(
        &self,
        force: bool,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.roas.renew(force, key, issuance_timing, signer)
        } else {
            debug!("no ROAs to renew - resource class has no current key");
            Ok(RoaUpdates::default())
        }
    }

    /// Publish all ROAs under the new key
    pub fn active_key_roas(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let key = self.get_new_key()?;
        self.roas.renew(true, key, issuance_timing, signer)
    }

    /// Updates the ROAs in accordance with the current authorizations
    pub fn update_roas(&self, routes: &Routes, config: &Config, signer: &KrillSigner) -> KrillResult<RoaUpdates> {
        if let Ok(key) = self.get_current_key() {
            let resources = key.incoming_cert().resources();
            let routes = routes.filter(resources);
            self.roas.update(&routes, key, config, signer)
        } else {
            debug!("no ROAs to update - resource class has no current key");
            Ok(RoaUpdates::default())
        }
    }

    /// Marks the ROAs as updated from a RoaUpdated event.
    pub fn roas_updated(&mut self, updates: RoaUpdates) {
        self.roas.updated(updates);
    }
}

/// # Autonomous System Provider Authorization
///
impl ResourceClass {
    /// Renew all ASPA objects under the current for which the not-after time
    /// is closer than the given number of weeks
    pub fn renew_aspas(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        if let Ok(key) = self.get_current_key() {
            let renew_threshold = Some(Time::now() + Duration::weeks(issuance_timing.timing_aspa_reissue_weeks_before));
            self.aspas.renew(key, renew_threshold, issuance_timing, signer)
        } else {
            debug!("no ASPAs to renew - resource class has no current key");
            Ok(AspaObjectsUpdates::default())
        }
    }

    /// Updates the ASPA objects in accordance with the supplied definitions
    pub fn update_aspas(
        &self,
        all_aspas: &AspaDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.aspas.update(all_aspas, key, config, signer)
        } else {
            debug!("no ASPAs to update - resource class has no current key");
            Ok(AspaObjectsUpdates::default())
        }
    }

    /// Apply ASPA object changes from events
    pub fn aspa_objects_updated(&mut self, updates: AspaObjectsUpdates) {
        self.aspas.updated(updates)
    }
}

/// # BGPSec
///
impl ResourceClass {
    /// Updates the BGPSec certificates in accordance with the supplied definitions
    /// and the resources (still) held in this resource class
    pub fn update_bgpsec_certs(
        &self,
        definitions: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.bgpsec_certificates.update(definitions, key, config, signer)
        } else {
            debug!("no BGPSec certificates to update - resource class has no current key");
            Ok(BgpSecCertificateUpdates::default())
        }
    }

    /// Renew BGPSec certificates that would expire otherwise.
    pub fn renew_bgpsec_certs(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        if let Ok(key) = self.get_current_key() {
            let renew_threshold =
                Some(Time::now() + Duration::weeks(issuance_timing.timing_bgpsec_reissue_weeks_before));

            self.bgpsec_certificates
                .renew(key, renew_threshold, issuance_timing, signer)
        } else {
            debug!("no BGPSec certificates to renew - resource class has no current key");
            Ok(BgpSecCertificateUpdates::default())
        }
    }

    /// Apply BGPSec Certificate changes from events
    pub fn bgpsec_certificates_updated(&mut self, updates: BgpSecCertificateUpdates) {
        self.bgpsec_certificates.updated(updates)
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
        let ee = SignSupport::make_rta_ee_cert(resources, current, validity, pub_key, signer)?;

        Ok(ee)
    }
}
