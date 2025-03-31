//! Resource classes of a CA.

use chrono::Duration;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use rpki::ca::idexchange::{CaHandle, ParentHandle, RepoInfo};
use rpki::ca::provisioning::{
    IssuanceRequest, RequestResourceLimit, ResourceClassEntitlements,
    ResourceClassName, RevocationRequest,
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::cert::Cert;
use rpki::repository::resources::ResourceSet;
use rpki::repository::x509::{Time, Validity};
use crate::api::ca::{
    IssuedCertificate, ReceivedCert, ResourceClassInfo, SuspendedCert,
    UnsuspendedCert,
};
use crate::api::roa::{RoaConfiguration, RoaInfo}; 
use crate::commons::KrillResult;
use crate::commons::crypto::{CsrInfo, KrillSigner, SignSupport};
use crate::commons::error::{Error, KrillError};
use crate::config::{Config, IssuanceTimingConfig};
use super::aspa::{AspaDefinitions, AspaObjects, AspaObjectsUpdates};
use super::bgpsec::{
    BgpSecCertificates, BgpSecCertificateUpdates, BgpSecDefinitions
};
use super::child::ChildCertificates;
use super::events::{CertAuthEvent};
use super::keys::{CertifiedKey, CurrentKey, KeyState, OldKey, PendingKey};
use super::roa::{Roas, RoaUpdates, Routes};


//------------ ResourceClass -----------------------------------------------

/// A resource class of a CA.
///
/// A CA may have multiple parents, e.g. two RIRs, and it may not get all its
/// resource entitlements in one set, but in a number of so-called "resource
/// classes".
///
/// Each ResourceClass has a namespace, which can be anything, but for Krill
/// is based on the name of the parent ca, and the name of the resource class
/// under that parent.
///
/// Furthermore a resource class manages the key life cycle, and certificates
/// for each key, as well as objects that need to be issued by the 'current'
/// key for this class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClass {
    /// The name of the resource class.
    name: ResourceClassName,

    /// The name space of the resource class.
    name_space: String,

    /// The handle of the parent CA for this resource class.
    parent_handle: ParentHandle,

    /// The resource class name at the parent CA for this resource class.
    parent_rc_name: ResourceClassName,

    /// The payload of the ROAs held by this resource class.
    #[serde(skip_serializing_if = "Roas::is_empty", default)]
    roas: Roas,

    /// The payload of the ASPA objects held by this resource class.
    #[serde(skip_serializing_if = "AspaObjects::is_empty", default)]
    aspas: AspaObjects,

    /// The BGPsec certificates held by this resource class.
    #[serde(skip_serializing_if = "BgpSecCertificates::is_empty", default)]
    bgpsec_certificates: BgpSecCertificates,

    /// The child certificates held by this resource class.
    #[serde(skip_serializing_if = "ChildCertificates::is_empty", default)]
    certificates: ChildCertificates,

    /// The last time we changed our own CA key.
    last_key_change: Time,

    /// The current CA keys and certificates for this resource class.
    ///
    /// This value also holds the resources this resource class is entitled
    /// to through the issued certificate of the currently active key (if
    /// there is one).
    key_state: KeyState,
}

/// # Creating new instances
impl ResourceClass {
    /// Creates a new resource class with a single pending key only.
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

    /* Unused but maybe we need it later again?
    pub fn for_ta(
        parent_rc_name: ResourceClassName,
        pending_key: KeyIdentifier,
    ) -> Self {
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
    */
}

/// # Data Access
impl ResourceClass {
    /// Returns the name of the parent for this resource class.
    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }

    /// Returns the name that the parent uses for this resource class.
    pub fn parent_rc_name(&self) -> &ResourceClassName {
        &self.parent_rc_name
    }

    /// Returns the current CA certificate, if there is any
    pub fn current_certificate(&self) -> Option<&ReceivedCert> {
        self.current_key().map(|k| k.incoming_cert())
    }

    /// Returns the current resources for this resource class
    pub fn current_resources(&self) -> Option<&ResourceSet> {
        self.current_certificate().map(|c| &c.resources)
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

    /// Returns the current key or errors out.
    pub fn get_current_key(&self) -> KrillResult<&CurrentKey> {
        self.current_key().ok_or(Error::KeyUseNoCurrentKey)
    }

    /// Returns whether a key roll can be started now.
    pub fn key_roll_possible(&self) -> bool {
        matches!(&self.key_state, KeyState::Active(_))
    }

    /// Returns information about this resource class.
    pub fn to_info(&self) -> ResourceClassInfo {
        ResourceClassInfo {
            name_space: self.name_space.clone(),
            parent_handle: self.parent_handle.clone(),
            keys: self.key_state.to_info(),
        }
    }
}

/// # Support repository migrations
impl ResourceClass {
    /// Sets the old repo for use during a repository migration.
    pub fn set_old_repo(&mut self, repo: RepoInfo) {
        self.key_state.set_old_repo_if_in_active_state(repo);
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Returns event details for receiving the certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn process_received_cert(
        &self,
        handle: &CaHandle,
        rcvd_cert: ReceivedCert,
        all_routes: &Routes,
        all_aspas: &AspaDefinitions,
        all_bgpsecs: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        // If this is for a pending key, then we need to promote this key

        let rcvd_cert_ki = rcvd_cert.key_identifier();

        match &self.key_state {
            KeyState::Pending(pending) => {
                if rcvd_cert_ki != pending.key_id() {
                    return Err(Error::KeyUseNoMatch(rcvd_cert_ki))
                }
                self.process_rcvd_cert_pending(
                    handle, rcvd_cert, all_routes, all_aspas, all_bgpsecs,
                    config, signer
                )
            }
            KeyState::Active(current) => {
                self.process_rcvd_cert_current(
                    handle, current, rcvd_cert,
                    all_routes, all_aspas, all_bgpsecs,
                    config, signer,
                )
            }
            KeyState::RollPending(pending, current) => {
                if rcvd_cert_ki == pending.key_id() {
                    let new_key = CertifiedKey::create(rcvd_cert);
                    Ok(vec![CertAuthEvent::KeyPendingToNew {
                        resource_class_name: self.name.clone(),
                        new_key,
                    }])
                }
                else {
                    self.process_rcvd_cert_current(
                        handle, current, rcvd_cert,
                        all_routes, all_aspas, all_bgpsecs,
                        config, signer,
                    )
                }
            }
            KeyState::RollNew(new, current) => {
                if rcvd_cert_ki == new.key_id() {
                    Ok(vec![CertAuthEvent::CertificateReceived {
                        resource_class_name: self.name.clone(),
                        ki: rcvd_cert_ki,
                        rcvd_cert,
                    }])
                }
                else {
                    self.process_rcvd_cert_current(
                        handle, current, rcvd_cert,
                        all_routes, all_aspas, all_bgpsecs,
                        config, signer,
                    )
                }
            }
            KeyState::RollOld(current, _old) => {
                // We will never request a new certificate for an old key
                self.process_rcvd_cert_current(
                    handle, current, rcvd_cert,
                    all_routes, all_aspas, all_bgpsecs,
                    config, signer,
                )
            }
        }
    }

    /// Processes having received the first certificate for this class.
    #[allow(clippy::too_many_arguments)]
    fn process_rcvd_cert_pending(
        &self,
        handle: &CaHandle,
        rcvd_cert: ReceivedCert,
        all_routes: &Routes,
        all_aspas: &AspaDefinitions,
        all_bgpsecs: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        info!(
            "Received certificate for CA '{}' under RC '{}', with resources: \
             '{}' valid until: '{}'",
            handle,
            self.name,
            rcvd_cert.resources,
            rcvd_cert.validity.not_after().to_rfc3339()
        );

        let current_key = CertifiedKey::create(rcvd_cert);

        let roa_updates = self.roas.create_updates(
            all_routes,
            &current_key,
            config,
            signer,
        )?;
        let aspa_updates = self.aspas.create_updates(
            all_aspas,
            &current_key,
            config,
            signer,
        )?;
        let bgpsec_updates
            = self.bgpsec_certificates.create_updates(
                all_bgpsecs,
                &current_key,
                config,
                signer,
            )?;

        let mut events =
            vec![CertAuthEvent::KeyPendingToActive {
                resource_class_name: self.name.clone(),
                current_key,
            }];

        if !roa_updates.is_empty() {
            events.push(CertAuthEvent::RoasUpdated {
                resource_class_name: self.name.clone(),
                updates: roa_updates,
            })
        }

        if !aspa_updates.is_empty() {
            events.push(CertAuthEvent::AspaObjectsUpdated {
                resource_class_name: self.name.clone(),
                updates: aspa_updates,
            })
        }

        if !bgpsec_updates.is_empty() {
            events.push(
                CertAuthEvent::BgpSecCertificatesUpdated {
                    resource_class_name: self.name.clone(),
                    updates: bgpsec_updates,
                },
            )
        }

        Ok(events)
    }

    /// Processes having received a new certificate for the current key.
    #[allow(clippy::too_many_arguments)]
    fn process_rcvd_cert_current(
        &self,
        handle: &CaHandle,
        current_key: &CurrentKey,
        rcvd_cert: ReceivedCert,
        all_routes: &Routes,
        all_aspas: &AspaDefinitions,
        all_bgpsecs: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let ki = rcvd_cert.key_identifier();
        if ki != current_key.key_id() {
            return Err(KrillError::KeyUseNoMatch(ki));
        }

        let rcvd_resources = &rcvd_cert.resources;

        let mut res = vec![CertAuthEvent::CertificateReceived {
            resource_class_name: self.name.clone(),
            ki,
            rcvd_cert: rcvd_cert.clone(),
        }];

        let rcvd_resources_diff = rcvd_resources.difference(
            &current_key.incoming_cert().resources
        );

        if !rcvd_resources_diff.is_empty() {
            info!(
                "Received new certificate under CA '{}' under RC '{}' with \
                 changed resources: '{}', valid until: {}",
                handle,
                self.name,
                rcvd_resources_diff,
                rcvd_cert.validity.not_after().to_rfc3339()
            );

            // Prep certified key for updated received certificate
            let updated_key = CertifiedKey::create(rcvd_cert);

            // Shrink any overclaiming child certificates
            let updates = self.certificates.shrink_overclaiming(
                updated_key.incoming_cert(),
                &config.issuance_timing,
                signer,
            )?;
            if !updates.is_empty() {
                res.push(CertAuthEvent::ChildCertificatesUpdated {
                    resource_class_name: self.name.clone(),
                    updates,
                });
            }

            // Re-issue ROAs based on updated resources.
            // Note that route definitions will not have changed in this case,
            // but the decision logic is all the same.
            {
                let updates = self.roas.create_updates(
                    all_routes,
                    &updated_key,
                    config,
                    signer,
                )?;
                if !updates.is_empty() {
                    res.push(CertAuthEvent::RoasUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    });
                }
            }

            // Re-issue ASPA objects based on updated resources.
            // Note that aspa definitions will not have changed in this case,
            // but the decision logic is all the same.
            {
                let updates = self.aspas.create_updates(
                    all_aspas,
                    &updated_key,
                    config,
                    signer,
                )?;
                if !updates.is_empty() {
                    res.push(CertAuthEvent::AspaObjectsUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    })
                }
            }

            // Re-issue BGPSec certificates based on updated resources.
            // Note that definitions will not have changed in this case, but
            // the decision logic is all the same.
            {
                let updates = self.bgpsec_certificates.create_updates(
                    all_bgpsecs,
                    &updated_key,
                    config,
                    signer,
                )?;
                if !updates.is_empty() {
                    res.push(CertAuthEvent::BgpSecCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates,
                    })
                }
            }
        }
        else {
            info!(
                "Received new certificate for CA '{}' under RC '{}', \
                 valid until: {}",
                handle,
                self.name,
                rcvd_cert.validity.not_after().to_rfc3339()
            )
        }

        Ok(res)
    }

    /// Appends events for requesting certificates for any key that needs it.
    ///
    /// Also creates revocation events for any unexpected keys to recover from
    /// issues where the parent believes we have keys that we do not know.
    /// This can happen in corner cases where re-initialization of Krill
    /// as a child is done without proper revocation at the parent, or as
    /// is the case with ARIN - Krill is sometimes told to just drop all
    /// resources.
    pub fn append_entitlement_events(
        &self,
        handle: &CaHandle,
        entitlement: &ResourceClassEntitlements,
        base_repo: &RepoInfo,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<()> {
        self.key_state.append_entitlement_events(
            handle,
            self.name.clone(),
            entitlement,
            base_repo,
            &self.name_space,
            signer,
            events,
        )
    }

    /// Returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        self.key_state.cert_requests()
    }

    /// Returns the revocation request for the old key, if it exists.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        self.key_state.revoke_request()
    }

    /// Returns whether we currently pending parent requests.
    pub fn has_pending_requests(&self) -> bool {
        !self.cert_requests().is_empty() || self.revoke_request().is_some()
    }
}

/// # Removing a resource class
///
impl ResourceClass {
    /// Returns revocation requests for all certified keys in this class.
    pub fn revoke(
        &self,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<RevocationRequest>> {
        self.key_state.revoke(self.parent_rc_name.clone(), signer)
    }
}

/// # Key Life Cycle
///
impl ResourceClass {
    /// Appends the events to initiate a key roll.
    pub fn append_keyroll_initiate(
        &self,
        base_repo: &RepoInfo,
        duration: Duration,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<bool> {
        if duration > Duration::seconds(0)
            && self.last_key_change + duration > Time::now()
        {
            return Ok(false);
        }

        self.key_state.append_keyroll_initiate(
            self.name.clone(),
            self.parent_rc_name.clone(),
            base_repo,
            &self.name_space,
            signer,
            events,
        )
    }

    /// Appends the events to activate a new key.
    ///
    /// This will only happen if it's been longer than the staging period.
    pub fn append_keyroll_activate(
        &self,
        staging_time: Duration,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<bool> {
        if let Some(new_key) = self.key_state.new_key() {
            if staging_time > Duration::seconds(0)
                && self.last_key_change + staging_time > Time::now()
            {
                Ok(false)
            }
            else {
                self.key_state.append_keyroll_activate(
                    self.name.clone(),
                    self.parent_rc_name.clone(),
                    signer,
                    events,
                )?;

                let roa_updates = self.roas.create_renewal(
                    true,
                    new_key,
                    issuance_timing,
                    signer,
                )?;
                if !roa_updates.is_empty() {
                    events.push(CertAuthEvent::RoasUpdated {
                        resource_class_name: self.name.clone(),
                        updates: roa_updates,
                    });
                }

                let aspa_updates = self.aspas.create_renewal(
                    new_key,
                    None,
                    issuance_timing,
                    signer,
                )?;
                if !aspa_updates.is_empty() {
                    events.push(CertAuthEvent::AspaObjectsUpdated {
                        resource_class_name: self.name.clone(),
                        updates: aspa_updates,
                    })
                }

                let cert_updates = self.certificates.activate_key(
                    new_key.incoming_cert(),
                    issuance_timing,
                    signer,
                )?;
                if !cert_updates.is_empty() {
                    events.push(CertAuthEvent::ChildCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates: cert_updates,
                    });
                }

                let bgpsec_updates = self.bgpsec_certificates.create_renewal(
                    new_key,
                    None,
                    issuance_timing,
                    signer,
                )?;
                if !bgpsec_updates.is_empty() {
                    events.push(CertAuthEvent::BgpSecCertificatesUpdated {
                        resource_class_name: self.name.clone(),
                        updates: bgpsec_updates,
                    });
                }

                Ok(true)
            }
        }
        else {
            Ok(false)
        }
    }

    /// Finish a key roll, withdraw the old key
    pub fn process_keyroll_finish(&self) -> KrillResult<CertAuthEvent> {
        match &self.key_state {
            KeyState::RollOld(_current, _old) => {
                Ok(CertAuthEvent::KeyRollFinished {
                    resource_class_name: self.name.clone(),
                })
            }
            _ => Err(Error::KeyUseNoOldKey),
        }
    }
}

/// # Issuing certificates
///
impl ResourceClass {
    /// Makes a single child certificate and wraps it in an issuance response.
    ///
    /// Will use the intersection of the requested child resources, and the
    /// resources actually held by the this resource class. An error will be
    /// returned if a ResourceRequestLimit was used that includes resources
    /// that are not in this intersection.
    ///
    /// Note that this certificate still needs to be added to this resource
    /// class through a command.
    pub fn issue_cert(
        &self,
        csr: CsrInfo,
        child_resources: &ResourceSet,
        limit: RequestResourceLimit,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCertificate> {
        let signing_cert = self.get_current_key()?.incoming_cert();
        let parent_resources = &signing_cert.resources;
        let resources = parent_resources.intersection(child_resources);

        let issued = SignSupport::make_issued_cert(
            csr,
            &resources,
            limit,
            signing_cert,
            issuance_timing.new_child_cert_validity(),
            signer,
        )?;

        Ok(issued)
    }

    /// Returns an issued certificate for a key, if it exists
    pub fn issued(&self, ki: &KeyIdentifier) -> Option<&IssuedCertificate> {
        self.certificates.get_issued(ki)
    }

    /// Returns a suspended certificate for a key, if it exists
    pub fn suspended(&self, ki: &KeyIdentifier) -> Option<&SuspendedCert> {
        self.certificates.get_suspended(ki)
    }
}

/// # ROAs
///
impl ResourceClass {
    /// Returns the ROA updates to match the given ROA definition.
    pub fn create_roa_updates(
        &self,
        routes: &Routes,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        if let Ok(key) = self.get_current_key() {
            let resources = &key.incoming_cert().resources;
            let routes = routes.filter(resources);
            self.roas.create_updates(&routes, key, config, signer)
        }
        else {
            debug!("no ROAs to update - resource class has no current key");
            Ok(RoaUpdates::default())
        }
    }

    /// Returns the ROA updates that renews ROAs.
    ///
    /// If `force` is `true`, all ROAs will be renewed, otherwise only those
    /// that are close to expire.
    pub fn create_roa_renewal(
        &self,
        force: bool,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.roas.create_renewal(force, key, issuance_timing, signer)
        }
        else {
            debug!("no ROAs to renew - resource class has no current key");
            Ok(RoaUpdates::default())
        }
    }

    /// Finds all matching ROA infos for the given configuration.
    pub fn matching_roa_infos(
        &self,
        config: &RoaConfiguration,
    ) -> Vec<RoaInfo> {
        self.roas.matching_roa_infos(config)
    }
}

/// # ASPA objects
///
impl ResourceClass {
    /// Returns the ASPA updates to match the given ASPA definition.
    pub fn create_aspa_updates(
        &self,
        all_aspas: &AspaDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.aspas.create_updates(all_aspas, key, config, signer)
        }
        else {
            debug!("no ASPAs to update - resource class has no current key");
            Ok(AspaObjectsUpdates::default())
        }
    }

    /// Returns the updates necessary to renew ASPA objects.
    pub fn create_aspa_renewal(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        if let Ok(key) = self.get_current_key() {
            let renew_threshold =
                Some(issuance_timing.new_aspa_issuance_threshold());
            self.aspas.create_renewal(
                key, renew_threshold, issuance_timing, signer
            )
        }
        else {
            debug!("no ASPAs to renew - resource class has no current key");
            Ok(AspaObjectsUpdates::default())
        }
    }
}

/// # BGPsec router keys
///
impl ResourceClass {
    /// Returns the updates to match the given BGPsec definition.
    pub fn create_bgpsec_updates(
        &self,
        definitions: &BgpSecDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        if let Ok(key) = self.get_current_key() {
            self.bgpsec_certificates
                .create_updates(definitions, key, config, signer)
        }
        else {
            debug!(
                "no BGPsec certificates to update - \
                 resource class has no current key"
            );
            Ok(BgpSecCertificateUpdates::default())
        }
    }

    /// Returns the updates necessary to renew BGPsec certificate.
    pub fn create_bgpsec_renewal(
        &self,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        if let Ok(key) = self.get_current_key() {
            let renew_threshold = Some(
                issuance_timing.new_bgpsec_issuance_threshold()
            );

            self.bgpsec_certificates.create_renewal(
                key,
                renew_threshold,
                issuance_timing,
                signer,
            )
        }
        else {
            debug!(
                "no BGPSec certificates to renew - \
                 resource class has no current key"
            );
            Ok(BgpSecCertificateUpdates::default())
        }
    }
}

/// # Resource Tagged Attestations (RTA)
impl ResourceClass {
    /// Create an EE certificate to be used on an RTA.
    ///
    /// Returns an error if there is no overlap in resources between the
    /// desired resources on the RTA and this desource class‘ current
    /// resources.
    pub fn create_rta_ee(
        &self,
        resources: &ResourceSet,
        validity: Validity,
        key: KeyIdentifier,
        signer: &KrillSigner,
    ) -> KrillResult<Cert> {
        let current = self.current_key().ok_or_else(|| {
            Error::custom("No current key to sign RTA with")
        })?;

        if !current.incoming_cert().resources.contains(resources) {
            return Err(Error::custom("Resources for RTA not held"));
        }

        let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
        let ee = SignSupport::make_rta_ee_cert(
            resources,
            current.incoming_cert(), &current.key_id(),
            validity, pub_key, signer,
        )?;

        Ok(ee)
    }
}


/// # Applying events
///
/// The methods in this section should be the only methods manipulating
/// the resource class. They all start with `apply_` to make their function
/// clear.
impl ResourceClass {
    /// Adds a issuance request to an existing key for future reference.
    pub fn apply_issuance_request(
        &mut self,
        key_id: KeyIdentifier,
        req: IssuanceRequest,
    ) {
        self.key_state.apply_issuance_request(key_id, req);
    }

    /// Marks a certificate as received.
    //
    //  XXX PANICS
    pub fn apply_received_cert(
        &mut self,
        key_id: KeyIdentifier,
        cert: ReceivedCert,
    ) {
        match &mut self.key_state {
            KeyState::Pending(_pending) => {
                panic!("Would have received KeyPendingToActive event")
            }
            KeyState::Active(current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollPending(_pending, current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollNew(new, current) => {
                if new.key_id() == key_id {
                    new.set_incoming_cert(cert);
                }
                else {
                    current.set_incoming_cert(cert);
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id() == key_id {
                    current.set_incoming_cert(cert);
                }
                else {
                    old.set_incoming_cert(cert);
                }
            }
        }
    }

    /// Adds a pending key.
    //
    //  XXX PANICS
    pub fn apply_pending_key_id_added(&mut self, key_id: KeyIdentifier) {
        match &self.key_state {
            KeyState::Active(current) => {
                let pending = PendingKey::new(key_id);
                self.key_state =
                    KeyState::RollPending(pending, current.clone())
            }
            _ => panic!(
                "Should never create event to add key when roll in progress"
            ),
        }
    }

    /// Moves a pending key to new
    //
    //  XXX PANICS
    pub fn apply_pending_key_to_new(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::RollPending(_pending, current) => {
                self.key_state = KeyState::RollNew(new, current.clone());
            }
            _ => panic!(
                "Cannot move pending to new, if state is not roll pending"
            ),
        }
    }

    /// Moves a pending key to current
    //
    //  XXX PANICS
    pub fn apply_pending_key_to_active(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::Pending(_pending) => {
                self.key_state = KeyState::Active(new);
            }
            _ => panic!(
                "Cannot move pending to active, if state is not pending"
            ),
        }
    }

    /// Activates the new key
    //
    //  XXX PANICS
    pub fn apply_new_key_activated(&mut self, revoke_req: RevocationRequest) {
        match &self.key_state {
            KeyState::RollNew(new, current) => {
                let old_key = OldKey::new(current.clone(), revoke_req);
                self.key_state = KeyState::RollOld(new.clone(), old_key);
            }
            _ => panic!(
                "Should never create event to activate key when \
                no roll in progress"
            ),
        }
    }

    /// Removes the old key.
    ///
    /// We return the to the state where there is one active key.
    //
    //  XXX PANICS
    pub fn apply_old_key_removed(&mut self) {
        match &self.key_state {
            KeyState::RollOld(current, _old) => {
                self.key_state = KeyState::Active(current.clone());
            }
            _ => panic!(
                "Should never create event to remove old key, when \
                there is none"
            ),
        }
    }

    /// Adds an issued certificate.
    pub fn apply_added_issued_certificate(
        &mut self, issued: IssuedCertificate
    ) {
        self.certificates.add_issued_certificate(issued);
    }

    /// Unsuspends the given certificate.
    pub fn apply_unsuspend_certificate(
        &mut self, unsuspended: UnsuspendedCert
    ) {
        self.certificates.unsuspend_certificate(unsuspended);
    }

    pub fn apply_suspend_certificate(&mut self, suspended: SuspendedCert) {
        self.certificates.suspend_certificate(suspended);
    }

    /// Removes a revoked key.
    pub fn apply_removed_revoked_key(&mut self, key: &KeyIdentifier) {
        self.certificates.remove_revoked_key(key);
    }

    /// Applies the given ROA updates.
    pub fn apply_roa_updates(&mut self, updates: RoaUpdates) {
        self.roas.apply_updates(updates);
    }

    /// Apply ASPA object changes from events
    pub fn apply_aspa_updates(&mut self, updates: AspaObjectsUpdates) {
        self.aspas.apply_updates(updates)
    }

    /// Apply BGPSec Certificate changes from events
    pub fn apply_bgpsec_updates(
        &mut self, updates: BgpSecCertificateUpdates,
    ) {
        self.bgpsec_certificates.apply_updates(updates)
    }
}


//------------ DropReason ----------------------------------------------------

pub type DropReason = String;

