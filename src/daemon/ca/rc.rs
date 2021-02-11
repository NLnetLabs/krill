use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::x509::{Time, Validity};

use crate::{
    commons::{
        api::{
            EntitlementClass, HexEncodedHash, IssuanceRequest, IssuedCert, ParentHandle, RcvdCert, ReplacedObject,
            RepoInfo, RequestResourceLimit, ResourceClassInfo, ResourceClassName, ResourceSet, Revocation,
            RevocationRequest,
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

    /// Gets the new key for a key roll, or returns an error if there is none.
    pub fn get_new_key(&self) -> KrillResult<&NewKey> {
        if let KeyState::RollNew(new_key, _) = &self.key_state {
            Ok(new_key)
        } else {
            Err(Error::KeyUseNoNewKey)
        }
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behaviour.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(
            self.name_space.clone(),
            self.parent_handle.clone(),
            self.key_state.as_info(),
        )
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Returns event details for receiving the certificate.
    pub fn update_received_cert(
        &self,
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
                    let certified_key = CertifiedKey::create(rcvd_cert);
                    Ok(vec![CaEvtDet::KeyPendingToActive(self.name.clone(), certified_key)])
                }
            }
            KeyState::Active(current) => self.update_rcvd_cert_current(current, rcvd_cert, routes, config, signer),
            KeyState::RollPending(pending, current) => {
                if rcvd_cert_ki == pending.key_id() {
                    let certified_key = CertifiedKey::create(rcvd_cert);
                    Ok(vec![CaEvtDet::KeyPendingToNew(self.name.clone(), certified_key)])
                } else {
                    self.update_rcvd_cert_current(current, rcvd_cert, routes, config, signer)
                }
            }
            KeyState::RollNew(new, current) => {
                if rcvd_cert_ki == new.key_id() {
                    Ok(vec![CaEvtDet::CertificateReceived(
                        self.name.clone(),
                        rcvd_cert_ki,
                        rcvd_cert,
                    )])
                } else {
                    self.update_rcvd_cert_current(current, rcvd_cert, routes, config, signer)
                }
            }
            KeyState::RollOld(current, _old) => {
                // We will never request a new certificate for an old key
                self.update_rcvd_cert_current(current, rcvd_cert, routes, config, signer)
            }
        }
    }

    fn update_rcvd_cert_current(
        &self,
        current_key: &CurrentKey,
        rcvd_cert: RcvdCert,
        routes: &Routes,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();
        if rcvd_cert_ki != current_key.key_id() {
            return Err(ca::Error::KeyUseNoMatch(rcvd_cert_ki));
        }

        let rcvd_resources = rcvd_cert.resources();

        let mut res = vec![];
        res.push(CaEvtDet::CertificateReceived(
            self.name.clone(),
            rcvd_cert_ki,
            rcvd_cert.clone(),
        ));

        if rcvd_resources != current_key.incoming_cert().resources() {
            debug!("Received a new certificate for resource class: {}, with resources: {}, will now re-issue certs and ROAs if needed.", self.name, rcvd_resources);
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
                res.push(CaEvtDet::ChildCertificatesUpdated(self.name.clone(), updates));
            }

            // Check whether ROAs need to be re-issued.
            let updated_key = CertifiedKey::create(rcvd_cert);
            let roa_updates = self.roas.update(routes, &updated_key, config, signer)?;
            if !roa_updates.is_empty() {
                res.push(CaEvtDet::RoasUpdated(self.name.clone(), roa_updates));
            }
        }

        Ok(res)
    }

    /// Request certificates for any key that needs it.
    /// Also, create revocation events for any unexpected keys to recover from
    /// issues where the parent believes we have keys that we do not know. This
    /// can happen in corner cases where re-initialisation of Krill as a child
    /// is done without proper revocation at the parent, or as is the case with
    /// ARIN - Krill is sometimes told to just drop all resources.
    pub fn make_entitlement_events(
        &self,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        self.key_state
            .make_entitlement_events(self.name.clone(), entitlement, base_repo, &self.name_space, signer)
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

/// # Publishing
///
impl ResourceClass {
    // #[deprecated]
    // pub fn publish_objects(
    //     &self,
    //     repo_info: &RepoInfo,
    //     objects_delta: ObjectsDelta,
    //     new_revocations: Vec<Revocation>,
    //     mode: &PublishMode,
    //     issuance_timing: &IssuanceTimingConfig,
    //     signer: &KrillSigner,
    // ) -> KrillResult<CaEvtDet> {
    // let mut key_pub_map = HashMap::new();

    // let (publish_key, other_key_opt) = match mode {
    //     PublishMode::KeyRollActivation => (self.get_new_key()?, Some(self.get_current_key()?)),
    //     _ => {
    //         let other_key_opt = match &self.key_state {
    //             KeyState::RollNew(new, _) => Some(new),
    //             KeyState::RollOld(_, old) => Some(old.key()),
    //             _ => None,
    //         };
    //         (self.get_current_key()?, other_key_opt)
    //     }
    // };

    // let (publish_key_revocations, other_key_revocations) = match mode {
    //     PublishMode::KeyRollActivation => (vec![], new_revocations),
    //     _ => (new_revocations, vec![]),
    // };

    // let publish_key_delta = self
    //     .make_current_set_delta(
    //         publish_key,
    //         objects_delta,
    //         publish_key_revocations,
    //         issuance_timing,
    //         signer,
    //     )
    //     .map_err(Error::signer)?;

    // key_pub_map.insert(*publish_key.key_id(), publish_key_delta);

    // if let Some(other_key) = other_key_opt {
    //     let ns = self.name_space();
    //     let delta = ObjectsDelta::new(repo_info.ca_repository(ns));

    //     let other_delta = self
    //         .make_current_set_delta(other_key, delta, other_key_revocations, issuance_timing, signer)
    //         .map_err(ca::Error::signer)?;

    //     key_pub_map.insert(*other_key.key_id(), other_delta);
    // }

    // Ok(CaEvtDet::ObjectSetUpdated(self.name.clone(), key_pub_map))
}

// fn needs_publication(&self, mode: &PublishMode, hours: i64) -> bool {
//     match mode {
//         PublishMode::Normal => {
//             if let Ok(key) = self.get_current_key() {
//                 key.close_to_next_update(hours)
//             } else {
//                 false
//             }
//         }
//         _ => true,
//     }
// }

// Republish all keys in this class (that want it). Also update
// ROAs as needed.
// #[deprecated]
// pub fn republish(
//     &self,
//     repo_info: &RepoInfo,
//     mode: &PublishMode,
//     config: &Config,
//     signer: &KrillSigner,
// ) -> KrillResult<Vec<CaEvtDet>> {
// let mut res = vec![];

// let ns = self.name_space();
// let mut delta = ObjectsDelta::new(repo_info.ca_repository(ns));
// let mut revocations = vec![];

// let roa_updates = match mode {
//     PublishMode::Normal => self.renew_roas(&config.issuance_timing, signer),
//     PublishMode::KeyRollActivation => self.active_key_roas(&config.issuance_timing, signer),
//     PublishMode::NewRepo(info) => self.migrate_roas(info, &config.issuance_timing, signer),
//     PublishMode::UpdatedResources(resources, routes) => {
//         self.update_roas(routes, Some(resources), config, signer)
//     }
// }?;

// if roa_updates.contains_changes() {
//     for added in roa_updates.added().into_iter() {
//         delta.add(added);
//     }
//     for update in roa_updates.updated().into_iter() {
//         delta.update(update);
//     }
//     for withdraw in roa_updates.withdrawn().into_iter() {
//         delta.withdraw(withdraw);
//     }
//     revocations.append(&mut roa_updates.revocations());

//     res.push(CaEvtDet::RoasUpdated(self.name.clone(), roa_updates));
// }

// let child_cert_updates = self.update_child_certificates(mode, &config.issuance_timing, signer)?;
// if !child_cert_updates.is_empty() {
//     for issued in child_cert_updates.issued() {
//         match issued.replaces() {
//             None => delta.add(AddedObject::from(issued.cert())),
//             Some(old) => delta.update(UpdatedObject::for_cert(issued.cert(), old.hash().clone())),
//         }
//     }
//     for key in child_cert_updates.removed() {
//         if let Some(issued) = self.certificates.get(key) {
//             delta.withdraw(WithdrawnObject::from(issued.cert()));
//             revocations.push(Revocation::from(issued.cert()));
//         }
//     }
//     res.push(CaEvtDet::ChildCertificatesUpdated(
//         self.name.clone(),
//         child_cert_updates,
//     ));
// }

// if !delta.is_empty()
//     || !revocations.is_empty()
//     || self.needs_publication(mode, config.issuance_timing.timing_publish_hours_before_next)
// {
//     res.push(self.publish_objects(&repo_info, delta, revocations, mode, &config.issuance_timing, signer)?);
// }

// Ok(res)
// }

// /// Create a publish event details including the revocations, update, withdrawals needed
// /// for updating child certificates.
// pub fn republish_certs(
//     &self,
//     issued_certs: &[&IssuedCert],
//     removed_certs: &[&Cert],
//     repo_info: &RepoInfo,
//     issuance_timing: &IssuanceTimingConfig,
//     signer: &KrillSigner,
// ) -> KrillResult<HashMap<KeyIdentifier, CurrentObjectSetDelta>> {
//     let issuing_key = self.get_current_key()?;
//     let name_space = self.name_space();

//     let mut revocations = vec![];
//     for cert in removed_certs {
//         revocations.push(Revocation::from(*cert));
//     }
//     for issued in issued_certs {
//         if let Some(replaced) = issued.replaces() {
//             revocations.push(replaced.revocation());
//         }
//     }

//     let ca_repo = repo_info.ca_repository(name_space);
//     let mut objects_delta = ObjectsDelta::new(ca_repo);

//     for removed in removed_certs {
//         objects_delta.withdraw(WithdrawnObject::from(*removed));
//     }
//     for issued in issued_certs {
//         match issued.replaces() {
//             None => objects_delta.add(AddedObject::from(issued.cert())),
//             Some(replaced) => objects_delta.update(UpdatedObject::for_cert(issued.cert(), replaced.hash().clone())),
//         }
//     }

//     let set_delta = self
//         .make_current_set_delta(issuing_key, objects_delta, revocations, issuance_timing, signer)
//         .map_err(Error::signer)?;

//     let mut res = HashMap::new();
//     res.insert(*issuing_key.key_id(), set_delta);
//     Ok(res)
// }

// fn make_current_set_delta(
//     &self,
//     signing_key: &CertifiedKey,
//     mut objects_delta: ObjectsDelta,
//     mut new_revocations: Vec<Revocation>,
//     issuance_timing: &IssuanceTimingConfig,
//     signer: &KrillSigner,
// ) -> KrillResult<CurrentObjectSetDelta> {
//     let signing_cert = signing_key.incoming_cert();
//     let current_set = signing_key.current_set();
//     let current_revocations = current_set.revocations().clone();
//     let number = current_set.number() + 1;

//     let current_mft = current_set.manifest_info();
//     let current_mft_hash = current_mft.current().to_hex_hash();
//     let current_crl = current_set.crl_info();
//     let current_crl_hash = current_crl.current().to_hex_hash();

//     new_revocations.push(Revocation::from(current_mft.current()));

//     // Create a new CRL
//     let (crl_info, revocations_delta) = CrlBuilder::build_deprecated(
//         current_revocations,
//         new_revocations,
//         number,
//         Some(current_crl_hash),
//         signing_cert,
//         issuance_timing.timing_publish_next_hours,
//         signer,
//     )?;

//     match crl_info.added_or_updated() {
//         AddedOrUpdated::Added(added) => objects_delta.add(added),
//         AddedOrUpdated::Updated(updated) => objects_delta.update(updated),
//     }

//     // For the new manifest:
//     //
//     // List all current files, i.e.
//     //  - the new CRL
//     //  - current ROAs
//     //  - current Certs
//     //  - applying the delta - which may update the current ROAs and Certs on the MFT
//     let issued = self.certificates.current();
//     let roas = self.roas.iter();

//     let manifest_info = ManifestBuilder::new(&crl_info, issued, roas, &objects_delta).build(
//         signing_cert,
//         number,
//         Some(current_mft_hash),
//         issuance_timing,
//         signer,
//     )?;

//     match manifest_info.added_or_updated() {
//         AddedOrUpdated::Added(added) => objects_delta.add(added),
//         AddedOrUpdated::Updated(updated) => objects_delta.update(updated),
//     }

//     Ok(CurrentObjectSetDelta::new(
//         number,
//         revocations_delta,
//         manifest_info,
//         crl_info,
//         objects_delta,
//     ))
// }

// pub fn all_objects(&self, base_repo: &RepoInfo) -> Vec<PublishElement> {
//     let mut res = vec![];
//     let ns = self.name_space();

//     // ROAs
//     let roas = self.roas.current_objects();
//     for p in roas.publish(base_repo, ns) {
//         res.push(p.into());
//     }

//     // Certs
//     for cert in self.certificates.current() {
//         let base64 = Base64::from_content(cert.to_captured().as_slice());
//         let uri = cert.uri().clone();
//         res.push(PublishElement::new(base64, uri));
//     }

//     // MFT and CRL for each key
//     let sets = match &self.key_state {
//         KeyState::Pending(_) => vec![],
//         KeyState::Active(current) => vec![current.current_set()],
//         KeyState::RollPending(_, current) => vec![current.current_set()],
//         KeyState::RollNew(new, current) => vec![new.current_set(), current.current_set()],
//         KeyState::RollOld(current, old) => vec![current.current_set(), old.current_set()],
//     };

//     for set in sets {
//         let crl_info = set.crl_info();
//         let crl_base64 = crl_info.current().content().clone();
//         let crl_uri = base_repo.resolve(ns, crl_info.name());
//         res.push(PublishElement::new(crl_base64, crl_uri));

//         let mft_info = set.manifest_info();
//         let mft_base64 = mft_info.current().content().clone();
//         let mft_uri = base_repo.resolve(ns, mft_info.name());
//         res.push(PublishElement::new(mft_base64, mft_uri));
//     }

//     res
// }
// }

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
    pub fn pending_key_added(&mut self, key_id: KeyIdentifier) {
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
        if self.last_key_change + duration > Time::now() {
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
    pub fn keyroll_activate(&self, staging_time: Duration, signer: &KrillSigner) -> KrillResult<Vec<CaEvtDet>> {
        if !self.key_state.has_new_key() || self.last_key_change + staging_time > Time::now() {
            return Ok(vec![]);
        }

        Ok(vec![self.key_state.keyroll_activate(
            self.name.clone(),
            self.parent_rc_name.clone(),
            signer,
        )?])
    }

    /// Finish a key roll, withdraw the old key
    pub fn keyroll_finish(&self) -> KrillResult<CaEvtDet> {
        match &self.key_state {
            KeyState::RollOld(_current, _old) => Ok(CaEvtDet::KeyRollFinished(self.name.clone())),
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

    fn update_child_certificates(
        &self,
        mode: &PublishMode,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ChildCertificateUpdates> {
        let mut updates = ChildCertificateUpdates::default();

        let signing_key = match mode {
            PublishMode::KeyRollActivation => self.get_new_key()?,
            _ => self.get_current_key()?,
        };

        match mode {
            PublishMode::Normal => {
                // re-issue: things about to expire
                // revoke: nothing
                for issued in self.certificates.expiring(issuance_timing) {
                    let re_issued = self.re_issue(issued, None, signing_key, None, issuance_timing, signer)?;
                    updates.issue(re_issued);
                }
            }
            PublishMode::UpdatedResources(resources, _) => {
                //    re-issue: overclaiming with remaining
                //    revoke: overclaiming without remaining
                for issued in self.certificates.overclaiming(resources) {
                    let remaining_resources = issued.resource_set().intersection(resources);
                    if remaining_resources.is_empty() {
                        // revoke
                        updates.remove(issued.subject_key_identifier());
                    } else {
                        // re-issue
                        let re_issued = self.re_issue(
                            issued,
                            Some(remaining_resources),
                            signing_key,
                            None,
                            issuance_timing,
                            signer,
                        )?;
                        updates.issue(re_issued);
                    }
                }
            }
            PublishMode::KeyRollActivation => {
                for issued in self.certificates.iter() {
                    let re_issued = self.re_issue(issued, None, signing_key, None, issuance_timing, signer)?;
                    updates.issue(re_issued);
                }
            }
            PublishMode::NewRepo(info) => {
                for issued in self.certificates.iter() {
                    let csr_info_update = CsrInfo::new(
                        info.ca_repository(self.name_space()),
                        info.rpki_manifest(self.name_space(), &issued.subject_key_identifier()),
                        Some(info.rpki_notify()),
                        issued.subject_public_key_info().clone(),
                    );

                    let re_issued = self.re_issue(
                        issued,
                        None,
                        signing_key,
                        Some(csr_info_update),
                        issuance_timing,
                        signer,
                    )?;
                    updates.issue(re_issued);
                }
            }
        }

        Ok(updates)
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
    /// RC's current resources.
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
//------------ PublishMode -------------------------------------------------

/// Describes which kind of publication we're after:
///
/// Normal: Use the current key and resources. ROAs are re-issued and revoked
///         under the current key - if needed.
///
/// UpdatedResources: Use the current key, but with the new resource set that
///         this key is about to be updated with.
///
/// KeyRollActivation: Publish ROAs and certificates under the new key, and revoke
///         them under the old key - which will be revoked shortly.
///
/// NewRepo: Publish ROAs and certificates under a new repository.
///
#[derive(Clone, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PublishMode {
    Normal,
    UpdatedResources(ResourceSet, Routes),
    KeyRollActivation,
    NewRepo(RepoInfo),
}
