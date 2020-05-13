use std::collections::HashMap;

use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::Base64;
use crate::commons::api::{
    AddedObject, CurrentObject, CurrentObjects, EntitlementClass, HexEncodedHash, IssuanceRequest,
    IssuedCert, ObjectName, ObjectsDelta, ParentHandle, RcvdCert, ReplacedObject, RepoInfo,
    RequestResourceLimit, ResourceClassInfo, ResourceClassName, ResourceSet, Revocation,
    RevocationRequest, RevokedObject, UpdatedObject, WithdrawnObject,
};
use crate::commons::error::Error;
use crate::commons::KrillResult;
use crate::constants::ROA_CERTIFICATE_REISSUE_WEEKS;
use crate::daemon::ca::events::{ChildCertificateUpdates, RoaUpdates};
use crate::daemon::ca::signing::CsrInfo;
use crate::daemon::ca::{
    self, ta_handle, AddedOrUpdated, CertifiedKey, ChildCertificates, CrlBuilder, CurrentKey,
    CurrentObjectSetDelta, EvtDet, KeyState, ManifestBuilder, NewKey, OldKey, PendingKey, RoaInfo,
    Roas, RouteAuthorization, SignSupport, Signer,
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
        self.current_key().ok_or_else(|| Error::KeyUseNoCurrentKey)
    }

    /// Gets the new key for a key roll, or returns an error if there is none.
    pub fn get_new_key(&self) -> KrillResult<&NewKey> {
        if let KeyState::RollNew(new_key, _) = &self.key_state {
            Ok(new_key)
        } else {
            Err(Error::KeyUseNoNewKey)
        }
    }

    pub fn current_objects(&self) -> CurrentObjects {
        let mut current_objects = CurrentObjects::default();

        for roa_info in self.roas.current() {
            current_objects.insert(roa_info.name().clone(), roa_info.object().clone());
        }

        for issued in self.certificates.current() {
            let cert = issued.cert();
            current_objects.insert(ObjectName::from(cert), CurrentObject::from(cert));
        }

        fn add_mft_and_crl(objects: &mut CurrentObjects, key: &CertifiedKey) {
            let mft = key.current_set().manifest_info();
            objects.insert(mft.name().clone(), mft.current().clone());

            let crl = key.current_set().crl_info();
            objects.insert(crl.name().clone(), crl.current().clone());
        }

        match &self.key_state {
            KeyState::Pending(_) => {} // nothing to add
            KeyState::Active(current) => {
                add_mft_and_crl(&mut current_objects, current);
            }
            KeyState::RollPending(_, current) => {
                add_mft_and_crl(&mut current_objects, current);
            }
            KeyState::RollNew(new, current) => {
                add_mft_and_crl(&mut current_objects, new);
                add_mft_and_crl(&mut current_objects, current);
            }
            KeyState::RollOld(current, old) => {
                add_mft_and_crl(&mut current_objects, current);
                add_mft_and_crl(&mut current_objects, old);
            }
        }

        current_objects
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behaviour.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(
            self.name_space.clone(),
            self.parent_handle.clone(),
            self.key_state.as_info(),
            self.current_objects(),
        )
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Returns event details for receiving the certificate.
    pub fn update_received_cert<S: Signer>(
        &self,
        rcvd_cert: RcvdCert,
        repo_info: &RepoInfo,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        // If this is for a pending key, then we need to promote this key

        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();

        fn create_active_key_and_delta<S: Signer>(
            rcvd_cert: RcvdCert,
            repo_info: &RepoInfo,
            name_space: &str,
            signer: &S,
        ) -> KrillResult<(CertifiedKey, ObjectsDelta)> {
            let mut delta = ObjectsDelta::new(rcvd_cert.ca_repository().clone());
            let active_key = CertifiedKey::create(rcvd_cert, repo_info, name_space, signer)?;

            match active_key.current_set().manifest_info().added_or_updated() {
                AddedOrUpdated::Added(added) => delta.add(added),
                _ => panic!("New active key cannot have update."),
            }

            match active_key.current_set().crl_info().added_or_updated() {
                AddedOrUpdated::Added(added) => delta.add(added),
                _ => panic!("New active key cannot have update."),
            }
            Ok((active_key, delta))
        }

        match &self.key_state {
            KeyState::Pending(pending) => {
                if rcvd_cert_ki != pending.key_id() {
                    Err(Error::KeyUseNoMatch(rcvd_cert_ki))
                } else {
                    let (active_key, delta) = create_active_key_and_delta(
                        rcvd_cert,
                        repo_info,
                        self.name_space(),
                        signer,
                    )?;
                    Ok(vec![EvtDet::KeyPendingToActive(
                        self.name.clone(),
                        active_key,
                        delta,
                    )])
                }
            }
            KeyState::Active(current) => {
                self.update_rcvd_cert_current(current, rcvd_cert, repo_info, signer)
            }
            KeyState::RollPending(pending, current) => {
                if rcvd_cert_ki == pending.key_id() {
                    let (active_key, delta) = create_active_key_and_delta(
                        rcvd_cert,
                        repo_info,
                        self.name_space(),
                        signer,
                    )?;
                    Ok(vec![EvtDet::KeyPendingToNew(
                        self.name.clone(),
                        active_key,
                        delta,
                    )])
                } else {
                    self.update_rcvd_cert_current(current, rcvd_cert, repo_info, signer)
                }
            }
            KeyState::RollNew(new, current) => {
                if rcvd_cert_ki == new.key_id() {
                    Ok(vec![EvtDet::CertificateReceived(
                        self.name.clone(),
                        rcvd_cert_ki,
                        rcvd_cert,
                    )])
                } else {
                    self.update_rcvd_cert_current(current, rcvd_cert, repo_info, signer)
                }
            }
            KeyState::RollOld(current, _old) => {
                // We will never request a new certificate for an old key
                self.update_rcvd_cert_current(current, rcvd_cert, repo_info, signer)
            }
        }
    }

    fn update_rcvd_cert_current<S: Signer>(
        &self,
        current: &CurrentKey,
        rcvd_cert: RcvdCert,
        repo_info: &RepoInfo,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();
        if rcvd_cert_ki != current.key_id() {
            return Err(ca::Error::KeyUseNoMatch(rcvd_cert_ki));
        }

        let rcvd_resources = rcvd_cert.resources().clone();

        let mut res = vec![];
        res.push(EvtDet::CertificateReceived(
            self.name.clone(),
            rcvd_cert_ki,
            rcvd_cert,
        ));

        if &rcvd_resources != current.incoming_cert().resources() {
            let publish_mode = PublishMode::UpdatedResources(rcvd_resources);
            let authorizations: Vec<RouteAuthorization> =
                self.roas.authorizations().cloned().collect();
            res.append(&mut self.republish(
                authorizations.as_slice(),
                repo_info,
                &publish_mode,
                signer,
            )?)
        }

        Ok(res)
    }

    /// Request certificates for any key that needs it.
    /// Also, create revocation events for any unexpected keys to recover from
    /// issues where the parent believes we have keys that we do not know. This
    /// can happen in corner cases where re-initialisation of Krill as a child
    /// is done without proper revocation at the parent, or as is the case with
    /// ARIN - Krill is sometimes told to just drop all resources.
    pub fn make_entitlement_events<S: Signer>(
        &self,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        self.key_state.make_entitlement_events(
            self.name.clone(),
            entitlement,
            base_repo,
            &self.name_space,
            signer,
        )
    }

    /// Request new certificates for all keys when the base repo changes.
    pub fn make_request_events_new_repo<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        self.key_state.request_certs_new_repo(
            self.name.clone(),
            base_repo,
            &self.name_space,
            signer,
        )
    }

    /// This function returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        self.key_state.cert_requests()
    }

    /// Returns the revocation request for the old key, if it exists.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        self.key_state.revoke_request()
    }
}

/// # Publishing
///
impl ResourceClass {
    /// Applies a publication delta to the appropriate key in this resource class.
    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta, key_id: KeyIdentifier) {
        self.key_state.apply_delta(delta, key_id);
    }

    /// Publish/update/withdraw objects under the key, determined by the
    /// [PublishMode]. Will revoke updated and withdrawn objects under the
    /// correct key as well, i.e. when activating a new key objects will
    /// be re-published and updated in terms of publication, but will only
    /// be revoked under the old key.
    pub fn publish_objects<S: Signer>(
        &self,
        repo_info: &RepoInfo,
        objects_delta: ObjectsDelta,
        new_revocations: Vec<Revocation>,
        mode: &PublishMode,
        signer: &S,
    ) -> KrillResult<EvtDet> {
        let mut key_pub_map = HashMap::new();

        let (publish_key, other_key_opt) = match mode {
            PublishMode::KeyRollActivation => (self.get_new_key()?, Some(self.get_current_key()?)),
            _ => {
                let other_key_opt = match &self.key_state {
                    KeyState::RollNew(new, _) => Some(new),
                    KeyState::RollOld(_, old) => Some(old.key()),
                    _ => None,
                };
                (self.get_current_key()?, other_key_opt)
            }
        };

        let (publish_key_revocations, other_key_revocations) = match mode {
            PublishMode::KeyRollActivation => (vec![], new_revocations),
            _ => (new_revocations, vec![]),
        };

        let publish_key_delta = self
            .make_current_set_delta(
                publish_key,
                repo_info,
                objects_delta,
                publish_key_revocations,
                signer,
            )
            .map_err(Error::signer)?;

        key_pub_map.insert(publish_key.key_id().clone(), publish_key_delta);

        if let Some(other_key) = other_key_opt {
            let ns = self.name_space();
            let delta = ObjectsDelta::new(repo_info.ca_repository(ns));

            let other_delta = self
                .make_current_set_delta(other_key, repo_info, delta, other_key_revocations, signer)
                .map_err(ca::Error::signer)?;

            key_pub_map.insert(other_key.key_id().clone(), other_delta);
        }

        Ok(EvtDet::ObjectSetUpdated(self.name.clone(), key_pub_map))
    }

    fn needs_publication(&self, mode: &PublishMode) -> bool {
        match mode {
            PublishMode::Normal => self.get_current_key().unwrap().close_to_next_update(),
            _ => true,
        }
    }

    /// Republish all keys in this class (that want it). Also update
    /// ROAs as needed.
    pub fn republish<S: Signer>(
        &self,
        authorizations: &[RouteAuthorization],
        repo_info: &RepoInfo,
        mode: &PublishMode,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        let mut res = vec![];

        let ns = self.name_space();
        let mut delta = ObjectsDelta::new(repo_info.ca_repository(ns));
        let mut revocations = vec![];

        let roa_updates = self.update_roas(authorizations, mode, signer)?;
        if roa_updates.contains_changes() {
            for added in roa_updates.added().into_iter() {
                delta.add(added);
            }
            for update in roa_updates.updated().into_iter() {
                delta.update(update);
            }
            for withdraw in roa_updates.withdrawn().into_iter() {
                delta.withdraw(withdraw);
            }
            revocations.append(&mut roa_updates.revocations());

            res.push(EvtDet::RoasUpdated(self.name.clone(), roa_updates));
        }

        let child_cert_updates = self.update_child_certificates(mode, signer)?;
        if !child_cert_updates.is_empty() {
            for issued in child_cert_updates.issued() {
                match issued.replaces() {
                    None => delta.add(AddedObject::from(issued.cert())),
                    Some(old) => {
                        delta.update(UpdatedObject::for_cert(issued.cert(), old.hash().clone()))
                    }
                }
            }
            for key in child_cert_updates.removed() {
                let issued = self.certificates.get(key).unwrap();
                delta.withdraw(WithdrawnObject::from(issued.cert()));
                revocations.push(Revocation::from(issued.cert()));
            }
            res.push(EvtDet::ChildCertificatesUpdated(
                self.name.clone(),
                child_cert_updates,
            ));
        }

        if !delta.is_empty() || !revocations.is_empty() || self.needs_publication(mode) {
            res.push(self.publish_objects(&repo_info, delta, revocations, mode, signer)?);
        }

        Ok(res)
    }

    /// Create a publish event details including the revocations, update, withdrawals needed
    /// for updating child certificates.
    pub fn republish_certs<S: Signer>(
        &self,
        issued_certs: &[&IssuedCert],
        removed_certs: &[&Cert],
        repo_info: &RepoInfo,
        signer: &S,
    ) -> KrillResult<HashMap<KeyIdentifier, CurrentObjectSetDelta>> {
        let issuing_key = self.get_current_key()?;
        let name_space = self.name_space();

        let mut revocations = vec![];
        for cert in removed_certs {
            revocations.push(Revocation::from(*cert));
        }
        for issued in issued_certs {
            if let Some(replaced) = issued.replaces() {
                revocations.push(replaced.revocation());
            }
        }

        let ca_repo = repo_info.ca_repository(name_space);
        let mut objects_delta = ObjectsDelta::new(ca_repo);

        for removed in removed_certs {
            objects_delta.withdraw(WithdrawnObject::from(*removed));
        }
        for issued in issued_certs {
            match issued.replaces() {
                None => objects_delta.add(AddedObject::from(issued.cert())),
                Some(replaced) => objects_delta.update(UpdatedObject::for_cert(
                    issued.cert(),
                    replaced.hash().clone(),
                )),
            }
        }

        let set_delta = self
            .make_current_set_delta(issuing_key, repo_info, objects_delta, revocations, signer)
            .map_err(Error::signer)?;

        let mut res = HashMap::new();
        res.insert(issuing_key.key_id().clone(), set_delta);
        Ok(res)
    }

    fn make_current_set_delta<S: Signer>(
        &self,
        signing_key: &CertifiedKey,
        repo_info: &RepoInfo,
        mut objects_delta: ObjectsDelta,
        mut new_revocations: Vec<Revocation>,
        signer: &S,
    ) -> KrillResult<CurrentObjectSetDelta> {
        let signing_cert = signing_key.incoming_cert();
        let current_set = signing_key.current_set();
        let current_revocations = current_set.revocations().clone();
        let number = current_set.number() + 1;

        let current_mft = current_set.manifest_info();
        let current_mft_hash = current_mft.current().to_hex_hash();
        let current_crl = current_set.crl_info();
        let current_crl_hash = current_crl.current().to_hex_hash();

        new_revocations.push(Revocation::from(current_mft.current()));

        // Create a new CRL
        let (crl_info, revocations_delta) = CrlBuilder::build(
            current_revocations,
            new_revocations,
            number,
            Some(current_crl_hash),
            signing_cert,
            signer,
        )?;

        match crl_info.added_or_updated() {
            AddedOrUpdated::Added(added) => objects_delta.add(added),
            AddedOrUpdated::Updated(updated) => objects_delta.update(updated),
        }

        // For the new manifest:
        //
        // List all current files, i.e.
        //  - the new CRL
        //  - current ROAs
        //  - current Certs
        //  - applying the delta - which may update the current ROAs and Certs on the MFT
        let issued = self.certificates.current();
        let roas = self.roas.iter();

        let manifest_info = ManifestBuilder::new(&crl_info, issued, roas, &objects_delta).build(
            signing_cert,
            repo_info,
            self.name_space(),
            number,
            Some(current_mft_hash),
            signer,
        )?;

        match manifest_info.added_or_updated() {
            AddedOrUpdated::Added(added) => objects_delta.add(added),
            AddedOrUpdated::Updated(updated) => objects_delta.update(updated),
        }

        Ok(CurrentObjectSetDelta::new(
            number,
            revocations_delta,
            manifest_info,
            crl_info,
            objects_delta,
        ))
    }

    pub fn all_objects(&self, base_repo: &RepoInfo) -> Vec<PublishElement> {
        let mut res = vec![];
        let ns = self.name_space();

        // ROAs
        for info in self.roas.current() {
            let base64 = info.object().content().clone();
            let object_name = info.name().clone();
            let uri = base_repo.resolve(ns, object_name.as_str());
            res.push(PublishElement::new(base64, uri));
        }
        // Certs
        for cert in self.certificates.current() {
            let base64 = Base64::from_content(cert.to_captured().as_slice());
            let uri = cert.uri().clone();
            res.push(PublishElement::new(base64, uri));
        }

        // MFT and CRL for each key
        let sets = match &self.key_state {
            KeyState::Pending(_) => vec![],
            KeyState::Active(current) => vec![current.current_set()],
            KeyState::RollPending(_, current) => vec![current.current_set()],
            KeyState::RollNew(new, current) => vec![new.current_set(), current.current_set()],
            KeyState::RollOld(current, old) => vec![current.current_set(), old.current_set()],
        };

        for set in sets {
            let crl_info = set.crl_info();
            let crl_base64 = crl_info.current().content().clone();
            let crl_uri = base_repo.resolve(ns, crl_info.name());
            res.push(PublishElement::new(crl_base64, crl_uri));

            let mft_info = set.manifest_info();
            let mft_base64 = mft_info.current().content().clone();
            let mft_uri = base_repo.resolve(ns, mft_info.name());
            res.push(PublishElement::new(mft_base64, mft_uri));
        }

        res
    }
}

/// # Removing a resource class
///
impl ResourceClass {
    /// Returns withdraws for all current objects, for when this resource class
    /// needs to be removed.
    pub fn withdraw(&self, base_repo: &RepoInfo) -> ObjectsDelta {
        let base_repo = base_repo.ca_repository(self.name_space());
        let mut delta = ObjectsDelta::new(base_repo);

        for withdraw in self.current_objects().withdraw().into_iter() {
            delta.withdraw(withdraw);
        }
        delta
    }

    /// Returns revocation requests for all certified keys in this resource class.
    pub fn revoke<S: Signer>(&self, signer: &S) -> KrillResult<Vec<RevocationRequest>> {
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
    pub fn keyroll_initiate<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        duration: Duration,
        signer: &mut S,
    ) -> KrillResult<Vec<EvtDet>> {
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
    pub fn keyroll_activate<S: Signer>(
        &self,
        repo_info: &RepoInfo,
        staging: Duration,
        signer: &S,
    ) -> KrillResult<Vec<EvtDet>> {
        if !self.key_state.has_new_key() || self.last_key_change + staging > Time::now() {
            return Ok(vec![]);
        }

        let mut res = vec![];

        let authorizations: Vec<RouteAuthorization> = self.roas.authorizations().cloned().collect();

        res.push(self.key_state.keyroll_activate(
            self.name.clone(),
            self.parent_rc_name.clone(),
            signer,
        )?);

        res.append(&mut self.republish(
            authorizations.as_slice(),
            repo_info,
            &PublishMode::KeyRollActivation,
            signer,
        )?);

        Ok(res)
    }

    /// Finish a key roll, withdraw the old key
    pub fn keyroll_finish(&self, base_repo: &RepoInfo) -> KrillResult<EvtDet> {
        match &self.key_state {
            KeyState::RollOld(_current, old) => {
                let mut objects_delta =
                    ObjectsDelta::new(base_repo.ca_repository(self.name_space()));

                let crl_info = old.current_set().crl_info();
                objects_delta.withdraw(crl_info.withdraw());

                let mft_info = old.current_set().manifest_info();
                objects_delta.withdraw(mft_info.withdraw());

                Ok(EvtDet::KeyRollFinished(self.name.clone(), objects_delta))
            }
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
    pub fn issue_cert<S: Signer>(
        &self,
        csr: CsrInfo,
        child_resources: &ResourceSet,
        limit: RequestResourceLimit,
        signer: &S,
    ) -> KrillResult<IssuedCert> {
        let signing_key = self.get_current_key()?;
        let parent_resources = signing_key.incoming_cert().resources();
        let resources = parent_resources.intersection(child_resources);
        let replaces = self
            .certificates
            .get(&csr.key_id())
            .map(ReplacedObject::from);

        let issued =
            SignSupport::make_issued_cert(csr, &resources, limit, replaces, signing_key, signer)?;

        Ok(issued)
    }

    fn re_issue<S: Signer>(
        &self,
        previous: &IssuedCert,
        updated_resources: Option<ResourceSet>,
        signing_key: &CertifiedKey,
        csr_info_opt: Option<CsrInfo>,
        signer: &S,
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
            signer,
        )?;

        Ok(re_issued)
    }

    fn update_child_certificates<S: Signer>(
        &self,
        mode: &PublishMode,
        signer: &S,
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
                for issued in self.certificates.expiring() {
                    let re_issued = self.re_issue(issued, None, signing_key, None, signer)?;
                    updates.issue(re_issued);
                }
            }
            PublishMode::UpdatedResources(resources) => {
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
                            signer,
                        )?;
                        updates.issue(re_issued);
                    }
                }
            }
            PublishMode::KeyRollActivation => {
                for issued in self.certificates.iter() {
                    let re_issued = self.re_issue(issued, None, signing_key, None, signer)?;
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

                    let re_issued =
                        self.re_issue(issued, None, signing_key, Some(csr_info_update), signer)?;
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
    /// Updates the ROAs in accordance with the current authorizations, and
    /// the target resources and key determined by the PublishMode.
    pub fn update_roas<S: Signer>(
        &self,
        auths: &[RouteAuthorization],
        mode: &PublishMode,
        signer: &S,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        let key = match mode {
            PublishMode::KeyRollActivation => self.get_new_key()?,
            _ => self.get_current_key()?,
        };

        let resources = match mode {
            PublishMode::Normal | PublishMode::NewRepo(_) => key.incoming_cert().resources(),
            PublishMode::UpdatedResources(resources) => resources,
            PublishMode::KeyRollActivation => self.get_current_key()?.incoming_cert().resources(),
        };

        let new_repo = match &mode {
            PublishMode::NewRepo(info) => Some(info.ca_repository(self.name_space())),
            _ => None,
        };

        // Remove any ROAs no longer in auths, or no longer in resources.
        for (current_auth, roa_info) in self.roas.iter() {
            if !auths.contains(current_auth) || !resources.contains(&current_auth.prefix().into()) {
                updates.remove(*current_auth, RevokedObject::from(roa_info.object()));
            }
        }

        for auth in auths {
            // if the auth is not in this resource class, just skip it.
            if !resources.contains(&auth.prefix().into()) {
                continue;
            }

            match self.roas.get(auth) {
                None => {
                    // NO ROA yet, so create one.
                    let roa = Roas::make_roa(auth, key, new_repo.as_ref(), signer)?;
                    let name = ObjectName::from(auth);
                    updates.update(*auth, RoaInfo::new_roa(&roa, name));
                }
                Some(roa) => {
                    // Re-issue if the ROA is getting close to its expiration time, or if we are
                    //  activating the new key.
                    let expiring = roa.object().expires()
                        < Time::now() + Duration::weeks(ROA_CERTIFICATE_REISSUE_WEEKS);
                    let activating = mode == &PublishMode::KeyRollActivation;

                    if expiring || activating || new_repo.is_some() {
                        let new_roa = Roas::make_roa(auth, key, new_repo.as_ref(), signer)?;
                        let name = ObjectName::from(auth);
                        updates.update(*auth, RoaInfo::updated_roa(roa, &new_roa, name));
                    }
                }
            }
        }

        Ok(updates)
    }

    /// Marks the ROAs as updated from a RoaUpdated event.
    pub fn roas_updated(&mut self, updates: RoaUpdates) {
        self.roas.updated(updates);
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
/// PendingKeyActivation: The pending key will be activated, to either a new
///         (init) or the current (roll) key, and needs to be published.
///
/// KeyActivation: Publish ROAs and certificates under the new key, and revoke
///         them under the old key - which will be revoked shortly.
///
#[derive(Clone, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PublishMode {
    Normal,
    UpdatedResources(ResourceSet),
    KeyRollActivation,
    NewRepo(RepoInfo),
}
