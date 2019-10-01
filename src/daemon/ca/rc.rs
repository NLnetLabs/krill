use std::collections::HashMap;

use chrono::Duration;
use serde::{Deserialize, Serialize};

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::{
    AddedObject, CurrentObject, CurrentObjects, EntitlementClass, HexEncodedHash, IssuanceRequest,
    IssuanceResponse, IssuedCert, KeyStateInfo, ObjectName, ObjectsDelta, ParentHandle, RcvdCert,
    ReplacedObject, RepoInfo, RequestResourceLimit, ResourceClassName, ResourceSet, Revocation,
    RevocationRequest, RevokedObject, RouteAuthorization, SigningCert, UpdatedObject,
    WithdrawnObject,
};
use crate::daemon::ca::events::RoaUpdates;
use crate::daemon::ca::signing::CsrInfo;
use crate::daemon::ca::{
    self, ta_handle, AddedOrUpdated, Certificates, CertifiedKey, CrlBuilder, CurrentKey,
    CurrentObjectSetDelta, Error, EvtDet, KeyState, ManifestBuilder, NewKey, OldKey, PendingKey,
    Result, RoaInfo, Roas, SignSupport, Signer,
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
    certificates: Certificates,

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
            certificates: Certificates::default(),
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
            certificates: Certificates::default(),
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

    pub fn get_current_key(&self) -> Result<&CurrentKey> {
        self.current_key()
            .ok_or_else(|| Error::ResourceClassNoCurrentKey)
    }

    /// Gets the new key for a key roll, or returns an error if there is none.
    pub fn get_new_key(&self) -> Result<&NewKey> {
        if let KeyState::RollNew(new_key, _) = &self.key_state {
            Ok(new_key)
        } else {
            Err(Error::ResourceClassNoNewKey)
        }
    }

    fn current_objects(&self) -> CurrentObjects {
        let mut current_objects = CurrentObjects::default();

        for (auth, roa_info) in self.roas.iter() {
            let roa = roa_info.roa();
            current_objects.insert(ObjectName::from(auth), CurrentObject::from(roa));
        }

        for issued in self.certificates.current() {
            let cert = issued.cert();
            current_objects.insert(ObjectName::from(cert), CurrentObject::from(cert));
        }

        fn add_mft_and_crl(objects: &mut CurrentObjects, key: &CertifiedKey) {
            let mft = key.current_set().manifest();
            objects.insert(ObjectName::from(mft), CurrentObject::from(mft));

            let crl = key.current_set().crl();
            objects.insert(ObjectName::from(crl), CurrentObject::from(crl));
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
    pub fn as_info(&self) -> KeyStateInfo {
        KeyStateInfo::new(
            self.name_space.clone(),
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
    ) -> ca::Result<Vec<EvtDet>> {
        // If this is for a pending key, then we need to promote this key

        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();

        fn create_active_key_and_delta<S: Signer>(
            rcvd_cert: RcvdCert,
            signer: &S,
        ) -> ca::Result<(CertifiedKey, ObjectsDelta)> {
            let mut delta = ObjectsDelta::new(rcvd_cert.ca_repository().clone());
            let active_key = CertifiedKey::create(rcvd_cert, signer)?;

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
                    Err(ca::Error::NoKeyMatch(rcvd_cert_ki))
                } else {
                    let (active_key, delta) = create_active_key_and_delta(rcvd_cert, signer)?;
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
                    let (active_key, delta) = create_active_key_and_delta(rcvd_cert, signer)?;
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
    ) -> ca::Result<Vec<EvtDet>> {
        let rcvd_cert_ki = rcvd_cert.cert().subject_key_identifier();
        if rcvd_cert_ki != current.key_id() {
            return Err(ca::Error::NoKeyMatch(rcvd_cert_ki));
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
    pub fn make_request_events<S: Signer>(
        &self,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &S,
    ) -> Result<Vec<EvtDet>> {
        self.key_state.request_certs(
            self.name.clone(),
            entitlement,
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
    ) -> ca::Result<EvtDet> {
        let mut key_pub_map = HashMap::new();

        let (publish_key, other_key_opt) = match mode {
            PublishMode::Normal | PublishMode::UpdatedResources(_) => {
                let other_key_opt = match &self.key_state {
                    KeyState::RollNew(new, _) => Some(new),
                    KeyState::RollOld(_, old) => Some(old.key()),
                    _ => None,
                };
                (self.get_current_key()?, other_key_opt)
            }
            PublishMode::KeyRollActivation => (self.get_new_key()?, Some(self.get_current_key()?)),
        };

        let (publish_key_revocations, other_key_revocations) = match mode {
            PublishMode::Normal | PublishMode::UpdatedResources(_) => (new_revocations, vec![]),
            PublishMode::KeyRollActivation => (vec![], new_revocations),
        };

        let publish_key_delta = self
            .make_current_set_delta(publish_key, objects_delta, publish_key_revocations, signer)
            .map_err(Error::signer)?;

        key_pub_map.insert(publish_key.key_id().clone(), publish_key_delta);

        if let Some(other_key) = other_key_opt {
            let ns = self.name_space();
            let delta = ObjectsDelta::new(repo_info.ca_repository(ns));

            let other_delta = self
                .make_current_set_delta(other_key, delta, other_key_revocations, signer)
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
    ) -> ca::Result<Vec<EvtDet>> {
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

        if !delta.is_empty() || !revocations.is_empty() || self.needs_publication(mode) {
            res.push(self.publish_objects(&repo_info, delta, revocations, mode, signer)?);
        }

        Ok(res)
    }

    /// Create a publish event details including the revocations, update, withdrawals needed
    /// for updating child certificates.
    pub fn republish_certs<S: Signer>(
        &self,
        issued_certs: Vec<&IssuedCert>,
        removed_certs: Vec<&Cert>,
        repo_info: &RepoInfo,
        signer: &S,
    ) -> Result<HashMap<KeyIdentifier, CurrentObjectSetDelta>> {
        let issuing_key = self.get_current_key()?;
        let name_space = self.name_space();

        let mut revocations = vec![];
        for cert in removed_certs.iter() {
            revocations.push(Revocation::from(*cert));
        }
        for issued in issued_certs.iter() {
            if let Some(replaced) = issued.replaces() {
                revocations.push(replaced.revocation());
            }
        }

        let ca_repo = repo_info.ca_repository(name_space);
        let mut objects_delta = ObjectsDelta::new(ca_repo);

        for removed in removed_certs.into_iter() {
            objects_delta.withdraw(WithdrawnObject::from(removed));
        }
        for issued in issued_certs.into_iter() {
            match issued.replaces() {
                None => objects_delta.add(AddedObject::from(issued.cert())),
                Some(replaced) => objects_delta.update(UpdatedObject::for_cert(
                    issued.cert(),
                    replaced.hash().clone(),
                )),
            }
        }

        let set_delta = self
            .make_current_set_delta(issuing_key, objects_delta, revocations, signer)
            .map_err(Error::signer)?;

        let mut res = HashMap::new();
        res.insert(issuing_key.key_id().clone(), set_delta);
        Ok(res)
    }

    fn make_current_set_delta<S: Signer>(
        &self,
        signing_key: &CertifiedKey,
        mut objects_delta: ObjectsDelta,
        mut new_revocations: Vec<Revocation>,
        signer: &S,
    ) -> ca::Result<CurrentObjectSetDelta> {
        let signing_cert = signing_key.incoming_cert();
        let signing_pub_key = signer
            .get_key_info(signing_key.key_id())
            .map_err(ca::Error::signer)?;

        let current_set = signing_key.current_set();
        let current_revocations = current_set.revocations().clone();
        let number = current_set.number() + 1;

        let current_mft = current_set.manifest();
        let current_mft_hash = HexEncodedHash::from(current_mft);
        let current_crl = current_set.crl();
        let current_crl_hash = HexEncodedHash::from(current_crl);

        new_revocations.push(Revocation::from(current_mft));

        // Create a new CRL
        let (crl_info, revocations_delta) = CrlBuilder::build(
            current_revocations,
            new_revocations,
            number,
            Some(current_crl_hash),
            &signing_pub_key,
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
        //  - applying the delta
        let issued = self.certificates.current();
        let roas = self.roas.iter();

        let manifest_info = ManifestBuilder::new(&crl_info, issued, roas, &objects_delta).build(
            &signing_pub_key,
            signing_cert,
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
    pub fn revoke<S: Signer>(&self, signer: &S) -> ca::Result<Vec<RevocationRequest>> {
        self.key_state.revoke(self.name.clone(), signer)
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
    ) -> ca::Result<Vec<EvtDet>> {
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
    ) -> ca::Result<Vec<EvtDet>> {
        if self.last_key_change + staging > Time::now() {
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
    pub fn keyroll_finish(&self, base_repo: &RepoInfo) -> ca::Result<EvtDet> {
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
            _ => Err(Error::InvalidKeyStatus),
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
        mode: &PublishMode,
        signer: &S,
    ) -> ca::Result<IssuanceResponse> {
        let signing_key = match mode {
            PublishMode::Normal | PublishMode::UpdatedResources(_) => self.get_current_key()?,
            PublishMode::KeyRollActivation => self.get_new_key()?,
        };

        let parent_resources = match mode {
            PublishMode::UpdatedResources(resources) => resources,
            _ => signing_key.incoming_cert().resources(),
        };

        let resources = parent_resources.intersection(child_resources);
        let replaces = self
            .certificates
            .get(&csr.key_id())
            .map(ReplacedObject::from);

        let issued =
            SignSupport::make_issued_cert(csr, &resources, limit, replaces, signing_key, signer)?;

        let signing_cert = SigningCert::from(signing_key.incoming_cert());

        Ok(IssuanceResponse::new(
            self.name.clone(),
            signing_cert,
            resources,
            issued.cert().validity().not_after(),
            issued,
        ))
    }

    /// Stores an [IssuedCert](krill_commons.api.ca.IssuedCert)
    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.certificates.certificate_issued(issued);
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
    ) -> ca::Result<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        let key = match mode {
            PublishMode::Normal | PublishMode::UpdatedResources(_) => self.get_current_key()?,
            PublishMode::KeyRollActivation => self.get_new_key()?,
        };

        let resources = match mode {
            PublishMode::Normal => key.incoming_cert().resources(),
            PublishMode::UpdatedResources(resources) => resources,
            PublishMode::KeyRollActivation => self.get_current_key()?.incoming_cert().resources(),
        };

        // Remove any ROAs no longer in auths, or no longer in resources.
        for (current_auth, roa_info) in self.roas.iter() {
            if !auths.contains(current_auth) || !resources.contains(&current_auth.prefix().into()) {
                updates.remove(*current_auth, RevokedObject::from(roa_info.roa()));
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
                    let roa = Roas::make_roa(auth, key.incoming_cert(), key.key_id(), signer)?;

                    updates.update(*auth, RoaInfo::new_roa(roa));
                }
                Some(roa) => {
                    // Re-issue if the ROA is getting close to its expiration time, or if we are
                    //  activating the new key.
                    let expiring =
                        roa.roa().cert().validity().not_after() < Time::now() + Duration::weeks(4);
                    let activating = mode == &PublishMode::KeyRollActivation;

                    if expiring || activating {
                        let new_roa =
                            Roas::make_roa(auth, key.incoming_cert(), key.key_id(), signer)?;

                        updates.update(*auth, RoaInfo::updated_roa(roa, new_roa));
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
}
