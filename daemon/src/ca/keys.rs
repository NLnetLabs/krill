use serde::{Deserialize, Serialize};

use rpki::crypto::{KeyIdentifier, PublicKeyFormat};
use rpki::csr::Csr;
use rpki::uri;

use krill_commons::api::ca::{
    CertifiedKey, CurrentObjects, ObjectsDelta, OldKey, PendingKey, PublicationDelta, RcvdCert,
    RepoInfo, ResourceClassKeysInfo, ResourceClassName,
};
use krill_commons::api::{
    EntitlementClass, IssuanceRequest, RequestResourceLimit, RevocationRequest,
};

use crate::ca::{self, Error, EvtDet, Result, Signer};

//------------ ResourceClassKeys ---------------------------------------------

/// This type contains the keys for a resource class and guards that keys
/// are created, activated, rolled and retired properly.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ResourceClassKeys {
    Pending(PendingKey),
    Active(CurrentKey),
    RollPending(PendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldKey),
}

pub type NewKey = CertifiedKey;
pub type CurrentKey = CertifiedKey;

impl ResourceClassKeys {
    pub fn create(pending_key: KeyIdentifier) -> Self {
        ResourceClassKeys::Pending(PendingKey::new(pending_key))
    }

    pub fn for_ta(key: CurrentKey) -> Self {
        ResourceClassKeys::Active(key)
    }

    pub fn add_request(&mut self, key_id: KeyIdentifier, req: IssuanceRequest) {
        match self {
            ResourceClassKeys::Pending(pending) => pending.add_request(req),
            ResourceClassKeys::Active(current) => current.add_request(req),
            ResourceClassKeys::RollPending(pending, current) => {
                if pending.key_id() == &key_id {
                    pending.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.add_request(req)
                } else {
                    old.add_request(req)
                }
            }
        }
    }

    pub fn objects(&self) -> CurrentObjects {
        let mut objects = CurrentObjects::default();

        match self {
            ResourceClassKeys::Pending(_pending) => {}
            ResourceClassKeys::Active(current) => {
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollPending(_pending, current) => {
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollNew(new, current) => {
                objects = objects + new.current_set().objects().clone();
                objects = objects + current.current_set().objects().clone();
            }
            ResourceClassKeys::RollOld(current, old) => {
                objects = objects + current.current_set().objects().clone();
                objects = objects + old.current_set().objects().clone();
            }
        }

        objects
    }

    /// Withdraw all objects in all keys
    pub fn withdraw(&self, base_repo: uri::Rsync) -> ObjectsDelta {
        let mut delta = ObjectsDelta::new(base_repo);
        for withdraw in self.objects().withdraw() {
            delta.withdraw(withdraw)
        }
        delta
    }

    /// Revoke all current keys
    pub fn revoke<S: Signer>(
        &self,
        class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<Vec<RevocationRequest>> {
        match self {
            ResourceClassKeys::Pending(_pending) => Ok(vec![]), // nothing to revoke
            ResourceClassKeys::Active(current) | ResourceClassKeys::RollPending(_, current) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_current])
            }
            ResourceClassKeys::RollNew(new, current) => {
                let revoke_new = Self::revoke_key(class_name.clone(), new.key_id(), signer)?;
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                Ok(vec![revoke_new, revoke_current])
            }
            ResourceClassKeys::RollOld(current, old) => {
                let revoke_current = Self::revoke_key(class_name, current.key_id(), signer)?;
                let revoke_old = old.revoke_req().clone();
                Ok(vec![revoke_current, revoke_old])
            }
        }
    }

    fn revoke_key<S: Signer>(
        class_name: ResourceClassName,
        key_id: &KeyIdentifier,
        signer: &S,
    ) -> ca::Result<RevocationRequest> {
        let ki = signer
            .get_key_info(key_id)
            .map_err(Error::signer)?
            .key_identifier();

        Ok(RevocationRequest::new(class_name, ki))
    }

    fn find_matching_key_for_rcvd_cert<S: Signer>(
        &self,
        cert: &RcvdCert,
        signer: &S,
    ) -> ca::Result<CertifiedKey> {
        match self {
            ResourceClassKeys::Pending(pending) => {
                self.matches_key_id(pending.key_id(), cert, signer)?;
                Ok(CertifiedKey::new(*pending.key_id(), cert.clone()))
            }
            ResourceClassKeys::Active(current) => {
                self.matches_key_id(current.key_id(), cert, signer)?;
                Ok(current.clone())
            }
            ResourceClassKeys::RollPending(pending, current) => {
                if self.matches_key_id(pending.key_id(), cert, signer).is_ok() {
                    Ok(CertifiedKey::new(*pending.key_id(), cert.clone()))
                } else {
                    self.matches_key_id(current.key_id(), cert, signer)?;
                    Ok(current.clone())
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if self.matches_key_id(new.key_id(), cert, signer).is_ok() {
                    Ok(new.clone())
                } else {
                    self.matches_key_id(current.key_id(), cert, signer)?;
                    Ok(current.clone())
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if self.matches_key_id(current.key_id(), cert, signer).is_ok() {
                    Ok(current.clone())
                } else {
                    self.matches_key_id(old.key_id(), cert, signer)?;
                    Ok(old.key().clone())
                }
            }
        }
    }

    /// Helper to match a key_id to a pub key.
    fn matches_key_id<S: Signer>(
        &self,
        key_id: &KeyIdentifier,
        cert: &RcvdCert,
        signer: &S,
    ) -> ca::Result<()> {
        let cert = cert.cert();
        let pub_key = cert.subject_public_key_info();

        if let Ok(info) = signer.get_key_info(key_id) {
            if &info == pub_key {
                return Ok(());
            }
        }

        Err(ca::Error::NoKeyMatch(cert.subject_key_identifier()))
    }

    pub fn update_received_cert<S: Signer>(
        &self,
        rcvd_cert: RcvdCert,
        rcn: ResourceClassName,
        signer: &S,
    ) -> ca::Result<EvtDet> {
        let certified_key = self.find_matching_key_for_rcvd_cert(&rcvd_cert, signer)?;

        Ok(EvtDet::CertificateReceived(
            rcn.clone(),
            *certified_key.key_id(),
            rcvd_cert,
        ))
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta, key_id: KeyIdentifier) {
        match self {
            ResourceClassKeys::Pending(_pending) => panic!("Should never have delta for pending"),
            ResourceClassKeys::Active(current) => current.apply_delta(delta),
            ResourceClassKeys::RollPending(_pending, current) => current.apply_delta(delta),
            ResourceClassKeys::RollNew(new, current) => {
                if new.key_id() == &key_id {
                    new.apply_delta(delta)
                } else {
                    current.apply_delta(delta)
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.key_id() == &key_id {
                    current.apply_delta(delta)
                } else {
                    old.apply_delta(delta)
                }
            }
        }
    }

    pub fn request_certs<S: Signer>(
        &self,
        rcn: ResourceClassName,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &S,
    ) -> Result<Vec<EvtDet>> {
        let mut keys_for_requests = vec![];
        match self {
            ResourceClassKeys::Pending(pending) => {
                keys_for_requests.push(pending.key_id());
            }
            ResourceClassKeys::Active(current) => {
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollPending(pending, current) => {
                keys_for_requests.push(pending.key_id());
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if new.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(new.key_id());
                }
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if current.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(current.key_id());
                }
                if old.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                    keys_for_requests.push(old.key_id());
                }
            }
        }

        let mut res = vec![];

        for key_id in keys_for_requests.into_iter() {
            let req = self.create_issuance_req(
                base_repo,
                name_space,
                entitlement.class_name().clone(),
                key_id,
                signer,
            )?;

            res.push(EvtDet::CertificateRequested(rcn.clone(), req, *key_id));
        }

        Ok(res)
    }

    /// Returns all open certificate requests
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        let mut res = vec![];
        match self {
            ResourceClassKeys::Pending(pending) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::Active(current) => {
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollPending(pending, current) => {
                if let Some(r) = pending.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollNew(new, current) => {
                if let Some(r) = new.request() {
                    res.push(r.clone())
                }
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
            }
            ResourceClassKeys::RollOld(current, old) => {
                if let Some(r) = current.request() {
                    res.push(r.clone())
                }
                if let Some(r) = old.request() {
                    res.push(r.clone())
                }
            }
        }
        res
    }

    /// Creates a Csr for the given key. Note that this parses the encoded
    /// key. This is not the most efficient way, but makes storing and
    /// serializing the Csr in an event possible (the Captured cannot be
    /// stored).
    fn create_issuance_req<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        name_space: &str,
        class_name: ResourceClassName,
        key: &KeyIdentifier,
        signer: &S,
    ) -> Result<IssuanceRequest> {
        let pub_key = signer.get_key_info(key).map_err(Error::signer)?;

        let enc = Csr::construct(
            signer,
            key,
            &base_repo.ca_repository(name_space),
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(Error::signer)?;

        let csr = Csr::decode(enc.as_slice()).map_err(Error::signer)?;

        Ok(IssuanceRequest::new(
            class_name,
            RequestResourceLimit::default(),
            csr,
        ))
    }

    /// Returns the revoke request if there is an old key.
    pub fn revoke_request(&self) -> Option<&RevocationRequest> {
        match self {
            ResourceClassKeys::RollOld(_current, old) => Some(old.revoke_req()),
            _ => None,
        }
    }

    pub fn as_info(&self) -> ResourceClassKeysInfo {
        match self.clone() {
            ResourceClassKeys::Pending(p) => ResourceClassKeysInfo::Pending(p),
            ResourceClassKeys::Active(c) => ResourceClassKeysInfo::Active(c),
            ResourceClassKeys::RollPending(p, c) => ResourceClassKeysInfo::RollPending(p, c),
            ResourceClassKeys::RollNew(n, c) => ResourceClassKeysInfo::RollNew(n, c),
            ResourceClassKeys::RollOld(c, o) => ResourceClassKeysInfo::RollOld(c, o),
        }
    }
}

/// # Key Rolls
///
impl ResourceClassKeys {
    /// Initiates a key roll if the current state is 'Active'. This will return event details
    /// for a newly create pending key and requested certificate for it.
    pub fn keyroll_initiate<S: Signer>(
        &self,
        class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        base_repo: &RepoInfo,
        name_space: &str,
        signer: &mut S,
    ) -> ca::Result<Vec<EvtDet>> {
        match self {
            ResourceClassKeys::Active(_current) => {
                let key_id = {
                    signer
                        .create_key(PublicKeyFormat::default())
                        .map_err(Error::signer)?
                };

                let issuance_req = self.create_issuance_req(
                    base_repo,
                    name_space,
                    parent_class_name,
                    &key_id,
                    signer,
                )?;

                Ok(vec![
                    EvtDet::KeyRollPendingKeyAdded(class_name.clone(), key_id),
                    EvtDet::CertificateRequested(class_name, issuance_req, key_id),
                ])
            }
            _ => Ok(vec![]),
        }
    }

    /// Marks the new key as current, and the current key as old, and requests revocation of
    /// the old key.
    pub fn keyroll_activate<S: Signer>(
        &self,
        class_name: ResourceClassName,
        parent_class_name: ResourceClassName,
        signer: &S,
    ) -> ca::Result<EvtDet> {
        match self {
            ResourceClassKeys::RollNew(_new, current) => {
                let revoke_req = Self::revoke_key(parent_class_name, current.key_id(), signer)?;
                Ok(EvtDet::KeyRollActivated(class_name, revoke_req))
            }
            _ => Err(Error::ResourceClassNoNewKey),
        }
    }
}
