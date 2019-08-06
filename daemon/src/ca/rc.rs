use std::ops::Deref;
use std::sync::{Arc, RwLock};

use rpki::crypto::PublicKey;
use rpki::csr::Csr;

use krill_commons::api::admin::Handle;
use krill_commons::api::ca::{
    CertifiedKey, CurrentObjects, KeyRef, ObjectsDelta, PendingKey, PublicationDelta, RcvdCert,
    RepoInfo, ResourceClassInfo,
};
use krill_commons::api::{EntitlementClass, IssuanceRequest, RequestResourceLimit};
use krill_commons::util::softsigner::SignerKeyId;

use crate::ca::{
    self, Error, Evt, EvtDet, ParentHandle, ResourceClassName, Result, SignSupport, Signer,
};

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
/// key for this class. The key life cycle has the following stages:
///
/// - Pending Key
///
/// This is a newly generated key, for which a certificate has been requested,
/// but it is not yet received. This key is not published.
///
/// Pending keys can only be created for new Resource Classes, or when there
/// is no key roll in progress: i.e. the Resource Class contains a 'current'
/// key only.
///
/// - New Key
///
/// When a certificate is received for a pending key, it is promoted to a 'new'
/// key. If there are no other keys in this resource class, then this key can
/// be promoted to 'current' key immediately - see below.
///
/// If there is already an current key, then the new key status should be
/// observed for at least 24 hours. New keys publish a manifest and a ROA, but
/// no other products.
///
/// - Current Key
///
/// A current key publishes a manifest and CRL, and all the products pertaining
/// to the Internet Number Resources in this resource class.
///
/// If a resource class contains a current key only, a key roll can be
/// initiated: a pending key is created and a certificate is requested, when
/// the certificate is received the pending key is promoted to 'new' key, and
/// a staging period of at least 24 hours is started. Note that the MFT and
/// CRL for both keys are published under the same namespace, but only the
/// current key publishes additional objects.
///
/// When the staging period is over the new key can be promoted to current
/// key. When this happens the current key is promoted to the stage 'revoke'
/// key - see below. And the 'new' key become the 'current' key.
///
/// - Revoke Key
///
/// A revoke key only publishes a manifest and CRL, but no additional
/// products. When a revoke key is created a revocation request is generated
/// for the parent. The moment confirmation is received from the parent, the
/// 'revoke' key is dropped, and its content is withdrawn.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceClass {
    name_space: String,
    pending_key: Option<PendingKey>,
    new_key: Option<CertifiedKey>,
    current_key: Option<CertifiedKey>,
    revoke_key: Option<CertifiedKey>,
}

impl ResourceClass {
    /// Creates a new ResourceClass with a single pending key only.
    pub fn create(name_space: String, pending_key: SignerKeyId) -> Self {
        let pending_key = PendingKey::new(pending_key);
        ResourceClass {
            name_space,
            pending_key: Some(pending_key),
            new_key: None,
            current_key: None,
            revoke_key: None,
        }
    }

    pub fn add_request(&mut self, status: KeyStatus, req: IssuanceRequest) {
        match status {
            KeyStatus::Pending => {
                self.pending_key.as_mut().unwrap().add_request(req);
            }
            KeyStatus::New => {
                self.new_key.as_mut().unwrap().add_request(req);
            }
            KeyStatus::Current => {
                self.current_key.as_mut().unwrap().add_request(req);
            }
            KeyStatus::Revoke => {
                self.revoke_key.as_mut().unwrap().add_request(req);
            }
        }
    }

    pub fn name_space(&self) -> &str {
        &self.name_space
    }

    /// Returns the current objects under the new key.
    pub fn new_objects(&self) -> Option<&CurrentObjects> {
        self.new_key.as_ref().map(|k| k.current_set().objects())
    }

    /// Returns the current objects under the current key.
    pub fn current_objects(&self) -> Option<&CurrentObjects> {
        self.current_key.as_ref().map(|k| k.current_set().objects())
    }

    /// Returns the current objects under the key that is to be revoked.
    pub fn revoke_objects(&self) -> Option<&CurrentObjects> {
        self.revoke_key.as_ref().map(|k| k.current_set().objects())
    }

    /// Returns withdraws for all current objects, for when this resource class
    /// needs to be removed.
    pub fn withdraw(&self, base_repo: &RepoInfo) -> ObjectsDelta {
        let base_repo = base_repo.ca_repository(self.name_space());
        let mut delta = ObjectsDelta::new(base_repo);

        if let Some(objects) = self.new_objects() {
            for withdraw in objects.withdraw().into_iter() {
                delta.withdraw(withdraw);
            }
        }
        if let Some(objects) = self.current_objects() {
            for withdraw in objects.withdraw().into_iter() {
                delta.withdraw(withdraw);
            }
        }
        if let Some(objects) = self.revoke_objects() {
            for withdraw in objects.withdraw().into_iter() {
                delta.withdraw(withdraw);
            }
        }
        delta
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_received_cert<S: Signer>(
        &self,
        rcvd_cert: RcvdCert,
        base_repo: &RepoInfo,
        handle: &Handle,
        parent_handle: ParentHandle,
        class_name: ResourceClassName,
        version: u64,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let mut res = vec![];

        let mut status = self.status_for_cert(&rcvd_cert, signer.read().unwrap().deref())?;

        let event = if status == KeyStatus::Pending {
            self.update_cert_for_pending(
                &handle,
                &parent_handle,
                &class_name,
                rcvd_cert.clone(),
                self.new_status_for_pending(),
                version,
            )?
        } else {
            self.update_cert_for_certified_key(
                &handle,
                &parent_handle,
                &class_name,
                rcvd_cert.clone(),
                status,
                version,
            )
        };

        res.push(event);

        // Get the key that needs publishing and apply the cert to it.
        let key_to_publish = self.key_to_publish(status, rcvd_cert)?;

        // TODO: Check current objects in relation to resources
        //       and shrink/remove/add based on config.
        let ca_repo = base_repo.ca_repository(&self.name_space);
        let delta = ObjectsDelta::new(ca_repo);

        // Publish
        if status == KeyStatus::Pending {
            status = self.new_status_for_pending()
        }

        res.push(EvtDet::published(
            &handle,
            version + 1,
            parent_handle,
            class_name,
            status,
            SignSupport::publish(signer, &key_to_publish, base_repo, &self.name_space, delta)
                .map_err(Error::signer)?,
        ));

        Ok(res)
    }

    /// Updates the certificate for the pending key, and depending on whether
    /// this a key for a new resource class, or a pending key in a key roll,
    /// returns the correct lifecycle event.
    fn update_cert_for_pending(
        &self,
        handle: &Handle,
        parent_handle: &ParentHandle,
        class_name: &str,
        cert: RcvdCert,
        new_status: KeyStatus,
        version: u64,
    ) -> Result<Evt> {
        match new_status {
            KeyStatus::Pending => Err(Error::KeyStatusChange(
                KeyStatus::Pending,
                KeyStatus::Pending,
            )),

            KeyStatus::New => unimplemented!("Issue #23 (key rolls)"),

            KeyStatus::Current => Ok(EvtDet::pending_activated(
                handle,
                version,
                parent_handle.clone(),
                class_name.to_string(),
                cert,
            )),

            KeyStatus::Revoke => Err(Error::KeyStatusChange(
                KeyStatus::Pending,
                KeyStatus::Revoke,
            )),
        }
    }

    /// Returns an event for updating the certificate on an existing
    /// certified key.
    fn update_cert_for_certified_key(
        &self,
        handle: &Handle,
        parent_handle: &ParentHandle,
        class_name: &str,
        cert: RcvdCert,
        status: KeyStatus,
        version: u64,
    ) -> Evt {
        EvtDet::certificate_received(
            handle,
            version,
            parent_handle.clone(),
            class_name.to_string(),
            status,
            cert,
        )
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behaviour.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(
            self.name_space.clone(),
            self.pending_key.clone(),
            self.new_key.clone(),
            self.current_key.clone(),
            self.revoke_key.clone(),
        )
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Request a certificate for a key of the given status.
    pub fn request_cert<S: Signer>(
        &self,
        key_status: KeyStatus,
        entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &Arc<RwLock<S>>,
    ) -> Result<Option<IssuanceRequest>> {
        let signer = signer.read().map_err(Error::signer)?;

        let key_opt = match key_status {
            KeyStatus::Pending => self.pending_key.as_ref().map(|k| k.key_id()),
            KeyStatus::New => match self.new_key.as_ref() {
                None => None,
                Some(key) => {
                    if key.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                        Some(key.key_id())
                    } else {
                        None
                    }
                }
            },
            KeyStatus::Current => match self.current_key.as_ref() {
                None => None,
                Some(key) => {
                    if key.wants_update(entitlement.resource_set(), entitlement.not_after()) {
                        Some(key.key_id())
                    } else {
                        None
                    }
                }
            },
            KeyStatus::Revoke => return Err(Error::InvalidKeyStatus),
        };

        match key_opt {
            None => Ok(None),
            Some(key) => {
                let csr = self.create_csr(base_repo, key, signer.deref())?;
                Ok(Some(IssuanceRequest::new(
                    entitlement.class_name().to_string(),
                    RequestResourceLimit::default(),
                    csr,
                )))
            }
        }
    }

    /// Creates a Csr for the given key. Note that this parses the encoded
    /// key. This is not the most efficient way, but makes storing and
    /// serializing the Csr in an event possible (the Captured cannot be
    /// stored).
    fn create_csr<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        key: &SignerKeyId,
        signer: &S,
    ) -> Result<Csr> {
        let pub_key = signer.get_key_info(key).map_err(Error::signer)?;

        let enc = Csr::construct(
            signer,
            key,
            &base_repo.ca_repository(&self.name_space),
            &base_repo.rpki_manifest(&self.name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(Error::signer)?;

        let csr = Csr::decode(enc.as_slice()).map_err(Error::signer)?;

        Ok(csr)
    }
}

/// # Publishing
///
impl ResourceClass {
    /// Applies a publication delta to the appropriate key in this resource class.
    pub fn apply_delta(&mut self, delta: PublicationDelta, key_status: KeyStatus) {
        match key_status {
            KeyStatus::Pending => None,
            KeyStatus::New => self.new_key.as_mut(),
            KeyStatus::Current => self.current_key.as_mut(),
            KeyStatus::Revoke => self.revoke_key.as_mut(),
        }
        .unwrap()
        .apply_delta(delta)
    }
}

/// # Key Life Cycle and Receiving Certificates
///
impl ResourceClass {
    /// This function activates the pending key.
    ///
    /// This can only happen based on an event that happens when a pending
    /// key for a new resource class is activated. Therefore the current key
    /// can simply be overwritten.
    pub fn pending_key_activated(&mut self, cert: RcvdCert) {
        let (key_id, _req) = self.pending_key.take().unwrap().unwrap();
        let certified_key = CertifiedKey::new(key_id, cert);
        self.current_key = Some(certified_key);
    }

    /// This function marks a certificate as received.
    pub fn received_cert(&mut self, status: KeyStatus, cert: RcvdCert) {
        match status {
            KeyStatus::Pending => unimplemented!("Key roll, see issue #23"),
            KeyStatus::New => unimplemented!("Key roll, see issue #23"),
            KeyStatus::Current => {
                if let Some(key) = self.current_key.as_mut() {
                    key.set_incoming_cert(cert)
                };
            }
            KeyStatus::Revoke => unimplemented!("Should never request cert for this key"),
        }
    }

    /// This function returns all current certificate requests.
    pub fn cert_requests(&self) -> Vec<IssuanceRequest> {
        let mut res = vec![];
        if let Some(p) = self.pending_key.as_ref() {
            if let Some(r) = p.request() {
                res.push(r.clone());
            }
        }
        if let Some(p) = self.new_key.as_ref() {
            if let Some(r) = p.request() {
                res.push(r.clone())
            }
        }
        if let Some(p) = self.current_key.as_ref() {
            if let Some(r) = p.request() {
                res.push(r.clone())
            }
        }

        res
    }

    /// Returns the new status for a pending key which receives a RcvdCert.
    pub fn new_status_for_pending(&self) -> KeyStatus {
        if self.current_key.is_some() {
            KeyStatus::New
        } else {
            KeyStatus::Current
        }
    }

    /// This function will find the status of the matching key for a received
    /// certificate. An error is returned if no matching key could be found.
    pub fn status_for_cert<S: Signer>(
        &self,
        rcvd_cert: &RcvdCert,
        signer: &S,
    ) -> Result<KeyStatus> {
        self.match_key(rcvd_cert.cert().subject_public_key_info(), signer)
    }

    pub fn key_to_publish(&self, status: KeyStatus, rcvd_cert: RcvdCert) -> Result<CertifiedKey> {
        Ok(match status {
            KeyStatus::Pending => {
                let (key_id, _req) = self
                    .pending_key
                    .clone()
                    .ok_or_else(|| Error::InvalidKeyStatus)?
                    .unwrap();
                CertifiedKey::new(key_id, rcvd_cert)
            }
            KeyStatus::New => self
                .new_key
                .clone()
                .ok_or_else(|| Error::InvalidKeyStatus)?
                .with_new_cert(rcvd_cert),
            KeyStatus::Current => self
                .current_key
                .clone()
                .ok_or_else(|| Error::InvalidKeyStatus)?
                .with_new_cert(rcvd_cert),
            KeyStatus::Revoke => self
                .revoke_key
                .clone()
                .ok_or_else(|| Error::InvalidKeyStatus)?
                .with_new_cert(rcvd_cert),
        })
    }

    /// Helper to find which of the key_id-s of held keys in different stages
    /// match the public key, and return that status. Returns an error if
    /// there is no match.
    fn match_key<S: Signer>(&self, pub_key: &PublicKey, signer: &S) -> ca::Result<KeyStatus> {
        if self.matches_key_id(
            self.pending_key.as_ref().map(PendingKey::key_id),
            pub_key,
            signer,
        ) {
            return Ok(KeyStatus::Pending);
        }

        if self.matches_key_id(
            self.new_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer,
        ) {
            return Ok(KeyStatus::New);
        }

        if self.matches_key_id(
            self.current_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer,
        ) {
            return Ok(KeyStatus::Current);
        }

        if self.matches_key_id(
            self.revoke_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer,
        ) {
            return Ok(KeyStatus::Revoke);
        }

        Err(Error::NoKeyMatch(KeyRef::from(&pub_key.key_identifier())))
    }

    /// Helper to match a key_id to a pub key.
    fn matches_key_id<S: Signer>(
        &self,
        key_id: Option<&SignerKeyId>,
        pub_key: &PublicKey,
        signer: &S,
    ) -> bool {
        if let Some(id) = key_id {
            if let Ok(info) = signer.get_key_info(id) {
                &info == pub_key
            } else {
                false
            }
        } else {
            false
        }
    }
}

//------------ KeyStatus -----------------------------------------------------

#[derive(Copy, Clone, Debug, Deserialize, Display, Eq, Serialize, PartialEq)]
pub enum KeyStatus {
    Pending,
    New,
    Current,
    Revoke,
}
