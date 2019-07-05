use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use rpki::crypto::{PublicKey, PublicKeyFormat};
use rpki::csr::Csr;

use krill_commons::api::{EntitlementClass, Entitlements, IssuanceRequest};
use krill_commons::api::admin::{Handle, ParentCaContact, Token};
use krill_commons::api::ca::{
    AllCurrentObjects,
    CertifiedKey,
    KeyRef,
    ObjectsDelta,
    PublicationDelta,
    RcvdCert,
    RepoInfo,
    ResourceSet,
};
use krill_commons::eventsourcing::{
    Aggregate,
    CommandDetails,
    SentCommand,
    StoredEvent,
};
use krill_commons::util::softsigner::SignerKeyId;

use crate::trustanchor::CaSigner;
use crate::signing::CaSignSupport;

pub const CA_NS: &str = "cas";

//------------ CertAuthInit --------------------------------------------------

pub type CaIni = StoredEvent<CaIniDet>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaIniDet(Token, RepoInfo);

impl CaIniDet {
    pub fn init(
        handle: &Handle,
        token: Token,
        info: RepoInfo
    ) -> CaIni {
        CaIni::new(
            handle,
            0,
            CaIniDet(token, info)
        )
    }
}


//------------ CaEvt -------------------------------------------------------

pub type CaEvt = StoredEvent<CaEvtDet>;


//------------ CertRequested -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertRequested {
    parent: ParentCaContact,
    class_name: String,
    resource_limit: Option<ResourceSet>,
    csr: Csr
}

impl CertRequested {
    pub fn unwrap(self) -> (ParentCaContact, String, Option<ResourceSet>, Csr) {
        (self.parent, self.class_name, self.resource_limit, self.csr)
    }
    pub fn parent(&self) -> &ParentCaContact {
        &self.parent
    }
    pub fn class_name(&self) -> &str {
        &self.class_name
    }
    pub fn resource_limit(&self) -> Option<&ResourceSet> {
        self.resource_limit.as_ref()
    }
    pub fn csr(&self) -> &Csr {
        &self.csr
    }
}

impl Into<IssuanceRequest> for CertRequested {
    fn into(self) -> IssuanceRequest {
        IssuanceRequest::new(
            self.class_name, self.resource_limit, self.csr
        )
    }
}


//------------ CertReceived ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertReceived {
    parent: ParentHandle,
    class_name: ResourceClassName,
    key_status: KeyStatus,
    cert: RcvdCert
}


//------------ CaEvtDet ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CaEvtDet {
    // Parent Events
    ParentAdded(ParentHandle, ParentCaContact),
    ResourceClassAdded(ParentHandle, ResourceClassName, ResourceClass),

    // Certificate Events
    CertificateRequested(CertRequested),
    CertificateReceived(CertReceived),

    // Key Life Cycle Events
    PendingKeyActivated(ParentHandle, ResourceClassName, RcvdCert),

    // Publishing
    Published(ParentHandle, ResourceClassName, KeyStatus, PublicationDelta)
}

impl CaEvtDet {
    /// This marks a parent as added to the CA.
    pub fn parent_added(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        info: ParentCaContact
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ParentAdded(parent_handle, info)
        )
    }

    /// This marks a resource class as added under a parent for the CA.
    pub fn resource_class_added(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        class_name: String,
        resource_class: ResourceClass
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ResourceClassAdded(
                parent_handle, class_name, resource_class
            )
        )
    }

    /// This marks that a certificate has been requested. This does not result
    /// in any status change inside the CA and is intended to be picked up by
    /// a listener which will contact the parent of this CA. If that listener
    /// then gets a new certificate, it will send a command to the CA with
    /// the new certificate to mark it as received, and take other
    /// appriopiate actions (key life cycle, publication).
    pub fn certificate_requested(
        handle: &Handle,
        version: u64,
        cert_issue_req: CertRequested
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::CertificateRequested(cert_issue_req)
        )
    }

    /// This marks a certificate as received for the key of the given status
    /// in a given resource class under a parent.
    pub fn certificate_received(
        handle: &Handle,
        version: u64,
        received: CertReceived
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::CertificateReceived(received)
        )
    }

    /// This marks the pending key as activated. This occurs when a resource
    /// class that was initialised with a pending key has received the
    /// certificate for the pending key.
    ///
    /// Note that key roll management is going to be implemented in the near
    /// future and then there will also be appropriate events for all the
    /// stages in a key roll.
    pub fn pending_activated(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        class_name: ResourceClassName,
        received: RcvdCert
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::PendingKeyActivated(parent, class_name, received)
        )
    }

    /// This marks a delta as published for a key under a resource class
    /// under a parent CA.
    pub fn published(
        handle: &Handle,
        version: u64,
        parent: ParentHandle,
        class_name: ResourceClassName,
        key_status: KeyStatus,
        delta: PublicationDelta
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::Published(parent, class_name, key_status, delta)
        )
    }
}


//------------ CertAuthCommand ---------------------------------------------

pub type CaCmd<S> = SentCommand<CaCmdDet<S>>;

type ParentHandle = Handle;
type ResourceClassName = String;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CaCmdDet<S: CaSigner> {
    AddParent(ParentHandle, ParentCaContact),
    UpdateEntitlements(ParentHandle, Entitlements, Arc<RwLock<S>>),
    UpdateRcvdCert(
        ParentHandle,
        ResourceClassName,
        RcvdCert,
        Arc<RwLock<S>>
    )
}

impl<S: CaSigner> CommandDetails for CaCmdDet<S> {
    type Event = CaEvt;
}

impl<S: CaSigner> CaCmdDet<S> {
    pub fn add_parent(
        handle: &Handle,
        name: &str,
        info: ParentCaContact
    ) -> CaCmd<S> {
        SentCommand::new(
            handle,
            None,
            CaCmdDet::AddParent(Handle::from(name), info)
        )
    }

    pub fn upd_entitlements(
        handle: &Handle,
        parent: &ParentHandle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>
    ) -> CaCmd<S> {
        SentCommand::new(
            handle,
            None,
            CaCmdDet::UpdateEntitlements(
                parent.clone(),
                entitlements,
                signer
            )
        )
    }

    pub fn upd_received_cert(
        handle: &Handle,
        parent: &ParentHandle,
        class_name: &str,
        cert: RcvdCert,
        signer: Arc<RwLock<S>>
    ) -> CaCmd<S> {
        SentCommand::new(
            handle,
            None,
            CaCmdDet::UpdateRcvdCert(
                parent.clone(),
                class_name.to_string(),
                cert,
                signer
            )
        )
    }
}


//------------ CertAuth ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertAuth<S: CaSigner> {
    handle: Handle,
    version: u64,

    token: Token, // The admin token for this CertAuth

    base_repo: RepoInfo,
    parents: HashMap<Handle, ParentCa>,

    phantom_signer: PhantomData<S>
}


pub type CaRes<T> = Result<T, Error>;
pub type CaEvtsRes = CaRes<Vec<CaEvt>>;

impl<S: CaSigner> Aggregate for CertAuth<S> {
    type Command = CaCmd<S>;
    type Event = CaEvt;
    type InitEvent = CaIni;
    type Error = Error;

    fn init(event: CaIni) -> CaRes<Self> {
        let (handle, _version, details) = event.unwrap();

        let token = details.0;
        let base_repo = details.1;

        let parents = HashMap::new();

        Ok(CertAuth {
            handle,
            version: 1,

            token,
            base_repo,
            parents,
            phantom_signer: PhantomData
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: CaEvt) {
        self.version += 1;
        match event.into_details() {
            CaEvtDet::ParentAdded(handle, info) => {
                let parent = ParentCa::without_resource(info);
                self.parents.insert(handle, parent);
            },
            CaEvtDet::ResourceClassAdded(parent, name, rc) => {
                // Evt cannot occur without parent existing
                self.parents.get_mut(&parent).unwrap()
                    .resources.insert(name, rc);
            }
            CaEvtDet::CertificateRequested(req) => {
                info!(
                    "Certificate requested for class {} from {}",
                    req.class_name,
                    req.parent
                );
                // do nothing, this should be picked up by listener and sent
                // to parent
            },
            CaEvtDet::PendingKeyActivated(parent, class_name, cert) => {
                let mut parent = self.parent_mut(parent).unwrap();
                let mut rc = parent.class_mut(&class_name).unwrap();
                rc.pending_key_activated(cert);
            }
            CaEvtDet::CertificateReceived(_rcvd) => {
                unimplemented!()
            },
            CaEvtDet::Published(parent, class_name, status, delta) => {
                let mut parent = self.parent_mut(parent).unwrap();
                let mut rc = parent.class_mut(&class_name).unwrap();
                let mut ck = rc.get_key_mut(&status).unwrap();
                ck.apply_delta(delta);
            }

        }
    }

    fn process_command(&self, command: CaCmd<S>) -> CaEvtsRes {
        match command.into_details() {
            CaCmdDet::AddParent(parent, info) => {
                self.add_parent(parent,info)
            },
            CaCmdDet::UpdateEntitlements(parent, entitlements, signer) => {
                self.update_entitlements(parent, entitlements, signer)
            },
            CaCmdDet::UpdateRcvdCert(parent, class_name, rcvd_cert, signer) => {
                self.update_received_cert(parent, class_name, rcvd_cert, signer)
            }
        }
    }
}

/// # Publishing
///
impl<S: CaSigner> CertAuth<S> {
    /// Returns all current objects for all parents, resource classes and keys
    pub fn current_objects(&self) -> AllCurrentObjects {
        AllCurrentObjects::empty()
    }
}

/// # Manage parents & resources under parents
///
impl<S: CaSigner> CertAuth<S> {
    /// List all parents
    pub fn parents(&self) -> impl Iterator<Item=(&Handle, &ParentCa)>{
        self.parents.iter()
    }

    fn parent(&self, parent: Handle) -> CaRes<&ParentCa> {
        self.parents.get(&parent).ok_or_else(|| Error::UnknownParent(parent))
    }

    fn parent_mut(&mut self, parent: Handle) -> CaRes<&mut ParentCa> {
        self.parents.get_mut(&parent).ok_or_else(|| Error::UnknownParent(parent))
    }

    /// Adds a parent. This method will return an error in case a parent
    /// by this name (handle) is already known.
    fn add_parent(&self, parent: Handle, info: ParentCaContact) -> CaEvtsRes {
        if self.parents.contains_key(&parent) {
            Err(Error::DuplicateParent(parent))
        } else {
            Ok(vec![CaEvtDet::parent_added(
                &self.handle,
                self.version,
                parent,
                info
            )])
        }
    }

    /// This processes entitlements from a parent, and updates the known
    /// entitlement(s) and/or requests certificate(s) as needed. In case
    /// there are no changes in entitlements and certificates, this method
    /// will result in 0 events - i.e. it is then a no-op.
    fn update_entitlements(
        &self,
        parent_handle: Handle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>
    ) -> CaEvtsRes {
        let mut res = vec![];

        let parent = self.parent(parent_handle.clone())?;

        // Check if there is a resource class for each entitlement
        let mut version = self.version;
        for ent in entitlements.classes() {

            let name = ent.name();

            if let Some(_rc) = parent.resources.get(name) {
                // Check whether a new certificate
                // should be requested.
                // I.e. we only have a pending key, or
                // the current key certificate does not
                // match the entitled validity time or
                // resources.
                unimplemented!()
            } else {
                // Create a resource class with a pending key
                let key_id = {
                    signer.write().unwrap()
                        .create_key(PublicKeyFormat::default())
                        .map_err(Error::signer)?
                };

                let ns = format!("{}-{}", &parent_handle, name);
                let rc = ResourceClass::create(ns, key_id);

                // Create certificate sign request
                let csr = {
                    // there must be simpler way to take the one CSR
                    // that must be in the resulting Vec
                    rc.request_certs(
                        ent,
                        &self.base_repo,
                        &signer
                    )?.into_iter().next().unwrap()
                };

                let cert_issue_req = CertRequested {
                    parent: parent.contact.clone(),
                    class_name: ent.name().to_string(),
                    resource_limit: None,
                    csr
                };

                let added = CaEvtDet::resource_class_added(
                    &self.handle,
                    version,
                    parent_handle.clone(),
                    name.to_string(),
                    rc
                );

                version += 1;

                let req = CaEvtDet::certificate_requested(
                    &self.handle,
                    version,
                    cert_issue_req
                );

                version += 1;

                res.push(added);
                res.push(req);
            }
        }
        Ok(res)
    }


    /// This method updates the received certificate for the given parent
    /// and resource class, and will return an error if either is unknown.
    ///
    /// It will generate an event for the certificate that is received, and
    /// if it was received for a pending key it will return an event to promote
    /// the pending key appropriately, finally it will also return a
    /// publication event for the matching key if publication is needed.
    ///
    /// In future, when ROAs and delegating certificates are supported, this
    /// should be updated to also generate appropriate events for changes
    /// affecting these objects if needed - e.g. because resources were lost
    /// and ROAs/Certs would be become invalid.
    fn update_received_cert(
        &self,
        parent_handle: Handle,
        class_name: String,
        rcvd_cert: RcvdCert,
        signer: Arc<RwLock<S>>
    ) -> CaEvtsRes {
        let parent = self.parent(parent_handle.clone())?;
        let rc = parent.class(&class_name)?;


        let mut res = vec![];

        let (mut status, new_status) = rc.match_cert(
            &rcvd_cert,
            signer.read().unwrap().deref()
        )?;

        let handle = &self.handle;
        let mut version = self.version;

        let event = if status == KeyStatus::Pending {
            self.update_cert_for_pending(
                &handle,
                &parent_handle,
                &class_name,
                rcvd_cert.clone(),
                new_status.clone().unwrap(),
                version
            )?
        } else {
            self.update_cert_for_certified_key(
                &handle,
                &parent_handle,
                &class_name,
                rcvd_cert.clone(),
                status.clone(),
                version
            )
        };

        res.push(event);
        version += 1;


        // Get the key that needs publishing and apply the cert to it.
        let key_to_publish = match status {
            KeyStatus::Pending => {
                CertifiedKey::new(rc.pending_key.clone().unwrap(), rcvd_cert)
            },
            KeyStatus::New => {
                rc.new_key.clone().unwrap().with_new_cert(rcvd_cert)
            },
            KeyStatus::Current => {
                rc.current_key.clone().unwrap().with_new_cert(rcvd_cert)
            },
            KeyStatus::Revoke => {
                rc.revoke_key.clone().unwrap().with_new_cert(rcvd_cert)
            },
        };

        // TODO: Check current objects in relation to resources
        //       and shrink/remove/add based on config.
        let ca_repo = self.base_repo.ca_repository(&rc.name_space);
        let delta = ObjectsDelta::new(ca_repo);

        // Publish
        if status == KeyStatus::Pending {
            status = new_status.unwrap()
        }

        res.push(CaEvtDet::published(
            &handle,
            version,
            parent_handle,
            class_name,
            status,
            CaSignSupport::publish(
                signer,
                &key_to_publish,
                &self.base_repo,
                &rc.name_space,
                delta
            ).map_err(Error::signer)?
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
    ) -> CaRes<CaEvt> {
        match new_status {
            KeyStatus::Pending =>
                Err(Error::KeyStatusChange(KeyStatus::Pending,
                                           KeyStatus::Pending)),

            KeyStatus::New => unimplemented!(), // needed for key rolls

            KeyStatus::Current => {
                Ok(CaEvtDet::pending_activated(
                    handle,
                    version,
                    parent_handle.clone(),
                    class_name.to_string(),
                    cert
                ))
            },

            KeyStatus::Revoke =>
                Err(Error::KeyStatusChange(KeyStatus::Pending,
                                           KeyStatus::Revoke))
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
    ) -> CaEvt {
        CaEvtDet::certificate_received(
            handle,
            version,
            CertReceived {
                parent: parent_handle.clone(),
                class_name: class_name.to_string(),
                key_status: status,
                cert
            }
        )
    }
}


//------------ ParentCa ------------------------------------------------------

/// This type defines a parent for a CA and includes the information
/// needed to contact it, as well as a map of all the ResourceClass-es
/// that the CA has under this parent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParentCa {
    contact: ParentCaContact,
    resources: HashMap<String, ResourceClass>
}

impl ParentCa {
    pub fn without_resource(contact: ParentCaContact) -> Self {
        ParentCa { contact, resources: HashMap::new() }
    }

    pub fn contact(&self) -> &ParentCaContact { &self.contact }

    fn class(&self, class_name: &str) -> CaRes<&ResourceClass> {
        self.resources.get(class_name)
            .ok_or_else(|| Error::UnknownResourceClass(class_name.to_string()))
    }

    fn class_mut(&mut self, class_name: &str) -> CaRes<&mut ResourceClass> {
        self.resources.get_mut(class_name)
            .ok_or_else(|| Error::UnknownResourceClass(class_name.to_string()))
    }
}

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
    pending_key: Option<SignerKeyId>,
    new_key: Option<CertifiedKey>,
    current_key: Option<CertifiedKey>,
    revoke_key: Option<CertifiedKey>
}

impl ResourceClass {
    /// Creates a new ResourceClass with a single pending key only.
    pub fn create(name_space: String, pending_key: SignerKeyId) -> Self {
        ResourceClass {
            name_space,
            pending_key: Some(pending_key),
            new_key: None,
            current_key: None,
            revoke_key: None
        }
    }
}

/// # Request certificates
///
impl ResourceClass {
    /// Creates CSRs for all keys in this resource class that can use a new
    /// certificate based on the current cert they have, and the entitlement.
    pub fn request_certs<S: CaSigner>(
        &self,
        _entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &Arc<RwLock<S>>
    ) -> CaRes<Vec<Csr>> {
        let mut res = vec![];
        let signer = signer.read().map_err(Error::signer)?;

        if let Some(key) = self.pending_key.as_ref() {
            let csr = self.create_csr(base_repo, key, signer.deref())?;
            res.push(csr)
        }

        if self.new_key.is_some() ||
            self.current_key.is_some() ||
            self.revoke_key.is_some() {
            // TODO Request updated cert for keys with cert if needed
            unimplemented!()
        }

        Ok(res)
    }

    /// Creates a Csr for the given key. Note that this parses the encoded
    /// key. This is not the most efficient way, but makes storing and
    /// serializing the Csr in an event possible (the Captured cannot be
    /// stored).
    fn create_csr<S: CaSigner>(
        &self,
        base_repo: &RepoInfo,
        key: &SignerKeyId,
        signer: &S
    ) -> CaRes<Csr> {
        let pub_key = signer.get_key_info(key).map_err(Error::signer)?;

        let enc = Csr::construct(
            signer,
            key,
            &base_repo.ca_repository(&self.name_space),
            &base_repo.rpki_manifest(&self.name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify())).map_err(Error::signer)?;

        let csr = Csr::decode(enc.as_slice()).map_err(Error::signer)?;

        Ok(csr)
    }
}


/// # Key Life Cycle and Receiving Certificates
///
impl ResourceClass {

    /// Gets a mutable reference to a certified key of the given status.
    fn get_key_mut(&mut self, status: &KeyStatus) -> Option<&mut CertifiedKey> {
        match status {
            KeyStatus::Pending => None,
            KeyStatus::New => self.new_key.as_mut(),
            KeyStatus::Current => self.current_key.as_mut(),
            KeyStatus::Revoke => self.revoke_key.as_mut()
        }
    }

    /// This function activates the pending key.
    ///
    /// This can only happen based on an event that happens when a pending
    /// key for a new resource class is activated. Therefore the current key
    /// can simply be overwritten.
    fn pending_key_activated(&mut self, cert: RcvdCert) {
        let key_id = self.pending_key.take().unwrap();
        let certified_key = CertifiedKey::new(key_id, cert);
        self.current_key = Some(certified_key);
    }

    /// This function will find the status of the matching key for a received
    /// certificate, and if it is a pending key it will also return the
    /// appropriate state change for that key. An error is returned if no
    /// matching key could be found.
    fn match_cert<S: CaSigner>(
        &self,
        rcvd_cert: &RcvdCert,
        signer: &S
    ) -> CaRes<(KeyStatus, Option<KeyStatus>)> {
        let status = self.match_key(
            rcvd_cert.cert().subject_public_key_info(),
            signer
        )?;

        let change = if status == KeyStatus::Pending {
            match self.current_key {
                None => Some(KeyStatus::Current),
                Some(_) => Some(KeyStatus::New)
            }
        } else {
            None
        };

        Ok((status, change))
    }

    /// Helper to find which of the key_id-s of held keys in different stages
    /// match the public key, and return that status. Returns an error if
    /// there is no match.
    fn match_key<S: CaSigner>(
        &self,
        pub_key: &PublicKey,
        signer: &S
    ) -> Result<KeyStatus, Error> {

        if self.matches_key_id(
            self.pending_key.as_ref(),
            pub_key,
            signer
        ) {
            return Ok(KeyStatus::Pending)
        }

        if self.matches_key_id(
            self.new_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer
        ) {
            return Ok(KeyStatus::New)
        }

        if self.matches_key_id(
            self.current_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer
        ) {
            return Ok(KeyStatus::Current)
        }

        if self.matches_key_id(
            self.revoke_key.as_ref().map(CertifiedKey::key_id),
            pub_key,
            signer
        ) {
            return Ok(KeyStatus::Revoke)
        }

        Err(Error::NoKeyMatch(KeyRef::from(&pub_key.key_identifier())))
    }

    /// Helper to match a key_id to a pub key.
    fn matches_key_id<S: CaSigner>(
        &self,
        key_id: Option<&SignerKeyId>,
        pub_key: &PublicKey,
        signer: &S
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

#[derive(Clone, Debug, Deserialize, Display, Eq, Serialize, PartialEq)]
pub enum KeyStatus {
    Pending,
    New,
    Current,
    Revoke
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum  Error {
    #[display(fmt = "Duplicate parent added: {}", _0)]
    DuplicateParent(Handle),

    #[display(fmt = "Got response for unknown parent: {}", _0)]
    UnknownParent(Handle),

    #[display(fmt = "Got response for unknown resource class: {}", _0)]
    UnknownResourceClass(String),

    #[display(fmt = "No key held by CA matching issued certificate: {}", _0)]
    NoKeyMatch(KeyRef),

    #[display(fmt = "Signing issue: {}", _0)]
    SignerError(String),

    #[display(fmt = "Key cannot change from status {} to {}", _0, _1)]
    KeyStatusChange(KeyStatus, KeyStatus),
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }
}

impl std::error::Error for Error {}
