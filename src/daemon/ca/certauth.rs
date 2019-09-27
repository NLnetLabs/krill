use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::Cert;
use rpki::crypto::{KeyIdentifier, PublicKey, PublicKeyFormat};

use crate::commons::api::{
    self, CertAuthInfo, ChildHandle, EntitlementClass, Entitlements, Handle, IssuanceRequest,
    IssuanceResponse, IssuedCert, ObjectsDelta, ParentCaContact, ParentHandle, PubServerContact,
    RcvdCert, RepoInfo, RequestResourceLimit, ResourceClassName, ResourceSet, RevocationRequest,
    RevocationResponse, RouteAuthorization, RouteAuthorizationUpdates, SigningCert, Token,
    UpdateChildRequest,
};
use crate::commons::eventsourcing::{Aggregate, StoredEvent};
use crate::commons::remote::builder::{IdCertBuilder, SignedMessageBuilder};
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc6492;
use crate::commons::remote::rfc8183::ChildRequest;
use crate::commons::remote::sigmsg::SignedMessage;
use crate::daemon::ca::rc::PublishMode;
use crate::daemon::ca::signing::CsrInfo;
use crate::daemon::ca::{
    self, ta_handle, ChildDetails, Cmd, CmdDet, CurrentObjectSetDelta, Error, Evt, EvtDet, Ini,
    ResourceClass, Result, Routes, Signer,
};

//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: KeyIdentifier,
    cert: IdCert,
}

impl Rfc8183Id {
    pub fn generate<S: Signer>(signer: &mut S) -> Result<Self> {
        let key = signer
            .create_key(PublicKeyFormat::default())
            .map_err(|e| Error::SignerError(e.to_string()))?;
        let cert = IdCertBuilder::new_ta_id_cert(&key, signer.deref())
            .map_err(|e| Error::SignerError(e.to_string()))?;
        Ok(Rfc8183Id { key, cert })
    }
}

//------------ CertAuth ----------------------------------------------------

/// This type defines a Certification Authority at a slightly higher level
/// than one might expect.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertAuth<S: Signer> {
    handle: Handle,
    version: u64,

    token: Token,  // The admin token to access this CertAuth
    id: Rfc8183Id, // Used for RFC 6492 (up-down) and RFC 8181 (publication)

    base_repo: RepoInfo,
    pubserver: PubServerContact, // TODO, allow remote

    parents: HashMap<ParentHandle, ParentCaContact>,

    next_class_name: u32,
    resources: HashMap<ResourceClassName, ResourceClass>,

    children: HashMap<ChildHandle, ChildDetails>,

    routes: Routes,

    phantom_signer: PhantomData<S>,
}

impl<S: Signer> Aggregate for CertAuth<S> {
    type Command = Cmd<S>;
    type Event = Evt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Ini) -> Result<Self> {
        let (handle, _version, details) = event.unwrap();
        let (token, id, base_repo, ta_opt) = details.unwrap();

        let pubserver = PubServerContact::embedded(); // TODO: support remote

        let mut parents = HashMap::new();
        let mut resources = HashMap::new();
        let mut next_class_name = 0;

        if let Some(ta_details) = ta_opt {
            let key_id = ta_details.cert().subject_key_identifier();
            parents.insert(ta_handle(), ParentCaContact::Ta(ta_details));

            let rcn = ResourceClassName::from(next_class_name);
            next_class_name += 1;
            resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
        }

        let children = HashMap::new();
        let routes = Routes::default();

        Ok(CertAuth {
            handle,
            version: 1,

            token,
            id,

            base_repo,
            pubserver,

            parents,

            next_class_name,
            resources,

            children,

            routes,

            phantom_signer: PhantomData,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Evt) {
        self.version += 1;
        match event.into_details() {
            //-----------------------------------------------------------------------
            // Being a parent
            //-----------------------------------------------------------------------
            EvtDet::ChildAdded(child, details) => {
                self.children.insert(child, details);
            }
            EvtDet::ChildCertificateIssued(child, response) => {
                self.resources
                    .get_mut(response.class_name())
                    .unwrap()
                    .certificate_issued(response.issued().clone());

                self.children
                    .get_mut(&child)
                    .unwrap()
                    .add_issue_response(response);
            }

            EvtDet::ChildKeyRevoked(child, response) => {
                self.resources
                    .get_mut(response.class_name())
                    .unwrap()
                    .key_revoked(response.key());

                self.children
                    .get_mut(&child)
                    .unwrap()
                    .add_revoke_response(response);
            }

            EvtDet::ChildUpdatedIdCert(child, cert) => {
                self.children.get_mut(&child).unwrap().set_id_cert(cert)
            }

            EvtDet::ChildUpdatedResources(child, resources, grace) => self
                .children
                .get_mut(&child)
                .unwrap()
                .set_resources(resources, grace),

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            EvtDet::ParentAdded(handle, info) => {
                self.parents.insert(handle, info);
            }
            EvtDet::ResourceClassAdded(name, rc) => {
                self.next_class_name += 1;
                self.resources.insert(name, rc);
            }
            EvtDet::ResourceClassRemoved(name, _delta, _parent, _revocations) => {
                self.resources.remove(&name);
            }
            EvtDet::CertificateRequested(name, req, status) => {
                self.resources
                    .get_mut(&name)
                    .unwrap()
                    .add_request(status, req);
            }
            EvtDet::CertificateReceived(class_name, key_id, cert) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .received_cert(key_id, cert);
            }

            //-----------------------------------------------------------------------
            // Key Life Cycle
            //-----------------------------------------------------------------------
            EvtDet::KeyRollPendingKeyAdded(class_name, key_id) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .pending_key_added(key_id);
            }
            EvtDet::KeyPendingToNew(rcn, key, _delta) => {
                self.resources
                    .get_mut(&rcn)
                    .unwrap()
                    .pending_key_to_new(key);
            }
            EvtDet::KeyPendingToActive(rcn, key, _delta) => {
                self.resources
                    .get_mut(&rcn)
                    .unwrap()
                    .pending_key_to_active(key);
            }
            EvtDet::KeyRollActivated(class_name, revoke_req) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .new_key_activated(revoke_req);
            }
            EvtDet::KeyRollFinished(class_name, _delta) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .old_key_removed();
            }

            //-----------------------------------------------------------------------
            // Route Authorizations
            //-----------------------------------------------------------------------
            EvtDet::RouteAuthorizationAdded(update) => self.routes.add(update),
            EvtDet::RouteAuthorizationRemoved(removal) => self.routes.remove(&removal),
            EvtDet::RoasUpdated(rcn, updates) => {
                self.resources.get_mut(&rcn).unwrap().roas_updated(updates)
            }

            //-----------------------------------------------------------------------
            // General functions
            //-----------------------------------------------------------------------
            EvtDet::ObjectSetUpdated(class_name, delta_map) => {
                let rc = self.resources.get_mut(&class_name).unwrap();
                for (key_id, delta) in delta_map.into_iter() {
                    rc.apply_delta(delta, key_id);
                }
            }
        }
    }

    fn process_command(&self, command: Cmd<S>) -> ca::Result<Vec<Evt>> {
        match command.into_details() {
            // being a parent
            CmdDet::ChildAdd(child, id_cert_opt, resources) => {
                self.add_child(child, id_cert_opt, resources)
            }
            CmdDet::ChildUpdate(child, req) => self.update_child(&child, req),
            CmdDet::ChildCertify(child, request, signer) => {
                self.certify_child(child, request, signer)
            }
            CmdDet::ChildRevokeKey(child, request, signer) => {
                self.revoke_child_key(child, request, signer)
            }
            CmdDet::ChildShrink(child, signer) => self.shrink_child(&child, signer),

            // being a child
            CmdDet::AddParent(parent, info) => self.add_parent(parent, info),
            CmdDet::UpdateResourceClasses(parent, entitlements, signer) => {
                self.update_resource_classes(parent, entitlements, signer)
            }
            CmdDet::UpdateRcvdCert(class_name, rcvd_cert, signer) => {
                self.update_received_cert(class_name, rcvd_cert, signer)
            }

            // Key rolls
            CmdDet::KeyRollInitiate(duration, signer) => self.keyroll_initiate(duration, signer),
            CmdDet::KeyRollActivate(duration, signer) => self.keyroll_activate(duration, signer),
            CmdDet::KeyRollFinish(rcn, response) => self.keyroll_finish(rcn, response),

            // Route Authorizations
            CmdDet::RouteAuthorizationsUpdate(updates, signer) => {
                self.route_authorizations_update(updates, signer)
            }

            // Republish
            CmdDet::Republish(signer) => self.republish(signer),
        }
    }
}

/// # Data presentation
///
impl<S: Signer> CertAuth<S> {
    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let base_repo = self.base_repo.clone();

        let parents = self.parents.clone();

        let mut resources = HashMap::new();

        for (name, rc) in &self.resources {
            resources.insert(name.clone(), rc.as_info());
        }
        let mut children = HashMap::new();
        for (handle, details) in &self.children {
            children.insert(handle.clone(), details.clone().into());
        }

        let authorizations = self.routes.authorizations().cloned().collect();

        CertAuthInfo::new(
            handle,
            base_repo,
            parents,
            resources,
            children,
            authorizations,
        )
    }

    pub fn child_request(&self) -> ChildRequest {
        ChildRequest::new(self.handle.clone(), self.id.cert.clone())
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id.cert
    }
    pub fn id_key(&self) -> &KeyIdentifier {
        &self.id.key
    }
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn all_resources(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for rc in self.resources.values() {
            if let Some(rc_resources) = rc.current_resources() {
                resources = resources.union(rc_resources);
            }
        }
        resources
    }
}

/// # Being a parent
///
impl<S: Signer> CertAuth<S> {
    pub fn verify_rfc6492(&self, msg: SignedMessage) -> Result<rfc6492::Message> {
        let content = rfc6492::Message::from_signed_message(&msg)?;

        let child_handle = content.sender();
        let child = self.get_child(child_handle)?;

        let child_cert = child
            .id_cert()
            .ok_or_else(|| Error::Unauthorized(child_handle.clone()))?;

        msg.validate(child_cert)
            .map_err(|_| Error::InvalidRfc6492)?;

        Ok(content)
    }

    pub fn sign_rfc6492_response(&self, msg: rfc6492::Message, signer: &S) -> Result<Bytes> {
        let key = &self.id.key;
        Ok(SignedMessageBuilder::create(key, signer, msg.into_bytes())
            .map_err(Error::signer)?
            .as_bytes())
    }

    /// List entitlements (section 3.3.2 of RFC6492). Return an error if
    /// the child is not authorized -- or unknown etc.
    pub fn list(&self, child_handle: &Handle) -> Result<api::Entitlements> {
        let mut classes = vec![];

        for rcn in self.resources.keys() {
            if let Some(class) = self.entitlement_class(child_handle, rcn) {
                classes.push(class);
            }
        }

        Ok(Entitlements::new(classes))
    }

    /// Returns an issuance response for a child and a specific resource
    /// class name and public key for the issued certificate.
    pub fn issuance_response(
        &self,
        child_handle: &Handle,
        class_name: &ResourceClassName,
        pub_key: &PublicKey,
    ) -> Result<api::IssuanceResponse> {
        let entitlement_class = self
            .entitlement_class(child_handle, class_name)
            .ok_or_else(|| Error::NoIssuedCert)?;

        entitlement_class
            .into_issuance_response(pub_key)
            .ok_or_else(|| Error::NoIssuedCert)
    }

    /// Returns the EntitlementClass for this child for the given class name.
    fn entitlement_class(
        &self,
        child_handle: &Handle,
        rcn: &ResourceClassName,
    ) -> Option<api::EntitlementClass> {
        let my_rc = match self.resources.get(rcn) {
            Some(rc) => rc,
            None => return None,
        };

        let my_current_key = match my_rc.current_key() {
            Some(key) => key,
            None => return None,
        };

        let my_rcvd_cert = my_current_key.incoming_cert();
        let issuer = SigningCert::new(my_rcvd_cert.uri().clone(), my_rcvd_cert.cert().clone());

        let child = match self.get_child(child_handle) {
            Ok(child) => child,
            Err(_) => return None,
        };

        let child_resources = my_rcvd_cert.resources().intersection(child.resources());
        if child_resources.is_empty() {
            return None;
        }

        let not_after = child.not_after(rcn);
        let issued = child.issued(rcn);

        Some(EntitlementClass::new(
            rcn.clone(),
            issuer,
            child_resources,
            not_after,
            issued,
        ))
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(&self, child: &Handle) -> Result<&ChildDetails> {
        match self.children.get(child) {
            None => Err(Error::UnknownChild(child.clone())),
            Some(child) => Ok(child),
        }
    }

    /// Returns an iterator for the handles of all children under this CA.
    pub fn children(&self) -> impl Iterator<Item = &ChildHandle> {
        self.children.keys()
    }

    /// Adds the child, returns an error if the child is a duplicate,
    /// or if the resources are empty, or not held by this CA.
    fn add_child(
        &self,
        child: ChildHandle,
        id_cert: Option<IdCert>,
        resources: ResourceSet,
    ) -> ca::Result<Vec<Evt>> {
        if resources.is_empty() {
            return Err(Error::MustHaveResources);
        }
        if self.has_child(&child) {
            return Err(Error::DuplicateChild(child));
        }

        let child_details = ChildDetails::new(id_cert, resources);

        Ok(vec![EvtDet::child_added(
            &self.handle,
            self.version,
            child,
            child_details,
        )])
    }

    /// Certifies a child, unless:
    /// = the child is unknown,
    /// = the child is not authorised,
    /// = the csr is invalid,
    /// = the limit exceeds the child allocation,
    /// = the signer throws up..
    fn certify_child(
        &self,
        child: Handle,
        request: IssuanceRequest,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let signer = signer.read().unwrap();
        let signer = signer.deref();

        let (rcn, limit, csr) = request.unwrap();
        let csr_info = CsrInfo::try_from(&csr)?;

        let issue_response =
            self.issue_child_certificate(&child, rcn.clone(), csr_info, limit, signer)?;

        let set_deltas =
            self.republish_certs(&rcn, vec![issue_response.issued()], vec![], signer)?;

        let issued_event =
            EvtDet::child_certificate_issued(&self.handle, self.version, child, issue_response);

        let set_updated_event =
            EvtDet::current_set_updated(&self.handle, self.version + 1, rcn.clone(), set_deltas);

        Ok(vec![issued_event, set_updated_event])
    }

    /// Issue a new child certificate.
    fn issue_child_certificate(
        &self,
        child: &ChildHandle,
        rcn: ResourceClassName,
        csr_info: CsrInfo,
        limit: RequestResourceLimit,
        signer: &S,
    ) -> Result<IssuanceResponse> {
        let my_rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::unknown_resource_class(&rcn))?;

        let child = self.get_child(&child)?;

        my_rc.issue_cert(
            csr_info,
            child.resources(),
            limit,
            &PublishMode::Normal,
            signer,
        )
    }

    /// Create a publish event details including the revocations, update, withdrawals needed
    /// for updating child certificates.
    fn republish_certs(
        &self,
        class_name: &ResourceClassName,
        issued_certs: Vec<&IssuedCert>,
        removed_certs: Vec<&Cert>,
        signer: &S,
    ) -> Result<HashMap<KeyIdentifier, CurrentObjectSetDelta>> {
        self.resources
            .get(&class_name)
            .ok_or_else(|| Error::unknown_resource_class(&class_name))?
            .republish_certs(issued_certs, removed_certs, &self.base_repo, signer)
    }

    /// Shrink a child if it has any overclaiming certificates and the grace period has passed.
    ///
    /// When shrinking the parent will remove and completely revoke any resource classes for
    /// which there are no more resources. And it will shrink certificates where resources are
    /// lost, i.e. it will revoke the current certificate and issue a new certificate with the
    /// new resource set on it.
    ///
    /// Note: We could also go for the intersection of the currently entitled resources and the
    /// resources on the old certificate, but.. this is useful only really if the child CA
    /// deliberately asked for a certificate with a sub-set of resources (which is allowed, but
    /// very uncommon, and unclear why it would be beneficial), and - more importantly - it
    /// creates a corner case where there are new entitled resources but there is no intersection
    /// with the old resource set.
    pub fn shrink_child(
        &self,
        child_handle: &ChildHandle,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let signer = signer.read().unwrap();
        let signer = signer.deref();

        let child = self.get_child(child_handle)?;
        let mut events = vec![];

        debug!("Checking if child {} needs shrinking", child_handle);

        for issuance_res in child.overclaims() {
            // Keep track of things that will need to be published
            let mut issuance_responses = vec![];
            let mut removed = vec![];

            // If the overclaiming last issued cert still has entitled resources
            // then we will shrink it, i.e. re-issue a new certificate with a the
            // new resources for the resource class. Otherwise it is revoked and
            // removed.

            let rcn = issuance_res.class_name();
            let cert = issuance_res.issued().cert();

            match self.entitlement_class(child_handle, rcn) {
                // No entitlements -> revoke
                // Entitlements
                //     - include all issued -> do nothing
                //     - do not include issued -> shrink
                None => {
                    info!(
                        "Revoking certificate in resource class '{}', child '{}' lost resources",
                        rcn, child_handle
                    );

                    let ki = cert.subject_key_identifier();
                    let revocation = RevocationResponse::new(rcn.clone(), ki);
                    events.push(EvtDet::ChildKeyRevoked(child_handle.clone(), revocation));
                    removed.push(cert);
                }
                Some(entitled) => {
                    let entitled_resources = entitled.resource_set();
                    if !entitled_resources.contains(issuance_res.resource_set()) {
                        info!(
                            "Shrinking certificate in resource class '{}' for child '{}' to '{}'",
                            rcn, child_handle, entitled_resources
                        );

                        let csr_info = CsrInfo::from(cert);

                        issuance_responses.push(self.issue_child_certificate(
                            child_handle,
                            rcn.clone(),
                            csr_info,
                            RequestResourceLimit::default(),
                            signer,
                        )?);
                    }
                }
            }

            let issued = issuance_responses.iter().map(|res| res.issued()).collect();

            let set_deltas = self.republish_certs(rcn, issued, removed, signer)?;

            for response in issuance_responses.into_iter() {
                events.push(EvtDet::ChildCertificateIssued(
                    child_handle.clone(),
                    response,
                ));
            }

            events.push(EvtDet::ObjectSetUpdated(rcn.clone(), set_deltas));
        }

        let mut version = self.version;
        let events = events
            .into_iter()
            .map(|details| {
                version += 1;
                StoredEvent::new(self.handle(), version - 1, details)
            })
            .collect();

        Ok(events)
    }

    /// Updates child IdCert and/or Resource entitlements.
    ///
    /// Note: this does not yet revoke / reissue / republish anything. If the 'force' option was
    /// used in the update request, then shrink_child should be called with a grace period that
    /// is effective immediately.
    fn update_child(&self, child_handle: &Handle, req: UpdateChildRequest) -> ca::Result<Vec<Evt>> {
        let (cert_opt, resources_opt, force) = req.unpack();

        let mut version = self.version;
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if let Some(id_cert) = cert_opt {
            if Some(&id_cert) != child.id_cert() {
                res.push(EvtDet::child_updated_cert(
                    &self.handle,
                    version,
                    child_handle.clone(),
                    id_cert,
                ));
                version += 1;
            }
        }

        if let Some(resources) = resources_opt {
            if &resources != child.resources() {
                res.push(EvtDet::child_updated_resources(
                    &self.handle,
                    version,
                    child_handle.clone(),
                    resources,
                    force,
                ));
            }
        }

        Ok(res)
    }

    /// Revokes a key for a child. So, add the last cert for the key to the CRL, and withdraw
    /// the .cer file for it.
    fn revoke_child_key(
        &self,
        child_handle: ChildHandle,
        request: RevocationRequest,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let signer = signer.read().unwrap();
        let signer = signer.deref();

        let rcn = request.class_name();

        let child = self.get_child(&child_handle)?;

        let issued = child
            .issuance_response(request.key())
            .ok_or_else(|| Error::NoIssuedCert)?
            .issued()
            .cert();

        let handle = &self.handle;
        let version = self.version;

        let set_deltas = self.republish_certs(&rcn, vec![], vec![issued], signer)?;

        let wdr = EvtDet::current_set_updated(handle, version + 1, rcn.clone(), set_deltas);
        let rev = EvtDet::child_revoke_key(handle, version, child_handle, request.into());

        Ok(vec![rev, wdr])
    }

    /// Returns `true` if the child is known, `false` otherwise. No errors.
    fn has_child(&self, child_handle: &Handle) -> bool {
        self.children.contains_key(child_handle)
    }
}

/// # Being a child
///
impl<S: Signer> CertAuth<S> {
    /// List all parents
    pub fn parents(&self) -> impl Iterator<Item = &ParentHandle> {
        self.parents.keys()
    }

    fn has_parent(&self, parent: &ParentHandle) -> bool {
        self.parents.contains_key(parent)
    }

    /// Returns true if this CertAuth is set up as a TA.
    pub fn is_ta(&self) -> bool {
        for info in self.parents.values() {
            if let ParentCaContact::Ta(_) = info {
                return true;
            }
        }

        false
    }

    /// Gets the ParentCaContact for this ParentHandle. Returns an Err when the
    /// parent does not exist.
    pub fn parent(&self, parent: &ParentHandle) -> Result<&ParentCaContact> {
        self.parents
            .get(parent)
            .ok_or_else(|| Error::UnknownParent(parent.clone()))
    }

    /// Adds a parent. This method will return an error in case a parent
    /// by this name (handle) is already known.
    fn add_parent(&self, parent: Handle, info: ParentCaContact) -> ca::Result<Vec<Evt>> {
        if self.has_parent(&parent) {
            Err(Error::DuplicateParent(parent))
        } else if self.is_ta() {
            Err(Error::NotAllowedForTa)
        } else {
            Ok(vec![EvtDet::parent_added(
                &self.handle,
                self.version,
                parent,
                info,
            )])
        }
    }

    /// Maps a parent and parent's resource class name to a ResourceClassName and
    /// ResourceClass of our own.
    fn find_parent_rc(
        &self,
        parent: &ParentHandle,
        parent_rcn: &ResourceClassName,
    ) -> Option<&ResourceClass> {
        for rc in self.resources.values() {
            if rc.parent_handle() == parent && rc.parent_rc_name() == parent_rcn {
                return Some(rc);
            }
        }
        None
    }

    /// Get all the current open certificate requests for a parent.
    /// Returns an empty list if the parent is not found.
    pub fn cert_requests(
        &self,
        parent_handle: &ParentHandle,
    ) -> HashMap<ResourceClassName, Vec<IssuanceRequest>> {
        let mut res = HashMap::new();

        for (name, rc) in self.resources.iter() {
            if rc.parent_handle() == parent_handle {
                res.insert(name.clone(), rc.cert_requests());
            }
        }

        res
    }

    fn make_request_events(
        &self,
        version: &mut u64,
        entitlement: &EntitlementClass,
        rc: &ResourceClass,
        signer: &S,
    ) -> Result<Vec<Evt>> {
        let req_details_list = rc.make_request_events(entitlement, &self.base_repo, signer)?;

        let mut res = vec![];
        for details in req_details_list.into_iter() {
            res.push(StoredEvent::new(&self.handle, *version, details));
            *version += 1;
        }
        Ok(res)
    }

    /// Returns the open revocation requests for the given parent.
    pub fn revoke_requests(
        &self,
        parent: &ParentHandle,
    ) -> HashMap<ResourceClassName, Vec<RevocationRequest>> {
        let mut res = HashMap::new();
        for (name, rc) in self.resources.iter() {
            let mut revokes = vec![];
            if let Some(req) = rc.revoke_request() {
                if rc.parent_handle() == parent {
                    revokes.push(req.clone())
                }
            }
            res.insert(name.clone(), revokes);
        }
        res
    }

    /// This processes entitlements from a parent, and updates the resource
    /// classes for this CA as needed. I.e.
    ///
    /// 1) It removes lost RCs, and requests revocation of the key(s). Note
    ///    that this revocation request may result in an error because the
    ///    parent already revoked these keys - or not - we don't know.
    ///
    ///    Krill parents will by default do a 'soft' shrink where resource
    ///    classes are removed, but not yet revoked. So a krill parent will
    ///    expect the revoke request from the child.
    ///
    /// 2) For any new RCs in the entitlements new RCs will be created, each
    ///    with a pending key and an open certificate sign request.
    ///
    /// 3) For RCs that exist both for the CA and in the entitlements, new
    ///    certificates will be requested in case resource entitlements, or
    ///    validity times (not after) changed.
    ///
    ///  TODO: Shrink issued ROAs and certificates pro-actively before
    ///        requesting the shrunk certificate.
    fn update_resource_classes(
        &self,
        parent_handle: Handle,
        entitlements: Entitlements,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let mut res = vec![];

        // Check if there is a resource class for each entitlement
        let mut version = self.version;

        // Check if there are any current resource classes, now removed
        // from the entitlements. In which case we will have to clean them
        // up and un-publish everything there was.
        let current_resource_classes = &self.resources;

        let entitled_classes: Vec<&ResourceClassName> = entitlements
            .classes()
            .iter()
            .map(|c| c.class_name())
            .collect();

        for (name, rc) in current_resource_classes.iter().filter(|(_name, class)| {
            // Find the classes for this parent, not included
            // in the entitlements now received.
            class.parent_handle() == &parent_handle
                && !entitled_classes.contains(&class.parent_rc_name())
        }) {
            let signer = signer.read().unwrap();

            let delta = rc.withdraw(&self.base_repo);
            let revocations = rc.revoke(signer.deref())?;

            res.push(EvtDet::resource_class_removed(
                &self.handle,
                version,
                name.clone(),
                delta,
                parent_handle.clone(),
                revocations,
            ));
            version += 1;
        }

        // Now check all the entitlements and either create an RC for them, or update.
        let mut next_class_name = self.next_class_name;

        for ent in entitlements.classes() {
            let parent_rc_name = ent.class_name();

            match self.find_parent_rc(&parent_handle, &parent_rc_name) {
                Some(rc) => {
                    // We have a matching RC, make requests (note this may be a no-op).
                    let signer = signer.read().unwrap();
                    res.append(&mut self.make_request_events(
                        &mut version,
                        ent,
                        rc,
                        signer.deref(),
                    )?);
                }
                None => {
                    // Create a resource class with a pending key
                    let key_id = {
                        signer
                            .write()
                            .unwrap()
                            .create_key(PublicKeyFormat::default())
                            .map_err(Error::signer)?
                    };

                    let rcn = ResourceClassName::from(next_class_name);
                    next_class_name += 1;

                    let ns = rcn.to_string();

                    let rc = ResourceClass::create(
                        rcn.clone(),
                        ns,
                        parent_handle.clone(),
                        parent_rc_name.clone(),
                        key_id,
                    );
                    let rc_add_version = version;
                    version += 1;

                    let signer = signer.read().unwrap();
                    let mut request_events =
                        self.make_request_events(&mut version, ent, &rc, signer.deref())?;

                    let added = EvtDet::resource_class_added(&self.handle, rc_add_version, rcn, rc);

                    res.push(added);
                    res.append(&mut request_events);
                }
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
        rcn: ResourceClassName,
        rcvd_cert: RcvdCert,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        debug!(
            "CA {}: Updating received cert for class: {}",
            self.handle, rcn
        );

        let signer = signer.read().unwrap();

        let rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::unknown_resource_class(&rcn))?;
        let evt_details = rc.update_received_cert(rcvd_cert, &self.base_repo, signer.deref())?;

        let mut res = vec![];
        let mut version = self.version;

        for details in evt_details.into_iter() {
            res.push(StoredEvent::new(&self.handle, version, details));
            version += 1;
        }

        Ok(res)
    }
}

/// # Key Rolls
///
impl<S: Signer> CertAuth<S> {
    fn keyroll_initiate(&self, duration: Duration, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let mut signer = signer.write().unwrap();
        let mut version = self.version;
        let mut res = vec![];

        for rc in self.resources.values() {
            for details in rc
                .keyroll_initiate(&self.base_repo, duration, signer.deref_mut())?
                .into_iter()
            {
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }
        }

        Ok(res)
    }

    fn keyroll_activate(&self, staging: Duration, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let signer = signer.read().unwrap();
        let mut version = self.version;
        let mut res = vec![];

        for class in self.resources.values() {
            for details in class
                .keyroll_activate(&self.base_repo, staging, signer.deref())?
                .into_iter()
            {
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }
        }

        Ok(res)
    }

    fn keyroll_finish(
        &self,
        rcn: ResourceClassName,
        _response: RevocationResponse,
    ) -> ca::Result<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }
        let my_rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::unknown_resource_class(&rcn))?;

        let finish_details = my_rc.keyroll_finish(&self.base_repo)?;

        Ok(vec![StoredEvent::new(
            self.handle(),
            self.version,
            finish_details,
        )])
    }
}

/// # Publishing
///
impl<S: Signer> CertAuth<S> {
    /// Republish objects for this CA
    pub fn republish(&self, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        let signer = signer.read().unwrap();

        let mut res = vec![];
        let mut version = self.version;

        for rc in self.resources.values() {
            if rc.current_key().is_some() {
                let auths: Vec<RouteAuthorization> =
                    self.routes.authorizations().cloned().collect();

                for evt_det in rc
                    .republish(
                        auths.as_slice(),
                        &self.base_repo,
                        &PublishMode::Normal,
                        signer.deref(),
                    )?
                    .into_iter()
                {
                    res.push(StoredEvent::new(&self.handle, version, evt_det));
                    version += 1;
                }
            }
        }

        Ok(res)
    }
}

/// # Managing Route Authorizations
///
impl<S: Signer> CertAuth<S> {
    /// Updates the route authorizations for this CA, and update ROAs. Will return
    /// an error in case authorisations are added for which this CA does not hold
    /// the prefix.
    fn route_authorizations_update(
        &self,
        updates: RouteAuthorizationUpdates,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let (added, removed) = updates.unpack();
        let signer = signer.read().unwrap();
        let mode = PublishMode::Normal;

        let mut res = vec![];
        let mut version = self.version;
        let all_resources = self.all_resources();

        let mut current_auths: HashSet<RouteAuthorization> =
            self.routes.authorizations().cloned().collect();

        for auth in added {
            if current_auths.contains(&auth) {
                return Err(Error::AuthorisationAlreadyPresent(auth));
            } else if !all_resources.contains(&auth.prefix().into()) {
                return Err(Error::AuthorisationNotEntitled(auth));
            } else {
                current_auths.insert(auth);
                res.push(StoredEvent::new(
                    self.handle(),
                    version,
                    EvtDet::RouteAuthorizationAdded(auth),
                ));
                version += 1;
            }
        }

        for auth in removed {
            if current_auths.contains(&auth) {
                current_auths.remove(&auth);
                res.push(StoredEvent::new(
                    self.handle(),
                    version,
                    EvtDet::RouteAuthorizationRemoved(auth),
                ));
                version += 1;
            } else {
                return Err(Error::AuthorisationUnknown(auth));
            }
        }

        let current_auths: Vec<RouteAuthorization> = current_auths.into_iter().collect();

        let mut deltas = HashMap::new();

        // Update ROAs, and derive deltas and revocations for publishing.
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.update_roas(current_auths.as_slice(), &mode, signer.deref())?;
            if updates.contains_changes() {
                let mut delta = ObjectsDelta::new(self.base_repo.ca_repository(rc.name_space()));

                for added in updates.added().into_iter() {
                    delta.add(added);
                }
                for update in updates.updated().into_iter() {
                    delta.update(update);
                }
                for withdraw in updates.withdrawn().into_iter() {
                    delta.withdraw(withdraw);
                }

                let revocations = updates.revocations();

                deltas.insert(rcn, (delta, revocations));

                res.push(StoredEvent::new(
                    self.handle(),
                    version,
                    EvtDet::RoasUpdated(rcn.clone(), updates),
                ));
                version += 1;
            }
        }

        // Create publication delta with all additions/updates/withdraws as a single delta
        for (rcn, (delta, revocations)) in deltas.into_iter() {
            let rc = self.resources.get(&rcn).unwrap();

            let pub_detail =
                rc.publish_objects(&self.base_repo, delta, revocations, &mode, signer.deref())?;

            res.push(StoredEvent::new(&self.handle, version, pub_detail));
            version += 1;
        }

        Ok(res)
    }
}
