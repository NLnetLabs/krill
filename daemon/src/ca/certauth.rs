use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::{PublicKey, PublicKeyFormat};
use rpki::x509::{Name, Serial, Time, Validity};

use krill_commons::api::admin::{
    Handle, ParentCaContact, PubServerContact, Token, UpdateChildRequest,
};
use krill_commons::api::ca::{
    AddedObject, CertAuthInfo, ChildCaDetails, CurrentObject, IssuedCert, ObjectName, ObjectsDelta,
    PublicationDelta, RcvdCert, ReplacedObject, RepoInfo, ResourceClassName, ResourceSet,
    Revocation, TrustAnchorInfo, UpdatedObject, WithdrawnObject,
};
use krill_commons::api::{
    self, EntitlementClass, Entitlements, IssuanceRequest, IssuanceResponse, RequestResourceLimit,
    RevocationRequest, RevocationResponse, SigningCert,
};
use krill_commons::eventsourcing::{Aggregate, StoredEvent};
use krill_commons::remote::builder::{IdCertBuilder, SignedMessageBuilder};
use krill_commons::remote::id::IdCert;
use krill_commons::remote::rfc6492;
use krill_commons::remote::rfc8183::ChildRequest;
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::util::softsigner::KeyId;

use crate::ca::signing::CertSiaInfo;
use crate::ca::{
    self, ta_handle, ChildHandle, Cmd, CmdDet, Error, Evt, EvtDet, Ini, ParentHandle,
    ResourceClass, Result, SignSupport, Signer,
};

//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: KeyId,
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

    children: HashMap<ChildHandle, ChildCaDetails>,

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

        if let Some(ta) = ta_opt {
            let (key, tal) = ta.unpack();
            parents.insert(ta_handle(), ParentCaContact::Ta(tal));

            let rcn = ResourceClassName::from(next_class_name);
            next_class_name += 1;
            resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key));
        }

        let children = HashMap::new();

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
                let (class_name, _, _, issued) = response.unwrap();
                self.children
                    .get_mut(&child)
                    .unwrap()
                    .add_cert(&class_name, issued);
            }
            EvtDet::ChildKeyRevoked(child, response) => {
                self.children.get_mut(&child).unwrap().revoke_key(response);
            }
            EvtDet::ChildUpdatedIdCert(child, cert) => {
                self.children.get_mut(&child).unwrap().set_id_cert(cert);
            }
            EvtDet::ChildUpdatedResourceClass(child, class, resources) => self
                .children
                .get_mut(&child)
                .unwrap()
                .set_resources_for_class(class, resources),
            EvtDet::ChildRemovedResourceClass(child, name) => {
                self.children
                    .get_mut(&child)
                    .unwrap()
                    .remove_resource(&name);
            }

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
            // Key Roll
            //-----------------------------------------------------------------------
            EvtDet::KeyRollPendingKeyAdded(class_name, key_id) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .pending_key_added(key_id);
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
            // General functions
            //-----------------------------------------------------------------------
            EvtDet::Published(class_name, delta_map) => {
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
            CmdDet::ChildShrink(child, grace, signer) => self.shrink_child(&child, grace, signer),

            // being a child
            CmdDet::AddParent(parent, info) => self.add_parent(parent, info),
            CmdDet::UpdateEntitlements(parent, entitlements, signer) => {
                self.update_entitlements(parent, entitlements, signer)
            }
            CmdDet::UpdateRcvdCert(class_name, rcvd_cert, signer) => {
                self.update_received_cert(class_name, rcvd_cert, signer)
            }

            // Key rolls
            CmdDet::KeyRollInitiate(duration, signer) => self.keyroll_initiate(duration, signer),
            CmdDet::KeyRollActivate(duration, signer) => self.keyroll_activate(duration, signer),
            CmdDet::KeyRollFinish(rcn, response) => self.keyroll_finish(rcn, response),

            // Republish
            CmdDet::Republish(signer) => self.republish(signer),
        }
    }
}

/// # Data presentation
///
impl<S: Signer> CertAuth<S> {
    pub fn as_ta_info(&self) -> Result<TrustAnchorInfo> {
        if let Ok(ta) = self.parent(&ta_handle()) {
            let tal = match ta {
                ParentCaContact::Ta(tal) => Some(tal),
                _ => None,
            }
            .ok_or_else(|| Error::NotTa)?;

            let rc = self
                .resources
                .get(&ResourceClassName::default())
                .ok_or_else(|| Error::NotTa)?;
            let cert = rc.current_certificate().ok_or_else(|| Error::NotTa)?;

            let resources = cert.resources().clone();
            let repo_info = self.base_repo.clone();
            let children = self.children.clone();
            let tal = tal.clone();

            Ok(TrustAnchorInfo::new(
                resources,
                repo_info,
                children,
                cert.clone(),
                tal,
            ))
        } else {
            Err(Error::NotTa)
        }
    }

    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let base_repo = self.base_repo.clone();

        let parents = self.parents.clone();

        let mut resources = HashMap::new();

        for (name, rc) in &self.resources {
            resources.insert(name.clone(), rc.as_info());
        }
        let children = self.children.clone();

        CertAuthInfo::new(handle, base_repo, parents, resources, children)
    }

    pub fn child_request(&self) -> ChildRequest {
        ChildRequest::new(self.handle.clone(), self.id.cert.clone())
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id.cert
    }
    pub fn id_key(&self) -> &KeyId {
        &self.id.key
    }
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

/// # Being a parent
///
impl<S: Signer> CertAuth<S> {
    pub fn verify_rfc6492(&self, msg: SignedMessage) -> Result<rfc6492::Message> {
        let content = rfc6492::Message::from_signed_message(&msg)?;

        let child_handle = Handle::from(content.sender());
        let child = self.get_child(&child_handle)?;

        let child_cert = child
            .id_cert()
            .ok_or_else(|| Error::Unauthorized(child_handle))?;
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
        class_name: &ResourceClassName,
    ) -> Option<api::EntitlementClass> {
        let child = match self.get_child(child_handle) {
            Ok(child) => child,
            Err(_) => return None,
        };

        let child_resources = match child.resources_for_class(class_name) {
            Some(res) => res,
            None => return None,
        };

        if child_resources.resources().is_empty() {
            return None;
        }

        let until = child_resources.not_after();
        let issued = child_resources.certs_iter().cloned().collect();

        let my_rc = match self.resources.get(class_name) {
            Some(rc) => rc,
            None => return None,
        };

        let my_rcvd_cert = match my_rc.current_certificate() {
            Some(cert) => cert,
            None => return None,
        };
        let cert = SigningCert::new(my_rcvd_cert.uri().clone(), my_rcvd_cert.cert().clone());

        Some(EntitlementClass::new(
            class_name.clone(),
            cert,
            child_resources.resources().clone(),
            until,
            issued,
        ))
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(&self, child: &Handle) -> Result<&ChildCaDetails> {
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

        let child_resource_classes = self.child_resource_classes_entitlements(resources)?;
        let mut child_details = ChildCaDetails::new(id_cert);
        for (name, resources) in child_resource_classes.into_iter() {
            child_details.add_new_resource_class(name, resources);
        }

        Ok(vec![EvtDet::child_added(
            &self.handle,
            self.version,
            child,
            child_details,
        )])
    }

    /// Returns a result containing a hashmap of resource class names to partial resource sets,
    /// given the overall child resource entitlements, relative to the resources held by this
    /// CA. Returns an Error if any resources are missing.
    fn child_resource_classes_entitlements(
        &self,
        child_resources: ResourceSet,
    ) -> Result<HashMap<ResourceClassName, ResourceSet>> {
        let mut map = HashMap::new();
        let mut matched_resources = ResourceSet::default();

        for (name, rc) in &self.resources {
            if let Some(rcvd_cert) = rc.current_certificate() {
                let resources = rcvd_cert.resources().intersection(&child_resources);
                if !resources.is_empty() {
                    matched_resources = matched_resources.union(&resources);
                    map.insert(name.clone(), resources);
                }
            }
        }

        if matched_resources == child_resources {
            Ok(map)
        } else {
            Err(Error::MissingResources)
        }
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
        let (class_name, limit, csr) = request.unwrap();

        csr.validate()
            .map_err(|_| Error::invalid_csr(&child, "invalid signature"))?;

        let sia_info = {
            let ca_repository = csr
                .ca_repository()
                .cloned()
                .ok_or_else(|| Error::invalid_csr(&child, "Missing CA repository uri"))?;
            let rpki_manifest = csr
                .rpki_manifest()
                .cloned()
                .ok_or_else(|| Error::invalid_csr(&child, "Missing rpki manifest uri"))?;
            let rpki_notify = csr.rpki_notify().cloned();

            CertSiaInfo::new(ca_repository, rpki_manifest, rpki_notify)
        };

        let pub_key = csr.public_key().clone();

        let issue_response = self.issue_child_certificate(
            &child,
            class_name.clone(),
            pub_key,
            sia_info,
            limit,
            signer.read().unwrap().deref(),
        )?;

        let publication_delta = self.update_published_child_certificates(
            &class_name,
            vec![issue_response.issued()],
            vec![],
            signer,
        )?;

        let issued_event =
            EvtDet::child_certificate_issued(&self.handle, self.version, child, issue_response);

        let publish_event = EvtDet::published(
            &self.handle,
            self.version + 1,
            class_name,
            publication_delta,
        );

        Ok(vec![issued_event, publish_event])
    }

    /// Issue a new child certificate.
    fn issue_child_certificate(
        &self,
        child: &ChildHandle,
        class_name: ResourceClassName,
        pub_key: PublicKey,
        sia_info: CertSiaInfo,
        limit: RequestResourceLimit,
        signer: &S,
    ) -> Result<IssuanceResponse> {
        let my_rc = self
            .resources
            .get(&class_name)
            .ok_or_else(|| Error::unknown_resource_class(&class_name))?;
        let issuing_key = my_rc.get_current_key()?;
        let issuing_cert = issuing_key.incoming_cert();

        // verify child and resources
        let child_resources = self
            .get_child(&child)?
            .resources_for_class(&class_name)
            .ok_or_else(|| Error::MissingResourceClass)?;

        if child_resources.resources().is_empty() {
            return Err(Error::MissingResources);
        }

        let current_cert = child_resources.cert(&pub_key.key_identifier());
        let replaces = current_cert.map(ReplacedObject::from);

        let resources = child_resources
            .resources()
            .apply_limit(&limit)
            .map_err(|_| Error::MissingResources)?;

        // create new cert
        let issued_cert = {
            let serial = { Serial::random(signer).map_err(Error::signer)? };
            let issuer = issuing_cert.cert().subject().clone();

            let validity = Validity::new(
                Time::now() - Duration::minutes(3),
                child_resources.not_after(),
            );

            let subject = Some(Name::from_pub_key(&pub_key));

            let key_usage = KeyUsage::Ca;
            let overclaim = Overclaim::Refuse;

            let mut cert = TbsCert::new(
                serial, issuer, validity, subject, pub_key, key_usage, overclaim,
            );
            cert.set_basic_ca(Some(true));

            // Note! The issuing CA is not authoritative over *where* the child CA
            // may publish. I.e. it will sign over any claimed URIs by the child,
            // and assume that they will not be able to do anything malicious,
            // because the publication server for those URIs should verify the
            // identity of the publisher, and that RPs will not invalidate the
            // content of another CA's repo, if they it is wrongfully claimed.
            let (ca_repository, rpki_manifest, rpki_notify) = sia_info.unpack();

            cert.set_ca_issuer(Some(issuing_cert.uri().clone()));
            cert.set_crl_uri(Some(issuing_cert.crl_uri()));
            cert.set_ca_repository(Some(ca_repository));
            cert.set_rpki_manifest(Some(rpki_manifest));
            cert.set_rpki_notify(rpki_notify);

            cert.set_as_resources(Some(resources.to_as_resources()));
            cert.set_v4_resources(Some(resources.to_ip_resources_v4()));
            cert.set_v6_resources(Some(resources.to_ip_resources_v6()));

            cert.set_authority_key_identifier(Some(issuing_cert.cert().subject_key_identifier()));

            let cert = {
                cert.into_cert(signer, issuing_key.key_id())
                    .map_err(Error::signer)?
            };

            let cert_uri = issuing_cert.uri_for_object(&cert);

            IssuedCert::new(cert_uri, limit, resources.clone(), cert, replaces)
        };

        let signing_cert = SigningCert::from(issuing_cert);

        Ok(IssuanceResponse::new(
            class_name,
            signing_cert,
            resources,
            issued_cert.cert().validity().not_after(),
            issued_cert,
        ))
    }

    /// Create a publish event details including the revocations, update, withdrawals needed
    /// for updating child certificates.
    pub fn update_published_child_certificates(
        &self,
        class_name: &ResourceClassName,
        issued_certs: Vec<&IssuedCert>,
        removed_certs: Vec<&Cert>,
        signer: Arc<RwLock<S>>,
    ) -> Result<HashMap<KeyId, PublicationDelta>> {
        let my_rc = self
            .resources
            .get(&class_name)
            .ok_or_else(|| Error::unknown_resource_class(&class_name))?;

        let issuing_key = my_rc.get_current_key()?;
        let name_space = my_rc.name_space();

        let mut revocations = vec![];
        for cert in removed_certs.iter() {
            revocations.push(Revocation::from(*cert));
        }
        for issued in issued_certs.iter() {
            if let Some(replaced) = issued.replaces() {
                revocations.push(replaced.revocation());
            }
        }

        let ca_repo = self.base_repo.ca_repository(name_space);
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

        let delta = SignSupport::publish(
            signer,
            issuing_key,
            &self.base_repo,
            name_space,
            objects_delta,
            revocations,
        )
        .map_err(Error::signer)?;

        let mut res = HashMap::new();
        res.insert(issuing_key.key_id().clone(), delta);
        Ok(res)
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
        grace: Duration,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        let child = self.get_child(child_handle)?;
        let mut events = vec![];

        debug!("Checking if child {} needs shrinking", child_handle);

        for (class_name, child_resources) in child.resources().iter() {
            if let Some(pending_time) = child_resources.shrink_pending() {
                if pending_time + grace <= Time::now() {
                    let mut issuance_responses = vec![];
                    let mut removed = vec![];

                    let new_resources = child_resources.resources();

                    if new_resources.is_empty() {
                        info!(
                            "Removing resource class '{}' for child '{}'",
                            class_name, child_handle
                        );
                        // Remove resource set and revoke all certs
                        for (keyref, issued) in child_resources.certs().iter() {
                            let revocation =
                                RevocationResponse::new(class_name.clone(), keyref.into());
                            events.push(EvtDet::ChildKeyRevoked(child_handle.clone(), revocation));
                            removed.push(issued.cert())
                        }
                        events.push(EvtDet::ChildRemovedResourceClass(
                            child_handle.clone(),
                            class_name.clone(),
                        ));
                    } else {
                        // Re-issue all certs that are overclaiming.
                        for issued_cert in child_resources.certs_iter() {
                            if !new_resources.contains(issued_cert.resource_set()) {
                                info!(
                                    "Shrinking cert in resource class '{}' for child '{}' to '{}'",
                                    class_name, child_handle, new_resources
                                );

                                let sia_info = {
                                    let ca_repo =
                                        issued_cert.cert().ca_repository().cloned().unwrap();
                                    let mft_uri =
                                        issued_cert.cert().rpki_manifest().cloned().unwrap();
                                    let not_opt = issued_cert.cert().rpki_notify().cloned();
                                    CertSiaInfo::new(ca_repo, mft_uri, not_opt)
                                };

                                let pub_key = issued_cert.cert().subject_public_key_info().clone();
                                issuance_responses.push(self.issue_child_certificate(
                                    child_handle,
                                    class_name.clone(),
                                    pub_key,
                                    sia_info,
                                    RequestResourceLimit::default(),
                                    signer.read().unwrap().deref(),
                                )?);
                            }
                        }
                    }
                    let issued = issuance_responses.iter().map(|res| res.issued()).collect();

                    let publication_delta = self.update_published_child_certificates(
                        &class_name,
                        issued,
                        removed,
                        signer.clone(),
                    )?;

                    for response in issuance_responses.into_iter() {
                        events.push(EvtDet::ChildCertificateIssued(
                            child_handle.clone(),
                            response,
                        ));
                    }

                    events.push(EvtDet::Published(class_name.clone(), publication_delta));
                }
            }
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
        let (cert_opt, resources_opt) = req.unpack();

        let mut version = self.version;
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if let Some(id_cert) = cert_opt {
            res.push(EvtDet::child_updated_cert(
                &self.handle,
                version,
                child_handle.clone(),
                id_cert,
            ));
        }

        if let Some(resources) = resources_opt {
            // The new entitlements (provided this CA has them)
            let child_entitlements = self.child_resource_classes_entitlements(resources)?;

            // Get the current child resources
            let mut child_resources = HashMap::new();
            for (class_name, child_rc) in child.resources().iter() {
                child_resources.insert(class_name, child_rc.resources());
            }

            // Determine for each entitlement whether the current is changed, or a new
            // resource class can be added.
            for (class_name, entitled_resource_set) in child_entitlements.into_iter() {
                if match child_resources.remove(&class_name) {
                    None => true,
                    Some(current_resources) => current_resources != &entitled_resource_set,
                } {
                    res.push(EvtDet::child_updated_resources(
                        &self.handle,
                        version,
                        child_handle.clone(),
                        class_name,
                        entitled_resource_set,
                    ));
                    version += 1;
                }
            }

            // All left-over current resources where not removed above, and therefore no
            // longer part of the entitlements for this child. So set the ResourceSet to
            // empty for these ones.
            for (class_name, _) in child_resources.into_iter() {
                res.push(EvtDet::child_updated_resources(
                    &self.handle,
                    version,
                    child_handle.clone(),
                    class_name.clone(),
                    ResourceSet::default(),
                ));
                version += 1;
            }
        }

        Ok(res)
    }

    /// Revokes a key for a child. So, add all certs for the key to the CRL, and withdraw
    /// the .cer file for it.
    fn revoke_child_key(
        &self,
        child: ChildHandle,
        request: RevocationRequest,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        // verify child and resources
        let class_name = request.class_name().clone();

        let child_resources = self
            .get_child(&child)?
            .resources_for_class(&class_name)
            .ok_or_else(|| Error::MissingResourceClass)?;

        let my_rc = self
            .resources
            .get(&class_name)
            .ok_or_else(|| Error::unknown_resource_class(&class_name))?;

        let ca_key = my_rc.get_current_key()?;
        let name_space = my_rc.name_space();

        if let Some(last_cert) = child_resources.cert(request.key()) {
            let response = request.into();

            let name = ObjectName::from(last_cert.cert());
            let current_object = CurrentObject::from(last_cert.cert());
            let withdrawn = WithdrawnObject::for_current(name, &current_object);

            let revocations = vec![Revocation::from(last_cert.cert())];

            let mut objects_delta = ObjectsDelta::new(self.base_repo.ca_repository(name_space));
            objects_delta.withdraw(withdrawn);

            let pub_delta = SignSupport::publish(
                signer,
                ca_key,
                &self.base_repo,
                name_space,
                objects_delta,
                revocations,
            )
            .map_err(Error::signer)?;

            let mut deltas = HashMap::new();
            deltas.insert(ca_key.key_id().clone(), pub_delta);

            let revoked = EvtDet::child_revoke_key(&self.handle, self.version, child, response);
            let published = EvtDet::published(&self.handle, self.version + 1, class_name, deltas);

            Ok(vec![revoked, published])
        } else {
            Err(Error::NoIssuedCert)
        }
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
    ) -> Option<(&ResourceClassName, &ResourceClass)> {
        for (my_name, rc) in self.resources.iter() {
            if rc.parent_handle() == parent && rc.parent_rc_name() == parent_rcn {
                return Some((my_name, rc));
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
        rcn: ResourceClassName,
        entitlement: &EntitlementClass,
        rc: &ResourceClass,
        signer: &S,
    ) -> Result<Vec<Evt>> {
        let req_details_list = rc.make_request_events(rcn, entitlement, &self.base_repo, signer)?;

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

    /// This processes entitlements from a parent, and updates the known
    /// entitlement(s) and/or requests certificate(s) as needed. In case
    /// there are no changes in entitlements and certificates, this method
    /// will result in 0 events - i.e. it is then a no-op.
    ///
    /// If there are no more resources in a resource class, then the CA will
    /// request revocation for all its keys in the resource class.
    fn update_entitlements(
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

        for (name, class) in current_resource_classes.iter().filter(|(_name, class)| {
            // Find the classes for this parent, not included
            // in the entitlements now received.
            class.parent_handle() == &parent_handle
                && !entitled_classes.contains(&class.parent_rc_name())
        }) {
            let signer = signer.read().unwrap();

            let delta = class.withdraw(&self.base_repo);
            let revocations = class.revoke(name.clone(), signer.deref())?;

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
        for ent in entitlements.classes() {
            let parent_rc_name = ent.class_name();

            match self.find_parent_rc(&parent_handle, &parent_rc_name) {
                Some((rcn, rc)) => {
                    // We have a matching RC, make requests (note this may be a no-op).
                    let signer = signer.read().unwrap();
                    res.append(&mut self.make_request_events(
                        &mut version,
                        rcn.clone(),
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

                    let rcn = ResourceClassName::from(self.next_class_name);
                    let ns = rcn.to_string();

                    let rc = ResourceClass::create(
                        ns,
                        parent_handle.clone(),
                        parent_rc_name.clone(),
                        key_id,
                    );
                    let rc_add_version = version;
                    version += 1;

                    let signer = signer.read().unwrap();
                    let mut request_events = self.make_request_events(
                        &mut version,
                        rcn.clone(),
                        ent,
                        &rc,
                        signer.deref(),
                    )?;

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

        let rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::unknown_resource_class(&rcn))?;
        let evt_details = rc.update_received_cert(rcvd_cert, &self.base_repo, rcn, signer)?;

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

        for (class_name, class) in self.resources.iter() {
            for details in class
                .keyroll_initiate(
                    class_name.clone(),
                    &self.base_repo,
                    duration,
                    signer.deref_mut(),
                )?
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

        for (class_name, class) in self.resources.iter() {
            for details in class
                .keyroll_activate(class_name.clone(), staging, signer.deref())?
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

        let finish_details = my_rc.keyroll_finish(rcn, &self.base_repo)?;

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
        let mut publish_details = vec![];
        for (class_name, rc) in self.resources.iter() {
            publish_details.push(rc.republish(
                &self.base_repo,
                class_name.clone(),
                signer.clone(),
            )?);
        }

        let mut res = vec![];
        let mut version = self.version;
        for details in publish_details.into_iter() {
            res.push(StoredEvent::new(&self.handle, version, details));
            version += 1;
        }

        Ok(res)
    }
}
