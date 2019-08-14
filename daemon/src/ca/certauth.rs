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
    AddedObject, CaParentsInfo, CertAuthInfo, CertifiedKey, ChildCaDetails, CurrentObject,
    IssuedCert, ObjectName, ObjectsDelta, ParentCaInfo, PublicationDelta, RcvdCert, ReplacedObject,
    RepoInfo, ResourceSet, Revocation, TrustAnchorInfo, TrustAnchorLocator, UpdatedObject,
    WithdrawnObject,
};
use krill_commons::api::{
    self, EntitlementClass, Entitlements, IssuanceRequest, IssuanceResponse, RequestResourceLimit,
    RevocationRequest, RevocationResponse, SigningCert, DFLT_CLASS,
};
use krill_commons::eventsourcing::{Aggregate, StoredEvent};
use krill_commons::remote::builder::{IdCertBuilder, SignedMessageBuilder};
use krill_commons::remote::id::IdCert;
use krill_commons::remote::rfc6492;
use krill_commons::remote::rfc8183::ChildRequest;
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::util::softsigner::KeyId;

use crate::ca::{
    self, ChildHandle, Cmd, CmdDet, Error, Evt, EvtDet, Ini, ParentHandle, ResourceClass,
    ResourceClassName, Result, SignSupport, Signer,
};
use crate::ca::signing::CertSiaInfo;

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

//------------ CaType ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CaType {
    Child,
    Ta(CertifiedKey, TrustAnchorLocator),
}

//------------ CaParents ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CaParents {
    SelfSigned(CertifiedKey, TrustAnchorLocator),
    Parents(HashMap<Handle, ParentCa>),
}

impl CaParents {
    fn as_info(&self) -> CaParentsInfo {
        match self {
            CaParents::SelfSigned(key, tal) => CaParentsInfo::SelfSigned(key.clone(), tal.clone()),
            CaParents::Parents(map) => {
                let mut map_info = HashMap::new();

                for (handle, parent) in map {
                    map_info.insert(handle.clone(), parent.as_info());
                }

                CaParentsInfo::Parents(map_info)
            }
        }
    }

    fn is_self_signed(&self) -> bool {
        match self {
            CaParents::SelfSigned(_, _) => true,
            _ => false,
        }
    }

    fn assert_parent_new(&self, parent: &Handle) -> Result<()> {
        match self {
            CaParents::SelfSigned(_, _) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => {
                if map.contains_key(parent) {
                    Err(Error::DuplicateParent(parent.clone()))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn insert(&mut self, handle: Handle, parent: ParentCa) -> Result<()> {
        match self {
            CaParents::SelfSigned(_, _) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => {
                map.insert(handle, parent);
                Ok(())
            }
        }
    }

    fn get(&self, handle: &Handle) -> Result<&ParentCa> {
        match self {
            CaParents::SelfSigned(_, _) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => Ok(map
                .get(handle)
                .ok_or_else(|| Error::UnknownParent(handle.clone()))?),
        }
    }

    fn get_mut(&mut self, handle: &Handle) -> Result<&mut ParentCa> {
        match self {
            CaParents::SelfSigned(_, _) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => Ok(map
                .get_mut(handle)
                .ok_or_else(|| Error::UnknownParent(handle.clone()))?),
        }
    }

    fn ta_key_mut(&mut self) -> Result<&mut CertifiedKey> {
        match self {
            CaParents::SelfSigned(key, _) => Ok(key),
            CaParents::Parents(_map) => Err(Error::NotTa),
        }
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
    parents: CaParents,
    pubserver: PubServerContact, // TODO, allow remote

    children: HashMap<Handle, ChildCaDetails>,

    phantom_signer: PhantomData<S>,
}

impl<S: Signer> Aggregate for CertAuth<S> {
    type Command = Cmd<S>;
    type Event = Evt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Ini) -> Result<Self> {
        let (handle, _version, details) = event.unwrap();

        let (token, id, base_repo, ca_type) = details.unwrap();

        if ca_type == CaType::Child && handle == Handle::from("ta") {
            return Err(Error::NameReservedTa);
        }

        let parents = match ca_type {
            CaType::Child => CaParents::Parents(HashMap::new()),
            CaType::Ta(key, tal) => CaParents::SelfSigned(key, tal),
        };
        let pubserver = PubServerContact::embedded();

        let children = HashMap::new();

        Ok(CertAuth {
            handle,
            version: 1,

            token,
            id,

            base_repo,
            parents,
            pubserver,

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
                let child = self.children.get_mut(&child).unwrap();
                child.add_cert(&class_name, issued);
            }
            EvtDet::ChildKeyRevoked(child, response) => {
                let child = self.children.get_mut(&child).unwrap();
                child.revoke_key(response);
            }
            EvtDet::ChildUpdatedIdCert(child, cert) => {
                let child = self.children.get_mut(&child).unwrap();
                child.set_id_cert(cert);
            }
            EvtDet::ChildUpdatedResourceClass(child, class, resources) => {
                let child = self.children.get_mut(&child).unwrap();
                child.set_resources_for_class(&class, resources)
            }
            EvtDet::ChildRemovedResourceClass(child, name) => {
                let child = self.children.get_mut(&child).unwrap();
                child.remove_resource(name.as_str());
            }

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            EvtDet::ParentAdded(handle, info) => {
                let parent = ParentCa::without_resource(info);
                self.parents.insert(handle, parent).unwrap();
            }
            EvtDet::ResourceClassAdded(parent, name, rc) => {
                // Evt cannot occur without parent existing
                self.parents
                    .get_mut(&parent)
                    .unwrap()
                    .resources
                    .insert(name, rc);
            }
            EvtDet::ResourceClassRemoved(parent, name, _delta, _revocations) => {
                self.parents
                    .get_mut(&parent)
                    .unwrap()
                    .resources
                    .remove(&name);
            }
            EvtDet::CertificateRequested(parent, req, status) => {
                let class = req.class_name().to_owned();
                self.parents
                    .get_mut(&parent)
                    .unwrap()
                    .resources
                    .get_mut(&class)
                    .unwrap()
                    .add_request(status, req)
            }
            EvtDet::CertificateReceived(parent, class_name, key_id, cert) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                rc.received_cert(key_id, cert);
            }

            //-----------------------------------------------------------------------
            // Key Roll
            //-----------------------------------------------------------------------
            EvtDet::KeyRollPendingKeyAdded(parent, class_name, key_id) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                rc.pending_key_added(key_id);
            }
            EvtDet::KeyRollActivated(parent, class_name, revoke_req) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                rc.new_key_activated(revoke_req);
            }
            EvtDet::KeyRollFinished(parent, class_name, _delta) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                rc.old_key_removed();
            }

            //-----------------------------------------------------------------------
            // General functions
            //-----------------------------------------------------------------------
            EvtDet::Published(parent, class_name, delta_map) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                for (key_id, delta) in delta_map.into_iter() {
                    rc.apply_delta(delta, key_id);
                }
            }
            EvtDet::TaPublished(delta) => {
                let ta_key = self.ta_key_mut().unwrap();
                ta_key.apply_delta(delta);
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
            CmdDet::UpdateRcvdCert(parent, class_name, rcvd_cert, signer) => {
                self.update_received_cert(parent, class_name, rcvd_cert, signer)
            }

            // Key rolls
            CmdDet::KeyRollInitiate(duration, signer) => self.keyroll_initiate(duration, signer),
            CmdDet::KeyRollActivate(duration, signer) => self.keyroll_activate(duration, signer),
            CmdDet::KeyRollFinish(parent, response) => self.keyroll_finish(parent, response),

            // Republish
            CmdDet::Republish(signer) => self.republish(signer),
        }
    }
}

/// # Data presentation
///
impl<S: Signer> CertAuth<S> {
    pub fn as_ta_info(&self) -> Result<TrustAnchorInfo> {
        if let CaParents::SelfSigned(key, tal) = &self.parents {
            let resources = key.incoming_cert().resources().clone();
            let repo_info = self.base_repo.clone();
            let children = self.children.clone();
            let cert = key.incoming_cert().clone();
            let tal = tal.clone();

            Ok(TrustAnchorInfo::new(
                resources, repo_info, children, cert, tal,
            ))
        } else {
            unimplemented!()
        }
    }

    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let base_repo = self.base_repo.clone();
        let parents = self.parents.as_info();
        let children = self.children.clone();

        CertAuthInfo::new(handle, base_repo, parents, children)
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
    ///
    /// Only supported in TAs until issue #25 is implemented.
    pub fn list(&self, child_handle: &Handle) -> Result<api::Entitlements> {
        // TODO: Support arbitrary resource classes. See issue #25.
        let mut classes = vec![];
        if let Some(class) = self.entitlement_class(child_handle, DFLT_CLASS) {
            classes.push(class);
        }

        Ok(Entitlements::new(classes))
    }

    /// Returns an issuance response for a child and a specific resource
    /// class name and public key for the issued certificate.
    pub fn issuance_response(
        &self,
        child_handle: &Handle,
        class_name: &str,
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
        class_name: &str,
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

        let cert = match &self.parents {
            CaParents::SelfSigned(key, _tal) => key.incoming_cert(),
            CaParents::Parents(_) => unimplemented!("Issue #25 (delegate from CA)"),
        };
        let cert = SigningCert::new(cert.uri().clone(), cert.cert().clone());

        Some(EntitlementClass::new(
            class_name.to_string(),
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

    /// Adds the child, returns an error if the child is a duplicate,
    /// or if the resources are not held by this CA, or (until #25) if
    /// this CA is not a TA.
    fn add_child(
        &self,
        child: ChildHandle,
        id_cert: Option<IdCert>,
        resources: ResourceSet,
    ) -> ca::Result<Vec<Evt>> {
        // check that
        // 1) the resource set is not empty
        if resources.is_empty() {
            return Err(Error::MustHaveResources);
        }

        // 2) the resources are held by me
        match &self.parents {
            CaParents::SelfSigned(key, _tal) => {
                if !key.incoming_cert().resources().contains(&resources) {
                    return Err(Error::MissingResources);
                }
            }
            CaParents::Parents(_map) => {
                unimplemented!("#25 Issue #25 (delegate from CA)");
            }
        }

        // 3) there is no existing child by this name
        if self.has_child(&child) {
            return Err(Error::DuplicateChild(child));
        }

        // TODO: Handle add child to normal CA (issue #25)
        let mut child_details = ChildCaDetails::new(id_cert);
        child_details.add_new_resource_class(DFLT_CLASS, resources);

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
    ///
    /// This CA is not a TA (until #25)
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
            &class_name,
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

        let publish_event = EvtDet::published_ta(&self.handle, self.version + 1, publication_delta);

        Ok(vec![issued_event, publish_event])
    }

    /// Issue a new child certificate.
    fn issue_child_certificate(
        &self,
        child: &ChildHandle,
        class_name: &ResourceClassName,
        pub_key: PublicKey,
        sia_info: CertSiaInfo,
        limit: RequestResourceLimit,
        signer: &S,
    ) -> Result<IssuanceResponse> {
        let issuing_key = match &self.parents {
            CaParents::SelfSigned(key, _tal) => key,
            CaParents::Parents(_) => unimplemented!("Issue #25 (delegate from CA)"),
        };

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
            class_name.clone(),
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
        _class_name: &ResourceClassName, // Issue #25
        issued_certs: Vec<&IssuedCert>,
        removed_certs: Vec<&Cert>,
        signer: Arc<RwLock<S>>,
    ) -> Result<PublicationDelta> {
        let issuing_key = match &self.parents {
            CaParents::SelfSigned(key, _tal) => key,
            CaParents::Parents(_) => unimplemented!("Issue #25 (delegate from CA)"),
        };

        let name_space = ""; // TODO: #25 use name space for RC

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

        SignSupport::publish(
            signer,
            issuing_key,
            &self.base_repo,
            name_space,
            objects_delta,
            revocations,
        )
        .map_err(Error::signer)
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
    fn shrink_child(
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
                                    class_name,
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
                        class_name,
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

                    events.push(EvtDet::TaPublished(publication_delta));
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
            let mut my_resources = HashMap::new();
            match &self.parents {
                CaParents::Parents(_parents_map) => unimplemented!("Issue #25"),
                CaParents::SelfSigned(key, _tal) => {
                    my_resources.insert(DFLT_CLASS, key.incoming_cert().resources());
                }
            }

            let all_my_resources = my_resources
                .values()
                .fold(ResourceSet::default(), |acc, res| acc.union(res));

            if !all_my_resources.contains(&resources) {
                return Err(Error::MissingResources);
            }

            // Map the new child resources to classes
            let mut child_entitlements = HashMap::new();
            for (class_name, resources_for_class) in my_resources.into_iter() {
                let child_resources_for_class = resources_for_class.intersection(&resources);
                if !child_resources_for_class.is_empty() {
                    child_entitlements.insert(class_name.to_string(), child_resources_for_class);
                }
            }

            // Get the current child resources
            let mut child_resources = HashMap::new();
            for (class_name, child_rc) in child.resources().iter() {
                child_resources.insert(class_name, child_rc.resources());
            }

            // Determine for each whether the entitlement is changed, added, or removed

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

            for class_name in child_resources.keys() {
                res.push(EvtDet::child_updated_resources(
                    &self.handle,
                    version,
                    child_handle.clone(),
                    class_name.to_string(),
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
        let class_name = request.class_name();
        let child_resources = self
            .get_child(&child)?
            .resources_for_class(class_name)
            .ok_or_else(|| Error::MissingResourceClass)?;

        let ca_key = match &self.parents {
            CaParents::SelfSigned(key, _) => key,
            CaParents::Parents(_map) => unimplemented!("Issue #25"),
        };

        // TODO For #25 find correct namespace for matching RC
        let name_space = "";

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

            let revoked = EvtDet::child_revoke_key(&self.handle, self.version, child, response);
            let published = EvtDet::published_ta(&self.handle, self.version + 1, pub_delta);

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
    /// Returns true if this CertAuth is set up as a TA.
    pub fn is_ta(&self) -> bool {
        self.parents.is_self_signed()
    }
    /// List all parents
    pub fn parents(&self) -> Result<Vec<(Handle, ParentCa)>> {
        match &self.parents {
            CaParents::SelfSigned(_, _) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => Ok(map.iter().map(|e| (e.0.clone(), e.1.clone())).collect()),
        }
    }

    pub fn parent(&self, parent: &Handle) -> Result<&ParentCa> {
        self.parents.get(parent)
    }

    fn parent_mut(&mut self, parent: &Handle) -> Result<&mut ParentCa> {
        self.parents.get_mut(parent)
    }

    fn ta_key_mut(&mut self) -> Result<&mut CertifiedKey> {
        self.parents.ta_key_mut()
    }

    /// Adds a parent. This method will return an error in case a parent
    /// by this name (handle) is already known.
    fn add_parent(&self, parent: Handle, info: ParentCaContact) -> ca::Result<Vec<Evt>> {
        self.parents.assert_parent_new(&parent)?;

        Ok(vec![EvtDet::parent_added(
            &self.handle,
            self.version,
            parent,
            info,
        )])
    }

    /// Get all the current open certificate requests for a parent.
    /// Returns an empty list if the parent is not found.
    pub fn cert_requests(&self, parent_handle: &ParentHandle) -> Vec<IssuanceRequest> {
        let mut res = vec![];

        if let Ok(parent) = self.parent(parent_handle) {
            for (_class_name, rc) in parent.resources.iter() {
                res.append(&mut rc.cert_requests())
            }
        }

        res
    }

    fn make_request_events(
        &self,
        version: &mut u64,
        parent: &ParentHandle,
        entitlement: &EntitlementClass,
        rc: &ResourceClass,
        signer: &S,
    ) -> Result<Vec<Evt>> {
        let req_details_list =
            rc.make_request_events(parent.clone(), entitlement, &self.base_repo, signer)?;

        let mut res = vec![];
        for details in req_details_list.into_iter() {
            res.push(StoredEvent::new(&self.handle, *version, details));
            *version += 1;
        }
        Ok(res)
    }

    /// Returns the open revocation requests for the given parent.
    pub fn revoke_requests(&self, parent: &ParentHandle) -> Vec<&RevocationRequest> {
        let mut res = vec![];
        if let Ok(parent) = self.parent(parent) {
            for (_class_name, rc) in parent.resources.iter() {
                if let Some(req) = rc.revoke_request() {
                    res.push(req)
                }
            }
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

        let parent = self.parent(&parent_handle)?;

        // Check if there is a resource class for each entitlement
        let mut version = self.version;

        // Check if there are any current resource classes, now removed
        // from the entitlements. In which case we will have to clean them
        // up and un-publish everything there was.
        let current_resource_classes = &parent.resources;
        let entitled_classes: Vec<&str> = entitlements
            .classes()
            .iter()
            .map(|c| c.class_name())
            .collect();
        for (name, class) in current_resource_classes
            .iter()
            .filter(|(name, _class)| !entitled_classes.contains(&name.as_str()))
        {
            let signer = signer.read().unwrap();

            let delta = class.withdraw(&self.base_repo);
            let revocations = class.revoke(name.clone(), signer.deref())?;

            res.push(EvtDet::resource_class_removed(
                &self.handle,
                version,
                parent_handle.clone(),
                name.clone(),
                delta,
                revocations,
            ));
            version += 1;
        }

        for ent in entitlements.classes() {
            let name = ent.class_name();

            if let Some(rc) = parent.resources.get(name) {
                let signer = signer.read().unwrap();
                res.append(&mut self.make_request_events(
                    &mut version,
                    &parent_handle,
                    ent,
                    rc,
                    signer.deref(),
                )?);
            } else {
                // Create a resource class with a pending key
                let key_id = {
                    signer
                        .write()
                        .unwrap()
                        .create_key(PublicKeyFormat::default())
                        .map_err(Error::signer)?
                };

                let ns = format!("{}-{}", &parent_handle, name);
                let rc = ResourceClass::create(ns, key_id);
                let rc_add_version = version;
                version += 1;

                let signer = signer.read().unwrap();
                let mut request_events = self.make_request_events(
                    &mut version,
                    &parent_handle,
                    ent,
                    &rc,
                    signer.deref(),
                )?;

                let added = EvtDet::resource_class_added(
                    &self.handle,
                    rc_add_version,
                    parent_handle.clone(),
                    name.to_string(),
                    rc,
                );

                res.push(added);
                res.append(&mut request_events);
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
        class_name: ResourceClassName,
        rcvd_cert: RcvdCert,
        signer: Arc<RwLock<S>>,
    ) -> ca::Result<Vec<Evt>> {
        debug!(
            "CA {}: Updating received cert for class: {}",
            self.handle, class_name
        );
        let parent = self.parent(&parent_handle)?;
        let rc = parent.class(&class_name)?;
        let evt_details = rc.update_received_cert(
            rcvd_cert,
            &self.base_repo,
            parent_handle,
            class_name,
            signer,
        )?;

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
        match &self.parents {
            CaParents::SelfSigned(_, _) => Ok(vec![]), // pending IETF standard.
            CaParents::Parents(map) => {
                let mut signer = signer.write().unwrap();
                let mut version = self.version;
                let mut res = vec![];

                for (parent_handle, parent) in map.iter() {
                    for (class_name, class) in parent.resources().iter() {
                        for details in class
                            .keyroll_initiate(
                                parent_handle.clone(),
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
                }

                Ok(res)
            }
        }
    }

    fn keyroll_activate(&self, staging: Duration, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        match &self.parents {
            CaParents::SelfSigned(_, _) => Ok(vec![]),
            CaParents::Parents(map) => {
                let signer = signer.read().unwrap();
                let mut version = self.version;
                let mut res = vec![];

                for (parent_handle, parent) in map.iter() {
                    for (class_name, class) in parent.resources().iter() {
                        for details in class
                            .keyroll_activate(
                                parent_handle.clone(),
                                class_name.clone(),
                                staging,
                                signer.deref(),
                            )?
                            .into_iter()
                        {
                            res.push(StoredEvent::new(self.handle(), version, details));
                            version += 1;
                        }
                    }
                }
                Ok(res)
            }
        }
    }

    fn keyroll_finish(
        &self,
        parent_h: ParentHandle,
        response: RevocationResponse,
    ) -> ca::Result<Vec<Evt>> {
        match &self.parents {
            CaParents::SelfSigned(_, _) => Ok(vec![]),
            CaParents::Parents(map) => {
                let (class_name, _key_id) = response.unpack();
                let parent = map
                    .get(&parent_h)
                    .ok_or_else(|| Error::UnknownParent(parent_h.clone()))?;

                let rc = parent
                    .resources()
                    .get(&class_name)
                    .ok_or_else(|| Error::UnknownResourceClass(class_name.clone()))?;

                let finish_details = rc.keyroll_finish(parent_h, class_name, &self.base_repo)?;

                Ok(vec![StoredEvent::new(
                    self.handle(),
                    self.version,
                    finish_details,
                )])
            }
        }
    }
}

/// # Publishing
///
impl<S: Signer> CertAuth<S> {
    fn republish_delta_for_key(
        key: &CertifiedKey,
        repo_info: &RepoInfo,
        name_space: &str,
        signer: Arc<RwLock<S>>,
    ) -> Result<PublicationDelta> {
        let ca_repo = repo_info.ca_repository(name_space);
        let objects_delta = ObjectsDelta::new(ca_repo);
        SignSupport::publish(signer, key, repo_info, name_space, objects_delta, vec![])
            .map_err(Error::signer)
    }

    /// Republish objects for this CA
    pub fn republish(&self, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        let mut res = vec![];
        match &self.parents {
            CaParents::SelfSigned(key, _tal) => {
                if key.needs_publication() {
                    let delta =
                        Self::republish_delta_for_key(key, &self.base_repo, "", signer.clone())?;

                    res.push(EvtDet::published_ta(&self.handle, self.version, delta))
                }
            }
            CaParents::Parents(_map) => error!("Republishing CAs not implemented"),
        }
        Ok(res)
    }
}

//------------ ParentCa ------------------------------------------------------

/// This type defines a parent for a CA and includes the information
/// needed to contact it, as well as a map of all the ResourceClass-es
/// that the CA has under this parent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParentCa {
    contact: ParentCaContact,
    resources: HashMap<ResourceClassName, ResourceClass>,
}

impl ParentCa {
    fn resources(&self) -> &HashMap<ResourceClassName, ResourceClass> {
        &self.resources
    }

    fn as_info(&self) -> ParentCaInfo {
        let mut resources_info = HashMap::new();

        for el in self.resources.iter() {
            resources_info.insert(el.0.clone(), el.1.as_info());
        }

        ParentCaInfo::new(self.contact.clone(), resources_info)
    }

    pub fn without_resource(contact: ParentCaContact) -> Self {
        ParentCa {
            contact,
            resources: HashMap::new(),
        }
    }

    pub fn contact(&self) -> &ParentCaContact {
        &self.contact
    }

    fn class(&self, class_name: &str) -> Result<&ResourceClass> {
        self.resources
            .get(class_name)
            .ok_or_else(|| Error::UnknownResourceClass(class_name.to_string()))
    }

    fn class_mut(&mut self, class_name: &str) -> Result<&mut ResourceClass> {
        self.resources
            .get_mut(class_name)
            .ok_or_else(|| Error::UnknownResourceClass(class_name.to_string()))
    }
}
