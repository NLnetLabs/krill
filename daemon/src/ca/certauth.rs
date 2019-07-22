use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::{Deref};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::{TbsCert, KeyUsage, Overclaim};
use rpki::crypto::{PublicKey, PublicKeyFormat};
use rpki::csr::Csr;
use rpki::x509::{Serial, Validity, Time, Name};

use krill_commons::api::{
    self,
    DFLT_CLASS,
    EncodedHash,
    EntitlementClass,
    Entitlements,
    IssuanceRequest,
    SigningCert,
    RequestResourceLimit,
    IssuanceResponse
};
use krill_commons::api::admin::{
    Handle,
    ParentCaContact,
    Token,
    PubServerContact
};
use krill_commons::api::ca::{
    AddedObject,
    AllCurrentObjects,
    CaParentsInfo,
    CertAuthInfo,
    CertifiedKey,
    ChildCa,
    ChildCaDetails,
    CurrentObject,
    CurrentObjects,
    IssuedCert,
    KeyRef,
    ObjectName,
    ObjectsDelta,
    ParentCaInfo,
    PendingKey,
    PublicationDelta,
    RcvdCert,
    RepoInfo,
    ResourceClassInfo,
    ResourceSet,
    TrustAnchorInfo,
    TrustAnchorLocator,
    UpdatedObject,
};
use krill_commons::eventsourcing::Aggregate;
use krill_commons::remote::builder::{IdCertBuilder, SignedMessageBuilder};
use krill_commons::remote::id::IdCert;
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::remote::rfc8183::ChildRequest;
use krill_commons::remote::rfc6492;
use krill_commons::util::softsigner::SignerKeyId;

use ca::{
    self,
    CmdDet,
    Cmd,
    CertIssued,
    CertRequested,
    CertReceived,
    Error,
    Evt,
    EvtDet,
    Ini,
    ParentHandle,
    Result,
    Signer,
    SignSupport,
};


//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: SignerKeyId,
    cert: IdCert
}

impl Rfc8183Id {
    pub fn generate<S: Signer>(signer: &mut S) -> Result<Self> {
        let key = signer.create_key(PublicKeyFormat::default())
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
    Ta(CertifiedKey, TrustAnchorLocator)
}

//------------ CaParents ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CaParents {
    SelfSigned(CertifiedKey, TrustAnchorLocator),
    Parents(HashMap<Handle, ParentCa>)
}

impl CaParents {
    fn as_info(&self) -> CaParentsInfo {
        match self {
            CaParents::SelfSigned(key, tal) => {
                CaParentsInfo::SelfSigned(key.clone(), tal.clone())
            },
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
            CaParents::SelfSigned(_,_) => true,
            _ => false
        }
    }

    fn assert_parent_new(&self, parent: &Handle) -> Result<()> {
        match self {
            CaParents::SelfSigned(_,_) => Err(Error::NotAllowedForTa),
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
            CaParents::SelfSigned(_,_) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => {
                map.insert(handle, parent);
                Ok(())
            }
        }
    }

    fn get(&self, handle: &Handle) -> Result<&ParentCa> {
        match self {
            CaParents::SelfSigned(_,_) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => Ok(
                map.get(handle)
                    .ok_or_else(|| Error::UnknownParent(handle.clone()))?
            )
        }
    }

    fn get_mut(&mut self, handle: &Handle) -> Result<&mut ParentCa> {
        match self {
            CaParents::SelfSigned(_,_) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => Ok(
                map.get_mut(handle)
                    .ok_or_else(|| Error::UnknownParent(handle.clone()))?
            )
        }
    }

    fn ta_key_mut(&mut self) -> Result<&mut CertifiedKey> {
        match self {
            CaParents::SelfSigned(key,_) => Ok(key),
            CaParents::Parents(_map) => Err(Error::NotTa)
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

    phantom_signer: PhantomData<S>
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
            return Err(Error::NameReservedTa)
        }

        let parents = match ca_type {
            CaType::Child => CaParents::Parents(HashMap::new()),
            CaType::Ta(key, tal) => CaParents::SelfSigned(key, tal)
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

            phantom_signer: PhantomData
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Evt) {
        self.version += 1;
        match event.into_details() {
            // Being a parent
            EvtDet::ChildAdded(child) => {
                let (handle, details) = child.unwrap();
                self.children.insert(handle, details);
            },
            EvtDet::CertificateIssued(cert_issued) => {
                let (child_handle, response) = cert_issued.unwrap();
                let (class_name, _, _, issued) = response.unwrap();

                let child = self.children.get_mut(&child_handle).unwrap();

                child.add_cert(&class_name, issued);
            },

            // Being a child
            EvtDet::ParentAdded(handle, info) => {
                let parent = ParentCa::without_resource(info);
                self.parents.insert(handle, parent).unwrap();
            },
            EvtDet::ResourceClassAdded(parent, name, rc) => {
                // Evt cannot occur without parent existing
                self.parents.get_mut(&parent).unwrap()
                    .resources.insert(name, rc);
            }
            EvtDet::CertificateRequested(req) => {
                let (parent, status, req) = req.unwrap();
                let class = req.class_name().to_owned();
                self.parents.get_mut(&parent).unwrap()
                    .resources.get_mut(&class).unwrap()
                    .add_request(status, req)
            },
            EvtDet::PendingKeyActivated(parent, class_name, cert) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                rc.pending_key_activated(cert);
            }
            EvtDet::CertificateReceived(_rcvd) => {
                unimplemented!()
            },

            // General functions
            EvtDet::Published(parent, class_name, status, delta) => {
                let parent = self.parent_mut(&parent).unwrap();
                let rc = parent.class_mut(&class_name).unwrap();
                let ck = rc.get_key_mut(status).unwrap();
                ck.apply_delta(delta);
            },
            EvtDet::TaPublished(delta) => {
                let ta_key = self.ta_key_mut().unwrap();
                ta_key.apply_delta(delta);
            }

        }
    }

    fn process_command(&self, command: Cmd<S>) -> ca::Result<Vec<Evt>> {
        match command.into_details() {
            // being a parent
            CmdDet::AddChild(child, token, id_cert_opt, resources) =>  {
                self.add_child(child, token, id_cert_opt, resources)
            },
            CmdDet::CertifyChild(child, request, token, signer) => {
                self.certify_child(child, request, token, signer)
            }

            // being a child
            CmdDet::AddParent(parent, info) => {
                self.add_parent(parent,info)
            },
            CmdDet::UpdateEntitlements(parent, entitlements, signer) => {
                self.update_entitlements(parent, entitlements, signer)
            },
            CmdDet::UpdateRcvdCert(parent, class_name, rcvd_cert, signer) => {
                self.update_received_cert(parent, class_name, rcvd_cert, signer)
            },

            // general CA functions
            CmdDet::Republish(signer) => {
                self.republish(signer)
            }
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
            let children  = self.children.clone();
            let cert = key.incoming_cert().clone();
            let tal = tal.clone();


            Ok(TrustAnchorInfo::new(
                resources,
                repo_info,
                children,
                cert,
                tal
            ))
        } else {
            unimplemented!()
        }
    }

    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let base_repo = self.base_repo.clone();
        let parents = self.parents.as_info();
        let children  = self.children.clone();

        CertAuthInfo::new(handle, base_repo, parents, children)
    }

    pub fn child_request(&self) -> ChildRequest {
        ChildRequest::new(self.handle.clone(), self.id.cert.clone())
    }

    pub fn id_cert(&self) -> &IdCert { &self.id.cert }
    pub(crate) fn id_key(&self) -> &SignerKeyId { &self.id.key }
    pub fn handle(&self) -> &Handle { &self.handle }
}

/// # Publishing
///
impl<S: Signer> CertAuth<S> {
    /// Returns all current objects for all parents, resource classes and keys
    pub fn current_objects(&self) -> AllCurrentObjects {
        let mut objects = AllCurrentObjects::empty();

        match &self.parents {
            CaParents::SelfSigned(key, _tal) => {
                objects.add_name_space(DFLT_CLASS, key.current_set().objects())
            },
            CaParents::Parents(parents) => {
                for parent in parents.values() {
                    for rc in parent.resources.values() {
                        let ns = rc.name_space();
                        if let Some(new_objects) = rc.new_objects() {
                            objects.add_name_space(ns, new_objects);
                        }
                        if let Some(current_objects) = rc.current_objects() {
                            objects.add_name_space(ns, current_objects);
                        }
                        if let Some(revoke_objects) = rc.revoke_objects() {
                            objects.add_name_space(ns, revoke_objects);
                        }
                    }
                }
            }
        }

        objects
    }

    fn republish_delta_for_key(
        key: &CertifiedKey,
        repo_info: &RepoInfo,
        name_space: &str,
        signer: Arc<RwLock<S>>
    ) -> Result<PublicationDelta> {
        let ca_repo = repo_info.ca_repository(name_space);
        let objects_delta = ObjectsDelta::new(ca_repo);
        SignSupport::publish(
            signer,
            key,
            repo_info,
            name_space,
            objects_delta
        ).map_err(Error::signer)
    }

    /// Republish objects for this CA
    pub fn republish(&self, signer: Arc<RwLock<S>>) -> ca::Result<Vec<Evt>> {
        let mut res = vec![];
        match &self.parents {
            CaParents::SelfSigned(key, _tal) => {
                if key.needs_publication() {
                    let delta = Self::republish_delta_for_key(
                        key,
                        &self.base_repo,
                        "",
                        signer.clone()
                    )?;

                    res.push(EvtDet::published_ta(
                        &self.handle,
                        self.version,
                        delta
                    ))
                }
            },
            CaParents::Parents(_map) => {
                unimplemented!()
            }
        }
        Ok(res)
    }
}

/// # Being a parent
///
impl<S: Signer> CertAuth<S> {

    pub fn verify_rfc6492(
        &self,
        msg: SignedMessage
    ) -> Result<(rfc6492::Message, Token)> {
        let content = rfc6492::Message::from_signed_message(&msg)?;

        let child_handle = Handle::from(content.sender());
        let child = self.get_child(&child_handle)?;

        let child_cert = child.id_cert()
            .ok_or_else(|| Error::Unauthorized(child_handle))?;
        msg.validate(child_cert).map_err(|_| Error::InvalidRfc6492)?;

        let token = child.token().clone();

        Ok((content, token))
    }

    pub fn sign_rfc6492_response(
        &self,
        msg: rfc6492::Message,
        signer: &S
    ) -> Result<Bytes> {
        let key = &self.id.key;
        Ok(SignedMessageBuilder::create(
            key,
            signer,
            msg.into_bytes()
        ).map_err(Error::signer)?.as_bytes())
    }

    /// List entitlements (section 3.3.2 of RFC6492). Return an error if
    /// the child is not authorized -- or unknown etc.
    ///
    /// Only supported in TAs until issue #25 is implemented.
    pub fn list(
        &self,
        child_handle: &Handle,
        token: &Token
    ) -> Result<api::Entitlements> {
        // TODO: Support arbitrary resource classes. See issue #25.
        let dflt_entitlement_class = self.entitlement_class(
            child_handle,
            DFLT_CLASS,
            token
        )?;

        Ok(Entitlements::new(vec![dflt_entitlement_class]))
    }

    /// Returns an issuance response for a child and a specific resource
    /// class name and public key for the issued certificate.
    pub fn issuance_response(
        &self,
        child_handle: &Handle,
        class_name: &str,
        pub_key: &PublicKey,
        token: &Token
    ) -> Result<api::IssuanceResponse> {
        let entitlement_class = self.entitlement_class(
            child_handle,
            class_name,
            token
        )?;

        entitlement_class
            .into_issuance_response(pub_key)
            .ok_or_else(|| Error::NoIssuedCert)
    }


    /// Returns the EntitlementClass for this child for the given class name.
    fn entitlement_class(
        &self,
        child_handle: &Handle,
        class_name: &str,
        token: &Token
    ) -> Result<api::EntitlementClass> {
        let child = self.get_authorised_child(child_handle, token)?;

        let child_resources = child.resources_for_class(class_name)
            .ok_or_else(|| Error::MissingResources)?;

        let until = child_resources.not_after();
        let issued = child_resources.certs().cloned().collect();

        let cert = match &self.parents {
            CaParents::SelfSigned(key, _tal) => key.incoming_cert(),
            CaParents::Parents(_) => unimplemented!("Issue #25 (delegate from CA)")
        };
        let resources = cert.resources().clone();
        let cert = SigningCert::new(cert.uri().clone(), cert.cert().clone());

        Ok(EntitlementClass::new(
            class_name.to_string(),
            cert,
            resources,
            until,
            issued
        ))
    }

    /// Returns an authorized child, or an error if the child is not
    /// authorized or unknown.
    pub fn get_authorised_child(
        &self,
        child_handle: &Handle,
        token: &Token
    ) -> Result<&ChildCaDetails> {
        let child = self.get_child(child_handle)?;

        if token != child.token() {
            Err(Error::Unauthorized(child_handle.clone()))
        } else {
            Ok(child)
        }
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(&self, child: &Handle) -> Result<&ChildCaDetails> {
        match self.children.get(child) {
            None => Err(Error::UnknownChild(child.clone())),
            Some(child) => Ok(child)
        }
    }

    /// Adds the child, returns an error if the child is a duplicate,
    /// or if the resources are not held by this CA, or (until #25) if
    /// this CA is not a TA.
    fn add_child(
        &self,
        handle: Handle,
        token: Token,
        id_cert: Option<IdCert>,
        resources: ResourceSet
    ) -> ca::Result<Vec<Evt>> {
        // check that
        // 1) the resource set is not empty
        if resources.is_empty() {
            return Err(Error::MustHaveResources)
        }

        // 2) the resources are held by me
        match &self.parents {
            CaParents::SelfSigned(key, _tal) => {
                if ! key.incoming_cert().resources().contains(&resources) {
                    return Err(Error::MissingResources)
                }
            },
            CaParents::Parents(_map) => {
                unimplemented!("#25 Issue #25 (delegate from CA)");
            }
        }

        // 3) there is no existing child by this name
        if self.has_child(&handle) {
            return Err(Error::DuplicateChild(handle))
        }

        // TODO: Handle add child to normal CA (issue #25)
        let mut child = ChildCa::without_resources(handle, token, id_cert);
        child.add_resources(DFLT_CLASS, resources);


        Ok(vec![EvtDet::child_added(
            &self.handle,
            self.version,
            child
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
        token: Token,
        signer: Arc<RwLock<S>>
    ) -> ca::Result<Vec<Evt>> {
        let (class_name, limit, csr) = request.unwrap();

        let issuing_key = match &self.parents {
            CaParents::SelfSigned(key, _tal) => key,
            CaParents::Parents(_) => unimplemented!("Issue #25 (delegate from CA)")
        };

        let issuing_cert = issuing_key.incoming_cert();

        // verify child and resources
        let child_resources = self.get_authorised_child(&child, &token)?
            .resources_for_class(&class_name)
            .ok_or_else(|| Error::MissingResourceClass)?;

        if child_resources.resources().is_empty() {
            return Err(Error::MissingResources)
        }

        let resources = limit.resolve(child_resources.resources())
            .ok_or_else(|| Error::MissingResources)?;

        csr.validate()
            .map_err(|_| Error::invalid_csr(&child, "invalid signature"))?;

        // TODO: Check for key-re-use, ultimately return 1204 (RFC6492 3.4.1)
        let current_cert = child_resources.cert(csr.public_key());

        // create new cert
        let issued_cert = {
            let serial = {
                Serial::random(signer.read().unwrap().deref())
                    .map_err(Error::signer)?
            };
            let issuer = issuing_cert.cert().subject().clone();

            let validity = Validity::new(
                Time::now() - Duration::minutes(3),
                child_resources.not_after()
            );

            let subject = Some(Name::from_pub_key(csr.public_key()));
            let pub_key = csr.public_key().clone();

            let key_usage = KeyUsage::Ca;
            let overclaim = Overclaim::Refuse;

            let mut cert = TbsCert::new(
                serial, issuer, validity, subject, pub_key, key_usage, overclaim
            );
            cert.set_basic_ca(Some(true));

            // Note! The issuing CA is not authoritative over *where* the child CA
            // may publish. I.e. it will sign over any claimed URIs by the child,
            // and assume that they will not be able to do anything malicious,
            // because the publication server for those URIs should verify the
            // identity of the publisher, and that RPs will not invalidate the
            // content of another CA's repo, if they it is wrongfully claimed.
            let ca_repository = csr.ca_repository()
                .ok_or_else(|| Error::invalid_csr(&child, "missing ca repo"))?;
            let rpki_manifest = csr.rpki_manifest()
                .ok_or_else(|| Error::invalid_csr(&child, "missing mft uri"))?;
            let rpki_notify = csr.rpki_notify();

            cert.set_ca_issuer(Some(issuing_cert.uri().clone()));
            cert.set_crl_uri(Some(issuing_cert.crl_uri()));

            cert.set_ca_repository(Some(ca_repository.clone()));
            cert.set_rpki_manifest(Some(rpki_manifest.clone()));
            cert.set_rpki_notify(rpki_notify.cloned());

            cert.set_as_resources(Some(resources.asn().clone()));
            cert.set_v4_resources(Some(resources.v4().deref().clone()));
            cert.set_v6_resources(Some(resources.v6().deref().clone()));

            cert.set_authority_key_identifier(
                Some(issuing_cert.cert().subject_key_identifier())
            );

            let cert = {
                cert.into_cert(
                    signer.read().unwrap().deref(),
                    issuing_key.key_id()
                ).map_err(Error::signer)?
            };

            let cert_uri = issuing_cert.uri_for_object(&cert);

            IssuedCert::new(cert_uri, limit, resources.clone(), cert)
        };

        let version = self.version;
        let cert_object = CurrentObject::from(issued_cert.cert());

        let signing_cert = SigningCert::from(issuing_cert);

        let cert_issued = CertIssued::new(
            child,
            IssuanceResponse::new(
                DFLT_CLASS.to_string(),
                signing_cert,
                resources,
                issued_cert.cert().validity().not_after(),
                issued_cert.clone()
            )
        );

        let issued_event = EvtDet::certificate_issued(
            &self.handle,
            version,
            cert_issued
        );

        let delta = {
            let ca_repo = self.base_repo.ca_repository("");
            let mut delta = ObjectsDelta::new(ca_repo);
            let cert_name = ObjectName::from(issued_cert.cert());

            match current_cert {
                None => {
                    delta.add(AddedObject::new(cert_name,cert_object))
                },
                Some(old) => {
                    let old_hash = EncodedHash::from_content(
                        old.cert().to_captured().as_slice()
                    );
                    delta.update(UpdatedObject::new(
                        cert_name, cert_object, old_hash
                    ))
                }
            }
            delta
        };

        let publish_event = EvtDet::published_ta(
            &self.handle,
            version + 1,
            SignSupport::publish(
                signer,
                issuing_key,
                &self.base_repo,
                "",
                delta
            ).map_err(Error::signer)?
        );

        Ok(vec![issued_event, publish_event])
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
            CaParents::SelfSigned(_,_) => Err(Error::NotAllowedForTa),
            CaParents::Parents(map) => {
                Ok(map.iter().map(|e| (e.0.clone(), e.1.clone())).collect())
            }
        }
    }

    fn parent(&self, parent: &Handle) -> Result<&ParentCa> {
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
    fn add_parent(
        &self,
        parent: Handle,
        info: ParentCaContact
    ) -> ca::Result<Vec<Evt>> {

        self.parents.assert_parent_new(&parent)?;

        Ok(vec![EvtDet::parent_added(
            &self.handle,
            self.version,
            parent,
            info
        )])
    }

    /// Get all the current open certificate requests for a parent.
    /// Returns an empty list if the parent is not found.
    pub fn cert_requests(&self, parent_handle: &ParentHandle) -> Vec<CertRequested> {
        let mut res = vec![];

        if let Ok(parent)= self.parent(parent_handle) {
            for (_class_name, rc) in parent.resources.iter() {
                if let Some(p) = &rc.pending_key {
                    if let Some(r) = p.request() {
                        res.push(
                            CertRequested::new(
                                parent_handle.clone(),
                                KeyStatus::Pending,
                                r.clone()
                            )
                        )
                    }
                }
            }
        }

        res
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
    ) -> ca::Result<Vec<Evt>> {
        let mut res = vec![];

        let parent = self.parent(&parent_handle)?;

        // Check if there is a resource class for each entitlement
        let mut version = self.version;
        for ent in entitlements.classes() {

            let name = ent.class_name();

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

                let cert_issue_req = CertRequested::new(
                    parent_handle.clone(),
                    KeyStatus::Pending,
                    IssuanceRequest::new(
                        ent.class_name().to_string(),
                        RequestResourceLimit::default(),
                        csr
                    )
                );

                let added = EvtDet::resource_class_added(
                    &self.handle,
                    version,
                    parent_handle.clone(),
                    name.to_string(),
                    rc
                );

                version += 1;

                let req = EvtDet::certificate_requested(
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
    ) -> ca::Result<Vec<Evt>> {
        debug!("CA {}: Updating received cert for {}", self.handle, class_name);
        let parent = self.parent(&parent_handle)?;
        let rc = parent.class(&class_name)?;

        let mut res = vec![];

        let mut status = rc.match_cert(
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
                rc.new_status_for_pending(),
                version
            )?
        } else {
            self.update_cert_for_certified_key(
                &handle,
                &parent_handle,
                &class_name,
                rcvd_cert.clone(),
                status,
                version
            )
        };

        res.push(event);
        version += 1;


        // Get the key that needs publishing and apply the cert to it.
        let key_to_publish = match status {
            KeyStatus::Pending => {
                let (key_id, _req) = rc.pending_key.clone().unwrap().unwrap();
                CertifiedKey::new(key_id, rcvd_cert)
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
            status = rc.new_status_for_pending()
        }

        res.push(EvtDet::published(
            &handle,
            version,
            parent_handle,
            class_name,
            status,
            SignSupport::publish(
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
    ) -> Result<Evt> {
        match new_status {
            KeyStatus::Pending =>
                Err(Error::KeyStatusChange(KeyStatus::Pending,
                                           KeyStatus::Pending)),

            KeyStatus::New => unimplemented!("Issue #23 (key rolls)"),

            KeyStatus::Current => {
                Ok(EvtDet::pending_activated(
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
    ) -> Evt {
        EvtDet::certificate_received(
            handle,
            version,
            CertReceived::new(
                parent_handle.clone(),
                class_name.to_string(),
                status,
                cert
            )
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
    fn as_info(&self) -> ParentCaInfo {
        let mut resources_info = HashMap::new();

        for el in self.resources.iter() {
            resources_info.insert(el.0.clone(), el.1.as_info());
        }

        ParentCaInfo::new(self.contact.clone(), resources_info)
    }

    pub fn without_resource(contact: ParentCaContact) -> Self {
        ParentCa { contact, resources: HashMap::new() }
    }

    pub fn contact(&self) -> &ParentCaContact { &self.contact }

    fn class(&self, class_name: &str) -> Result<&ResourceClass> {
        self.resources.get(class_name)
            .ok_or_else(|| Error::UnknownResourceClass(class_name.to_string()))
    }

    fn class_mut(&mut self, class_name: &str) -> Result<&mut ResourceClass> {
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
    pending_key: Option<PendingKey>,
    new_key: Option<CertifiedKey>,
    current_key: Option<CertifiedKey>,
    revoke_key: Option<CertifiedKey>
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
            revoke_key: None
        }
    }

    pub fn add_request(
        &mut self,
        status: KeyStatus,
        req: IssuanceRequest
    ) {
        match status {
            KeyStatus::Pending => {
                self.pending_key.as_mut().unwrap().add_request(req);
            },
            KeyStatus::New => {
                self.new_key.as_mut().unwrap().add_request(req);
            },
            KeyStatus::Current => {
                self.current_key.as_mut().unwrap().add_request(req);
            },
            KeyStatus::Revoke => {
                self.revoke_key.as_mut().unwrap().add_request(req);
            },
        }
    }

    pub fn name_space(&self) -> &str { &self.name_space }

    pub fn new_objects(&self) -> Option<&CurrentObjects> {
        self.new_key.as_ref().map(|k| k.current_set().objects())
    }

    pub fn current_objects(&self) -> Option<&CurrentObjects> {
        self.current_key.as_ref().map(|k| k.current_set().objects())
    }

    pub fn revoke_objects(&self) -> Option<&CurrentObjects> {
        self.revoke_key.as_ref().map(|k| k.current_set().objects())
    }

    /// Returns a ResourceClassInfo for this, which contains all the
    /// same data, but which does not have any behaviour.
    pub fn as_info(&self) -> ResourceClassInfo {
        ResourceClassInfo::new(
            self.name_space.clone(),
            self.pending_key.clone(),
            self.new_key.clone(),
            self.current_key.clone(),
            self.revoke_key.clone()
        )
    }

}

/// # Request certificates
///
impl ResourceClass {
    /// Creates CSRs for all keys in this resource class that can use a new
    /// certificate based on the current cert they have, and the entitlement.
    pub fn request_certs<S: Signer>(
        &self,
        _entitlement: &EntitlementClass,
        base_repo: &RepoInfo,
        signer: &Arc<RwLock<S>>
    ) -> Result<Vec<Csr>> {
        let mut res = vec![];
        let signer = signer.read().map_err(Error::signer)?;

        if let Some(key) = self.pending_key.as_ref() {
            let csr = self.create_csr(base_repo, key.key_id(), signer.deref())?;
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
    fn create_csr<S: Signer>(
        &self,
        base_repo: &RepoInfo,
        key: &SignerKeyId,
        signer: &S
    ) -> Result<Csr> {
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
    fn get_key_mut(&mut self, status: KeyStatus) -> Option<&mut CertifiedKey> {
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
        let (key_id, _req) = self.pending_key.take().unwrap().unwrap();
        let certified_key = CertifiedKey::new(key_id, cert);
        self.current_key = Some(certified_key);
    }


    /// Returns the new status for a pending key which receives a RcvdCert.
    fn new_status_for_pending(&self) -> KeyStatus {
        if self.current_key.is_some() {
            KeyStatus::New
        } else {
            KeyStatus::Current
        }
    }


    /// This function will find the status of the matching key for a received
    /// certificate. An error is returned if no matching key could be found.
    fn match_cert<S: Signer>(
        &self,
        rcvd_cert: &RcvdCert,
        signer: &S
    ) -> Result<KeyStatus> {
        self.match_key(
            rcvd_cert.cert().subject_public_key_info(),
            signer
        )
    }

    /// Helper to find which of the key_id-s of held keys in different stages
    /// match the public key, and return that status. Returns an error if
    /// there is no match.
    fn match_key<S: Signer>(
        &self,
        pub_key: &PublicKey,
        signer: &S
    ) -> ca::Result<KeyStatus> {

        if self.matches_key_id(
            self.pending_key.as_ref().map(PendingKey::key_id),
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
    fn matches_key_id<S: Signer>(
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

#[derive(Copy, Clone, Debug, Deserialize, Display, Eq, Serialize, PartialEq)]
pub enum KeyStatus {
    Pending,
    New,
    Current,
    Revoke
}


