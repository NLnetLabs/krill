use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crypto::{KeyIdentifier, PublicKey};
use rpki::rta::RtaBuilder;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::{
    self, CertAuthInfo, ChildHandle, EntitlementClass, Entitlements, Handle, IdCertPem, IssuanceRequest, IssuedCert,
    ObjectsDelta, ParentCaContact, ParentHandle, RcvdCert, RepositoryContact, RequestResourceLimit, ResourceClassName,
    ResourceSet, Revocation, RevocationRequest, RevocationResponse, RoaDefinition, RtaList, RtaName, RtaPrepResponse,
    SigningCert, StorableCaCommand, TaCertDetails, TrustAnchorLocator,
};
use crate::commons::crypto::{CsrInfo, IdCert, IdCertBuilder, KrillSigner, ProtocolCms, ProtocolCmsBuilder};
use crate::commons::error::{Error, RoaDeltaError};
use crate::commons::eventsourcing::{Aggregate, StoredEvent};
use crate::commons::remote::rfc6492;
use crate::commons::remote::rfc8183;
use crate::commons::KrillResult;
use crate::daemon::ca::events::ChildCertificateUpdates;
use crate::daemon::ca::rc::PublishMode;
use crate::daemon::ca::{
    ta_handle, ChildDetails, Cmd, CmdDet, CurrentObjectSetDelta, Evt, EvtDet, Ini, PreparedRta, ResourceClass,
    ResourceTaggedAttestation, RouteAuthorization, RouteAuthorizationUpdates, Routes, RtaContentRequest,
    RtaPrepareRequest, Rtas, SignedRta,
};
use crate::daemon::config::{Config, IssuanceTimingConfig};

//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: KeyIdentifier, // convenient (and efficient) access
    cert: IdCert,
}

impl Rfc8183Id {
    pub fn generate(signer: &KrillSigner) -> KrillResult<Self> {
        let key = signer.create_key()?;
        let cert =
            IdCertBuilder::new_ta_id_cert(&key, signer.deref()).map_err(|e| Error::SignerError(e.to_string()))?;
        Ok(Rfc8183Id { key, cert })
    }
}

impl Rfc8183Id {
    pub fn key_hash(&self) -> String {
        self.cert.ski_hex()
    }
}

//------------ CertAuth ----------------------------------------------------

/// This type defines a Certification Authority at a slightly higher level
/// than one might expect.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertAuth {
    handle: Handle,
    version: u64,

    id: Rfc8183Id, // Used for RFC 6492 (up-down) and RFC 8181 (publication)

    repository: Option<RepositoryContact>,
    repository_pending_withdraw: Option<RepositoryContact>,

    parents: HashMap<ParentHandle, ParentCaContact>,

    next_class_name: u32,
    resources: HashMap<ResourceClassName, ResourceClass>,

    children: HashMap<ChildHandle, ChildDetails>,
    routes: Routes,

    #[serde(skip_serializing_if = "Rtas::is_empty", default = "Rtas::default")]
    rtas: Rtas,
}

impl Aggregate for CertAuth {
    type Command = Cmd;
    type StorableCommandDetails = StorableCaCommand;
    type Event = Evt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Ini) -> KrillResult<Self> {
        let (handle, _version, details) = event.unpack();
        let (id, repo_info, ta_opt) = details.unpack();

        let mut parents = HashMap::new();
        let mut resources = HashMap::new();
        let mut next_class_name = 0;

        let children = HashMap::new();
        let routes = Routes::default();
        let rtas = Rtas::default();

        if let Some(ta_details) = ta_opt {
            let key_id = ta_details.cert().subject_key_identifier();
            parents.insert(ta_handle(), ParentCaContact::Ta(ta_details));

            let rcn = ResourceClassName::from(next_class_name);
            next_class_name += 1;
            resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
        }

        let repository = repo_info.map(RepositoryContact::embedded);

        Ok(CertAuth {
            handle,
            version: 1,

            id,

            repository,
            repository_pending_withdraw: None,

            parents,

            next_class_name,
            resources,

            children,

            routes,
            rtas,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Evt) {
        self.version += 1;
        match event.into_details() {
            //-----------------------------------------------------------------------
            // Being a trust anchor
            //-----------------------------------------------------------------------
            EvtDet::TrustAnchorMade(details) => {
                let key_id = details.cert().subject_key_identifier();
                self.parents.insert(ta_handle(), ParentCaContact::Ta(details));
                let rcn = ResourceClassName::from(self.next_class_name);
                self.next_class_name += 1;
                self.resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
            }

            //-----------------------------------------------------------------------
            // Being a parent
            //-----------------------------------------------------------------------
            EvtDet::ChildAdded(child, details) => {
                self.children.insert(child, details);
            }
            EvtDet::ChildCertificateIssued(child, rcn, ki) => {
                self.children.get_mut(&child).unwrap().add_issue_response(rcn, ki);
            }

            EvtDet::ChildKeyRevoked(child, rcn, ki) => {
                self.resources.get_mut(&rcn).unwrap().key_revoked(&ki);

                self.children.get_mut(&child).unwrap().add_revoke_response(ki);
            }

            EvtDet::ChildCertificatesUpdated(rcn, updates) => {
                let rc = self.resources.get_mut(&rcn).unwrap();
                let (issued, removed) = updates.unpack();
                for iss in issued {
                    rc.certificate_issued(iss)
                }
                for rem in removed {
                    rc.key_revoked(&rem);

                    // This loop is inefficient, but certificate revocations are not that common, so it's
                    // not a big deal. Tracking this better would require that track the child handle somehow.
                    // That is a bit hard when this revocation is the result from a republish where we lost
                    // all resources delegated to the child.
                    for child in self.children.values_mut() {
                        if child.is_issued(&rem) {
                            child.add_revoke_response(rem)
                        }
                    }
                }
            }

            EvtDet::ChildUpdatedIdCert(child, cert) => self.children.get_mut(&child).unwrap().set_id_cert(cert),

            EvtDet::ChildUpdatedResources(child, resources) => {
                self.children.get_mut(&child).unwrap().set_resources(resources)
            }

            EvtDet::ChildRemoved(child) => {
                self.children.remove(&child);
            }

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            EvtDet::IdUpdated(id) => {
                self.id = id;
            }
            EvtDet::ParentAdded(handle, info) => {
                self.parents.insert(handle, info);
            }
            EvtDet::ParentUpdated(handle, info) => {
                self.parents.insert(handle, info);
            }
            EvtDet::ParentRemoved(handle, _deltas) => {
                self.parents.remove(&handle);
                self.resources.retain(|_, rc| rc.parent_handle() != &handle);
            }

            EvtDet::ResourceClassAdded(name, rc) => {
                self.next_class_name += 1;
                self.resources.insert(name, rc);
            }
            EvtDet::ResourceClassRemoved(name, _delta, _parent, _revocations) => {
                self.resources.remove(&name);
            }
            EvtDet::CertificateRequested(name, req, status) => {
                self.resources.get_mut(&name).unwrap().add_request(status, req);
            }
            EvtDet::CertificateReceived(class_name, key_id, cert) => {
                self.resources.get_mut(&class_name).unwrap().received_cert(key_id, cert);
            }

            //-----------------------------------------------------------------------
            // Key Life Cycle
            //-----------------------------------------------------------------------
            EvtDet::KeyRollPendingKeyAdded(class_name, key_id) => {
                self.resources.get_mut(&class_name).unwrap().pending_key_added(key_id);
            }
            EvtDet::KeyPendingToNew(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_new(key);
            }
            EvtDet::KeyPendingToActive(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_active(key);
            }
            EvtDet::KeyRollActivated(class_name, revoke_req) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .new_key_activated(revoke_req);
            }
            EvtDet::KeyRollFinished(class_name, _delta) => {
                self.resources.get_mut(&class_name).unwrap().old_key_removed();
            }
            EvtDet::UnexpectedKeyFound(_, _) => {
                // no action needed, this is marked to flag that a key may be removed
            }

            //-----------------------------------------------------------------------
            // Route Authorizations
            //-----------------------------------------------------------------------
            EvtDet::RouteAuthorizationAdded(update) => self.routes.add(update),
            EvtDet::RouteAuthorizationRemoved(removal) => {
                self.routes.remove(&removal);
            }
            EvtDet::RoasUpdated(rcn, updates) => self.resources.get_mut(&rcn).unwrap().roas_updated(updates),

            //-----------------------------------------------------------------------
            // Publication
            //-----------------------------------------------------------------------
            EvtDet::ObjectSetUpdated(class_name, delta_map) => {
                let rc = self.resources.get_mut(&class_name).unwrap();
                for (key_id, delta) in delta_map.into_iter() {
                    rc.apply_delta(delta, key_id);
                }
            }
            EvtDet::RepoUpdated(contact) => {
                if let Some(current) = &self.repository {
                    self.repository_pending_withdraw = Some(current.clone())
                }
                self.repository = Some(contact);
            }
            EvtDet::RepoCleaned(_) => {
                self.repository_pending_withdraw = None;
            }

            //-----------------------------------------------------------------------
            // Resource Tagged Attestations
            //-----------------------------------------------------------------------
            EvtDet::RtaPrepared(name, prepared) => {
                self.rtas.add_prepared(name, prepared);
            }
            EvtDet::RtaSigned(name, signed) => {
                self.rtas.add_signed(name, signed);
            }
        }
    }

    fn process_command(&self, command: Cmd) -> KrillResult<Vec<Evt>> {
        info!(
            "Sending command to CA '{}', version: {}: {}",
            self.handle, self.version, command
        );

        match command.into_details() {
            // trust anchor
            CmdDet::MakeTrustAnchor(uris, signer) => self.trust_anchor_make(uris, signer),

            // being a parent
            CmdDet::ChildAdd(child, id_cert_opt, resources) => self.child_add(child, id_cert_opt, resources),
            CmdDet::ChildUpdateResources(child, res) => self.child_update_resources(&child, res),
            CmdDet::ChildUpdateId(child, id) => self.child_update_id(&child, id),
            CmdDet::ChildCertify(child, request, config, signer) => self.child_certify(child, request, &config, signer),
            CmdDet::ChildRevokeKey(child, request, config, signer) => {
                self.child_revoke_key(child, request, &config.issuance_timing, signer)
            }
            CmdDet::ChildRemove(child, config, signer) => self.child_remove(&child, &config.issuance_timing, signer),

            // being a child
            CmdDet::GenerateNewIdKey(signer) => self.generate_new_id_key(signer),
            CmdDet::AddParent(parent, info) => self.add_parent(parent, info),
            CmdDet::UpdateParentContact(parent, info) => self.update_parent(parent, info),
            CmdDet::RemoveParent(parent) => self.remove_parent(parent),

            CmdDet::UpdateResourceClasses(parent, entitlements, signer) => {
                self.update_resource_classes(parent, entitlements, signer)
            }
            CmdDet::UpdateRcvdCert(class_name, rcvd_cert, config, signer) => {
                self.update_received_cert(class_name, rcvd_cert, &config.issuance_timing, signer)
            }

            // Key rolls
            CmdDet::KeyRollInitiate(duration, signer) => self.keyroll_initiate(duration, signer),
            CmdDet::KeyRollActivate(duration, config, signer) => {
                self.keyroll_activate(duration, &config.issuance_timing, signer)
            }
            CmdDet::KeyRollFinish(rcn, response) => self.keyroll_finish(rcn, response),

            // Route Authorizations
            CmdDet::RouteAuthorizationsUpdate(updates, config, signer) => {
                self.route_authorizations_update(updates, &config, signer)
            }

            // Republish
            CmdDet::Republish(config, signer) => self.republish(&config.issuance_timing, &signer),
            CmdDet::RepoUpdate(contact, config, signer) => self.update_repo(contact, &config.issuance_timing, &signer),
            CmdDet::RepoRemoveOld(_signer) => self.clean_repo(),

            // Resource Tagged Attestations
            CmdDet::RtaMultiPrepare(name, request, signer) => self.rta_multi_prep(name, request, signer.deref()),
            CmdDet::RtaCoSign(name, rta, signer) => self.rta_cosign(name, rta, signer.deref()),
            CmdDet::RtaSign(name, request, signer) => self.rta_sign(name, request, signer.deref()),
        }
    }
}

/// # Data presentation
///
impl CertAuth {
    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let repo_info = self.repository.as_ref().map(|repo| repo.repo_info().clone());

        let parents = self.parents.clone();

        let mut resources = HashMap::new();

        for (name, rc) in &self.resources {
            resources.insert(name.clone(), rc.as_info());
        }
        let children: Vec<ChildHandle> = self.children.keys().cloned().collect();

        let id_cert_pem = IdCertPem::from(&self.id.cert);

        CertAuthInfo::new(handle, id_cert_pem, repo_info, parents, resources, children)
    }

    pub fn roa_definitions(&self) -> Vec<RoaDefinition> {
        self.routes.authorizations().map(|a| a.as_ref()).cloned().collect()
    }

    pub fn child_request(&self) -> rfc8183::ChildRequest {
        rfc8183::ChildRequest::new(self.handle.clone(), self.id.cert.clone())
    }

    pub fn publisher_request(&self) -> rfc8183::PublisherRequest {
        rfc8183::PublisherRequest::new(None, self.handle.clone(), self.id_cert().clone())
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

/// # Publishing
///
impl CertAuth {
    pub fn all_objects(&self) -> Vec<PublishElement> {
        let mut res = vec![];
        if let Some(repo_info) = self.repository.as_ref().map(|r| r.repo_info()) {
            for rc in self.resources.values() {
                res.append(&mut rc.all_objects(repo_info));
            }
        }
        res
    }

    pub fn get_repository_contact(&self) -> KrillResult<&RepositoryContact> {
        self.repository.as_ref().ok_or(Error::RepoNotSet)
    }

    pub fn old_repository_contact(&self) -> Option<&RepositoryContact> {
        self.repository_pending_withdraw.as_ref()
    }
}

/// # Being a trustanchor
///
impl CertAuth {
    fn trust_anchor_make(&self, uris: Vec<uri::Https>, signer: Arc<KrillSigner>) -> KrillResult<Vec<Evt>> {
        if !self.resources.is_empty() {
            return Err(Error::custom("Cannot turn CA with resources into TA"));
        }

        let repo_info = self.get_repository_contact()?.repo_info();

        let key = signer.create_key()?;

        let resources = ResourceSet::all_resources();

        let cert = {
            let serial: Serial = signer.random_serial()?;

            let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
            let name = pub_key.to_subject_name();

            let mut cert = TbsCert::new(
                serial,
                name.clone(),
                Validity::new(Time::five_minutes_ago(), Time::years_from_now(100)),
                Some(name),
                pub_key.clone(),
                KeyUsage::Ca,
                Overclaim::Refuse,
            );

            cert.set_basic_ca(Some(true));

            let ns = ResourceClassName::default().to_string();

            cert.set_ca_repository(Some(repo_info.ca_repository(&ns)));
            cert.set_rpki_manifest(Some(repo_info.rpki_manifest(&ns, &pub_key.key_identifier())));
            cert.set_rpki_notify(Some(repo_info.rpki_notify()));

            cert.set_as_resources(resources.to_as_resources());
            cert.set_v4_resources(resources.to_ip_resources_v4());
            cert.set_v6_resources(resources.to_ip_resources_v6());

            signer.sign_cert(cert, &key)?
        };

        let tal = TrustAnchorLocator::new(uris, &cert);

        let ta_details = TaCertDetails::new(cert, resources, tal);

        Ok(vec![StoredEvent::new(
            &self.handle,
            self.version,
            EvtDet::TrustAnchorMade(ta_details),
        )])
    }
}

/// # Being a parent
///
impl CertAuth {
    pub fn verify_rfc6492(&self, msg: ProtocolCms) -> KrillResult<rfc6492::Message> {
        let content = rfc6492::Message::from_signed_message(&msg)?;

        let child_handle = content.sender();
        let child = self.get_child(child_handle)?;

        let child_cert = child
            .id_cert()
            .ok_or_else(|| Error::CaChildUnauthorized(self.handle.clone(), child_handle.clone()))?;

        msg.validate(child_cert).map_err(|_| Error::Rfc6492SignatureInvalid)?;

        Ok(content)
    }

    pub fn sign_rfc6492_response(&self, msg: rfc6492::Message, signer: &KrillSigner) -> KrillResult<Bytes> {
        let key = &self.id.key;
        Ok(ProtocolCmsBuilder::create(key, signer, msg.into_bytes())
            .map_err(Error::signer)?
            .as_bytes())
    }

    /// List entitlements (section 3.3.2 of RFC6492). Return an error if
    /// the child is not authorized -- or unknown etc.
    pub fn list(
        &self,
        child_handle: &Handle,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<api::Entitlements> {
        let mut classes = vec![];

        for rcn in self.resources.keys() {
            if let Some(class) = self.entitlement_class(child_handle, rcn, issuance_timing) {
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
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<api::IssuanceResponse> {
        let entitlement_class = self
            .entitlement_class(child_handle, class_name, issuance_timing)
            .ok_or_else(|| Error::KeyUseNoIssuedCert)?;

        entitlement_class
            .into_issuance_response(pub_key)
            .ok_or_else(|| Error::KeyUseNoIssuedCert)
    }

    /// Returns the EntitlementClass for this child for the given class name.
    fn entitlement_class(
        &self,
        child_handle: &Handle,
        rcn: &ResourceClassName,
        issuance_timing: &IssuanceTimingConfig,
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

        let child_keys = child.issued(rcn);

        let mut issued_certs = vec![];
        let mut not_after = Time::now();
        for ki in child_keys {
            if let Some(issued) = my_rc.issued(&ki) {
                issued_certs.push(issued.clone());
                let eligble_not_after = Self::child_cert_eligible_not_after(issued, issuance_timing);
                if eligble_not_after > not_after {
                    not_after = eligble_not_after
                }
            }
        }

        Some(EntitlementClass::new(
            rcn.clone(),
            issuer,
            child_resources,
            not_after,
            issued_certs,
        ))
    }

    fn child_cert_eligible_not_after(issued: &IssuedCert, issuance_timing: &IssuanceTimingConfig) -> Time {
        let expiration_time = issued.validity().not_after();
        if expiration_time
            > Time::now() + chrono::Duration::weeks(issuance_timing.timing_child_certificate_reissue_weeks_before)
        {
            expiration_time
        } else {
            Time::now() + chrono::Duration::weeks(issuance_timing.timing_child_certificate_valid_weeks)
        }
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(&self, child: &Handle) -> KrillResult<&ChildDetails> {
        match self.children.get(child) {
            None => Err(Error::CaChildUnknown(self.handle.clone(), child.clone())),
            Some(child) => Ok(child),
        }
    }

    /// Returns an iterator for the handles of all children under this CA.
    pub fn children(&self) -> impl Iterator<Item = &ChildHandle> {
        self.children.keys()
    }

    /// Adds the child, returns an error if the child is a duplicate,
    /// or if the resources are empty, or not held by this CA.
    fn child_add(&self, child: ChildHandle, id_cert: Option<IdCert>, resources: ResourceSet) -> KrillResult<Vec<Evt>> {
        if resources.is_empty() {
            Err(Error::CaChildMustHaveResources(self.handle.clone(), child))
        } else if !self.all_resources().contains(&resources) {
            Err(Error::CaChildExtraResources(self.handle.clone(), child))
        } else if self.has_child(&child) {
            Err(Error::CaChildDuplicate(self.handle.clone(), child))
        } else {
            let child_details = ChildDetails::new(id_cert, resources);

            Ok(vec![EvtDet::child_added(
                &self.handle,
                self.version,
                child,
                child_details,
            )])
        }
    }

    /// Certifies a child, unless:
    /// = the child is unknown,
    /// = the child is not authorized,
    /// = the csr is invalid,
    /// = the limit exceeds the child allocation,
    /// = the signer throws up..
    fn child_certify(
        &self,
        child: Handle,
        request: IssuanceRequest,
        config: &Config,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        let (rcn, limit, csr) = request.unpack();
        let csr_info = CsrInfo::try_from(&csr)?;

        if !csr_info.allowed_uris(config.test_mode) {
            return Err(Error::invalid_csr(
                "MUST use hostnames in URIs for certificate requests unless server uses TEST mode.",
            ));
        }

        let issued =
            self.issue_child_certificate(&child, rcn.clone(), csr_info, limit, &config.issuance_timing, &signer)?;

        let set_deltas = self.republish_certs(&rcn, &[&issued], &[], &config.issuance_timing, &signer)?;

        let issued_event = EvtDet::child_certificate_issued(
            &self.handle,
            self.version,
            child,
            rcn.clone(),
            issued.subject_key_identifier(),
        );

        let mut cert_updates = ChildCertificateUpdates::default();
        cert_updates.issue(issued);
        let child_certs_updated =
            EvtDet::child_certificates_updated(&self.handle, self.version + 1, rcn.clone(), cert_updates);

        let set_updated_event = EvtDet::current_set_updated(&self.handle, self.version + 2, rcn, set_deltas);

        Ok(vec![issued_event, child_certs_updated, set_updated_event])
    }

    /// Issue a new child certificate.
    fn issue_child_certificate(
        &self,
        child: &ChildHandle,
        rcn: ResourceClassName,
        csr_info: CsrInfo,
        limit: RequestResourceLimit,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCert> {
        let my_rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn))?;

        let child = self.get_child(&child)?;
        child.resources().apply_limit(&limit)?;

        my_rc.issue_cert(csr_info, child.resources(), limit, issuance_timing, signer)
    }

    /// Create a publish event details including the revocations, update, withdrawals needed
    /// for updating child certificates.
    fn republish_certs(
        &self,
        rcn: &ResourceClassName,
        issued_certs: &[&IssuedCert],
        removed_certs: &[&Cert],
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<HashMap<KeyIdentifier, CurrentObjectSetDelta>> {
        let repo = self.get_repository_contact()?;

        self.resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn.clone()))?
            .republish_certs(issued_certs, removed_certs, repo.repo_info(), issuance_timing, signer)
    }

    /// Updates child Resource entitlements.
    ///
    /// This does not yet revoke / reissue / republish anything.
    /// Also, this is a no-op if the child already has these resources.
    fn child_update_resources(&self, child_handle: &Handle, resources: ResourceSet) -> KrillResult<Vec<Evt>> {
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if &resources != child.resources() {
            res.push(EvtDet::child_updated_resources(
                &self.handle,
                self.version,
                child_handle.clone(),
                resources,
            ));
        }

        Ok(res)
    }

    /// Updates child IdCert
    fn child_update_id(&self, child_handle: &Handle, id_cert: IdCert) -> KrillResult<Vec<Evt>> {
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if Some(&id_cert) != child.id_cert() {
            res.push(EvtDet::child_updated_cert(
                &self.handle,
                self.version,
                child_handle.clone(),
                id_cert,
            ));
        }

        Ok(res)
    }

    /// Revokes a key for a child. So, add the last cert for the key to the CRL, and withdraw
    /// the .cer file for it.
    fn child_revoke_key(
        &self,
        child_handle: ChildHandle,
        request: RevocationRequest,
        issuance_timing: &IssuanceTimingConfig,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        let (rcn, key) = request.unpack();

        let child = self.get_child(&child_handle)?;

        if !child.is_issued(&key) {
            return Err(Error::KeyUseNoIssuedCert);
        }

        let my_rc = self.resources.get(&rcn).ok_or_else(|| Error::KeyUseNoIssuedCert)?;
        let removed = my_rc.issued(&key).ok_or_else(|| Error::KeyUseNoIssuedCert)?.cert();

        let handle = &self.handle;
        let version = self.version;

        let set_deltas = self.republish_certs(&rcn, &[], &[removed], issuance_timing, &signer)?;

        let mut child_certificate_updates = ChildCertificateUpdates::default();
        child_certificate_updates.remove(key);

        let rev = EvtDet::child_revoke_key(handle, version, child_handle, rcn.clone(), key);
        let wdr = EvtDet::current_set_updated(handle, version + 1, rcn.clone(), set_deltas);
        let upd = EvtDet::child_certificates_updated(handle, version + 2, rcn, child_certificate_updates);

        Ok(vec![rev, wdr, upd])
    }

    fn child_remove(
        &self,
        child_handle: &ChildHandle,
        issuance_timing: &IssuanceTimingConfig,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        let child = self.get_child(&child_handle)?;

        let mut version = self.version;
        let handle = &self.handle;

        let mut res = vec![];

        // Find all the certs in all RCs for this child and revoke, and unpublish them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut issued_certs = vec![];
            for key in certified_keys {
                if let Some(issued) = rc.issued(&key) {
                    issued_certs.push(issued);
                }
            }

            let removed: Vec<&Cert> = issued_certs.iter().map(|c| c.cert()).collect();
            let set_deltas = self.republish_certs(&rcn, &[], &removed, issuance_timing, &signer)?;
            res.push(EvtDet::current_set_updated(handle, version, rcn.clone(), set_deltas));
            version += 1;

            let mut cert_updates = ChildCertificateUpdates::default();
            for issued in issued_certs {
                cert_updates.remove(issued.subject_key_identifier())
            }
            res.push(EvtDet::child_certificates_updated(
                handle,
                version,
                rcn.clone(),
                cert_updates,
            ));
            version += 1;
        }

        res.push(EvtDet::child_removed(handle, version, child_handle.clone()));

        Ok(res)
    }

    /// Returns `true` if the child is known, `false` otherwise. No errors.
    fn has_child(&self, child_handle: &Handle) -> bool {
        self.children.contains_key(child_handle)
    }
}

/// # Being a child
///
impl CertAuth {
    /// Generates a new ID key for this CA.
    fn generate_new_id_key(&self, signer: Arc<KrillSigner>) -> KrillResult<Vec<Evt>> {
        let id = Rfc8183Id::generate(&signer)?;

        Ok(vec![EvtDet::id_updated(&self.handle, self.version, id)])
    }

    /// List all parents
    pub fn parents(&self) -> impl Iterator<Item = &ParentHandle> {
        self.parents.keys()
    }

    fn parent_known(&self, parent: &ParentHandle) -> bool {
        self.parents.contains_key(parent)
    }

    fn parent_for_info(&self, info: &ParentCaContact) -> Option<&ParentHandle> {
        for (parent, parent_info) in &self.parents {
            if parent_info == info {
                return Some(parent);
            }
        }
        None
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
    pub fn parent(&self, parent: &ParentHandle) -> KrillResult<&ParentCaContact> {
        self.parents
            .get(parent)
            .ok_or_else(|| Error::CaParentUnknown(self.handle.clone(), parent.clone()))
    }

    /// Find the parent for a given resource class name.
    pub fn parent_for_rc(&self, rcn: &ResourceClassName) -> KrillResult<&ParentHandle> {
        let rc = self
            .resources
            .get(rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn.clone()))?;
        Ok(rc.parent_handle())
    }

    /// Adds a parent. This method will return an error in case a parent
    /// by this name (handle) is already known. Or in case the same reponse
    /// is used for more than one parent.
    fn add_parent(&self, parent: Handle, info: ParentCaContact) -> KrillResult<Vec<Evt>> {
        if self.parent_known(&parent) {
            Err(Error::CaParentDuplicateName(self.handle.clone(), parent))
        } else if let Some(other) = self.parent_for_info(&info) {
            Err(Error::CaParentDuplicateInfo(self.handle.clone(), other.clone()))
        } else if self.is_ta() {
            Err(Error::TaNotAllowed)
        } else {
            Ok(vec![EvtDet::parent_added(&self.handle, self.version, parent, info)])
        }
    }

    /// Removes a parent. Returns an error if it doesn't exist.
    fn remove_parent(&self, parent: Handle) -> KrillResult<Vec<Evt>> {
        let _parent = self.parent(&parent)?;
        let repo = self.get_repository_contact()?;

        // remove the parent, the RCs and un-publish everything.
        let mut deltas = vec![];
        for rc in self.resources.values().filter(|rc| rc.parent_handle() == &parent) {
            deltas.push(rc.withdraw(repo.repo_info()));
        }

        Ok(vec![EvtDet::parent_removed(&self.handle, self.version, parent, deltas)])
    }

    /// Updates an existing parent's contact. This will return an error if
    /// the parent is not known.
    fn update_parent(&self, parent: Handle, info: ParentCaContact) -> KrillResult<Vec<Evt>> {
        if !self.parent_known(&parent) {
            Err(Error::CaParentUnknown(self.handle.clone(), parent))
        } else if self.is_ta() {
            Err(Error::TaNotAllowed)
        } else {
            Ok(vec![EvtDet::parent_updated(&self.handle, self.version, parent, info)])
        }
    }

    /// Maps a parent and parent's resource class name to a ResourceClassName and
    /// ResourceClass of our own.
    fn find_parent_rc(&self, parent: &ParentHandle, parent_rcn: &ResourceClassName) -> Option<&ResourceClass> {
        for rc in self.resources.values() {
            if rc.parent_handle() == parent && rc.parent_rc_name() == parent_rcn {
                return Some(rc);
            }
        }
        None
    }

    /// Get all the current open certificate requests for a parent.
    /// Returns an empty list if the parent is not found.
    pub fn cert_requests(&self, parent_handle: &ParentHandle) -> HashMap<ResourceClassName, Vec<IssuanceRequest>> {
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
        signer: &KrillSigner,
    ) -> KrillResult<Vec<Evt>> {
        let repo = self.get_repository_contact()?;
        let parent_class_name = entitlement.class_name().clone();
        let req_details_list = rc.make_entitlement_events(entitlement, repo.repo_info(), signer)?;

        let mut res = vec![];
        for details in req_details_list.into_iter() {
            debug!(
                "Updating Entitlements for CA: {}, Request for RC: {}",
                &self.handle, &parent_class_name
            );
            res.push(StoredEvent::new(&self.handle, *version, details));
            *version += 1;
        }
        Ok(res)
    }

    /// Returns the open revocation requests for the given parent.
    pub fn revoke_requests(&self, parent: &ParentHandle) -> HashMap<ResourceClassName, Vec<RevocationRequest>> {
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
    /// 2) For any new RCs in the entitlements new RCs will be created, each
    ///    with a pending key and an open certificate sign request.
    ///
    /// 3) For RCs that exist both for the CA and in the entitlements, new
    ///    certificates will be requested in case resource entitlements, or
    ///    validity times (not after) changed.
    ///
    /// Note that when we receive the updated certificate, we will republish
    /// and shrink/revoke child certificates and ROAs as needed.
    fn update_resource_classes(
        &self,
        parent_handle: Handle,
        entitlements: Entitlements,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        let mut res = vec![];

        // Check if there is a resource class for each entitlement
        let mut version = self.version;

        // Check if there are any current resource classes, now removed
        // from the entitlements. In which case we will have to clean them
        // up and un-publish everything there was.
        let current_resource_classes = &self.resources;

        let entitled_classes: Vec<&ResourceClassName> = entitlements.classes().iter().map(|c| c.class_name()).collect();

        for (name, rc) in current_resource_classes.iter().filter(|(_name, class)| {
            // Find the classes for this parent, not included
            // in the entitlements now received.
            class.parent_handle() == &parent_handle && !entitled_classes.contains(&class.parent_rc_name())
        }) {
            let repo = self.get_repository_contact()?;
            let delta = rc.withdraw(repo.repo_info());
            let revocations = rc.revoke(signer.deref())?;

            debug!("Updating Entitlements for CA: {}, Removing RC: {}", &self.handle, &name);

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
                    res.append(&mut self.make_request_events(&mut version, ent, rc, signer.deref())?);
                }
                None => {
                    // Create a resource class with a pending key
                    let key_id = signer.create_key()?;

                    let rcn = ResourceClassName::from(next_class_name);
                    next_class_name += 1;

                    let ns = rcn.to_string();

                    let rc =
                        ResourceClass::create(rcn.clone(), ns, parent_handle.clone(), parent_rc_name.clone(), key_id);
                    let rc_add_version = version;
                    version += 1;
                    debug!("Updating Entitlements for CA: {}, adding RC: {}", &self.handle, &rcn);

                    let mut request_events = self.make_request_events(&mut version, ent, &rc, signer.deref())?;

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
        issuance_timing: &IssuanceTimingConfig,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        debug!("CA {}: Updating received cert for class: {}", self.handle, rcn);

        let rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn))?;

        let repo = self.get_repository_contact()?;

        let evt_details = rc.update_received_cert(rcvd_cert, repo.repo_info(), issuance_timing, signer.deref())?;

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
impl CertAuth {
    fn keyroll_initiate(&self, duration: Duration, signer: Arc<KrillSigner>) -> KrillResult<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let mut version = self.version;
        let mut res = vec![];

        for (rcn, rc) in self.resources.iter() {
            let mut started = false;
            let repo = self.get_repository_contact()?;
            for details in rc.keyroll_initiate(repo.repo_info(), duration, &signer)?.into_iter() {
                started = true;
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }

            if started {
                info!("Started key roll for ca: {}, rc: {}", &self.handle, rcn);
            }
        }

        Ok(res)
    }

    fn keyroll_activate(
        &self,
        staging: Duration,
        issuance_timing: &IssuanceTimingConfig,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let mut version = self.version;
        let mut res = vec![];

        for (rcn, rc) in self.resources.iter() {
            let mut activated = false;

            let repo = self.get_repository_contact()?;

            for details in rc
                .keyroll_activate(repo.repo_info(), staging, issuance_timing, signer.deref())?
                .into_iter()
            {
                activated = true;
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }

            if activated {
                info!("Activated key for ca: {}, rc: {}", &self.handle, rcn);
            }
        }

        Ok(res)
    }

    fn keyroll_finish(&self, rcn: ResourceClassName, _response: RevocationResponse) -> KrillResult<Vec<Evt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }
        let my_rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn.clone()))?;

        let repo = self.get_repository_contact()?;

        let finish_details = my_rc.keyroll_finish(repo.repo_info())?;

        info!("Finished key roll for ca: {}, rc: {}", &self.handle, rcn);

        Ok(vec![StoredEvent::new(self.handle(), self.version, finish_details)])
    }
}

/// # Publishing
///
impl CertAuth {
    /// Republish objects for this CA
    pub fn republish(&self, issuance_timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Vec<Evt>> {
        let mut version = self.version;
        let mut res = vec![];

        for evt_det in self.republish_resource_classes(&PublishMode::Normal, issuance_timing, signer)? {
            res.push(StoredEvent::new(&self.handle, version, evt_det));
            version += 1;
        }

        Ok(res)
    }

    fn republish_resource_classes(
        &self,
        mode: &PublishMode,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<EvtDet>> {
        let mut res = vec![];

        for rc in self.resources.values() {
            if rc.current_key().is_some() {
                let repo_info = if let PublishMode::NewRepo(info) = mode {
                    info
                } else {
                    self.get_repository_contact()?.repo_info()
                };

                res.append(&mut rc.republish(repo_info, mode, issuance_timing, signer)?);
            }
        }

        Ok(res)
    }

    /// Update repository:
    /// - check that it is indeed different
    /// - regenerate all objects under the new URI (CRL URIs updated)
    /// - request new certs for all keys
    ///
    /// Note that this will then trigger (asynchronous):
    /// - updated objects synchronised with repository
    /// - CSRs submitted to parent(s)
    pub fn update_repo(
        &self,
        new_contact: RepositoryContact,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<Evt>> {
        // check that it is indeed different
        if let Some(contact) = &self.repository {
            if contact == &new_contact {
                return Err(Error::CaRepoInUse(self.handle.clone()));
            }
        }

        let info = new_contact.repo_info().clone();

        let mut evt_dts = vec![];

        // register updated repo
        evt_dts.push(EvtDet::RepoUpdated(new_contact));

        // issue new things => will trigger publication at the new location
        evt_dts.append(&mut self.republish_resource_classes(
            &PublishMode::NewRepo(info.clone()),
            issuance_timing,
            signer,
        )?);

        // request new certs => when received will trigger unpublishing at old location
        for rc in self.resources.values() {
            evt_dts.append(&mut rc.make_request_events_new_repo(&info, &signer)?);
        }

        let mut version = self.version;
        let mut res = vec![];
        for dt in evt_dts.into_iter() {
            res.push(StoredEvent::new(&self.handle, version, dt));
            version += 1;
        }
        Ok(res)
    }

    fn clean_repo(&self) -> KrillResult<Vec<Evt>> {
        match &self.repository_pending_withdraw {
            None => Ok(vec![]),
            Some(repo) => Ok(vec![StoredEvent::new(
                &self.handle,
                self.version,
                EvtDet::RepoCleaned(repo.clone()),
            )]),
        }
    }

    pub fn has_old_repo(&self) -> bool {
        self.repository_pending_withdraw.is_some()
    }
}

/// # Managing Route Authorizations
///
impl CertAuth {
    /// Updates the route authorizations for this CA, and update ROAs. Will return
    /// an error in case authorizations are added for which this CA does not hold
    /// the prefix.
    fn route_authorizations_update(
        &self,
        route_auth_updates: RouteAuthorizationUpdates,
        config: &Config,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<Evt>> {
        let route_auth_updates = route_auth_updates.into_explicit();

        let (routes, mut evts) = self.update_authorizations(&route_auth_updates)?;

        let repo = self.get_repository_contact()?;
        let mut deltas = HashMap::new();

        // for rc in self.resources
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.update_roas(&routes, config, signer.deref())?;
            if updates.contains_changes() {
                let mut delta = ObjectsDelta::new(repo.repo_info().ca_repository(rc.name_space()));

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

                evts.push(EvtDet::RoasUpdated(rcn.clone(), updates));
            }
        }

        // Create publication delta with all additions/updates/withdraws as a single delta
        for (rcn, (delta, revocations)) in deltas.into_iter() {
            let rc = self.resources.get(&rcn).unwrap();
            evts.push(rc.publish_objects(
                repo.repo_info(),
                delta,
                revocations,
                &PublishMode::Normal,
                &config.issuance_timing,
                &signer,
            )?);
        }

        let mut res = vec![];
        let mut version = self.version;
        for e in evts {
            res.push(StoredEvent::new(&self.handle, version, e));
            version += 1;
        }
        Ok(res)
    }

    /// Verifies that the updates are correct, i.e.:
    /// - additions are for prefixes held by this CA
    /// - removals are for known authorizations
    /// - additions are new
    ///   - no duplicates, or
    ///   - not covered by remaining after the removals
    ///
    /// Returns the desired Routes and the event details for
    /// persisting the changes, or an error in case of issues.
    ///
    /// Note: this does not re-issue the actual ROAs, this
    ///       can be used for the 'dry-run' option.
    pub fn update_authorizations(&self, updates: &RouteAuthorizationUpdates) -> KrillResult<(Routes, Vec<EvtDet>)> {
        let mut delta_errors = RoaDeltaError::default();
        let mut res = vec![];

        let all_resources = self.all_resources();

        let mut desired_routes = self.routes.clone();

        // make sure that all removals are held
        for auth in updates.removed() {
            if desired_routes.remove(auth) {
                res.push(EvtDet::RouteAuthorizationRemoved(*auth));
            } else {
                delta_errors.add_unknown((*auth).into())
            }
        }

        // make sure that all new additions are allowed
        for addition in updates.added() {
            let roa_def: RoaDefinition = (*addition).into();
            let authorizations: Vec<&RouteAuthorization> = desired_routes.authorizations().collect();

            if !addition.max_length_valid() {
                // The (max) length is invalid for thie prefix
                delta_errors.add_invalid_length(roa_def);
            } else if !all_resources.contains_roa_address(&addition.as_roa_ip_address()) {
                // We do not hold the prefix
                delta_errors.add_notheld(roa_def);
            } else if authorizations.iter().any(|existing| *existing == addition) {
                // A duplicate ROA already exists
                delta_errors.add_duplicate(roa_def);
            } else {
                // Ok, this seems okay now
                desired_routes.add(*addition);
                res.push(EvtDet::RouteAuthorizationAdded(*addition));
            }
        }

        if !delta_errors.is_empty() {
            Err(Error::RoaDeltaError(delta_errors))
        } else {
            Ok((desired_routes, res))
        }
    }
}

/// # Resource Tagged Attestations
///
impl CertAuth {
    pub fn rta_list(&self) -> RtaList {
        self.rtas.list()
    }

    pub fn rta_show(&self, name: &str) -> KrillResult<ResourceTaggedAttestation> {
        self.rtas.signed_rta(name)
    }

    pub fn rta_prep_response(&self, name: &str) -> KrillResult<RtaPrepResponse> {
        self.rtas
            .prepared_rta(name)
            .map(|prepped| RtaPrepResponse::new(prepped.keys()))
    }

    /// Sign a new RTA
    fn rta_sign(&self, name: RtaName, request: RtaContentRequest, signer: &KrillSigner) -> KrillResult<Vec<Evt>> {
        let (resources, validity, mut keys, content) = request.unpack();

        if self.rtas.has(&name) {
            return Err(Error::Custom(format!("RTA with name '{}' already exists", name)));
        }

        let rc2ee = self.rta_ee_map_single(&resources, validity, &mut keys, signer)?;
        let builder = ResourceTaggedAttestation::rta_builder(&resources, content, keys)?;

        self.rta_sign_with_ee(name, resources, rc2ee, builder, signer)
    }

    /// Co-sign an existing RTA, will fail if there is no existing matching prepared RTA
    fn rta_cosign(&self, name: RtaName, rta: ResourceTaggedAttestation, signer: &KrillSigner) -> KrillResult<Vec<Evt>> {
        let builder = rta.to_builder()?;

        let resources = {
            let asns = builder.content().as_resources().clone();
            let v4 = builder.content().v4_resources().clone();
            let v6 = builder.content().v6_resources().clone();
            ResourceSet::new(asns, v4, v6)
        };

        let keys = builder.content().subject_keys();
        let rc2ee = self.rta_ee_map_prepared(&name, &resources, keys, signer)?;

        self.rta_sign_with_ee(name, resources, rc2ee, builder, signer)
    }

    fn rta_sign_with_ee(
        &self,
        name: RtaName,
        resources: ResourceSet,
        rc_ee: HashMap<ResourceClassName, Cert>,
        mut rta_builder: RtaBuilder,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<Evt>> {
        let revocation_info = rc_ee
            .iter()
            .map(|(rcn, ee)| (rcn.clone(), Revocation::from(ee)))
            .collect();

        // Then sign the content with all those RCs and all keys (including submitted keys) and add the cert
        for (_rcn, ee) in rc_ee.into_iter() {
            let ee_key = ee.subject_key_identifier();
            signer.sign_rta(&mut rta_builder, ee)?;
            signer.destroy_key(&ee_key)?;
        }

        let rta = ResourceTaggedAttestation::finalize(rta_builder);

        let signed_rta = SignedRta::new(resources, revocation_info, rta);

        // Return the RTA
        Ok(vec![StoredEvent::new(
            self.handle(),
            self.version,
            EvtDet::RtaSigned(name, signed_rta),
        )])
    }

    fn rta_ee_map_prepared(
        &self,
        name: &str,
        resources: &ResourceSet,
        keys: &[KeyIdentifier],
        signer: &KrillSigner,
    ) -> KrillResult<HashMap<ResourceClassName, Cert>> {
        let prepared = self.rtas.prepared_rta(name)?;

        let validity = prepared.validity();

        if resources != prepared.resources() {
            return Err(Error::custom("Request to sign prepared RTA with changed resources"));
        }

        // Sign with all prepared keys, error out if one of those keys is removed from the request
        let mut rc_ee: HashMap<ResourceClassName, Cert> = HashMap::new();
        for (rcn, key) in prepared.key_map() {
            if !keys.contains(key) {
                return Err(Error::custom("RTA Request does not include key for prepared RTA"));
            }

            let rc = self
                .resources
                .get(rcn)
                .ok_or_else(|| Error::custom("RC for prepared RTA not found"))?;

            let rc_resources = rc
                .current_resources()
                .ok_or_else(|| Error::custom("RC for RTA has no resources"))?;

            let intersection = rc_resources.intersection(&resources);
            if intersection.is_empty() {
                return Err(Error::custom(
                    "RC for prepared RTA no longer contains relevant resources",
                ));
            }

            let ee = rc.create_rta_ee(&intersection, validity, *key, &signer)?;
            rc_ee.insert(rcn.clone(), ee);
        }

        Ok(rc_ee)
    }

    fn rta_ee_map_single(
        &self,
        resources: &ResourceSet,
        validity: Validity,
        keys: &mut Vec<KeyIdentifier>,
        signer: &KrillSigner,
    ) -> KrillResult<HashMap<ResourceClassName, Cert>> {
        // If there are no other keys supplied, then we MUST have all resources.
        // Otherwise we will just assume that others sign over the resources that
        // we do not have.
        if keys.is_empty() && !self.all_resources().contains(&resources) {
            return Err(Error::RtaResourcesNotHeld);
        }

        // Create an EE for each RC that contains part of the resources
        let mut rc_ee: HashMap<ResourceClassName, Cert> = HashMap::new();
        for (rcn, rc) in self.resources.iter() {
            if let Some(rc_resources) = rc.current_resources() {
                let intersection = resources.intersection(rc_resources);
                if !intersection.is_empty() {
                    let key = signer.create_key()?;
                    let ee = rc.create_rta_ee(&intersection, validity, key, &signer)?;
                    rc_ee.insert(rcn.clone(), ee);
                }
            }
        }

        let one_of_keys: Vec<KeyIdentifier> = rc_ee.values().map(|ee| ee.subject_key_identifier()).collect();

        // Add all one-off keys to the list of Key Identifiers
        // Note that list includes possible keys by other CAs in the RtaRequest
        for key in one_of_keys.iter() {
            keys.push(*key);
        }

        Ok(rc_ee)
    }

    pub fn rta_multi_prep(
        &self,
        name: RtaName,
        request: RtaPrepareRequest,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<Evt>> {
        let (resources, validity) = request.unpack();

        if self.all_resources().intersection(&resources).is_empty() {
            return Err(Error::custom("None of the resources for RTA are held by this CA"));
        }

        if self.rtas.has(&name) {
            return Err(Error::Custom(format!("RTA with name '{}' already exists", name)));
        }

        let mut keys = HashMap::new();

        for (rcn, rc) in self.resources.iter() {
            if let Some(rc_resources) = rc.current_resources() {
                if !rc_resources.intersection(&resources).is_empty() {
                    let key = signer.create_key()?;
                    keys.insert(rcn.clone(), key);
                }
            }
        }

        let prepared = PreparedRta::new(resources, validity, keys);

        Ok(vec![StoredEvent::new(
            self.handle(),
            self.version,
            EvtDet::RtaPrepared(name, prepared),
        )])
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;

    #[test]
    fn generate_id_cert() {
        test::test_under_tmp(|d| {
            let signer = KrillSigner::build(&d).unwrap();
            let id = Rfc8183Id::generate(&signer).unwrap();
            id.cert.validate_ta().unwrap();
        });
    }
}
