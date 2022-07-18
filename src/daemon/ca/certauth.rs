use std::{collections::HashMap, convert::TryFrom, ops::Deref, sync::Arc, vec};

use bytes::Bytes;
use chrono::Duration;

use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle},
        provisioning,
        provisioning::{
            IssuanceRequest, IssuanceResponse, ProvisioningCms, RequestResourceLimit, ResourceClassEntitlements,
            ResourceClassListResponse, ResourceClassName, RevocationRequest, RevocationResponse, SigningCert,
        },
    },
    crypto::{KeyIdentifier, PublicKey},
    repository::{
        cert::{Cert, KeyUsage, Overclaim, TbsCert},
        resources::ResourceSet,
        rta::RtaBuilder,
        x509::{Serial, Time, Validity},
    },
    uri,
};

use crate::{
    commons::{
        api::{
            AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate, BgpSecAsnKey,
            BgpSecCsrInfoList, BgpSecDefinitionUpdates, CertAuthInfo, DelegatedCertificate, IdCertInfo, ObjectName,
            ParentCaContact, ReceivedCert, RepositoryContact, Revocation, RoaDefinition, RtaList, RtaName,
            RtaPrepResponse, StorableCaCommand, TaCertDetails, TrustAnchorLocator,
        },
        crypto::{CsrInfo, KrillSigner},
        error::{Error, RoaDeltaError},
        eventsourcing::{Aggregate, StoredEvent},
        KrillResult,
    },
    constants::test_mode_enabled,
    daemon::{
        ca::{
            events::ChildCertificateUpdates, ta_handle, AspaDefinitions, BgpSecDefinitions, CaEvt, CaEvtDet,
            ChildDetails, Cmd, CmdDet, DropReason, Ini, PreparedRta, ResourceClass, ResourceTaggedAttestation,
            Rfc8183Id, RouteAuthorization, RouteAuthorizationUpdates, Routes, RtaContentRequest, RtaPrepareRequest,
            Rtas, SignedRta, StoredBgpSecCsr,
        },
        config::{Config, IssuanceTimingConfig},
    },
};

//------------ CertAuth ----------------------------------------------------

/// This type defines a Certification Authority at a slightly higher level
/// than one might expect.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertAuth {
    handle: CaHandle,
    version: u64,

    id: Rfc8183Id, // Used for RFC 6492 (up-down) and RFC 8181 (publication)

    repository: Option<RepositoryContact>,
    parents: HashMap<ParentHandle, ParentCaContact>,

    next_class_name: u32,
    resources: HashMap<ResourceClassName, ResourceClass>,

    children: HashMap<ChildHandle, ChildDetails>,
    routes: Routes,

    #[serde(skip_serializing_if = "Rtas::is_empty", default)]
    rtas: Rtas,

    #[serde(skip_serializing_if = "AspaDefinitions::is_empty", default)]
    aspas: AspaDefinitions,

    #[serde(skip_serializing_if = "BgpSecDefinitions::is_empty", default)]
    bgpsec_defs: BgpSecDefinitions,
}

impl Aggregate for CertAuth {
    type Command = Cmd;
    type StorableCommandDetails = StorableCaCommand;
    type Event = CaEvt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Ini) -> KrillResult<Self> {
        let (handle, _version, details) = event.unpack();
        let id = details.unpack();

        let repository = None;
        let parents = HashMap::new();

        let next_class_name = 0;
        let resources = HashMap::new();

        let children = HashMap::new();

        let routes = Routes::default();
        let rtas = Rtas::default();
        let aspas = AspaDefinitions::default();
        let bgpsec_defs = BgpSecDefinitions::default();

        Ok(CertAuth {
            handle,
            version: 1,

            id,

            repository,
            parents,

            next_class_name,
            resources,

            children,

            routes,
            rtas,
            aspas,
            bgpsec_defs,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: CaEvt) {
        self.version += 1;
        match event.into_details() {
            //-----------------------------------------------------------------------
            // Being a trust anchor
            //-----------------------------------------------------------------------
            CaEvtDet::TrustAnchorMade { ta_cert_details } => {
                let key_id = ta_cert_details.cert().key_identifier();
                self.parents
                    .insert(ta_handle().into_converted(), ParentCaContact::Ta(ta_cert_details));
                let rcn = ResourceClassName::from(self.next_class_name);
                self.next_class_name += 1;
                self.resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
            }

            //-----------------------------------------------------------------------
            // Being a parent
            //-----------------------------------------------------------------------
            CaEvtDet::ChildAdded {
                child,
                id_cert,
                resources,
            } => {
                let details = ChildDetails::new(id_cert, resources);
                self.children.insert(child, details);
            }
            CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => {
                self.children
                    .get_mut(&child)
                    .unwrap()
                    .add_issue_response(resource_class_name, ki);
            }

            CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => {
                self.resources.get_mut(&resource_class_name).unwrap().key_revoked(&ki);
                self.children.get_mut(&child).unwrap().add_revoke_response(ki);
            }

            CaEvtDet::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                let rc = self.resources.get_mut(&resource_class_name).unwrap();
                let (issued, removed, suspended_certs, unsuspended_certs) = updates.unpack();
                for cert in issued {
                    rc.certificate_issued(cert)
                }

                for cert in unsuspended_certs {
                    rc.certificate_unsuspended(cert)
                }

                for rem in removed {
                    rc.key_revoked(&rem);

                    // This loop is inefficient, but certificate revocations are not that common, so it's
                    // not a big deal. Tracking this better would require that we track the child handle somehow.
                    // That is a bit hard when this revocation is the result from a republish where we lost
                    // all resources delegated to the child.
                    for child in self.children.values_mut() {
                        if child.is_issued(&rem) {
                            child.add_revoke_response(rem)
                        }
                    }
                }
                for cert in suspended_certs {
                    rc.certificate_suspended(cert);
                }
            }

            CaEvtDet::ChildUpdatedIdCert { child, id_cert } => {
                self.children.get_mut(&child).unwrap().set_id_cert(id_cert)
            }

            CaEvtDet::ChildUpdatedResources { child, resources } => {
                self.children.get_mut(&child).unwrap().set_resources(resources)
            }

            CaEvtDet::ChildRemoved { child } => {
                self.children.remove(&child);
            }

            CaEvtDet::ChildSuspended { child } => self.children.get_mut(&child).unwrap().suspend(),

            CaEvtDet::ChildUnsuspended { child } => self.children.get_mut(&child).unwrap().unsuspend(),

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            CaEvtDet::IdUpdated { id } => {
                self.id = id;
            }
            CaEvtDet::ParentAdded { parent, contact } => {
                self.parents.insert(parent, contact);
            }
            CaEvtDet::ParentUpdated { parent, contact } => {
                self.parents.insert(parent, contact);
            }
            CaEvtDet::ParentRemoved { parent } => {
                self.parents.remove(&parent);
                self.resources.retain(|_, rc| rc.parent_handle() != &parent);
            }

            CaEvtDet::ResourceClassAdded {
                resource_class_name,
                parent,
                parent_resource_class_name,
                pending_key,
            } => {
                self.next_class_name += 1;
                let ns = resource_class_name.to_string();
                let rc = ResourceClass::create(
                    resource_class_name.clone(),
                    ns,
                    parent,
                    parent_resource_class_name,
                    pending_key,
                );
                self.resources.insert(resource_class_name, rc);
            }
            CaEvtDet::ResourceClassRemoved {
                resource_class_name, ..
            } => {
                self.resources.remove(&resource_class_name);
            }
            CaEvtDet::CertificateRequested {
                resource_class_name,
                req,
                ki,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .add_request(ki, req);
            }
            CaEvtDet::CertificateReceived {
                resource_class_name,
                ki,
                rcvd_cert,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .received_cert(ki, rcvd_cert);
            }

            //-----------------------------------------------------------------------
            // Key Life Cycle
            //-----------------------------------------------------------------------
            CaEvtDet::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id: pending_key,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .pending_key_id_added(pending_key);
            }
            CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .pending_key_to_new(new_key);
            }
            CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .pending_key_to_active(current_key);
            }
            CaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => {
                self.resources
                    .get_mut(&resource_class_name)
                    .unwrap()
                    .new_key_activated(revoke_req);
            }
            CaEvtDet::KeyRollFinished { resource_class_name } => {
                self.resources.get_mut(&resource_class_name).unwrap().old_key_removed();
            }
            CaEvtDet::UnexpectedKeyFound { .. } => {
                // no action needed, this is marked to flag that a key may be removed on the
                // server side. The revocation requests are picked up by the `MessageQueue`
                // listener.
            }

            //-----------------------------------------------------------------------
            // Route Authorizations
            //-----------------------------------------------------------------------
            CaEvtDet::RouteAuthorizationAdded { auth } => self.routes.add(auth),
            CaEvtDet::RouteAuthorizationRemoved { auth } => {
                self.routes.remove(&auth);
            }
            CaEvtDet::RoasUpdated {
                resource_class_name,
                updates,
            } => self
                .resources
                .get_mut(&resource_class_name)
                .unwrap()
                .roas_updated(updates),

            //-----------------------------------------------------------------------
            // Autonomous System Provider Authorization
            //-----------------------------------------------------------------------
            CaEvtDet::AspaConfigAdded { aspa_config } => self.aspas.add_or_replace(aspa_config),
            CaEvtDet::AspaConfigUpdated { customer, update } => self.aspas.apply_update(customer, &update),
            CaEvtDet::AspaConfigRemoved { customer } => self.aspas.remove(customer),
            CaEvtDet::AspaObjectsUpdated {
                resource_class_name,
                updates,
            } => self
                .resources
                .get_mut(&resource_class_name)
                .unwrap()
                .aspa_objects_updated(updates),

            //-----------------------------------------------------------------------
            // BGPSec
            //-----------------------------------------------------------------------
            CaEvtDet::BgpSecDefinitionAdded { key, csr } => self.bgpsec_defs.add_or_replace(key, csr),
            CaEvtDet::BgpSecDefinitionUpdated { key, csr } => self.bgpsec_defs.add_or_replace(key, csr),
            CaEvtDet::BgpSecDefinitionRemoved { key } => {
                self.bgpsec_defs.remove(&key);
            }
            CaEvtDet::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                let rc = self.resources.get_mut(&resource_class_name).unwrap();
                rc.bgpsec_certificates_updated(updates);
            }

            //-----------------------------------------------------------------------
            // Publication
            //-----------------------------------------------------------------------
            CaEvtDet::RepoUpdated { contact } => {
                if let Some(current) = &self.repository {
                    for rc in self.resources.values_mut() {
                        rc.set_old_repo(current.repo_info().clone());
                    }
                }
                self.repository = Some(contact);
            }

            //-----------------------------------------------------------------------
            // Resource Tagged Attestations
            //-----------------------------------------------------------------------
            CaEvtDet::RtaPrepared { name, prepared } => {
                self.rtas.add_prepared(name, prepared);
            }
            CaEvtDet::RtaSigned { name, rta } => {
                self.rtas.add_signed(name, rta);
            }
        }
    }

    fn process_command(&self, command: Cmd) -> KrillResult<Vec<CaEvt>> {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Sending command to CA '{}', version: {}: {}",
                self.handle,
                self.version,
                command
            );
        }

        match command.into_details() {
            // trust anchor
            CmdDet::MakeTrustAnchor(uris, rsync_uri, signer) => self.trust_anchor_make(uris, rsync_uri, signer),

            // being a parent
            CmdDet::ChildAdd(child, id_cert, resources) => self.child_add(child, id_cert, resources),
            CmdDet::ChildUpdateResources(child, res) => self.child_update_resources(&child, res),
            CmdDet::ChildUpdateId(child, id_cert) => self.child_update_id_cert(&child, id_cert),
            CmdDet::ChildCertify(child, request, config, signer) => self.child_certify(child, request, &config, signer),
            CmdDet::ChildRevokeKey(child, request) => self.child_revoke_key(child, request),
            CmdDet::ChildRemove(child) => self.child_remove(&child),
            CmdDet::ChildSuspendInactive(child) => self.child_suspend_inactive(&child),
            CmdDet::ChildUnsuspend(child) => self.child_unsuspend(&child),

            // being a child
            CmdDet::GenerateNewIdKey(signer) => self.generate_new_id_key(signer),
            CmdDet::AddParent(parent, info) => self.add_parent(parent, info),
            CmdDet::UpdateParentContact(parent, info) => self.update_parent(parent, info),
            CmdDet::RemoveParent(parent) => self.remove_parent(parent),

            CmdDet::UpdateEntitlements(parent, entitlements, signer) => {
                self.update_entitlements(parent, entitlements, signer)
            }
            CmdDet::UpdateRcvdCert(class_name, rcvd_cert, config, signer) => {
                self.update_received_cert(class_name, rcvd_cert, &config, signer)
            }
            CmdDet::DropResourceClass(rcn, reason, signer) => self.drop_resource_class(rcn, reason, signer),

            // Key rolls
            CmdDet::KeyRollInitiate(duration, signer) => self.keyroll_initiate(duration, signer),
            CmdDet::KeyRollActivate(duration, config, signer) => self.keyroll_activate(duration, config, signer),
            CmdDet::KeyRollFinish(rcn, response) => self.keyroll_finish(rcn, response),

            // Route Authorizations
            CmdDet::RouteAuthorizationsUpdate(updates, config, signer) => {
                self.route_authorizations_update(updates, &config, signer)
            }
            CmdDet::RouteAuthorizationsRenew(config, signer) => {
                self.route_authorizations_renew(false, &config, &signer)
            }
            CmdDet::RouteAuthorizationsForceRenew(config, signer) => {
                self.route_authorizations_renew(true, &config, &signer)
            }

            // ASPA
            CmdDet::AspasUpdate(updates, config, signer) => self.aspas_definitions_update(updates, &config, &signer),
            CmdDet::AspasUpdateExisting(customer, update, config, signer) => {
                self.aspas_update(customer, update, &config, &signer)
            }
            CmdDet::AspasRenew(config, signer) => self.aspas_renew(&config, &signer),

            // BGPSec
            CmdDet::BgpSecUpdateDefinitions(updates, config, signer) => {
                self.bgpsec_definitions_update(updates, &config, &signer)
            }
            CmdDet::BgpSecRenew(config, signer) => self.bgpsec_renew(&config, &signer),

            // Republish
            CmdDet::RepoUpdate(contact, signer) => self.update_repo(contact, &signer),

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
    // For many commands with multiple resulting events, it's easier to build a list of event *details*
    // and worry about numbering the versions here.
    fn events_from_details(&self, event_details: Vec<CaEvtDet>) -> Vec<CaEvt> {
        let mut res = vec![];
        let mut version = self.version;
        for event in event_details {
            res.push(StoredEvent::new(&self.handle, version, event));
            version += 1;
        }
        res
    }
}

/// # Data presentation
///
impl CertAuth {
    /// Returns a `CertAuthInfo` for this, which includes a data representation
    /// of the internal structure, in particular with regards to parent, children,
    /// resource classes and keys.
    pub fn as_ca_info(&self) -> CertAuthInfo {
        let handle = self.handle.clone();
        let repo_info = self.repository.as_ref().map(|repo| repo.repo_info().clone());

        let parents = self.parents.clone();

        let mut resources = HashMap::new();

        for (name, rc) in &self.resources {
            resources.insert(name.clone(), rc.as_info());
        }
        let children: Vec<ChildHandle> = self.children.keys().cloned().collect();

        let id_cert = self.id.cert().clone();

        let suspended_children = self
            .children
            .iter()
            .filter(|(_ca, details)| details.is_suspended())
            .map(|(ca, _)| ca.clone())
            .collect();

        CertAuthInfo::new(
            handle,
            id_cert,
            repo_info,
            parents,
            resources,
            children,
            suspended_children,
        )
    }

    /// Returns the current RoaDefinitions for this, i.e. the intended authorized
    /// prefixes. Provided that the resources are held by this `CertAuth` one can
    /// expect that corresponding ROA **objects** are created by the system.
    pub fn roa_definitions(&self) -> Vec<RoaDefinition> {
        self.routes.authorizations().map(|a| a.as_ref()).cloned().collect()
    }

    /// Returns an RFC 8183 Child Request - which can be represented as XML to a
    /// parent of this `CertAuth`
    pub fn child_request(&self) -> idexchange::ChildRequest {
        idexchange::ChildRequest::new(self.id_cert().base64().clone(), self.handle.convert())
    }

    /// Returns an RFC 8183 Publisher Request - which can be represented as XML to a
    /// repository for this `CertAuth`
    pub fn publisher_request(&self) -> idexchange::PublisherRequest {
        idexchange::PublisherRequest::new(self.id_cert().base64().clone(), self.handle.convert(), None)
    }

    pub fn id_cert(&self) -> &IdCertInfo {
        self.id.cert()
    }

    pub fn handle(&self) -> &CaHandle {
        &self.handle
    }

    /// Returns the complete set of all currently received resources, under all parents, for
    /// this `CertAuth`
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
    pub fn repository_contact(&self) -> KrillResult<&RepositoryContact> {
        self.repository.as_ref().ok_or(Error::RepoNotSet)
    }
}

/// # Being a Trust Anchor
///
impl CertAuth {
    fn trust_anchor_make(
        &self,
        uris: Vec<uri::Https>,
        rsync_uri: uri::Rsync,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        if !self.resources.is_empty() {
            return Err(Error::custom("Cannot turn CA with resources into TA"));
        }

        let repo_info = self.repository_contact()?.repo_info();

        let key = signer.create_key()?;

        let resources = ResourceSet::all();

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
            cert.set_rpki_manifest(Some(
                repo_info.resolve(&ns, ObjectName::mft_for_key(&pub_key.key_identifier()).as_ref()),
            ));
            cert.set_rpki_notify(repo_info.rpki_notify().cloned());

            cert.set_as_resources(resources.to_as_resources());
            cert.set_v4_resources(resources.to_ip_resources_v4());
            cert.set_v6_resources(resources.to_ip_resources_v6());

            signer.sign_cert(cert, &key)?
        };

        let tal = TrustAnchorLocator::new(uris, rsync_uri.clone(), cert.subject_public_key_info());

        let rcvd_cert =
            ReceivedCert::create(cert, rsync_uri, resources, RequestResourceLimit::default()).map_err(Error::custom)?;

        let ta_cert_details = TaCertDetails::new(rcvd_cert, tal);

        info!("Created Trust Anchor");

        Ok(vec![StoredEvent::new(
            &self.handle,
            self.version,
            CaEvtDet::TrustAnchorMade { ta_cert_details },
        )])
    }
}

/// # Being a parent
///
impl CertAuth {
    pub fn verify_rfc6492(&self, cms: ProvisioningCms) -> KrillResult<provisioning::Message> {
        let child_handle = cms.message().sender().convert();
        let child = self.get_child(&child_handle)?;

        cms.validate(child.id_cert().public_key())
            .map_err(|_| Error::Rfc6492SignatureInvalid)?;

        Ok(cms.into_message())
    }

    pub fn sign_rfc6492_response(&self, message: provisioning::Message, signer: &KrillSigner) -> KrillResult<Bytes> {
        signer
            .create_rfc6492_cms(message, &self.id.cert().public_key().key_identifier())
            .map(|res| res.to_bytes())
            .map_err(Error::signer)
    }

    /// List entitlements (section 3.3.2 of RFC6492). Return an error if
    /// the child is not authorized -- or unknown etc.
    pub fn list(
        &self,
        child_handle: &ChildHandle,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<ResourceClassListResponse> {
        let mut classes = vec![];

        for rcn in self.resources.keys() {
            if let Some(class) = self.entitlement_class(child_handle, rcn, issuance_timing)? {
                classes.push(class);
            }
        }

        Ok(ResourceClassListResponse::new(classes))
    }

    /// Returns an issuance response for a child and a specific resource
    /// class name and public key for the issued certificate.
    pub fn issuance_response(
        &self,
        child_handle: &ChildHandle,
        class_name: &ResourceClassName,
        pub_key: &PublicKey,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<IssuanceResponse> {
        let entitlement_class = self
            .entitlement_class(child_handle, class_name, issuance_timing)?
            .ok_or(Error::KeyUseNoIssuedCert)?;

        entitlement_class
            .into_issuance_response(pub_key)
            .ok_or(Error::KeyUseNoIssuedCert)
    }

    /// Returns the ResourceClassEntitlements for this child for the given class name.
    fn entitlement_class(
        &self,
        child_handle: &ChildHandle,
        rcn: &ResourceClassName,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<Option<ResourceClassEntitlements>> {
        let my_rc = match self.resources.get(rcn) {
            Some(rc) => rc,
            None => return Ok(None),
        };

        let my_current_key = match my_rc.current_key() {
            Some(key) => key,
            None => return Ok(None),
        };

        let my_rcvd_cert = my_current_key.incoming_cert();
        let my_cert = my_rcvd_cert.to_cert().map_err(|e| {
            Error::Custom(format!(
                "Issue with certificate held by CA '{}', error: {} ",
                self.handle(),
                e
            ))
        })?;

        let signing_cert = SigningCert::new(my_rcvd_cert.uri().clone(), my_cert);

        let child = match self.get_child(child_handle) {
            Ok(child) => child,
            Err(_) => return Ok(None),
        };

        let child_resources = my_rcvd_cert.resources().intersection(child.resources());
        if child_resources.is_empty() {
            return Ok(None);
        }

        let child_keys = child.issued(rcn);

        let mut issued_certs = vec![];

        // Check current issued certificates, so we may lie a tiny bit here.. i.e. we want to avoid that
        // child CAs feel the urge to request new certificates all the time - so we will only tell them
        // about the normal - longer - not after time if their current certificate(s) will expire within
        // the configured number of weeks. I.e. using defaults:
        //  - they would be eligible to a not-after of 52 weeks
        //  - we only tell them 4 weeks before their old cert would expire
        //
        // Note that a child may have multiple keys and issued certificates if they are doing a keyroll.
        // Typically these certificates will have almost the same expiration time, but even if they don't
        // and one of them is about to expire, while the other is still valid for a while.. then telling
        // the child that they are eligible to the not after time of the other is still fine - it would
        // still trigger them to request a replacement for the first which was about to expire.
        let mut not_after = Time::now() + Duration::weeks(issuance_timing.timing_child_certificate_valid_weeks);
        let threshold = Time::now() + Duration::weeks(issuance_timing.timing_child_certificate_reissue_weeks_before);

        for ki in child_keys {
            if let Some(delegated) = my_rc.delegated(&ki) {
                issued_certs.push(delegated.to_issued_cert().map_err(|e| {
                    // This should never happen, unless our current delegated certificate can no longer be parsed
                    Error::Custom(format!(
                        "Issue with delegated certificate held by CA '{}', published at '{}', error: {} ",
                        self.handle(),
                        delegated.uri(),
                        e
                    ))
                })?);

                let expires = delegated.validity().not_after();

                if expires > threshold {
                    not_after = expires;
                }
            }
        }

        Ok(Some(ResourceClassEntitlements::new(
            rcn.clone(),
            child_resources,
            not_after,
            issued_certs,
            signing_cert,
        )))
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(&self, child: &ChildHandle) -> KrillResult<&ChildDetails> {
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
    fn child_add(&self, child: ChildHandle, id_cert: IdCertInfo, resources: ResourceSet) -> KrillResult<Vec<CaEvt>> {
        if resources.is_empty() {
            Err(Error::CaChildMustHaveResources(self.handle.clone(), child))
        } else if !self.all_resources().contains(&resources) {
            Err(Error::CaChildExtraResources(self.handle.clone(), child))
        } else if self.has_child(&child) {
            Err(Error::CaChildDuplicate(self.handle.clone(), child))
        } else {
            info!(
                "CA '{}' added child '{}' with resources '{}'",
                self.handle, child, resources
            );

            Ok(vec![CaEvtDet::child_added(
                &self.handle,
                self.version,
                child,
                id_cert,
                resources,
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
        child: ChildHandle,
        request: IssuanceRequest,
        config: &Config,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        let (rcn, limit, csr) = request.unpack();
        let csr_info = CsrInfo::try_from(&csr)?;

        if !csr_info.global_uris() && !test_mode_enabled() {
            return Err(Error::invalid_csr(
                "MUST use hostnames in URIs for certificate requests.",
            ));
        }

        let issued =
            self.issue_child_certificate(&child, rcn.clone(), csr_info, limit, &config.issuance_timing, &signer)?;

        let cert_name = ObjectName::new(&issued.key_identifier(), ".cer");

        info!(
            "CA '{}' issued certificate '{}' to child '{}'",
            self.handle, cert_name, child
        );

        let issued_event =
            CaEvtDet::child_certificate_issued(&self.handle, self.version, child, rcn.clone(), issued.key_identifier());

        let mut cert_updates = ChildCertificateUpdates::default();
        cert_updates.issue(issued);
        let child_certs_updated =
            CaEvtDet::child_certificates_updated(&self.handle, self.version + 1, rcn, cert_updates);

        Ok(vec![issued_event, child_certs_updated])
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
    ) -> KrillResult<DelegatedCertificate> {
        let my_rc = self.resources.get(&rcn).ok_or(Error::ResourceClassUnknown(rcn))?;
        let child = self.get_child(child)?;

        // note this will ultimately return an error if the requested limit exceeds
        // the child's resources.
        my_rc.issue_cert(csr_info, child.resources(), limit, issuance_timing, signer)
    }

    /// Updates child Resource entitlements.
    ///
    /// This does not yet revoke / reissue / republish anything.
    /// Also, this is a no-op if the child already has these resources.
    fn child_update_resources(&self, child_handle: &ChildHandle, resources: ResourceSet) -> KrillResult<Vec<CaEvt>> {
        if !self.all_resources().contains(&resources) {
            Err(Error::CaChildExtraResources(self.handle.clone(), child_handle.clone()))
        } else {
            let child = self.get_child(child_handle)?;

            let resources_diff = resources.difference(child.resources());

            if !resources_diff.is_empty() {
                info!(
                    "CA '{}' update child '{}' resources: {}",
                    self.handle, child_handle, resources_diff
                );

                Ok(vec![CaEvtDet::child_updated_resources(
                    &self.handle,
                    self.version,
                    child_handle.clone(),
                    resources,
                )])
            } else {
                // Using 'debug' here, because there are possible use cases where updating the child resources to some expected
                // resource set should be considered a no-op without complaints. E.g. if there is a background job calling
                // the API and setting entitlements.
                debug!(
                    "CA '{}' update child '{}' resources has no effect, child already holds all resources",
                    self.handle, child_handle
                );
                Ok(vec![])
            }
        }
    }

    /// Updates child IdCert
    fn child_update_id_cert(&self, child_handle: &ChildHandle, id_cert: IdCertInfo) -> KrillResult<Vec<CaEvt>> {
        let child = self.get_child(child_handle)?;

        if &id_cert != child.id_cert() {
            info!(
                "CA '{}' updated child '{}' cert. New key id: {}",
                self.handle,
                child_handle,
                id_cert.public_key().key_identifier()
            );

            Ok(vec![CaEvtDet::child_updated_cert(
                &self.handle,
                self.version,
                child_handle.clone(),
                id_cert,
            )])
        } else {
            // Using 'debug' here, because of possible no-op use cases where the API is called from a background job.
            debug!(
                "CA '{}' updated child '{}' cert had no effect. Child ID certificate is identical",
                self.handle, child_handle
            );
            Ok(vec![])
        }
    }

    /// Revokes a key for a child. So, add the last cert for the key to the CRL, and withdraw
    /// the .cer file for it.
    fn child_revoke_key(&self, child_handle: ChildHandle, request: RevocationRequest) -> KrillResult<Vec<CaEvt>> {
        let (rcn, key) = request.unpack();

        let child = self.get_child(&child_handle)?;

        if !child.is_issued(&key) {
            return Err(Error::KeyUseNoIssuedCert);
        }

        let handle = &self.handle;
        let version = self.version;

        let mut child_certificate_updates = ChildCertificateUpdates::default();
        child_certificate_updates.remove(key);

        let cert_name = ObjectName::new(&key, "cer");
        info!(
            "CA '{}' revoked certificate '{}' for child '{}'",
            handle, cert_name, child_handle
        );

        let rev = CaEvtDet::child_revoke_key(handle, version, child_handle, rcn.clone(), key);
        let upd = CaEvtDet::child_certificates_updated(handle, version + 1, rcn, child_certificate_updates);

        Ok(vec![rev, upd])
    }

    fn child_remove(&self, child_handle: &ChildHandle) -> KrillResult<Vec<CaEvt>> {
        let child = self.get_child(child_handle)?;

        let mut version = self.version;
        let handle = &self.handle;

        let mut res = vec![];

        // Find all the certs in all RCs for this child and revoke, and withdraw them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut issued_certs = vec![];
            for key in certified_keys {
                if let Some(issued) = rc.delegated(&key) {
                    issued_certs.push(issued);
                }
            }

            let mut cert_updates = ChildCertificateUpdates::default();
            for issued in issued_certs {
                info!(
                    "CA '{}' revoked certificate '{}' for child '{}'",
                    handle,
                    issued.name(),
                    child_handle
                );
                cert_updates.remove(issued.key_identifier())
            }
            res.push(CaEvtDet::child_certificates_updated(
                handle,
                version,
                rcn.clone(),
                cert_updates,
            ));
            version += 1;
        }

        info!("CA '{}' removed child '{}'", handle, child_handle);
        res.push(CaEvtDet::child_removed(handle, version, child_handle.clone()));

        Ok(res)
    }

    // Suspend a child. The intention is that this is called when it is discovered
    // that the child has been inactive, i.e. not contacting this parent for a pro-longed
    // period of time (hours).
    //
    // When a child is suspended we need to:
    // - mark it as suspended
    // - withdraw all certificates issued to it (suspend them)
    fn child_suspend_inactive(&self, child_handle: &ChildHandle) -> KrillResult<Vec<CaEvt>> {
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if child.is_suspended() {
            return Ok(res); // nothing to do, child is already suspended
        }

        let mut version = self.version;
        let handle = &self.handle;

        // Find all the certs in all RCs for this child and suspend them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut cert_updates = ChildCertificateUpdates::default();

            for key in certified_keys {
                if let Some(delegated) = rc.delegated(&key) {
                    cert_updates.suspend(delegated.convert());
                }
            }

            res.push(CaEvtDet::child_certificates_updated(
                handle,
                version,
                rcn.clone(),
                cert_updates,
            ));
            version += 1;
        }

        // Only mark the child as suspended if there was at least one certificate
        // to suspend above. If not this is a no-op - the child has not yet requested
        // any certificates so there is nothing to suspend.
        if !res.is_empty() {
            info!("CA '{}' suspended inactive child '{}'", handle, child_handle);
            res.push(CaEvtDet::child_suspended(handle, version, child_handle.clone()));
        }

        Ok(res)
    }

    // Unsuspend a child. The intention is that this is called automatically when
    // a suspended (inactive) child CA is seen to contact this parent again.
    //
    // When a child is unsuspended we need to:
    // - mark it as unsuspended
    // - republish existing suspended certificates for it, provided that
    //    - they will not expire for another day
    //    - they do not exceed the current resource entitlements of the CA
    // - other suspended certificates will just be removed.
    //
    // Then the child may or may not request new certificates as it sees fit.
    // I.e. the unsuspend should be done before the child gets an answer to its
    // RFC 6492 list request.
    fn child_unsuspend(&self, child_handle: &ChildHandle) -> KrillResult<Vec<CaEvt>> {
        let mut res = vec![];

        let child = self.get_child(child_handle)?;

        if !child.is_suspended() {
            return Ok(res); // nothing to do, child is not suspended
        }

        let mut version = self.version;
        let handle = &self.handle;

        // Find all the certs in all RCs for this child and suspend them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut cert_updates = ChildCertificateUpdates::default();

            for key in certified_keys {
                if let Some(suspended) = rc.suspended(&key) {
                    // check that the cert is actually not expired or about to expire and not overclaiming
                    if suspended.validity().not_after() > Time::now() + Duration::days(1)
                        && child.resources().contains(suspended.resources())
                    {
                        // certificate is still fit for publication, so move it back to issued
                        cert_updates.unsuspend(suspended.convert());
                    } else {
                        // certificate should not be published as is. Remove it and the child will request
                        // a new certificate because the resources and or validity entitlements will have
                        // changed.
                        cert_updates.remove(suspended.key_identifier());
                    }
                }
            }

            res.push(CaEvtDet::child_certificates_updated(
                handle,
                version,
                rcn.clone(),
                cert_updates,
            ));
            version += 1;
        }

        info!("CA '{}' unsuspended child '{}'", handle, child_handle);
        res.push(CaEvtDet::child_unsuspended(handle, version, child_handle.clone()));

        Ok(res)
    }

    /// Returns `true` if the child is known, `false` otherwise. No errors.
    fn has_child(&self, child_handle: &ChildHandle) -> bool {
        self.children.contains_key(child_handle)
    }
}

/// # Being a child
///
impl CertAuth {
    /// Generates a new ID key for this CA.
    fn generate_new_id_key(&self, signer: Arc<KrillSigner>) -> KrillResult<Vec<CaEvt>> {
        let id = Rfc8183Id::generate(&signer)?;

        info!(
            "CA '{}' generated new ID certificate with key id: {}",
            self.handle,
            id.cert().public_key().key_identifier()
        );
        Ok(vec![CaEvtDet::id_updated(&self.handle, self.version, id)])
    }

    /// List all parents
    pub fn parents(&self) -> impl Iterator<Item = &ParentHandle> {
        self.parents.keys()
    }

    pub fn nr_parents(&self) -> usize {
        self.parents.len()
    }

    pub fn parent_known(&self, parent: &ParentHandle) -> bool {
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
    /// by this name (handle) is already known. Or in case the same response
    /// is used for more than one parent.
    fn add_parent(&self, parent: ParentHandle, info: ParentCaContact) -> KrillResult<Vec<CaEvt>> {
        if self.parent_known(&parent) {
            Err(Error::CaParentDuplicateName(self.handle.clone(), parent))
        } else if let Some(other) = self.parent_for_info(&info) {
            Err(Error::CaParentDuplicateInfo(self.handle.clone(), other.clone()))
        } else if self.is_ta() {
            Err(Error::TaNotAllowed)
        } else {
            info!("CA '{}' added parent '{}'", self.handle, parent);
            Ok(vec![CaEvtDet::parent_added(&self.handle, self.version, parent, info)])
        }
    }

    /// Removes a parent. Returns an error if it doesn't exist.
    fn remove_parent(&self, parent: ParentHandle) -> KrillResult<Vec<CaEvt>> {
        if !self.parent_known(&parent) {
            Err(Error::CaParentUnknown(self.handle.clone(), parent))
        } else {
            let mut event_details = vec![];

            info!("CA '{}' removed parent '{}'", self.handle, parent);

            for (rcn, rc) in &self.resources {
                if rc.parent_handle() == &parent {
                    event_details.push(CaEvtDet::ResourceClassRemoved {
                        resource_class_name: rcn.clone(),
                        parent: parent.clone(),
                        revoke_requests: vec![], // We will do a best effort revoke request, but not triggered through this event
                    });
                }
            }

            event_details.push(CaEvtDet::ParentRemoved { parent });

            Ok(self.events_from_details(event_details))
        }
    }

    /// Updates an existing parent's contact. This will return an error if
    /// the parent is not known.
    fn update_parent(&self, parent: ParentHandle, info: ParentCaContact) -> KrillResult<Vec<CaEvt>> {
        if !self.parent_known(&parent) {
            Err(Error::CaParentUnknown(self.handle.clone(), parent))
        } else if self.is_ta() {
            Err(Error::TaNotAllowed)
        } else {
            info!("CA '{}' updated contact info for parent '{}'", self.handle, parent);
            Ok(vec![CaEvtDet::parent_updated(&self.handle, self.version, parent, info)])
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
        entitlement: &ResourceClassEntitlements,
        rc: &ResourceClass,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let repo = self.repository_contact()?;
        rc.make_entitlement_events(self.handle(), entitlement, repo.repo_info(), signer)
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

    /// Returns whether the CA has any pending requests for a parent
    pub fn has_pending_requests(&self, parent: &ParentHandle) -> bool {
        for rc in self.resources.values() {
            if rc.parent_handle() == parent && rc.has_pending_requests() {
                return true;
            }
        }
        false
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
    fn update_entitlements(
        &self,
        parent_handle: ParentHandle,
        entitlements: ResourceClassListResponse,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        let mut event_details: Vec<CaEvtDet> = vec![];

        // Check if there is a resource class for each entitlement

        // Check if there are any current resource classes, now removed
        // from the entitlements. In which case we will have to clean them
        // up and un-publish everything there was.
        let current_resource_classes = &self.resources;

        let entitled_classes: Vec<&ResourceClassName> = entitlements.classes().iter().map(|c| c.class_name()).collect();

        for (rcn, rc) in current_resource_classes.iter().filter(|(_name, class)| {
            // Find the classes for this parent, not included
            // in the entitlements now received.
            class.parent_handle() == &parent_handle && !entitled_classes.contains(&class.parent_rc_name())
        }) {
            let revoke_requests = rc.revoke(signer.deref())?;

            info!("Updating Entitlements for CA: {}, Removing RC: {}", &self.handle, &rcn);

            event_details.push(CaEvtDet::ResourceClassRemoved {
                resource_class_name: rcn.clone(),
                parent: parent_handle.clone(),
                revoke_requests,
            });
        }

        // Now check all the entitlements and either create an RC for them, or update.
        let mut next_class_name = self.next_class_name;

        for ent in entitlements.classes() {
            let parent_rc_name = ent.class_name();

            match self.find_parent_rc(&parent_handle, parent_rc_name) {
                Some(rc) => {
                    // We have a matching RC, make requests (note this may be a no-op).
                    event_details.append(&mut self.make_request_events(ent, rc, signer.deref())?);
                }
                None => {
                    // Create a resource class with a pending key
                    let pending_key = signer.create_key()?;

                    let resource_class_name = ResourceClassName::from(next_class_name);
                    next_class_name += 1;

                    info!("CA '{}' received entitlement under parent '{}', created resource class '{}' and made certificate request", self.handle, parent_handle, resource_class_name);

                    let ns = resource_class_name.to_string();

                    let rc = ResourceClass::create(
                        resource_class_name.clone(),
                        ns,
                        parent_handle.clone(),
                        parent_rc_name.clone(),
                        pending_key,
                    );

                    let added = CaEvtDet::ResourceClassAdded {
                        resource_class_name,
                        parent: parent_handle.clone(),
                        parent_resource_class_name: parent_rc_name.clone(),
                        pending_key,
                    };
                    let mut request_events = self.make_request_events(ent, &rc, signer.deref())?;

                    event_details.push(added);
                    event_details.append(&mut request_events);
                }
            }
        }

        Ok(self.events_from_details(event_details))
    }

    /// This method updates the received certificate for the given parent
    /// and resource class, and will return an error if either is unknown.
    ///
    /// It will generate an event for the certificate that is received, and
    /// if it was received for a pending key it will return an event to promote
    /// the pending key appropriately, finally it will also return a
    /// publication event for the matching key if publication is needed.
    ///
    /// This will also generate appropriate events for changes affecting
    /// issued ROAs and delegated certificates - if because resources were
    /// lost and ROAs/Certs would be become invalid.
    fn update_received_cert(
        &self,
        rcn: ResourceClassName,
        rcvd_cert: ReceivedCert,
        config: &Config,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        debug!("CA {}: Updating received cert for class: {}", self.handle, rcn);

        let rc = self.resources.get(&rcn).ok_or(Error::ResourceClassUnknown(rcn))?;

        let evt_details = rc.update_received_cert(
            self.handle(),
            rcvd_cert,
            &self.routes,
            &self.aspas,
            &self.bgpsec_defs,
            config,
            signer.deref(),
        )?;

        let mut res = vec![];
        let mut version = self.version;

        for details in evt_details.into_iter() {
            res.push(StoredEvent::new(&self.handle, version, details));
            version += 1;
        }

        Ok(res)
    }

    /// Drop a resource class because it no longer works under this parent for the specified
    /// reason. Note that this will generate revocation requests for the current keys which
    /// will be sent to the parent on a best effort basis - e.g. if the parent removed the resource
    /// class it may well refuse to revoke the keys - it may not known them.
    fn drop_resource_class(
        &self,
        rcn: ResourceClassName,
        reason: DropReason,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        warn!("Dropping resource class '{}' because of reason: {}", rcn, reason);

        let rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn.clone()))?;
        let revoke_requests = rc.revoke(signer.deref())?;

        Ok(self.events_from_details(vec![CaEvtDet::ResourceClassRemoved {
            resource_class_name: rcn,
            parent: rc.parent_handle().clone(),
            revoke_requests,
        }]))
    }
}

/// # Key Rolls
///
impl CertAuth {
    fn keyroll_initiate(&self, duration: Duration, signer: Arc<KrillSigner>) -> KrillResult<Vec<CaEvt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let mut version = self.version;
        let mut res = vec![];

        for (rcn, rc) in self.resources.iter() {
            let mut started = false;
            let repo = self.repository_contact()?;
            for details in rc.keyroll_initiate(repo.repo_info(), duration, &signer)?.into_iter() {
                started = true;
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }

            if started {
                info!(
                    "Started key roll for ca: {}, rc: {}, under parent: {}",
                    &self.handle,
                    rcn,
                    rc.parent_handle()
                );
            }
        }

        Ok(res)
    }

    fn keyroll_activate(
        &self,
        staging_time: Duration,
        config: Arc<Config>,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<Vec<CaEvt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }

        let mut version = self.version;
        let mut res = vec![];

        for (rcn, rc) in self.resources.iter() {
            let mut activated = false;

            for details in rc
                .keyroll_activate(staging_time, &config.issuance_timing, signer.deref())?
                .into_iter()
            {
                activated = true;
                res.push(StoredEvent::new(self.handle(), version, details));
                version += 1;
            }

            if activated {
                info!(
                    "Activated key for ca: {}, rc: {}, under parent: {}",
                    &self.handle,
                    rcn,
                    rc.parent_handle()
                );
            }
        }

        Ok(res)
    }

    fn keyroll_finish(&self, rcn: ResourceClassName, _response: RevocationResponse) -> KrillResult<Vec<CaEvt>> {
        if self.is_ta() {
            return Ok(vec![]);
        }
        let my_rc = self
            .resources
            .get(&rcn)
            .ok_or_else(|| Error::ResourceClassUnknown(rcn.clone()))?;

        let finish_details = my_rc.keyroll_finish()?;

        info!(
            "Finished key roll for ca: {}, rc: {}, under parent: {}",
            &self.handle,
            rcn,
            my_rc.parent_handle()
        );

        Ok(vec![StoredEvent::new(self.handle(), self.version, finish_details)])
    }
}

/// # Publishing
///
impl CertAuth {
    /// Update repository:
    ///    - Will return an error in case the repo is already set (issue 481)
    ///    - Will support migrations using key rollover in future (issue 480)
    ///    - Assumes that the repository can be reached (this is checked by CaManager before issuing the command to this CA)
    pub fn update_repo(&self, contact: RepositoryContact, signer: &KrillSigner) -> KrillResult<Vec<CaEvt>> {
        let mut evt_dets = vec![];
        if let Some(existing_contact) = &self.repository {
            if existing_contact == &contact {
                return Err(Error::CaRepoInUse(self.handle.clone()));
            }
            // Initiate rolls in all RCs so we can use the new repo in the new key.
            let info = contact.repo_info().clone();
            for rc in self.resources.values() {
                // If we are in any keyroll, reject.. because we will need to
                // introduce the change as a key roll (new key, new repo, etc),
                // and we can only do one roll at a time.
                if !rc.key_roll_possible() {
                    // If we can't roll... well then we have to bail out.
                    // Note: none of these events are committed in that case.
                    return Err(Error::KeyRollNotAllowed);
                }

                evt_dets.append(&mut rc.keyroll_initiate(&info, Duration::seconds(0), signer)?);
            }
        }

        // register updated repo
        info!(
            "CA '{}' updated repository. Service URI will be: {}",
            self.handle,
            contact.server_info().service_uri()
        );

        evt_dets.push(CaEvtDet::RepoUpdated { contact });
        Ok(self.events_from_details(evt_dets))
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
    ) -> KrillResult<Vec<CaEvt>> {
        let route_auth_updates = route_auth_updates.into_explicit();

        let (routes, mut evt_dets) = self.update_authorizations(&route_auth_updates)?;

        // for rc in self.resources
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.update_roas(&routes, config, signer.deref())?;
            if updates.contains_changes() {
                info!("CA '{}' under RC '{}' updated ROAs: {}", self.handle, rcn, updates);

                evt_dets.push(CaEvtDet::RoasUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(self.events_from_details(evt_dets))
    }

    /// Renew existing ROA objects if needed.
    pub fn route_authorizations_renew(
        &self,
        force: bool,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvt>> {
        let mut evt_dets = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.renew_roas(force, &config.issuance_timing, signer)?;
            if updates.contains_changes() {
                if force {
                    info!("CA '{}' reissued all ROAs under RC '{}'", self.handle, rcn);
                } else {
                    info!(
                        "CA '{}' reissued ROAs under RC '{}' before they would expire: {}",
                        self.handle, rcn, updates
                    );
                }

                evt_dets.push(CaEvtDet::RoasUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(self.events_from_details(evt_dets))
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
    pub fn update_authorizations(&self, updates: &RouteAuthorizationUpdates) -> KrillResult<(Routes, Vec<CaEvtDet>)> {
        let mut delta_errors = RoaDeltaError::default();
        let mut res = vec![];

        let all_resources = self.all_resources();

        let mut desired_routes = self.routes.clone();

        // make sure that all removals are held
        for auth in updates.removed() {
            if desired_routes.remove(auth) {
                res.push(CaEvtDet::RouteAuthorizationRemoved { auth: *auth });
            } else {
                delta_errors.add_unknown((*auth).into())
            }
        }

        // make sure that all new additions are allowed
        for addition in updates.added() {
            let roa_def: RoaDefinition = (*addition).into();
            let authorizations: Vec<&RouteAuthorization> = desired_routes.authorizations().collect();

            if !addition.max_length_valid() {
                // The (max) length is invalid for this prefix
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
                res.push(CaEvtDet::RouteAuthorizationAdded { auth: *addition });
            }
        }

        if !delta_errors.is_empty() {
            Err(Error::RoaDeltaError(self.handle().clone(), delta_errors))
        } else {
            Ok((desired_routes, res))
        }
    }
}

/// # Autonomous System Provider Authorizations
///
impl CertAuth {
    /// Show current AspaDefinitions
    pub fn aspas_definitions_show(&self) -> AspaDefinitionList {
        AspaDefinitionList::new(self.aspas.all().cloned().collect())
    }

    /// Process AspaDefinitionUpdates:
    /// - add new aspas
    /// - replace existing
    /// - remove aspas to be removed
    pub fn aspas_definitions_update(
        &self,
        updates: AspaDefinitionUpdates,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvt>> {
        let mut res = vec![];

        let (add_or_replace, remove) = updates.unpack();

        // Keep track of a copy of the AspaDefinitions so we can use to update ASPA objects
        let mut all_aspas = self.aspas.clone();

        for customer in remove {
            if !all_aspas.has(customer) {
                return Err(Error::AspaCustomerUnknown(self.handle().clone(), customer));
            }
            res.push(CaEvtDet::AspaConfigRemoved { customer });
            all_aspas.remove(customer);
        }

        for aspa_config in add_or_replace {
            let customer = aspa_config.customer();

            if !self.all_resources().contains_asn(customer) {
                return Err(Error::AspaCustomerAsNotEntitled(self.handle().clone(), customer));
            }

            // Update the aspas copy so we can update ASPA objects for the events
            all_aspas.add_or_replace(aspa_config.clone());

            match self.aspas.get(customer) {
                None => res.push(CaEvtDet::AspaConfigAdded { aspa_config }),
                Some(existing) => {
                    // Determine the update from existing to (new) aspa_config
                    let added = aspa_config
                        .providers()
                        .iter()
                        .filter(|new_provider| !existing.providers().contains(new_provider))
                        .copied()
                        .collect();

                    let removed = existing
                        .providers()
                        .iter()
                        .filter(|existing| !aspa_config.providers().contains(existing))
                        .copied()
                        .collect();

                    let update = AspaProvidersUpdate::new(added, removed);

                    if update.contains_changes() {
                        res.push(CaEvtDet::AspaConfigUpdated { customer, update })
                    }
                }
            }
        }

        res.append(&mut self.create_updated_aspa_objects(&all_aspas, config, signer)?);

        Ok(self.events_from_details(res))
    }

    pub fn aspas_update(
        &self,
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvt>> {
        self.verify_update(customer, &update)?;

        let mut all_aspas = self.aspas.clone();
        all_aspas.apply_update(customer, &update);

        let mut res = self.create_updated_aspa_objects(&all_aspas, config, signer)?;
        res.push(CaEvtDet::AspaConfigUpdated { customer, update });

        Ok(self.events_from_details(res))
    }

    /// Renew existing ASPA objects if needed.
    pub fn aspas_renew(&self, config: &Config, signer: &KrillSigner) -> KrillResult<Vec<CaEvt>> {
        let mut evt_dets = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.renew_aspas(&config.issuance_timing, signer)?;
            if updates.contains_changes() {
                info!(
                    "CA '{}' reissued ASPAs under RC '{}' before they would expire",
                    self.handle, rcn
                );

                evt_dets.push(CaEvtDet::AspaObjectsUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(self.events_from_details(evt_dets))
    }

    fn create_updated_aspa_objects(
        &self,
        all_aspas: &AspaDefinitions,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvtDet>> {
        let mut update_events = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.update_aspas(all_aspas, config, signer)?;
            if updates.contains_changes() {
                update_events.push(CaEvtDet::AspaObjectsUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }
        Ok(update_events)
    }

    /// Verifies whether the update can be applied.
    fn verify_update(&self, customer: AspaCustomer, update: &AspaProvidersUpdate) -> KrillResult<()> {
        if update.is_empty() {
            return Err(Error::AspaProvidersUpdateEmpty(self.handle().clone(), customer));
        }

        if !self.all_resources().contains_asn(customer) {
            return Err(Error::AspaCustomerAsNotEntitled(self.handle().clone(), customer));
        }

        let current = self
            .aspas
            .get(customer)
            .ok_or_else(|| Error::AspaCustomerUnknown(self.handle().clone(), customer))?;

        current
            .verify_update(update)
            .map_err(|conflict| Error::AspaProvidersUpdateConflict(self.handle().clone(), conflict))?;

        Ok(())
    }
}

/// # BGPSec
///
impl CertAuth {
    pub fn bgpsec_definitions_show(&self) -> BgpSecCsrInfoList {
        self.bgpsec_defs.info_list()
    }

    /// Process BGPSec Definition updates
    pub fn bgpsec_definitions_update(
        &self,
        updates: BgpSecDefinitionUpdates,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvt>> {
        let mut res = vec![];

        let (additions, removals) = updates.unpack();

        // We keep a copy of the definitions so that we can:
        // a. remove and then re-add definitions
        // b. use the updated definitions to generate objects in
        //    applicable RCs
        //
        // (note: actual modifications of self are done when the events are applied)
        let mut definitions = self.bgpsec_defs.clone();

        for key in removals {
            if !definitions.remove(&key) {
                return Err(Error::BgpSecDefinitionUnknown(self.handle.clone(), key));
            } else {
                res.push(CaEvtDet::BgpSecDefinitionRemoved { key });
            }
        }

        // Verify that the CSR in each 'addition' is valid. Then either add
        // a new or update an existing definition.
        for definition in additions {
            // ensure the CSR is validly signed
            definition
                .csr()
                .validate()
                .map_err(|_| Error::BgpSecDefinitionInvalidlySigned(self.handle.clone(), definition.clone()))?;

            let key = BgpSecAsnKey::from(&definition);
            let csr = StoredBgpSecCsr::from(definition.csr());

            // ensure this CA holds the AS
            if !self.all_resources().contains_asn(key.asn()) {
                return Err(Error::BgpSecDefinitionNotEntitled(self.handle.clone(), key));
            }

            if let Some(stored_csr) = definitions.get_stored_csr(&key) {
                if stored_csr != &csr {
                    res.push(CaEvtDet::BgpSecDefinitionUpdated { key, csr: csr.clone() });
                    definitions.add_or_replace(key, csr);
                }
            } else {
                res.push(CaEvtDet::BgpSecDefinitionAdded { key, csr: csr.clone() });
                definitions.add_or_replace(key, csr);
            }
        }

        // Process the updated BGPSec definitions in each RC and add/remove
        // BGPSec certificates as needed.
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.update_bgpsec_certs(&definitions, config, signer)?;
            if !updates.is_empty() {
                res.push(CaEvtDet::BgpSecCertificatesUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(self.events_from_details(res))
    }

    /// Renew any BGPSec certificates if needed.
    pub fn bgpsec_renew(&self, config: &Config, signer: &KrillSigner) -> KrillResult<Vec<CaEvt>> {
        let mut evt_dets = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.renew_bgpsec_certs(&config.issuance_timing, signer)?;

            if updates.contains_changes() {
                info!(
                    "CA '{}' reissued BGPSec certificates under RC '{}' before they would expire",
                    self.handle, rcn
                );

                evt_dets.push(CaEvtDet::BgpSecCertificatesUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(self.events_from_details(evt_dets))
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
    fn rta_sign(&self, name: RtaName, request: RtaContentRequest, signer: &KrillSigner) -> KrillResult<Vec<CaEvt>> {
        let (resources, validity, mut keys, content) = request.unpack();

        if self.rtas.has(&name) {
            return Err(Error::Custom(format!("RTA with name '{}' already exists", name)));
        }

        let rc2ee = self.rta_ee_map_single(&resources, validity, &mut keys, signer)?;
        let builder = ResourceTaggedAttestation::rta_builder(&resources, content, keys)?;

        self.rta_sign_with_ee(name, resources, rc2ee, builder, signer)
    }

    /// Co-sign an existing RTA, will fail if there is no existing matching prepared RTA
    fn rta_cosign(
        &self,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CaEvt>> {
        let builder = rta.to_builder()?;

        let resources = {
            let asns = builder.content().as_resources().clone();
            let ipv4 = builder.content().v4_resources().clone();
            let ipv6 = builder.content().v6_resources().clone();
            ResourceSet::new(asns, ipv4.into(), ipv6.into())
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
    ) -> KrillResult<Vec<CaEvt>> {
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

        let rta = SignedRta::new(resources, revocation_info, rta);

        info!("CA '{}' signed an RTA object named '{}'", self.handle, name);

        // Return the RTA
        Ok(vec![StoredEvent::new(
            self.handle(),
            self.version,
            CaEvtDet::RtaSigned { name, rta },
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

            let intersection = rc_resources.intersection(resources);
            if intersection.is_empty() {
                return Err(Error::custom(
                    "RC for prepared RTA no longer contains relevant resources",
                ));
            }

            let ee = rc.create_rta_ee(&intersection, validity, *key, signer)?;
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
        if keys.is_empty() && !self.all_resources().contains(resources) {
            return Err(Error::RtaResourcesNotHeld);
        }

        // Create an EE for each RC that contains part of the resources
        let mut rc_ee: HashMap<ResourceClassName, Cert> = HashMap::new();
        for (rcn, rc) in self.resources.iter() {
            if let Some(rc_resources) = rc.current_resources() {
                let intersection = resources.intersection(rc_resources);
                if !intersection.is_empty() {
                    let key = signer.create_key()?;
                    let ee = rc.create_rta_ee(&intersection, validity, key, signer)?;
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
    ) -> KrillResult<Vec<CaEvt>> {
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

        info!(
            "CA '{}' prepared an RTA object named '{}' for multi-signing",
            self.handle, name
        );

        Ok(vec![StoredEvent::new(
            self.handle(),
            self.version,
            CaEvtDet::RtaPrepared { name, prepared },
        )])
    }
}

/// # Deactivate
///
impl CertAuth {
    pub fn revoke_under_parent(
        &self,
        parent: &ParentHandle,
        signer: &KrillSigner,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationRequest>>> {
        let mut res = HashMap::new();
        for (rcn, rc) in &self.resources {
            if rc.parent_handle() == parent {
                res.insert(rcn.clone(), rc.revoke(signer)?);
            }
        }
        Ok(res)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commons::crypto::KrillSignerBuilder, daemon::config::ConfigDefaults, test};
    use std::time::Duration;

    #[test]
    fn generate_id_cert() {
        test::test_under_tmp(|d| {
            let signers = ConfigDefaults::signers();
            let signer = KrillSignerBuilder::new(&d, Duration::from_secs(1), &signers)
                .build()
                .unwrap();

            Rfc8183Id::generate(&signer).unwrap();
            // Note that ID (TA) certificate generation is tested in rpki-rs
        });
    }
}
