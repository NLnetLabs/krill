//! The aggregate for an RPKI Certificaton Authority.

use std::vec;
use std::collections::HashMap;
use bytes::Bytes;
use chrono::Duration;
use log::{debug, info, trace, warn};
use rpki::ca::{idexchange, provisioning};
use rpki::ca::idexchange::{CaHandle, ChildHandle, MyHandle, ParentHandle};
use rpki::ca::provisioning::{
    IssuanceRequest, IssuanceResponse, ProvisioningCms, RequestResourceLimit,
    ResourceClassEntitlements, ResourceClassListResponse, ResourceClassName,
    RevocationRequest, RevocationResponse, SigningCert,
};
use rpki::crypto::{KeyIdentifier, PublicKey};
use rpki::repository::cert::Cert;
use rpki::repository::resources::ResourceSet;
use rpki::repository::rta::RtaBuilder;
use rpki::repository::x509::{Time, Validity};
use serde::{Deserialize, Serialize};
use crate::api::admin::{
    ParentCaContact, RepositoryContact, ResourceClassNameMapping,
};
use crate::api::aspa::{
    AspaDefinition, AspaDefinitionList, AspaDefinitionUpdates,
    AspaProvidersUpdate, CustomerAsn,
};
use crate::api::bgpsec::{
    BgpSecCsrInfoList, BgpSecDefinitionUpdates,
};
use crate::api::ca::{
    CertAuthInfo, ChildState, IdCertInfo, ObjectName, ParentInfo,
    ParentKindInfo, ReceivedCert, Revocation, RtaList, RtaName,
    RtaPrepResponse,
};
use crate::api::import::{ImportChild, ImportChildCertificate};
use crate::api::roa::{
    ConfiguredRoa, RoaConfiguration, RoaConfigurationUpdates, RoaInfo,
};
use crate::api::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest, 
};
use crate::commons::KrillResult;
use crate::commons::crypto::{CsrInfo, KrillSigner};
use crate::commons::error::Error;
use crate::commons::eventsourcing::Aggregate;
use crate::constants::test_mode_enabled;
use crate::config::{Config, IssuanceTimingConfig};
use crate::server::runtime::KrillRuntime;
use super::aspa::AspaDefinitions;
use super::bgpsec::BgpSecDefinitions;
use super::child::{ChildDetails, ChildCertificateUpdates, UsedKeyState};
use super::commands::{
    CertAuthCommand, CertAuthCommandDetails, CertAuthInitCommand, 
    CertAuthStorableCommand,
};
use super::events::{CertAuthEvent, CertAuthInitEvent};
use super::rc::{DropReason, ResourceClass};
use super::roa::Routes;
use super::rta::{PreparedRta, Rtas, SignedRta};


//------------ CertAuth ------------------------------------------------------

/// The aggregate for an RPKI Certification Authority (CA).
///
/// It represents an “organizational” CA: It can have multiple parents and
/// multiple keys under each. For each of them, it will have a resource class
/// that represents the actual published CA.
///
/// Configurations for published objects such as ROAs or ASPA objects are
/// kept at the level of the CA, and actual RPKI objects are then issued
/// under the resource class that has matching resources.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuth {
    /// The local handle of the CA.
    handle: CaHandle,

    /// The current version of the CA.
    version: u64,

    /// The identity certificate.
    ///
    /// This is used for both the up-down (aka RFC 6492) and publication
    /// (aka RFC 8183) protocols.
    id: Rfc8183Id,

    /// Contact information for the repository this CA publishes to.
    ///
    /// This can be `None` if a repository has not been configured yet. In
    /// this case, no certficates are issued and no objects published.
    repository: Option<RepositoryContact>,

    /// The parent CAs and their contact information.
    parents: HashMap<ParentHandle, ParentCaContact>,

    /// The name of the next resource class to be created.
    next_class_name: u32,

    /// The resource classes of the CA.
    resources: HashMap<ResourceClassName, ResourceClass>,

    /// The child CAs of the CA.
    children: HashMap<ChildHandle, ChildDetails>,

    /// The ROA definitions.
    routes: Routes,

    /// The RTAs of the CA.
    #[serde(skip_serializing_if = "Rtas::is_empty", default)]
    rtas: Rtas,

    /// The ASPA definitions of the CA.
    #[serde(skip_serializing_if = "AspaDefinitions::is_empty", default)]
    aspas: AspaDefinitions,

    /// The BGPsec router key definitions of the CA.
    #[serde(skip_serializing_if = "BgpSecDefinitions::is_empty", default)]
    bgpsec_defs: BgpSecDefinitions,
}

impl Aggregate for CertAuth {
    type Command = CertAuthCommand;
    type StorableCommandDetails = CertAuthStorableCommand;
    type Event = CertAuthEvent;

    type InitCommand = CertAuthInitCommand;
    type InitEvent = CertAuthInitEvent;

    type Error = Error;

    type Context<'a> = &'a KrillRuntime;

    fn init(handle: &MyHandle, event: CertAuthInitEvent) -> Self {
        CertAuth {
            handle: handle.clone(),
            version: 1,

            id: event.id,

            repository: None,
            parents: HashMap::new(),

            next_class_name: 0,
            resources: HashMap::new(),

            children: HashMap::new(),

            routes: Routes::default(),
            rtas: Rtas::default(),
            aspas: AspaDefinitions::default(),
            bgpsec_defs: BgpSecDefinitions::default(),
        }
    }

    fn process_init_command(
        _command: CertAuthInitCommand,
        krill: &KrillRuntime,
    ) -> Result<CertAuthInitEvent, Error> {
        Rfc8183Id::generate(krill.signer()).map(|id| CertAuthInitEvent { id })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn process_command(
        &self,
        command: CertAuthCommand,
        krill: &KrillRuntime,
    ) -> Result<Vec<CertAuthEvent>, Error> {
        trace!(
            "Sending command to CA '{}', version: {}: {}",
            self.handle, self.version, command,
        );

        match command.into_details() {
            // Child commands

            CertAuthCommandDetails::ChildAdd(child, id_cert, resources) => {
                self.process_child_add(child, id_cert, resources)
            }

            CertAuthCommandDetails::ChildImport(
                import_child
            ) => {
                self.process_child_import(
                    import_child, krill.config(), krill.signer(),
                )
            }

            CertAuthCommandDetails::ChildUpdateResources(child, res) => {
                self.process_child_update_resources(&child, res)
            }

            CertAuthCommandDetails::ChildUpdateId(child, id_cert) => {
                self.process_child_update_id_cert(&child, id_cert)
            }

            CertAuthCommandDetails::ChildUpdateResourceClassNameMapping(
                child, mapping,
            ) => {
                self.process_child_resource_class_name_mapping(child, mapping)
            }

            CertAuthCommandDetails::ChildCertify(
                child, request,
            ) => {
                self.process_child_certify(
                    child, request, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::ChildRevokeKey(child, request) => {
                self.process_child_revoke_key(child, request)
            }

            CertAuthCommandDetails::ChildRemove(child) => {
                self.process_child_remove(&child)
            }

            CertAuthCommandDetails::ChildSuspendInactive(child) => {
                self.process_child_suspend_inactive(&child)
            }

            CertAuthCommandDetails::ChildUnsuspend(child) => {
                self.process_child_unsuspend(&child)
            }


            // Parent commands

            CertAuthCommandDetails::GenerateNewIdKey => {
                self.process_generate_new_id_key(krill.signer())
            }

            CertAuthCommandDetails::AddParent(parent, info) => {
                self.process_add_parent(parent, info)
            }

            CertAuthCommandDetails::UpdateParentContact(parent, info) => {
                self.process_update_parent_contact(parent, info)
            }

            CertAuthCommandDetails::RemoveParent(parent) => {
                self.process_remove_parent(parent)
            }

            CertAuthCommandDetails::UpdateEntitlements(
                parent, entitlements
            ) => {
                self.process_update_entitlements(
                    parent, entitlements, krill.signer(),
                )
            }

            CertAuthCommandDetails::UpdateRcvdCert(class_name, rcvd_cert) => {
                self.process_update_received_cert(
                    class_name, rcvd_cert, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::DropResourceClass(rcn, reason) => {
                self.process_drop_resource_class(rcn, reason, krill.signer())
            }

            // Key rolls

            CertAuthCommandDetails::KeyRollInitiate(duration) => {
                self.process_keyroll_initiate(duration, krill.signer())
            }

            CertAuthCommandDetails::KeyRollActivate(duration) => {
                self.process_keyroll_activate(
                    duration, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::KeyRollFinish(rcn, response) => {
                self.process_keyroll_finish(rcn, response)
            }

            // Publishing

            CertAuthCommandDetails::RepoUpdate(contact) => {
                self.process_update_repo(contact, krill.signer())
            }

            // ROAs

            CertAuthCommandDetails::RouteAuthorizationsUpdate(updates) => {
                self.process_route_authorizations_update(
                    updates, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::RouteAuthorizationsRenew => {
                self.process_route_authorizations_renew(
                    false, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::RouteAuthorizationsForceRenew=> {
                self.process_route_authorizations_renew(
                    true, krill.config(), krill.signer()
                )
            }

            // ASPA

            CertAuthCommandDetails::AspasUpdate(updates) => {
                self.process_aspas_update(
                    updates, krill.config(), krill.signer()
                )
            }

            CertAuthCommandDetails::AspasUpdateExisting(
                customer, update,
            ) => {
                self.process_aspas_update_existing(
                    customer, update, krill.config(), krill.signer(),
                )
            }

            CertAuthCommandDetails::AspasRenew => {
                self.process_aspas_renew(krill.config(), krill.signer())
            }

            // BGPsec router keys

            CertAuthCommandDetails::BgpSecUpdateDefinitions(updates) => {
                self.process_bgpsec_definitions_update(
                    updates, krill.config(), krill.signer(),
                )
            }

            CertAuthCommandDetails::BgpSecRenew => {
                self.process_bgpsec_renew(krill.config(), krill.signer())
            }

            // RTA
            CertAuthCommandDetails::RtaMultiPrepare(name, request) => {
                self.process_rta_multi_prep(name, request, krill.signer())
            }

            CertAuthCommandDetails::RtaCoSign(name, rta) => {
                self.process_rta_cosign(name, rta, krill.signer())
            }

            CertAuthCommandDetails::RtaSign(name, request) => {
                self.process_rta_sign(name, request, krill.signer())
            }
        }
    }

    //  XXX This method panics when events are inconsistent. This should
    //      probably be changed.
    //
    //  XXX PANICS
    fn apply(&mut self, event: CertAuthEvent) {
        match event {
            // Child events
            CertAuthEvent::ChildAdded { child, id_cert, resources } => {
                self.children.insert(
                    child,
                    ChildDetails::new(id_cert, resources)
                );
            }

            CertAuthEvent::ChildCertificateIssued {
                child, resource_class_name, ki,
            } => {
                self.children.get_mut(
                    &child
                ).unwrap().used_keys.insert(
                    ki, UsedKeyState::InUse(resource_class_name)
                );
            }

            CertAuthEvent::ChildKeyRevoked {
                child, resource_class_name, ki,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_removed_revoked_key(&ki);
                self.children.get_mut(
                    &child
                ).unwrap().used_keys.insert(
                    ki, UsedKeyState::Revoked
                );
            }

            CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name, updates,
            } => {
                let rc = self.resources.get_mut(
                    &resource_class_name
                ).unwrap();

                for cert in updates.issued {
                    rc.apply_added_issued_certificate(cert)
                }

                for cert in updates.unsuspended {
                    rc.apply_unsuspend_certificate(cert)
                }

                for rem in updates.removed {
                    rc.apply_removed_revoked_key(&rem);

                    // This loop is inefficient, but certificate revocations
                    // are not that common, so it's
                    // not a big deal. Tracking this better would require that
                    // we track the child handle somehow.
                    // That is a bit hard when this revocation is the result
                    // from a republish where we lost
                    // all resources delegated to the child.
                    for child in self.children.values_mut() {
                        if child.is_issued(&rem) {
                            child.used_keys.insert(
                                rem, UsedKeyState::Revoked
                            );
                        }
                    }
                }

                for cert in updates.suspended {
                    rc.apply_suspend_certificate(cert);
                }
            }

            CertAuthEvent::ChildUpdatedIdCert { child, id_cert } => {
                self.children.get_mut(&child).unwrap().id_cert = id_cert;
            }

            CertAuthEvent::ChildUpdatedResources { child, resources } => {
                self.children.get_mut(
                    &child
                ).unwrap().resources = resources
            }

            CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                child, name_in_parent, name_for_child,
            } => {
                self.children.get_mut(
                    &child
                ).unwrap().rcn_map.insert(name_in_parent, name_for_child);
            }

            CertAuthEvent::ChildRemoved { child } => {
                self.children.remove(&child);
            }

            CertAuthEvent::ChildSuspended { child } => {
                self.children.get_mut(&child).unwrap().state =
                    ChildState::Suspended
            }

            CertAuthEvent::ChildUnsuspended { child } => {
                self.children.get_mut(&child).unwrap().state =
                    ChildState::Active
            }

            //--- Parent events

            CertAuthEvent::IdUpdated { id } => {
                self.id = id;
            }

            CertAuthEvent::ParentAdded { parent, contact } => {
                self.parents.insert(parent, contact);
            }

            CertAuthEvent::ParentUpdated { parent, contact } => {
                self.parents.insert(parent, contact);
            }

            CertAuthEvent::ParentRemoved { parent } => {
                self.parents.remove(&parent);
                self.resources.retain(|_, rc| rc.parent_handle() != &parent);
            }

            CertAuthEvent::ResourceClassAdded {
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

            CertAuthEvent::ResourceClassRemoved {
                resource_class_name, ..
            } => {
                self.resources.remove(&resource_class_name);
            }

            CertAuthEvent::CertificateRequested {
                resource_class_name, req, ki,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_issuance_request(ki, req);
            }

            CertAuthEvent::CertificateReceived {
                resource_class_name,
                ki,
                rcvd_cert,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_received_cert(ki, rcvd_cert);
            }


            // Key roll events

            CertAuthEvent::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id: pending_key,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_pending_key_id_added(pending_key);
            }

            CertAuthEvent::KeyPendingToNew {
                resource_class_name, new_key,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_pending_key_to_new(new_key);
            }

            CertAuthEvent::KeyPendingToActive {
                resource_class_name, current_key,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_pending_key_to_active(current_key);
            }

            CertAuthEvent::KeyRollActivated {
                resource_class_name, revoke_req,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_new_key_activated(revoke_req);
            }

            CertAuthEvent::KeyRollFinished {
                resource_class_name,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_old_key_removed();
            }

            CertAuthEvent::UnexpectedKeyFound { .. } => {
                // no action needed, this is marked to flag that a key may be
                // removed on the server side. The revocation
                // requests are picked up by the `MessageQueue`
                // listener.
            }

            // ROA events

            CertAuthEvent::RouteAuthorizationAdded { auth } => {
                self.routes.add(auth)
            }

            CertAuthEvent::RouteAuthorizationComment { auth, comment } => {
                self.routes.update_comment(&auth, comment)
            }

            CertAuthEvent::RouteAuthorizationRemoved { auth } => {
                self.routes.remove(&auth);
            }

            CertAuthEvent::RoasUpdated { resource_class_name, updates } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_roa_updates(updates)
            }


            // ASPA events

            CertAuthEvent::AspaConfigAdded { aspa_config } => {
                self.aspas.add_or_replace(aspa_config)
            }

            CertAuthEvent::AspaConfigUpdated { customer, update } => {
                self.aspas.apply_update(customer, &update)
            }

            CertAuthEvent::AspaConfigRemoved { customer } => {
                self.aspas.remove(customer)
            }

            CertAuthEvent::AspaObjectsUpdated {
                resource_class_name, updates,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_aspa_updates(updates)
            }

            // BGPsec router keys

            CertAuthEvent::BgpSecDefinitionAdded { key, csr } => {
                self.bgpsec_defs.add_or_replace(key, csr)
            }

            CertAuthEvent::BgpSecDefinitionUpdated { key, csr } => {
                self.bgpsec_defs.add_or_replace(key, csr)
            }

            CertAuthEvent::BgpSecDefinitionRemoved { key } => {
                self.bgpsec_defs.remove(&key);
            }

            CertAuthEvent::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                self.resources.get_mut(
                    &resource_class_name
                ).unwrap().apply_bgpsec_updates(updates)
            }


            // Publication

            CertAuthEvent::RepoUpdated { contact } => {
                if let Some(current) = &self.repository {
                    for rc in self.resources.values_mut() {
                        rc.set_old_repo(current.repo_info.clone());
                    }
                }
                self.repository = Some(contact);
            }


            // RTA

            CertAuthEvent::RtaPrepared { name, prepared } => {
                self.rtas.add_prepared(name, prepared);
            }

            CertAuthEvent::RtaSigned { name, rta } => {
                self.rtas.add_signed(name, rta);
            }
        }
    }

    fn pre_save_events(
        &self, events: &[Self::Event], krill: &KrillRuntime,
    ) -> Result<(), Self::Error> {
        // Let the object store update its ROAs and issued
        // certificates and/or generate manifests and CRLs when relevant
        // changes occur in a `CertAuth`.
        krill.ca_manager().ca_objects_store().cert_auth_pre_save_events(
            self, events
        )?;

        // Let the [`TaskQueue`] handle events pre-save so
        // that relevant changes in a `CertAuth` can trigger follow-up
        // actions. This is done as pre-save listener, because commands
        // that would result in a follow-up should fail, if the task cannot be
        // planned.
        //
        // Tasks will typically be picked up after the CA changes are
        // committed, but they may also be picked up sooner by another
        // thread. Because of that the tasks will remember which minimal
        // version of the CA they are intended for, so that they can
        // be rescheduled should they have been picked up too soon.
        //
        // An example of a triggered task: schedule a synchronisation with the
        // repository (publication server) in case ROAs have been
        // updated.
        krill.tasks().cert_auth_pre_save_events(self, events)?;

        Ok(())
    }

    fn post_save_events(
        &self, events: &[Self::Event], krill: &KrillRuntime,
    ) {
        // Also let the [`TaskQueue`] handle events post-save. We
        // use this to send best-effort post-save signals to children
        // in case a certificate was updated or a child key was revoked.
        // This is a no-op for remote children (we cannot send a signal over
        // RFC 6492).
        krill.tasks().cert_auth_post_save_events(self, events);
    }
}

/// # Data presentation
///
impl CertAuth {
    /// Returns the handle of this CA.
    pub fn handle(&self) -> &CaHandle {
        &self.handle
    }

    /// Returns the CA information for use in the API.
    pub fn as_ca_info(&self) -> CertAuthInfo {
        CertAuthInfo {
            handle: self.handle.clone(),
            id_cert: self.id.cert().clone(),
            repo_info: self.repository.as_ref().map(|repo| {
                repo.repo_info.clone()
            }),
            parents: self.parents.keys().map(|handle| {
                ParentInfo {
                    handle: handle.clone(),
                    kind: ParentKindInfo::Rfc6492
                }
            }).collect(),
            resources: {
                self.resources.values().filter_map(|rc| {
                    rc.current_resources()
                }).fold(
                    ResourceSet::default(),
                    |res, resources| res.union(resources),
                )
            },
            resource_classes: self.resources.iter().map(|(rcn, cls)| {
                (rcn.clone(), cls.to_info())
            }).collect(),
            children: self.children.keys().cloned().collect(),
            suspended_children: {
                self.children.iter().filter(|(_ca, details)| {
                    details.state.is_suspended()
                }).map(|(ca, _)| ca.clone()).collect()
            },
        }
    }

    /// Returns a list of the currently configured ROAs.
    pub fn configured_roas(&self) -> Vec<ConfiguredRoa> {
        // XXX This creates a temporary vec which should probably be avoided.
        self.configured_roas_for_configs(
            self.routes.roa_configurations()
        )
    }

    /// Returns a list of ROAs matching the given ROA configurations.
    pub fn configured_roas_for_configs(
        &self,
        roa_configurations: Vec<RoaConfiguration>,
    ) -> Vec<ConfiguredRoa> {
        let mut configured_roas = vec![];

        for roa_configuration in roa_configurations {
            let mut roa_objects: Vec<RoaInfo> = vec![];
            for rc in self.resources.values() {
                roa_objects
                    .append(&mut rc.matching_roa_infos(&roa_configuration));
            }
            configured_roas
                .push(ConfiguredRoa { roa_configuration, roa_objects })
        }

        configured_roas
    }

    /// Returns an RFC 8183 Child Request.
    ///
    /// This request can be presented as XML to a parent of this CA.
    pub fn child_request(&self) -> idexchange::ChildRequest {
        idexchange::ChildRequest::new(
            self.id_cert().base64.clone(),
            self.handle.convert(),
        )
    }

    /// Returns an RFC 8183 Publisher Request.
    ///
    /// This request can be presented as XML to the repository for this CA.
    pub fn publisher_request(&self) -> idexchange::PublisherRequest {
        idexchange::PublisherRequest::new(
            self.id_cert().base64.clone(),
            self.handle.convert(),
            None,
        )
    }

    /// Returns the ID certificate used by this CA.
    pub fn id_cert(&self) -> &IdCertInfo {
        self.id.cert()
    }

    /// Returns the complete set of all currently received resources, under
    /// all parents, for this `CertAuth`
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
    /// Returns the repository contact information for this CA.
    ///
    /// If the CA does not yet have a repository assigned, returns an error.
    pub fn repository_contact(&self) -> KrillResult<&RepositoryContact> {
        self.repository.as_ref().ok_or(Error::RepoNotSet)
    }
}

/// # Child CAs of this CA.
impl CertAuth {
    /// Export a child under this CA, if possible.
    pub fn child_export(
        &self, child_handle: &ChildHandle,
    ) -> KrillResult<ImportChild> {
        let child = self.get_child(child_handle)?;

        let id_cert = (&child.id_cert).try_into()?;
        let resources = child.resources.clone();

        if self.resources.len() != 1 {
            return Err(Error::custom(
                "export child is not supported for multiple resource classes.",
            ));
        }
        // We know there is exactly one entry.
        let (my_rcn, rc) = self.resources.iter().next().unwrap();

        let issued_key = {
            let issued_keys = child.issued(my_rcn);
            if issued_keys.len() != 1 {
                return Err(Error::custom(
                    "export child is not supported if child has no \
                     issued certificate, or is doing a key rollover.",
                ));
            }
            issued_keys[0]
        };

        let issued_cert = rc.issued(&issued_key).ok_or(Error::custom(
            "no issued certificate found for child to export",
        ))?;

        let csr = issued_cert.csr_info.clone();

        let class_name = {
            let child_rcn = child.name_for_parent_rcn(my_rcn);
            if my_rcn != &child_rcn {
                Some(child_rcn)
            }
            else {
                None
            }
        };

        let issued_cert = ImportChildCertificate { csr, class_name };

        Ok(ImportChild {
            name: child_handle.clone(),
            id_cert,
            resources,
            issued_cert,
        })
    }

    /// Verifies a received provisioning protocol CMS message.
    ///
    /// If the message is for a known child and validates against the ID
    /// certificate stored for that child, returns the message. Otherwise
    /// returns an error.
    pub fn verify_rfc6492(
        &self,
        cms: ProvisioningCms,
    ) -> KrillResult<provisioning::Message> {
        let child_handle = cms.message().sender().convert();
        let child = self.get_child(&child_handle).map_err(|e| {
            Error::Custom(format!(
                "CA {} has issue with request by child {}: {}",
                self.handle(),
                child_handle,
                e
            ))
        })?;

        cms.validate(&child.id_cert.public_key).map_err(|e| {
            Error::Custom(format!(
                "CA {} cannot validate request by child {}: {}",
                self.handle(),
                child_handle,
                e
            ))
        })?;

        Ok(cms.into_message())
    }

    /// Signs a provisioning protocol message for sending towards the child.
    pub fn sign_rfc6492_response(
        &self,
        message: provisioning::Message,
        signer: &KrillSigner,
    ) -> KrillResult<Bytes> {
        signer.create_rfc6492_cms(
            message, &self.id.cert().public_key.key_identifier(),
        ).map(|res| res.to_bytes()).map_err(Error::signer)
    }

    /// Creates a “resource class list response” for a child CA.
    ///
    /// This response is part of the provisioning protocol and contains all
    /// entitlements assigned to a child CA.
    ///
    /// The method returns an error if the child CA is not authorized or
    /// unknown.
    pub fn list(
        &self,
        child_handle: &ChildHandle,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<ResourceClassListResponse> {
        let mut classes = vec![];

        for my_rcn in self.resources.keys() {
            if let Some(class) = self.entitlement_class(
                child_handle, my_rcn, issuance_timing
            )? {
                classes.push(class);
            }
        }

        Ok(ResourceClassListResponse::new(classes))
    }

    /// Creates a “issuance response” for specific resource class of a child.
    ///
    /// This response is part of the provisioning protocol and contains a
    /// single certificate issued to the child CA in a specific resource
    /// class.
    pub fn issuance_response(
        &self,
        child_handle: &ChildHandle,
        my_rcn: &ResourceClassName,
        pub_key: &PublicKey,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<IssuanceResponse> {
        let entitlement_class = self.entitlement_class(
            child_handle, my_rcn, issuance_timing
        )?.ok_or(Error::KeyUseNoIssuedCert)?;

        entitlement_class.into_issuance_response(
            pub_key
        ).ok_or(Error::KeyUseNoIssuedCert)
    }

    /// Creates the entitlements for a child CA in a specific resource class.
    ///
    /// Returns `Ok(None)` if the child or resource class don’t exist or the
    /// resource class hasn’t been certified yet by our parent or the child
    /// doesn’t have resources in this class.
    fn entitlement_class(
        &self,
        child_handle: &ChildHandle,
        my_rcn: &ResourceClassName,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<Option<ResourceClassEntitlements>> {
        let my_rc = match self.resources.get(my_rcn) {
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

        let signing_cert = SigningCert::new(
            my_rcvd_cert.uri.clone(), my_cert
        );

        let child = match self.get_child(child_handle) {
            Ok(child) => child,
            Err(_) => return Ok(None),
        };

        let child_resources = my_rcvd_cert.resources.intersection(
            &child.resources
        );
        if child_resources.is_empty() {
            return Ok(None);
        }

        let child_keys = child.issued(my_rcn);

        let mut issued_certs = vec![];

        // Check current issued certificates, so we may lie a tiny bit here..
        // i.e. we want to avoid that child CAs feel the urge to
        // request new certificates all the time - so we will only tell them
        // about the normal - longer - not after time if their current
        // certificate(s) will expire within the configured number of
        // weeks. I.e. using defaults:
        //  - they would be eligible to a not-after of 52 weeks
        //  - we only tell them 4 weeks before their old cert would expire
        //
        // Note that a child may have multiple keys and issued certificates if
        // they are doing a keyroll. Typically these certificates will
        // have almost the same expiration time, but even if they don't
        // and one of them is about to expire, while the other is still valid
        // for a while.. then telling the child that they are eligible
        // to the not after time of the other is still fine - it would
        // still trigger them to request a replacement for the first which was
        // about to expire.
        let mut not_after = issuance_timing.new_child_cert_not_after();
        let threshold = issuance_timing.new_child_cert_issuance_threshold();

        for ki in child_keys {
            if let Some(issued) = my_rc.issued(&ki) {
                issued_certs.push(
                    issued.to_rfc6492_issued_cert().map_err(|e| {
                        // This should never happen, unless our current
                        // issued certificate can no longer be parsed
                        Error::Custom(format!(
                            "Issue with issued certificate held by \
                             CA '{}', published at '{}', error: {} ",
                            self.handle(),
                            issued.uri,
                            e
                        ))
                    })?
                );

                let expires = issued.validity.not_after();

                if expires > threshold {
                    not_after = expires;
                }
            }
        }

        let child_rcn = child.name_for_parent_rcn(my_rcn);

        Ok(Some(ResourceClassEntitlements::new(
            child_rcn,
            child_resources,
            not_after,
            issued_certs,
            signing_cert,
        )))
    }

    /// Returns whether the child is known.
    fn has_child(&self, child_handle: &ChildHandle) -> bool {
        self.children.contains_key(child_handle)
    }

    /// Returns a child, or an error if the child is unknown.
    pub fn get_child(
        &self,
        child: &ChildHandle,
    ) -> KrillResult<&ChildDetails> {
        self.children.get(child).ok_or_else(|| {
            Error::CaChildUnknown(self.handle.clone(), child.clone())
        })
    }

    /// Returns an iterator for the handles of all children under this CA.
    pub fn children(&self) -> impl Iterator<Item = &ChildHandle> {
        self.children.keys()
    }

    /// Processes the “add child” command.
    ///
    /// Returns an error if the child is a duplicate, or if the resources are
    /// empty, or not held by this CA.
    fn process_child_add(
        &self,
        child: ChildHandle,
        id_cert: IdCertInfo,
        resources: ResourceSet,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if resources.is_empty() {
            Err(Error::CaChildMustHaveResources(self.handle.clone(), child))
        }
        else if !self.all_resources().contains(&resources) {
            Err(Error::CaChildExtraResources(self.handle.clone(), child))
        }
        else if self.has_child(&child) {
            Err(Error::CaChildDuplicate(self.handle.clone(), child))
        }
        else {
            info!(
                "CA '{}' added child '{}' with resources '{}'",
                self.handle, child, resources
            );

            Ok(vec![CertAuthEvent::ChildAdded { child, id_cert, resources }])
        }
    }

    /// Process the “child import” command.
    fn process_child_import(
        &self,
        import_child: ImportChild,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        // overview:
        // - perform checks (e.g. not supported in case we have multiple RCs)
        // - add the child
        // - add the resource class mapping if given
        // - sign a new certificate for the child
        // Combine all events and return them.

        let (child_handle, id_cert, resources, issued_cert) = (
            import_child.name,
            import_child.id_cert,
            import_child.resources,
            import_child.issued_cert,
        );
        let id_cert_info = IdCertInfo::from(id_cert);

        let (class_name_override, csr_info) =
            (issued_cert.class_name, issued_cert.csr);
        let limit = RequestResourceLimit::default(); // i.e. no limit

        // Ensure that we have one, and only one, resource class
        // and get its name.
        if self.resources.len() != 1 {
            return Err(Error::custom(
                "cannot import CA unless parent has exactly one resource \
                 class",
            ));
        }
        let my_rcn = self.resources.keys().next().ok_or_else(|| {
            Error::custom("cannot get resource class")
        })?.clone();

        // Add the child
        let mut events = self.process_child_add(
            child_handle.clone(),
            id_cert_info,
            resources.clone(),
        )?;

        // Add a resource class name mapping if applicable
        if let Some(name_for_child) = class_name_override {
            if name_for_child != my_rcn {
                let mapping = ResourceClassNameMapping {
                    name_in_parent: my_rcn.clone(),
                    name_for_child,
                };

                events.push(
                    CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                        child: child_handle.clone(),
                        name_in_parent: mapping.name_in_parent,
                        name_for_child: mapping.name_for_child,
                    },
                );
            }
        }

        // Issue a certificate for the imported child
        self.append_child_certify(
            child_handle,
            &resources,
            my_rcn,
            csr_info,
            limit,
            config,
            signer,
            &mut events,
        )?;

        Ok(events)
    }

    /// Processes the “child update resources“ command.
    ///
    /// The command requests an update to the entitlements of the given child
    /// CA. If successful, it only creates an event that updates those
    /// resources but does not revoke, reissue, or republish anything.
    ///
    /// If the CA itself does not posses the given resources, the command
    /// results in an error.
    ///
    /// If the child already has the given resources, the command becomes a
    /// no-op.
    fn process_child_update_resources(
        &self, child_handle: &ChildHandle, resources: ResourceSet
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if !self.all_resources().contains(&resources) {
            return Err(Error::CaChildExtraResources(
                self.handle.clone(),
                child_handle.clone(),
            ))
        }

        let child = self.get_child(child_handle)?;
        let resources_diff = resources.difference(&child.resources);
        if !resources_diff.is_empty() {
            info!(
                "CA '{}' update child '{}' resources: {}",
                self.handle, child_handle, resources_diff
            );

            Ok(vec![CertAuthEvent::ChildUpdatedResources {
                child: child_handle.clone(),
                resources,
            }])
        }
        else {
            // Using 'debug' here, because there are possible use cases
            // where updating the child resources to some expected
            // resource set should be considered a no-op without
            // complaints. E.g. if there is a background job calling
            // the API and setting entitlements.
            debug!(
                "CA '{}' update child '{}' resources has no effect, \
                 child already holds all resources",
                self.handle, child_handle
            );
            Ok(vec![])
        }
    }

    /// Processes the “child update ID cert” command.
    ///
    /// If the child already uses the provided ID cert, this is a no-op.
    fn process_child_update_id_cert(
        &self, child_handle: &ChildHandle, id_cert: IdCertInfo
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let child = self.get_child(child_handle)?;

        if id_cert != child.id_cert {
            info!(
                "CA '{}' updated child '{}' cert. New key id: {}",
                self.handle,
                child_handle,
                id_cert.public_key.key_identifier()
            );

            Ok(vec![CertAuthEvent::ChildUpdatedIdCert {
                child: child_handle.clone(),
                id_cert,
            }])
        }
        else {
            // Using 'debug' here, because of possible no-op use cases where
            // the API is called from a background job.
            debug!(
                "CA '{}' updated child '{}' cert had no effect. \
                 Child ID certificate is identical",
                self.handle, child_handle
            );
            Ok(vec![])
        }
    }

    /// Processes the “child update resource class name mapping” command.
    fn process_child_resource_class_name_mapping(
        &self,
        child_handle: ChildHandle,
        mapping: ResourceClassNameMapping,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let child = self.get_child(&child_handle)?;

        if !self.resources.contains_key(&mapping.name_in_parent) {
            warn!(
                "Updating resource class name mapping for\
                 child '{}, but parent does not have any resource class \
                 called '{}', or at least not yet.",
                 child_handle, &mapping.name_in_parent
            );
        }

        if !child.issued(&mapping.name_in_parent).is_empty() {
            return Err(Error::Custom(format!(
                "Cannot add mapping for resource class '{}', child already \
                 received certificate(s).",
                mapping.name_in_parent
            )));
        }

        Ok(vec![
            CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                child: child_handle,
                name_in_parent: mapping.name_in_parent,
                name_for_child: mapping.name_for_child,
            },
        ])
    }

    /// Processes the “child certify” command.
    ///
    /// Returns the events that certify a child, unless:
    /// * the child is unknown,
    /// * the child is not authorized,
    /// * the CSR is invalid,
    /// * the limit exceeds the child allocation,
    /// * the signer fails..
    fn process_child_certify(
        &self,
        child_handle: ChildHandle,
        request: IssuanceRequest,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let (child_rcn, limit, csr) = request.unpack();

        let child = self.get_child(&child_handle)?;
        let my_rcn = child.parent_name_for_rcn(&child_rcn);
        let csr_info = CsrInfo::try_from(&csr)?;

        let mut res = Vec::new();
        self.append_child_certify(
            child_handle,
            &child.resources,
            my_rcn,
            csr_info,
            limit,
            config,
            signer,
            &mut res,
        )?;
        Ok(res)
    }

    /// Appends the events that certify a child CA.
    #[allow(clippy::too_many_arguments)]
    fn append_child_certify(
        &self,
        child_handle: ChildHandle,
        resources: &ResourceSet,
        my_rcn: ResourceClassName,
        csr_info: CsrInfo,
        limit: RequestResourceLimit,
        config: &Config,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<()> {
        if !csr_info.global_uris() && !test_mode_enabled() {
            return Err(Error::invalid_csr(
                "MUST use hostnames in URIs for certificate requests.",
            ));
        }

        let my_rc = self.resources.get(&my_rcn).ok_or_else(|| {
            Error::ResourceClassUnknown(my_rcn.clone())
        })?;

        let issued = my_rc.issue_cert(
            csr_info,
            resources,
            limit,
            &config.issuance_timing,
            &signer,
        )?;
        let cert_name = ObjectName::from_key(&issued.key_identifier(), "cer");

        info!(
            "CA '{}' issued certificate '{}' to child '{}'",
            self.handle, cert_name, child_handle
        );

        events.push(CertAuthEvent::ChildCertificateIssued {
            child: child_handle,
            resource_class_name: my_rcn.clone(),
            ki: issued.key_identifier(),
        });

        let mut cert_updates = ChildCertificateUpdates::default();
        cert_updates.issued.push(issued);
        events.push(CertAuthEvent::ChildCertificatesUpdated {
            resource_class_name: my_rcn,
            updates: cert_updates
        });

        Ok(())
    }

    /// Processes the “child revoke key” command.
    ///
    /// Revokes a key for a child by adding the last certificate for the key
    /// to the CRL and withdrawing the certificate object for it.
    fn process_child_revoke_key(
        &self,
        child_handle: ChildHandle,
        request: RevocationRequest,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let (child_rcn, key) = request.unpack();

        if !self.resources.contains_key(&child_rcn) {
            // This request is for a resource class we don't have. We should
            // not get such requests but telling this to a child may confuse
            // them more, so just return with an empty vec of events - there
            // is no work to do - and ensure that the child just gets a
            // confirmation where this is called.
            return Ok(vec![]);
        }

        let child = self.get_child(&child_handle)?;
        let my_rcn = child.parent_name_for_rcn(&child_rcn);

        if !child.is_issued(&key) {
            return Err(Error::KeyUseNoIssuedCert);
        }

        let mut child_certificate_updates =
            ChildCertificateUpdates::default();
        child_certificate_updates.removed.push(key);

        let cert_name = ObjectName::from_key(&key, "cer");
        info!(
            "CA '{}' revoked certificate '{}' for child '{}'",
            self.handle, cert_name, child_handle
        );

        let rev = CertAuthEvent::ChildKeyRevoked {
            child: child_handle,
            resource_class_name: my_rcn.clone(),
            ki: key,
        };
        let upd = CertAuthEvent::ChildCertificatesUpdated {
            resource_class_name: my_rcn,
            updates: child_certificate_updates,
        };

        Ok(vec![rev, upd])
    }

    /// Processes the ”child remove” command.
    fn process_child_remove(
        &self,
        child_handle: &ChildHandle,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let child = self.get_child(child_handle)?;

        let mut res = Vec::new();

        // Find all the certs in all RCs for this child and revoke, and
        // withdraw them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut cert_updates = ChildCertificateUpdates::default();
            for key in certified_keys {
                if let Some(issued) = rc.issued(&key) {
                    info!(
                        "CA '{}' revoked certificate '{}' for child '{}'",
                        self.handle,
                        issued.name,
                        child_handle
                    );
                    cert_updates.removed.push(issued.key_identifier())
                }
            }

            res.push(CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name: rcn.clone(),
                updates: cert_updates,
            });
        }

        info!("CA '{}' removed child '{}'", self.handle, child_handle);
        res.push(CertAuthEvent::ChildRemoved { child: child_handle.clone() });

        Ok(res)
    }

    /// Processes the “child suspend inactive“ command.
    ///
    /// Suspend a child that has been discovered to be inactive, i.e., has not
    /// been contacting this parent for a prolonged period of time.
    ///
    /// When a child is suspended we need to:
    /// * mark it as suspended, and
    /// * withdraw all certificates issued to it.
    ///
    /// If the child does not have any active certificates, it is not
    /// suspended and the command becomes a no-op.
    fn process_child_suspend_inactive(
        &self,
        child_handle: &ChildHandle,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let child = self.get_child(child_handle)?;

        let mut res = Vec::new();

        if child.state.is_suspended() {
            return Ok(res); // nothing to do, child is already suspended
        }

        // Find all the certs in all RCs for this child and suspend them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut cert_updates = ChildCertificateUpdates::default();

            for key in certified_keys {
                if let Some(issued) = rc.issued(&key) {
                    cert_updates.suspended.push(issued.to_converted());
                }
            }

            res.push(CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name: rcn.clone(),
                updates: cert_updates,
            });
        }

        // Only mark the child as suspended if there was at least one
        // certificate to suspend above. If not this is a no-op - the
        // child has not yet requested any certificates so there is
        // nothing to suspend.
        if !res.is_empty() {
            info!(
                "CA '{}' suspended inactive child '{}'",
                self.handle, child_handle
            );
            res.push(
                CertAuthEvent::ChildSuspended { child: child_handle.clone() }
            );
        }

        Ok(res)
    }

    /// Processes the “child unsuspend” command.
    ///
    /// This command should be issued automatically when a suspended child
    /// CA is seen to contact the parent again.
    ///
    /// When a child is unsuspended we need to:
    /// * mark it as unsuspended,
    /// * republish existing suspended certificates for it, provided that
    ///    * they will not expire for another day,
    ///    * they do not exceed the current resource entitlements of the
    ///      CA, and
    /// - remove other suspended certificates.
    ///
    /// Then the child may or may not request new certificates as it sees fit.
    /// I.e. the unsuspend should be done before the child gets an answer to
    /// its RFC 6492 list request.
    fn process_child_unsuspend(
        &self,
        child_handle: &ChildHandle,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let child = self.get_child(child_handle)?;

        let mut res = Vec::new();

        if !child.state.is_suspended() {
            return Ok(res); // nothing to do, child is not suspended
        }

        // Find all the certs in all RCs for this child and suspend them.
        for (rcn, rc) in self.resources.iter() {
            let certified_keys = child.issued(rcn);

            if certified_keys.is_empty() {
                continue;
            }

            let mut cert_updates = ChildCertificateUpdates::default();

            for key in certified_keys {
                if let Some(suspended) = rc.suspended(&key) {
                    // check that the cert is actually not expired or about to
                    // expire and not overclaiming
                    if suspended.validity.not_after()
                        > Time::now() + Duration::days(1)
                        && child.resources.contains(&suspended.resources)
                    {
                        // certificate is still fit for publication, so move
                        // it back to issued
                        cert_updates.unsuspended.push(
                            suspended.to_converted()
                        );
                    }
                    else {
                        // certificate should not be published as is. Remove
                        // it and the child will request
                        // a new certificate because the resources and or
                        // validity entitlements will have
                        // changed.
                        cert_updates.removed.push(suspended.key_identifier());
                    }
                }
            }

            res.push(CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name: rcn.clone(),
                updates: cert_updates,
            });
        }

        info!("CA '{}' unsuspended child '{}'", self.handle, child_handle);
        res.push(
            CertAuthEvent::ChildUnsuspended { child: child_handle.clone() }
        );

        Ok(res)
    }
}

/// # Parent CAs of this CA
///
impl CertAuth {
    /// Returns an iterator over the handles of all parent CAs.
    pub fn parents(&self) -> impl Iterator<Item = &ParentHandle> {
        self.parents.keys()
    }

    /// Returns the number parents of the CA.
    pub fn nr_parents(&self) -> usize {
        self.parents.len()
    }

    /// Returns whether the given parent is a parent of this CA.
    pub fn has_parent(&self, parent: &ParentHandle) -> bool {
        self.parents.contains_key(parent)
    }

    /// Gets the ParentCaContact for this ParentHandle. Returns an Err when
    /// the parent does not exist.
    pub fn parent(
        &self,
        parent: &ParentHandle,
    ) -> KrillResult<&ParentCaContact> {
        self.parents.get(parent).ok_or_else(|| {
            Error::CaParentUnknown(self.handle.clone(), parent.clone())
        })
    }

    /// Returns the parent handle for the given resource class.
    ///
    /// Returns an error if the resource class is not known to this CA.
    pub fn parent_for_rc(
        &self,
        rcn: &ResourceClassName,
    ) -> KrillResult<&ParentHandle> {
        Ok(self.resources.get(rcn).ok_or_else(|| {
            Error::ResourceClassUnknown(rcn.clone())
        })?.parent_handle())
    }

    /// Returns all currently open certificate requests for a parent.
    ///
    /// Returns an empty map if the parent is not found.
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

    /// Returns whether the CA has any pending requests for a parent
    pub fn has_pending_requests(&self, parent: &ParentHandle) -> bool {
        for rc in self.resources.values() {
            if rc.parent_handle() == parent && rc.has_pending_requests() {
                return true;
            }
        }
        false
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

    /// Returns new revocation requests for all resource class under a parent.
    pub fn revoke_under_parent(
        &self,
        parent: &ParentHandle,
        signer: &KrillSigner,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationRequest>>> {
        let mut events = HashMap::new();
        for (rcn, rc) in &self.resources {
            if rc.parent_handle() == parent {
                events.insert(rcn.clone(), rc.revoke(signer)?);
            }
        }
        Ok(events)
    }

    /// Processes the “generate new ID key” command.
    fn process_generate_new_id_key(
        &self,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let id = Rfc8183Id::generate(&signer)?;

        info!(
            "CA '{}' generated new ID certificate with key id: {}",
            self.handle,
            id.cert().public_key.key_identifier()
        );
        Ok(vec![CertAuthEvent::IdUpdated { id }])
    }

    /// Processes the “add parent” command.
    ///
    /// Returns an error in case a parent by this handle is already known or
    /// the same response is used for more than one parent.
    fn process_add_parent(
        &self,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if self.has_parent(&parent) {
            return Err(Error::CaParentDuplicateName(
                self.handle.clone(), parent
            ))
        }

        // Check if the parent contact was used already.
        for (parent, parent_info) in &self.parents {
            if *parent_info == contact {
                return Err(Error::CaParentDuplicateInfo(
                    self.handle.clone(),
                    parent.clone(),
                ))
            }
        }

        info!("CA '{}' added parent '{}'", self.handle, parent);
        Ok(vec![CertAuthEvent::ParentAdded { parent, contact }])
    }

    /// Processes the “update parent contact” command.
    fn process_update_parent_contact(
        &self,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if !self.has_parent(&parent) {
            return Err(Error::CaParentUnknown(self.handle.clone(), parent))
        }

        info!(
            "CA '{}' updated contact info for parent '{}'",
            self.handle, parent
        );
        Ok(vec![CertAuthEvent::ParentUpdated { parent, contact }])
    }

    /// Processes the “remove parent” command.
    ///
    /// Returns an error if it doesn't exist.
    fn process_remove_parent(
        &self,
        parent: ParentHandle,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if !self.has_parent(&parent) {
            return Err(Error::CaParentUnknown(self.handle.clone(), parent))
        }

        let mut res = Vec::new();

        info!("CA '{}' removed parent '{}'", self.handle, parent);

        for (rcn, rc) in &self.resources {
            if rc.parent_handle() == &parent {
                res.push(CertAuthEvent::ResourceClassRemoved {
                    resource_class_name: rcn.clone(),
                    parent: parent.clone(),
                    revoke_requests: vec![], /* We will do a best
                                              * effort revoke request,
                                              * but not triggered
                                              * through this event */
                });
            }
        }

        res.push(CertAuthEvent::ParentRemoved { parent });

        Ok(res)
    }

    /// Processes the “update entitlements” command.
    ///
    /// Processes entitlements received from a parent, and updates the
    /// resource classes for this CA as needed. I.e.
    ///
    /// 1) It removes lost resource classes and requests revocation of the
    ///    key(s). Note that this revocation request may result in an error
    ///    because the parent already revoked these keys - or not - we don't
    ///    know.
    ///
    /// 2) For any new resource class in the entitlements new resource
    ///    classes will be created, each with a pending key and an open
    ///    certificate sign request.
    ///
    /// 3) For resource classes that exist both for the CA and in the
    ///    entitlements, new certificates will be requested in case resource
    ///    entitlements, or validity times (“not after”) changed.
    ///
    /// Note that when we receive the updated certificate, we will republish
    /// and shrink/revoke child certificates and objects as needed.
    fn process_update_entitlements(
        &self,
        parent_handle: ParentHandle,
        entitlements: ResourceClassListResponse,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut res = Vec::new();

        // Check if there is a resource class for each entitlement

        // Check if there are any current resource classes, now removed
        // from the entitlements. In which case we will have to clean them
        // up and un-publish everything there was.
        let current_resource_classes = &self.resources;

        let entitled_classes = entitlements
            .classes()
            .iter()
            .map(|c| c.class_name())
            .collect::<Vec<_>>();

        for (rcn, rc) in
            current_resource_classes.iter().filter(|(_name, class)| {
                // Find the classes for this parent, not included
                // in the entitlements now received.
                class.parent_handle() == &parent_handle
                    && !entitled_classes.contains(&class.parent_rc_name())
            })
        {
            let revoke_requests = rc.revoke(signer)?;

            info!(
                "Updating Entitlements for CA: {}, Removing RC: {}",
                &self.handle, &rcn
            );

            res.push(CertAuthEvent::ResourceClassRemoved {
                resource_class_name: rcn.clone(),
                parent: parent_handle.clone(),
                revoke_requests,
            });
        }

        // Now check all the entitlements and either create an RC for them, or
        // update.
        let mut next_class_name = self.next_class_name;

        for ent in entitlements.classes() {
            let parent_rc_name = ent.class_name();

            match self.find_parent_rc(&parent_handle, parent_rc_name) {
                Some(rc) => {
                    // We have a matching RC, make requests (note this may be
                    // a no-op).
                    rc.append_entitlement_events(
                        self.handle(),
                        ent,
                        &self.repository_contact()?.repo_info,
                        &signer,
                        &mut res,
                    )?;
                }
                None => {
                    // Create a resource class with a pending key
                    let pending_key = signer.create_key()?;

                    let rcn = ResourceClassName::from(next_class_name);
                    next_class_name += 1;

                    info!(
                        "CA '{}' received entitlement under parent '{}', \
                         created resource class '{}' and made certificate \
                         request",
                         self.handle, parent_handle, rcn,
                    );

                    let rc = ResourceClass::create(
                        rcn.clone(),
                        rcn.to_string(),
                        parent_handle.clone(),
                        parent_rc_name.clone(),
                        pending_key,
                    );

                    res.push(
                        CertAuthEvent::ResourceClassAdded {
                            resource_class_name: rcn,
                            parent: parent_handle.clone(),
                            parent_resource_class_name: parent_rc_name.clone(),
                            pending_key,
                        }
                    );
                    rc.append_entitlement_events(
                        self.handle(),
                        ent,
                        &self.repository_contact()?.repo_info,
                        &signer,
                        &mut res
                    )?;
                }
            }
        }

        Ok(res)
    }

    /// Maps a parent's resource class name to our own resource class.
    fn find_parent_rc(
        &self,
        parent: &ParentHandle,
        parent_rcn: &ResourceClassName,
    ) -> Option<&ResourceClass> {
        self.resources.values().find(|&rc| {
            rc.parent_handle() == parent && rc.parent_rc_name() == parent_rcn
        })
    }

    /// Processes the “update received certificate” command.
    ///
    /// This method updates the received certificate for the given parent
    /// and resource class, and will return an error if either is unknown.
    ///
    /// It will generate an event for the certificate that is received, and
    /// if it was received for a pending key it will return an event to
    /// promote the pending key appropriately, finally it will also return
    /// a publication event for the matching key if publication is needed.
    ///
    /// This will also generate appropriate events for changes affecting
    /// issued ROAs and certificates - if those would become invalid
    /// because resources were lost.
    fn process_update_received_cert(
        &self,
        rcn: ResourceClassName,
        rcvd_cert: ReceivedCert,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        debug!(
            "CA {}: Updating received cert for class: {}",
            self.handle, rcn
        );

        let rc = self.resources.get(&rcn).ok_or_else(|| {
            Error::ResourceClassUnknown(rcn)
        })?;

        rc.process_received_cert(
            self.handle(),
            rcvd_cert,
            &self.routes,
            &self.aspas,
            &self.bgpsec_defs,
            config,
            signer
        )
    }

    /// Processes the “drop resource class” command.
    ///
    /// The command drops a resource class because it no longer works under
    /// this parent for the specified reason. Note that this will generate
    /// revocation requests for the current keys which will be sent to the
    /// parent on a best effort basis - e.g. if the parent removed the
    /// resource class it may well refuse to revoke the keys - it may not
    /// known them.
    fn process_drop_resource_class(
        &self,
        rcn: ResourceClassName,
        reason: DropReason,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        warn!(
            "Dropping resource class '{rcn}' because of reason: {reason}"
        );
        let rc = self.resources.get(&rcn).ok_or_else(|| {
            Error::ResourceClassUnknown(rcn.clone())
        })?;

        rc.revoke(signer).map(|revoke_requests| {
            vec![CertAuthEvent::ResourceClassRemoved {
                resource_class_name: rcn,
                parent: rc.parent_handle().clone(),
                revoke_requests,
            }]
        })
    }
}

/// # Key Rolls
impl CertAuth {
    /// Processes the “key roll initiate” command.
    fn process_keyroll_initiate(
        &self,
        duration: Duration,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut res = Vec::new();

        for (rcn, rc) in self.resources.iter() {
            let repo = self.repository_contact()?;
            if rc.append_keyroll_initiate(
                &repo.repo_info, duration, signer, &mut res
            )? {
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

    /// Processes the “key roll activate” command.
    fn process_keyroll_activate(
        &self,
        staging_time: Duration,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut res = vec![];

        for (rcn, rc) in self.resources.iter() {
            if rc.append_keyroll_activate(
                staging_time, &config.issuance_timing, signer, &mut res
            )? {
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

    /// Processes the “key roll finish” command.
    fn process_keyroll_finish(
        &self,
        rcn: ResourceClassName,
        _response: RevocationResponse,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let my_rc = self.resources.get(&rcn).ok_or_else(|| {
            Error::ResourceClassUnknown(rcn.clone())
        })?;

        let finish_event = my_rc.process_keyroll_finish()?;

        info!(
            "Finished key roll for ca: {}, rc: {}, under parent: {}",
            &self.handle,
            rcn,
            my_rc.parent_handle()
        );

        Ok(vec![finish_event])
    }
}

/// # Publishing
impl CertAuth {
    /// Processes the “update repository” command.
    ///
    /// Currently, this only allows initially setting the repository. In the
    /// future, we will support migrating to a new repository using a key
    /// roll. See issue #480.
    ///
    /// The command assumes that the repository can be reached. This is
    /// checked by the CA manager before issuing the command.
    pub fn process_update_repo(
        &self,
        contact: RepositoryContact,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut events = vec![];
        if let Some(existing_contact) = &self.repository {
            if existing_contact == &contact {
                return Err(Error::CaRepoInUse(self.handle.clone()));
            }

            // Initiate rolls in all RCs so we can use the new repo in the new
            // key.
            for rc in self.resources.values() {
                // If we are in any key roll, reject because we will need to
                // introduce the change as a key roll (new key, new repo,
                // etc), and we can only do one roll at a
                // time.
                if !rc.key_roll_possible() {
                    // If we can't roll,  well then we have to bail out.
                    // Note: none of these events are committed in that case.
                    return Err(Error::KeyRollInProgress);
                }

                rc.append_keyroll_initiate(
                    &contact.repo_info,
                    Duration::seconds(0),
                    signer,
                    &mut events,
                )?;
            }
        }

        // register updated repo
        info!(
            "CA '{}' updated repository. Service URI will be: {}",
            self.handle,
            contact.server_info.service_uri
        );

        events.push(CertAuthEvent::RepoUpdated { contact });
        Ok(events)
    }
}


/// # ROAs
///
impl CertAuth {
    /// Returns the ROA configuration resulting from applying the updates.
    ///
    /// Does not change the current configuration. Returns the resulting
    /// configuration or the reasons why the updates cannot be applied.
    pub fn get_updated_authorizations(
        &self, updates: &RoaConfigurationUpdates,
    ) -> KrillResult<Routes> {
        Ok(self.routes.process_updates(
            self.handle(), &self.all_resources(), updates
        )?.0)
    }

    /// Processes the “route authorizations update” command.
    ///
    /// Updates the route authorizations for this CA and updates ROAs. Will
    /// return an error in case authorizations are added for which this CA
    /// does not hold the prefix.
    fn process_route_authorizations_update(
        &self,
        mut route_auth_updates: RoaConfigurationUpdates,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        route_auth_updates.set_explicit_max_length();

        let (routes, mut events) = self.routes.process_updates(
            self.handle(), &self.all_resources(), &route_auth_updates
        )?;

        // for rc in self.resources
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_roa_updates(&routes, config, signer)?;
            if !updates.is_empty() {
                info!(
                    "CA '{}' under RC '{}' updated ROAs: {}",
                    self.handle, rcn, updates
                );

                events.push(CertAuthEvent::RoasUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(events)
    }

    /// Processes the “route origin authorization renew“ commands.
    ///
    /// If `force` is `true`, all authorizations are renewed, otherwise only
    /// those that are close to expiring.
    pub fn process_route_authorizations_renew(
        &self,
        force: bool,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut events = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_roa_renewal(
                force, &config.issuance_timing, signer
            )?;
            if !updates.is_empty() {
                if force {
                    info!(
                        "CA '{}' reissued all ROAs under RC '{}'",
                        self.handle, rcn
                    );
                }
                else {
                    info!(
                        "CA '{}' reissued ROAs under RC '{}' before they \
                        would expire: {}",
                        self.handle, rcn, updates
                    );
                }

                events.push(CertAuthEvent::RoasUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(events)
    }
}

/// # ASPA
///
impl CertAuth {
    /// Returns the list of current ASPA definitions.
    pub fn aspas_definitions_show(&self) -> AspaDefinitionList {
        AspaDefinitionList::new(self.aspas.iter().cloned().collect())
    }

    /// Processes the “ASPAs update” command.
    fn process_aspas_update(
        &self,
        updates: AspaDefinitionUpdates,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let (all_aspas, mut events) = self.aspas.process_updates(
            self.handle(), &self.all_resources(), updates
        )?;
        self.append_updated_aspa_objects(
            &all_aspas, config, signer, &mut events
        )?;
        Ok(events)
    }

    /// Processes the “ASPAs update existing” command.
    fn process_aspas_update_existing(
        &self,
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {

        if self.updated_allowed_and_needed(customer, &update)? {
            let mut all_aspas = self.aspas.clone();
            all_aspas.apply_update(customer, &update);
            let mut events = Vec::new();

            self.append_updated_aspa_objects(
                &all_aspas, config, signer, &mut events
            )?;
            events.push(
                CertAuthEvent::AspaConfigUpdated { customer, update }
            );
            Ok(events)
        }
        else {
            Ok(vec![])
        }
    }

    /// Verifies whether the update is allowed and needs to be applied.
    ///
    /// The update does not need to be applied if there would be no change in
    /// the configured ASPA definition. This gives us idempotence and
    /// allows an operator just issue a command to add a provider for a
    /// customer ASN, and if it was already authorised then no work is
    /// needed.
    fn updated_allowed_and_needed(
        &self,
        customer: CustomerAsn,
        update: &AspaProvidersUpdate,
    ) -> KrillResult<bool> {
        // The easiest way to check this is by getting the existing
        // definition, or a default empty one if we did not have one,
        // then apply the update on a copy and verify if it's actually
        // changed, and if so if the the result would be acceptable.

        let existing = self.aspas.get(customer).cloned().unwrap_or_else(|| {
            AspaDefinition { customer, providers: vec![] }
        });

        let mut updated = existing.clone();
        updated.apply_update(update);

        if updated == existing {
            Ok(false)
        }
        else if updated.providers.is_empty() {
            // this update will remove the definition
            Ok(true)
        }
        else if !self.all_resources().contains_asn(customer) {
            // removal would have been okay, but for all other changes the CA
            // still needs to hold the customer AS
            Err(Error::AspaCustomerAsNotEntitled(
                self.handle().clone(),
                customer,
            ))
        }
        else if updated.customer_used_as_provider() {
            Err(Error::AspaCustomerAsProvider(
                self.handle().clone(),
                customer,
            ))
        }
        else {
            Ok(true)
        }
    }

    /// Appends the events for updating the ASPA objects.
    fn append_updated_aspa_objects(
        &self,
        all_aspas: &AspaDefinitions,
        config: &Config,
        signer: &KrillSigner,
        events: &mut Vec<CertAuthEvent>,
    ) -> KrillResult<()> {
        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_aspa_updates(all_aspas, config, signer)?;
            if !updates.is_empty() {
                events.push(CertAuthEvent::AspaObjectsUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }
        Ok(())
    }

    /// Processes the “ASPAs renew” command.
    fn process_aspas_renew(
        &self,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut events = Vec::new();

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_aspa_renewal(
                &config.issuance_timing, signer
            )?;
            if !updates.is_empty() {
                info!(
                    "CA '{}' reissued ASPAs under RC '{}' before they would \
                    expire",
                    self.handle, rcn
                );

                events.push(CertAuthEvent::AspaObjectsUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(events)
    }
}

/// # BGPsec router keys
///
impl CertAuth {
    /// Returns all current BGPsec router key definitions.
    pub fn bgpsec_definitions_show(&self) -> BgpSecCsrInfoList {
        self.bgpsec_defs.create_info_list()
    }

    /// Processes the “BGPsec update definitions“ command.
    fn process_bgpsec_definitions_update(
        &self,
        updates: BgpSecDefinitionUpdates,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let (definitions, mut events) = self.bgpsec_defs.process_updates(
            self.handle(), &self.all_resources(), updates
        )?;

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_bgpsec_updates(
                &definitions, config, signer
            )?;
            if !updates.is_empty() {
                events.push(CertAuthEvent::BgpSecCertificatesUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(events)
    }

    /// Processes the “BGPsec renew” command.
    fn process_bgpsec_renew(
        &self,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let mut events = vec![];

        for (rcn, rc) in self.resources.iter() {
            let updates = rc.create_bgpsec_renewal(
                &config.issuance_timing, signer
            )?;

            if !updates.is_empty() {
                info!(
                    "CA '{}' reissued BGPsec certificates under RC '{}' \
                     before they would expire",
                    self.handle, rcn
                );

                events.push(CertAuthEvent::BgpSecCertificatesUpdated {
                    resource_class_name: rcn.clone(),
                    updates,
                });
            }
        }

        Ok(events)
    }
}


/// # RTAs
///
impl CertAuth {
    /// Returns a list of all currently defined RTAs.
    pub fn rta_list(&self) -> RtaList {
        self.rtas.list()
    }

    /// Returns the RTA with the given name.
    pub fn rta_show(
        &self,
        name: &str,
    ) -> KrillResult<ResourceTaggedAttestation> {
        self.rtas.signed_rta(name)
    }

    /// Returns the RTA preparation response for the given RTA.
    pub fn rta_prep_response(
        &self,
        name: &str,
    ) -> KrillResult<RtaPrepResponse> {
        self.rtas
            .prepared_rta(name)
            .map(|prepped| RtaPrepResponse::new(prepped.keys().collect()))
    }

    /// Processes the “RTA multisigned prepare“ command.
    fn process_rta_multi_prep(
        &self,
        name: RtaName,
        request: RtaPrepareRequest,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if self.all_resources().intersection(&request.resources).is_empty() {
            return Err(Error::custom(
                "None of the resources for RTA are held by this CA",
            ));
        }

        if self.rtas.has(&name) {
            return Err(Error::Custom(format!(
                "RTA with name '{name}' already exists"
            )));
        }

        let mut keys = HashMap::new();

        for (rcn, rc) in self.resources.iter() {
            if let Some(rc_resources) = rc.current_resources() {
                if !rc_resources.intersection(&request.resources).is_empty() {
                    let key = signer.create_key()?;
                    keys.insert(rcn.clone(), key);
                }
            }
        }

        let prepared = PreparedRta::new(
            request.resources, request.validity, keys
        );

        info!(
            "CA '{}' prepared an RTA object named '{}' for multi-signing",
            self.handle, name
        );

        Ok(vec![CertAuthEvent::RtaPrepared { name, prepared }])
    }

    /// Proceses the “RTA co-sign“ command.
    ///
    /// Co-signs an existing RTA. Will fail if there is no existing matching
    /// prepared RTA.
    fn process_rta_cosign(
        &self,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let builder = rta.to_builder()?;

        let resources = {
            let asns = builder.content().as_resources().clone();
            let ipv4 = builder.content().v4_resources().clone();
            let ipv6 = builder.content().v6_resources().clone();
            ResourceSet::new(asns, ipv4.into(), ipv6.into())
        };

        let keys = builder.content().subject_keys();
        let rc2ee = self.rta_ee_map_prepared(
            &name, &resources, keys, signer
        )?;

        self.rta_sign_with_ee(name, resources, rc2ee, builder, signer)
    }

    /// Processes the “RTA sign” command.
    fn process_rta_sign(
        &self,
        name: RtaName,
        mut request: RtaContentRequest,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        if self.rtas.has(&name) {
            return Err(Error::Custom(
                format!("RTA with name '{name}' already exists")
            ));
        }

        let rc2ee = self.rta_ee_map_single(
            &request.resources,
            request.validity,
            &mut request.subject_keys,
            signer
        )?;
        let builder = ResourceTaggedAttestation::rta_builder(
            &request.resources, request.content, request.subject_keys,
        )?;

        self.rta_sign_with_ee(name, request.resources, rc2ee, builder, signer)
    }

    /// Signs an RTA with an EE certificate.
    fn rta_sign_with_ee(
        &self,
        name: RtaName,
        resources: ResourceSet,
        rc_ee: HashMap<ResourceClassName, Cert>,
        mut rta_builder: RtaBuilder,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<CertAuthEvent>> {
        let revocation_info = rc_ee.iter().map(|(rcn, ee)| {
            (rcn.clone(), Revocation::from(ee))
        }).collect();

        // Then sign the content with all those RCs and all keys (including
        // submitted keys) and add the cert
        for (_rcn, ee) in rc_ee.into_iter() {
            let ee_key = ee.subject_key_identifier();
            signer.sign_rta(&mut rta_builder, ee)?;
            signer.destroy_key(&ee_key)?;
        }

        let rta = ResourceTaggedAttestation::finalize(rta_builder);

        let rta = SignedRta::new(resources, revocation_info, rta);

        info!("CA '{}' signed an RTA object named '{}'", self.handle, name);

        // Return the RTA
        Ok(vec![CertAuthEvent::RtaSigned { name, rta }])
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
            return Err(Error::custom(
                "Request to sign prepared RTA with changed resources",
            ));
        }

        // Sign with all prepared keys, error out if one of those keys is
        // removed from the request
        let mut rc_ee: HashMap<ResourceClassName, Cert> = HashMap::new();
        for (rcn, key) in prepared.rcn_keys() {
            if !keys.contains(&key) {
                return Err(Error::custom(
                    "RTA Request does not include key for prepared RTA",
                ));
            }

            let rc = self.resources.get(rcn).ok_or_else(|| {
                Error::custom("RC for prepared RTA not found")
            })?;

            let rc_resources = rc.current_resources().ok_or_else(|| {
                Error::custom("RC for RTA has no resources")
            })?;

            let intersection = rc_resources.intersection(resources);
            if intersection.is_empty() {
                return Err(Error::custom(
                    "RC for prepared RTA no longer contains relevant resources",
                ));
            }

            let ee =
                rc.create_rta_ee(&intersection, validity, key, signer)?;
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
        // If there are no other keys supplied, then we MUST have all
        // resources. Otherwise we will just assume that others sign
        // over the resources that we do not have.
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
                    let ee = rc.create_rta_ee(
                        &intersection,
                        validity,
                        key,
                        signer,
                    )?;
                    rc_ee.insert(rcn.clone(), ee);
                }
            }
        }

        let one_of_keys: Vec<KeyIdentifier> = rc_ee
            .values()
            .map(|ee| ee.subject_key_identifier())
            .collect();

        // Add all one-off keys to the list of Key Identifiers
        // Note that list includes possible keys by other CAs in the
        // RtaRequest
        for key in one_of_keys.iter() {
            keys.push(*key);
        }

        Ok(rc_ee)
    }
}


//------------ Rfc8183Id ---------------------------------------------------

/// An identity used for communication with a parent CA.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    /// The ID certificate to use.
    cert: IdCertInfo,
}

impl Rfc8183Id {
    /// Creates a new identity from an existing ID certificate.
    ///
    /// This is only used for upgrading from older versions.
    pub fn new(cert: IdCertInfo) -> Self {
        Rfc8183Id { cert }
    }

    /// Generates a new ID using the given signer.
    pub fn generate(signer: &KrillSigner) -> KrillResult<Self> {
        let cert = signer.create_self_signed_id_cert()?;
        let cert = IdCertInfo::from(&cert);
        Ok(Rfc8183Id { cert })
    }

    /// Returns the ID certificate.
    pub fn cert(&self) -> &IdCertInfo {
        &self.cert
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use crate::commons::crypto::KrillSignerBuilder;
    use crate::commons::test;
    use crate::config::ConfigDefaults;
    use std::time::Duration;
    use super::*;

    #[test]
    fn generate_id_cert() {
        test::test_in_memory(|storage_uri| {
            let signers = ConfigDefaults::signers();
            let signer = KrillSignerBuilder::new(
                storage_uri,
                Duration::from_secs(1),
                &signers,
            )
            .build()
            .unwrap();

            Rfc8183Id::generate(&signer).unwrap();
            // Note that ID (TA) certificate generation is tested in rpki-rs
        });
    }
}
