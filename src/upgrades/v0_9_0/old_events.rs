use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt,
    path::PathBuf,
};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange,
        idexchange::{ChildHandle, Handle, ParentHandle, PublisherHandle, RepoInfo},
        provisioning::{IssuanceRequest, ResourceClassName, RevocationRequest},
        publication::Base64,
        resourceset::ResourceSet,
    },
    repository::{
        crypto::KeyIdentifier,
        roa::Roa,
        x509::{Serial, Time},
    },
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        api::rrdp::{CurrentObjects, DeltaElements, PublishElement, RrdpSession},
        api::{
            DelegatedCertificate, ObjectName, ParentCaContact, RcvdCert, RepositoryContact, RevocationsDelta,
            RevokedObject, RoaAggregateKey, RtaName, TaCertDetails,
        },
        eventsourcing::StoredEvent,
    },
    daemon::ca::{self, CaEvt, CaEvtDet, PreparedRta, RouteAuthorization, SignedRta},
    pubd::{
        Publisher, RepositoryAccessEvent, RepositoryAccessEventDetails, RepositoryAccessInitDetails, RepositoryManager,
        RrdpSessionReset, RrdpUpdate,
    },
    upgrades::PrepareUpgradeError,
};

use super::*;

pub type OldPubdEvt = StoredEvent<OldPubdEvtDet>;
pub type OldPubdInit = StoredEvent<OldPubdIniDet>;
pub type OldCaEvt = StoredEvent<OldCaEvtDet>;

impl OldPubdEvt {
    pub fn into_stored_pubd_event(self, version: u64) -> Result<RepositoryAccessEvent, PrepareUpgradeError> {
        let (id, _, details) = self.unpack();
        Ok(RepositoryAccessEvent::new(&id, version, details.into()))
    }

    pub fn needs_migration(&self) -> bool {
        matches!(self.details(), OldPubdEvtDet::PublisherAdded(_, _))
            || matches!(self.details(), OldPubdEvtDet::PublisherRemoved(_, _))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldPubdIniDet {
    id_cert: IdCert,
    session: RrdpSession,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
    repo_base_dir: PathBuf,
}

impl OldPubdIniDet {
    pub fn unpack(self) -> (IdCert, RrdpSession, uri::Https, uri::Rsync, PathBuf) {
        (
            self.id_cert,
            self.session,
            self.rrdp_base_uri,
            self.rsync_jail,
            self.repo_base_dir,
        )
    }
}

impl fmt::Display for OldPubdIniDet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "old init")
    }
}

impl From<OldPubdIniDet> for RepositoryAccessInitDetails {
    fn from(old: OldPubdIniDet) -> Self {
        RepositoryAccessInitDetails::new(old.id_cert, old.rrdp_base_uri, old.rsync_jail)
    }
}

pub struct DerivedEmbeddedCaMigrationInfo {
    pub child_request: idexchange::ChildRequest,
    pub parent_responses: HashMap<ChildHandle, idexchange::ParentResponse>,
}

impl OldCaEvt {
    pub fn into_stored_ca_event(
        self,
        version: u64,
        repo_manager: &RepositoryManager,
        derived_embedded_ca_info_map: &HashMap<Handle, DerivedEmbeddedCaMigrationInfo>,
    ) -> Result<CaEvt, PrepareUpgradeError> {
        let (id, _, details) = self.unpack();

        let event = match details {
            OldCaEvtDet::RepoUpdated(contact) => {
                let contact = match contact {
                    OldRepositoryContact::Rfc8181(res) => RepositoryContact::new(res),
                    OldRepositoryContact::Embedded(_) => {
                        let res = repo_manager.repository_response(&id)?;
                        RepositoryContact::new(res)
                    }
                };
                CaEvtDet::RepoUpdated { contact }
            }
            OldCaEvtDet::ParentAdded(parent, old_contact) => {
                let contact = match old_contact {
                    OldParentCaContact::Rfc6492(res) => ParentCaContact::for_rfc6492(res),
                    OldParentCaContact::Ta(details) => ParentCaContact::Ta(details),
                    OldParentCaContact::Embedded => match derived_embedded_ca_info_map.get(&parent) {
                        Some(info) => {
                            let res = info.parent_responses.get(&id).ok_or_else(|| PrepareUpgradeError::Custom(
                                format!("Cannot upgrade CA '{}' using embedded parent '{}' which no longer has this CA as a child", id, parent)))?;
                            ParentCaContact::for_rfc6492(res.clone())
                        }
                        None => {
                            return Err(PrepareUpgradeError::Custom(format!(
                                "Cannot upgrade CA '{}' using embedded parent '{}' which is no longer present",
                                id, parent
                            )))
                        }
                    },
                };
                CaEvtDet::ParentAdded { parent, contact }
            }
            OldCaEvtDet::ChildAdded(child, old_details) => {
                let (resources, id_cert_opt) = (old_details.resources, old_details.id_cert);

                let id_cert = match id_cert_opt {
                    Some(id_cert) => id_cert,
                    None => {
                        let child_info = derived_embedded_ca_info_map.get(&child).ok_or_else(|| {
                            PrepareUpgradeError::Custom(format!(
                                "Cannot upgrade CA {}, embedded child {} is no longer present",
                                id, child
                            ))
                        })?;

                        child_info.child_request.id_cert().clone()
                    }
                };

                CaEvtDet::ChildAdded {
                    child,
                    id_cert,
                    resources,
                }
            }
            _ => details.try_into()?,
        };

        Ok(CaEvt::new(&id, version, event))
    }

    pub fn needs_migration(&self) -> bool {
        !matches!(self.details(), OldCaEvtDet::ObjectSetUpdated(_, _))
            && !matches!(self.details(), OldCaEvtDet::RepoCleaned(_))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldCaEvtDet {
    // Being a Trust Anchor
    TrustAnchorMade(TaCertDetails),

    // Being a parent Events
    ChildAdded(ChildHandle, OldChildDetails),
    ChildCertificateIssued(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildKeyRevoked(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildCertificatesUpdated(ResourceClassName, OldChildCertificateUpdates),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResources(ChildHandle, ResourceSet),
    ChildRemoved(ChildHandle),

    // Being a child Events
    IdUpdated(Rfc8183Id),
    ParentAdded(ParentHandle, OldParentCaContact),
    ParentUpdated(ParentHandle, OldParentCaContact),
    ParentRemoved(ParentHandle, Vec<ObjectsDelta>),

    ResourceClassAdded(ResourceClassName, OldResourceClass),
    ResourceClassRemoved(ResourceClassName, ObjectsDelta, ParentHandle, Vec<RevocationRequest>),
    CertificateRequested(ResourceClassName, IssuanceRequest, KeyIdentifier),
    CertificateReceived(ResourceClassName, KeyIdentifier, RcvdCert),

    // Key life cycle
    KeyRollPendingKeyAdded(ResourceClassName, KeyIdentifier),
    KeyPendingToNew(ResourceClassName, OldCertifiedKey, ObjectsDelta),
    KeyPendingToActive(ResourceClassName, OldCertifiedKey, ObjectsDelta),
    KeyRollActivated(ResourceClassName, RevocationRequest),
    KeyRollFinished(ResourceClassName, ObjectsDelta),
    UnexpectedKeyFound(ResourceClassName, RevocationRequest),

    // Route Authorizations
    RouteAuthorizationAdded(RouteAuthorization),
    RouteAuthorizationRemoved(RouteAuthorization),
    RoasUpdated(ResourceClassName, RoaUpdates),

    // Publishing
    ObjectSetUpdated(ResourceClassName, HashMap<KeyIdentifier, CurrentObjectSetDelta>),
    RepoUpdated(OldRepositoryContact),
    RepoCleaned(OldRepositoryContact),

    // Rta
    RtaPrepared(RtaName, PreparedRta),
    RtaSigned(RtaName, SignedRta),
}

impl TryFrom<OldCaEvtDet> for CaEvtDet {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCaEvtDet) -> Result<Self, Self::Error> {
        let evt = match old {
            OldCaEvtDet::TrustAnchorMade(ta_cert_details) => CaEvtDet::TrustAnchorMade { ta_cert_details },
            OldCaEvtDet::ChildAdded(_child, _details) => {
                unreachable!("Add child must be converted with embedded children in mind")
            }
            OldCaEvtDet::ChildCertificateIssued(child, resource_class_name, ki) => CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            },
            OldCaEvtDet::ChildKeyRevoked(child, resource_class_name, ki) => CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            },
            OldCaEvtDet::ChildCertificatesUpdated(resource_class_name, cert_updates) => {
                CaEvtDet::ChildCertificatesUpdated {
                    resource_class_name,
                    updates: cert_updates.into(),
                }
            }
            OldCaEvtDet::ChildUpdatedIdCert(child, id_cert) => CaEvtDet::ChildUpdatedIdCert { child, id_cert },
            OldCaEvtDet::ChildUpdatedResources(child, resources) => {
                CaEvtDet::ChildUpdatedResources { child, resources }
            }
            OldCaEvtDet::ChildRemoved(child) => CaEvtDet::ChildRemoved { child },

            OldCaEvtDet::IdUpdated(id) => CaEvtDet::IdUpdated { id: id.into() },
            OldCaEvtDet::ParentAdded(_parent, _contact) => {
                unreachable!("Parent Added event is migrated differently")
            }
            OldCaEvtDet::ParentUpdated(_parent, _contact) => {
                unreachable!("Parent Updated event is migrated differently")
            }
            OldCaEvtDet::ParentRemoved(parent, _delta) => CaEvtDet::ParentRemoved { parent },

            OldCaEvtDet::ResourceClassAdded(_rcn, rc) => rc.into_added_event()?,
            OldCaEvtDet::ResourceClassRemoved(resource_class_name, _delta, parent, revoke_requests) => {
                CaEvtDet::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_requests,
                }
            }
            OldCaEvtDet::CertificateRequested(resource_class_name, req, ki) => CaEvtDet::CertificateRequested {
                resource_class_name,
                req,
                ki,
            },
            OldCaEvtDet::CertificateReceived(resource_class_name, ki, rcvd_cert) => CaEvtDet::CertificateReceived {
                resource_class_name,
                ki,
                rcvd_cert,
            },

            OldCaEvtDet::KeyRollPendingKeyAdded(resource_class_name, pending_key_id) => {
                CaEvtDet::KeyRollPendingKeyAdded {
                    resource_class_name,
                    pending_key_id,
                }
            }
            OldCaEvtDet::KeyPendingToNew(resource_class_name, new_key, _delta) => CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key: new_key.into(),
            },
            OldCaEvtDet::KeyPendingToActive(resource_class_name, current_key, _delta) => CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key: current_key.into(),
            },
            OldCaEvtDet::KeyRollActivated(resource_class_name, revoke_req) => CaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            },
            OldCaEvtDet::KeyRollFinished(resource_class_name, _delta) => {
                CaEvtDet::KeyRollFinished { resource_class_name }
            }
            OldCaEvtDet::UnexpectedKeyFound(resource_class_name, revoke_req) => CaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            },

            OldCaEvtDet::RouteAuthorizationAdded(auth) => CaEvtDet::RouteAuthorizationAdded { auth },
            OldCaEvtDet::RouteAuthorizationRemoved(auth) => CaEvtDet::RouteAuthorizationRemoved { auth },
            OldCaEvtDet::RoasUpdated(resource_class_name, updates) => CaEvtDet::RoasUpdated {
                resource_class_name,
                updates: updates.try_into()?,
            },

            OldCaEvtDet::ObjectSetUpdated(_, _) => unreachable!("This event must not be migrated"),

            OldCaEvtDet::RepoUpdated(_contact) => {
                unreachable!("Repo Updated is migrated with the embedded repo context")
            }
            OldCaEvtDet::RepoCleaned(_contact) => unreachable!("This event must not be migrated"),

            OldCaEvtDet::RtaPrepared(name, prepared) => CaEvtDet::RtaPrepared { name, prepared },
            OldCaEvtDet::RtaSigned(name, rta) => CaEvtDet::RtaSigned { name, rta },
        };
        Ok(evt)
    }
}

impl fmt::Display for OldCaEvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pre 0.9.0 event")
    }
}

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldChildCertificateUpdates {
    issued: Vec<DelegatedCertificate>,
    removed: Vec<KeyIdentifier>,
}

impl From<OldChildCertificateUpdates> for ca::ChildCertificateUpdates {
    fn from(old: OldChildCertificateUpdates) -> Self {
        ca::ChildCertificateUpdates::new(old.issued, old.removed, vec![], vec![])
    }
}

impl OldChildCertificateUpdates {
    pub fn unpack(self) -> (Vec<DelegatedCertificate>, Vec<KeyIdentifier>) {
        (self.issued, self.removed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectsDelta {
    ca_repo: uri::Rsync,
    added: Vec<AddedObject>,
    updated: Vec<UpdatedObject>,
    withdrawn: Vec<WithdrawnObject>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddedObject {
    name: ObjectName,
    object: CurrentObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdatedObject {
    name: ObjectName,
    object: CurrentObject,
    old: Hash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: Hash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSetDelta {
    pub number: u64,
    pub revocations_delta: RevocationsDelta,
    pub manifest_info: OldManifestInfo,
    pub crl_info: OldCrlInfo,
    pub objects_delta: ObjectsDelta,
}

// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaUpdates {
    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    updated: HashMap<RouteAuthorization, RoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    removed: HashMap<RouteAuthorization, RevokedObject>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate_updated: HashMap<RoaAggregateKey, AggregateRoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate_removed: HashMap<RoaAggregateKey, RevokedObject>,
}

impl TryFrom<RoaUpdates> for ca::RoaUpdates {
    type Error = PrepareUpgradeError;

    fn try_from(old: RoaUpdates) -> Result<Self, PrepareUpgradeError> {
        let mut updates = ca::RoaUpdates::default();
        for (auth, info) in old.updated {
            let roa = info.roa()?;
            let roa_info = ca::RoaInfo::new(roa, info.since);
            updates.update(auth, roa_info);
        }

        for (auth, revoke) in old.removed {
            updates.remove(auth, revoke)
        }

        for (agg_key, agg_info) in old.aggregate_updated {
            let roa = agg_info.roa.roa()?;
            let roa_info = ca::RoaInfo::new(roa, agg_info.roa.since);
            let authorizations = agg_info.authorizations;
            let agg = ca::AggregateRoaInfo::new(authorizations, roa_info);
            updates.update_aggregate(agg_key, agg);
        }

        for (agg_key, revoke) in old.aggregate_removed {
            updates.remove_aggregate(agg_key, revoke);
        }

        Ok(updates)
    }
}

impl RoaUpdates {
    #[allow(clippy::type_complexity)]
    pub fn unpack(
        self,
    ) -> (
        HashMap<RouteAuthorization, RoaInfo>,
        HashMap<RouteAuthorization, RevokedObject>,
        HashMap<RoaAggregateKey, AggregateRoaInfo>,
        HashMap<RoaAggregateKey, RevokedObject>,
    ) {
        (
            self.updated,
            self.removed,
            self.aggregate_updated,
            self.aggregate_removed,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaInfo {
    pub object: CurrentObject,           // actual ROA
    name: ObjectName,                    // Name for object in repo
    since: Time,                         // first ROA in RC created
    replaces: Option<OldReplacedObject>, // for revoking when renewing
}

impl RoaInfo {
    pub fn roa(&self) -> Result<Roa, PrepareUpgradeError> {
        Roa::decode(self.object.content.to_bytes(), true)
            .map_err(|_| PrepareUpgradeError::custom("Cannot parse existing ROA"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateRoaInfo {
    pub authorizations: Vec<RouteAuthorization>,

    #[serde(flatten)]
    pub roa: RoaInfo,
}

pub type OldCaIni = StoredEvent<OldCaIniDet>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCaIniDet {
    id: Rfc8183Id,

    // The following two fields need to be kept to maintain data compatibility
    // with Krill 0.4.2 installations.
    //
    // Newer versions of krill will no longer include these fields. I.e. there
    // will be no default embedded repository, and trust anchors will be created
    // through an explicit command and events.
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<RepoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ta_details: Option<TaCertDetails>,
}

impl OldCaIniDet {
    pub fn unpack(self) -> (Rfc8183Id, Option<RepoInfo>, Option<TaCertDetails>) {
        (self.id, self.info, self.ta_details)
    }
}

impl fmt::Display for OldCaIniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA init")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObject {
    content: Base64,
    serial: Serial,
    expires: Time,
}

impl CurrentObject {
    pub fn content(&self) -> &Base64 {
        &self.content
    }
}

//================ Pubd

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldPubdEvtDet {
    PublisherAdded(PublisherHandle, OldPublisher),
    PublisherRemoved(PublisherHandle, RrdpUpdate),
    Published(PublisherHandle, RrdpUpdate),
    RrdpSessionReset(RrdpSessionReset),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldPublisher {
    /// Used by remote RFC8181 publishers
    pub id_cert: IdCert,

    /// Publication jail for this publisher
    pub base_uri: uri::Rsync,

    /// All objects currently published by this publisher, by hash
    pub current_objects: OldCurrentObjects,
}

impl OldPublisher {
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        self.current_objects.apply_delta(delta);
    }
}

impl fmt::Display for OldPubdEvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pre 0.9.0 event")
    }
}

impl From<OldPublisher> for Publisher {
    fn from(old: OldPublisher) -> Self {
        Publisher::new(old.id_cert, old.base_uri)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCurrentObjects(HashMap<Hash, PublishElement>);

impl OldCurrentObjects {
    pub fn new(map: HashMap<Hash, PublishElement>) -> Self {
        OldCurrentObjects(map)
    }
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unpack();

        for p in publishes {
            let hash = p.base64().to_hash();
            self.0.insert(hash, p);
        }

        for u in updates {
            self.0.remove(u.hash());
            let p: PublishElement = u.into();
            let hash = p.base64().to_hash();
            self.0.insert(hash, p);
        }

        for w in withdraws {
            self.0.remove(w.hash());
        }
    }
}

impl From<OldCurrentObjects> for CurrentObjects {
    fn from(old: OldCurrentObjects) -> Self {
        CurrentObjects::new(old.0)
    }
}

impl From<OldPubdEvtDet> for RepositoryAccessEventDetails {
    fn from(old: OldPubdEvtDet) -> Self {
        match old {
            OldPubdEvtDet::PublisherAdded(name, publisher) => RepositoryAccessEventDetails::PublisherAdded {
                name,
                publisher: publisher.into(),
            },
            OldPubdEvtDet::PublisherRemoved(name, _) => RepositoryAccessEventDetails::PublisherRemoved { name },
            _ => unreachable!("no need to migrate these old events"),
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::OldCaEvt;

    #[test]
    #[ignore = "see issue #819"]
    fn convert_old_child_certificates_updated() {
        let json = include_str!("../../../test-resources/migrations/delta-26.json");
        let old_evt: OldCaEvt = serde_json::from_str(json).unwrap();
    }
}
