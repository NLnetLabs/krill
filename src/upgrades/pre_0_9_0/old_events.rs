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
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle, RepoInfo},
        provisioning::{IssuanceRequest, RequestResourceLimit, ResourceClassName, RevocationRequest},
        publication::Base64,
    },
    crypto::KeyIdentifier,
    repository::{
        resources::ResourceSet,
        roa::Roa,
        x509::{Serial, Time},
        Cert,
    },
    rrdp::{self, Hash},
    uri,
};

use crate::{
    commons::{
        api::rrdp::{CurrentObjects, DeltaElements, PublishElement, RrdpSession},
        api::{
            rrdp::{Delta, Notification},
            CertInfo, IdCertInfo, ObjectName, ParentCaContact, ReceivedCert, RepositoryContact, Revocation,
            RevocationsDelta, RoaAggregateKey, RtaName,
        },
        eventsourcing::StoredEvent,
    },
    daemon::ca::{self, CaEvt, CaEvtDet, PreparedRta, RoaPayloadJsonMapKey, SignedRta},
    pubd::{
        Publisher, RepositoryAccessEvent, RepositoryAccessEventDetails, RepositoryAccessInitDetails, RepositoryManager,
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
        RepositoryAccessInitDetails::new(old.id_cert.into(), old.rrdp_base_uri, old.rsync_jail)
    }
}

pub struct DerivedEmbeddedCaMigrationInfo {
    pub child_id: IdCertInfo,
    pub parent_responses: HashMap<ChildHandle, idexchange::ParentResponse>,
}

impl OldCaEvt {
    pub fn into_stored_ca_event(
        self,
        version: u64,
        repo_manager: &RepositoryManager,
        derived_embedded_ca_info_map: &HashMap<CaHandle, DerivedEmbeddedCaMigrationInfo>,
    ) -> Result<CaEvt, PrepareUpgradeError> {
        let (id, _, details) = self.unpack();

        let event = match details {
            OldCaEvtDet::RepoUpdated(contact) => {
                let contact = match contact {
                    OldRepositoryContact::Rfc8181(res) => RepositoryContact::for_response(res),
                    OldRepositoryContact::Embedded(_) => {
                        let res = repo_manager.repository_response(&id.convert())?;
                        RepositoryContact::for_response(res)
                    }
                }?;
                CaEvtDet::RepoUpdated { contact }
            }
            OldCaEvtDet::ParentAdded(parent, old_contact) => {
                let contact = match old_contact {
                    OldParentCaContact::Rfc6492(res) => ParentCaContact::for_rfc8183_parent_response(res)?,
                    OldParentCaContact::Ta(details) => ParentCaContact::Ta(details.try_into()?),
                    OldParentCaContact::Embedded => match derived_embedded_ca_info_map.get(&parent.convert()) {
                        Some(info) => {
                            let res = info.parent_responses.get(&id.convert()).ok_or_else(|| PrepareUpgradeError::Custom(
                                format!("Cannot upgrade CA '{}' using embedded parent '{}' which no longer has this CA as a child", id, parent)))?;
                            ParentCaContact::for_rfc8183_parent_response(res.clone())?
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
                    None => {
                        let child_info = derived_embedded_ca_info_map.get(&child.convert()).ok_or_else(|| {
                            PrepareUpgradeError::Custom(format!(
                                "Cannot upgrade CA {}, embedded child {} is no longer present",
                                id, child
                            ))
                        })?;

                        child_info.child_id.clone()
                    }
                    Some(id_cert) => id_cert.into(),
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
    TrustAnchorMade(OldTaCertDetails),

    // Being a parent Events
    ChildAdded(ChildHandle, OldChildDetails),
    ChildCertificateIssued(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildKeyRevoked(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildCertificatesUpdated(ResourceClassName, OldChildCertificateUpdates),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResources(ChildHandle, ResourceSet),
    ChildRemoved(ChildHandle),

    // Being a child Events
    IdUpdated(OldRfc8183Id),
    ParentAdded(ParentHandle, OldParentCaContact),
    ParentUpdated(ParentHandle, OldParentCaContact),
    ParentRemoved(ParentHandle, Vec<ObjectsDelta>),

    ResourceClassAdded(ResourceClassName, OldResourceClass),
    ResourceClassRemoved(ResourceClassName, ObjectsDelta, ParentHandle, Vec<RevocationRequest>),
    CertificateRequested(ResourceClassName, IssuanceRequest, KeyIdentifier),
    CertificateReceived(ResourceClassName, KeyIdentifier, OldRcvdCert),

    // Key life cycle
    KeyRollPendingKeyAdded(ResourceClassName, KeyIdentifier),
    KeyPendingToNew(ResourceClassName, OldCertifiedKey, ObjectsDelta),
    KeyPendingToActive(ResourceClassName, OldCertifiedKey, ObjectsDelta),
    KeyRollActivated(ResourceClassName, RevocationRequest),
    KeyRollFinished(ResourceClassName, ObjectsDelta),
    UnexpectedKeyFound(ResourceClassName, RevocationRequest),

    // Route Authorizations
    RouteAuthorizationAdded(RoaPayloadJsonMapKey),
    RouteAuthorizationRemoved(RoaPayloadJsonMapKey),
    RoasUpdated(ResourceClassName, OldRoaUpdates),

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
        Ok(match old {
            OldCaEvtDet::TrustAnchorMade(ta_cert_details) => CaEvtDet::TrustAnchorMade {
                ta_cert_details: ta_cert_details.try_into()?,
            },
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
                    updates: cert_updates.try_into()?,
                }
            }
            OldCaEvtDet::ChildUpdatedIdCert(child, id_cert) => CaEvtDet::ChildUpdatedIdCert {
                child,
                id_cert: id_cert.into(),
            },
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
                rcvd_cert: rcvd_cert.try_into()?,
            },

            OldCaEvtDet::KeyRollPendingKeyAdded(resource_class_name, pending_key_id) => {
                CaEvtDet::KeyRollPendingKeyAdded {
                    resource_class_name,
                    pending_key_id,
                }
            }
            OldCaEvtDet::KeyPendingToNew(resource_class_name, new_key, _delta) => CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key: new_key.try_into()?,
            },
            OldCaEvtDet::KeyPendingToActive(resource_class_name, current_key, _delta) => CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key: current_key.try_into()?,
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
        })
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
    issued: Vec<OldDelegatedCertificate>,
    removed: Vec<KeyIdentifier>,
}

impl TryFrom<OldChildCertificateUpdates> for ca::ChildCertificateUpdates {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldChildCertificateUpdates) -> Result<Self, Self::Error> {
        let mut issued = vec![];

        for old_delegated in old.issued.into_iter() {
            issued.push(old_delegated.try_into()?);
        }

        Ok(ca::ChildCertificateUpdates::new(issued, old.removed, vec![], vec![]))
    }
}

impl OldChildCertificateUpdates {
    pub fn unpack(self) -> (Vec<OldDelegatedCertificate>, Vec<KeyIdentifier>) {
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
pub struct OldRoaUpdates {
    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    updated: HashMap<RoaPayloadJsonMapKey, OldRoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    removed: HashMap<RoaPayloadJsonMapKey, OldRevokedObject>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate_updated: HashMap<RoaAggregateKey, OldAggregateRoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate_removed: HashMap<RoaAggregateKey, OldRevokedObject>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRevokedObject {
    revocation: Revocation,
    hash: rrdp::Hash,
}

impl TryFrom<OldRoaUpdates> for ca::RoaUpdates {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldRoaUpdates) -> Result<Self, PrepareUpgradeError> {
        let mut updates = ca::RoaUpdates::default();
        for (auth, info) in old.updated {
            let roa = info.roa()?;
            let roa_info = ca::RoaInfo::new(vec![auth], roa);
            updates.update(auth, roa_info);
        }

        for (auth, _revoke) in old.removed {
            updates.remove(auth);
        }

        for (agg_key, agg_info) in old.aggregate_updated {
            let authorizations = agg_info.authorizations;
            let roa = agg_info.roa.roa()?;
            let roa_info = ca::RoaInfo::new(authorizations, roa);
            updates.update_aggregate(agg_key, roa_info);
        }

        for (agg_key, _revoke) in old.aggregate_removed {
            updates.remove_aggregate(agg_key);
        }

        Ok(updates)
    }
}

impl OldRoaUpdates {
    #[allow(clippy::type_complexity)]
    pub fn unpack(
        self,
    ) -> (
        HashMap<RoaPayloadJsonMapKey, OldRoaInfo>,
        HashMap<RoaPayloadJsonMapKey, OldRevokedObject>,
        HashMap<RoaAggregateKey, OldAggregateRoaInfo>,
        HashMap<RoaAggregateKey, OldRevokedObject>,
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
pub struct OldRoaInfo {
    pub object: CurrentObject,           // actual ROA
    name: ObjectName,                    // Name for object in repo
    since: Time,                         // first ROA in RC created
    replaces: Option<OldReplacedObject>, // for revoking when renewing
}

impl OldRoaInfo {
    pub fn roa(&self) -> Result<Roa, PrepareUpgradeError> {
        Roa::decode(self.object.content.to_bytes(), true)
            .map_err(|_| PrepareUpgradeError::custom("Cannot parse existing ROA"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldAggregateRoaInfo {
    pub authorizations: Vec<RoaPayloadJsonMapKey>,

    #[serde(flatten)]
    pub roa: OldRoaInfo,
}

pub type OldCaIni = StoredEvent<OldCaIniDet>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCaIniDet {
    id: OldRfc8183Id,

    // The following two fields need to be kept to maintain data compatibility
    // with Krill 0.4.2 installations.
    //
    // Newer versions of krill will no longer include these fields. I.e. there
    // will be no default embedded repository, and trust anchors will be created
    // through an explicit command and events.
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<RepoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ta_details: Option<OldTaCertDetails>,
}

impl OldCaIniDet {
    pub fn unpack(self) -> (OldRfc8183Id, Option<RepoInfo>, Option<OldTaCertDetails>) {
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
    PublisherRemoved(PublisherHandle, OldRrdpUpdate),
    Published(PublisherHandle, OldRrdpUpdate),
    RrdpSessionReset(OldRrdpSessionReset),
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
        Publisher::new(old.id_cert.into(), old.base_uri)
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

//------------ OldDelegatedCertificate ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldDelegatedCertificate {
    uri: uri::Rsync, // where this cert is published
    #[serde(default)]
    limit: RequestResourceLimit, // the limit on the request
    resource_set: ResourceSet,
    cert: Cert,
}

impl OldDelegatedCertificate {
    pub fn key_identifier(&self) -> KeyIdentifier {
        self.cert.subject_key_identifier()
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}

impl PartialEq for OldDelegatedCertificate {
    fn eq(&self, other: &OldDelegatedCertificate) -> bool {
        self.uri == other.uri
            && self.limit == other.limit
            && self.resource_set == other.resource_set
            && self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for OldDelegatedCertificate {}

impl<T> TryFrom<OldDelegatedCertificate> for CertInfo<T> {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldDelegatedCertificate) -> Result<Self, Self::Error> {
        CertInfo::create(old.cert, old.uri, old.resource_set, old.limit)
            .map_err(|e| PrepareUpgradeError::Custom(format!("cannot convert certificate: {}", e)))
    }
}

//------------ OldRcvdCert ------------------------------------------------------

/// Contains a CA Certificate that has been issued to this CA, for some key.
///
/// Note, this may be a self-signed TA Certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRcvdCert {
    cert: Cert,
    uri: uri::Rsync,
    resources: ResourceSet,
}

impl PartialEq for OldRcvdCert {
    fn eq(&self, other: &OldRcvdCert) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() && self.uri == other.uri
    }
}

impl Eq for OldRcvdCert {}

impl TryFrom<OldRcvdCert> for ReceivedCert {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldRcvdCert) -> Result<Self, Self::Error> {
        ReceivedCert::create(old.cert, old.uri, old.resources, RequestResourceLimit::default())
            .map_err(|e| PrepareUpgradeError::Custom(format!("cannot convert certificate: {}", e)))
    }
}

//------------ OldRrdpSessionReset -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRrdpSessionReset {
    snapshot: OldSnapshot,
    notification: Notification,
}

impl OldRrdpSessionReset {
    pub fn new(snapshot: OldSnapshot, notification: Notification) -> Self {
        OldRrdpSessionReset { snapshot, notification }
    }

    pub fn time(&self) -> Time {
        self.notification.time()
    }

    pub fn notification(&self) -> &Notification {
        &self.notification
    }

    pub fn unpack(self) -> (OldSnapshot, Notification) {
        (self.snapshot, self.notification)
    }
}

//------------ OldRrdpUpdate -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRrdpUpdate {
    delta: Delta,
    notification: Notification,
}

impl OldRrdpUpdate {
    pub fn new(delta: Delta, notification: Notification) -> Self {
        OldRrdpUpdate { delta, notification }
    }

    pub fn time(&self) -> Time {
        self.notification.time()
    }

    pub fn unpack(self) -> (Delta, Notification) {
        (self.delta, self.notification)
    }

    pub fn elements(&self) -> &DeltaElements {
        self.delta.elements()
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::OldCaEvt;

    #[test]
    fn convert_old_child_certificates_updated() {
        let json = include_str!("../../../test-resources/migrations/delta-26.json");
        let _old_evt: OldCaEvt = serde_json::from_str(json).unwrap();
    }
}
