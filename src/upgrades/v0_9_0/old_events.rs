use std::{collections::HashMap, fmt};

use rpki::{crypto::KeyIdentifier, uri, x509::Time};

use crate::{
    commons::{
        api::{
            ChildHandle, CurrentObject, HexEncodedHash, IssuanceRequest, IssuedCert, ObjectName, ParentCaContact,
            ParentHandle, ResourceClassName, ResourceSet, RevocationRequest, RevocationsDelta, RevokedObject,
            RoaAggregateKey, RtaName, TaCertDetails,
        },
        crypto::IdCert,
        eventsourcing::StoredEvent,
    },
    daemon::ca::{PreparedRta, RouteAuthorization, SignedRta},
};

use super::*;

pub type OldEvt = StoredEvent<OldEvtDet>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldEvtDet {
    // Being a Trust Anchor
    TrustAnchorMade(TaCertDetails),

    // Being a parent Events
    ChildAdded(ChildHandle, ChildDetails),
    ChildCertificateIssued(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildKeyRevoked(ChildHandle, ResourceClassName, KeyIdentifier),
    ChildCertificatesUpdated(ResourceClassName, ChildCertificateUpdates),
    ChildUpdatedIdCert(ChildHandle, IdCert),
    ChildUpdatedResources(ChildHandle, ResourceSet),
    ChildRemoved(ChildHandle),

    // Being a child Events
    IdUpdated(Rfc8183Id),
    ParentAdded(ParentHandle, ParentCaContact),
    ParentUpdated(ParentHandle, ParentCaContact),
    ParentRemoved(ParentHandle, Vec<ObjectsDelta>),

    ResourceClassAdded(ResourceClassName, ResourceClass),
    ResourceClassRemoved(ResourceClassName, ObjectsDelta, ParentHandle, Vec<RevocationRequest>),
    CertificateRequested(ResourceClassName, IssuanceRequest, KeyIdentifier),
    CertificateReceived(ResourceClassName, KeyIdentifier, RcvdCert),

    // Key life cycle
    KeyRollPendingKeyAdded(ResourceClassName, KeyIdentifier),
    KeyPendingToNew(ResourceClassName, CertifiedKey, ObjectsDelta),
    KeyPendingToActive(ResourceClassName, CertifiedKey, ObjectsDelta),
    KeyRollActivated(ResourceClassName, RevocationRequest),
    KeyRollFinished(ResourceClassName, ObjectsDelta),
    UnexpectedKeyFound(ResourceClassName, RevocationRequest),

    // Route Authorizations
    RouteAuthorizationAdded(RouteAuthorization),
    RouteAuthorizationRemoved(RouteAuthorization),
    RoasUpdated(ResourceClassName, RoaUpdates),

    // Publishing
    ObjectSetUpdated(ResourceClassName, HashMap<KeyIdentifier, CurrentObjectSetDelta>),
    RepoUpdated(RepositoryContact),
    RepoCleaned(RepositoryContact),

    // Rta
    RtaPrepared(RtaName, PreparedRta),
    RtaSigned(RtaName, SignedRta),
}

impl fmt::Display for OldEvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pre 0.9.0 event")
    }
}

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificateUpdates {
    issued: Vec<IssuedCert>,
    removed: Vec<KeyIdentifier>,
}

impl ChildCertificateUpdates {
    pub fn unpack(self) -> (Vec<IssuedCert>, Vec<KeyIdentifier>) {
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
    old: HexEncodedHash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: HexEncodedHash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSetDelta {
    pub number: u64,
    pub revocations_delta: RevocationsDelta,
    pub manifest_info: ManifestInfo,
    pub crl_info: CrlInfo,
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
    pub object: CurrentObject,        // actual ROA
    name: ObjectName,                 // Name for object in repo
    since: Time,                      // first ROA in RC created
    replaces: Option<ReplacedObject>, // for revoking when re-newing
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateRoaInfo {
    pub authorizations: Vec<RouteAuthorization>,

    #[serde(flatten)]
    pub roa: RoaInfo,
}

pub type OldIni = StoredEvent<OldIniDet>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldIniDet {
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

impl OldIniDet {
    pub fn unpack(self) -> (Rfc8183Id, Option<RepoInfo>, Option<TaCertDetails>) {
        (self.id, self.info, self.ta_details)
    }
}

impl fmt::Display for OldIniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pre 0.9.0 CA init")
    }
}
