use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt,
};

use rpki::{
    crypto::KeyIdentifier,
    roa::Roa,
    uri,
    x509::{Serial, Time},
};

use crate::{
    commons::{
        api::{
            Base64, ChildHandle, HexEncodedHash, IssuanceRequest, IssuedCert, ObjectName, ParentHandle, RcvdCert,
            RepoInfo, ResourceClassName, ResourceSet, RevocationRequest, RevocationsDelta, RevokedObject,
            RoaAggregateKey, RtaName, TaCertDetails,
        },
        crypto::IdCert,
        eventsourcing::StoredEvent,
    },
    daemon::ca::{self, CaEvt, CaEvtDet, PreparedRta, RouteAuthorization, SignedRta},
    upgrades::UpgradeError,
};

use super::*;

pub type OldEvt = StoredEvent<OldEvtDet>;

impl OldEvt {
    pub fn into_stored_ca_event(self, version: u64) -> Result<CaEvt, UpgradeError> {
        let (id, _, details) = self.unpack();
        Ok(CaEvt::new(&id, version, details.try_into()?))
    }

    pub fn needs_migration(&self) -> bool {
        !matches!(self.details(), OldEvtDet::ObjectSetUpdated(_, _))
    }
}

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

impl TryFrom<OldEvtDet> for CaEvtDet {
    type Error = UpgradeError;

    fn try_from(old: OldEvtDet) -> Result<Self, Self::Error> {
        let evt = match old {
            OldEvtDet::TrustAnchorMade(ta_cert_details) => CaEvtDet::TrustAnchorMade { ta_cert_details },
            OldEvtDet::ChildAdded(child, details) => CaEvtDet::ChildAdded {
                child,
                id_cert: details.id_cert,
                resources: details.resources,
            },
            OldEvtDet::ChildCertificateIssued(child, resource_class_name, ki) => CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            },
            OldEvtDet::ChildKeyRevoked(child, resource_class_name, ki) => CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            },
            OldEvtDet::ChildCertificatesUpdated(resource_class_name, cert_updates) => {
                CaEvtDet::ChildCertificatesUpdated {
                    resource_class_name,
                    updates: cert_updates.into(),
                }
            }
            OldEvtDet::ChildUpdatedIdCert(child, id_cert) => CaEvtDet::ChildUpdatedIdCert { child, id_cert },
            OldEvtDet::ChildUpdatedResources(child, resources) => CaEvtDet::ChildUpdatedResources { child, resources },
            OldEvtDet::ChildRemoved(child) => CaEvtDet::ChildRemoved { child },

            OldEvtDet::IdUpdated(id) => CaEvtDet::IdUpdated { id: id.into() },
            OldEvtDet::ParentAdded(parent, contact) => CaEvtDet::ParentAdded {
                parent,
                contact: contact.into(),
            },
            OldEvtDet::ParentUpdated(parent, contact) => CaEvtDet::ParentUpdated {
                parent,
                contact: contact.into(),
            },
            OldEvtDet::ParentRemoved(parent, _delta) => CaEvtDet::ParentRemoved { parent },

            OldEvtDet::ResourceClassAdded(_rcn, rc) => rc.into_added_event()?,
            OldEvtDet::ResourceClassRemoved(resource_class_name, _delta, parent, revoke_reqs) => {
                CaEvtDet::ResourceClassRemoved {
                    resource_class_name,
                    parent,
                    revoke_reqs,
                }
            }
            OldEvtDet::CertificateRequested(resource_class_name, req, ki) => CaEvtDet::CertificateRequested {
                resource_class_name,
                req,
                ki,
            },
            OldEvtDet::CertificateReceived(resource_class_name, ki, rcvd_cert) => CaEvtDet::CertificateReceived {
                resource_class_name,
                ki,
                rcvd_cert,
            },

            OldEvtDet::KeyRollPendingKeyAdded(resource_class_name, pending_key) => CaEvtDet::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key,
            },
            OldEvtDet::KeyPendingToNew(resource_class_name, new_key, _delta) => CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key: new_key.into(),
            },
            OldEvtDet::KeyPendingToActive(resource_class_name, current_key, _delta) => CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key: current_key.into(),
            },
            OldEvtDet::KeyRollActivated(resource_class_name, revoke_req) => CaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            },
            OldEvtDet::KeyRollFinished(resource_class_name, _delta) => {
                CaEvtDet::KeyRollFinished { resource_class_name }
            }
            OldEvtDet::UnexpectedKeyFound(resource_class_name, revoke_req) => CaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            },

            OldEvtDet::RouteAuthorizationAdded(auth) => CaEvtDet::RouteAuthorizationAdded { auth },
            OldEvtDet::RouteAuthorizationRemoved(auth) => CaEvtDet::RouteAuthorizationRemoved { auth },
            OldEvtDet::RoasUpdated(resource_class_name, updates) => CaEvtDet::RoasUpdated {
                resource_class_name,
                updates: updates.try_into()?,
            },

            OldEvtDet::ObjectSetUpdated(_, _) => unimplemented!("This event must not be migrated"),

            OldEvtDet::RepoUpdated(contact) => CaEvtDet::RepoUpdated {
                contact: contact.into(),
            },
            OldEvtDet::RepoCleaned(contact) => CaEvtDet::RepoCleaned {
                contact: contact.into(),
            },

            OldEvtDet::RtaPrepared(name, prepared) => CaEvtDet::RtaPrepared { name, prepared },
            OldEvtDet::RtaSigned(name, rta) => CaEvtDet::RtaSigned { name, rta },
        };
        Ok(evt)
    }
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

impl From<ChildCertificateUpdates> for ca::ChildCertificateUpdates {
    fn from(old: ChildCertificateUpdates) -> Self {
        ca::ChildCertificateUpdates::new(old.issued, old.removed)
    }
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

impl TryFrom<RoaUpdates> for ca::RoaUpdates {
    type Error = UpgradeError;

    fn try_from(old: RoaUpdates) -> Result<Self, UpgradeError> {
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
    pub object: CurrentObject,        // actual ROA
    name: ObjectName,                 // Name for object in repo
    since: Time,                      // first ROA in RC created
    replaces: Option<ReplacedObject>, // for revoking when re-newing
}

impl RoaInfo {
    pub fn roa(&self) -> Result<Roa, UpgradeError> {
        Roa::decode(self.object.content.to_bytes(), true).map_err(|_| UpgradeError::custom("Cannot parse existing ROA"))
    }
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
