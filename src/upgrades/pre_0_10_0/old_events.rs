use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt,
};

use bytes::Bytes;
use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle, RepoInfo, ServiceUri},
        provisioning::{
            IssuanceRequest, ParentResourceClassName, RequestResourceLimit, ResourceClassName, RevocationRequest,
        },
        publication::Base64,
    },
    crypto::KeyIdentifier,
    repository::{aspa::Aspa, resources::ResourceSet, x509::Time, Cert, Crl, Manifest, Roa},
    rrdp, uri,
};

use crate::{
    commons::{
        api::{
            AspaCustomer, AspaDefinition, AspaProvidersUpdate, CertInfo, DelegatedCertificate, ObjectName,
            ParentCaContact, ParentServerInfo, PublicationServerInfo, ReceivedCert, RepositoryContact, Revocation,
            Revocations, RoaAggregateKey, RtaName, SuspendedCert, TaCertDetails, TrustAnchorLocator, UnsuspendedCert,
        },
        eventsourcing::StoredEvent,
        util::ext_serde,
    },
    daemon::ca::{
        self, AspaInfo, AspaObjectsUpdates, CaEvt, CaEvtDet, CaObjects, CertifiedKey, ChildCertificateUpdates,
        ObjectSetRevision, PreparedRta, PublishedObject, RoaInfo, RoaUpdates, RouteAuthorization, SignedRta,
    },
    pubd::{Publisher, RepositoryAccessEvent, RepositoryAccessEventDetails, RepositoryAccessInitDetails},
    upgrades::PrepareUpgradeError,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRfc8183Id {
    cert: IdCert,
}

impl From<OldRfc8183Id> for ca::Rfc8183Id {
    fn from(old: OldRfc8183Id) -> Self {
        ca::Rfc8183Id::new(old.cert.into())
    }
}

//------------ OldTaCertDetails -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldTaCertDetails {
    cert: Cert,
    resources: ResourceSet,
    tal: OldTrustAnchorLocator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldTrustAnchorLocator {
    uris: Vec<uri::Https>,
    rsync_uri: Option<uri::Rsync>,
    #[serde(deserialize_with = "ext_serde::de_bytes", serialize_with = "ext_serde::ser_bytes")]
    encoded_ski: Bytes,
}

impl TryFrom<OldTaCertDetails> for TaCertDetails {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldTaCertDetails) -> Result<Self, Self::Error> {
        let cert = old.cert;
        let resources = old.resources;
        let tal = old.tal;

        let rsync_uri = match tal.rsync_uri {
            Some(uri) => uri,
            None => {
                // Early krill testbeds did not have a usable rsync URI for the TA certificate
                // That said, we can kind of make one up because this is only used in a test
                // context anyhow. And otherwise we would not be able to upgrade.

                // So, we will just take the
                cert.rpki_manifest()
                    .ok_or_else(|| {
                        PrepareUpgradeError::custom(
                            "Cannot migrate TA, rsync URI is missing and TA cert does not have a manifest URI?!",
                        )
                    })?
                    .parent()
                    .unwrap()
                    .join(b"ta.cer")
                    .unwrap()
            }
        };
        let limit = RequestResourceLimit::default();

        let public_key = cert.subject_public_key_info().clone();
        let rvcd_cert = ReceivedCert::create(cert, rsync_uri.clone(), resources, limit)
            .map_err(|e| PrepareUpgradeError::Custom(format!("Could not convert old TA details: {}", e)))?;

        let tal = TrustAnchorLocator::new(tal.uris, rsync_uri, &public_key);

        Ok(TaCertDetails::new(rvcd_cert, tal))
    }
}

impl PartialEq for OldTaCertDetails {
    fn eq(&self, other: &Self) -> bool {
        self.tal == other.tal
            && self.resources == other.resources
            && self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for OldTaCertDetails {}

//------------ OldChildCertificateUpdates -------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldChildCertificateUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    issued: Vec<OldDelegatedCertificate>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<KeyIdentifier>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    suspended: Vec<OldSuspendedCert>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    unsuspended: Vec<OldUnsuspendedCert>,
}

impl TryFrom<OldChildCertificateUpdates> for ChildCertificateUpdates {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldChildCertificateUpdates) -> Result<Self, PrepareUpgradeError> {
        let mut issued: Vec<DelegatedCertificate> = vec![];
        let mut suspended: Vec<SuspendedCert> = vec![];
        let mut unsuspended: Vec<UnsuspendedCert> = vec![];

        for old_delegated in old.issued.into_iter() {
            issued.push(old_delegated.try_into()?);
        }

        for old_suspended in old.suspended.into_iter() {
            suspended.push(old_suspended.try_into()?);
        }

        for old_unsuspended in old.unsuspended.into_iter() {
            unsuspended.push(old_unsuspended.try_into()?);
        }

        Ok(ChildCertificateUpdates::new(
            issued,
            old.removed,
            suspended,
            unsuspended,
        ))
    }
}

//------------ OldDelegatedCertificate ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldDelegatedCertificate {
    uri: uri::Rsync,             // where this cert is published
    limit: RequestResourceLimit, // the limit on the request
    resource_set: ResourceSet,
    cert: Cert,
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

pub type OldSuspendedCert = OldDelegatedCertificate;
pub type OldUnsuspendedCert = OldDelegatedCertificate;

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

//------------ OldCertifiedKey --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct OldCertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: OldRcvdCert,
    request: Option<IssuanceRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepoInfo>,
}

impl TryFrom<OldCertifiedKey> for CertifiedKey {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCertifiedKey) -> Result<Self, Self::Error> {
        Ok(CertifiedKey::new(
            old.key_id,
            old.incoming_cert.try_into()?,
            old.request,
            old.old_repo,
        ))
    }
}

//------------ OldParentCaContact -----------------------------------------------

/// This type contains the information needed to contact the parent ca
/// for resource provisioning requests (RFC6492).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum OldParentCaContact {
    Ta(OldTaCertDetails),
    Rfc6492(OldParentResponse),
}

impl TryFrom<OldParentCaContact> for ParentCaContact {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldParentCaContact) -> Result<Self, Self::Error> {
        Ok(match old {
            OldParentCaContact::Ta(old) => ParentCaContact::Ta(old.try_into()?),
            OldParentCaContact::Rfc6492(old) => ParentCaContact::Rfc6492(old.into()),
        })
    }
}

//------------ OldParentResponse ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldParentResponse {
    /// The parent CA's IdCert
    id_cert: IdCert,

    /// The handle of the parent CA.
    parent_handle: ParentHandle,

    /// The handle chosen for the child CA. Note that this may not be the
    /// same as the handle the CA asked for.
    child_handle: ChildHandle,

    /// The URI where the CA needs to send its RFC6492 messages
    service_uri: ServiceUri,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

impl From<OldParentResponse> for ParentServerInfo {
    fn from(old: OldParentResponse) -> Self {
        ParentServerInfo::new(
            old.service_uri,
            old.id_cert.public_key().clone(),
            old.parent_handle,
            old.child_handle,
        )
    }
}

//------------ OldRepositoryContact ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub struct OldRepositoryContact {
    repository_response: OldRepositoryResponse,
}

impl From<OldRepositoryContact> for RepositoryContact {
    fn from(old: OldRepositoryContact) -> Self {
        let repo_info = old.repository_response.repo_info;
        let public_key = old.repository_response.id_cert.public_key().clone();
        let service_uri = old.repository_response.service_uri;

        RepositoryContact::new(repo_info, PublicationServerInfo::new(public_key, service_uri))
    }
}

//------------ OldRoaInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRoaInfo {
    roa: Roa,
    since: Time, // first ROA in RC created
}

impl PartialEq for OldRoaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.roa.to_captured().as_slice() == other.roa.to_captured().as_slice()
    }
}

impl Eq for OldRoaInfo {}

//------------ OldAggregateRoaInfo --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldAggregateRoaInfo {
    authorizations: Vec<RouteAuthorization>,

    #[serde(flatten)]
    roa: OldRoaInfo,
}

impl From<OldAggregateRoaInfo> for RoaInfo {
    fn from(old: OldAggregateRoaInfo) -> Self {
        RoaInfo::new(old.authorizations, old.roa.roa)
    }
}

//------------ OldRoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRoaUpdates {
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new",
        with = "updated_sorted_map"
    )]
    updated: HashMap<RouteAuthorization, OldRoaInfo>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new",
        with = "removed_sorted_map"
    )]
    removed: HashMap<RouteAuthorization, OldRevokedObject>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new",
        with = "aggregate_updated_sorted_map"
    )]
    aggregate_updated: HashMap<RoaAggregateKey, OldAggregateRoaInfo>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new",
        with = "aggregate_removed_sorted_map"
    )]
    aggregate_removed: HashMap<RoaAggregateKey, OldRevokedObject>,
}

impl From<OldRoaUpdates> for RoaUpdates {
    fn from(old: OldRoaUpdates) -> Self {
        let updated: HashMap<RouteAuthorization, RoaInfo> = old
            .updated
            .into_iter()
            .map(|(auth, old_info)| (auth, RoaInfo::new(vec![auth], old_info.roa)))
            .collect();

        let aggregate_updated: HashMap<RoaAggregateKey, RoaInfo> = old
            .aggregate_updated
            .into_iter()
            .map(|(auth, old_info)| (auth, old_info.into()))
            .collect();

        let removed = old.removed.into_keys().collect();
        let aggregate_removed = old.aggregate_removed.into_keys().collect();

        RoaUpdates::new(updated, removed, aggregate_updated, aggregate_removed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRevokedObject {
    revocation: Revocation,
    hash: rrdp::Hash,
}

mod updated_sorted_map {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct Item {
        auth: RouteAuthorization,
        roa: OldRoaInfo,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        auth: &'a RouteAuthorization,
        roa: &'a OldRoaInfo,
    }

    pub fn serialize<S>(map: &HashMap<RouteAuthorization, OldRoaInfo>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(auth, roa)| ItemRef { auth, roa }).collect();
        sorted_vec.sort_by_key(|el| el.auth);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RouteAuthorization, OldRoaInfo>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<Item>::deserialize(deserializer)? {
            map.insert(item.auth, item.roa);
        }
        Ok(map)
    }
}

mod aggregate_updated_sorted_map {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct Item {
        agg: RoaAggregateKey,
        roa: OldAggregateRoaInfo,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        agg: &'a RoaAggregateKey,
        roa: &'a OldAggregateRoaInfo,
    }

    pub fn serialize<S>(map: &HashMap<RoaAggregateKey, OldAggregateRoaInfo>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(agg, roa)| ItemRef { agg, roa }).collect();
        sorted_vec.sort_by_key(|el| el.agg);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RoaAggregateKey, OldAggregateRoaInfo>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<Item>::deserialize(deserializer)? {
            map.insert(item.agg, item.roa);
        }
        Ok(map)
    }
}

mod removed_sorted_map {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct Item {
        auth: RouteAuthorization,
        removed: OldRevokedObject,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        auth: &'a RouteAuthorization,
        removed: &'a OldRevokedObject,
    }

    pub fn serialize<S>(map: &HashMap<RouteAuthorization, OldRevokedObject>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(auth, removed)| ItemRef { auth, removed }).collect();
        sorted_vec.sort_by_key(|el| el.auth);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RouteAuthorization, OldRevokedObject>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<Item>::deserialize(deserializer)? {
            map.insert(item.auth, item.removed);
        }
        Ok(map)
    }
}

mod aggregate_removed_sorted_map {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct Item {
        agg: RoaAggregateKey,
        removed: OldRevokedObject,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        agg: &'a RoaAggregateKey,
        removed: &'a OldRevokedObject,
    }

    pub fn serialize<S>(map: &HashMap<RoaAggregateKey, OldRevokedObject>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(agg, removed)| ItemRef { agg, removed }).collect();
        sorted_vec.sort_by_key(|el| el.agg);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RoaAggregateKey, OldRevokedObject>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<Item>::deserialize(deserializer)? {
            map.insert(item.agg, item.removed);
        }
        Ok(map)
    }
}

//------------ OldAspaInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldAspaInfo {
    definition: AspaDefinition,
    aspa: Aspa,
    since: Time, // Creation time
}

impl PartialEq for OldAspaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.aspa.to_captured().as_slice() == other.aspa.to_captured().as_slice()
    }
}

impl Eq for OldAspaInfo {}

impl From<OldAspaInfo> for AspaInfo {
    fn from(old: OldAspaInfo) -> Self {
        AspaInfo::new(old.definition, old.aspa)
    }
}

//------------ OldAspaObjectsUpdates ------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldAspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<OldAspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<AspaCustomer>,
}

impl From<OldAspaObjectsUpdates> for AspaObjectsUpdates {
    fn from(old: OldAspaObjectsUpdates) -> Self {
        let updated = old.updated.into_iter().map(|old| old.into()).collect();
        AspaObjectsUpdates::new(updated, old.removed)
    }
}

//------------ OldRepositoryResponse --------------------------------------------

/// pre rpki-0.15.0 <repository_response/>
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldRepositoryResponse {
    /// The Publication Server Identity Certificate
    id_cert: IdCert,

    /// The name the publication server decided to call the CA by.
    /// Note that this may not be the same as the handle the CA asked for.
    publisher_handle: PublisherHandle,

    /// The URI where the CA needs to send its RFC8181 messages
    service_uri: ServiceUri,

    /// Contains the rsync base (sia_base) and optional RRDP (RFC8182)
    /// notification xml uri
    repo_info: RepoInfo,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

//------------ OldCaIni -----------------------------------------------------------

pub type OldCaIni = StoredEvent<OldCaIniDet>;

//------------ OldCaIniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCaIniDet {
    id: OldRfc8183Id,
}

impl From<OldCaIniDet> for ca::Rfc8183Id {
    fn from(old: OldCaIniDet) -> Self {
        old.id.into()
    }
}

impl fmt::Display for OldCaIniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized with ID key hash: {}",
            self.id.cert.public_key().key_identifier()
        )?;
        Ok(())
    }
}

//------------ OldEvt ---------------------------------------------------------

pub type OldCaEvt = StoredEvent<OldCaEvtDet>;

impl TryFrom<OldCaEvt> for CaEvt {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCaEvt) -> Result<Self, Self::Error> {
        let (id, version, details) = old.unpack();
        Ok(CaEvt::new(&id, version, details.try_into()?))
    }
}

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum OldCaEvtDet {
    // Being a Trust Anchor
    TrustAnchorMade {
        ta_cert_details: OldTaCertDetails,
    },

    // Being a parent Events
    /// A child was added to this (parent) CA
    ChildAdded {
        child: ChildHandle,
        id_cert: IdCert,
        resources: ResourceSet,
    },

    /// A certificate was issued to the child of this (parent) CA
    ChildCertificateIssued {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },

    /// A child key was revoked.
    ChildKeyRevoked {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },

    /// Child certificates (for potentially multiple children) were updated
    /// under a CA resource class. I.e. child certificates were issued,
    /// removed, or suspended.
    ChildCertificatesUpdated {
        resource_class_name: ResourceClassName,
        updates: OldChildCertificateUpdates,
    },
    ChildUpdatedIdCert {
        child: ChildHandle,
        id_cert: IdCert,
    },
    ChildUpdatedResources {
        child: ChildHandle,
        resources: ResourceSet,
    },
    ChildRemoved {
        child: ChildHandle,
    },

    // (Un)Suspend a child events
    ChildSuspended {
        child: ChildHandle,
    },
    ChildUnsuspended {
        child: ChildHandle,
    },

    // Being a child Events
    IdUpdated {
        id: OldRfc8183Id,
    },
    ParentAdded {
        parent: ParentHandle,
        contact: OldParentCaContact,
    },
    ParentUpdated {
        parent: ParentHandle,
        contact: OldParentCaContact,
    },
    ParentRemoved {
        parent: ParentHandle,
    },
    ResourceClassAdded {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        parent_resource_class_name: ParentResourceClassName,
        pending_key: KeyIdentifier,
    },
    ResourceClassRemoved {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        revoke_requests: Vec<RevocationRequest>,
    },
    CertificateRequested {
        resource_class_name: ResourceClassName,
        req: IssuanceRequest,
        ki: KeyIdentifier, // Also contained in request. Drop?
    },
    CertificateReceived {
        resource_class_name: ResourceClassName,
        rcvd_cert: OldRcvdCert,
        ki: KeyIdentifier, // Also in received cert. Drop?
    },

    // Key life cycle
    KeyRollPendingKeyAdded {
        // A pending key is added to an existing resource class in order to initiate
        // a key roll. Note that there will be a separate 'CertificateRequested' event for
        // this key.
        resource_class_name: ResourceClassName,
        pending_key_id: KeyIdentifier,
    },
    KeyPendingToNew {
        // A pending key is marked as 'new' when it has received its (first) certificate.
        // This means that the key is staged and a mft and crl will be published. According
        // to RFC 6489 this key should be staged for 24 hours before it is promoted to
        // become the active key. However, in practice this time can be shortened.
        resource_class_name: ResourceClassName,
        new_key: OldCertifiedKey, // pending key which received a certificate becomes 'new', i.e. it is staged.
    },
    KeyPendingToActive {
        // When a new resource class is created it will have a single pending key only which
        // is promoted to become the active (current) key for the resource class immediately
        // after receiving its first certificate. Technically this is not a roll, but a simple
        // first activation.
        resource_class_name: ResourceClassName,
        current_key: OldCertifiedKey, // there was no current key, pending becomes active without staging when cert is received.
    },
    KeyRollActivated {
        // When a 'new' key is activated (becomes current), the previous current key will be
        // marked as old and we will request its revocation. Note that any current ROAs and/or
        // delegated certificates will also be re-issued under the new 'current' key. These changes
        // are tracked in separate `RoasUpdated` and `ChildCertificatesUpdated` events.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },
    KeyRollFinished {
        // The key roll is finished when the parent confirms that the old key is revoked.
        // We can remove it and stop publishing its mft and crl.
        resource_class_name: ResourceClassName,
    },
    UnexpectedKeyFound {
        // This event is generated in case our parent reports keys to us that we do not
        // believe we have. This should not happen in practice, but this is tracked so that
        // we can recover from this situation. We can request revocation for all these keys
        // and create new keys in the RC as needed.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },

    // Route Authorizations
    RouteAuthorizationAdded {
        // Tracks a single authorization (VRP) which is added. Note that (1) a command to
        // update ROAs can contain multiple changes in which case multiple events will
        // result, and (2) we do not have a 'modify' event. Modifications of e.g. the
        // max length are expressed as a 'removed' and 'added' event in a single transaction.
        auth: ca::RouteAuthorization,
    },
    RouteAuthorizationRemoved {
        // Tracks a single authorization (VRP) which is removed. See remark for RouteAuthorizationAdded.
        auth: ca::RouteAuthorization,
    },
    RoasUpdated {
        // Tracks ROA *objects* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: OldRoaUpdates,
    },

    // ASPA
    AspaConfigAdded {
        aspa_config: AspaDefinition,
    },
    AspaConfigUpdated {
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
    },
    AspaConfigRemoved {
        customer: AspaCustomer,
    },
    AspaObjectsUpdated {
        // Tracks ASPA *object* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: OldAspaObjectsUpdates,
    },

    // BGPSec - not present before 0.10.0

    // Publishing
    RepoUpdated {
        // Adds the repository contact for this CA so that publication can commence,
        // and certificates can be requested from parents. Note: the CA can only start
        // requesting certificates when it knows which URIs it can use.
        contact: OldRepositoryContact,
    },

    // Rta
    //
    // NOTE RTA support is still experimental and incomplete.
    RtaSigned {
        // Adds a signed RTA. The RTA can be single signed, or it can
        // be a multi-signed RTA based on an existing 'PreparedRta'.
        name: RtaName,
        rta: SignedRta,
    },
    RtaPrepared {
        // Adds a 'prepared' RTA. I.e. the context of keys which need to be included
        // in a multi-signed RTA.
        name: RtaName,
        prepared: PreparedRta,
    },
}

impl TryFrom<OldCaEvtDet> for CaEvtDet {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCaEvtDet) -> Result<Self, Self::Error> {
        Ok(match old {
            OldCaEvtDet::TrustAnchorMade { ta_cert_details } => CaEvtDet::TrustAnchorMade {
                ta_cert_details: ta_cert_details.try_into()?,
            },
            OldCaEvtDet::ChildAdded {
                child,
                id_cert,
                resources,
            } => CaEvtDet::ChildAdded {
                child,
                id_cert: id_cert.into(),
                resources,
            },
            OldCaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            },
            OldCaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            },
            OldCaEvtDet::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            } => CaEvtDet::ChildCertificatesUpdated {
                resource_class_name,
                updates: updates.try_into()?,
            },
            OldCaEvtDet::ChildUpdatedIdCert { child, id_cert } => CaEvtDet::ChildUpdatedIdCert {
                child,
                id_cert: id_cert.into(),
            },
            OldCaEvtDet::ChildUpdatedResources { child, resources } => {
                CaEvtDet::ChildUpdatedResources { child, resources }
            }
            OldCaEvtDet::ChildRemoved { child } => CaEvtDet::ChildRemoved { child },
            OldCaEvtDet::ChildSuspended { child } => CaEvtDet::ChildSuspended { child },
            OldCaEvtDet::ChildUnsuspended { child } => CaEvtDet::ChildUnsuspended { child },
            OldCaEvtDet::IdUpdated { id } => CaEvtDet::IdUpdated { id: id.into() },
            OldCaEvtDet::ParentAdded { parent, contact } => CaEvtDet::ParentAdded {
                parent,
                contact: contact.try_into()?,
            },
            OldCaEvtDet::ParentUpdated { parent, contact } => CaEvtDet::ParentUpdated {
                parent,
                contact: contact.try_into()?,
            },
            OldCaEvtDet::ParentRemoved { parent } => CaEvtDet::ParentRemoved { parent },
            OldCaEvtDet::ResourceClassAdded {
                resource_class_name,
                parent,
                parent_resource_class_name,
                pending_key,
            } => CaEvtDet::ResourceClassAdded {
                resource_class_name,
                parent,
                parent_resource_class_name,
                pending_key,
            },
            OldCaEvtDet::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_requests,
            } => CaEvtDet::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_requests,
            },
            OldCaEvtDet::CertificateRequested {
                resource_class_name,
                req,
                ki,
            } => CaEvtDet::CertificateRequested {
                resource_class_name,
                req,
                ki,
            },
            OldCaEvtDet::CertificateReceived {
                resource_class_name,
                rcvd_cert,
                ki,
            } => CaEvtDet::CertificateReceived {
                resource_class_name,
                rcvd_cert: rcvd_cert.try_into()?,
                ki,
            },
            OldCaEvtDet::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            } => CaEvtDet::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            },
            OldCaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key: new_key.try_into()?,
            },
            OldCaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key: current_key.try_into()?,
            },
            OldCaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => CaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            },
            OldCaEvtDet::KeyRollFinished { resource_class_name } => CaEvtDet::KeyRollFinished { resource_class_name },
            OldCaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => CaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            },
            OldCaEvtDet::RouteAuthorizationAdded { auth } => CaEvtDet::RouteAuthorizationAdded { auth },
            OldCaEvtDet::RouteAuthorizationRemoved { auth } => CaEvtDet::RouteAuthorizationRemoved { auth },
            OldCaEvtDet::RoasUpdated {
                resource_class_name,
                updates,
            } => CaEvtDet::RoasUpdated {
                resource_class_name,
                updates: updates.into(),
            },
            OldCaEvtDet::AspaConfigAdded { aspa_config } => CaEvtDet::AspaConfigAdded { aspa_config },
            OldCaEvtDet::AspaConfigUpdated { customer, update } => CaEvtDet::AspaConfigUpdated { customer, update },
            OldCaEvtDet::AspaConfigRemoved { customer } => CaEvtDet::AspaConfigRemoved { customer },
            OldCaEvtDet::AspaObjectsUpdated {
                resource_class_name,
                updates,
            } => CaEvtDet::AspaObjectsUpdated {
                resource_class_name,
                updates: updates.into(),
            },
            OldCaEvtDet::RepoUpdated { contact } => CaEvtDet::RepoUpdated {
                contact: contact.into(),
            },
            OldCaEvtDet::RtaSigned { name, rta } => CaEvtDet::RtaSigned { name, rta },
            OldCaEvtDet::RtaPrepared { name, prepared } => CaEvtDet::RtaPrepared { name, prepared },
        })
    }
}

impl fmt::Display for OldCaEvtDet {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!("not used for migration")
    }
}

//-------------------------------------------------------------------------------
//------------------------- CaObjects -------------------------------------------
//-------------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCaObjects {
    ca: CaHandle,
    repo: Option<OldRepositoryContact>,

    #[serde(with = "old_ca_objects_classes_serde")]
    classes: HashMap<ResourceClassName, OldResourceClassObjects>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    deprecated_repos: Vec<OldDeprecatedRepository>,
}

impl TryFrom<OldCaObjects> for ca::CaObjects {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCaObjects) -> Result<Self, Self::Error> {
        let ca = old.ca;

        let repo = old.repo.map(|contact| contact.into());

        let mut classes: HashMap<ResourceClassName, ca::ResourceClassObjects> = HashMap::new();
        for (rcn, old_objects) in old.classes.into_iter() {
            classes.insert(rcn, old_objects.try_into()?);
        }

        let deprecated_repos = old
            .deprecated_repos
            .into_iter()
            .map(|deprecated| deprecated.into())
            .collect();

        Ok(CaObjects::new(ca, repo, classes, deprecated_repos))
    }
}

mod old_ca_objects_classes_serde {

    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct ClassesItem {
        class_name: ResourceClassName,
        objects: OldResourceClassObjects,
    }

    #[derive(Debug, Serialize)]
    struct ClassesItemRef<'a> {
        class_name: &'a ResourceClassName,
        objects: &'a OldResourceClassObjects,
    }

    pub fn serialize<S>(
        map: &HashMap<ResourceClassName, OldResourceClassObjects>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(
            map.iter()
                .map(|(class_name, objects)| ClassesItemRef { class_name, objects }),
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ResourceClassName, OldResourceClassObjects>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<ClassesItem>::deserialize(deserializer)? {
            map.insert(item.class_name, item.objects);
        }
        Ok(map)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldDeprecatedRepository {
    contact: OldRepositoryContact,
    clean_attempts: usize,
}

impl From<OldDeprecatedRepository> for ca::DeprecatedRepository {
    fn from(old: OldDeprecatedRepository) -> Self {
        ca::DeprecatedRepository::new(old.contact.into(), old.clean_attempts)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldResourceClassObjects {
    keys: OldResourceClassKeyState,
}

impl TryFrom<OldResourceClassObjects> for ca::ResourceClassObjects {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldResourceClassObjects) -> Result<Self, Self::Error> {
        old.keys.try_into().map(|keys| ca::ResourceClassObjects::new(keys))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OldResourceClassKeyState {
    Current(OldCurrentKeyState),
    Staging(OldStagingKeyState),
    Old(OldOldKeyState),
}

impl TryFrom<OldResourceClassKeyState> for ca::ResourceClassKeyState {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldResourceClassKeyState) -> Result<Self, Self::Error> {
        Ok(match old {
            OldResourceClassKeyState::Current(state) => ca::ResourceClassKeyState::Current(state.try_into()?),
            OldResourceClassKeyState::Staging(state) => ca::ResourceClassKeyState::Staging(state.try_into()?),
            OldResourceClassKeyState::Old(state) => ca::ResourceClassKeyState::Old(state.try_into()?),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCurrentKeyState {
    current_set: OldCurrentKeyObjectSet,
}

impl TryFrom<OldCurrentKeyState> for ca::CurrentKeyState {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCurrentKeyState) -> Result<Self, Self::Error> {
        Ok(ca::CurrentKeyState::new(old.current_set.try_into()?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStagingKeyState {
    staging_set: OldBasicKeyObjectSet,
    current_set: OldCurrentKeyObjectSet,
}

impl TryFrom<OldStagingKeyState> for ca::StagingKeyState {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldStagingKeyState) -> Result<Self, Self::Error> {
        Ok(ca::StagingKeyState::new(
            old.staging_set.try_into()?,
            old.current_set.try_into()?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldOldKeyState {
    current_set: OldCurrentKeyObjectSet,
    old_set: OldBasicKeyObjectSet,
}

impl TryFrom<OldOldKeyState> for ca::OldKeyState {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldOldKeyState) -> Result<Self, Self::Error> {
        Ok(ca::OldKeyState::new(
            old.current_set.try_into()?,
            old.old_set.try_into()?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCurrentKeyObjectSet {
    #[serde(flatten)]
    basic: OldBasicKeyObjectSet,

    #[serde(with = "objects_to_roas_serde")]
    roas: HashMap<ObjectName, OldPublishedRoa>,

    #[serde(with = "objects_to_aspas_serde", skip_serializing_if = "HashMap::is_empty", default)]
    aspas: HashMap<ObjectName, OldPublishedAspa>,

    #[serde(with = "objects_to_certs_serde")]
    certs: HashMap<ObjectName, OldPublishedCert>,
}

impl TryFrom<OldCurrentKeyObjectSet> for ca::CurrentKeyObjectSet {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldCurrentKeyObjectSet) -> Result<Self, Self::Error> {
        let basic = old.basic.try_into()?;

        let mut published_objects = HashMap::new();
        for (name, old_roa) in old.roas.into_iter() {
            let base64 = Base64::from(&old_roa.0);
            let serial = old_roa.0.cert().serial_number();
            let expires = old_roa.0.cert().validity().not_after();
            let published_object = PublishedObject::new(name.clone(), base64, serial, expires);
            published_objects.insert(name, published_object);
        }

        for (name, old_aspa) in old.aspas.into_iter() {
            let base64 = Base64::from(&old_aspa.0);
            let serial = old_aspa.0.cert().serial_number();
            let expires = old_aspa.0.cert().validity().not_after();
            let published_object = PublishedObject::new(name.clone(), base64, serial, expires);
            published_objects.insert(name, published_object);
        }

        for (name, old_cert) in old.certs.into_iter() {
            let base64 = Base64::from(&old_cert.cert);
            let serial = old_cert.cert.serial_number();
            let expires = old_cert.cert.validity().not_after();
            let published_object = PublishedObject::new(name.clone(), base64, serial, expires);
            published_objects.insert(name, published_object);
        }

        Ok(ca::CurrentKeyObjectSet::new(basic, published_objects))
    }
}

mod objects_to_roas_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameRoaItem {
        name: ObjectName,
        roa: OldPublishedRoa,
    }

    #[derive(Debug, Serialize)]
    struct NameRoaItemRef<'a> {
        name: &'a ObjectName,
        roa: &'a OldPublishedRoa,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, OldPublishedRoa>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, roa)| NameRoaItemRef { name, roa }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, OldPublishedRoa>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameRoaItem>::deserialize(deserializer)? {
            map.insert(item.name, item.roa);
        }
        Ok(map)
    }
}

mod objects_to_aspas_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameItem {
        name: ObjectName,
        aspa: OldPublishedAspa,
    }

    #[derive(Debug, Serialize)]
    struct NameItemRef<'a> {
        name: &'a ObjectName,
        aspa: &'a OldPublishedAspa,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, OldPublishedAspa>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, aspa)| NameItemRef { name, aspa }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, OldPublishedAspa>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameItem>::deserialize(deserializer)? {
            map.insert(item.name, item.aspa);
        }
        Ok(map)
    }
}

mod objects_to_certs_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameCertItem {
        name: ObjectName,
        issued: OldPublishedCert,
    }

    #[derive(Debug, Serialize)]
    struct NameCertItemRef<'a> {
        name: &'a ObjectName,
        issued: &'a OldPublishedCert,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, OldPublishedCert>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, issued)| NameCertItemRef { name, issued }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, OldPublishedCert>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameCertItem>::deserialize(deserializer)? {
            map.insert(item.name, item.issued);
        }
        Ok(map)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldBasicKeyObjectSet {
    signing_cert: OldRcvdCert,
    number: u64,
    revocations: Revocations,
    manifest: OldPublishedManifest,
    crl: OldPublishedCrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<OldRepositoryContact>,
}

impl TryFrom<OldBasicKeyObjectSet> for ca::BasicKeyObjectSet {
    type Error = PrepareUpgradeError;

    fn try_from(old: OldBasicKeyObjectSet) -> Result<Self, Self::Error> {
        let signing_cert = old.signing_cert.try_into()?;

        let number = old.number;
        let this_update = old.manifest.this_update();
        let next_update = old.manifest.next_update();

        let revision = ObjectSetRevision::new(number, this_update, next_update);

        let revocations = old.revocations;
        let manifest = old.manifest.into();
        let crl = old.crl.into();
        let old_repo = old.old_repo.map(|repo| repo.into());

        Ok(ca::BasicKeyObjectSet::new(
            signing_cert,
            revision,
            revocations,
            manifest,
            crl,
            old_repo,
        ))
    }
}

//------------ PublishedCert -----------------------------------------------
pub type OldPublishedCert = OldDelegatedCertificate;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldPublishedRoa(Roa);

impl PartialEq for OldPublishedRoa {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_captured().into_bytes() == other.0.to_captured().into_bytes()
    }
}

impl Eq for OldPublishedRoa {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldPublishedAspa(Aspa);

impl PartialEq for OldPublishedAspa {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_captured().into_bytes() == other.0.to_captured().into_bytes()
    }
}

impl Eq for OldPublishedAspa {}

//------------ PublishedManifest ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldPublishedManifest(Manifest);

impl OldPublishedManifest {
    pub fn this_update(&self) -> Time {
        self.0.this_update()
    }

    pub fn next_update(&self) -> Time {
        self.0.next_update()
    }
}

impl From<OldPublishedManifest> for ca::PublishedManifest {
    fn from(old: OldPublishedManifest) -> Self {
        old.0.into()
    }
}

impl PartialEq for OldPublishedManifest {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_captured().into_bytes() == other.0.to_captured().into_bytes()
    }
}

impl Eq for OldPublishedManifest {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldPublishedCrl(Crl);

impl From<OldPublishedCrl> for ca::PublishedCrl {
    fn from(old: OldPublishedCrl) -> Self {
        old.0.into()
    }
}

impl PartialEq for OldPublishedCrl {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_captured().into_bytes() == other.0.to_captured().into_bytes()
    }
}

impl Eq for OldPublishedCrl {}

// Repository

//------------ OldRepositoryAccessIni -------------------------------------------

pub type OldRepositoryAccessIni = StoredEvent<OldRepositoryAccessInitDetails>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRepositoryAccessInitDetails {
    id_cert: IdCert,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl From<OldRepositoryAccessInitDetails> for RepositoryAccessInitDetails {
    fn from(old: OldRepositoryAccessInitDetails) -> Self {
        RepositoryAccessInitDetails::new(old.id_cert.into(), old.rrdp_base_uri, old.rsync_jail)
    }
}

impl fmt::Display for OldRepositoryAccessInitDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized publication server. RRDP base uri: {}, Rsync Jail: {}",
            self.rrdp_base_uri, self.rsync_jail
        )
    }
}

//------------ OldRepositoryAccessEvent -----------------------------------------

pub type OldRepositoryAccessEvent = StoredEvent<OldRepositoryAccessEventDetails>;

impl From<OldRepositoryAccessEvent> for RepositoryAccessEvent {
    fn from(old: OldRepositoryAccessEvent) -> Self {
        let (id, version, details) = old.unpack();
        RepositoryAccessEvent::new(&id, version, details.into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum OldRepositoryAccessEventDetails {
    PublisherAdded {
        name: PublisherHandle,
        publisher: OldPublisher,
    },
    PublisherRemoved {
        name: PublisherHandle,
    },
}

impl From<OldRepositoryAccessEventDetails> for RepositoryAccessEventDetails {
    fn from(old: OldRepositoryAccessEventDetails) -> Self {
        match old {
            OldRepositoryAccessEventDetails::PublisherAdded { name, publisher } => {
                RepositoryAccessEventDetails::PublisherAdded {
                    name,
                    publisher: publisher.into(),
                }
            }
            OldRepositoryAccessEventDetails::PublisherRemoved { name } => {
                RepositoryAccessEventDetails::PublisherRemoved { name }
            }
        }
    }
}

impl fmt::Display for OldRepositoryAccessEventDetails {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!("not used for migration")
    }
}

//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldPublisher {
    /// Used by remote RFC8181 publishers
    id_cert: IdCert,

    /// Publication jail for this publisher
    base_uri: uri::Rsync,
}

impl From<OldPublisher> for Publisher {
    fn from(old: OldPublisher) -> Self {
        Publisher::new(old.id_cert.into(), old.base_uri)
    }
}
