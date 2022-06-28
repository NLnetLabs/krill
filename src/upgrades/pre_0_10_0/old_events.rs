use std::{collections::HashMap, fmt};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{self, ChildHandle, ParentHandle, PublisherHandle, RepoInfo, ServiceUri},
        provisioning::{
            IssuanceRequest, ParentResourceClassName, RequestResourceLimit, ResourceClassName, RevocationRequest,
        },
    },
    crypto::KeyIdentifier,
    repository::{aspa::Aspa, resources::ResourceSet, x509::Time, Cert, Roa},
    uri,
};

use crate::{
    commons::{
        api::{
            AspaCustomer, AspaDefinition, AspaProvidersUpdate, BgpSecAsnKey, IdCertInfo, RevokedObject,
            RoaAggregateKey, RtaName, TrustAnchorLocator,
        },
        eventsourcing::StoredEvent,
    },
    daemon::ca::{
        self, BgpSecCertificateUpdates, PreparedRta, Rfc8183Id, RouteAuthorization, SignedRta, StoredBgpSecCsr,
    },
    pubd::{Publisher, RepositoryAccessEvent, RepositoryAccessEventDetails, RepositoryAccessInitDetails},
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
    tal: TrustAnchorLocator,
}

impl OldTaCertDetails {
    pub fn new(cert: Cert, resources: ResourceSet, tal: TrustAnchorLocator) -> Self {
        OldTaCertDetails { cert, resources, tal }
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
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

//------------ OldParentCaContact -----------------------------------------------

/// This type contains the information needed to contact the parent ca
/// for resource provisioning requests (RFC6492).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum OldParentCaContact {
    Ta(OldTaCertDetails),
    Rfc6492(idexchange::ParentResponse),
}

//------------ OldRepositoryContact ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub struct OldRepositoryContact {
    repository_response: idexchange::RepositoryResponse,
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
    removed: HashMap<RouteAuthorization, RevokedObject>,

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
    aggregate_removed: HashMap<RoaAggregateKey, RevokedObject>,
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
        removed: RevokedObject,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        auth: &'a RouteAuthorization,
        removed: &'a RevokedObject,
    }

    pub fn serialize<S>(map: &HashMap<RouteAuthorization, RevokedObject>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(auth, removed)| ItemRef { auth, removed }).collect();
        sorted_vec.sort_by_key(|el| el.auth);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RouteAuthorization, RevokedObject>, D::Error>
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
        removed: RevokedObject,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        agg: &'a RoaAggregateKey,
        removed: &'a RevokedObject,
    }

    pub fn serialize<S>(map: &HashMap<RoaAggregateKey, RevokedObject>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(agg, removed)| ItemRef { agg, removed }).collect();
        sorted_vec.sort_by_key(|el| el.agg);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RoaAggregateKey, RevokedObject>, D::Error>
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

//------------ OldAspaObjectsUpdates ------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldAspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<OldAspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<AspaCustomer>,
}

//------------ OldRepositoryResponse --------------------------------------------

/// pre rpki-0.15.0 <repository_response/>
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldRepositoryResponse {
    /// The Publication Server Identity Certificate
    id_cert: IdCertInfo,

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
        id_cert: IdCertInfo,
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
        id_cert: IdCertInfo,
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

    // BGPSec
    BgpSecDefinitionAdded {
        key: BgpSecAsnKey,
        csr: StoredBgpSecCsr,
    },
    BgpSecDefinitionUpdated {
        key: BgpSecAsnKey,
        csr: StoredBgpSecCsr,
    },
    BgpSecDefinitionRemoved {
        key: BgpSecAsnKey,
    },
    BgpSecCertificatesUpdated {
        // Tracks the actual BGPSec certificates (re-)issued in a resource class
        resource_class_name: ResourceClassName,
        updates: BgpSecCertificateUpdates,
    },

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
