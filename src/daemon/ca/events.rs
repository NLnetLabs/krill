use std::{collections::HashMap, fmt};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{CaHandle, ChildHandle, ParentHandle},
        provisioning::{IssuanceRequest, ParentResourceClassName, ResourceClassName, RevocationRequest},
    },
    repository::{crypto::KeyIdentifier, resources::ResourceSet},
};

use crate::{
    commons::{
        api::{
            AspaCustomer, AspaDefinition, AspaProvidersUpdate, DelegatedCertificate, ObjectName, ParentCaContact,
            RcvdCert, RepositoryContact, RevokedObject, RoaAggregateKey, RtaName, SuspendedCert, TaCertDetails,
            UnsuspendedCert,
        },
        crypto::KrillSigner,
        eventsourcing::StoredEvent,
        KrillResult,
    },
    daemon::ca::{
        AggregateRoaInfo, AspaInfo, CertifiedKey, PreparedRta, PublishedRoa, Rfc8183Id, RoaInfo, RouteAuthorization,
        SignedRta,
    },
};

//------------ Ini -----------------------------------------------------------

pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IniDet {
    id: Rfc8183Id,
}

impl IniDet {
    pub fn unpack(self) -> Rfc8183Id {
        self.id
    }
}

impl IniDet {
    pub fn new(handle: &CaHandle, id: Rfc8183Id) -> Ini {
        Ini::new(handle, 0, IniDet { id })
    }

    pub fn init(handle: &CaHandle, signer: &KrillSigner) -> KrillResult<Ini> {
        let id = Rfc8183Id::generate(signer)?;
        Ok(Self::new(handle, id))
    }
}

impl fmt::Display for IniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Initialized with ID key hash: {}", self.id.key_id())?;
        Ok(())
    }
}

//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaUpdates {
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new",
        with = "updated_sorted_map"
    )]
    updated: HashMap<RouteAuthorization, RoaInfo>,

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
    aggregate_updated: HashMap<RoaAggregateKey, AggregateRoaInfo>,

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
        roa: RoaInfo,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        auth: &'a RouteAuthorization,
        roa: &'a RoaInfo,
    }

    pub fn serialize<S>(map: &HashMap<RouteAuthorization, RoaInfo>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(auth, roa)| ItemRef { auth, roa }).collect();
        sorted_vec.sort_by_key(|el| el.auth);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RouteAuthorization, RoaInfo>, D::Error>
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
        roa: AggregateRoaInfo,
    }

    #[derive(Debug, Serialize)]
    struct ItemRef<'a> {
        agg: &'a RoaAggregateKey,
        roa: &'a AggregateRoaInfo,
    }

    pub fn serialize<S>(map: &HashMap<RoaAggregateKey, AggregateRoaInfo>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sorted_vec: Vec<ItemRef> = map.iter().map(|(agg, roa)| ItemRef { agg, roa }).collect();
        sorted_vec.sort_by_key(|el| el.agg);

        serializer.collect_seq(sorted_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<RoaAggregateKey, AggregateRoaInfo>, D::Error>
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

impl RoaUpdates {
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty()
            && self.removed.is_empty()
            && self.aggregate_updated.is_empty()
            && self.aggregate_removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn update(&mut self, auth: RouteAuthorization, roa: RoaInfo) {
        self.updated.insert(auth, roa);
    }

    pub fn remove(&mut self, auth: RouteAuthorization, revoke: RevokedObject) {
        self.removed.insert(auth, revoke);
    }

    pub fn remove_aggregate(&mut self, key: RoaAggregateKey, revoke: RevokedObject) {
        self.aggregate_removed.insert(key, revoke);
    }

    pub fn update_aggregate(&mut self, key: RoaAggregateKey, aggregate: AggregateRoaInfo) {
        self.aggregate_updated.insert(key, aggregate);
    }

    pub fn added_roas(&self) -> KrillResult<HashMap<ObjectName, PublishedRoa>> {
        let mut res = HashMap::new();

        for (auth, simple) in &self.updated {
            let roa = simple.roa().clone();
            let name = ObjectName::from(auth);

            res.insert(name, PublishedRoa::new(roa));
        }

        for (agg_key, agg_info) in &self.aggregate_updated {
            let roa = agg_info.roa_info().roa().clone();
            let name = ObjectName::from(agg_key);

            res.insert(name, PublishedRoa::new(roa));
        }

        Ok(res)
    }

    pub fn removed_roas(&self) -> Vec<ObjectName> {
        let mut res = vec![];

        for simple in self.removed.keys() {
            res.push(ObjectName::from(simple))
        }

        for agg in self.aggregate_removed.keys() {
            res.push(ObjectName::from(agg))
        }

        res
    }

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

impl fmt::Display for RoaUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.updated.is_empty() {
            write!(f, "Updated single VRP ROAs: ")?;
            for roa in self.updated.keys() {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, "Removed single VRP ROAs: ")?;
            for roa in self.removed.keys() {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        if !self.aggregate_updated.is_empty() {
            write!(f, "Updated ASN aggregated ROAs: ")?;
            for roa in self.aggregate_updated.keys() {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        if !self.aggregate_removed.is_empty() {
            write!(f, "Removed ASN aggregated ROAs: ")?;
            for roa in self.aggregate_removed.keys() {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        Ok(())
    }
}

//------------ AspaObjectsUpdates ------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<AspaCustomer>,
}

impl AspaObjectsUpdates {
    pub fn new(updated: Vec<AspaInfo>, removed: Vec<AspaCustomer>) -> Self {
        AspaObjectsUpdates { updated, removed }
    }

    pub fn for_new_aspa_info(new_aspa: AspaInfo) -> Self {
        AspaObjectsUpdates {
            updated: vec![new_aspa],
            removed: vec![],
        }
    }

    pub fn add_updated(&mut self, update: AspaInfo) {
        self.updated.push(update)
    }

    pub fn add_removed(&mut self, customer: AspaCustomer) {
        self.removed.push(customer)
    }

    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn unpack(self) -> (Vec<AspaInfo>, Vec<AspaCustomer>) {
        (self.updated, self.removed)
    }

    pub fn updated(&self) -> &Vec<AspaInfo> {
        &self.updated
    }

    pub fn removed(&self) -> &Vec<AspaCustomer> {
        &self.removed
    }
}

//------------ ChildCertificateUpdates -------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificateUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    issued: Vec<DelegatedCertificate>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<KeyIdentifier>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    suspended: Vec<SuspendedCert>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    unsuspended: Vec<UnsuspendedCert>,
}

impl ChildCertificateUpdates {
    pub fn new(
        issued: Vec<DelegatedCertificate>,
        removed: Vec<KeyIdentifier>,
        suspended: Vec<SuspendedCert>,
        unsuspended: Vec<UnsuspendedCert>,
    ) -> Self {
        ChildCertificateUpdates {
            issued,
            removed,
            suspended,
            unsuspended,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.issued.is_empty() && self.removed.is_empty() && self.suspended.is_empty() && self.unsuspended.is_empty()
    }

    /// Add an issued certificate to the current set of issued certificates.
    /// Note that this is typically a newly issued certificate, but it can
    /// also be a previously issued certificate which had been suspended and
    /// is now unsuspended.
    pub fn issue(&mut self, new: DelegatedCertificate) {
        self.issued.push(new);
    }

    /// Remove certificates for a key identifier. This will ensure that they
    /// are revoked.
    pub fn remove(&mut self, ki: KeyIdentifier) {
        self.removed.push(ki);
    }

    /// List all currently issued (not suspended) certificates.
    pub fn issued(&self) -> &Vec<DelegatedCertificate> {
        &self.issued
    }

    /// List all removals (revocations).
    pub fn removed(&self) -> &Vec<KeyIdentifier> {
        &self.removed
    }

    /// Suspend a certificate
    pub fn suspend(&mut self, suspended_cert: SuspendedCert) {
        self.suspended.push(suspended_cert);
    }

    /// List all suspended certificates in this update.
    pub fn suspended(&self) -> &Vec<SuspendedCert> {
        &self.suspended
    }

    /// Unsuspend a certificate
    pub fn unsuspend(&mut self, unsuspended_cert: UnsuspendedCert) {
        self.unsuspended.push(unsuspended_cert);
    }

    /// List all unsuspended certificates in this update.
    pub fn unsuspended(&self) -> &Vec<UnsuspendedCert> {
        &self.unsuspended
    }

    pub fn unpack(
        self,
    ) -> (
        Vec<DelegatedCertificate>,
        Vec<KeyIdentifier>,
        Vec<SuspendedCert>,
        Vec<UnsuspendedCert>,
    ) {
        (self.issued, self.removed, self.suspended, self.unsuspended)
    }
}

//------------ Evt ---------------------------------------------------------

pub type CaEvt = StoredEvent<CaEvtDet>;

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CaEvtDet {
    // Being a Trust Anchor
    TrustAnchorMade {
        ta_cert_details: TaCertDetails,
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
        updates: ChildCertificateUpdates,
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
        id: Rfc8183Id,
    },
    ParentAdded {
        parent: ParentHandle,
        contact: ParentCaContact,
    },
    ParentUpdated {
        parent: ParentHandle,
        contact: ParentCaContact,
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
        rcvd_cert: RcvdCert,
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
        new_key: CertifiedKey, // pending key which received a certificate becomes 'new', i.e. it is staged.
    },
    KeyPendingToActive {
        // When a new resource class is created it will have a single pending key only which
        // is promoted to become the active (current) key for the resource class immediately
        // after receiving its first certificate. Technically this is not a roll, but a simple
        // first activation.
        resource_class_name: ResourceClassName,
        current_key: CertifiedKey, // there was no current key, pending becomes active without staging when cert is received.
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
        auth: RouteAuthorization,
    },
    RouteAuthorizationRemoved {
        // Tracks a single authorization (VRP) which is removed. See remark for RouteAuthorizationAdded.
        auth: RouteAuthorization,
    },
    RoasUpdated {
        // Tracks ROA *objects* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: RoaUpdates,
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
        updates: AspaObjectsUpdates,
    },

    // Publishing
    RepoUpdated {
        // Adds the repository contact for this CA so that publication can commence,
        // and certificates can be requested from parents. Note: the CA can only start
        // requesting certificates when it knows which URIs it can use.
        contact: RepositoryContact,
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

impl CaEvtDet {
    /// This marks the RFC8183Id as updated
    pub(super) fn id_updated(handle: &CaHandle, version: u64, id: Rfc8183Id) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::IdUpdated { id })
    }

    /// This marks a parent as added to the CA.
    pub(super) fn parent_added(
        handle: &CaHandle,
        version: u64,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ParentAdded { parent, contact })
    }

    /// This marks a parent contact as updated
    pub(super) fn parent_updated(
        handle: &CaHandle,
        version: u64,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ParentUpdated { parent, contact })
    }

    pub(super) fn child_added(
        handle: &CaHandle,
        version: u64,
        child: ChildHandle,
        id_cert: IdCert,
        resources: ResourceSet,
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ChildAdded {
                child,
                id_cert,
                resources,
            },
        )
    }

    pub(super) fn child_updated_cert(handle: &CaHandle, version: u64, child: ChildHandle, id_cert: IdCert) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ChildUpdatedIdCert { child, id_cert })
    }

    pub(super) fn child_updated_resources(
        handle: &CaHandle,
        version: u64,
        child: ChildHandle,
        resources: ResourceSet,
    ) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ChildUpdatedResources { child, resources })
    }

    pub(super) fn child_certificate_issued(
        handle: &CaHandle,
        version: u64,
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            },
        )
    }

    pub(super) fn child_revoke_key(
        handle: &CaHandle,
        version: u64,
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            },
        )
    }

    pub(super) fn child_certificates_updated(
        handle: &CaHandle,
        version: u64,
        resource_class_name: ResourceClassName,
        updates: ChildCertificateUpdates,
    ) -> CaEvt {
        StoredEvent::new(
            handle,
            version,
            CaEvtDet::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            },
        )
    }

    pub(super) fn child_removed(handle: &CaHandle, version: u64, child: ChildHandle) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ChildRemoved { child })
    }

    pub(super) fn child_suspended(handle: &CaHandle, version: u64, child: ChildHandle) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ChildSuspended { child })
    }

    pub(super) fn child_unsuspended(handle: &CaHandle, version: u64, child: ChildHandle) -> CaEvt {
        StoredEvent::new(handle, version, CaEvtDet::ChildUnsuspended { child })
    }
}

impl fmt::Display for CaEvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Being a Trust Anchor
            CaEvtDet::TrustAnchorMade { ta_cert_details } => write!(
                f,
                "turn into TA with key (hash) {}",
                ta_cert_details.cert().subject_key_identifier()
            ),

            // Being a parent Events
            CaEvtDet::ChildAdded {
                child,
                id_cert,
                resources,
            } => {
                write!(
                    f,
                    "added child '{}' with resources '{}, id (hash): {}",
                    child,
                    resources,
                    id_cert.subject_key_identifier()
                )
            }
            CaEvtDet::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "issued certificate to child '{}' for class '{}' and pub key '{}'",
                child, resource_class_name, ki
            ),
            CaEvtDet::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                write!(
                    f,
                    "updated child certificates in resource class {}",
                    resource_class_name
                )?;
                let issued = updates.issued();
                if !issued.is_empty() {
                    write!(f, " issued keys: ")?;
                    for iss in issued {
                        write!(f, " {}", iss.subject_key_identifier())?;
                    }
                }
                let revoked = updates.removed();
                if !revoked.is_empty() {
                    write!(f, " revoked keys: ")?;
                    for rev in revoked {
                        write!(f, " {}", rev)?;
                    }
                }
                let suspended = updates.suspended();
                if !suspended.is_empty() {
                    write!(f, " suspended keys: ")?;
                    for cert in suspended {
                        write!(f, " {}", cert.subject_key_identifier())?;
                    }
                }
                let unsuspended = updates.unsuspended();
                if !unsuspended.is_empty() {
                    write!(f, " unsuspended keys: ")?;
                    for cert in unsuspended {
                        write!(f, " {}", cert.subject_key_identifier())?;
                    }
                }

                Ok(())
            }
            CaEvtDet::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "revoked certificate for child '{}' in resource class '{}' with key(hash) '{}'",
                child, resource_class_name, ki
            ),
            CaEvtDet::ChildUpdatedIdCert { child, id_cert } => {
                write!(
                    f,
                    "updated child '{}' id (hash) '{}'",
                    child,
                    id_cert.subject_key_identifier()
                )
            }
            CaEvtDet::ChildUpdatedResources { child, resources } => {
                write!(f, "updated child '{}' resources to '{}'", child, resources)
            }
            CaEvtDet::ChildRemoved { child } => write!(f, "removed child '{}'", child),
            CaEvtDet::ChildSuspended { child } => write!(f, "suspended child '{}'", child),
            CaEvtDet::ChildUnsuspended { child } => write!(f, "unsuspended child '{}'", child),

            // Being a child Events
            CaEvtDet::IdUpdated { id } => write!(f, "updated RFC8183 id to key '{}'", id.key_id()),
            CaEvtDet::ParentAdded { parent, contact } => {
                let contact_str = match contact {
                    ParentCaContact::Ta(_) => "TA proxy",
                    ParentCaContact::Rfc6492(_) => "RFC6492",
                };
                write!(f, "added {} parent '{}' ", contact_str, parent)
            }
            CaEvtDet::ParentUpdated { parent, contact } => {
                let contact_str = match contact {
                    ParentCaContact::Ta(_) => "TA proxy",
                    ParentCaContact::Rfc6492(_) => "RFC6492",
                };
                write!(f, "updated parent '{}' contact to '{}' ", parent, contact_str)
            }
            CaEvtDet::ParentRemoved { parent } => write!(f, "removed parent '{}'", parent),

            CaEvtDet::ResourceClassAdded {
                resource_class_name, ..
            } => write!(f, "added resource class with name '{}'", resource_class_name),
            CaEvtDet::ResourceClassRemoved {
                resource_class_name,
                parent,
                ..
            } => write!(
                f,
                "removed resource class with name '{}' under parent '{}'",
                resource_class_name, parent
            ),
            CaEvtDet::CertificateRequested {
                resource_class_name,
                ki,
                ..
            } => write!(
                f,
                "requested certificate for key (hash) '{}' under resource class '{}'",
                ki, resource_class_name
            ),
            CaEvtDet::CertificateReceived {
                resource_class_name,
                ki,
                ..
            } => write!(
                f,
                "received certificate for key (hash) '{}' under resource class '{}'",
                ki, resource_class_name
            ),

            // Key life cycle
            CaEvtDet::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            } => {
                write!(
                    f,
                    "key roll: added pending key '{}' under resource class '{}'",
                    pending_key_id, resource_class_name
                )
            }
            CaEvtDet::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => write!(
                f,
                "key roll: moving pending key '{}' to new state under resource class '{}'",
                new_key.key_id(),
                resource_class_name
            ),
            CaEvtDet::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => write!(
                f,
                "activating pending key '{}' under resource class '{}'",
                current_key.key_id(),
                resource_class_name
            ),
            CaEvtDet::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => write!(
                f,
                "key roll: activated new key, requested revocation of '{}' under resource class '{}'",
                revoke_req.key(),
                resource_class_name
            ),
            CaEvtDet::KeyRollFinished { resource_class_name } => {
                write!(f, "key roll: finished for resource class '{}'", resource_class_name)
            }
            CaEvtDet::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => write!(
                f,
                "Found unexpected key in resource class '{}', will try to revoke key id: '{}'",
                resource_class_name,
                revoke_req.key()
            ),

            // Route Authorizations
            CaEvtDet::RouteAuthorizationAdded { auth } => write!(f, "added ROA: '{}'", auth),
            CaEvtDet::RouteAuthorizationRemoved { auth } => write!(f, "removed ROA: '{}'", auth),
            CaEvtDet::RoasUpdated {
                resource_class_name,
                updates,
            } => {
                write!(f, "updated ROA objects under resource class '{}'", resource_class_name)?;
                if !updates.updated.is_empty() || !updates.aggregate_updated.is_empty() {
                    write!(f, " added: ")?;
                    for auth in updates.updated.keys() {
                        write!(f, "{} ", ObjectName::from(auth))?;
                    }
                    for agg_key in updates.aggregate_updated.keys() {
                        write!(f, "{} ", ObjectName::from(agg_key))?;
                    }
                }
                if !updates.removed.is_empty() || !updates.aggregate_removed.is_empty() {
                    write!(f, " removed: ")?;
                    for auth in updates.removed.keys() {
                        write!(f, "{} ", ObjectName::from(auth))?;
                    }
                    for agg_key in updates.aggregate_removed.keys() {
                        write!(f, "{} ", ObjectName::from(agg_key))?;
                    }
                }
                Ok(())
            }

            // Autonomous System Provider Authorization
            CaEvtDet::AspaConfigAdded { aspa_config: addition } => write!(f, "{}", addition),
            CaEvtDet::AspaConfigUpdated { customer, update } => {
                write!(f, "updated ASPA config for customer ASN: {} {}", customer, update)
            }
            CaEvtDet::AspaConfigRemoved { customer } => write!(f, "removed ASPA config for customer ASN: {}", customer),
            CaEvtDet::AspaObjectsUpdated {
                resource_class_name,
                updates,
            } => {
                write!(f, "updated ASPA objects under resource class '{}'", resource_class_name)?;
                if !updates.updated().is_empty() {
                    write!(f, " updated:")?;
                    for upd in updates.updated() {
                        write!(f, " {}", ObjectName::aspa(upd.customer()))?;
                    }
                }
                if !updates.removed().is_empty() {
                    write!(f, " removed:")?;
                    for rem in updates.removed() {
                        write!(f, " {}", ObjectName::aspa(*rem))?;
                    }
                }
                Ok(())
            }

            // Publishing
            CaEvtDet::RepoUpdated { contact } => {
                write!(f, "updated repository to remote server: {}", contact.service_uri())
            }

            // Rta
            CaEvtDet::RtaPrepared { name, prepared } => {
                write!(f, "Prepared RTA '{}' for resources: {}", name, prepared.resources())
            }
            CaEvtDet::RtaSigned { name, rta } => {
                write!(f, "Signed RTA '{}' for resources: {}", name, rta.resources())
            }
        }
    }
}
