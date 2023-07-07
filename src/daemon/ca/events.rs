use std::{collections::HashMap, fmt};

use rpki::{
    ca::{
        idexchange::{ChildHandle, ParentHandle},
        provisioning::{IssuanceRequest, ParentResourceClassName, ResourceClassName, RevocationRequest},
    },
    crypto::KeyIdentifier,
    repository::resources::ResourceSet,
};

use crate::{
    commons::{
        api::{
            AspaCustomer, AspaDefinition, AspaProvidersUpdate, BgpSecAsnKey, IdCertInfo, IssuedCertificate, ObjectName,
            ParentCaContact, ReceivedCert, RepositoryContact, RoaAggregateKey, RtaName, SuspendedCert, UnsuspendedCert,
        },
        crypto::KrillSigner,
        eventsourcing::{Event, InitEvent},
        KrillResult,
    },
    daemon::ca::{AspaInfo, CertifiedKey, PreparedRta, RoaInfo, RoaPayloadJsonMapKey, SignedRta},
};

use super::{BgpSecCertInfo, StoredBgpSecCsr};

//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    cert: IdCertInfo,
}

impl Rfc8183Id {
    pub fn new(cert: IdCertInfo) -> Self {
        Rfc8183Id { cert }
    }

    pub fn generate(signer: &KrillSigner) -> KrillResult<Self> {
        let cert = signer.create_self_signed_id_cert()?;
        let cert = IdCertInfo::from(&cert);
        Ok(Rfc8183Id { cert })
    }

    pub fn cert(&self) -> &IdCertInfo {
        &self.cert
    }
}

impl From<Rfc8183Id> for IdCertInfo {
    fn from(id: Rfc8183Id) -> Self {
        id.cert
    }
}

//------------ CertAuthInitEvent ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInitEvent {
    id: Rfc8183Id,
}

impl InitEvent for CertAuthInitEvent {}

impl CertAuthInitEvent {
    pub fn unpack(self) -> Rfc8183Id {
        self.id
    }
}

impl CertAuthInitEvent {
    pub fn new(id: Rfc8183Id) -> CertAuthInitEvent {
        CertAuthInitEvent { id }
    }

    pub fn init(signer: &KrillSigner) -> KrillResult<CertAuthInitEvent> {
        Rfc8183Id::generate(signer).map(|id| CertAuthInitEvent { id })
    }
}

impl fmt::Display for CertAuthInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized with ID key hash: {}",
            self.id.cert().public_key().key_identifier()
        )?;
        Ok(())
    }
}

//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaUpdates {
    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    updated: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    removed: Vec<RoaPayloadJsonMapKey>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate_updated: HashMap<RoaAggregateKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    aggregate_removed: Vec<RoaAggregateKey>,
}

impl RoaUpdates {
    pub fn new(
        updated: HashMap<RoaPayloadJsonMapKey, RoaInfo>,
        removed: Vec<RoaPayloadJsonMapKey>,
        aggregate_updated: HashMap<RoaAggregateKey, RoaInfo>,
        aggregate_removed: Vec<RoaAggregateKey>,
    ) -> Self {
        RoaUpdates {
            updated,
            removed,
            aggregate_updated,
            aggregate_removed,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.updated.is_empty()
            && self.removed.is_empty()
            && self.aggregate_updated.is_empty()
            && self.aggregate_removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn update(&mut self, auth: RoaPayloadJsonMapKey, roa: RoaInfo) {
        self.updated.insert(auth, roa);
    }

    pub fn remove(&mut self, auth: RoaPayloadJsonMapKey) {
        self.removed.push(auth);
    }

    pub fn remove_aggregate(&mut self, key: RoaAggregateKey) {
        self.aggregate_removed.push(key);
    }

    pub fn update_aggregate(&mut self, key: RoaAggregateKey, info: RoaInfo) {
        self.aggregate_updated.insert(key, info);
    }

    pub fn added_roas(&self) -> HashMap<ObjectName, RoaInfo> {
        let mut res = HashMap::new();

        for (auth, info) in &self.updated {
            let name = ObjectName::from(auth);
            res.insert(name, info.clone());
        }

        for (agg_key, info) in &self.aggregate_updated {
            let name = ObjectName::from(agg_key);
            res.insert(name, info.clone());
        }

        res
    }

    pub fn removed_roas(&self) -> Vec<ObjectName> {
        let mut res = vec![];

        for simple in &self.removed {
            res.push(ObjectName::from(simple))
        }

        for agg in &self.aggregate_removed {
            res.push(ObjectName::from(agg))
        }

        res
    }

    #[allow(clippy::type_complexity)]
    pub fn unpack(
        self,
    ) -> (
        HashMap<RoaPayloadJsonMapKey, RoaInfo>,
        Vec<RoaPayloadJsonMapKey>,
        HashMap<RoaAggregateKey, RoaInfo>,
        Vec<RoaAggregateKey>,
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
            for roa in &self.removed {
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
            for roa in &self.aggregate_removed {
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

//------------ BgpSecCertificateUpdates ------------------------------------
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCertificateUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<BgpSecCertInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<BgpSecAsnKey>,
}

impl BgpSecCertificateUpdates {
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
    }

    pub fn len(&self) -> usize {
        self.updated.len() + self.removed.len()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn updated(&self) -> &Vec<BgpSecCertInfo> {
        &self.updated
    }

    pub fn removed(&self) -> &Vec<BgpSecAsnKey> {
        &self.removed
    }

    pub fn unpack(self) -> (Vec<BgpSecCertInfo>, Vec<BgpSecAsnKey>) {
        (self.updated, self.removed)
    }

    pub fn add_updated(&mut self, update: BgpSecCertInfo) {
        self.updated.push(update);
    }

    pub fn add_removed(&mut self, remove: BgpSecAsnKey) {
        self.removed.push(remove);
    }
}

//------------ ChildCertificateUpdates -------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificateUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    issued: Vec<IssuedCertificate>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<KeyIdentifier>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    suspended: Vec<SuspendedCert>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    unsuspended: Vec<UnsuspendedCert>,
}

impl ChildCertificateUpdates {
    pub fn new(
        issued: Vec<IssuedCertificate>,
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
    pub fn issue(&mut self, new: IssuedCertificate) {
        self.issued.push(new);
    }

    /// Remove certificates for a key identifier. This will ensure that they
    /// are revoked.
    pub fn remove(&mut self, ki: KeyIdentifier) {
        self.removed.push(ki);
    }

    /// List all currently issued (not suspended) certificates.
    pub fn issued(&self) -> &Vec<IssuedCertificate> {
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
        Vec<IssuedCertificate>,
        Vec<KeyIdentifier>,
        Vec<SuspendedCert>,
        Vec<UnsuspendedCert>,
    ) {
        (self.issued, self.removed, self.suspended, self.unsuspended)
    }
}

//------------ CertAuthEvent ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CertAuthEvent {
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
        updates: ChildCertificateUpdates,
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
        rcvd_cert: ReceivedCert,
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
        // issued certificates will also be re-issued under the new 'current' key. These changes
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
        auth: RoaPayloadJsonMapKey,
    },
    RouteAuthorizationComment {
        auth: RoaPayloadJsonMapKey,
        comment: Option<String>,
    },
    RouteAuthorizationRemoved {
        // Tracks a single authorization (VRP) which is removed. See remark for RouteAuthorizationAdded.
        auth: RoaPayloadJsonMapKey,
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

impl Event for CertAuthEvent {}

impl CertAuthEvent {
    /// This marks the RFC8183Id as updated
    pub(super) fn id_updated(id: Rfc8183Id) -> CertAuthEvent {
        CertAuthEvent::IdUpdated { id }
    }

    /// This marks a parent as added to the CA.
    pub(super) fn parent_added(parent: ParentHandle, contact: ParentCaContact) -> CertAuthEvent {
        CertAuthEvent::ParentAdded { parent, contact }
    }

    /// This marks a parent contact as updated
    pub(super) fn parent_updated(parent: ParentHandle, contact: ParentCaContact) -> CertAuthEvent {
        CertAuthEvent::ParentUpdated { parent, contact }
    }

    pub(super) fn child_added(child: ChildHandle, id_cert: IdCertInfo, resources: ResourceSet) -> CertAuthEvent {
        CertAuthEvent::ChildAdded {
            child,
            id_cert,
            resources,
        }
    }

    pub(super) fn child_updated_cert(child: ChildHandle, id_cert: IdCertInfo) -> CertAuthEvent {
        CertAuthEvent::ChildUpdatedIdCert { child, id_cert }
    }

    pub(super) fn child_updated_resources(child: ChildHandle, resources: ResourceSet) -> CertAuthEvent {
        CertAuthEvent::ChildUpdatedResources { child, resources }
    }

    pub(super) fn child_certificate_issued(
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    ) -> CertAuthEvent {
        CertAuthEvent::ChildCertificateIssued {
            child,
            resource_class_name,
            ki,
        }
    }

    pub(super) fn child_revoke_key(
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    ) -> CertAuthEvent {
        CertAuthEvent::ChildKeyRevoked {
            child,
            resource_class_name,
            ki,
        }
    }

    pub(super) fn child_certificates_updated(
        resource_class_name: ResourceClassName,
        updates: ChildCertificateUpdates,
    ) -> CertAuthEvent {
        CertAuthEvent::ChildCertificatesUpdated {
            resource_class_name,
            updates,
        }
    }

    pub(super) fn child_removed(child: ChildHandle) -> CertAuthEvent {
        CertAuthEvent::ChildRemoved { child }
    }

    pub(super) fn child_suspended(child: ChildHandle) -> CertAuthEvent {
        CertAuthEvent::ChildSuspended { child }
    }

    pub(super) fn child_unsuspended(child: ChildHandle) -> CertAuthEvent {
        CertAuthEvent::ChildUnsuspended { child }
    }
}

impl fmt::Display for CertAuthEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Being a parent Events
            CertAuthEvent::ChildAdded {
                child,
                id_cert,
                resources,
            } => {
                write!(
                    f,
                    "added child '{}' with resources '{}, id (hash): {}",
                    child,
                    resources,
                    id_cert.public_key().key_identifier()
                )
            }
            CertAuthEvent::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "issued certificate to child '{}' for class '{}' and pub key '{}'",
                child, resource_class_name, ki
            ),
            CertAuthEvent::ChildCertificatesUpdated {
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
                        write!(f, " {}", iss.key_identifier())?;
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
                        write!(f, " {}", cert.key_identifier())?;
                    }
                }
                let unsuspended = updates.unsuspended();
                if !unsuspended.is_empty() {
                    write!(f, " unsuspended keys: ")?;
                    for cert in unsuspended {
                        write!(f, " {}", cert.key_identifier())?;
                    }
                }

                Ok(())
            }
            CertAuthEvent::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "revoked certificate for child '{}' in resource class '{}' with key(hash) '{}'",
                child, resource_class_name, ki
            ),
            CertAuthEvent::ChildUpdatedIdCert { child, id_cert } => {
                write!(
                    f,
                    "updated child '{}' id (hash) '{}'",
                    child,
                    id_cert.public_key().key_identifier()
                )
            }
            CertAuthEvent::ChildUpdatedResources { child, resources } => {
                write!(f, "updated child '{}' resources to '{}'", child, resources)
            }
            CertAuthEvent::ChildRemoved { child } => write!(f, "removed child '{}'", child),
            CertAuthEvent::ChildSuspended { child } => write!(f, "suspended child '{}'", child),
            CertAuthEvent::ChildUnsuspended { child } => write!(f, "unsuspended child '{}'", child),

            // Being a child Events
            CertAuthEvent::IdUpdated { id } => write!(
                f,
                "updated RFC8183 id to key '{}'",
                id.cert().public_key().key_identifier()
            ),
            CertAuthEvent::ParentAdded { parent, .. } => {
                write!(f, "added parent '{}' ", parent)
            }
            CertAuthEvent::ParentUpdated { parent, .. } => {
                write!(f, "updated parent '{}'", parent)
            }
            CertAuthEvent::ParentRemoved { parent } => write!(f, "removed parent '{}'", parent),

            CertAuthEvent::ResourceClassAdded {
                resource_class_name, ..
            } => write!(f, "added resource class with name '{}'", resource_class_name),
            CertAuthEvent::ResourceClassRemoved {
                resource_class_name,
                parent,
                ..
            } => write!(
                f,
                "removed resource class with name '{}' under parent '{}'",
                resource_class_name, parent
            ),
            CertAuthEvent::CertificateRequested {
                resource_class_name,
                ki,
                ..
            } => write!(
                f,
                "requested certificate for key (hash) '{}' under resource class '{}'",
                ki, resource_class_name
            ),
            CertAuthEvent::CertificateReceived {
                resource_class_name,
                ki,
                ..
            } => write!(
                f,
                "received certificate for key (hash) '{}' under resource class '{}'",
                ki, resource_class_name
            ),

            // Key life cycle
            CertAuthEvent::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            } => {
                write!(
                    f,
                    "key roll: added pending key '{}' under resource class '{}'",
                    pending_key_id, resource_class_name
                )
            }
            CertAuthEvent::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => write!(
                f,
                "key roll: moving pending key '{}' to new state under resource class '{}'",
                new_key.key_id(),
                resource_class_name
            ),
            CertAuthEvent::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => write!(
                f,
                "activating pending key '{}' under resource class '{}'",
                current_key.key_id(),
                resource_class_name
            ),
            CertAuthEvent::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => write!(
                f,
                "key roll: activated new key, requested revocation of '{}' under resource class '{}'",
                revoke_req.key(),
                resource_class_name
            ),
            CertAuthEvent::KeyRollFinished { resource_class_name } => {
                write!(f, "key roll: finished for resource class '{}'", resource_class_name)
            }
            CertAuthEvent::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => write!(
                f,
                "Found unexpected key in resource class '{}', will try to revoke key id: '{}'",
                resource_class_name,
                revoke_req.key()
            ),

            // Route Authorizations
            CertAuthEvent::RouteAuthorizationAdded { auth } => write!(f, "added ROA: '{}'", auth),
            CertAuthEvent::RouteAuthorizationComment { auth, comment } => {
                if let Some(comment) = comment {
                    write!(f, "added comment to ROA: '{}' => {}", auth, comment)
                } else {
                    write!(f, "removed comment from ROA: '{}'", auth)
                }
            }
            CertAuthEvent::RouteAuthorizationRemoved { auth } => write!(f, "removed ROA: '{}'", auth),
            CertAuthEvent::RoasUpdated {
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
                    for auth in &updates.removed {
                        write!(f, "{} ", ObjectName::from(auth))?;
                    }
                    for agg_key in &updates.aggregate_removed {
                        write!(f, "{} ", ObjectName::from(agg_key))?;
                    }
                }
                Ok(())
            }

            // Autonomous System Provider Authorization
            CertAuthEvent::AspaConfigAdded { aspa_config: addition } => write!(f, "{}", addition),
            CertAuthEvent::AspaConfigUpdated { customer, update } => {
                write!(f, "updated ASPA config for customer ASN: {} {}", customer, update)
            }
            CertAuthEvent::AspaConfigRemoved { customer } => {
                write!(f, "removed ASPA config for customer ASN: {}", customer)
            }
            CertAuthEvent::AspaObjectsUpdated {
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

            // BGPSec
            CertAuthEvent::BgpSecDefinitionAdded { key, .. } => {
                write!(
                    f,
                    "added BGPSec definition for ASN: {} and key id: {}",
                    key.asn(),
                    key.key_identifier()
                )
            }
            CertAuthEvent::BgpSecDefinitionUpdated { key, .. } => {
                write!(
                    f,
                    "updated CSR for BGPSec definition for ASN: {} and key id: {}",
                    key.asn(),
                    key.key_identifier()
                )
            }
            CertAuthEvent::BgpSecDefinitionRemoved { key } => {
                write!(
                    f,
                    "removed BGPSec definition for ASN: {} and key id: {}",
                    key.asn(),
                    key.key_identifier()
                )
            }
            CertAuthEvent::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                write!(
                    f,
                    "updated BGPSec certificates under resource class '{}'",
                    resource_class_name
                )?;
                let updated = updates.updated();
                if !updated.is_empty() {
                    write!(f, " added: ")?;
                    for cert in updated {
                        write!(f, "{} ", ObjectName::from(cert))?;
                    }
                }
                let removed = updates.removed();
                if !removed.is_empty() {
                    write!(f, " removed: ")?;
                    for key in removed {
                        write!(f, "{} ", ObjectName::from(key))?;
                    }
                }
                Ok(())
            }

            // Publishing
            CertAuthEvent::RepoUpdated { contact } => {
                write!(
                    f,
                    "updated repository to remote server: {}",
                    contact.server_info().service_uri()
                )
            }

            // Rta
            CertAuthEvent::RtaPrepared { name, prepared } => {
                write!(f, "Prepared RTA '{}' for resources: {}", name, prepared.resources())
            }
            CertAuthEvent::RtaSigned { name, rta } => {
                write!(f, "Signed RTA '{}' for resources: {}", name, rta.resources())
            }
        }
    }
}
