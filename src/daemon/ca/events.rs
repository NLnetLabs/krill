use std::collections::HashMap;
use std::fmt;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

use rpki::crypto::KeyIdentifier;

use crate::commons::api::{
    AddedObject, ChildHandle, Handle, IssuanceRequest, IssuedCert, ObjectName, ObjectsDelta, ParentCaContact,
    ParentHandle, RcvdCert, RepoInfo, RepositoryContact, ResourceClassName, ResourceSet, Revocation, RevocationRequest,
    RevokedObject, RoaAggregateKey, TaCertDetails, UpdatedObject, WithdrawnObject,
};
use crate::commons::eventsourcing::StoredEvent;
use crate::commons::remote::crypto::IdCert;
use crate::commons::KrillResult;
use crate::daemon::ca::signing::Signer;
use crate::daemon::ca::{
    AggregateRoaInfo, CertifiedKey, ChildDetails, CurrentObjectSetDelta, ResourceClass, Rfc8183Id, RoaInfo,
    RouteAuthorization,
};

//------------ Ini -----------------------------------------------------------

pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IniDet {
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

impl IniDet {
    pub fn unpack(self) -> (Rfc8183Id, Option<RepoInfo>, Option<TaCertDetails>) {
        (self.id, self.info, self.ta_details)
    }
}

impl IniDet {
    pub fn init<S: Signer>(handle: &Handle, signer: Arc<RwLock<S>>) -> KrillResult<Ini> {
        let mut signer = signer.write().unwrap();
        let id = Rfc8183Id::generate(signer.deref_mut())?;
        Ok(Ini::new(
            handle,
            0,
            IniDet {
                id,
                info: None,
                ta_details: None,
            },
        ))
    }
}

impl fmt::Display for IniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Initialised with ID key hash: {}", self.id.key_hash())?;
        Ok(())
    }
}

//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
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

impl Default for RoaUpdates {
    fn default() -> Self {
        RoaUpdates {
            updated: HashMap::new(),
            removed: HashMap::new(),
            aggregate_updated: HashMap::new(),
            aggregate_removed: HashMap::new(),
        }
    }
}

impl RoaUpdates {
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
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

    pub fn added(&self) -> Vec<AddedObject> {
        let mut res = vec![];
        for (_auth, info) in self.updated.iter() {
            if info.replaces().is_none() {
                let object = info.object().clone();
                let name = info.name().clone();
                res.push(AddedObject::new(name, object));
            }
        }
        for (_, info) in self.aggregate_updated.iter() {
            if info.roa().replaces().is_none() {
                let object = info.roa().object().clone();
                let name = info.roa().name().clone();
                res.push(AddedObject::new(name, object));
            }
        }

        res
    }

    pub fn updated(&self) -> Vec<UpdatedObject> {
        let mut res = vec![];
        for (_auth, info) in self.updated.iter() {
            if let Some(replaced) = info.replaces() {
                let object = info.object().clone();
                let name = info.name().clone();
                res.push(UpdatedObject::new(name, object, replaced.hash().clone()));
            }
        }
        for (_, info) in self.aggregate_updated.iter() {
            if let Some(replaced) = info.roa().replaces() {
                let object = info.roa().object().clone();
                let name = info.roa().name().clone();
                res.push(UpdatedObject::new(name, object, replaced.hash().clone()));
            }
        }
        res
    }

    pub fn withdrawn(&self) -> Vec<WithdrawnObject> {
        let mut res = vec![];
        for (auth, revoked) in self.removed.iter() {
            let name = ObjectName::from(auth);
            let hash = revoked.hash().clone();
            res.push(WithdrawnObject::new(name, hash));
        }
        for (key, revoked) in self.aggregate_removed.iter() {
            let name = ObjectName::from(key);
            let hash = revoked.hash().clone();
            res.push(WithdrawnObject::new(name, hash));
        }
        res
    }

    pub fn revocations(&self) -> Vec<Revocation> {
        let mut res = vec![];
        for info in self.updated.values() {
            if let Some(old) = info.replaces() {
                res.push(old.revocation());
            }
        }

        for agg in self.aggregate_updated.values() {
            if let Some(old) = agg.roa().replaces() {
                res.push(old.revocation());
            }
        }

        for revoked in self.removed.values() {
            res.push(revoked.revocation())
        }

        for revoked in self.aggregate_removed.values() {
            res.push(revoked.revocation());
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

//------------ ChildCertificateUpdates -------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificateUpdates {
    issued: Vec<IssuedCert>,
    removed: Vec<KeyIdentifier>,
}

impl ChildCertificateUpdates {
    pub fn is_empty(&self) -> bool {
        self.issued.is_empty() && self.removed.is_empty()
    }
    pub fn issue(&mut self, new: IssuedCert) {
        self.issued.push(new);
    }
    pub fn remove(&mut self, ki: KeyIdentifier) {
        self.removed.push(ki);
    }

    pub fn issued(&self) -> &Vec<IssuedCert> {
        &self.issued
    }
    pub fn removed(&self) -> &Vec<KeyIdentifier> {
        &self.removed
    }
    pub fn unpack(self) -> (Vec<IssuedCert>, Vec<KeyIdentifier>) {
        (self.issued, self.removed)
    }
}

//------------ Evt ---------------------------------------------------------

pub type Evt = StoredEvent<EvtDet>;

//------------ EvtDet -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum EvtDet {
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
}

impl EvtDet {
    /// This marks the RFC8183Id as updated
    pub(super) fn id_updated(handle: &Handle, version: u64, id: Rfc8183Id) -> Evt {
        StoredEvent::new(handle, version, EvtDet::IdUpdated(id))
    }

    /// This marks a parent as added to the CA.
    pub(super) fn parent_added(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        info: ParentCaContact,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ParentAdded(parent_handle, info))
    }

    /// This marks a parent contact as updated
    pub(super) fn parent_updated(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        info: ParentCaContact,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ParentUpdated(parent_handle, info))
    }

    /// This marks a parent as removed
    pub(super) fn parent_removed(
        handle: &Handle,
        version: u64,
        parent_handle: ParentHandle,
        withdraws: Vec<ObjectsDelta>,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ParentRemoved(parent_handle, withdraws))
    }

    /// This marks a resource class as added under a parent for the CA.
    pub(super) fn resource_class_added(
        handle: &Handle,
        version: u64,
        class_name: ResourceClassName,
        resource_class: ResourceClass,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ResourceClassAdded(class_name, resource_class))
    }

    /// This marks a resource class as removed, and all its (possible) objects as withdrawn
    pub(super) fn resource_class_removed(
        handle: &Handle,
        version: u64,
        class_name: ResourceClassName,
        delta: ObjectsDelta,
        parent: ParentHandle,
        revocations: Vec<RevocationRequest>,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::ResourceClassRemoved(class_name, delta, parent, revocations),
        )
    }

    pub(super) fn child_added(handle: &Handle, version: u64, child: ChildHandle, details: ChildDetails) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildAdded(child, details))
    }

    pub(super) fn child_updated_cert(handle: &Handle, version: u64, child: ChildHandle, id_cert: IdCert) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildUpdatedIdCert(child, id_cert))
    }

    pub(super) fn child_updated_resources(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        resources: ResourceSet,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildUpdatedResources(child, resources))
    }

    pub(super) fn child_certificate_issued(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        rcn: ResourceClassName,
        ki: KeyIdentifier,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildCertificateIssued(child, rcn, ki))
    }

    pub(super) fn child_revoke_key(
        handle: &Handle,
        version: u64,
        child: ChildHandle,
        rcn: ResourceClassName,
        ki: KeyIdentifier,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildKeyRevoked(child, rcn, ki))
    }

    pub(super) fn child_certificates_updated(
        handle: &Handle,
        version: u64,
        rcn: ResourceClassName,
        updates: ChildCertificateUpdates,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildCertificatesUpdated(rcn, updates))
    }

    pub(super) fn child_removed(handle: &Handle, version: u64, child: ChildHandle) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ChildRemoved(child))
    }

    pub(super) fn current_set_updated(
        handle: &Handle,
        version: u64,
        rcn: ResourceClassName,
        deltas: HashMap<KeyIdentifier, CurrentObjectSetDelta>,
    ) -> Evt {
        StoredEvent::new(handle, version, EvtDet::ObjectSetUpdated(rcn, deltas))
    }
}

impl fmt::Display for EvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Being a Trust Anchor
            EvtDet::TrustAnchorMade(details) => write!(
                f,
                "turn into TA with key (hash) {}",
                details.cert().subject_key_identifier()
            ),

            // Being a parent Events
            EvtDet::ChildAdded(child, details) => {
                write!(f, "added child '{}' with resources '{}", child, details.resources())?;
                if let Some(cert) = details.id_cert() {
                    write!(f, ", id (hash): {}", cert.ski_hex())?;
                }
                Ok(())
            }
            EvtDet::ChildCertificateIssued(child, rcn, ki) => write!(
                f,
                "issued certificate to child '{}' for class '{}' and pub key '{}'",
                child, rcn, ki
            ),
            EvtDet::ChildCertificatesUpdated(rcn, updates) => {
                write!(f, "updated child certificates in resource class {}", rcn)?;
                let issued = updates.issued();
                if !issued.is_empty() {
                    write!(f, " (re-)issued keys: ")?;
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
                Ok(())
            }
            EvtDet::ChildKeyRevoked(child, rcn, ki) => write!(
                f,
                "revoked certificate for child '{}' in resource class '{}' with key(hash) '{}'",
                child, rcn, ki
            ),
            EvtDet::ChildUpdatedIdCert(child, id_crt) => {
                write!(f, "updated child '{}' id (hash) '{}'", child, id_crt.ski_hex())
            }
            EvtDet::ChildUpdatedResources(child, resources) => {
                write!(f, "updated child '{}' resources to '{}'", child, resources)
            }
            EvtDet::ChildRemoved(child) => write!(f, "removed child '{}'", child),

            // Being a child Events
            EvtDet::IdUpdated(id) => write!(f, "updated RFC8183 id to key '{}'", id.key_hash()),
            EvtDet::ParentAdded(parent, contact) => {
                let contact_str = match contact {
                    ParentCaContact::Embedded => "embedded",
                    ParentCaContact::Ta(_) => "TA proxy",
                    ParentCaContact::Rfc6492(_) => "RFC6492",
                };
                write!(f, "added {} parent '{}' ", contact_str, parent)
            }
            EvtDet::ParentUpdated(parent, contact) => {
                let contact_str = match contact {
                    ParentCaContact::Embedded => "embedded",
                    ParentCaContact::Ta(_) => "TA proxy",
                    ParentCaContact::Rfc6492(_) => "RFC6492",
                };
                write!(f, "updated parent '{}' contact to '{}' ", parent, contact_str)
            }
            EvtDet::ParentRemoved(parent, _deltas) => write!(f, "removed parent '{}'", parent),

            EvtDet::ResourceClassAdded(rcn, _) => write!(f, "added resource class with name '{}'", rcn),
            EvtDet::ResourceClassRemoved(rcn, _, parent, _) => write!(
                f,
                "removed resource class with name '{}' under parent '{}'",
                rcn, parent
            ),
            EvtDet::CertificateRequested(rcn, _, ki) => write!(
                f,
                "requested certificate for key (hash) '{}' under resource class '{}'",
                ki, rcn
            ),
            EvtDet::CertificateReceived(rcn, ki, _) => write!(
                f,
                "received certificate for key (hash) '{}' under resource class '{}'",
                ki, rcn
            ),

            // Key life cycle
            EvtDet::KeyRollPendingKeyAdded(rcn, ki) => {
                write!(f, "key roll: added pending key '{}' under resource class '{}'", ki, rcn)
            }
            EvtDet::KeyPendingToNew(rcn, key, _) => write!(
                f,
                "key roll: moving pending key '{}' to new state under resource class '{}'",
                key.key_id(),
                rcn
            ),
            EvtDet::KeyPendingToActive(rcn, key, _) => write!(
                f,
                "activating pending key '{}' under resource class '{}'",
                key.key_id(),
                rcn
            ),
            EvtDet::KeyRollActivated(rcn, revoke) => write!(
                f,
                "key roll: activated new key, requested revocation of '{}' under resource class '{}'",
                revoke.key(),
                rcn
            ),
            EvtDet::KeyRollFinished(rcn, _) => write!(f, "key roll: finished for resource class '{}'", rcn),
            EvtDet::UnexpectedKeyFound(rcn, revoke) => write!(
                f,
                "Found unexpected key in resource class '{}', will try to revoke key id: '{}'",
                rcn,
                revoke.key()
            ),

            // Route Authorizations
            EvtDet::RouteAuthorizationAdded(route) => write!(f, "added ROA: '{}'", route),
            EvtDet::RouteAuthorizationRemoved(route) => write!(f, "removed ROA: '{}'", route),
            EvtDet::RoasUpdated(rcn, roa_updates) => {
                write!(f, "updated ROAs under resource class '{}'", rcn)?;
                if !roa_updates.updated.is_empty() {
                    write!(f, " added: ")?;
                    for auth in roa_updates.updated.keys() {
                        write!(f, "{} ", auth)?;
                    }
                }
                if !roa_updates.removed.is_empty() {
                    write!(f, " removed: ")?;
                    for auth in roa_updates.removed.keys() {
                        write!(f, "{} ", auth)?;
                    }
                }
                Ok(())
            }

            // Publishing
            EvtDet::ObjectSetUpdated(rcn, key_objects_map) => {
                write!(f, "updated objects under resource class '{}'", rcn)?;

                for (key, delta) in key_objects_map.iter() {
                    if !delta.objects().is_empty() {
                        write!(f, " key: '{}'", key)?;
                        write!(f, " added: ")?;
                        for add in delta.objects().added() {
                            write!(f, "{} ", add.name())?;
                        }
                        write!(f, " updated: ")?;
                        for upd in delta.objects().updated() {
                            write!(f, "{} ", upd.name())?;
                        }
                        write!(f, " withdrawn: ")?;
                        for upd in delta.objects().withdrawn() {
                            write!(f, "{} ", upd.name())?;
                        }
                    }
                }

                Ok(())
            }
            EvtDet::RepoUpdated(updated) => match updated {
                RepositoryContact::Embedded(_) => write!(f, "updated repository to embedded server"),
                RepositoryContact::Rfc8181(res) => {
                    write!(f, "updated repository to remote server: {}", res.service_uri())
                }
            },
            EvtDet::RepoCleaned(old) => match old {
                RepositoryContact::Embedded(_) => write!(f, "cleaned old embedded repository"),
                RepositoryContact::Rfc8181(res) => {
                    write!(f, "cleaned repository at remote server: {}", res.service_uri())
                }
            },
        }
    }
}
