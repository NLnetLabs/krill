use std::{collections::HashMap, fmt, path::PathBuf};

use rpki::{cert::Cert, crypto::KeyIdentifier, uri, x509::Time};

use crate::{
    commons::{
        api::{
            ChildHandle, CurrentObject, Handle, HexEncodedHash, IssuanceRequest, IssuedCert, ObjectName,
            ParentCaContact, ParentHandle, ResourceClassName, ResourceSet, Revocation, RevocationRequest, Revocations,
            RoaAggregateKey, StorableCaCommand,
        },
        crypto::IdCert,
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, AggregateStoreError, KeyValueError},
        remote::rfc8183,
    },
    constants::CASERVER_DIR,
    daemon::ca::{
        ta_handle, CaObjects, CaObjectsStore, IssuedCertObject, ObjectSet, ResourceClassObjects, RoaObject,
        RouteAuthorization,
    },
};

use super::{old_commands::*, old_events::*};

/// Migrate the current objects for each CA into the CaObjectStore
pub struct CaObjectsMigration;

impl CaObjectsMigration {
    pub fn migrate(work_dir: &PathBuf) -> Result<(), MigrationError> {
        // Check the current CAS dir, if it is pre-0.9.0 we need to migrate

        // Read all CAS based on snapshots and events, using the pre-0_9_0 data structs
        // which are preserved here.
        let store = AggregateStore::<CertAuth>::new(work_dir, CASERVER_DIR)?;
        store.warm()?;

        let ca_objects_store = CaObjectsStore::disk(work_dir)?;

        for ca_handle in store.list()? {
            let ca = store.get_latest(&ca_handle)?;
            let objects = ca.ca_objects();

            ca_objects_store.put_ca_objects(&ca_handle, &objects)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MigrationError(String);

impl From<KeyValueError> for MigrationError {
    fn from(s: KeyValueError) -> Self {
        MigrationError(s.to_string())
    }
}

impl From<AggregateStoreError> for MigrationError {
    fn from(s: AggregateStoreError) -> Self {
        MigrationError(s.to_string())
    }
}

impl From<Error> for MigrationError {
    fn from(e: Error) -> Self {
        MigrationError(e.to_string())
    }
}

impl std::error::Error for MigrationError {}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not migrate to v0.9.0 CA Object Store: {}", self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CertAuth {
    handle: Handle,
    version: u64,

    id: Rfc8183Id, // Used for RFC 6492 (up-down) and RFC 8181 (publication)

    repository: Option<RepositoryContact>,
    repository_pending_withdraw: Option<RepositoryContact>,

    parents: HashMap<ParentHandle, ParentCaContact>,

    next_class_name: u32,
    resources: HashMap<ResourceClassName, ResourceClass>,

    children: HashMap<ChildHandle, ChildDetails>,
    routes: Routes,
}

impl Aggregate for CertAuth {
    type Command = OldStoredCaCommand;
    type StorableCommandDetails = StorableCaCommand;
    type Event = OldEvt;
    type InitEvent = OldIni;
    type Error = MigrationError;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();
        let (id, repo_info, ta_opt) = details.unpack();

        let mut parents = HashMap::new();
        let mut resources = HashMap::new();
        let mut next_class_name = 0;

        let children = HashMap::new();
        let routes = Routes::default();

        if let Some(ta_details) = ta_opt {
            let key_id = ta_details.cert().subject_key_identifier();
            parents.insert(ta_handle(), ParentCaContact::Ta(ta_details));

            let rcn = ResourceClassName::from(next_class_name);
            next_class_name += 1;
            resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
        }

        let repository = repo_info.map(RepositoryContact::embedded);

        Ok(CertAuth {
            handle,
            version: 1,

            id,

            repository,
            repository_pending_withdraw: None,

            parents,

            next_class_name,
            resources,

            children,

            routes,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            //-----------------------------------------------------------------------
            // Being a trust anchor
            //-----------------------------------------------------------------------
            OldEvtDet::TrustAnchorMade(details) => {
                let key_id = details.cert().subject_key_identifier();
                self.parents.insert(ta_handle(), ParentCaContact::Ta(details));
                let rcn = ResourceClassName::from(self.next_class_name);
                self.next_class_name += 1;
                self.resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
            }

            //-----------------------------------------------------------------------
            // Being a parent
            //-----------------------------------------------------------------------
            OldEvtDet::ChildAdded(child, details) => {
                self.children.insert(child, details);
            }
            OldEvtDet::ChildCertificateIssued(child, rcn, ki) => {
                self.children.get_mut(&child).unwrap().add_issue_response(rcn, ki);
            }

            OldEvtDet::ChildKeyRevoked(child, rcn, ki) => {
                self.resources.get_mut(&rcn).unwrap().key_revoked(&ki);

                self.children.get_mut(&child).unwrap().add_revoke_response(ki);
            }

            OldEvtDet::ChildCertificatesUpdated(rcn, updates) => {
                let rc = self.resources.get_mut(&rcn).unwrap();
                let (issued, removed) = updates.unpack();
                for iss in issued {
                    rc.certificate_issued(iss)
                }
                for rem in removed {
                    rc.key_revoked(&rem);

                    // This loop is inefficient, but certificate revocations are not that common, so it's
                    // not a big deal. Tracking this better would require that track the child handle somehow.
                    // That is a bit hard when this revocation is the result from a republish where we lost
                    // all resources delegated to the child.
                    for child in self.children.values_mut() {
                        if child.is_issued(&rem) {
                            child.add_revoke_response(rem)
                        }
                    }
                }
            }

            OldEvtDet::ChildUpdatedIdCert(child, cert) => self.children.get_mut(&child).unwrap().set_id_cert(cert),

            OldEvtDet::ChildUpdatedResources(child, resources) => {
                self.children.get_mut(&child).unwrap().set_resources(resources)
            }

            OldEvtDet::ChildRemoved(child) => {
                self.children.remove(&child);
            }

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            OldEvtDet::IdUpdated(id) => {
                self.id = id;
            }
            OldEvtDet::ParentAdded(handle, info) => {
                self.parents.insert(handle, info);
            }
            OldEvtDet::ParentUpdated(handle, info) => {
                self.parents.insert(handle, info);
            }
            OldEvtDet::ParentRemoved(handle, _deltas) => {
                self.parents.remove(&handle);
                self.resources.retain(|_, rc| rc.parent_handle != handle);
            }

            OldEvtDet::ResourceClassAdded(name, rc) => {
                self.next_class_name += 1;
                self.resources.insert(name, rc);
            }
            OldEvtDet::ResourceClassRemoved(name, _delta, _parent, _revocations) => {
                self.resources.remove(&name);
            }
            OldEvtDet::CertificateRequested(name, req, status) => {
                self.resources.get_mut(&name).unwrap().add_request(status, req);
            }
            OldEvtDet::CertificateReceived(class_name, key_id, cert) => {
                self.resources.get_mut(&class_name).unwrap().received_cert(key_id, cert);
            }

            //-----------------------------------------------------------------------
            // Key Life Cycle
            //-----------------------------------------------------------------------
            OldEvtDet::KeyRollPendingKeyAdded(class_name, key_id) => {
                self.resources.get_mut(&class_name).unwrap().pending_key_added(key_id);
            }
            OldEvtDet::KeyPendingToNew(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_new(key);
            }
            OldEvtDet::KeyPendingToActive(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_active(key);
            }
            OldEvtDet::KeyRollActivated(class_name, revoke_req) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .new_key_activated(revoke_req);
            }
            OldEvtDet::KeyRollFinished(class_name, _delta) => {
                self.resources.get_mut(&class_name).unwrap().old_key_removed();
            }
            OldEvtDet::UnexpectedKeyFound(_, _) => {
                // no action needed, this is marked to flag that a key may be removed
            }

            //-----------------------------------------------------------------------
            // Route Authorizations
            //-----------------------------------------------------------------------
            OldEvtDet::RouteAuthorizationAdded(update) => self.routes.add(update),
            OldEvtDet::RouteAuthorizationRemoved(removal) => {
                self.routes.remove(&removal);
            }
            OldEvtDet::RoasUpdated(rcn, updates) => self.resources.get_mut(&rcn).unwrap().roas_updated(updates),

            //-----------------------------------------------------------------------
            // Publication
            //-----------------------------------------------------------------------
            OldEvtDet::ObjectSetUpdated(class_name, delta_map) => {
                let rc = self.resources.get_mut(&class_name).unwrap();
                for (key_id, delta) in delta_map.into_iter() {
                    rc.apply_delta(delta, key_id);
                }
            }
            OldEvtDet::RepoUpdated(contact) => {
                if let Some(current) = &self.repository {
                    self.repository_pending_withdraw = Some(current.clone())
                }
                self.repository = Some(contact);
            }
            OldEvtDet::RepoCleaned(_) => {
                self.repository_pending_withdraw = None;
            }

            //-----------------------------------------------------------------------
            // Resource Tagged Attestations
            //-----------------------------------------------------------------------
            OldEvtDet::RtaPrepared(_name, _prepared) => {
                // no-op
            }
            OldEvtDet::RtaSigned(_name, _signed) => {
                // no-op
            }
        }
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        unimplemented!("We will not apply commands for this migration")
    }
}

impl CertAuth {
    pub fn ca_objects(&self) -> CaObjects {
        let objects = self
            .resources
            .iter()
            .map(|(rcn, rc)| (rcn.clone(), rc.resource_class_objects()))
            .collect();

        CaObjects::new(objects)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: KeyIdentifier, // convenient (and efficient) access
    cert: IdCert,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryContact {
    Embedded(RepoInfo),
    Rfc8181(rfc8183::RepositoryResponse),
}

impl RepositoryContact {
    fn embedded(info: RepoInfo) -> Self {
        RepositoryContact::Embedded(info)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rpki_notify: uri::Https,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClass {
    name: ResourceClassName,
    name_space: String,

    parent_handle: ParentHandle,
    parent_rc_name: ResourceClassName,

    roas: Roas,
    certificates: ChildCertificates,

    last_key_change: Time,
    key_state: KeyState,
}

impl ResourceClass {
    pub fn for_ta(parent_rc_name: ResourceClassName, pending_key: KeyIdentifier) -> Self {
        ResourceClass {
            name: parent_rc_name.clone(),
            name_space: parent_rc_name.to_string(),
            parent_handle: ta_handle(),
            parent_rc_name,
            roas: Roas::default(),
            certificates: ChildCertificates::default(),
            last_key_change: Time::now(),
            key_state: KeyState::pending(pending_key),
        }
    }

    pub fn resource_class_objects(&self) -> ResourceClassObjects {
        let roas = self.roas.roa_object_infos();
        let certs: Vec<IssuedCertObject> = self.certificates.inner.values().map(|i| i.into()).collect();

        let mut objects = ResourceClassObjects::default();

        match &self.key_state {
            KeyState::Active(current)
            | KeyState::RollPending(_, current)
            | KeyState::RollNew(_, current)
            | KeyState::RollOld(current, _) => {
                objects.add_key(current.key_id, Self::object_set_for_current(current, roas, certs));
            }
            _ => {}
        }

        if let KeyState::RollNew(new, _) = &self.key_state {
            objects.add_key(new.key_id, Self::object_set_for_certified_key(new));
        }

        if let KeyState::RollOld(_, old) = &self.key_state {
            objects.add_key(old.key.key_id, Self::object_set_for_certified_key(&old.key));
        }

        objects
    }

    fn object_set_for_current(key: &CertifiedKey, roas: Vec<RoaObject>, certs: Vec<IssuedCertObject>) -> ObjectSet {
        let current_set = key.current_set.clone();
        ObjectSet::new(
            current_set.number,
            current_set.revocations,
            current_set.manifest_info.into(),
            current_set.crl_info.into(),
            roas,
            certs,
        )
    }

    fn object_set_for_certified_key(key: &CertifiedKey) -> ObjectSet {
        let current_set = key.current_set.clone();
        ObjectSet::new(
            current_set.number,
            current_set.revocations,
            current_set.manifest_info.into(),
            current_set.crl_info.into(),
            vec![],
            vec![],
        )
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta, key_id: KeyIdentifier) {
        self.key_state.apply_delta(delta, key_id);
    }

    /// Marks the ROAs as updated from a RoaUpdated event.
    pub fn roas_updated(&mut self, updates: RoaUpdates) {
        self.roas.updated(updates);
    }

    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.certificates.key_revoked(key);
    }

    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.certificates.certificate_issued(issued);
    }

    /// Adds a request to an existing key for future reference.
    pub fn add_request(&mut self, key_id: KeyIdentifier, req: IssuanceRequest) {
        self.key_state.add_request(key_id, req);
    }

    /// This function marks a certificate as received.
    pub fn received_cert(&mut self, key_id: KeyIdentifier, cert: RcvdCert) {
        // if there is a pending key, then we need to do some promotions..
        match &mut self.key_state {
            KeyState::Pending(_pending) => panic!("Would have received KeyPendingToActive event"),
            KeyState::Active(current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollPending(_pending, current) => {
                current.set_incoming_cert(cert);
            }
            KeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.set_incoming_cert(cert);
                } else {
                    current.set_incoming_cert(cert);
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id == key_id {
                    current.set_incoming_cert(cert);
                } else {
                    old.key.set_incoming_cert(cert);
                }
            }
        }
    }

    /// Adds a pending key.
    pub fn pending_key_added(&mut self, key_id: KeyIdentifier) {
        match &self.key_state {
            KeyState::Active(current) => {
                let pending = PendingKey { key_id, request: None };
                self.key_state = KeyState::RollPending(pending, current.clone())
            }
            _ => panic!("Should never create event to add key when roll in progress"),
        }
    }

    /// Moves a pending key to new
    pub fn pending_key_to_new(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::RollPending(_pending, current) => {
                self.key_state = KeyState::RollNew(new, current.clone());
            }
            _ => panic!("Cannot move pending to new, if state is not roll pending"),
        }
    }

    /// Moves a pending key to current
    pub fn pending_key_to_active(&mut self, new: CertifiedKey) {
        match &self.key_state {
            KeyState::Pending(_pending) => {
                self.key_state = KeyState::Active(new);
            }
            _ => panic!("Cannot move pending to active, if state is not pending"),
        }
    }

    /// Activates the new key
    pub fn new_key_activated(&mut self, revoke_req: RevocationRequest) {
        match &self.key_state {
            KeyState::RollNew(new, current) => {
                let old_key = OldKey {
                    key: current.clone(),
                    revoke_req,
                };
                self.key_state = KeyState::RollOld(new.clone(), old_key);
            }
            _ => panic!("Should never create event to activate key when no roll in progress"),
        }
    }

    /// Removes the old key, we return the to the state where there is one active key.
    pub fn old_key_removed(&mut self) {
        match &self.key_state {
            KeyState::RollOld(current, _old) => {
                self.key_state = KeyState::Active(current.clone());
            }
            _ => panic!("Should never create event to remove old key, when there is none"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roas {
    #[serde(alias = "inner", skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    simple: HashMap<RouteAuthorization, RoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate: HashMap<RoaAggregateKey, AggregateRoaInfo>,
}

impl Default for Roas {
    fn default() -> Self {
        Roas {
            simple: HashMap::new(),
            aggregate: HashMap::new(),
        }
    }
}

impl Roas {
    pub fn updated(&mut self, updates: RoaUpdates) {
        let (updated, removed, aggregate_updated, aggregate_removed) = updates.unpack();

        for (auth, info) in updated.into_iter() {
            self.simple.insert(auth, info);
        }

        for auth in removed.keys() {
            self.simple.remove(auth);
        }

        for (key, aggregate) in aggregate_updated.into_iter() {
            self.aggregate.insert(key, aggregate);
        }

        for key in aggregate_removed.keys() {
            self.aggregate.remove(key);
        }
    }

    pub fn roa_object_infos(&self) -> Vec<RoaObject> {
        let mut res = vec![];

        for (key, roa) in &self.simple {
            let name = ObjectName::from(key);
            res.push(RoaObject::new(name, roa.object.clone()))
        }

        for (key, agg) in &self.aggregate {
            let name = ObjectName::from(key);
            let roa = &agg.roa;
            res.push(RoaObject::new(name, roa.object.clone()))
        }

        res
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplacedObject {
    revocation: Revocation,
    hash: HexEncodedHash,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCertificates {
    inner: HashMap<KeyIdentifier, IssuedCert>,
}

impl ChildCertificates {
    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.inner.remove(key);
    }

    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.inner.insert(issued.cert().subject_key_identifier(), issued);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildDetails {
    id_cert: Option<IdCert>,
    resources: ResourceSet,
    used_keys: HashMap<KeyIdentifier, LastResponse>,
}

impl ChildDetails {
    pub fn is_issued(&self, ki: &KeyIdentifier) -> bool {
        matches!(self.used_keys.get(ki), Some(LastResponse::Current(_)))
    }

    pub fn set_id_cert(&mut self, id_cert: IdCert) {
        self.id_cert = Some(id_cert);
    }

    pub fn set_resources(&mut self, resources: ResourceSet) {
        self.resources = resources;
    }

    pub fn add_issue_response(&mut self, rcn: ResourceClassName, ki: KeyIdentifier) {
        self.used_keys.insert(ki, LastResponse::Current(rcn));
    }

    pub fn add_revoke_response(&mut self, ki: KeyIdentifier) {
        self.used_keys.insert(ki, LastResponse::Revoked);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum LastResponse {
    Current(ResourceClassName),
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Routes {
    map: HashMap<RouteAuthorization, RouteInfo>,
}

impl Routes {
    /// Adds a new authorization, or updates an existing one.
    pub fn add(&mut self, auth: RouteAuthorization) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Removes an authorization
    pub fn remove(&mut self, auth: &RouteAuthorization) -> bool {
        self.map.remove(auth).is_some()
    }
}

impl Default for Routes {
    fn default() -> Self {
        Routes { map: HashMap::new() }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteInfo {
    since: Time, // authorization first added by user

    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<u32>,
}

impl Default for RouteInfo {
    fn default() -> Self {
        RouteInfo {
            since: Time::now(),
            group: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Pending(PendingKey),
    Active(CurrentKey),
    RollPending(PendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldKey),
}

impl KeyState {
    fn pending(key_id: KeyIdentifier) -> Self {
        KeyState::Pending(PendingKey { key_id, request: None })
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta, key_id: KeyIdentifier) {
        match self {
            KeyState::Pending(_pending) => panic!("Should never have delta for pending"),
            KeyState::Active(current) => current.apply_delta(delta),
            KeyState::RollPending(_pending, current) => current.apply_delta(delta),
            KeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.apply_delta(delta)
                } else {
                    current.apply_delta(delta)
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id == key_id {
                    current.apply_delta(delta)
                } else {
                    old.key.apply_delta(delta)
                }
            }
        }
    }

    pub fn add_request(&mut self, key_id: KeyIdentifier, req: IssuanceRequest) {
        match self {
            KeyState::Pending(pending) => pending.add_request(req),
            KeyState::Active(current) => current.add_request(req),
            KeyState::RollPending(pending, current) => {
                if pending.key_id == key_id {
                    pending.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            KeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            KeyState::RollOld(current, old) => {
                if current.key_id == key_id {
                    current.add_request(req)
                } else {
                    old.key.add_request(req)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKey {
    key_id: KeyIdentifier,
    request: Option<IssuanceRequest>,
}

impl PendingKey {
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }
    pub fn clear_request(&mut self) {
        self.request = None
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldKey {
    key: CertifiedKey,
    revoke_req: RevocationRequest,
}

type NewKey = CertifiedKey;
type CurrentKey = CertifiedKey;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    current_set: CurrentObjectSet,
    request: Option<IssuanceRequest>,
}

impl CertifiedKey {
    pub fn set_incoming_cert(&mut self, incoming_cert: RcvdCert) {
        self.request = None;
        self.incoming_cert = incoming_cert;
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta) {
        self.current_set.apply_delta(delta)
    }

    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RcvdCert {
    cert: Cert,
    uri: uri::Rsync,
    resources: ResourceSet,
}

impl PartialEq for RcvdCert {
    fn eq(&self, other: &RcvdCert) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() && self.uri == other.uri
    }
}

impl Eq for RcvdCert {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSet {
    number: u64,
    revocations: Revocations,
    manifest_info: ManifestInfo,
    crl_info: CrlInfo,
}

impl CurrentObjectSet {
    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta) {
        self.number = delta.number;
        self.revocations.apply_delta(delta.revocations_delta);
        self.manifest_info = delta.manifest_info;
        self.crl_info = delta.crl_info;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManifestInfo {
    name: ObjectName,
    current: CurrentObject,
    next_update: Time,
    old: Option<HexEncodedHash>,
}

impl From<ManifestInfo> for crate::daemon::ca::ManifestInfo {
    fn from(info: ManifestInfo) -> Self {
        crate::daemon::ca::ManifestInfo::new(info.name, info.current, info.next_update, info.old)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrlInfo {
    name: ObjectName, // can be derived from CRL, but keeping in mem saves cpu
    current: CurrentObject,
    old: Option<HexEncodedHash>,
}

impl From<CrlInfo> for crate::daemon::ca::CrlInfo {
    fn from(info: CrlInfo) -> Self {
        crate::daemon::ca::CrlInfo::new(info.name, info.current, info.old)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::fs;

    use crate::commons::util::file;
    use crate::test::tmp_dir;

    use super::*;

    #[test]
    fn ca_objects_for_existing_ca() {
        let d = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_9_0/cas/");

        let mut work_dir_cas = d.clone();
        work_dir_cas.push("cas");

        file::backup_dir(&source, &work_dir_cas).unwrap();

        CaObjectsMigration::migrate(&d).unwrap();

        let _ = fs::remove_dir_all(d);
    }
}
