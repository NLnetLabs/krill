use std::{collections::HashMap, str::FromStr, sync::Arc};

use rpki::{crl::Crl, crypto::KeyIdentifier, manifest::Manifest, x509::Time};

use crate::{
    commons::{
        api::{
            self, ChildHandle, Handle, HexEncodedHash, IssuanceRequest, IssuedCert, ObjectName, ParentHandle, RcvdCert,
            RepoInfo, ResourceClassName, ResourceSet, Revocation, RevocationRequest, Revocations, RoaAggregateKey,
            TaCertDetails,
        },
        crypto::{IdCert, KrillSigner},
        eventsourcing::{
            Aggregate, AggregateStore, CommandKey, KeyStoreKey, KeyStoreVersion, KeyValueStore, StoredValueInfo,
        },
        remote::rfc8183,
    },
    constants::CASERVER_DIR,
    daemon::{
        ca::{
            self, ta_handle, BasicKeyObjectSet, CaEvtDet, CaObjects, CaObjectsStore, CurrentKeyObjectSet,
            PublishedCert, PublishedRoa, ResourceClassKeyState, ResourceClassObjects, RouteAuthorization,
        },
        config::Config,
    },
    upgrades::{UpgradeError, UpgradeResult, UpgradeStore},
};

use super::{old_commands::*, old_events::*};

/// Migrate the current objects for each CA into the CaObjectStore
pub struct CaObjectsMigration;

impl CaObjectsMigration {
    pub fn migrate(config: Arc<Config>) -> UpgradeResult<()> {
        let store = KeyValueStore::disk(&config.data_dir, CASERVER_DIR)?;
        let ca_store = AggregateStore::<ca::CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;

        let signer = Arc::new(KrillSigner::build(&config.data_dir)?);

        let cas_store_migration = CasStoreMigration { store, ca_store };
        if cas_store_migration.needs_migrate()? {
            info!("Krill version is older than 0.9.0-RC1, will now upgrade data structures.");
            Self::populate_ca_objects_store(config, signer)?;
            cas_store_migration.migrate()
        } else {
            Ok(())
        }
    }

    fn populate_ca_objects_store(config: Arc<Config>, signer: Arc<KrillSigner>) -> UpgradeResult<()> {
        // Read all CAS based on snapshots and events, using the pre-0_9_0 data structs
        // which are preserved here.
        info!("Krill will now populate the CA Objects Store");
        let store = AggregateStore::<CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;
        store.warm()?;

        let ca_objects_store = CaObjectsStore::disk(config, signer)?;

        for ca_handle in store.list()? {
            let ca = store.get_latest(&ca_handle)?;
            let objects = ca.ca_objects();

            ca_objects_store.put_ca_objects(&ca_handle, &objects)?;
        }

        Ok(())
    }
}

/// Migrate pre 0.9 commands and events for CAs
struct CasStoreMigration {
    store: KeyValueStore,
    ca_store: AggregateStore<ca::CertAuth>,
}

impl UpgradeStore for CasStoreMigration {
    fn needs_migrate(&self) -> Result<bool, UpgradeError> {
        if Self::version_before(&self.store, KeyStoreVersion::V0_6)? {
            Err(UpgradeError::custom("Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version."))
        } else {
            Self::version_before(&self.store, KeyStoreVersion::V0_9_0_RC1)
        }
    }

    fn migrate(&self) -> Result<(), UpgradeError> {
        info!("Krill will now reformat existing command and event data, and remove unnecessary data");

        // For each CA:
        //   - build a new
        for scope in self.store.scopes()? {
            let info_key = KeyStoreKey::scoped(scope.clone(), "info.json".to_string());
            let mut info: StoredValueInfo = match self.store.get(&info_key) {
                Ok(Some(info)) => info,
                _ => StoredValueInfo::default(),
            };

            // reset last event and command, we will find the new (higher) versions.
            info.last_event = 0;
            info.last_command = 1;

            // Find all command keys and sort them by sequence.
            // Then turn them back into key store keys for further processing.
            let cmd_keys = self.command_keys(&scope)?;

            for cmd_key in cmd_keys {
                debug!("  command: {}", cmd_key);
                let mut old_cmd: OldStoredCaCommand = self.get(&cmd_key)?;

                self.archive_migrated(&cmd_key)?;

                if let Some(evt_versions) = old_cmd.effect.events() {
                    let mut events = vec![];
                    for v in evt_versions {
                        let event_key = Self::event_key(&scope, *v);
                        debug!("  +- event: {}", event_key);
                        let old_evt: OldCaEvt = self
                            .store
                            .get(&event_key)?
                            .ok_or_else(|| UpgradeError::Custom(format!("Cannot parse old event: {}", event_key)))?;

                        self.archive_migrated(&event_key)?;

                        if old_evt.needs_migration() {
                            info.last_event += 1;

                            events.push(info.last_event);
                            let migrated_event = old_evt.into_stored_ca_event(info.last_event)?;
                            let key = KeyStoreKey::scoped(scope.clone(), format!("delta-{}.json", info.last_event));
                            self.store.store(&key, &migrated_event)?;
                        }
                    }

                    if events.is_empty() {
                        continue; // This command has no relevant events in 0.9, so don't save it.
                    }

                    old_cmd.set_events(events);
                }

                old_cmd.version = info.last_event + 1;
                old_cmd.sequence = info.last_command;

                info.last_command += 1;
                info.last_update = old_cmd.time;

                let migrated_cmd = old_cmd.into_ca_command();
                let cmd_key = CommandKey::for_stored(&migrated_cmd);
                let key = KeyStoreKey::scoped(scope.clone(), format!("{}.json", cmd_key));

                self.store.store(&key, &migrated_cmd)?;
            }

            self.archive_snapshots(&scope)?;

            info.snapshot_version = 0;
            info.last_command -= 1;

            self.store.store(&info_key, &info)?;
        }

        // ** Only if all CAs were migrated **
        //    --> clean up the archived commands and events
        //    --> restore to previous version of Krill is not supported
        for scope in self.store.scopes()? {
            info!("Check state of '{}' before cleanup.", scope);
            let ca =
                Handle::from_str(&scope).map_err(|e| UpgradeError::Custom(format!("Found invalid ca name: {}", e)))?;

            self.ca_store.get_latest(&ca).map_err(|e| {
                UpgradeError::Custom(format!("Could not rebuild CA '{}' after migration: {}", scope, e))
            })?;

            self.drop_migration_scope(&scope)?;
        }

        Ok(())
    }

    fn store(&self) -> &KeyValueStore {
        &self.store
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
    type StorableCommandDetails = OldStorableCaCommand;
    type Event = OldCaEvt;
    type InitEvent = OldCaIni;
    type Error = UpgradeError;

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
            OldCaEvtDet::TrustAnchorMade(details) => {
                let key_id = details.cert().subject_key_identifier();
                self.parents.insert(ta_handle(), ParentCaContact::Ta(details));
                let rcn = ResourceClassName::from(self.next_class_name);
                self.next_class_name += 1;
                self.resources.insert(rcn.clone(), ResourceClass::for_ta(rcn, key_id));
            }

            //-----------------------------------------------------------------------
            // Being a parent
            //-----------------------------------------------------------------------
            OldCaEvtDet::ChildAdded(child, details) => {
                self.children.insert(child, details);
            }
            OldCaEvtDet::ChildCertificateIssued(child, rcn, ki) => {
                self.children.get_mut(&child).unwrap().add_issue_response(rcn, ki);
            }

            OldCaEvtDet::ChildKeyRevoked(child, rcn, ki) => {
                self.resources.get_mut(&rcn).unwrap().key_revoked(&ki);

                self.children.get_mut(&child).unwrap().add_revoke_response(ki);
            }

            OldCaEvtDet::ChildCertificatesUpdated(rcn, updates) => {
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

            OldCaEvtDet::ChildUpdatedIdCert(child, cert) => self.children.get_mut(&child).unwrap().set_id_cert(cert),

            OldCaEvtDet::ChildUpdatedResources(child, resources) => {
                self.children.get_mut(&child).unwrap().set_resources(resources)
            }

            OldCaEvtDet::ChildRemoved(child) => {
                self.children.remove(&child);
            }

            //-----------------------------------------------------------------------
            // Being a child
            //-----------------------------------------------------------------------
            OldCaEvtDet::IdUpdated(id) => {
                self.id = id;
            }
            OldCaEvtDet::ParentAdded(handle, info) => {
                self.parents.insert(handle, info);
            }
            OldCaEvtDet::ParentUpdated(handle, info) => {
                self.parents.insert(handle, info);
            }
            OldCaEvtDet::ParentRemoved(handle, _deltas) => {
                self.parents.remove(&handle);
                self.resources.retain(|_, rc| rc.parent_handle != handle);
            }

            OldCaEvtDet::ResourceClassAdded(name, rc) => {
                self.next_class_name += 1;
                self.resources.insert(name, rc);
            }
            OldCaEvtDet::ResourceClassRemoved(name, _delta, _parent, _revocations) => {
                self.resources.remove(&name);
            }
            OldCaEvtDet::CertificateRequested(name, req, status) => {
                self.resources.get_mut(&name).unwrap().add_request(status, req);
            }
            OldCaEvtDet::CertificateReceived(class_name, key_id, cert) => {
                self.resources.get_mut(&class_name).unwrap().received_cert(key_id, cert);
            }

            //-----------------------------------------------------------------------
            // Key Life Cycle
            //-----------------------------------------------------------------------
            OldCaEvtDet::KeyRollPendingKeyAdded(class_name, key_id) => {
                self.resources.get_mut(&class_name).unwrap().pending_key_added(key_id);
            }
            OldCaEvtDet::KeyPendingToNew(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_new(key);
            }
            OldCaEvtDet::KeyPendingToActive(rcn, key, _delta) => {
                self.resources.get_mut(&rcn).unwrap().pending_key_to_active(key);
            }
            OldCaEvtDet::KeyRollActivated(class_name, revoke_req) => {
                self.resources
                    .get_mut(&class_name)
                    .unwrap()
                    .new_key_activated(revoke_req);
            }
            OldCaEvtDet::KeyRollFinished(class_name, _delta) => {
                self.resources.get_mut(&class_name).unwrap().old_key_removed();
            }
            OldCaEvtDet::UnexpectedKeyFound(_, _) => {
                // no action needed, this is marked to flag that a key may be removed
            }

            //-----------------------------------------------------------------------
            // Route Authorizations
            //-----------------------------------------------------------------------
            OldCaEvtDet::RouteAuthorizationAdded(update) => self.routes.add(update),
            OldCaEvtDet::RouteAuthorizationRemoved(removal) => {
                self.routes.remove(&removal);
            }
            OldCaEvtDet::RoasUpdated(rcn, updates) => self.resources.get_mut(&rcn).unwrap().roas_updated(updates),

            //-----------------------------------------------------------------------
            // Publication
            //-----------------------------------------------------------------------
            OldCaEvtDet::ObjectSetUpdated(class_name, delta_map) => {
                let rc = self.resources.get_mut(&class_name).unwrap();
                for (key_id, delta) in delta_map.into_iter() {
                    rc.apply_delta(delta, key_id);
                }
            }
            OldCaEvtDet::RepoUpdated(contact) => {
                if let Some(current) = &self.repository {
                    self.repository_pending_withdraw = Some(current.clone())
                }
                self.repository = Some(contact);
            }
            OldCaEvtDet::RepoCleaned(_) => {
                self.repository_pending_withdraw = None;
            }

            //-----------------------------------------------------------------------
            // Resource Tagged Attestations
            //-----------------------------------------------------------------------
            OldCaEvtDet::RtaPrepared(_name, _prepared) => {
                // no-op
            }
            OldCaEvtDet::RtaSigned(_name, _signed) => {
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
            .flat_map(|(rcn, rc)| {
                rc.resource_class_state()
                    .map(|state| (rcn.clone(), ResourceClassObjects::new(state)))
            })
            .collect();

        CaObjects::new(self.handle.clone(), self.repository.clone().map(|r| r.into()), objects)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    key: KeyIdentifier, // convenient (and efficient) access
    cert: IdCert,
}

impl From<Rfc8183Id> for ca::Rfc8183Id {
    fn from(old: Rfc8183Id) -> Self {
        ca::Rfc8183Id::new(old.cert)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryContact {
    Embedded(RepoInfo),
    Rfc8181(rfc8183::RepositoryResponse),
}

impl From<RepositoryContact> for api::RepositoryContact {
    fn from(old: RepositoryContact) -> Self {
        match old {
            RepositoryContact::Embedded(info) => api::RepositoryContact::embedded(info),
            RepositoryContact::Rfc8181(response) => api::RepositoryContact::rfc8181(response),
        }
    }
}

impl RepositoryContact {
    fn embedded(info: RepoInfo) -> Self {
        RepositoryContact::Embedded(info)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum ParentCaContact {
    Ta(TaCertDetails),
    Embedded,
    Rfc6492(rfc8183::ParentResponse),
}

impl From<ParentCaContact> for api::ParentCaContact {
    fn from(old: ParentCaContact) -> Self {
        match old {
            ParentCaContact::Ta(ta_cert_details) => api::ParentCaContact::for_ta(ta_cert_details),
            ParentCaContact::Embedded => api::ParentCaContact::embedded(),
            ParentCaContact::Rfc6492(response) => api::ParentCaContact::for_rfc6492(response),
        }
    }
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

    pub fn resource_class_state(&self) -> Option<ResourceClassKeyState> {
        let roas = self.roas.roa_objects();
        let certs: HashMap<ObjectName, PublishedCert> = self
            .certificates
            .inner
            .values()
            .map(|i| (ObjectName::from(i.cert()), i.clone().into()))
            .collect();

        match &self.key_state {
            KeyState::Pending(_) => None,

            KeyState::Active(current) | KeyState::RollPending(_, current) => Some(ResourceClassKeyState::current(
                Self::object_set_for_current(current, roas, certs),
            )),
            KeyState::RollNew(new, current) => Some(ResourceClassKeyState::staging(
                Self::object_set_for_certified_key(new),
                Self::object_set_for_current(current, roas, certs),
            )),

            KeyState::RollOld(current, old) => Some(ResourceClassKeyState::old(
                Self::object_set_for_current(current, roas, certs),
                Self::object_set_for_certified_key(&old.key),
            )),
        }
    }

    pub fn into_added_event(self) -> Result<CaEvtDet, UpgradeError> {
        let pending_key = match self.key_state {
            KeyState::Pending(pending) => Some(pending),
            _ => None,
        }
        .ok_or_else(|| UpgradeError::custom("Added a resource class which is not in state pending."))?
        .key_id;

        let (resource_class_name, parent, parent_resource_class_name) =
            (self.name, self.parent_handle, self.parent_rc_name);

        Ok(CaEvtDet::ResourceClassAdded {
            resource_class_name,
            parent,
            parent_resource_class_name,
            pending_key,
        })
    }

    fn object_set_for_current(
        key: &CertifiedKey,
        roas: HashMap<ObjectName, PublishedRoa>,
        certs: HashMap<ObjectName, PublishedCert>,
    ) -> CurrentKeyObjectSet {
        let current_set = key.current_set.clone();

        let mft = Manifest::decode(current_set.manifest_info.current.content().to_bytes(), true).unwrap();
        let crl = Crl::decode(current_set.crl_info.current.content().to_bytes()).unwrap();

        CurrentKeyObjectSet::new(
            key.incoming_cert.clone(),
            current_set.number,
            current_set.revocations,
            mft.into(),
            crl.into(),
            roas,
            certs,
        )
    }

    fn object_set_for_certified_key(key: &CertifiedKey) -> BasicKeyObjectSet {
        let current_set = key.current_set.clone();

        let mft = Manifest::decode(current_set.manifest_info.current.content().to_bytes(), true).unwrap();
        let crl = Crl::decode(current_set.crl_info.current.content().to_bytes()).unwrap();

        BasicKeyObjectSet::new(
            key.incoming_cert.clone(),
            current_set.number,
            current_set.revocations,
            mft.into(),
            crl.into(),
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

    pub fn roa_objects(&self) -> HashMap<ObjectName, PublishedRoa> {
        let mut res = HashMap::new();

        for (key, roa_info) in &self.simple {
            let name = ObjectName::from(key);
            let roa = roa_info.roa().unwrap();

            res.insert(name, PublishedRoa::new(roa));
        }

        for (key, agg) in &self.aggregate {
            let name = ObjectName::from(key);
            let roa_info = &agg.roa;
            let roa = roa_info.roa().unwrap();

            res.insert(name, PublishedRoa::new(roa));
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
    pub id_cert: Option<IdCert>,
    pub resources: ResourceSet,
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

impl From<CertifiedKey> for ca::CertifiedKey {
    fn from(old: CertifiedKey) -> Self {
        ca::CertifiedKey::new(old.key_id, old.incoming_cert, old.request)
    }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrlInfo {
    name: ObjectName, // can be derived from CRL, but keeping in mem saves cpu
    current: CurrentObject,
    old: Option<HexEncodedHash>,
}
