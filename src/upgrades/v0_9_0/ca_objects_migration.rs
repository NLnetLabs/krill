use std::{collections::HashMap, str::FromStr, sync::Arc};

use chrono::Duration;
use rpki::repository::{crl::Crl, crypto::KeyIdentifier, manifest::Manifest, x509::Time};
use rpki::uri;

use crate::{commons::{api::{
            ChildHandle, Handle, HexEncodedHash, IssuanceRequest, IssuedCert, ObjectName, ParentHandle, RcvdCert,
            RepoInfo, ResourceClassName, ResourceSet, Revocation, RevocationRequest, Revocations, RoaAggregateKey,
            TaCertDetails, RepositoryContact, StorableCaCommand, StoredEffect
        }, crypto::{IdCert, KrillSigner}, eventsourcing::{
            Aggregate, AggregateStore, CommandKey, KeyStoreKey, KeyValueStore, StoredValueInfo,
        }, remote::rfc8183, util::KrillVersion}, constants::{CASERVER_DIR, KRILL_VERSION}, daemon::{
        ca::{
            self, ta_handle, BasicKeyObjectSet, CaEvtDet, CaObjects, CaObjectsStore, CurrentKeyObjectSet,
            PublishedCert, PublishedRoa, ResourceClassKeyState, ResourceClassObjects, RouteAuthorization,
            CaEvt, IniDet, StoredCaCommand,
        },
        config::Config,
    }, pubd::RepositoryManager, upgrades::{UpgradeError, UpgradeResult, UpgradeStore}};

use super::super::MIGRATION_SCOPE;
use super::{old_commands::*, old_events::*};

/// Migrate the current objects for each CA into the CaObjectStore
pub struct CaObjectsMigration;

impl CaObjectsMigration {
    pub fn migrate(config: Arc<Config>, repo_manager: RepositoryManager) -> UpgradeResult<()> {
        let repo_manager = Arc::new(repo_manager);
        let store = KeyValueStore::disk(&config.data_dir, CASERVER_DIR)?;
        let ca_store = AggregateStore::<ca::CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;

        let signer = repo_manager.get_signer();

        if store.version_is_before(KrillVersion::release(0,6,0))? {
            Err(UpgradeError::custom("Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version."))
        } else if store.version_is_before(KrillVersion::candidate(0,9,0,1))? {
            info!("Krill version is older than 0.9.0-RC1, will now upgrade data structures.");

            // Populate object store which will contain all objects produced by CAs, while we are
            // at it.. return the information we will need in case we need to convert embedded child-parent
            // CA relationships to use RFC 6492.
            let derived_embedded_ca_info_map = Self::populate_ca_objects_store(config, repo_manager.clone(), signer)?;

            // Migrate existing CAs to the new data structure, commands and events
            CasStoreMigration {
                store,
                ca_store,
                repo_manager,
                derived_embedded_ca_info_map,
            }
            .migrate()
        } else {
            debug!("Krill is up to date, no CA data migration needed.");
            Ok(())
        }
    }

    fn populate_ca_objects_store(
        config: Arc<Config>,
        repo_manager: Arc<RepositoryManager>,
        signer: Arc<KrillSigner>,
    ) -> UpgradeResult<HashMap<Handle, DerivedEmbeddedCaMigrationInfo>> {
        // Read all CAS based on snapshots and events, using the pre-0_9_0 data structs
        // which are preserved here.
        info!("Krill will now populate the CA Objects Store");
        let store = AggregateStore::<OldCertAuth>::disk(&config.data_dir, CASERVER_DIR)?;
        if store.warm().is_err() {
            // most likely we are dealing with off by one errors in old krill info files. Archive them for migration and try again.
            let kv = KeyValueStore::disk(&config.data_dir, CASERVER_DIR)?;
            for c in store.list()? {
                let info_key = KeyStoreKey::scoped(c.to_string(), "info.json".to_string());
                kv.archive_to(&info_key, MIGRATION_SCOPE)?;
            }
        }

        let ca_objects_store = CaObjectsStore::disk(config.clone(), signer)?;

        let mut res = HashMap::new();

        for ca_handle in store.list()? {
            let ca = store.get_latest(&ca_handle)?;
            let objects = ca.ca_objects(repo_manager.as_ref())?;

            ca_objects_store.put_ca_objects(&ca_handle, &objects)?;

            res.insert(ca_handle, Self::derived_embedded_ca_info(ca, &config));
        }

        Ok(res)
    }

    fn derived_embedded_ca_info(ca: Arc<OldCertAuth>, config: &Config) -> DerivedEmbeddedCaMigrationInfo {
        let service_uri = format!("{}rfc6492/{}", config.service_uri().to_string(), ca.handle);
        let service_uri = uri::Https::from_string(service_uri).unwrap();
        let service_uri = rfc8183::ServiceUri::Https(service_uri);

        let child_request = rfc8183::ChildRequest::new(ca.handle.clone(), ca.id.cert.clone());
        let parent_responses = ca
            .children
            .keys()
            .map(|child_handle| {
                (
                    child_handle.clone(),
                    rfc8183::ParentResponse::new(
                        None,
                        ca.id.cert.clone(),
                        ca.handle.clone(),
                        child_handle.clone(),
                        service_uri.clone(),
                    ),
                )
            })
            .collect();

        DerivedEmbeddedCaMigrationInfo {
            child_request,
            parent_responses,
        }
    }
}

/// Migrate pre 0.9 commands and events for CAs
struct CasStoreMigration {
    store: KeyValueStore,
    ca_store: AggregateStore<ca::CertAuth>,
    repo_manager: Arc<RepositoryManager>,
    derived_embedded_ca_info_map: HashMap<Handle, DerivedEmbeddedCaMigrationInfo>,
}

impl UpgradeStore for CasStoreMigration {
    fn needs_migrate(&self) -> Result<bool, UpgradeError> {
        unreachable!("checked directly on keystore")
    }

    fn migrate(&self) -> Result<(), UpgradeError> {
        info!("Krill will now reformat existing command and event data, and remove unnecessary data");

        let dflt_actor = "krill".to_string();

        // For each CA:
        //   - build a new
        for scope in self.store.scopes()? {
            // Archive all keys in the scope, then we can write new keys as needed without
            // overwriting anything when we renumber.
            for key in self.store.keys(Some(scope.clone()), "")? {
                self.archive_to_migration_scope(&key)?;
            }

            let migration_scope = format!("{}/{}", scope, MIGRATION_SCOPE);

            let migration_info_key = KeyStoreKey::scoped(migration_scope.clone(), "info.json".to_string());
            let mut info: StoredValueInfo = match self.store.get(&migration_info_key) {
                Ok(Some(info)) => info,
                _ => StoredValueInfo::default(),
            };

            // reset last event and command, we will find the new (higher) versions.
            info.last_event = 0;
            info.last_command = 1;

            // Find all command keys and sort them by sequence.
            // Then turn them back into key store keys for further processing.
            let cmd_keys = self.command_keys(&migration_scope)?;

            // Get the time to use if we need to inject commands and events for the init
            // event, based on the first recorded time in command keys.
            let time_for_init_command = match cmd_keys.first() {
                Some(first_command) => {
                    let old_cmd: OldStoredCaCommand = self.get(&first_command)?;
                    old_cmd.time
                }
                None => Time::now(),
            };

            // Migrate the init event.
            let old_init_key = KeyStoreKey::scoped(migration_scope.clone(), "delta-0.json".to_string());
            let init_key = KeyStoreKey::scoped(scope.clone(), "delta-0.json".to_string());

            let old_init: OldCaIni = self.get(&old_init_key)?;
            let (id, _, old_ini_det) = old_init.unpack();
            let (rfc_8183_id, repo_opt, ta_opt) = old_ini_det.unpack();
            let ini = IniDet::new(&id, rfc_8183_id.into());
            debug!("  init: {}", init_key);
            self.store.store(&init_key, &ini)?;

            // If the CA was initialized with an embedded repository, then make sure that
            // we generate a command + events to update the repository to the 'local' RFC 8181
            // version of this repository.

            if repo_opt.is_some() {
                debug!("  +- Generate command and event for initialized repository");
                let res = self.repo_manager.repository_response(&id)?;

                let contact = RepositoryContact::new(res);
                let service_uri = contact.service_uri().clone();

                info.last_event += 1;
                let event = CaEvt::new(&id, info.last_event, CaEvtDet::RepoUpdated { contact });

                let command = StoredCaCommand::new(
                    dflt_actor.clone(),
                    time_for_init_command,
                    id,
                    info.last_event,
                    info.last_command,
                    StorableCaCommand::RepoUpdate { service_uri },
                    StoredEffect::Success { events: vec![1] },
                );

                info.last_command += 1;
                info.last_update = time_for_init_command;

                let event_key = Self::event_key(&scope, info.last_event);
                self.store.store(&event_key, &event)?;

                let cmd_key = CommandKey::for_stored(&command);
                let key = KeyStoreKey::scoped(scope.clone(), format!("{}.json", cmd_key));

                self.store.store(&key, &command)?;
            }

            // If the CA was initialized as a trust anchor, then we refuse to upgrade.
            // This can only happen if this is a very old test system. People will need
            // to set up a new test system instead.
            if ta_opt.is_some() {
                return Err(UpgradeError::custom(
                    "This Krill instance is set up as a test system, using a Trust Anchor, which cannot be migrated.",
                ));
            }

            info!("Will migrate {} commands for CA {}", cmd_keys.len(), scope);

            let mut total_migrated = 0;
            let time_started = Time::now();
            let total_commands = cmd_keys.len();

            for cmd_key in cmd_keys {
                // Do the migration counter first, so that we can just call continue when we need to skip commands
                total_migrated += 1;
                if total_migrated % 100 == 0 {
                    // ETA:
                    //  - (total_migrated / (now - started)) * total
                    let mut time_passed = (Time::now().timestamp() - time_started.timestamp()) as usize;
                    if time_passed == 0 {
                        time_passed = 1; // avoid divide by zero.. we are doing approximate estimates here
                    }
                    let migrated_per_second: f64 = total_migrated as f64 / time_passed as f64;
                    let expected_seconds = (total_commands as f64 / migrated_per_second) as i64;
                    let eta = time_started + Duration::seconds(expected_seconds);
                    info!(
                        "  migrated {} commands, expect to finish: {}",
                        total_migrated,
                        eta.to_rfc3339()
                    );
                }

                trace!("  command: {}", cmd_key);
                let mut old_cmd: OldStoredCaCommand = self.get(&cmd_key)?;

                if let Some(evt_versions) = old_cmd.effect.events() {
                    let mut events = vec![];
                    for v in evt_versions {
                        let migration_event_key = Self::event_key(&&migration_scope, *v);
                        trace!("  +- event: {}", migration_event_key);
                        let old_evt: OldCaEvt = self.store.get(&migration_event_key)?.ok_or_else(|| {
                            UpgradeError::Custom(format!("Cannot parse old event: {}", migration_event_key))
                        })?;

                        if old_evt.needs_migration() {
                            info.last_event += 1;

                            events.push(info.last_event);

                            let migrated_event = old_evt.into_stored_ca_event(
                                info.last_event,
                                &self.repo_manager,
                                &self.derived_embedded_ca_info_map,
                            )?;

                            let event_key =
                                KeyStoreKey::scoped(scope.clone(), format!("delta-{}.json", info.last_event));
                            self.store.store(&event_key, &migrated_event)?;
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

                let migrated_cmd = old_cmd.into_ca_command(&self.repo_manager, &self.derived_embedded_ca_info_map)?;
                let cmd_key = CommandKey::for_stored(&migrated_cmd);
                let key = KeyStoreKey::scoped(scope.clone(), format!("{}.json", cmd_key));

                self.store.store(&key, &migrated_cmd)?;
            }
            info!("Finished migrating commands for CA {}", scope);

            self.archive_snapshots(&scope)?;

            info.snapshot_version = 0;
            info.last_command -= 1;

            let info_key = KeyStoreKey::scoped(scope.clone(), "info.json".to_string());
            self.store.store(&info_key, &info)?;
        }

        // ** Only if all CAs were migrated **
        //    --> clean up the archived commands and events
        //    --> restore to previous version of Krill is not supported
        for scope in self.store.scopes()? {
            info!("Will rebuild CA '{}' from events and warm up the cache", scope);

            let ca = Handle::from_str(&scope)
                    .map_err(|e| UpgradeError::Custom(format!("Found invalid ca name: {}", e)))?;
            
            self.ca_store.warm_aggregate(&ca)
                .map_err(|e| UpgradeError::Custom(format!("Could not rebuild CA '{}' after migration: {}", ca, e)))?;
            
            self.drop_migration_scope(&scope)?;
        }

        info!("Done migration CAs to Krill version {}", KRILL_VERSION);

        Ok(())
    }

    fn store(&self) -> &KeyValueStore {
        &self.store
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OldCertAuth {
    handle: Handle,
    version: u64,

    id: Rfc8183Id, // Used for RFC 6492 (up-down) and RFC 8181 (publication)

    repository: Option<OldRepositoryContact>,
    repository_pending_withdraw: Option<OldRepositoryContact>,

    parents: HashMap<ParentHandle, OldParentCaContact>,

    next_class_name: u32,
    resources: HashMap<ResourceClassName, OldResourceClass>,

    children: HashMap<ChildHandle, OldChildDetails>,
    routes: OldRoutes,
}

impl Aggregate for OldCertAuth {
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
        let routes = OldRoutes::default();

        if let Some(ta_details) = ta_opt {
            let key_id = ta_details.cert().subject_key_identifier();
            parents.insert(ta_handle(), OldParentCaContact::Ta(ta_details));

            let rcn = ResourceClassName::from(next_class_name);
            next_class_name += 1;
            resources.insert(rcn.clone(), OldResourceClass::for_ta(rcn, key_id));
        }

        let repository = repo_info.map(OldRepositoryContact::embedded);

        Ok(OldCertAuth {
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
                self.parents.insert(ta_handle(), OldParentCaContact::Ta(details));
                let rcn = ResourceClassName::from(self.next_class_name);
                self.next_class_name += 1;
                self.resources
                    .insert(rcn.clone(), OldResourceClass::for_ta(rcn, key_id));
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
        unreachable!("We will not apply commands for this migration")
    }
}

impl OldCertAuth {
    pub fn ca_objects(&self, repo_manager: &RepositoryManager) -> Result<CaObjects, UpgradeError> {
        let objects = self
            .resources
            .iter()
            .flat_map(|(rcn, rc)| {
                rc.resource_class_state()
                    .map(|state| (rcn.clone(), ResourceClassObjects::new(state)))
            })
            .collect();

        let repo = match &self.repository {
            None => None,
            Some(old) => match old {
                OldRepositoryContact::Embedded(_) => {
                    let res = repo_manager.repository_response(&self.handle)?;
                    Some(RepositoryContact::new(res))
                }
                OldRepositoryContact::Rfc8181(res) => Some(RepositoryContact::new(res.clone())),
            },
        };

        Ok(CaObjects::new(self.handle.clone(), repo, objects))
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
pub enum OldRepositoryContact {
    Embedded(RepoInfo),
    Rfc8181(rfc8183::RepositoryResponse),
}

impl OldRepositoryContact {
    fn embedded(info: RepoInfo) -> Self {
        OldRepositoryContact::Embedded(info)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldParentCaContact {
    Ta(TaCertDetails),
    Embedded,
    Rfc6492(rfc8183::ParentResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldResourceClass {
    name: ResourceClassName,
    name_space: String,

    parent_handle: ParentHandle,
    parent_rc_name: ResourceClassName,

    roas: OldRoas,
    certificates: OldChildCertificates,

    last_key_change: Time,
    key_state: OldKeyState,
}

impl OldResourceClass {
    pub fn for_ta(parent_rc_name: ResourceClassName, pending_key: KeyIdentifier) -> Self {
        OldResourceClass {
            name: parent_rc_name.clone(),
            name_space: parent_rc_name.to_string(),
            parent_handle: ta_handle(),
            parent_rc_name,
            roas: OldRoas::default(),
            certificates: OldChildCertificates::default(),
            last_key_change: Time::now(),
            key_state: OldKeyState::pending(pending_key),
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
            OldKeyState::Pending(_) => None,

            OldKeyState::Active(current) | OldKeyState::RollPending(_, current) => Some(
                ResourceClassKeyState::current(Self::object_set_for_current(current, roas, certs)),
            ),
            OldKeyState::RollNew(new, current) => Some(ResourceClassKeyState::staging(
                Self::object_set_for_certified_key(new),
                Self::object_set_for_current(current, roas, certs),
            )),

            OldKeyState::RollOld(current, old) => Some(ResourceClassKeyState::old(
                Self::object_set_for_current(current, roas, certs),
                Self::object_set_for_certified_key(&old.key),
            )),
        }
    }

    pub fn into_added_event(self) -> Result<CaEvtDet, UpgradeError> {
        let pending_key = match self.key_state {
            OldKeyState::Pending(pending) => Some(pending),
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
        key: &OldCertifiedKey,
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

    fn object_set_for_certified_key(key: &OldCertifiedKey) -> BasicKeyObjectSet {
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
            OldKeyState::Pending(_pending) => panic!("Would have received KeyPendingToActive event"),
            OldKeyState::Active(current) => {
                current.set_incoming_cert(cert);
            }
            OldKeyState::RollPending(_pending, current) => {
                current.set_incoming_cert(cert);
            }
            OldKeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.set_incoming_cert(cert);
                } else {
                    current.set_incoming_cert(cert);
                }
            }
            OldKeyState::RollOld(current, old) => {
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
            OldKeyState::Active(current) => {
                let pending = OldPendingKey { key_id, request: None };
                self.key_state = OldKeyState::RollPending(pending, current.clone())
            }
            _ => panic!("Should never create event to add key when roll in progress"),
        }
    }

    /// Moves a pending key to new
    pub fn pending_key_to_new(&mut self, new: OldCertifiedKey) {
        match &self.key_state {
            OldKeyState::RollPending(_pending, current) => {
                self.key_state = OldKeyState::RollNew(new, current.clone());
            }
            _ => panic!("Cannot move pending to new, if state is not roll pending"),
        }
    }

    /// Moves a pending key to current
    pub fn pending_key_to_active(&mut self, new: OldCertifiedKey) {
        match &self.key_state {
            OldKeyState::Pending(_pending) => {
                self.key_state = OldKeyState::Active(new);
            }
            _ => panic!("Cannot move pending to active, if state is not pending"),
        }
    }

    /// Activates the new key
    pub fn new_key_activated(&mut self, revoke_req: RevocationRequest) {
        match &self.key_state {
            OldKeyState::RollNew(new, current) => {
                let old_key = OldOldKey {
                    key: current.clone(),
                    revoke_req,
                };
                self.key_state = OldKeyState::RollOld(new.clone(), old_key);
            }
            _ => panic!("Should never create event to activate key when no roll in progress"),
        }
    }

    /// Removes the old key, we return the to the state where there is one active key.
    pub fn old_key_removed(&mut self) {
        match &self.key_state {
            OldKeyState::RollOld(current, _old) => {
                self.key_state = OldKeyState::Active(current.clone());
            }
            _ => panic!("Should never create event to remove old key, when there is none"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRoas {
    #[serde(alias = "inner", skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    simple: HashMap<RouteAuthorization, RoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate: HashMap<RoaAggregateKey, AggregateRoaInfo>,
}

impl Default for OldRoas {
    fn default() -> Self {
        OldRoas {
            simple: HashMap::new(),
            aggregate: HashMap::new(),
        }
    }
}

impl OldRoas {
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
pub struct OldReplacedObject {
    revocation: Revocation,
    hash: HexEncodedHash,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldChildCertificates {
    inner: HashMap<KeyIdentifier, IssuedCert>,
}

impl OldChildCertificates {
    pub fn key_revoked(&mut self, key: &KeyIdentifier) {
        self.inner.remove(key);
    }

    pub fn certificate_issued(&mut self, issued: IssuedCert) {
        self.inner.insert(issued.cert().subject_key_identifier(), issued);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldChildDetails {
    pub id_cert: Option<IdCert>,
    pub resources: ResourceSet,
    used_keys: HashMap<KeyIdentifier, OldLastResponse>,
}

impl OldChildDetails {
    pub fn is_issued(&self, ki: &KeyIdentifier) -> bool {
        matches!(self.used_keys.get(ki), Some(OldLastResponse::Current(_)))
    }

    pub fn set_id_cert(&mut self, id_cert: IdCert) {
        self.id_cert = Some(id_cert);
    }

    pub fn set_resources(&mut self, resources: ResourceSet) {
        self.resources = resources;
    }

    pub fn add_issue_response(&mut self, rcn: ResourceClassName, ki: KeyIdentifier) {
        self.used_keys.insert(ki, OldLastResponse::Current(rcn));
    }

    pub fn add_revoke_response(&mut self, ki: KeyIdentifier) {
        self.used_keys.insert(ki, OldLastResponse::Revoked);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum OldLastResponse {
    Current(ResourceClassName),
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldRoutes {
    map: HashMap<RouteAuthorization, RouteInfo>,
}

impl OldRoutes {
    /// Adds a new authorization, or updates an existing one.
    pub fn add(&mut self, auth: RouteAuthorization) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Removes an authorization
    pub fn remove(&mut self, auth: &RouteAuthorization) -> bool {
        self.map.remove(auth).is_some()
    }
}

impl Default for OldRoutes {
    fn default() -> Self {
        OldRoutes { map: HashMap::new() }
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
pub enum OldKeyState {
    Pending(OldPendingKey),
    Active(CurrentKey),
    RollPending(OldPendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldOldKey),
}

impl OldKeyState {
    fn pending(key_id: KeyIdentifier) -> Self {
        OldKeyState::Pending(OldPendingKey { key_id, request: None })
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta, key_id: KeyIdentifier) {
        match self {
            OldKeyState::Pending(_pending) => panic!("Should never have delta for pending"),
            OldKeyState::Active(current) => current.apply_delta(delta),
            OldKeyState::RollPending(_pending, current) => current.apply_delta(delta),
            OldKeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.apply_delta(delta)
                } else {
                    current.apply_delta(delta)
                }
            }
            OldKeyState::RollOld(current, old) => {
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
            OldKeyState::Pending(pending) => pending.add_request(req),
            OldKeyState::Active(current) => current.add_request(req),
            OldKeyState::RollPending(pending, current) => {
                if pending.key_id == key_id {
                    pending.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            OldKeyState::RollNew(new, current) => {
                if new.key_id == key_id {
                    new.add_request(req)
                } else {
                    current.add_request(req)
                }
            }
            OldKeyState::RollOld(current, old) => {
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
pub struct OldPendingKey {
    key_id: KeyIdentifier,
    request: Option<IssuanceRequest>,
}

impl OldPendingKey {
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }
    pub fn clear_request(&mut self) {
        self.request = None
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldOldKey {
    key: OldCertifiedKey,
    revoke_req: RevocationRequest,
}

type NewKey = OldCertifiedKey;
type CurrentKey = OldCertifiedKey;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    current_set: OldCurrentObjectSet,
    request: Option<IssuanceRequest>,
}

impl From<OldCertifiedKey> for ca::CertifiedKey {
    fn from(old: OldCertifiedKey) -> Self {
        ca::CertifiedKey::new(old.key_id, old.incoming_cert, old.request)
    }
}

impl OldCertifiedKey {
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
pub struct OldCurrentObjectSet {
    number: u64,
    revocations: Revocations,
    manifest_info: OldManifestInfo,
    crl_info: OldCrlInfo,
}

impl OldCurrentObjectSet {
    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta) {
        self.number = delta.number;
        self.revocations.apply_delta(delta.revocations_delta);
        self.manifest_info = delta.manifest_info;
        self.crl_info = delta.crl_info;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldManifestInfo {
    name: ObjectName,
    current: CurrentObject,
    next_update: Time,
    old: Option<HexEncodedHash>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCrlInfo {
    name: ObjectName, // can be derived from CRL, but keeping in mem saves cpu
    current: CurrentObject,
    old: Option<HexEncodedHash>,
}
