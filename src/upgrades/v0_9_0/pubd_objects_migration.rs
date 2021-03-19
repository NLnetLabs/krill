use std::{
    collections::{HashMap, VecDeque},
    mem,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use rpki::{crypto::KeyIdentifier, uri};

use crate::{
    commons::{
        api::{
            rrdp::{Delta, Notification, PublishElement, RrdpSession, Snapshot, SnapshotRef},
            Handle, HexEncodedHash, PublisherHandle, RepositoryHandle,
        },
        crypto::IdCert,
        eventsourcing::{
            Aggregate, AggregateStore, CommandKey, KeyStoreKey, KeyStoreVersion, KeyValueStore, StoredEvent,
            StoredValueInfo,
        },
    },
    constants::{PUBSERVER_CONTENT_DIR, PUBSERVER_DFLT, PUBSERVER_DIR, REPOSITORY_RRDP_DIR},
    daemon::config::Config,
    pubd::{
        PublisherStats, RepoStats, RepositoryAccess, RepositoryAccessInitDetails, RepositoryContent, RrdpServer,
        RrdpSessionReset, RrdpUpdate, RsyncdStore,
    },
    upgrades::{UpgradeError, UpgradeResult, UpgradeStore},
};

use super::{
    old_commands::{OldStorableRepositoryCommand, OldStoredEffect, OldStoredRepositoryCommand},
    old_events::{OldCurrentObjects, OldPubdEvt, OldPubdEvtDet, OldPubdInit, OldPublisher},
};

pub struct PubdObjectsMigration;

impl PubdObjectsMigration {
    fn repository_handle() -> RepositoryHandle {
        Handle::from_str(PUBSERVER_DFLT).unwrap()
    }

    pub fn migrate(config: Arc<Config>) -> UpgradeResult<()> {
        let store = KeyValueStore::disk(&config.data_dir, PUBSERVER_DIR)?;
        let new_store = AggregateStore::disk(&config.data_dir, PUBSERVER_DIR)?;

        let store_migration = PubdStoreMigration { store, new_store };

        if store_migration.needs_migrate()? {
            info!("Krill will now migrate your existing Publication Server data to the 0.9 format");
            Self::populate_repo_content(config)?;
            store_migration.migrate()
        } else {
            Ok(())
        }
    }

    fn populate_repo_content(config: Arc<Config>) -> UpgradeResult<()> {
        let old_store = AggregateStore::<OldRepository>::disk(&config.data_dir, PUBSERVER_DIR)?;
        old_store.warm()?;

        let old_repo = old_store.get_latest(&Self::repository_handle())?;

        let publishers = old_repo
            .publishers
            .iter()
            .map(|(handle, old)| (handle.clone(), old.current_objects.clone().into()))
            .collect();

        let repo_content = RepositoryContent::new(
            publishers,
            old_repo.rrdp.clone().into(),
            old_repo.rsync.clone(),
            old_repo.stats.clone(),
        );

        let repo_content_store = KeyValueStore::disk(&config.data_dir, PUBSERVER_CONTENT_DIR)?;
        let dflt_key = KeyStoreKey::simple(PUBSERVER_DFLT.to_string());

        repo_content_store.store(&dflt_key, &repo_content).unwrap();

        Ok(())
    }
}

struct PubdStoreMigration {
    store: KeyValueStore,
    new_store: AggregateStore<RepositoryAccess>,
}

impl UpgradeStore for PubdStoreMigration {
    fn needs_migrate(&self) -> Result<bool, UpgradeError> {
        if !self.store.has_scope("0".to_string())? {
            Ok(false)
        } else if Self::version_before(&self.store, KeyStoreVersion::V0_6)? {
            Err(UpgradeError::custom("Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version."))
        } else {
            Self::version_before(&self.store, KeyStoreVersion::V0_9_0_RC1)
        }
    }

    fn migrate(&self) -> Result<(), UpgradeError> {
        // we only have 1 pubserver '0'
        let scope = "0";
        let handle = Handle::from_str(scope).unwrap();

        let info_key = KeyStoreKey::scoped(scope.to_string(), "info.json".to_string());
        let mut info: StoredValueInfo = match self.store.get(&info_key) {
            Ok(Some(info)) => info,
            _ => StoredValueInfo::default(),
        };

        // reset last event and command, we will find the new (higher) versions.
        info.last_event = 0;
        info.last_command = 1;

        // migrate init
        let init_key = Self::event_key(&scope, 0);
        let old_init: OldPubdInit = self
            .store
            .get(&init_key)?
            .ok_or_else(|| UpgradeError::custom("Cannot read pubd init event"))?;

        let (_, _, old_init) = old_init.unpack();
        let init: RepositoryAccessInitDetails = old_init.into();
        let init = StoredEvent::new(&handle, 0, init);
        self.store.store(&init_key, &init)?;

        // migrate commands and events
        for cmd_key in self.command_keys(scope)? {
            let mut old_cmd: OldStoredRepositoryCommand = self.get(&cmd_key)?;
            self.archive_migrated(&cmd_key)?;

            if let Some(evt_versions) = old_cmd.effect.events() {
                debug!("  command: {}", cmd_key);

                let mut events = vec![];
                for v in evt_versions {
                    let event_key = Self::event_key(scope, *v);
                    debug!("  +- event: {}", event_key);
                    let old_evt: OldPubdEvt = self
                        .store
                        .get(&event_key)?
                        .ok_or_else(|| UpgradeError::Custom(format!("Cannot parse old event: {}", event_key)))?;

                    self.archive_migrated(&event_key)?;

                    if old_evt.needs_migration() {
                        info.last_event += 1;

                        events.push(info.last_event);
                        let migrated_event = old_evt.into_stored_pubd_event(info.last_event)?;
                        let key = KeyStoreKey::scoped(scope.to_string(), format!("delta-{}.json", info.last_event));
                        self.store.store(&key, &migrated_event)?;
                    }
                }

                if events.is_empty() {
                    continue; // This command has no relevant events in 0.9, so don't save it.
                }

                old_cmd.effect = OldStoredEffect::Events(events);
            }

            old_cmd.version = info.last_event + 1;
            old_cmd.sequence = info.last_command;

            info.last_command += 1;
            info.last_update = old_cmd.time;

            let migrated_cmd = old_cmd.into_pubd_command();
            let cmd_key = CommandKey::for_stored(&migrated_cmd);
            let key = KeyStoreKey::scoped(scope.to_string(), format!("{}.json", cmd_key));

            self.store.store(&key, &migrated_cmd)?;
        }

        // move out the snapshots, we will rebuild from events
        // there will not be too many now that the publication
        // deltas are no longer done as events
        self.archive_snapshots(&scope)?;

        // update the info file
        info.snapshot_version = 0;
        info.last_command -= 1;
        self.store.store(&info_key, &info)?;

        // verify that we can now rebuild the 0.9 publication server based on
        // migrated commands and events.
        self.new_store.warm().map_err(|e| UpgradeError::Custom(format!("Could not rebuild state after migrating pubd! Error was: {}. Please report this issue to rpki-team@nlnetlabs.nl. For the time being: restore all files in the 'migration-0.9' directory to their parent directory and revert to the previous version of Krill.", e)))?;

        // Great, we have migrated everything, now delete the archived
        // commands and events which are no longer relevant
        self.drop_migration_scope(scope)?;

        Ok(())
    }

    fn store(&self) -> &KeyValueStore {
        &self.store
    }

    fn version_before(kv: &KeyValueStore, before: KeyStoreVersion) -> Result<bool, UpgradeError> {
        let key = KeyStoreKey::simple("version".to_string());
        match kv.get::<KeyStoreVersion>(&key) {
            Err(e) => Err(UpgradeError::KeyStoreError(e)),
            Ok(None) => Ok(true),
            Ok(Some(current_version)) => Ok(current_version < before),
        }
    }
}

/// Pre 0.9 Repository which combines the access (ID) functions, and content. Starting with 0.9 these
/// responsibilities will be handled by two separate components. For this migration we need to parse
/// the old repository structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct OldRepository {
    // Event sourcing support
    handle: Handle,
    version: u64,

    id_cert: IdCert,
    key_id: KeyIdentifier, // convenience access to id_cert pub key id

    publishers: HashMap<PublisherHandle, OldPublisher>,

    rrdp: OldRrdpServer,
    rsync: RsyncdStore,

    #[serde(default = "RepoStats::default")]
    stats: RepoStats,
}

impl Aggregate for OldRepository {
    type Command = OldStoredRepositoryCommand;
    type StorableCommandDetails = OldStorableRepositoryCommand;
    type Event = OldPubdEvt;
    type InitEvent = OldPubdInit; // no change needed from < 0.9
    type Error = UpgradeError;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();
        let (id_cert, session, rrdp_base_uri, rsync_jail, repo_base_dir) = details.unpack();

        let key_id = id_cert.subject_public_key_info().key_identifier();

        let stats = RepoStats::new(session);

        let rrdp = OldRrdpServer::create(rrdp_base_uri, &repo_base_dir, session);
        let rsync = RsyncdStore::new(rsync_jail, &repo_base_dir);

        Ok(OldRepository {
            handle,
            version: 1,
            id_cert,
            key_id,
            publishers: HashMap::new(),
            rrdp,
            rsync,
            stats,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            OldPubdEvtDet::PublisherAdded(publisher_handle, publisher) => {
                self.stats.new_publisher(&publisher_handle);
                self.publishers.insert(publisher_handle, publisher);
            }
            OldPubdEvtDet::PublisherRemoved(publisher_handle, update) => {
                self.publishers.remove(&publisher_handle);
                self.rrdp.apply_update(update);
                self.stats.remove_publisher(&publisher_handle, &self.rrdp.notification);
            }
            OldPubdEvtDet::Published(publisher_handle, update) => {
                // update content for publisher
                self.update_publisher(&publisher_handle, &update);

                let time = update.time();

                // update RRDP server
                self.rrdp.apply_update(update);

                // Can only have events for existing publishers, so unwrap is okay
                let publisher = self.get_publisher(&publisher_handle).unwrap();
                let current_objects = publisher.current_objects.clone().into();
                let publisher_stats = PublisherStats::new(&current_objects, time);

                let notification = &self.rrdp.notification;

                self.stats.publish(&publisher_handle, publisher_stats, notification)
            }
            OldPubdEvtDet::RrdpSessionReset(reset) => {
                self.stats.session_reset(reset.notification());
                self.rrdp.apply_reset(reset);
            }
        }
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        unimplemented!("no need to process commands for migration")
    }
}

impl OldRepository {
    fn update_publisher(&mut self, publisher: &PublisherHandle, update: &RrdpUpdate) {
        self.publishers
            .get_mut(publisher)
            .unwrap()
            .apply_delta(update.elements().clone())
    }

    pub fn get_publisher(&self, publisher_handle: &PublisherHandle) -> Result<&OldPublisher, UpgradeError> {
        self.publishers
            .get(publisher_handle)
            .ok_or_else(|| UpgradeError::Custom(format!("Cannot find publisher {} for old event", publisher_handle)))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRrdpServer {
    /// The base URI for notification, snapshot and delta files.
    rrdp_base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    rrdp_base_dir: PathBuf,

    session: RrdpSession,
    serial: u64,
    notification: Notification,

    #[serde(skip_serializing_if = "VecDeque::is_empty", default = "VecDeque::new")]
    old_notifications: VecDeque<Notification>,

    snapshot: OldSnapshot,
    deltas: Vec<Delta>,
}

impl OldRrdpServer {
    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &PathBuf, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = PathBuf::from(repo_dir);
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let snapshot = OldSnapshot::create(session);

        let serial = 0;
        let snapshot_uri = Self::new_snapshot_uri(&rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        OldRrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            session,
            serial,
            notification,
            snapshot,
            old_notifications: VecDeque::new(),
            deltas: vec![],
        }
    }
}

impl OldRrdpServer {
    fn apply_update(&mut self, update: RrdpUpdate) {
        let (delta, mut notification) = update.unpack();

        self.serial = notification.serial();

        mem::swap(&mut self.notification, &mut notification);
        notification.replace(self.notification.time());
        self.old_notifications.push_front(notification);

        self.old_notifications.retain(|n| !n.older_than_seconds(600));

        let mut snapshot = self.snapshot.clone();
        snapshot.apply_delta(delta.clone());
        self.snapshot = snapshot;

        let last_delta = self.notification.last_delta().unwrap(); // always at least 1 delta for updates
        self.deltas.insert(0, delta);
        self.deltas.retain(|d| d.serial() >= last_delta);
    }

    fn apply_reset(&mut self, reset: RrdpSessionReset) {
        let (snapshot, notification) = reset.unpack();

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.old_notifications.clear();
        self.snapshot = snapshot.into();
        self.deltas = vec![];
    }
}

/// URI support
impl OldRrdpServer {
    fn snapshot_rel(session: &RrdpSession, serial: u64) -> String {
        format!("{}/{}/snapshot.xml", session, serial)
    }

    fn new_snapshot_path(base: &PathBuf, session: &RrdpSession, serial: u64) -> PathBuf {
        let mut path = base.clone();
        path.push(Self::snapshot_rel(session, serial));
        path
    }

    fn new_snapshot_uri(base: &uri::Https, session: &RrdpSession, serial: u64) -> uri::Https {
        base.join(Self::snapshot_rel(session, serial).as_ref())
    }
}

impl From<OldRrdpServer> for RrdpServer {
    fn from(old: OldRrdpServer) -> Self {
        let rrdp_archive_dir = match old.rrdp_base_dir.parent() {
            Some(path) => {
                let mut path = PathBuf::from(path);
                path.push("archive");
                path
            }
            None => old.rrdp_base_dir.clone(),
        };

        RrdpServer::new(
            old.rrdp_base_uri,
            old.rrdp_base_dir,
            rrdp_archive_dir,
            old.session,
            old.serial,
            old.notification,
            old.old_notifications,
            old.snapshot.into(),
            VecDeque::from(old.deltas),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldSnapshot {
    session: RrdpSession,
    serial: u64,
    current_objects: OldCurrentObjects,
}

impl OldSnapshot {
    fn create(session: RrdpSession) -> Self {
        let current_objects = OldCurrentObjects::new(HashMap::new());
        OldSnapshot {
            session,
            serial: 0,
            current_objects,
        }
    }

    pub fn apply_delta(&mut self, delta: Delta) {
        let (session, serial, elements) = delta.unwrap();
        self.session = session;
        self.serial = serial;
        self.current_objects.apply_delta(elements)
    }

    fn xml(&self) -> Vec<u8> {
        self.to_snapshot().xml()
    }

    fn to_snapshot(&self) -> Snapshot {
        self.clone().into()
    }
}

impl From<OldSnapshot> for Snapshot {
    fn from(old: OldSnapshot) -> Self {
        Snapshot::new(old.session, old.serial, old.current_objects.into())
    }
}

impl From<Snapshot> for OldSnapshot {
    fn from(snap: Snapshot) -> Self {
        let (session, serial, current_objects) = snap.unpack();

        let map: HashMap<HexEncodedHash, PublishElement> = current_objects
            .elements()
            .into_iter()
            .map(|p| (p.base64().to_encoded_hash(), p.clone()))
            .collect();

        let current_objects = OldCurrentObjects::new(map);

        OldSnapshot {
            session,
            serial,
            current_objects,
        }
    }
}
