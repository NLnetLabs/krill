use std::{
    collections::{HashMap, VecDeque},
    mem,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use chrono::Duration;
use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{MyHandle, PublisherHandle},
    },
    crypto::KeyIdentifier,
    repository::x509::Time,
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        api::rrdp::{Delta, Notification, RrdpFileRandom, RrdpSession, SnapshotData, SnapshotRef},
        eventsourcing::{
            Aggregate, AggregateStore, CommandKey, KeyStoreKey, KeyValueStore, StoredEvent, StoredValueInfo,
        },
        util::KrillVersion,
    },
    constants::{
        KRILL_VERSION, PUBSERVER_CONTENT_DIR, PUBSERVER_DFLT, PUBSERVER_DIR, REPOSITORY_RRDP_DIR, RRDP_FIRST_SERIAL,
    },
    daemon::config::Config,
    pubd::{RepositoryAccess, RepositoryAccessInitDetails, RepositoryContent, RrdpServer, RsyncdStore},
    upgrades::pre_0_9_0::{
        old_commands::{OldStorableRepositoryCommand, OldStoredEffect, OldStoredRepositoryCommand},
        old_events::{OldCurrentObjects, OldPubdEvt, OldPubdEvtDet, OldPubdInit, OldPublisher, OldRrdpSessionReset},
    },
    upgrades::{PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore},
};

use super::old_events::OldRrdpUpdate;

pub struct PubdObjectsMigration;

impl PubdObjectsMigration {
    fn repository_handle() -> MyHandle {
        MyHandle::from_str(PUBSERVER_DFLT).unwrap()
    }

    pub fn prepare(mode: UpgradeMode, config: Arc<Config>) -> UpgradeResult<()> {
        let upgrade_data_dir = config.upgrade_data_dir();
        let current_kv_store = KeyValueStore::disk(&config.data_dir, PUBSERVER_DIR)?;
        let new_kv_store = KeyValueStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;
        let new_agg_store = AggregateStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;

        let store_migration = PubdStoreMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        };

        if store_migration.needs_migrate()? {
            info!("Migrate the existing Publication Server data to the 0.9 format");
            Self::populate_repo_content(config)?;
            store_migration.prepare_new_data(mode)
        } else {
            Ok(())
        }
    }

    /// Populate the 0.9.x style repository content. Overwrite any existing content if it
    /// exists - this is expected if the operators used "prepare-upgrade" and we are now
    /// resuming the migration.
    ///
    /// NOTE: this code is not called if the migration to 0.9.x would be complete.
    fn populate_repo_content(config: Arc<Config>) -> UpgradeResult<()> {
        info!("Populate the repository content based on current state");
        let old_store = AggregateStore::<OldRepository>::disk(&config.data_dir, PUBSERVER_DIR)?;

        let repo_handle = Self::repository_handle();

        let old_repo = old_store.get_latest(&repo_handle)?;

        let publishers = old_repo
            .publishers
            .iter()
            .map(|(handle, old)| (handle.clone(), old.current_objects.clone().into()))
            .collect();

        let repo_content = RepositoryContent::new(publishers, old_repo.rrdp.clone().into(), old_repo.rsync.clone());

        let upgrade_repo_content_store = KeyValueStore::disk(&config.upgrade_data_dir(), PUBSERVER_CONTENT_DIR)?;
        let dflt_key = KeyStoreKey::scoped("0".to_string(), "snapshot.json".to_string());

        upgrade_repo_content_store.store(&dflt_key, &repo_content).unwrap();

        info!("Finished populating the repository content");

        Ok(())
    }
}

struct PubdStoreMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<RepositoryAccess>,
}

impl UpgradeStore for PubdStoreMigration {
    fn needs_migrate(&self) -> Result<bool, PrepareUpgradeError> {
        if !self.current_kv_store.has_scope("0".to_string())? {
            Ok(false)
        } else if self.version_before(KrillVersion::release(0, 6, 0))? {
            Err(PrepareUpgradeError::custom("Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version."))
        } else {
            self.version_before(KrillVersion::candidate(0, 9, 0, 1))
        }
    }

    fn prepare_new_data(&self, mode: UpgradeMode) -> Result<(), PrepareUpgradeError> {
        // check existing version, wipe if needed
        self.preparation_store_prepare()?;

        // we only have 1 pubserver '0'
        let scope = "0";
        let handle = MyHandle::from_str(scope).unwrap(); // "0" is always safe

        // Get the info from the current store to see where we are
        let mut data_upgrade_info = self.data_upgrade_info(scope)?;

        // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
        let old_cmd_keys = self.command_keys(scope, data_upgrade_info.last_command)?;

        // Migrate the initialisation event, if not done in a previous run. This
        // is a special event that has no command, so we need to do this separately.
        if data_upgrade_info.last_event == 0 {
            let init_key = Self::event_key(scope, 0);

            let old_init: OldPubdInit = self
                .current_kv_store
                .get(&init_key)?
                .ok_or_else(|| PrepareUpgradeError::custom("Cannot read pubd init event"))?;

            let (_, _, old_init) = old_init.unpack();
            let init: RepositoryAccessInitDetails = old_init.into();
            let init = StoredEvent::new(&handle, 0, init);
            self.new_kv_store.store(&init_key, &init)?;
        }

        // Report the amount of (remaining) work
        let total_commands = old_cmd_keys.len();
        if data_upgrade_info.last_command == 0 {
            info!("Will migrate {} commands for Publication Server", total_commands);
        } else {
            info!(
                "Will resume migration of {} remaining commands for Publication Server",
                total_commands
            );
        }

        // Track commands migrated and time spent so we can report progress
        let mut total_migrated = 0;
        let time_started = Time::now();

        for old_cmd_key in old_cmd_keys {
            // Do the migration counter first, so that we can just call continue when we need to skip commands
            total_migrated += 1;

            // Report progress and expected time to finish on every 100 commands evaluated.
            if total_migrated % 100 == 0 {
                // expected time: (total_migrated / (now - started)) * total

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

            // We can skip all publish commands - they are no longer used. State is kept in
            // the RepositoryObjects structure instead.
            if old_cmd_key.name().contains("pubd-publish.json") {
                continue; // There is no migration needed for these commands.
            }

            // Read and parse the old command.
            let mut old_cmd: OldStoredRepositoryCommand = self.get(&old_cmd_key)?;

            // If the command was a success, then it will have events. Successful commands
            // that resulted in no changes are simply not recorded. That said, it may turn
            // out that the event list to migrate is empty - in that case we skip this command
            // and continue the command loop.
            //
            // Note that if the command resulted in an error we do not not get 'Some' empty
            // vec of events, but we get a None. So such commands will be migrated.
            if let Some(evt_versions) = old_cmd.effect.events() {
                trace!("  command: {}", old_cmd_key);

                let mut events = vec![];
                for v in evt_versions {
                    let old_event_key = Self::event_key(scope, *v);
                    trace!("  +- event: {}", old_event_key);
                    let old_evt: OldPubdEvt = self.current_kv_store.get(&old_event_key)?.ok_or_else(|| {
                        PrepareUpgradeError::Custom(format!("Cannot parse old event: {}", old_event_key))
                    })?;

                    if old_evt.needs_migration() {
                        // track event number
                        data_upgrade_info.last_event += 1;
                        events.push(data_upgrade_info.last_event);

                        // create and store migrated event
                        let migrated_event = old_evt.into_stored_pubd_event(data_upgrade_info.last_event)?;
                        let key = KeyStoreKey::scoped(
                            scope.to_string(),
                            format!("delta-{}.json", data_upgrade_info.last_event),
                        );
                        self.new_kv_store.store(&key, &migrated_event)?;
                    }
                }

                if events.is_empty() {
                    continue; // This command has no relevant events in 0.9, so don't save it.
                }

                old_cmd.effect = OldStoredEffect::Events(events);
            }

            // Update the data_upgrade_info for progress tracking
            data_upgrade_info.last_command += 1;
            data_upgrade_info.last_update = old_cmd.time;

            // Migrate the command
            {
                old_cmd.version = data_upgrade_info.last_event + 1;
                old_cmd.sequence = data_upgrade_info.last_command;

                let migrated_cmd = old_cmd.into_pubd_command();
                let cmd_key = CommandKey::for_stored(&migrated_cmd);
                let key = KeyStoreKey::scoped(scope.to_string(), format!("{}.json", cmd_key));

                self.new_kv_store.store(&key, &migrated_cmd)?;
            }

            // Save data_upgrade_info in case the migration is stopped
            self.update_data_upgrade_info(scope, &data_upgrade_info)?;
        }

        info!("Finished migrating Publication Server commands");

        // Create a new info file for the new aggregate repository
        {
            let info = StoredValueInfo::from(&data_upgrade_info);
            let info_key = KeyStoreKey::scoped(scope.to_string(), "info.json".to_string());
            self.new_kv_store.store(&info_key, &info)?;
        }

        // Verify migration
        info!("Will verify the migration by rebuilding the Publication Server from events");
        let repo_access = self.new_agg_store.get_latest(&handle).map_err(|e| {
            PrepareUpgradeError::Custom(format!(
                "Could not rebuild state after migrating pubd! Error was: {}.",
                e
            ))
        })?;

        // Store snapshot to avoid having to re-process the deltas again in future
        self.new_agg_store
            .store_snapshot(&handle, repo_access.as_ref())
            .map_err(|e| {
                PrepareUpgradeError::Custom(format!(
                    "Could not save snapshot after migration! Disk full?!? Error was: {}.",
                    e
                ))
            })?;

        match mode {
            UpgradeMode::PrepareOnly => {
                info!(
                    "Prepared Publication Server data migration to version {}. Will save progress for final upgrade when Krill restarts.",
                    KRILL_VERSION
                );
            }
            UpgradeMode::PrepareToFinalise => {
                info!(
                    "Prepared Publication Server data migration to version {}.",
                    KRILL_VERSION
                );
                self.remove_data_upgrade_info(scope)?;
            }
        }

        Ok(())
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }
}

/// Pre 0.9 Repository which combines the access (ID) functions, and content. Starting with 0.9 these
/// responsibilities will be handled by two separate components. For this migration we need to parse
/// the old repository structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct OldRepository {
    // Event sourcing support
    handle: MyHandle,
    version: u64,

    id_cert: IdCert,
    key_id: KeyIdentifier, // convenience access to id_cert pub key id

    publishers: HashMap<PublisherHandle, OldPublisher>,

    rrdp: OldRrdpServer,
    rsync: RsyncdStore,
}

impl Aggregate for OldRepository {
    type Command = OldStoredRepositoryCommand;
    type StorableCommandDetails = OldStorableRepositoryCommand;
    type Event = OldPubdEvt;
    type InitEvent = OldPubdInit; // no change needed from < 0.9
    type Error = PrepareUpgradeError;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();
        let (id_cert, session, rrdp_base_uri, rsync_jail, repo_base_dir) = details.unpack();

        let key_id = id_cert.subject_public_key_info().key_identifier();

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
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            OldPubdEvtDet::PublisherAdded(publisher_handle, publisher) => {
                self.publishers.insert(publisher_handle, publisher);
            }
            OldPubdEvtDet::PublisherRemoved(publisher_handle, update) => {
                self.publishers.remove(&publisher_handle);
                self.rrdp.apply_update(update);
            }
            OldPubdEvtDet::Published(publisher_handle, update) => {
                // update content for publisher
                self.update_publisher(&publisher_handle, &update);

                // update RRDP server
                self.rrdp.apply_update(update);
            }
            OldPubdEvtDet::RrdpSessionReset(reset) => {
                self.rrdp.apply_reset(reset);
            }
        }
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        unreachable!("no need to process commands for migration")
    }
}

impl OldRepository {
    fn update_publisher(&mut self, publisher: &PublisherHandle, update: &OldRrdpUpdate) {
        self.publishers
            .get_mut(publisher)
            .unwrap()
            .apply_delta(update.elements().clone())
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
    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &Path, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = repo_dir.to_path_buf();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let snapshot = OldSnapshot::create(session);

        let serial = RRDP_FIRST_SERIAL;
        let snapshot_uri = Self::new_snapshot_uri(&rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&rrdp_base_dir, &session, serial);
        let snapshot_hash = Hash::from_data(snapshot.xml().as_slice());

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
    fn apply_update(&mut self, update: OldRrdpUpdate) {
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

    fn apply_reset(&mut self, reset: OldRrdpSessionReset) {
        let (snapshot, notification) = reset.unpack();

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.old_notifications.clear();
        self.snapshot = snapshot;
        self.deltas = vec![];
    }
}

/// URI support
impl OldRrdpServer {
    fn snapshot_rel(session: &RrdpSession, serial: u64) -> String {
        format!("{}/{}/snapshot.xml", session, serial)
    }

    fn new_snapshot_path(base: &Path, session: &RrdpSession, serial: u64) -> PathBuf {
        let mut path = base.to_path_buf();
        path.push(Self::snapshot_rel(session, serial));
        path
    }

    fn new_snapshot_uri(base: &uri::Https, session: &RrdpSession, serial: u64) -> uri::Https {
        base.join(Self::snapshot_rel(session, serial).as_ref()).unwrap()
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
        self.to_snapshot().xml(self.session, self.serial)
    }

    fn to_snapshot(&self) -> SnapshotData {
        self.clone().into()
    }
}

impl From<OldSnapshot> for SnapshotData {
    fn from(old: OldSnapshot) -> Self {
        SnapshotData::new(RrdpFileRandom::default(), old.current_objects.into())
    }
}
