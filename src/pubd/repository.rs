use std::{
    collections::{HashMap, VecDeque},
    fmt, fs, mem,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange,
        idexchange::{MyHandle, PublisherHandle, RepoInfo},
        publication,
        publication::{ListReply, PublicationCms, PublishDelta},
    },
    repository::{crypto::KeyIdentifier, x509::Time},
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::rrdp::{
            CurrentObjects, Delta, DeltaElements, DeltaRef, FileRef, Notification, RrdpSession, Snapshot, SnapshotRef,
        },
        api::{PublicationServerUris, StorableRepositoryCommand},
        crypto::KrillSigner,
        error::{Error, KrillIoError},
        eventsourcing::{Aggregate, AggregateStore, KeyStoreKey, KeyValueStore},
        util::file,
        KrillResult,
    },
    constants::{
        PUBSERVER_CONTENT_DIR, PUBSERVER_DFLT, PUBSERVER_DIR, REPOSITORY_DIR, REPOSITORY_RRDP_ARCHIVE_DIR,
        REPOSITORY_RRDP_DIR, REPOSITORY_RSYNC_DIR, RRDP_FIRST_SERIAL,
    },
    daemon::config::{Config, RepositoryRetentionConfig},
    pubd::{
        publishers::Publisher, RepoAccessCmd, RepoAccessCmdDet, RepositoryAccessEvent, RepositoryAccessEventDetails,
        RepositoryAccessIni, RepositoryAccessInitDetails,
    },
};

//------------ RepositoryContentProxy ----------------------------------------

/// We can only have one (1) RepositoryContent, but it is stored
/// in a KeyValueStore. So this type provides a wrapper around this
/// so that callers don't need to worry about storage details.
#[derive(Debug)]
pub struct RepositoryContentProxy {
    cache: RwLock<Option<RepositoryContent>>,
    store: RwLock<KeyValueStore>,
    key: KeyStoreKey,
}

impl RepositoryContentProxy {
    pub fn disk(config: &Config) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let store = KeyValueStore::disk(work_dir, PUBSERVER_CONTENT_DIR)?;
        let store = RwLock::new(store);
        let key = KeyStoreKey::simple(format!("{}.json", PUBSERVER_DFLT));
        let cache = RwLock::new(None);

        let proxy = RepositoryContentProxy { cache, store, key };
        proxy.warm_cache()?;

        Ok(proxy)
    }

    fn warm_cache(&self) -> KrillResult<()> {
        let key_store_read = self.store.read().unwrap();

        if key_store_read.has(&self.key)? {
            info!("Warming the repository content cache, this can take a minute for large repositories.");
            let content = key_store_read.get(&self.key)?.unwrap();
            self.cache.write().unwrap().replace(content);
            info!("Repository content cache has been warmed.");
        }

        Ok(())
    }

    /// Initialize
    pub fn init(&self, work_dir: &Path, uris: PublicationServerUris) -> KrillResult<()> {
        if self.store.read().unwrap().has(&self.key)? {
            Err(Error::RepositoryServerAlreadyInitialized)
        } else {
            // initialize new repo content
            let repository_content = {
                let (rrdp_base_uri, rsync_jail) = uris.unpack();

                let publishers = HashMap::new();

                let session = RrdpSession::default();
                let stats = RepoStats::new(session);

                let mut repo_dir = work_dir.to_path_buf();
                repo_dir.push(REPOSITORY_DIR);

                let rrdp = RrdpServer::create(rrdp_base_uri, &repo_dir, session);
                let rsync = RsyncdStore::new(rsync_jail, &repo_dir);

                RepositoryContent::new(publishers, rrdp, rsync, stats)
            };

            // Store newly initialized repo content on disk
            let store = self.store.write().unwrap();
            store.store(&self.key, &repository_content)?;

            // Store newly initialized repo content in cache
            let mut cache = self.cache.write().unwrap();
            cache.replace(repository_content);

            Ok(())
        }
    }

    // Clear all content, so it can be re-initialized.
    // Only to be called after all publishers have been removed from the RepoAccess as well.
    pub fn clear(&self) -> KrillResult<()> {
        let store = self.store.write().unwrap();

        if let Ok(Some(content)) = store.get::<RepositoryContent>(&self.key) {
            content.clear();
            store.drop_key(&self.key)?;
        }

        let mut cache = self.cache.write().unwrap();
        cache.take();

        Ok(())
    }

    /// Return the repository content stats
    pub fn stats(&self) -> KrillResult<RepoStats> {
        self.read(|content| Ok(content.stats().clone()))
    }

    /// Add a publisher with an empty set of published objects.
    ///
    /// Replaces an existing publisher if it existed.
    /// This is only supposed to be called if adding the publisher
    /// to the RepositoryAccess was successful (and *that* will fail if
    /// the publisher is a duplicate). This method can only fail if
    /// there is an issue with the underlying key value store.
    pub fn add_publisher(&self, name: PublisherHandle) -> KrillResult<()> {
        self.write(|content| content.add_publisher(name))
    }

    /// Removes a publisher and its content.
    pub fn remove_publisher(
        &self,
        name: &PublisherHandle,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        self.write(|content| content.remove_publisher(name, jail, config))
    }

    /// Publish an update for a publisher.
    ///
    /// Assumes that the RFC 8181 CMS has been verified, but will check that all objects
    /// are within the publisher's uri space (jail).
    pub fn publish(
        &self,
        name: &PublisherHandle,
        delta: PublishDelta,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        self.write(|content| content.publish(name, delta.into(), jail, config))
    }

    /// Write all current files to disk
    pub fn write_repository(&self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        self.read(|content| content.write_repository(config))
    }

    /// Reset the RRDP session if it is initialized. Otherwise do nothing.
    pub fn session_reset(&self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        if self.cache.read().unwrap().is_some() {
            self.write(|content| content.session_reset(config))
        } else {
            // repository server was not initialized on this Krill instance. Nothing to reset.
            Ok(())
        }
    }

    /// Create a list reply containing all current objects for a publisher
    pub fn list_reply(&self, name: &PublisherHandle) -> KrillResult<ListReply> {
        self.read(|content| content.list_reply(name))
    }

    // Get all current objects for a publisher
    pub fn current_objects(&self, name: &PublisherHandle) -> KrillResult<CurrentObjects> {
        self.read(|content| content.objects_for_publisher(name).map(|o| o.clone()))
    }

    // Execute a closure on a mutable repository content in a single write 'transaction'
    fn write<F: FnOnce(&mut RepositoryContent) -> KrillResult<()>>(&self, op: F) -> KrillResult<()> {
        // If there is any existing content, then we can assume that the cache
        // has it - because it's initialized when we read the content during
        // initialization.
        let store = self.store.write().unwrap();
        let mut cache = self.cache.write().unwrap();

        let content: &mut RepositoryContent = cache.as_mut().ok_or(Error::RepositoryServerNotInitialized)?;

        op(content)?;

        store.store(&self.key, content)?;
        Ok(())
    }

    // Execute a closure on a mutable repository content in a single read 'transaction'
    //
    // This function fails if the repository content is not initialized.
    fn read<A, F: FnOnce(&RepositoryContent) -> KrillResult<A>>(&self, op: F) -> KrillResult<A> {
        // Note that because the content is initialized it is implied that the cache MUST always be
        // set. I.e. it is set on initialization and updated whenever the repository content is updated.
        // So, we can safely read from the cache only.
        let cache = self.cache.read().unwrap();
        let content = cache.as_ref().ok_or(Error::RepositoryServerNotInitialized)?;
        op(content)
    }
}

//------------ RepositoryContent -------------------------------------------

/// This type manages the content of the repository. Note that access
/// to the repository is managed by an event sourced component which
/// handles RFC8181 based access, and which can enforce restrictions,
/// such as the base uri for publishers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryContent {
    publishers: HashMap<PublisherHandle, CurrentObjects>,

    rrdp: RrdpServer,
    rsync: RsyncdStore,

    stats: RepoStats,
}

impl RepositoryContent {
    pub fn new(
        publishers: HashMap<PublisherHandle, CurrentObjects>,
        rrdp: RrdpServer,
        rsync: RsyncdStore,
        stats: RepoStats,
    ) -> Self {
        RepositoryContent {
            publishers,
            rrdp,
            rsync,
            stats,
        }
    }

    pub fn init(rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync, session: RrdpSession, repo_base_dir: &Path) -> Self {
        let publishers = HashMap::new();
        let rrdp = RrdpServer::create(rrdp_base_uri, repo_base_dir, session);
        let rsync = RsyncdStore::new(rsync_jail, repo_base_dir);
        let stats = RepoStats::new(session);

        RepositoryContent {
            publishers,
            rrdp,
            rsync,
            stats,
        }
    }

    // Clears all content on disk so the repository can be re-initialized
    pub fn clear(&self) {
        self.rrdp.clear();
        self.rsync.clear();
    }

    pub fn stats(&self) -> &RepoStats {
        &self.stats
    }
}

/// # Publisher Content
impl RepositoryContent {
    fn objects_for_publisher(&self, publisher: &PublisherHandle) -> KrillResult<&CurrentObjects> {
        self.publishers
            .get(publisher)
            .ok_or_else(|| Error::PublisherUnknown(publisher.clone()))
    }

    fn objects_for_publisher_mut(&mut self, publisher: &PublisherHandle) -> KrillResult<&mut CurrentObjects> {
        self.publishers
            .get_mut(publisher)
            .ok_or_else(|| Error::PublisherUnknown(publisher.clone()))
    }

    /// Gets a list reply containing all objects for this publisher.
    pub fn list_reply(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.objects_for_publisher(publisher).map(|o| o.to_list_reply())
    }

    pub fn publish(
        &mut self,
        name: &PublisherHandle,
        delta: DeltaElements,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        // update publisher, this will fail if the publisher tries
        // to update outside of its jail.
        let objects = self.objects_for_publisher_mut(name)?;
        objects.apply_delta(delta.clone(), jail)?;
        let publisher_stats = PublisherStats::new(objects, Time::now());

        // update the RRDP server
        self.rrdp.publish(delta, jail, config)?;

        // write repo (note rsync is based on updated rrdp snapshot)
        self.write_repository(config)?;

        // Update publisher stats
        self.stats.publish(name, publisher_stats, self.rrdp.notification());

        Ok(())
    }

    pub fn session_reset(&mut self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        info!(
            "Performing RRDP session reset. This ensures a consistent view for RPs in case we restarted from a backup."
        );

        self.rrdp.session_reset();
        self.stats.session_reset(self.rrdp.notification());
        self.write_repository(config)?;

        Ok(())
    }

    pub fn write_repository(&self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        self.rrdp.write(config)?;
        self.rsync.write(self.rrdp.snapshot())
    }

    pub fn add_publisher(&mut self, name: PublisherHandle) -> KrillResult<()> {
        self.stats.new_publisher(&name);
        self.publishers.insert(name, CurrentObjects::default());
        Ok(())
    }

    /// Removes the content for a publisher. This function will return
    /// ok if there is no content to remove - it is idempotent in that
    /// sense. However, if there are I/O errors removing the content then
    /// this function will fail.
    pub fn remove_publisher(
        &mut self,
        name: &PublisherHandle,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        if let Ok(objects) = self.objects_for_publisher(name) {
            let withdraws = objects.elements().iter().map(|e| e.as_withdraw()).collect();
            let delta = DeltaElements::new(vec![], vec![], withdraws);

            self.rrdp.publish(delta, jail, config)?;
            self.stats.remove_publisher(name, self.rrdp.notification());

            self.write_repository(config)
        } else {
            // nothing to remove
            Ok(())
        }
    }
}

//------------ RsyncdStore ---------------------------------------------------

/// This type is responsible for publishing files on disk in a structure so
/// that an rsyncd can be set up to serve this (RPKI) data. Note that the
/// rsync host name and module are part of the path, so make sure that the
/// rsyncd modules and paths are setup properly for each supported rsync
/// base uri used.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RsyncdStore {
    base_uri: uri::Rsync,
    rsync_dir: PathBuf,
    #[serde(skip_serializing, skip_deserializing, default = "RsyncdStore::new_lock")]
    lock: Arc<RwLock<()>>,
}

/// # Construct
///
impl RsyncdStore {
    pub fn new_lock() -> Arc<RwLock<()>> {
        Arc::new(RwLock::new(()))
    }

    pub fn new(base_uri: uri::Rsync, repo_dir: &Path) -> Self {
        let mut rsync_dir = repo_dir.to_path_buf();
        rsync_dir.push(REPOSITORY_RSYNC_DIR);
        let lock = Self::new_lock();
        RsyncdStore {
            base_uri,
            rsync_dir,
            lock,
        }
    }
}

/// # Publishing
///
impl RsyncdStore {
    /// Write all the files to disk for rsync to a tmp-dir, then switch
    /// things over in an effort to minimize the chance of people getting
    /// inconsistent syncs..
    pub fn write(&self, snapshot: &Snapshot) -> KrillResult<()> {
        let _lock = self
            .lock
            .write()
            .map_err(|_| Error::custom("Could not get write lock for rsync repo"))?;

        let mut new_dir = self.rsync_dir.clone();
        new_dir.push(&format!("tmp-{}", snapshot.serial()));
        fs::create_dir_all(&new_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not create dir(s) '{}' for publishing rsync",
                    new_dir.to_string_lossy()
                ),
                e,
            )
        })?;

        let elements = snapshot.elements();

        for publish in elements {
            let rel = publish
                .uri()
                .relative_to(&self.base_uri)
                .ok_or_else(|| Error::publishing_outside_jail(publish.uri(), &self.base_uri))?;

            let mut path = new_dir.clone();
            path.push(rel);

            file::save(&publish.base64().to_bytes(), &path)?;
        }

        let mut current_dir = self.rsync_dir.clone();
        current_dir.push("current");

        let mut old_dir = self.rsync_dir.clone();
        old_dir.push("old");

        if current_dir.exists() {
            fs::rename(&current_dir, &old_dir).map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not rename current rsync dir from '{}' to '{}' while publishing",
                        current_dir.to_string_lossy(),
                        old_dir.to_string_lossy()
                    ),
                    e,
                )
            })?;
        }

        fs::rename(&new_dir, &current_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not rename new rsync dir from '{}' to '{}' while publishing",
                    new_dir.to_string_lossy(),
                    current_dir.to_string_lossy()
                ),
                e,
            )
        })?;

        if old_dir.exists() {
            fs::remove_dir_all(&old_dir).map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not remove up old rsync dir '{}' while publishing",
                        old_dir.to_string_lossy()
                    ),
                    e,
                )
            })?;
        }

        Ok(())
    }

    fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rsync_dir);
    }
}

/// The RRDP server used by a Repository instance
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RrdpServer {
    /// The base URI for notification, snapshot and delta files.
    rrdp_base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    rrdp_base_dir: PathBuf,
    rrdp_archive_dir: PathBuf,

    session: RrdpSession,
    serial: u64,
    notification: Notification,

    #[serde(skip_serializing_if = "VecDeque::is_empty", default = "VecDeque::new")]
    old_notifications: VecDeque<Notification>,

    snapshot: Snapshot,
    deltas: VecDeque<Delta>,
}

impl RrdpServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rrdp_base_uri: uri::Https,
        rrdp_base_dir: PathBuf,
        rrdp_archive_dir: PathBuf,
        session: RrdpSession,
        serial: u64,
        notification: Notification,
        old_notifications: VecDeque<Notification>,
        snapshot: Snapshot,
        deltas: VecDeque<Delta>,
    ) -> Self {
        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            notification,
            old_notifications,
            snapshot,
            deltas,
        }
    }

    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &Path, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = repo_dir.to_path_buf();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let mut rrdp_archive_dir = repo_dir.to_path_buf();
        rrdp_archive_dir.push(REPOSITORY_RRDP_ARCHIVE_DIR);

        let snapshot = Snapshot::create(session);

        let serial = RRDP_FIRST_SERIAL;
        let snapshot_uri = snapshot.uri(&rrdp_base_uri);
        let snapshot_path = snapshot.path(&rrdp_base_dir);
        let snapshot_hash = Hash::from_data(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            notification,
            snapshot,
            old_notifications: VecDeque::new(),
            deltas: VecDeque::new(),
        }
    }

    fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rrdp_base_dir);
        let _ = fs::remove_dir_all(&self.rrdp_archive_dir);
    }

    fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn notification(&self) -> &Notification {
        &self.notification
    }

    /// Performs a session reset of the RRDP server. Useful if the serial needs
    /// to be rolled, or in case the RRDP server needed to recover to a previous
    /// state.
    fn session_reset(&mut self) {
        let session = RrdpSession::random();
        let snapshot = self.snapshot.session_reset(session);

        let snapshot_uri = snapshot.uri(&self.rrdp_base_uri);
        let snapshot_path = snapshot.path(&self.rrdp_base_dir);
        let snapshot_hash = Hash::from_data(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.old_notifications.clear();
        self.snapshot = snapshot;
        self.deltas = VecDeque::new();
    }

    /// Updates the RRDP server with the elements. Note that this assumes that
    /// the delta has already been checked against the jail and current
    /// objects of the publisher.
    fn publish(
        &mut self,
        elements: DeltaElements,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        if elements.is_empty() {
            Ok(())
        } else {
            // Update the snapshot, this can fail if the delta is illegal.
            self.snapshot.apply_delta(elements.clone(), jail)?;
            self.serial += 1;

            self.update_deltas(elements, config);
            self.update_notification(config);

            Ok(())
        }
    }

    // Push the delta and truncate excessive deltas:
    //  - never keep more than the size of the snapshot
    //  - always keep 'retention_delta_files_min_nr' files
    //  - always keep 'retention_delta_files_min_seconds' files
    //  - beyond this:
    //     - never keep more than 'retention_delta_files_max_nr'
    //     - never keep older than 'retention_delta_files_max_seconds'
    //     - keep the others
    fn update_deltas(&mut self, elements: DeltaElements, config: &RepositoryRetentionConfig) {
        self.deltas.push_front(Delta::new(self.session, self.serial, elements));
        let mut keep = 0;
        let mut size = 0;
        let snapshot_size = self.snapshot.size();

        let min_nr = config.retention_delta_files_min_nr;
        let min_secs = config.retention_delta_files_min_seconds;
        let max_nr = config.retention_delta_files_max_nr;
        let max_secs = config.retention_delta_files_max_seconds;

        for delta in &self.deltas {
            size += delta.elements().size();

            if size > snapshot_size {
                // never keep more than the size of the snapshot
                break;
            } else if keep < min_nr || delta.younger_than_seconds(min_secs) {
                // always keep 'retention_delta_files_min_nr' files
                // always keep 'retention_delta_files_min_seconds' file
                keep += 1
            } else if keep == max_nr || delta.older_than_seconds(max_secs) {
                // never keep more than 'retention_delta_files_max_nr'
                // never keep older than 'retention_delta_files_max_seconds'
                break;
            } else {
                // keep the remainder
                keep += 1;
            }
        }
        self.deltas.truncate(keep);
    }

    // Update the notification to include the current snapshot and
    // deltas. Remove old notifications exceeding the retention time,
    // so that we can delete old snapshots and deltas which are no longer
    // relevant.
    fn update_notification(&mut self, config: &RepositoryRetentionConfig) {
        let snapshot_ref = {
            let snapshot_uri = self.snapshot.uri(&self.rrdp_base_uri);
            let snapshot_path = self.snapshot.path(&self.rrdp_base_dir);
            let snapshot_xml = self.snapshot.xml();
            let snapshot_hash = Hash::from_data(snapshot_xml.as_slice());
            SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash)
        };

        let delta_refs = self
            .deltas
            .iter()
            .map(|delta| {
                let serial = delta.serial();
                let xml = delta.xml();
                let hash = Hash::from_data(xml.as_slice());

                let delta_uri = delta.uri(&self.rrdp_base_uri);
                let delta_path = delta.path(&self.rrdp_base_dir);
                let file_ref = FileRef::new(delta_uri, delta_path, hash);
                DeltaRef::new(serial, file_ref)
            })
            .collect();

        let mut notification = Notification::new(self.session, self.serial, snapshot_ref, delta_refs);

        mem::swap(&mut self.notification, &mut notification);
        notification.replace(self.notification.time());
        self.old_notifications.push_front(notification);

        self.old_notifications
            .retain(|n| !n.older_than_seconds(config.retention_old_notification_files_seconds));
    }

    /// Write the (missing) RRDP files to disk, and remove the ones
    /// no longer referenced in the notification file.
    fn write(&self, config: &RepositoryRetentionConfig) -> Result<(), Error> {
        // write snapshot if it's not there
        let snapshot_path = self.snapshot.path(&self.rrdp_base_dir);
        if !snapshot_path.exists() {
            self.snapshot.write_xml(&snapshot_path)?;
        }

        // write deltas if they are not there
        for delta in &self.deltas {
            let path = delta.path(&self.rrdp_base_dir);
            if !path.exists() {
                // assume that if the delta exists, it is correct
                delta.write_xml(&path)?;
            }
        }

        // write notification file
        let notification_path_new = self.notification_path_new();
        let notification_path = self.notification_path();
        self.notification.write_xml(&notification_path_new)?;
        fs::rename(&notification_path_new, &notification_path).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not rename notification file from '{}' to '{}'",
                    notification_path_new.to_string_lossy(),
                    notification_path.to_string_lossy()
                ),
                e,
            )
        })?;

        // clean up under the base dir:
        // - old session dirs
        for entry in fs::read_dir(&self.rrdp_base_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not read RRDP base directory '{}'",
                    self.rrdp_base_dir.to_string_lossy()
                ),
                e,
            )
        })? {
            let entry = entry.map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not read entry in RRDP base directory '{}'",
                        self.rrdp_base_dir.to_string_lossy()
                    ),
                    e,
                )
            })?;
            if self.session.to_string() == entry.file_name().to_string_lossy() {
                continue;
            } else {
                let path = entry.path();
                if path.is_dir() {
                    let _best_effort_rm = fs::remove_dir_all(path);
                }
            }
        }

        // clean up under the current session
        let mut session_dir = self.rrdp_base_dir.clone();
        session_dir.push(self.session.to_string());

        for entry in fs::read_dir(&session_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not read RRDP session directory '{}'",
                    session_dir.to_string_lossy()
                ),
                e,
            )
        })? {
            let entry = entry.map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not read entry in RRDP session directory '{}'",
                        session_dir.to_string_lossy()
                    ),
                    e,
                )
            })?;
            let path = entry.path();

            // remove any dir or file that is:
            // - not a number
            // - a number that is higher than the current serial
            // - a number that is lower than the last delta (if set)
            if let Ok(serial) = u64::from_str(entry.file_name().to_string_lossy().as_ref()) {
                // Skip the current serial
                if serial == self.serial {
                    continue;
                // Clean up old serial dirs once deltas are out of scope
                } else if !self.notification.includes_delta(serial)
                    && !self.old_notifications.iter().any(|n| n.includes_delta(serial))
                {
                    if config.retention_archive {
                        // If archiving is enabled, then move these directories under the archive base

                        let mut dest = self.rrdp_archive_dir.clone();
                        dest.push(self.session.to_string());
                        dest.push(format!("{}", serial));

                        info!("Archiving RRDP serial '{}' to '{}", serial, dest.to_string_lossy());
                        let _ = fs::create_dir_all(&dest);
                        let _ = fs::rename(path, dest);
                    } else if path.is_dir() {
                        let _best_effort_rm = fs::remove_dir_all(path);
                    } else {
                        let _best_effort_rm = fs::remove_file(path);
                    }
                // We still need this old serial dir for the delta, but may not need the snapshot
                // in it unless archiving is enabled.. in that case leave them and move them when
                // the complete serial dir goes out of scope above.
                } else if !config.retention_archive
                    && !self
                        .old_notifications
                        .iter()
                        .any(|old_notification| old_notification.includes_snapshot(serial))
                {
                    // see if the there is a snapshot file in this serial dir and if so do a best
                    // effort removal.
                    if let Ok(Some(snapshot_file_to_remove)) = Self::session_dir_snapshot(&session_dir, serial) {
                        // snapshot files are stored under their own unique random dir, e.g:
                        // <session_dir>/<serial>/<random>/snapshot.xml
                        //
                        // So also remove the otherwise empty parent directory.
                        if let Some(snapshot_parent_dir) = snapshot_file_to_remove.parent() {
                            let _ = fs::remove_dir_all(snapshot_parent_dir);
                        }
                    }
                } else {
                    // we still need this
                }
            } else {
                // clean up dirs or files under the base dir which are not sessions
                warn!(
                    "Found unexpected file or dir in RRDP repository - will try to remove: {}",
                    path.to_string_lossy()
                );
                if path.is_dir() {
                    let _best_effort_rm = fs::remove_dir_all(path);
                } else {
                    let _best_effort_rm = fs::remove_file(path);
                }
            }
        }

        Ok(())
    }
}

/// rrdp paths and uris
///
impl RrdpServer {
    pub fn notification_uri(&self) -> uri::Https {
        self.rrdp_base_uri.join(b"notification.xml").unwrap()
    }

    fn notification_path_new(&self) -> PathBuf {
        let mut path = self.rrdp_base_dir.clone();
        path.push("new-notification.xml");
        path
    }

    fn notification_path(&self) -> PathBuf {
        let mut path = self.rrdp_base_dir.clone();
        path.push("notification.xml");
        path
    }

    pub fn session_dir_snapshot(session_path: &Path, serial: u64) -> KrillResult<Option<PathBuf>> {
        Self::find_in_serial_dir(session_path, serial, "snapshot.xml")
    }

    /// Expects files (like delta.xml or snapshot.xml) under dir structure like:
    /// <session_path>/<serial>/<some random>/<filename>
    pub fn find_in_serial_dir(session_path: &Path, serial: u64, filename: &str) -> KrillResult<Option<PathBuf>> {
        let serial_dir = session_path.join(serial.to_string());
        if let Ok(randoms) = fs::read_dir(&serial_dir) {
            for entry in randoms {
                let entry = entry.map_err(|e| {
                    Error::io_error_with_context(
                        format!(
                            "Could not open directory entry under RRDP directory {}",
                            serial_dir.to_string_lossy()
                        ),
                        e,
                    )
                })?;
                if let Ok(files) = fs::read_dir(entry.path()) {
                    for file in files {
                        let file = file.map_err(|e| {
                            Error::io_error_with_context(
                                format!(
                                    "Could not open directory entry under RRDP directory {}",
                                    entry.path().to_string_lossy()
                                ),
                                e,
                            )
                        })?;
                        if file.file_name().to_string_lossy() == filename {
                            return Ok(Some(file.path()));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

/// We can only have one (1) RepositoryAccess, but it is an event-sourced
/// typed which is stored in an AggregateStore which could theoretically
/// serve multiple. So, we use RepositoryAccessProxy as a wrapper around
/// this so that callers don't need to worry about storage details.
pub struct RepositoryAccessProxy {
    store: AggregateStore<RepositoryAccess>,
    key: MyHandle,
}

impl RepositoryAccessProxy {
    pub fn disk(config: &Config) -> KrillResult<Self> {
        let store = AggregateStore::<RepositoryAccess>::disk(&config.data_dir, PUBSERVER_DIR)?;
        let key = MyHandle::from_str(PUBSERVER_DFLT).unwrap();

        if store.has(&key)? {
            if config.always_recover_data {
                store.recover()?;
            } else if let Err(e) = store.warm() {
                error!(
                    "Could not warm up cache, storage seems corrupt, will try to recover!! Error was: {}",
                    e
                );
                store.recover()?;
            }
        }

        Ok(RepositoryAccessProxy { store, key })
    }

    pub fn initialized(&self) -> KrillResult<bool> {
        self.store.has(&self.key).map_err(Error::AggregateStoreError)
    }

    pub fn init(&self, uris: PublicationServerUris, signer: &KrillSigner) -> KrillResult<()> {
        if self.initialized()? {
            Err(Error::RepositoryServerAlreadyInitialized)
        } else {
            let (rrdp_base_uri, rsync_jail) = uris.unpack();

            let ini = RepositoryAccessInitDetails::init(&self.key, rsync_jail, rrdp_base_uri, signer)?;

            self.store.add(ini)?;

            Ok(())
        }
    }

    pub fn clear(&self) -> KrillResult<()> {
        if !self.initialized()? {
            Err(Error::RepositoryServerNotInitialized)
        } else if !self.publishers()?.is_empty() {
            Err(Error::RepositoryServerHasPublishers)
        } else {
            self.store.drop_aggregate(&self.key)?;
            Ok(())
        }
    }

    fn read(&self) -> KrillResult<Arc<RepositoryAccess>> {
        if !self.initialized()? {
            Err(Error::RepositoryServerNotInitialized)
        } else {
            self.store
                .get_latest(&self.key)
                .map_err(|e| Error::custom(format!("Publication Server data issue: {}", e)))
        }
    }

    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        Ok(self.read()?.publishers())
    }

    pub fn get_publisher(&self, name: &PublisherHandle) -> KrillResult<Publisher> {
        self.read()?.get_publisher(name).map(|p| p.clone())
    }

    pub fn add_publisher(&self, req: idexchange::PublisherRequest, actor: &Actor) -> KrillResult<()> {
        let base_uri = self.read()?.base_uri_for(req.publisher_handle())?; // will verify that server was initialized
        let cmd = RepoAccessCmdDet::add_publisher(&self.key, req, base_uri, actor);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
        if !self.initialized()? {
            Err(Error::RepositoryServerNotInitialized)
        } else {
            let cmd = RepoAccessCmdDet::remove_publisher(&self.key, name, actor);
            self.store.command(cmd)?;
            Ok(())
        }
    }

    /// Returns the repository URI information for a publisher.
    pub fn repo_info_for(&self, name: &PublisherHandle) -> KrillResult<RepoInfo> {
        self.read()?.repo_info_for(name)
    }

    /// Returns the RFC8183 Repository Response for the publisher
    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher: &PublisherHandle,
    ) -> KrillResult<idexchange::RepositoryResponse> {
        self.read()?.repository_response(rfc8181_uri, publisher)
    }

    /// Parse submitted bytes by a Publisher as an RFC8181 ProtocolCms object, and validates it.
    pub fn decode_and_validate(
        &self,
        publisher: &PublisherHandle,
        bytes: &[u8],
    ) -> KrillResult<publication::PublicationCms> {
        let publisher = self.get_publisher(publisher)?;
        let msg = PublicationCms::decode(bytes).map_err(Error::Rfc8181)?;
        msg.validate(publisher.id_cert()).map_err(Error::Rfc8181)?;
        Ok(msg)
    }

    // /// Creates and signs an RFC8181 CMS response.
    pub fn respond(
        &self,
        message: publication::Message,
        signer: &KrillSigner,
    ) -> KrillResult<publication::PublicationCms> {
        let key_id = self.read()?.key_id();
        signer.create_rfc8181_cms(message, &key_id).map_err(Error::signer)
    }
}

//------------ RepositoryAccess --------------------------------------------

/// An RFC8181 Repository server, capable of handling Publishers (both embedded, and
/// remote RFC8181), and publishing to RRDP and disk, and signing responses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryAccess {
    // Event sourcing support
    handle: MyHandle,
    version: u64,

    id_cert: IdCert,
    publishers: HashMap<PublisherHandle, Publisher>,

    rsync_base: uri::Rsync,
    rrdp_base: uri::Https,
}

impl RepositoryAccess {
    pub fn key_id(&self) -> KeyIdentifier {
        self.id_cert.subject_public_key_info().key_identifier()
    }
}

/// # Event Sourcing support
///
impl Aggregate for RepositoryAccess {
    type Command = RepoAccessCmd;
    type StorableCommandDetails = StorableRepositoryCommand;
    type Event = RepositoryAccessEvent;
    type InitEvent = RepositoryAccessIni;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();
        let (id_cert, rrdp_base, rsync_base) = details.unpack();

        Ok(RepositoryAccess {
            handle,
            version: 1,
            id_cert,
            publishers: HashMap::new(),
            rsync_base,
            rrdp_base,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            RepositoryAccessEventDetails::PublisherAdded { name, publisher } => {
                self.publishers.insert(name, publisher);
            }
            RepositoryAccessEventDetails::PublisherRemoved { name } => {
                self.publishers.remove(&name);
            }
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        info!(
            "Sending command to publisher '{}', version: {}: {}",
            self.handle, self.version, command
        );

        match command.into_details() {
            RepoAccessCmdDet::AddPublisher { request, base_uri } => self.add_publisher(request, base_uri),
            RepoAccessCmdDet::RemovePublisher { name } => self.remove_publisher(name),
        }
    }
}

/// # Manage publishers
///
impl RepositoryAccess {
    /// Adds a publisher with access to the repository
    fn add_publisher(
        &self,
        publisher_request: idexchange::PublisherRequest,
        base_uri: uri::Rsync,
    ) -> Result<Vec<RepositoryAccessEvent>, Error> {
        let (id_cert, name, _tag) = publisher_request.unpack();

        if self.publishers.contains_key(&name) {
            Err(Error::PublisherDuplicate(name))
        } else {
            let publisher = Publisher::new(id_cert, base_uri);

            Ok(vec![RepositoryAccessEventDetails::publisher_added(
                &self.handle,
                self.version,
                name,
                publisher,
            )])
        }
    }

    /// Removes a publisher and all its content
    fn remove_publisher(&self, publisher_handle: PublisherHandle) -> Result<Vec<RepositoryAccessEvent>, Error> {
        if !self.has_publisher(&publisher_handle) {
            Err(Error::PublisherUnknown(publisher_handle))
        } else {
            Ok(vec![RepositoryAccessEventDetails::publisher_removed(
                &self.handle,
                self.version,
                publisher_handle,
            )])
        }
    }

    fn notification_uri(&self) -> uri::Https {
        self.rrdp_base.join(b"notification.xml").unwrap()
    }

    fn base_uri_for(&self, name: &PublisherHandle) -> KrillResult<uri::Rsync> {
        uri::Rsync::from_str(&format!("{}{}/", self.rsync_base, name))
            .map_err(|_| Error::Custom(format!("Cannot derive base uri for {}", name)))
    }

    /// Returns the repository URI information for a publisher.
    pub fn repo_info_for(&self, name: &PublisherHandle) -> KrillResult<RepoInfo> {
        let rsync_base = self.base_uri_for(name)?;
        Ok(RepoInfo::new(rsync_base, Some(self.notification_uri())))
    }

    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher_handle: &PublisherHandle,
    ) -> Result<idexchange::RepositoryResponse, Error> {
        let publisher = self.get_publisher(publisher_handle)?;
        let rsync_base = publisher.base_uri();
        let service_uri = idexchange::ServiceUri::Https(rfc8181_uri);

        Ok(idexchange::RepositoryResponse::new(
            self.id_cert.clone(),
            publisher_handle.clone(),
            service_uri,
            rsync_base.clone(),
            Some(self.notification_uri()),
            None,
        ))
    }

    pub fn get_publisher(&self, publisher_handle: &PublisherHandle) -> Result<&Publisher, Error> {
        self.publishers
            .get(publisher_handle)
            .ok_or_else(|| Error::PublisherUnknown(publisher_handle.clone()))
    }

    pub fn has_publisher(&self, name: &PublisherHandle) -> bool {
        self.publishers.contains_key(name)
    }

    pub fn publishers(&self) -> Vec<PublisherHandle> {
        self.publishers.keys().cloned().collect()
    }
}

//------------ RepoStats -----------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStats {
    publishers: HashMap<PublisherHandle, PublisherStats>,
    session: RrdpSession,
    serial: u64,
    last_update: Option<Time>,
}

impl RepoStats {
    pub fn new(session: RrdpSession) -> Self {
        RepoStats {
            publishers: HashMap::new(),
            session,
            serial: 0,
            last_update: None,
        }
    }

    pub fn publish(
        &mut self,
        publisher: &PublisherHandle,
        publisher_stats: PublisherStats,
        notification: &Notification,
    ) {
        self.publishers.insert(publisher.clone(), publisher_stats);
        self.serial = notification.serial();
        self.last_update = Some(notification.time());
    }

    pub fn session_reset(&mut self, notification: &Notification) {
        self.session = notification.session();
        self.serial = notification.serial();
        self.last_update = Some(notification.time())
    }

    pub fn new_publisher(&mut self, publisher: &PublisherHandle) {
        self.publishers.insert(publisher.clone(), PublisherStats::default());
    }

    pub fn remove_publisher(&mut self, publisher: &PublisherHandle, notification: &Notification) {
        self.publishers.remove(publisher);
        self.serial = notification.serial();
        self.last_update = Some(notification.time())
    }

    pub fn get_publishers(&self) -> &HashMap<PublisherHandle, PublisherStats> {
        &self.publishers
    }

    pub fn stale_publishers(&self, seconds: i64) -> Vec<PublisherHandle> {
        let mut res = vec![];
        for (publisher, stats) in self.publishers.iter() {
            if let Some(update_time) = stats.last_update {
                if Time::now().timestamp() - update_time.timestamp() >= seconds {
                    res.push(publisher.clone())
                }
            } else {
                res.push(publisher.clone())
            }
        }
        res
    }

    pub fn last_update(&self) -> Option<Time> {
        self.last_update
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn session(&self) -> RrdpSession {
        self.session
    }
}

impl fmt::Display for RepoStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(update) = self.last_update() {
            writeln!(f, "RRDP updated: {}", update.to_rfc3339())?;
        }
        writeln!(f, "RRDP session: {}", self.session())?;
        writeln!(f, "RRDP serial:  {}", self.serial())?;
        writeln!(f)?;
        writeln!(f, "Publisher, Objects, Size, Last Updated")?;
        for (publisher, stats) in self.get_publishers() {
            let update_str = match stats.last_update() {
                None => "never".to_string(),
                Some(update) => update.to_rfc3339(),
            };
            writeln!(
                f,
                "{}, {}, {}, {}",
                publisher,
                stats.objects(),
                stats.size(),
                update_str
            )?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherStats {
    objects: usize,
    size: usize,
    last_update: Option<Time>,
}

impl PublisherStats {
    pub fn new(current_objects: &CurrentObjects, last_update: Time) -> Self {
        let objects = current_objects.len();
        let size = current_objects.size();
        PublisherStats {
            objects,
            size,
            last_update: Some(last_update),
        }
    }

    pub fn objects(&self) -> usize {
        self.objects
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn last_update(&self) -> Option<Time> {
        self.last_update
    }
}

impl From<&CurrentObjects> for PublisherStats {
    fn from(objects: &CurrentObjects) -> Self {
        PublisherStats {
            objects: objects.len(),
            size: objects.size(),
            last_update: None,
        }
    }
}
