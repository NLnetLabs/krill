use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::mem;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use rpki::crypto::KeyIdentifier;
use rpki::uri;
use rpki::x509::Time;

use crate::{
    commons::{
        actor::Actor,
        api::rrdp::{
            CurrentObjects, Delta, DeltaElements, DeltaRef, FileRef, Notification, RrdpSession, Snapshot, SnapshotRef,
        },
        api::{
            Handle, HexEncodedHash, ListReply, PublicationServerUris, PublishDelta, PublisherHandle, RepoInfo,
            StorableRepositoryCommand,
        },
        crypto::{IdCert, KrillSigner, ProtocolCms, ProtocolCmsBuilder},
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, AggregateStoreError, KeyStoreKey, KeyValueStore},
        remote::rfc8183,
        util::file,
        KrillResult,
    },
    constants::{
        PUBSERVER_CONTENT_DIR, PUBSERVER_DFLT, PUBSERVER_DIR, REPOSITORY_DIR, REPOSITORY_RRDP_ARCHIVE_DIR,
        REPOSITORY_RRDP_DIR, REPOSITORY_RSYNC_DIR,
    },
    daemon::config::{Config, RepositoryRetentionConfig},
    pubd::publishers::Publisher,
    pubd::{RepoAccessCmd, RepoAccessCmdDet, RepositoryAccessEvent, RepositoryAccessEventDetails, RepositoryAccessIni},
};

use super::RepositoryAccessInitDetails;

//------------ RepositoryContentProxy ----------------------------------------

/// We can only have one (1) RepositoryContent, but it is stored
/// in a KeyValueStore. So this type provides a wrapper around this
/// so that callers don't need to worry about storage details.
#[derive(Debug)]
pub struct RepositoryContentProxy {
    store: RwLock<KeyValueStore>,
    key: KeyStoreKey,
}

impl RepositoryContentProxy {
    pub fn disk(config: &Config) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let store = KeyValueStore::disk(work_dir, PUBSERVER_CONTENT_DIR)?;
        let store = RwLock::new(store);

        let dflt_key = KeyStoreKey::simple(PUBSERVER_DFLT.to_string());
        Ok(RepositoryContentProxy { store, key: dflt_key })
    }

    // Initialise
    pub fn init(&self, work_dir: &PathBuf, uris: PublicationServerUris) -> KrillResult<()> {
        if self.store.read().unwrap().has(&self.key)? {
            Err(Error::RepositoryServerAlreadyInitialised)
        } else {
            let (rrdp_base_uri, rsync_jail) = uris.unpack();

            let publishers = HashMap::new();

            let session = RrdpSession::default();
            let stats = RepoStats::new(session);

            let mut repo_dir = work_dir.clone();
            repo_dir.push(REPOSITORY_DIR);

            let rrdp = RrdpServer::create(rrdp_base_uri, &repo_dir, session);
            let rsync = RsyncdStore::new(rsync_jail, &repo_dir);

            let repo = RepositoryContent::new(publishers, rrdp, rsync, stats);

            let store = self.store.write().unwrap();
            store.store(&self.key, &repo)?;

            Ok(())
        }
    }

    // Clear all content, so it can be re-initialised.
    // Only to be called after all publishers have been removed from the RepoAccess as well.
    pub fn clear(&self) -> KrillResult<()> {
        let store = self.store.write().unwrap();

        if let Ok(Some(content)) = store.get::<RepositoryContent>(&self.key) {
            content.clear();
            store.drop_key(&self.key)?;
        }

        Ok(())
    }

    pub fn stats(&self) -> KrillResult<RepoStats> {
        self.read_content().map(|c| c.stats().clone())
    }

    // Adds a publisher with an empty set of published objects.
    // Replaces an existing publisher if it existed.
    // This is only supposed to be called if adding the publisher
    // to the RepositoryAccess was successful (and *that* will fail if
    // the publisher is a duplicate). This method can only fail if
    // there is an issue with the underlying keyvalue store.
    pub fn add_publisher(&self, name: PublisherHandle) -> KrillResult<()> {
        self.write(|content| content.add_publisher(name))
    }

    // Removes a publisher and its content. Will also write the updated
    // RRDP and rsync content.
    pub fn remove_publisher(
        &self,
        name: &PublisherHandle,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        self.write(|content| content.remove_publisher(name, jail, config))
    }

    // Publish an update for a publisher. Assumes that the RFC 8181 CMS has
    // been verified, but will check that all objects are within the publisher's
    // uri space (jail).
    pub fn publish(
        &self,
        name: &PublisherHandle,
        delta: PublishDelta,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        self.write(|content| content.publish(name, delta.into(), jail, config))
    }

    // Write all current files to disk
    pub fn write_repository(&self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        self.read_content()?.write_repository(config)
    }

    // Reset the RRDP session
    pub fn session_reset(&self, config: &RepositoryRetentionConfig) -> KrillResult<()> {
        self.write(|content| content.session_reset(config))
    }

    fn write<F: FnOnce(&mut RepositoryContent) -> KrillResult<()>>(&self, op: F) -> KrillResult<()> {
        let store = self.store.write().unwrap();
        let mut content: RepositoryContent = store.get(&self.key)?.ok_or(Error::RepositoryServerNotInitialised)?;

        op(&mut content)?;

        store.store(&self.key, &content)?;
        Ok(())
    }

    fn read_content(&self) -> KrillResult<RepositoryContent> {
        self.store
            .read()
            .unwrap()
            .get(&self.key)?
            .ok_or(Error::RepositoryServerNotInitialised)
    }

    pub fn list_reply(&self, name: &PublisherHandle) -> KrillResult<ListReply> {
        self.read_content()?.list_reply(name)
    }

    pub fn current_objects(&self, name: &PublisherHandle) -> KrillResult<CurrentObjects> {
        self.read_content()?.objects_for_publisher(name).map(|o| o.clone())
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

    pub fn init(
        rrdp_base_uri: uri::Https,
        rsync_jail: uri::Rsync,
        session: RrdpSession,
        repo_base_dir: &PathBuf,
    ) -> Self {
        let publishers = HashMap::new();
        let rrdp = RrdpServer::create(rrdp_base_uri, &repo_base_dir, session);
        let rsync = RsyncdStore::new(rsync_jail, &repo_base_dir);
        let stats = RepoStats::new(session);

        RepositoryContent {
            publishers,
            rrdp,
            rsync,
            stats,
        }
    }

    // Clears all content on disk so the repository can be re-initialised
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
    pub fn list_reply(&self, publisher: &Handle) -> KrillResult<ListReply> {
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
        self.rrdp.session_reset()?;
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

    pub fn remove_publisher(
        &mut self,
        name: &PublisherHandle,
        jail: &uri::Rsync,
        config: &RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        let objects = self.objects_for_publisher(name)?;

        let withdraws = objects.elements().iter().map(|e| e.as_withdraw()).collect();
        let delta = DeltaElements::new(vec![], vec![], withdraws);

        self.rrdp.publish(delta, jail, config)?;
        self.stats.remove_publisher(name, self.rrdp.notification());

        self.write_repository(config)
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

    pub fn new(base_uri: uri::Rsync, repo_dir: &PathBuf) -> Self {
        let mut rsync_dir = PathBuf::from(repo_dir);
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
    /// things over in an effort to minimise the chance of people getting
    /// inconsistent syncs..
    pub fn write(&self, snapshot: &Snapshot) -> KrillResult<()> {
        let _lock = self
            .lock
            .write()
            .map_err(|_| Error::custom("Could not get write lock for rsync repo"))?;

        let mut new_dir = self.rsync_dir.clone();
        new_dir.push(&format!("tmp-{}", snapshot.serial()));
        fs::create_dir_all(&new_dir)?;

        let elements = snapshot.elements();

        for publish in elements {
            let rel = publish
                .uri()
                .relative_to(&self.base_uri)
                .ok_or_else(|| Error::publishing_outside_jail(publish.uri(), &self.base_uri))?;

            let rel = unsafe { from_utf8_unchecked(rel) };

            let mut path = new_dir.clone();
            path.push(rel);

            file::save(&publish.base64().to_bytes(), &path)?;
        }

        let mut current_dir = self.rsync_dir.clone();
        current_dir.push("current");

        let mut old_dir = self.rsync_dir.clone();
        old_dir.push("old");

        if current_dir.exists() {
            fs::rename(&current_dir, &old_dir)?;
        }

        fs::rename(&new_dir, &current_dir)?;

        if old_dir.exists() {
            fs::remove_dir_all(&old_dir)?;
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
    #[allow(clippy::clippy::too_many_arguments)]
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

    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &PathBuf, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = repo_dir.clone();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let mut rrdp_archive_dir = repo_dir.clone();
        rrdp_archive_dir.push(REPOSITORY_RRDP_ARCHIVE_DIR);

        let snapshot = Snapshot::create(session);

        let serial = 0;
        let snapshot_uri = Self::new_snapshot_uri(&rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

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
    fn session_reset(&mut self) -> KrillResult<()> {
        let session = RrdpSession::random();
        let serial = 0;

        let snapshot = self.snapshot.session_reset(session);

        let snapshot_uri = Self::new_snapshot_uri(&self.rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&self.rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.old_notifications.clear();
        self.snapshot = snapshot;
        self.deltas = VecDeque::new();

        Ok(())
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

    // Push the delta and truncate excessive deltas.
    //  - keep no more than the size of the snapshot
    //  - don't keep deltas older than configured seconds
    //  - but keep a minimum of configured deltas
    fn update_deltas(&mut self, elements: DeltaElements, config: &RepositoryRetentionConfig) {
        self.deltas.push_front(Delta::new(self.session, self.serial, elements));
        let mut keep = 0;
        let mut size = 0;
        let snapshot_size = self.snapshot.size();

        let retain_secs = config.retention_delta_files_seconds;
        let minimum = config.retention_delta_files_min_nr;

        for delta in &self.deltas {
            size += delta.elements().size();
            if size > snapshot_size || (keep > minimum && delta.older_than_seconds(retain_secs)) {
                break;
            }
            keep += 1;
        }
        self.deltas.truncate(keep);
    }

    // Update the notification to include the current snapshot and
    // deltas. Remove old notifications exceeding the retention time,
    // so that we can delete old snapshots and deltas which are no longer
    // relevant.
    fn update_notification(&mut self, config: &RepositoryRetentionConfig) {
        let snapshot_ref = {
            let snapshot_uri = self.snapshot_uri();
            let snapshot_path = self.snapshot_path(self.serial);
            let snapshot_xml = self.snapshot.xml();
            let snapshot_hash = HexEncodedHash::from_content(snapshot_xml.as_slice());
            SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash)
        };

        let delta_refs = self
            .deltas
            .iter()
            .map(|delta| {
                let serial = delta.serial();
                let xml = delta.xml();
                let hash = HexEncodedHash::from_content(xml.as_slice());

                let delta_uri = self.delta_uri(serial);
                let delta_path = self.delta_path(serial);
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
        let snapshot_path = self.snapshot_path(self.serial);
        if !snapshot_path.exists() {
            self.snapshot.write_xml(&snapshot_path)?;
        }

        // write deltas if they are not there
        for delta in &self.deltas {
            let path = self.delta_path(delta.serial());
            if !path.exists() {
                // assume that if the delta exists, it is correct
                delta.write_xml(&path)?;
            }
        }

        // write notification file
        let notification_path_new = self.notification_path_new();
        let notification_path = self.notification_path();
        self.notification.write_xml(&notification_path_new)?;
        fs::rename(notification_path_new, notification_path)?;

        // clean up under the base dir:
        // - old session dirs
        for entry in fs::read_dir(&self.rrdp_base_dir)? {
            let entry = entry?;
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

        for entry in fs::read_dir(&session_dir)? {
            let entry = entry?;
            let path = entry.path();

            // remove any dir or file that is:
            // - not a number
            // - a number that is higher than the current serial
            // - a number that is lower than the last delta (if set)
            if let Ok(serial) = u64::from_str(entry.file_name().to_string_lossy().as_ref()) {
                // Skip the current serial
                if serial == self.serial {
                    continue;
                // Clean up old serial dirs
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

                // clean snapshots no longer referenced in retained notification files
                // unless archiving mode is enabled -- in that case leave the snapshots
                // and they will be archived when the delta go out of scope (see above)
                } else if !self.old_notifications.iter().any(|n| n.includes_snapshot(serial))
                    && !config.retention_archive
                {
                    let snapshot_path = Self::new_snapshot_path(&self.rrdp_base_dir, &self.session, serial);
                    if snapshot_path.exists() {
                        let _best_effort_rm = fs::remove_file(snapshot_path);
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
        self.rrdp_base_uri.join(b"notification.xml")
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

    fn snapshot_rel(session: &RrdpSession, serial: u64) -> String {
        format!("{}/{}/snapshot.xml", session, serial)
    }

    fn new_snapshot_path(base: &PathBuf, session: &RrdpSession, serial: u64) -> PathBuf {
        let mut path = base.clone();
        path.push(Self::snapshot_rel(session, serial));
        path
    }

    fn snapshot_path(&self, serial: u64) -> PathBuf {
        Self::new_snapshot_path(&self.rrdp_base_dir, &self.session, serial)
    }

    fn new_snapshot_uri(base: &uri::Https, session: &RrdpSession, serial: u64) -> uri::Https {
        base.join(Self::snapshot_rel(session, serial).as_ref())
    }

    fn snapshot_uri(&self) -> uri::Https {
        Self::new_snapshot_uri(&self.rrdp_base_uri, &self.session, self.serial)
    }

    fn delta_rel(session: &RrdpSession, serial: u64) -> String {
        format!("{}/{}/delta.xml", session, serial)
    }

    fn delta_uri(&self, serial: u64) -> uri::Https {
        uri::Https::from_string(format!(
            "{}{}",
            self.rrdp_base_uri.to_string(),
            Self::delta_rel(&self.session, serial)
        ))
        .unwrap() // Cannot fail. Config checked at startup.
    }

    fn delta_path(&self, serial: u64) -> PathBuf {
        let mut path = self.rrdp_base_dir.clone();
        path.push(Self::delta_rel(&self.session, serial));
        path
    }
}

/// We can only have one (1) RepositoryAccess, but it is an event-sourced
/// typed which is stored in an AggregateStore which could theoretically
/// serve multiple. So, we use RepositoryAccessProxy as a wrapper around
/// this so that callers don't need to worry about storage details.
pub struct RepositoryAccessProxy {
    store: AggregateStore<RepositoryAccess>,
    key: Handle,
}

impl RepositoryAccessProxy {
    pub fn disk(config: &Config) -> KrillResult<Self> {
        let store = AggregateStore::<RepositoryAccess>::disk(&config.data_dir, PUBSERVER_DIR)?;
        let key = Handle::from_str(PUBSERVER_DFLT).unwrap();

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
            Err(Error::RepositoryServerAlreadyInitialised)
        } else {
            let (rrdp_base_uri, rsync_jail) = uris.unpack();

            let ini = RepositoryAccessInitDetails::init(&self.key, rsync_jail, rrdp_base_uri, signer)?;

            self.store.add(ini)?;

            Ok(())
        }
    }

    pub fn clear(&self) -> KrillResult<()> {
        if !self.initialized()? {
            Err(Error::RepositoryServerNotInitialised)
        } else if !self.publishers()?.is_empty() {
            Err(Error::RepositoryServerHasPublishers)
        } else {
            self.store.drop_aggregate(&self.key)?;
            Ok(())
        }
    }

    fn read(&self) -> KrillResult<Arc<RepositoryAccess>> {
        match self.store.get_latest(&self.key) {
            Ok(repo) => Ok(repo),
            Err(e) => match e {
                AggregateStoreError::UnknownAggregate(_) => Err(Error::RepositoryServerNotEnabled),
                _ => Err(Error::AggregateStoreError(e)),
            },
        }
    }

    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        Ok(self.read()?.publishers())
    }

    pub fn get_publisher(&self, name: &PublisherHandle) -> KrillResult<Publisher> {
        self.read()?.get_publisher(name).map(|p| p.clone())
    }

    pub fn add_publisher(&self, req: rfc8183::PublisherRequest, actor: &Actor) -> KrillResult<()> {
        let base_uri = self.read()?.base_uri_for(req.publisher_handle())?;
        let cmd = RepoAccessCmdDet::add_publisher(&self.key, req, base_uri, actor);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
        let cmd = RepoAccessCmdDet::remove_publisher(&self.key, name, actor);
        self.store.command(cmd)?;
        Ok(())
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
    ) -> KrillResult<rfc8183::RepositoryResponse> {
        self.read()?.repository_response(rfc8181_uri, publisher)
    }

    /// Parse submitted bytes by a Publisher as an RFC8181 ProtocolCms object, and validates it.
    pub fn validate(&self, publisher: &PublisherHandle, msg: Bytes) -> KrillResult<ProtocolCms> {
        let publisher = self.get_publisher(&publisher)?;
        let msg = ProtocolCms::decode(msg, false).map_err(|e| Error::Rfc8181Decode(e.to_string()))?;
        msg.validate(publisher.id_cert()).map_err(Error::Rfc8181Validation)?;
        Ok(msg)
    }

    /// Creates and signs an RFC8181 CMS response.
    pub fn respond(&self, message: Bytes, signer: &KrillSigner) -> KrillResult<Bytes> {
        let key_id = self.read()?.key_id();
        let response_builder = ProtocolCmsBuilder::create(&key_id, signer, message).map_err(Error::signer)?;
        Ok(response_builder.as_bytes())
    }
}

//------------ RepositoryAccess --------------------------------------------

/// An RFC8183 Repository server, capable of handling Publishers (both embedded, and
/// remote RFC8183), and publishing to RRDP and disk, and signing responses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryAccess {
    // Event sourcing support
    handle: Handle,
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
        publisher_request: rfc8183::PublisherRequest,
        base_uri: uri::Rsync,
    ) -> Result<Vec<RepositoryAccessEvent>, Error> {
        let (_tag, name, id_cert) = publisher_request.unpack();

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
        self.rrdp_base.join(b"notification.xml")
    }

    fn base_uri_for(&self, name: &PublisherHandle) -> KrillResult<uri::Rsync> {
        uri::Rsync::from_str(&format!("{}{}/", self.rsync_base, name))
            .map_err(|_| Error::Custom(format!("Cannot derive base uri for {}", name)))
    }

    /// Returns the repository URI information for a publisher.
    pub fn repo_info_for(&self, name: &PublisherHandle) -> KrillResult<RepoInfo> {
        let rsync_base = self.base_uri_for(name)?;
        Ok(RepoInfo::new(rsync_base, self.notification_uri()))
    }

    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher_handle: &PublisherHandle,
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        let publisher = self.get_publisher(publisher_handle)?;
        let rsync_base = publisher.base_uri();
        let service_uri = rfc8183::ServiceUri::Https(rfc8181_uri);

        let repo_info = RepoInfo::new(rsync_base.clone(), self.notification_uri());

        Ok(rfc8183::RepositoryResponse::new(
            None,
            publisher_handle.clone(),
            self.id_cert.clone(),
            service_uri,
            repo_info,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStats {
    publishers: HashMap<PublisherHandle, PublisherStats>,
    session: RrdpSession,
    serial: u64,
    last_update: Option<Time>,
}

impl Default for RepoStats {
    fn default() -> Self {
        RepoStats {
            publishers: HashMap::new(),
            session: RrdpSession::default(),
            serial: 0,
            last_update: None,
        }
    }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

impl Default for PublisherStats {
    fn default() -> Self {
        PublisherStats {
            objects: 0,
            size: 0,
            last_update: None,
        }
    }
}
