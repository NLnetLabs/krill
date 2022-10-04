use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
};

use rpki::{
    ca::{
        idexchange,
        idexchange::{MyHandle, PublisherHandle, RepoInfo},
        publication,
        publication::{ListReply, PublicationCms, PublishDelta},
    },
    crypto::KeyIdentifier,
    repository::{x509::Time, Manifest},
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{
            rrdp::{
                CurrentObjects, Delta, DeltaElements, DeltaRef, FileRef, Notification, RrdpFileRandom, RrdpSession,
                SnapshotData, SnapshotRef,
            },
            IdCertInfo,
        },
        api::{PublicationServerUris, StorableRepositoryCommand},
        crypto::KrillSigner,
        error::{Error, KrillIoError},
        eventsourcing::{Aggregate, AggregateStore, WalChange, WalCommand, WalSet, WalStore, WalSupport},
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
    store: Arc<WalStore<RepositoryContent>>,
    default_handle: MyHandle,
}

impl RepositoryContentProxy {
    pub fn disk(config: &Config) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let store = Arc::new(WalStore::disk(work_dir, PUBSERVER_CONTENT_DIR)?);
        store.warm()?;

        let default_handle = MyHandle::new("0".into());

        Ok(RepositoryContentProxy { store, default_handle })
    }

    /// Initialize
    pub fn init(&self, work_dir: &Path, uris: PublicationServerUris) -> KrillResult<()> {
        if self.store.has(&self.default_handle)? {
            Err(Error::RepositoryServerAlreadyInitialized)
        } else {
            // initialize new repo content
            let repository_content = {
                let (rrdp_base_uri, rsync_jail) = uris.unpack();

                let publishers = HashMap::new();

                let session = RrdpSession::default();

                let mut repo_dir = work_dir.to_path_buf();
                repo_dir.push(REPOSITORY_DIR);

                let rrdp = RrdpServer::create(rrdp_base_uri, &repo_dir, session);
                let rsync = RsyncdStore::new(rsync_jail, &repo_dir);

                RepositoryContent::new(publishers, rrdp, rsync)
            };

            // Store newly initialized repo content on disk
            self.store.add(&self.default_handle, repository_content)?;

            Ok(())
        }
    }

    fn get_default_content(&self) -> KrillResult<Arc<RepositoryContent>> {
        self.store
            .get_latest(&self.default_handle)
            .map_err(Error::WalStoreError)
    }

    // Clear all content, so it can be re-initialized.
    // Only to be called after all publishers have been removed from the RepoAccess as well.
    pub fn clear(&self) -> KrillResult<()> {
        let content = self.get_default_content()?;
        content.clear();
        self.store.remove(&self.default_handle)?;

        Ok(())
    }

    // Update snapshot on disk for faster load times after restart.
    pub fn update_snapshots(&self) -> KrillResult<()> {
        self.store
            .update_snapshot(&self.default_handle, false)
            .map_err(Error::WalStoreError)
    }

    /// Return the repository content stats
    pub fn stats(&self) -> KrillResult<RepoStats> {
        self.get_default_content().map(|content| content.stats())
    }

    /// Add a publisher with an empty set of published objects.
    ///
    /// Replaces an existing publisher if it existed.
    /// This is only supposed to be called if adding the publisher
    /// to the RepositoryAccess was successful (and *that* will fail if
    /// the publisher is a duplicate). This method can only fail if
    /// there is an issue with the underlying key value store.
    pub fn add_publisher(&self, publisher: PublisherHandle) -> KrillResult<()> {
        let command = RepositoryContentCommand::add_publisher(self.default_handle.clone(), publisher);
        self.store.send_command(command)?;
        Ok(())
    }

    /// Removes a publisher and its content.
    pub fn remove_publisher(&self, publisher: PublisherHandle, config: RepositoryRetentionConfig) -> KrillResult<()> {
        let command = RepositoryContentCommand::remove_publisher(self.default_handle.clone(), publisher, config);
        let content = self.store.send_command(command)?;

        content.write_repository(config)
    }

    /// Publish an update for a publisher.
    ///
    /// Assumes that the RFC 8181 CMS has been verified, but will check that all objects
    /// are within the publisher's uri space (jail).
    pub fn publish(
        &self,
        publisher: PublisherHandle,
        delta: PublishDelta,
        jail: &uri::Rsync,
        retention: RepositoryRetentionConfig,
    ) -> KrillResult<()> {
        debug!("Publish delta for {}", publisher);

        debug!("   get content");
        let content = self.get_default_content()?;
        debug!("   get objects for {}", publisher);
        let current_objects = content.objects_for_publisher(&publisher)?;
        let delta = DeltaElements::from(delta);

        debug!("   verify delta");
        current_objects.verify_delta(&delta, jail)?;

        let command = RepositoryContentCommand::publish(self.default_handle.clone(), publisher, delta, retention);
        let content = self.store.send_command(command)?;

        debug!("   update repository on disk");
        content.write_repository(retention)?;
        debug!("Done publishing");

        Ok(())
    }

    /// Write all current files to disk
    pub fn write_repository(&self, retention: RepositoryRetentionConfig) -> KrillResult<()> {
        let content = self.get_default_content()?;
        content.write_repository(retention)
    }

    /// Reset the RRDP session if it is initialized. Otherwise do nothing.
    pub fn session_reset(&self, retention: RepositoryRetentionConfig) -> KrillResult<()> {
        if self.store.has(&self.default_handle)? {
            let command = RepositoryContentCommand::session_reset(self.default_handle.clone());
            let content = self.store.send_command(command)?;

            content.write_repository(retention)
        } else {
            // repository server was not initialized on this Krill instance. Nothing to reset.
            Ok(())
        }
    }

    /// Create a list reply containing all current objects for a publisher
    pub fn list_reply(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        let content = self.get_default_content()?;
        content.list_reply(publisher)
    }

    // Get all current objects for a publisher
    pub fn current_objects(&self, name: &PublisherHandle) -> KrillResult<CurrentObjects> {
        let content = self.get_default_content()?;
        content.objects_for_publisher(name).map(|o| o.clone())
    }
}

//------------ RepositoryContentCommand ------------------------------------

#[derive(Clone, Debug)]
pub enum RepositoryContentCommand {
    ResetSession {
        handle: MyHandle,
    },
    AddPublisher {
        handle: MyHandle,
        publisher: PublisherHandle,
    },
    RemovePublisher {
        handle: MyHandle,
        publisher: PublisherHandle,
        retention: RepositoryRetentionConfig,
    },
    Publish {
        handle: MyHandle,
        publisher: PublisherHandle,
        delta: DeltaElements,
        retention: RepositoryRetentionConfig,
    },
}

impl RepositoryContentCommand {
    pub fn session_reset(handle: MyHandle) -> Self {
        RepositoryContentCommand::ResetSession { handle }
    }

    pub fn add_publisher(handle: MyHandle, publisher: PublisherHandle) -> Self {
        RepositoryContentCommand::AddPublisher { handle, publisher }
    }

    pub fn remove_publisher(
        handle: MyHandle,
        publisher: PublisherHandle,
        retention: RepositoryRetentionConfig,
    ) -> Self {
        RepositoryContentCommand::RemovePublisher {
            handle,
            publisher,
            retention,
        }
    }
    pub fn publish(
        handle: MyHandle,
        publisher: PublisherHandle,
        delta: DeltaElements,
        retention: RepositoryRetentionConfig,
    ) -> Self {
        RepositoryContentCommand::Publish {
            handle,
            publisher,
            delta,
            retention,
        }
    }
}

impl WalCommand for RepositoryContentCommand {
    fn handle(&self) -> &MyHandle {
        match self {
            RepositoryContentCommand::ResetSession { handle }
            | RepositoryContentCommand::AddPublisher { handle, .. }
            | RepositoryContentCommand::RemovePublisher { handle, .. }
            | RepositoryContentCommand::Publish { handle, .. } => handle,
        }
    }
}

impl fmt::Display for RepositoryContentCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentCommand::ResetSession { handle } => {
                write!(f, "reset session for repository {}", handle)
            }
            RepositoryContentCommand::AddPublisher { handle, publisher } => {
                write!(f, "add publisher '{}' to repository {}", publisher, handle)
            }
            RepositoryContentCommand::RemovePublisher { handle, publisher, .. } => {
                write!(f, "remove publisher '{}' from repository {}", publisher, handle)
            }
            RepositoryContentCommand::Publish { handle, publisher, .. } => {
                write!(f, "publish for publisher '{}' under repository {}", publisher, handle)
            }
        }
    }
}

//------------ RepositoryContentChange -------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryContentChange {
    SessionReset {
        reset: RrdpSessionReset,
    },
    PublisherAdded {
        publisher: PublisherHandle,
    },
    PublisherRemoved {
        publisher: PublisherHandle,
    },
    PublishedObjects {
        publisher: PublisherHandle,
        current_objects: CurrentObjects,
    },
    RrdpUpdated {
        update: RrdpUpdated,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpSessionReset {
    notification: Notification,
    snapshot: SnapshotData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpUpdated {
    time: Time,
    random: RrdpFileRandom,
    delta_elements: DeltaElements,
    deltas_truncate: usize,
}

impl fmt::Display for RepositoryContentChange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentChange::SessionReset { reset } => {
                write!(f, "RRDP session reset to: {}", reset.notification.session())
            }
            RepositoryContentChange::RrdpUpdated { .. } => {
                write!(f, "RRDP updated")
            }
            RepositoryContentChange::PublisherAdded { publisher } => write!(f, "added publisher: {}", publisher),
            RepositoryContentChange::PublisherRemoved { publisher } => write!(f, "removed publisher: {}", publisher),
            RepositoryContentChange::PublishedObjects { publisher, .. } => {
                write!(f, "published for publisher: {}", publisher)
            }
        }
    }
}

impl WalChange for RepositoryContentChange {}

//------------ RepositoryContent -------------------------------------------

/// This type manages the content of the repository. Note that access
/// to the repository is managed by an event sourced component which
/// handles RFC8181 based access, and which can enforce restrictions,
/// such as the base uri for publishers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryContent {
    #[serde(default)] // Make this backward compatible
    revision: u64,
    publishers: HashMap<PublisherHandle, CurrentObjects>,
    rrdp: RrdpServer,
    rsync: RsyncdStore,
}

/// # Construct
impl RepositoryContent {
    pub fn new(publishers: HashMap<PublisherHandle, CurrentObjects>, rrdp: RrdpServer, rsync: RsyncdStore) -> Self {
        RepositoryContent {
            revision: 0,
            publishers,
            rrdp,
            rsync,
        }
    }

    pub fn init(rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync, session: RrdpSession, repo_base_dir: &Path) -> Self {
        let publishers = HashMap::new();
        let rrdp = RrdpServer::create(rrdp_base_uri, repo_base_dir, session);
        let rsync = RsyncdStore::new(rsync_jail, repo_base_dir);

        RepositoryContent {
            revision: 0,
            publishers,
            rrdp,
            rsync,
        }
    }
}

/// # Write-ahead logging support
impl WalSupport for RepositoryContent {
    type Command = RepositoryContentCommand;
    type Change = RepositoryContentChange;
    type Error = Error;

    fn revision(&self) -> u64 {
        self.revision
    }

    fn apply(&mut self, set: WalSet<Self>) {
        for change in set.into_changes() {
            match change {
                RepositoryContentChange::SessionReset { reset } => self.rrdp.apply_session_reset(reset),
                RepositoryContentChange::RrdpUpdated { update } => self.rrdp.apply_rrdp_updated(update),
                RepositoryContentChange::PublisherAdded { publisher } => {
                    self.publishers.insert(publisher, CurrentObjects::default());
                }
                RepositoryContentChange::PublisherRemoved { publisher } => {
                    self.publishers.remove(&publisher);
                }
                RepositoryContentChange::PublishedObjects {
                    publisher,
                    current_objects,
                } => {
                    self.publishers.insert(publisher, current_objects);
                }
            }
        }
        self.revision += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Change>, Self::Error> {
        match command {
            RepositoryContentCommand::ResetSession { .. } => self.reset_session(),
            RepositoryContentCommand::AddPublisher { publisher, .. } => self.add_publisher(publisher),
            RepositoryContentCommand::RemovePublisher {
                publisher, retention, ..
            } => self.remove_publisher(publisher, retention),
            RepositoryContentCommand::Publish {
                publisher,
                delta,
                retention,
                ..
            } => self.publish(publisher, delta, retention),
        }
    }
}

/// # Publisher Content
impl RepositoryContent {
    // Clears all content on disk so the repository can be re-initialized
    pub fn clear(&self) {
        self.rrdp.clear();
        self.rsync.clear();
    }

    fn objects_for_publisher(&self, publisher: &PublisherHandle) -> KrillResult<&CurrentObjects> {
        self.publishers
            .get(publisher)
            .ok_or_else(|| Error::PublisherUnknown(publisher.clone()))
    }

    /// Gets a list reply containing all objects for this publisher.
    pub fn list_reply(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.objects_for_publisher(publisher).map(|o| o.to_list_reply())
    }

    pub fn reset_session(&self) -> KrillResult<Vec<RepositoryContentChange>> {
        info!("Performing RRDP session reset.");
        let reset = self.rrdp.reset_session();

        Ok(vec![RepositoryContentChange::SessionReset { reset }])
    }

    pub fn write_repository(&self, config: RepositoryRetentionConfig) -> KrillResult<()> {
        self.rrdp.write(config)?;
        self.rsync.write(self.rrdp.serial, self.rrdp.snapshot())
    }

    pub fn add_publisher(&self, publisher: PublisherHandle) -> KrillResult<Vec<RepositoryContentChange>> {
        Ok(vec![RepositoryContentChange::PublisherAdded { publisher }])
    }

    /// Removes the content for a publisher. This function will return
    /// ok if there is no content to remove - it is idempotent in that
    /// sense. However, if there are I/O errors removing the content then
    /// this function will fail.
    pub fn remove_publisher(
        &self,
        publisher: PublisherHandle,
        retention: RepositoryRetentionConfig,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        let mut res = vec![];
        // withdraw objects if any
        if let Ok(objects) = self.objects_for_publisher(&publisher) {
            let withdraws = objects.elements().iter().map(|e| e.as_withdraw()).collect();
            let delta = DeltaElements::new(vec![], vec![], withdraws);

            let update = self.rrdp.update_rrdp(delta, retention)?;
            res.push(RepositoryContentChange::RrdpUpdated { update })
        }

        // remove publisher if present
        if self.publishers.contains_key(&publisher) {
            res.push(RepositoryContentChange::PublisherRemoved { publisher });
        }

        Ok(res)
    }

    /// Publish content for a publisher. Assumes that the delta was
    /// already checked (this is done in RepositoryContentProxy::publish).
    pub fn publish(
        &self,
        publisher: PublisherHandle,
        delta: DeltaElements,
        retention: RepositoryRetentionConfig,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        let mut res = vec![];

        let mut current_objects = self
            .publishers
            .get(&publisher)
            .cloned()
            .ok_or_else(|| Error::PublisherUnknown(publisher.clone()))?;

        debug!("  apply delta to current objects of {}", publisher);
        current_objects.apply_delta(delta.clone());

        res.push(RepositoryContentChange::PublishedObjects {
            publisher,
            current_objects,
        });

        // TODO: Stage changes for publishers, and *then* update RRDP (see #693)
        debug!("   update RRDP state with changes");
        let update = self.rrdp.update_rrdp(delta, retention)?;
        debug!("   done updating RRDP state with changes");
        res.push(RepositoryContentChange::RrdpUpdated { update });

        Ok(res)
    }

    /// Returns the content stats for the repo
    pub fn stats(&self) -> RepoStats {
        RepoStats {
            publishers: self.publisher_stats(),
            session: self.rrdp.session,
            serial: self.rrdp.serial,
            last_update: Some(self.rrdp.notification().time()),
            rsync_base: self.rsync.base_uri.clone(),
            rrdp_base: self.rrdp.rrdp_base_uri.clone(),
        }
    }

    /// Returns the stats for all current publishers
    pub fn publisher_stats(&self) -> HashMap<PublisherHandle, PublisherStats> {
        self.publishers
            .iter()
            .map(|(pbl, objects)| (pbl.clone(), PublisherStats::from(objects)))
            .collect()
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
    pub fn write(&self, serial: u64, snapshot: &SnapshotData) -> KrillResult<()> {
        let _lock = self
            .lock
            .write()
            .map_err(|_| Error::custom("Could not get write lock for rsync repo"))?;

        let mut new_dir = self.rsync_dir.clone();
        new_dir.push(&format!("tmp-{}", serial));
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

    snapshot: SnapshotData,
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
        snapshot: SnapshotData,
        deltas: VecDeque<Delta>,
    ) -> Self {
        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            notification,
            snapshot,
            deltas,
        }
    }

    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &Path, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = repo_dir.to_path_buf();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let mut rrdp_archive_dir = repo_dir.to_path_buf();
        rrdp_archive_dir.push(REPOSITORY_RRDP_ARCHIVE_DIR);

        let snapshot = SnapshotData::create();

        let serial = RRDP_FIRST_SERIAL;
        let snapshot_uri = snapshot.uri(session, serial, &rrdp_base_uri);
        let snapshot_path = snapshot.path(session, serial, &rrdp_base_dir);
        let snapshot_hash = Hash::from_data(snapshot.xml(session, serial).as_slice());

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
            deltas: VecDeque::new(),
        }
    }

    fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rrdp_base_dir);
        let _ = fs::remove_dir_all(&self.rrdp_archive_dir);
    }

    fn snapshot(&self) -> &SnapshotData {
        &self.snapshot
    }

    pub fn notification(&self) -> &Notification {
        &self.notification
    }

    pub fn reset_session(&self) -> RrdpSessionReset {
        let session = RrdpSession::random();
        let snapshot = self.snapshot.with_new_random();
        let snapshot_uri = snapshot.uri(session, RRDP_FIRST_SERIAL, &self.rrdp_base_uri);
        let snapshot_path = snapshot.path(session, RRDP_FIRST_SERIAL, &self.rrdp_base_dir);
        let snapshot_hash = Hash::from_data(snapshot.xml(session, RRDP_FIRST_SERIAL).as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        RrdpSessionReset { snapshot, notification }
    }

    /// Applies the data from an RrdpSessionReset change.
    fn apply_session_reset(&mut self, reset: RrdpSessionReset) {
        let snapshot = reset.snapshot;
        let notification = reset.notification;

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.snapshot = snapshot;
        self.deltas = VecDeque::new();
    }

    /// Applies the data from an RrdpUpdated change.
    fn apply_rrdp_updated(&mut self, update: RrdpUpdated) {
        self.serial += 1;

        let delta = Delta::new(
            self.session,
            self.serial,
            update.time,
            update.random.clone(),
            update.delta_elements,
        );
        self.snapshot = self.snapshot.with_delta(update.random, delta.elements().clone());
        self.notification = self.make_updated_notification(&self.snapshot, &delta, update.deltas_truncate);

        self.deltas.truncate(update.deltas_truncate);
        self.deltas.push_front(delta);
    }

    /// Updates the RRDP server with the elements. Note that this assumes that
    /// the delta has already been checked against the jail and current
    /// objects of the publisher.
    fn update_rrdp(
        &self,
        delta_elements: DeltaElements,
        retention: RepositoryRetentionConfig,
    ) -> KrillResult<RrdpUpdated> {
        let time = Time::now();
        let random = RrdpFileRandom::default();

        let deltas_truncate = {
            // It's a bit inefficient to "pre-create" a new snapshot just to get its size, but
            // if we look at the current snapshot then we could be off.
            let snapshot_size = self.snapshot.with_delta(random.clone(), delta_elements.clone()).size();
            let delta_size = delta_elements.size();
            self.find_deltas_truncate(delta_size, snapshot_size, retention)
        };

        Ok(RrdpUpdated {
            time,
            random,
            delta_elements,
            deltas_truncate,
        })
    }

    // Get the position to truncate excessive deltas:
    //  - never keep more than the size of the snapshot
    //  - always keep 'retention_delta_files_min_nr' files
    //  - always keep 'retention_delta_files_min_seconds' files
    //  - beyond this:
    //     - never keep more than 'retention_delta_files_max_nr'
    //     - never keep older than 'retention_delta_files_max_seconds'
    //     - keep the others
    fn find_deltas_truncate(
        &self,
        delta_size: usize,
        snapshot_size: usize,
        config: RepositoryRetentionConfig,
    ) -> usize {
        // We will keep the new delta - not yet added to this.
        // So, we use its size as the starting point for the total delta size.
        let mut keep = 0;
        let mut size = delta_size;

        let min_nr = config.retention_delta_files_min_nr;
        let min_secs = config.retention_delta_files_min_seconds;
        let max_nr = config.retention_delta_files_max_nr;
        let max_secs = config.retention_delta_files_max_seconds;

        for delta in &self.deltas {
            size += delta.elements().size();

            if size > snapshot_size {
                // never keep more than the size of the snapshot
                break;
            } else if keep < min_nr || delta.younger_than_seconds(min_secs.into()) {
                // always keep 'retention_delta_files_min_nr' files
                // always keep 'retention_delta_files_min_seconds' file
                keep += 1
            } else if keep == max_nr || delta.older_than_seconds(max_secs.into()) {
                // never keep more than 'retention_delta_files_max_nr'
                // never keep older than 'retention_delta_files_max_seconds'
                break;
            } else {
                // keep the remainder
                keep += 1;
            }
        }

        keep
    }

    // Update the notification to include the current snapshot and
    // deltas. Remove old notifications exceeding the retention time,
    // so that we can delete old snapshots and deltas which are no longer
    // relevant.
    fn make_updated_notification(
        &self,
        snapshot: &SnapshotData,
        delta: &Delta,
        deltas_truncate: usize,
    ) -> Notification {
        let snapshot_ref = {
            let snapshot_uri = snapshot.uri(self.session, self.serial, &self.rrdp_base_uri);
            let snapshot_path = snapshot.path(self.session, self.serial, &self.rrdp_base_dir);
            let snapshot_xml = snapshot.xml(self.session, self.serial);
            let snapshot_hash = Hash::from_data(snapshot_xml.as_slice());
            SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash)
        };

        let delta_ref = {
            let serial = delta.serial();
            let xml = delta.xml();
            let hash = Hash::from_data(xml.as_slice());

            let delta_uri = delta.uri(&self.rrdp_base_uri);
            let delta_path = delta.path(&self.rrdp_base_dir);
            let file_ref = FileRef::new(delta_uri, delta_path, hash);
            DeltaRef::new(serial, file_ref)
        };

        self.notification.with_updates(snapshot_ref, delta_ref, deltas_truncate)
    }

    /// Write the (missing) RRDP files to disk, and remove the ones
    /// no longer referenced in the notification file.
    fn write(&self, retention: RepositoryRetentionConfig) -> Result<(), Error> {
        // write snapshot if it's not there
        let snapshot_path = self.snapshot.path(self.session, self.serial, &self.rrdp_base_dir);
        if !snapshot_path.exists() {
            self.snapshot.write_xml(self.session, self.serial, &snapshot_path)?;
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
                } else if !self.notification.includes_delta(serial) {
                    if retention.retention_archive {
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
                } else if !retention.retention_archive {
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
        let name = req.publisher_handle().clone();
        let id_cert = req.validate().map_err(Error::rfc8183)?;
        let base_uri = self.read()?.base_uri_for(&name)?;

        let cmd = RepoAccessCmdDet::add_publisher(&self.key, id_cert.into(), name, base_uri, actor);
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
        msg.validate(publisher.id_cert().public_key()).map_err(Error::Rfc8181)?;
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

    id_cert: IdCertInfo,
    publishers: HashMap<PublisherHandle, Publisher>,

    rsync_base: uri::Rsync,
    rrdp_base: uri::Https,
}

impl RepositoryAccess {
    pub fn key_id(&self) -> KeyIdentifier {
        self.id_cert.public_key().key_identifier()
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
            RepoAccessCmdDet::AddPublisher {
                id_cert,
                name,
                base_uri,
            } => self.add_publisher(id_cert, name, base_uri),
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
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
    ) -> Result<Vec<RepositoryAccessEvent>, Error> {
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
            self.id_cert.base64().clone(),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStats {
    publishers: HashMap<PublisherHandle, PublisherStats>,
    session: RrdpSession,
    serial: u64,
    last_update: Option<Time>,
    rsync_base: uri::Rsync,
    rrdp_base: uri::Https,
}

impl RepoStats {
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
            if let Some(update_time) = stats.last_update() {
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
        writeln!(f, "Server URIs:")?;
        writeln!(f, "    rrdp:    {}", self.rrdp_base)?;
        writeln!(f, "    rsync:   {}", self.rsync_base)?;
        writeln!(f)?;
        if let Some(update) = self.last_update() {
            writeln!(f, "RRDP updated:      {}", update.to_rfc3339())?;
        }
        writeln!(f, "RRDP session:      {}", self.session())?;
        writeln!(f, "RRDP serial:       {}", self.serial())?;
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
    manifests: Vec<PublisherManifestStats>,
}

impl PublisherStats {
    pub fn new(current_objects: &CurrentObjects) -> Self {
        Self::from(current_objects)
    }

    pub fn objects(&self) -> usize {
        self.objects
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the most recent "this_update" time
    /// from all manifest(s) published by this publisher,
    /// if any.. i.e. there may be 0, 1 or many manifests
    pub fn last_update(&self) -> Option<Time> {
        let mut last_update = None;
        for mft in self.manifests() {
            if let Some(last_update_until_now) = last_update {
                let this_manifest_this_update = mft.this_update();
                if this_manifest_this_update > last_update_until_now {
                    last_update = Some(this_manifest_this_update)
                }
            } else {
                last_update = Some(mft.this_update());
            }
        }

        last_update
    }

    pub fn manifests(&self) -> &Vec<PublisherManifestStats> {
        &self.manifests
    }
}

impl From<&CurrentObjects> for PublisherStats {
    fn from(objects: &CurrentObjects) -> Self {
        let mut manifests = vec![];
        for el in objects.elements() {
            // Add all manifests - as long as they are syntactically correct - do not
            // crash on incorrect objects.
            if el.uri().ends_with("mft") {
                if let Ok(mft) = Manifest::decode(el.base64().to_bytes().as_ref(), false) {
                    if let Ok(stats) = PublisherManifestStats::try_from(&mft) {
                        manifests.push(stats)
                    }
                }
            }
        }

        PublisherStats {
            objects: objects.len(),
            size: objects.size(),
            manifests,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherManifestStats {
    uri: uri::Rsync,
    this_update: Time,
    next_update: Time,
}

impl PublisherManifestStats {
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn this_update(&self) -> Time {
        self.this_update
    }

    pub fn next_update(&self) -> Time {
        self.next_update
    }
}

impl TryFrom<&Manifest> for PublisherManifestStats {
    type Error = ();

    // This will fail for syntactically incorrect manifests, which do
    // not include the signed object URI in their SIA.
    fn try_from(mft: &Manifest) -> Result<Self, Self::Error> {
        let uri = mft.cert().signed_object().cloned().ok_or(())?;
        Ok(PublisherManifestStats {
            uri,
            this_update: mft.this_update(),
            next_update: mft.next_update(),
        })
    }
}
