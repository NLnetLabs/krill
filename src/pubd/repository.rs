use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
};

use chrono::Duration;
use rpki::{
    ca::{
        idexchange,
        idexchange::{MyHandle, PublisherHandle, RepoInfo},
        publication,
        publication::{ListReply, PublicationCms, PublishDelta},
    },
    crypto::KeyIdentifier,
    repository::{x509::Time, Manifest},
    rrdp::{DeltaInfo, Hash, NotificationFile, SnapshotInfo},
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{
            rrdp::{
                CurrentObjects, DeltaData, DeltaElements, PublishElement, RrdpFileRandom, RrdpSession, SnapshotData,
                UpdateElement, WithdrawElement,
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
    daemon::config::{Config, RrdpUpdatesConfig},
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
    pub fn remove_publisher(
        &self,
        publisher: PublisherHandle,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
        let command = RepositoryContentCommand::remove_publisher(self.default_handle.clone(), publisher);
        let content = self.store.send_command(command)?;

        // TODO: move this to MQ / Scheduler
        if content.rrdp.update_rrdp_needed(rrdp_updates_config) {
            debug!("   create new RRDP delta");
            let command = RepositoryContentCommand::create_rrdp_delta(self.default_handle.clone(), rrdp_updates_config);
            let content = self.store.send_command(command)?;

            debug!("   update repository on disk");
            content.write_repository(rrdp_updates_config)?;
            debug!("Done publishing");
        }

        Ok(())
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
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
        debug!("Publish delta for {}", publisher);

        debug!("   get content");
        let content = self.get_default_content()?;
        debug!("   get objects for {}", publisher);
        let current_objects = content.objects_for_publisher(&publisher)?;
        let delta = DeltaElements::from(delta);

        debug!("   verify delta");
        current_objects.verify_delta(&delta, jail)?;

        let command = RepositoryContentCommand::publish(self.default_handle.clone(), publisher, delta);
        let content = self.store.send_command(command)?;

        // TODO: move this to MQ / Scheduler
        if content.rrdp.update_rrdp_needed(rrdp_updates_config) {
            debug!("   create new RRDP delta");
            let command = RepositoryContentCommand::create_rrdp_delta(self.default_handle.clone(), rrdp_updates_config);
            let content = self.store.send_command(command)?;

            debug!("   update repository on disk");
            content.write_repository(rrdp_updates_config)?;
            debug!("Done publishing");
        }

        Ok(())
    }

    /// Write all current files to disk
    pub fn write_repository(&self, rrdp_updates_config: RrdpUpdatesConfig) -> KrillResult<()> {
        let content = self.get_default_content()?;
        content.write_repository(rrdp_updates_config)
    }

    /// Reset the RRDP session if it is initialized. Otherwise do nothing.
    pub fn session_reset(&self, rrdp_updates_config: RrdpUpdatesConfig) -> KrillResult<()> {
        if self.store.has(&self.default_handle)? {
            let command = RepositoryContentCommand::session_reset(self.default_handle.clone());
            let content = self.store.send_command(command)?;

            content.write_repository(rrdp_updates_config)
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
    },
    Publish {
        handle: MyHandle,
        publisher: PublisherHandle,
        delta: DeltaElements,
    },
    CreateRrdpDelta {
        handle: MyHandle,
        rrdp_updates_config: RrdpUpdatesConfig,
    },
}

impl RepositoryContentCommand {
    pub fn session_reset(handle: MyHandle) -> Self {
        RepositoryContentCommand::ResetSession { handle }
    }

    pub fn add_publisher(handle: MyHandle, publisher: PublisherHandle) -> Self {
        RepositoryContentCommand::AddPublisher { handle, publisher }
    }

    pub fn remove_publisher(handle: MyHandle, publisher: PublisherHandle) -> Self {
        RepositoryContentCommand::RemovePublisher { handle, publisher }
    }
    pub fn publish(handle: MyHandle, publisher: PublisherHandle, delta: DeltaElements) -> Self {
        RepositoryContentCommand::Publish {
            handle,
            publisher,
            delta,
        }
    }
    pub fn create_rrdp_delta(handle: MyHandle, rrdp_updates_config: RrdpUpdatesConfig) -> Self {
        RepositoryContentCommand::CreateRrdpDelta {
            handle,
            rrdp_updates_config,
        }
    }
}

impl WalCommand for RepositoryContentCommand {
    fn handle(&self) -> &MyHandle {
        match self {
            RepositoryContentCommand::ResetSession { handle }
            | RepositoryContentCommand::AddPublisher { handle, .. }
            | RepositoryContentCommand::RemovePublisher { handle, .. }
            | RepositoryContentCommand::Publish { handle, .. }
            | RepositoryContentCommand::CreateRrdpDelta { handle, .. } => handle,
        }
    }
}

impl fmt::Display for RepositoryContentCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentCommand::ResetSession { handle } => {
                write!(f, "reset session for repository {}", handle)
            }
            RepositoryContentCommand::CreateRrdpDelta { handle, .. } => {
                write!(f, "create next RRDP delta for repository {}", handle)
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
    RrdpDeltaStaged {
        delta: DeltaElements,
    },
    RrdpUpdated {
        update: RrdpUpdated,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpSessionReset {
    last_update: Time,
    session: RrdpSession,
    snapshot: SnapshotData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpUpdated {
    time: Time,
    random: RrdpFileRandom,
    deltas_truncate: usize,
}

impl fmt::Display for RepositoryContentChange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentChange::SessionReset { reset } => write!(f, "RRDP session reset to: {}", reset.session),
            RepositoryContentChange::RrdpDeltaStaged { .. } => write!(f, "RRDP changes staged"),
            RepositoryContentChange::RrdpUpdated { .. } => write!(f, "RRDP updated"),
            RepositoryContentChange::PublisherAdded { publisher } => write!(f, "added publisher: {}", publisher),
            RepositoryContentChange::PublisherRemoved { publisher } => write!(f, "removed publisher: {}", publisher),
            RepositoryContentChange::PublishedObjects { publisher, .. } => write!(f, "published for: {}", publisher),
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
                RepositoryContentChange::RrdpDeltaStaged { delta } => self.rrdp.apply_rrdp_staged(delta),
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
            RepositoryContentCommand::CreateRrdpDelta {
                rrdp_updates_config, ..
            } => self.create_rrdp_delta(rrdp_updates_config),
            RepositoryContentCommand::AddPublisher { publisher, .. } => self.add_publisher(publisher),
            RepositoryContentCommand::RemovePublisher { publisher, .. } => self.remove_publisher(publisher),
            RepositoryContentCommand::Publish { publisher, delta, .. } => self.publish(publisher, delta),
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

    fn reset_session(&self) -> KrillResult<Vec<RepositoryContentChange>> {
        info!("Performing RRDP session reset.");
        let reset = self.rrdp.reset_session();

        Ok(vec![RepositoryContentChange::SessionReset { reset }])
    }

    pub fn write_repository(&self, config: RrdpUpdatesConfig) -> KrillResult<()> {
        self.rrdp.write(config)?;
        self.rsync.write(self.rrdp.serial, self.rrdp.snapshot())
    }

    fn add_publisher(&self, publisher: PublisherHandle) -> KrillResult<Vec<RepositoryContentChange>> {
        Ok(vec![RepositoryContentChange::PublisherAdded { publisher }])
    }

    /// Removes the content for a publisher. This function will return
    /// ok if there is no content to remove - it is idempotent in that
    /// sense. However, if there are I/O errors removing the content then
    /// this function will fail.
    fn remove_publisher(&self, publisher: PublisherHandle) -> KrillResult<Vec<RepositoryContentChange>> {
        let mut res = vec![];
        // withdraw objects if any
        if let Ok(objects) = self.objects_for_publisher(&publisher) {
            let withdraws = objects.elements().iter().map(|e| e.as_withdraw()).collect();
            let delta = DeltaElements::new(vec![], vec![], withdraws);
            res.push(RepositoryContentChange::RrdpDeltaStaged { delta });
        }

        // remove publisher if present
        if self.publishers.contains_key(&publisher) {
            res.push(RepositoryContentChange::PublisherRemoved { publisher });
        }

        Ok(res)
    }

    /// Publish content for a publisher. Assumes that the delta was
    /// already checked (this is done in RepositoryContentProxy::publish).
    fn publish(&self, publisher: PublisherHandle, delta: DeltaElements) -> KrillResult<Vec<RepositoryContentChange>> {
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
        debug!("   stage elements in RRDP state");
        res.push(RepositoryContentChange::RrdpDeltaStaged { delta });

        Ok(res)
    }

    /// Update the RRDP state
    fn create_rrdp_delta(&self, rrdp_config: RrdpUpdatesConfig) -> KrillResult<Vec<RepositoryContentChange>> {
        if self.rrdp.update_rrdp_needed(rrdp_config) {
            let update = self.rrdp.update_rrdp(rrdp_config)?;
            Ok(vec![RepositoryContentChange::RrdpUpdated { update }])
        } else {
            Ok(vec![])
        }
    }

    /// Returns the content stats for the repo
    pub fn stats(&self) -> RepoStats {
        RepoStats {
            publishers: self.publisher_stats(),
            session: self.rrdp.session,
            serial: self.rrdp.serial,
            last_update: Some(self.rrdp.last_update),
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
    last_update: Time,

    snapshot: SnapshotData,
    deltas: VecDeque<DeltaData>,

    #[serde(default)]
    staged_elements: StagedElements,
}

/// This type is used to combine staged delta elements for publishers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StagedElements(HashMap<uri::Rsync, DeltaElement>);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeltaElement {
    Publish(PublishElement),
    Update(UpdateElement),
    Withdraw(WithdrawElement),
}

impl RrdpServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rrdp_base_uri: uri::Https,
        rrdp_base_dir: PathBuf,
        rrdp_archive_dir: PathBuf,
        session: RrdpSession,
        serial: u64,
        last_update: Time,
        snapshot: SnapshotData,
        deltas: VecDeque<DeltaData>,
        staged_elements: StagedElements,
    ) -> Self {
        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            last_update,
            snapshot,
            deltas,
            staged_elements,
        }
    }

    pub fn create(rrdp_base_uri: uri::Https, repo_dir: &Path, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = repo_dir.to_path_buf();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let mut rrdp_archive_dir = repo_dir.to_path_buf();
        rrdp_archive_dir.push(REPOSITORY_RRDP_ARCHIVE_DIR);

        let serial = RRDP_FIRST_SERIAL;
        let last_update = Time::now();
        let snapshot = SnapshotData::create();

        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            last_update,
            snapshot,
            deltas: VecDeque::new(),
            staged_elements: StagedElements::default(),
        }
    }

    fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rrdp_base_dir);
        let _ = fs::remove_dir_all(&self.rrdp_archive_dir);
    }

    fn snapshot(&self) -> &SnapshotData {
        &self.snapshot
    }

    pub fn reset_session(&self) -> RrdpSessionReset {
        let last_update = Time::now();
        let session = RrdpSession::random();
        let snapshot = self.snapshot.with_new_random();

        RrdpSessionReset {
            last_update,
            snapshot,
            session,
        }
    }

    /// Applies the data from an RrdpSessionReset change.
    fn apply_session_reset(&mut self, reset: RrdpSessionReset) {
        self.snapshot = reset.snapshot;
        self.session = reset.session;
        self.last_update = reset.last_update;
        self.serial = RRDP_FIRST_SERIAL;
        self.deltas = VecDeque::new();
    }

    /// Applies staged DeltaElements
    fn apply_rrdp_staged(&mut self, elements: DeltaElements) {
        let (publishes, updates, withdraws) = elements.unpack();
        for pbl in publishes {
            let uri = pbl.uri().clone();
            // A publish that follows a withdraw for the same URI should be Update.
            if let Some(DeltaElement::Withdraw(staged_withdraw)) = self.staged_elements.0.get(&uri) {
                let hash = *staged_withdraw.hash();
                let update = UpdateElement::new(uri.clone(), hash, pbl.base64().clone());
                self.staged_elements.0.insert(uri, DeltaElement::Update(update));
            } else {
                // In any other case we just keep the new publish.
                // Because deltas are checked before they are applied we know that publish
                // elements cannot occur after another publish or update. They would have
                // had to be an update in that case.
                // Because this is checked when the publication delta is submitted, we can
                // ignore this case here.
                self.staged_elements.0.insert(uri, DeltaElement::Publish(pbl));
            };
        }

        for mut upd in updates {
            let uri = upd.uri().clone();
            // An update that follows a staged publish, should be fresh publish.
            // An update that follows a staged update, should use the hash from the previous update.
            // An update cannot follow a staged withdraw. It would have been a publish in that case.
            if let Some(DeltaElement::Publish(_)) = self.staged_elements.0.get(&uri) {
                self.staged_elements
                    .0
                    .insert(uri, DeltaElement::Publish(upd.into_publish()));
            } else if let Some(DeltaElement::Update(staged_update)) = self.staged_elements.0.get(&uri) {
                upd.updates_staged(staged_update); // set hash to previous update hash
                self.staged_elements.0.insert(uri, DeltaElement::Update(upd));
            } else {
                self.staged_elements.0.insert(uri, DeltaElement::Update(upd));
            }
        }

        for wdr in withdraws {
            // withdraws should always remove any staged publishes or updates.
            // they cannot follow staged withdraws (checked when delta is submitted)
            // so just add them all to the staged elements
            self.staged_elements
                .0
                .insert(wdr.uri().clone(), DeltaElement::Withdraw(wdr));
        }
    }

    /// Applies the data from an RrdpUpdated change.
    fn apply_rrdp_updated(&mut self, update: RrdpUpdated) {
        self.serial += 1;

        let mut staged_elements = StagedElements::default();
        std::mem::swap(&mut self.staged_elements, &mut staged_elements);

        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];
        for el in staged_elements.0.into_values() {
            match el {
                DeltaElement::Publish(pbl) => publishes.push(pbl),
                DeltaElement::Update(upd) => updates.push(upd),
                DeltaElement::Withdraw(wdr) => withdraws.push(wdr),
            }
        }
        let delta_elements = DeltaElements::new(publishes, updates, withdraws);

        let delta = DeltaData::new(self.serial, update.time, update.random, delta_elements);

        self.snapshot = self
            .snapshot
            .with_delta(delta.random().clone(), delta.elements().clone());

        self.deltas.truncate(update.deltas_truncate);
        self.deltas.push_front(delta);
        self.deltas_truncate_size();
    }

    /// Checks whether an RRDP update is needed
    fn update_rrdp_needed(&self, rrdp_updates_config: RrdpUpdatesConfig) -> bool {
        if self.staged_elements.0.is_empty() {
            debug!("No RRDP update is needed, there are no staged changes");
            false
        } else if let Some(minutes) = rrdp_updates_config.rrdp_delta_rrdp_delta_interval_mins {
            let needed = self.last_update < Time::now() + Duration::minutes(minutes.into());
            if needed {
                debug!(
                    "RRDP update is needed, last update was longer than {} minutes ago.",
                    minutes
                );
            } else {
                debug!(
                    "No RRDP update is needed, last update was at: {}",
                    self.last_update.to_rfc3339()
                );
            }
            needed
        } else {
            // No interval limit was set, always publish.
            debug!("RRDP update is needed, no staging interval was configured");
            true
        }
    }

    /// Updates the RRDP server with the staged delta elements.
    fn update_rrdp(&self, rrdp_updates_config: RrdpUpdatesConfig) -> KrillResult<RrdpUpdated> {
        let time = Time::now();
        let random = RrdpFileRandom::default();

        let deltas_truncate = self.find_deltas_truncate_age(rrdp_updates_config);

        Ok(RrdpUpdated {
            time,
            random,
            deltas_truncate,
        })
    }

    /// Truncate excessive deltas based on size. This is done
    /// after applying an RrdpUpdate because the outcome is
    /// deterministic. Compared to truncating the deltas based
    /// on age and number, because *that* depends on when the
    /// update was generated, and what the RrdpUpdatesConfig
    /// was set to at the time.
    fn deltas_truncate_size(&mut self) {
        let snapshot_size = self.snapshot().size();
        let mut total_deltas_size = 0;
        let mut keep = 0;

        for delta in &self.deltas {
            total_deltas_size += delta.elements().size();
            if total_deltas_size > snapshot_size {
                // never keep more than the size of the snapshot
                break;
            } else {
                keep += 1;
            }
        }

        self.deltas.truncate(keep);
    }

    /// Get the position to truncate excessive deltas, before applying the next delta:
    ///  - always keep 'rrdp_delta_files_min_nr' files
    ///  - always keep 'rrdp_delta_files_min_seconds' files
    ///  - beyond this:
    ///     - never keep more than 'rrdp_delta_files_max_nr'
    ///     - never keep older than 'rrdp_delta_files_max_seconds'
    ///     - keep the others
    fn find_deltas_truncate_age(&self, rrdp_updates_config: RrdpUpdatesConfig) -> usize {
        // We will keep the new delta - not yet added to this.
        let mut keep = 0;

        let min_nr = rrdp_updates_config.rrdp_delta_files_min_nr;
        let min_secs = rrdp_updates_config.rrdp_delta_files_min_seconds;
        let max_nr = rrdp_updates_config.rrdp_delta_files_max_nr;
        let max_secs = rrdp_updates_config.rrdp_delta_files_max_seconds;

        for delta in &self.deltas {
            if keep < min_nr || delta.younger_than_seconds(min_secs.into()) {
                // always keep 'rrdp_delta_files_min_nr' files
                //    we need < min_nr because we will add the new delta later
                // always keep 'rrdp_delta_files_min_seconds' file
                keep += 1
            } else if keep == max_nr - 1 || delta.older_than_seconds(max_secs.into()) {
                // never keep more than 'rrdp_delta_files_max_nr'
                //    we need max_nr -1 because we will add the new new delta later
                // never keep older than 'rrdp_delta_files_max_seconds'
                break;
            } else {
                // keep the remainder
                keep += 1;
            }
        }

        keep
    }

    /// Write the (missing) RRDP files to disk, and remove the ones
    /// no longer referenced in the notification file.
    fn write(&self, rrdp_updates_config: RrdpUpdatesConfig) -> Result<(), Error> {
        // Get the current notification file from disk, if it exists, so
        // we can determine which (new) snapshot and delta files to write,
        // and which old snapshot and delta files may be removed.
        debug!("Write updated RRDP state to disk - if there are any updates that is.");

        // Get the current notification file - as long as it's present and can
        // be parsed. If it cannot be parsed we just ignore it. I.e. we will generate
        // all current files in that case.
        let old_notification_opt: Option<NotificationFile> = file::read(&self.notification_path())
            .ok()
            .and_then(|bytes| rpki::rrdp::NotificationFile::parse(bytes.as_ref()).ok());

        if let Some(old_notification) = old_notification_opt.as_ref() {
            if old_notification.serial() == self.serial && old_notification.session_id() == self.session.into() {
                debug!("Existing notification file matches current session and serial. Nothing to write.");
                return Ok(());
            }
        }

        let deltas = self.write_delta_files(old_notification_opt)?;
        let snapshot = self.write_snapshot_file()?;

        self.write_notification_file(snapshot, deltas)?;

        // clean up under the base dir:
        self.cleanup_old_rrdp_files(rrdp_updates_config)
    }

    fn write_delta_files(&self, old_notification_opt: Option<NotificationFile>) -> KrillResult<Vec<DeltaInfo>> {
        // Find existing deltas in current file, if present and still applicable:
        // - there is a notification that can be parsed
        // - session did not change
        // - deltas have an overlap with current deltas (otherwise just regenerate new deltas)
        //
        // We will assume that files for deltas still exist on disk and were not changed, so we will not regenerate them.
        //
        // NOTE: if both session and serial remain unchanged we just return with Ok(()). There is no work.
        let mut deltas_from_old_notification: Vec<rpki::rrdp::DeltaInfo> = match old_notification_opt {
            None => {
                debug!("No old notification file found");
                vec![]
            }
            Some(mut old_notification) => {
                if old_notification.session_id() == self.session.into() {
                    // Sort the deltas from lowest serial up, and make sure that there are no gaps.
                    if old_notification.sort_and_verify_deltas(None) {
                        debug!("Found existing notification file for current session with deltas.");
                        old_notification.deltas().to_vec()
                    } else {
                        debug!("Found existing notification file with incomplete deltas, will regenerate files.");
                        vec![]
                    }
                } else {
                    debug!("Existing notification file was for different session, will regenerate all files.");
                    vec![]
                }
            }
        };

        // Go over the deltas we found and discard any delta with a serial that we no longer kept.
        // The deltas in the RrdpServer are sorted from highest to lowest serial (to make it easier to truncate).
        if let Some(last) = self.deltas.back() {
            // Only keep deltas are still kept.
            deltas_from_old_notification.retain(|delta| delta.serial() >= last.serial());
        } else if !deltas_from_old_notification.is_empty() {
            // We would expect the existing deltas to be empty as well in this case. But in any case,
            // wiping them will ensure we generate a new sane NotificationFile
            deltas_from_old_notification = vec![];
        }

        // Write new delta files and add their DeltaInfo to the list to include in the new notification file.
        // I.e. skip deltas that are still included in the curated list we got from the old notification.
        let last_written_serial = deltas_from_old_notification.last();
        let mut deltas = vec![];
        for delta in &self.deltas {
            if let Some(last) = last_written_serial {
                if delta.serial() <= last.serial() {
                    // Already included. We can skip this and assume that it was written to disk before.
                    // And no one went in and messed with it..
                    debug!("Skip writing delta for serial {}. File should exist.", delta.serial());
                    continue;
                }
            }
            // New delta, write it and add its distinctiveness to deltas (DeltaInfo vec) to include
            // in the notification file that we will write.
            let path = delta.path(self.session, delta.serial(), &self.rrdp_base_dir);
            let uri = delta.uri(self.session, delta.serial(), &self.rrdp_base_uri);
            let xml_bytes = delta.xml(self.session, delta.serial());
            let hash = Hash::from_data(xml_bytes.as_slice());

            debug!("Write delta file to: {}", path.to_string_lossy());
            file::save(&xml_bytes, &path)?;

            deltas.push(DeltaInfo::new(delta.serial(), uri, hash));
        }

        // Reverse the order of the (old) deltas so that it also goes high to low, and
        // we can get the new complete list to include in the notification file.
        deltas_from_old_notification.reverse();
        deltas.append(&mut deltas_from_old_notification);

        Ok(deltas)
    }

    fn write_snapshot_file(&self) -> KrillResult<SnapshotInfo> {
        let path = self.snapshot().path(self.session, self.serial, &self.rrdp_base_dir);
        let uri = self.snapshot().uri(self.session, self.serial, &self.rrdp_base_uri);
        let xml_bytes = self.snapshot().xml(self.session, self.serial);
        let hash = Hash::from_data(&xml_bytes);

        debug!("Write snapshot file to: {}", path.to_string_lossy());
        file::save(&xml_bytes, &path)?;

        Ok(SnapshotInfo::new(uri, hash))
    }

    fn write_notification_file(&self, snapshot: SnapshotInfo, deltas: Vec<DeltaInfo>) -> KrillResult<()> {
        // Write new notification file to new file first.
        // Prevent that half-overwritten files are served.
        let notification = NotificationFile::new(self.session.into(), self.serial, snapshot, deltas);
        let notification_path_new = self.notification_path_new();
        let mut notification_file_new = file::create_file_with_path(&notification_path_new)?;
        notification.write_xml(&mut notification_file_new).map_err(|e| {
            KrillIoError::new(
                format!(
                    "could not write new notification file to {}",
                    notification_path_new.to_string_lossy()
                ),
                e,
            )
        })?;

        // Rename the new file so it becomes current.
        let notification_path = self.notification_path();
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

        Ok(())
    }

    fn cleanup_old_rrdp_files(&self, rrdp_updates_config: RrdpUpdatesConfig) -> KrillResult<()> {
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
        let session_dir = self.rrdp_base_dir.join(self.session.to_string());

        // Get the delta range to keep. We use 0 as a special value, because it
        // is never used for deltas: i.e. no delta dirs will match if our delta
        // list is empty.
        let lowest_delta = self.deltas.back().map(|delta| delta.serial()).unwrap_or(0);
        let highest_delta = self.deltas.front().map(|delta| delta.serial()).unwrap_or(0);

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
                } else if serial < lowest_delta || serial > highest_delta {
                    if rrdp_updates_config.rrdp_files_archive {
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
                } else if !rrdp_updates_config.rrdp_files_archive {
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
        serial: u64,
        last_update: Time,
    ) {
        self.publishers.insert(publisher.clone(), publisher_stats);
        self.serial = serial;
        self.last_update = Some(last_update);
    }

    pub fn session_reset(&mut self, session: RrdpSession, serial: u64, last_update: Time) {
        self.session = session;
        self.serial = serial;
        self.last_update = Some(last_update)
    }

    pub fn new_publisher(&mut self, publisher: &PublisherHandle) {
        self.publishers.insert(publisher.clone(), PublisherStats::default());
    }

    pub fn remove_publisher(&mut self, publisher: &PublisherHandle, serial: u64, last_update: Time) {
        self.publishers.remove(publisher);
        self.serial = serial;
        self.last_update = Some(last_update);
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
