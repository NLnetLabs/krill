use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::mem;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};
use std::sync::{Arc, RwLock};

use rpki::crypto::KeyIdentifier;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::rrdp::{
    CurrentObjects, Delta, DeltaElements, DeltaRef, FileRef, Notification, RrdpSession, Snapshot, SnapshotRef,
};
use crate::commons::api::{Handle, HexEncodedHash, PublishDelta, PublisherHandle, RepoInfo, StorableRepositoryCommand};
use crate::commons::crypto::IdCert;
use crate::commons::error::Error;
use crate::commons::eventsourcing::Aggregate;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::commons::KrillResult;
use crate::constants::{
    test_mode_enabled, REPOSITORY_NOTIFICATION_RETAIN_SECONDS, REPOSITORY_RRDP_DIR, REPOSITORY_RSYNC_DIR,
};
use crate::pubd::events::RrdpSessionReset;
use crate::pubd::publishers::Publisher;
use crate::pubd::{Cmd, CmdDet, Evt, EvtDet, Ini, RrdpUpdate};

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
}

/// The RRDP server used by a Repository instance
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RrdpServer {
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

    snapshot: Snapshot,
    deltas: Vec<Delta>,
}

impl RrdpServer {
    fn new(rrdp_base_uri: uri::Https, repo_dir: &PathBuf, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = PathBuf::from(repo_dir);
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let snapshot = Snapshot::new(session);

        let serial = 0;
        let snapshot_uri = Self::new_snapshot_uri(&rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        RrdpServer {
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

    fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Performs a session reset of the RRDP server. Useful if the serial needs
    /// to be rolled, or in case the RRDP server needed to recover to a previous
    /// state.
    fn session_reset(&self) -> Result<RrdpSessionReset, Error> {
        let session = RrdpSession::new();
        let serial = 0;

        let snapshot = self.snapshot.session_reset(session);

        let snapshot_uri = Self::new_snapshot_uri(&self.rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&self.rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session, snapshot_ref);

        Ok(RrdpSessionReset::new(snapshot, notification))
    }

    fn apply_reset(&mut self, reset: RrdpSessionReset) {
        let (snapshot, notification) = reset.unpack();

        self.serial = notification.serial();
        self.session = notification.session();
        self.notification = notification;
        self.old_notifications.clear();
        self.snapshot = snapshot;
        self.deltas = vec![];
    }

    /// Updates the RRDP server with the elements. Note that this assumes that
    /// the delta has already been checked against the jail and current
    /// objects of the publisher. Also note that this only becomes effective
    /// after the corresponding events have been applied.
    fn publish(&self, elements: DeltaElements) -> Result<RrdpUpdate, Error> {
        let next = self.serial + 1;

        let delta = Delta::new(self.session, next, elements);

        let mut next_snapshot = self.snapshot.clone();
        next_snapshot.apply_delta(delta.clone());

        let snapshot_uri = self.snapshot_uri(next);
        let snapshot_path = self.snapshot_path(next);
        let snapshot_xml = next_snapshot.xml();
        let snapshot_hash = HexEncodedHash::from_content(snapshot_xml.as_slice());
        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        // keep at least 5 deltas if available, but beyond that no
        // more then the combined size of which would exceed the
        // size of the snapshot.
        let snapshot_size = next_snapshot.size();
        let mut deltas_size = delta.elements().size();

        let mut deltas = vec![&delta];

        for delta in &self.deltas {
            if deltas.len() < 5 {
                deltas.push(delta)
            } else {
                deltas_size += delta.elements().size();
                if deltas_size < snapshot_size {
                    deltas.push(delta)
                } else {
                    break;
                }
            }
        }

        let refs: Vec<DeltaRef> = deltas
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

        let notification = Notification::new(self.session, next, snapshot_ref, refs);

        Ok(RrdpUpdate::new(delta, notification))
    }

    /// Update the current RRDP state (as recorded in an event)
    pub fn apply_update(&mut self, update: RrdpUpdate) {
        let (delta, mut notification) = update.unpack();

        self.serial = notification.serial();

        mem::swap(&mut self.notification, &mut notification);
        notification.replace(self.notification.time());
        self.old_notifications.push_front(notification);

        let mut retain_secs = REPOSITORY_NOTIFICATION_RETAIN_SECONDS;

        if test_mode_enabled() {
            retain_secs = 1;
        }

        let threshold_timestamp = self.notification.time().timestamp() - retain_secs;
        self.old_notifications.retain(|n| n.replaced_after(threshold_timestamp));

        let mut snapshot = self.snapshot.clone();
        snapshot.apply_delta(delta.clone());
        self.snapshot = snapshot;

        let last_delta = self.notification.last_delta().unwrap(); // always at least 1 delta for updates
        self.deltas.insert(0, delta);
        self.deltas.retain(|d| d.serial() >= last_delta);
    }

    /// Write the (missing) RRDP files to disk, and remove the ones
    /// no longer referenced in the notification file.
    fn write(&self) -> Result<(), Error> {
        let mut something_changed = false;

        // write snapshot if it's not there
        let snapshot_path = self.snapshot_path(self.serial);
        if !snapshot_path.exists() {
            self.snapshot.write_xml(&snapshot_path)?;
            something_changed = true;
        }

        // write deltas if they are not there
        for delta in &self.deltas {
            let path = self.delta_path(delta.serial());
            if !path.exists() {
                // assume that if the delta exists, it is correct
                delta.write_xml(&path)?;
                something_changed = true;
            }
        }

        // if nothing changed then we're done
        if !something_changed {
            return Ok(());
        }

        // something changed, update notification file
        let notification_path = self.notification_path();
        self.notification.write_xml(&notification_path)?;

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

        info!(
            "Will try to clean old RRDP files and dirs under: {}",
            session_dir.to_string_lossy()
        );

        for entry in fs::read_dir(&session_dir)? {
            let entry = entry?;
            let path = entry.path();

            // remove any dir or file that is:
            // - not a number
            // - a number that is higher than the current serial
            // - a number that is lower than the last delta (if set)
            if let Ok(serial) = u64::from_str(entry.file_name().to_string_lossy().as_ref()) {
                trace!("Found serial: {}", serial);

                // Skip the current serial
                if serial == self.serial {
                    trace!("Matches current serial, skipping");
                    continue;
                // Clean up old serial dirs
                } else if !self.notification.includes_delta(serial)
                    && !self.old_notifications.iter().any(|n| n.includes_delta(serial))
                {
                    info!("Deltas no longer contained, will delete: {}", path.to_string_lossy());
                    if path.is_dir() {
                        let _best_effort_rm = fs::remove_dir_all(path);
                    } else {
                        let _best_effort_rm = fs::remove_file(path);
                    }
                // clean snapshots no longer referenced in retained notification files
                } else if !self.old_notifications.iter().any(|n| n.includes_snapshot(serial)) {
                    let snapshot_path = Self::new_snapshot_path(&self.rrdp_base_dir, &self.session, serial);
                    if snapshot_path.exists() {
                        info!(
                            "Snapshots no longer contained, will delete: {}",
                            snapshot_path.to_string_lossy()
                        );
                        let _best_effort_rm = fs::remove_file(snapshot_path);
                    }
                } else {
                    trace!("looks like we still need this");
                }
            } else {
                // clean up dirs or files under the base dir which are not sessions
                info!(
                    "Found some other file or dir - will try to remove: {}",
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
        uri::Https::from_string(format!("{}notification.xml", self.rrdp_base_uri.to_string())).unwrap()
        // Cannot fail. Config checked at startup.
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
        uri::Https::from_string(format!("{}{}", base.to_string(), Self::snapshot_rel(session, serial))).unwrap()
        // Cannot fail. Config checked at startup.
    }

    fn snapshot_uri(&self, serial: u64) -> uri::Https {
        Self::new_snapshot_uri(&self.rrdp_base_uri, &self.session, serial)
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

//------------ Repository --------------------------------------------------

/// An RFC8183 Repository server, capable of handling Publishers (both embedded, and
/// remote RFC8183), and publishing to RRDP and disk, and signing responses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Repository {
    // Event sourcing support
    handle: Handle,
    version: u64,

    id_cert: IdCert,
    key_id: KeyIdentifier, // convenience access to id_cert pub key id

    publishers: HashMap<PublisherHandle, Publisher>,

    rrdp: RrdpServer,
    rsync: RsyncdStore,

    #[serde(default = "RepoStats::default")]
    stats: RepoStats,
}

impl Repository {
    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
}

/// # Event Sourcing support
///
impl Aggregate for Repository {
    type Command = Cmd;
    type StorableCommandDetails = StorableRepositoryCommand;
    type Event = Evt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();
        let (id_cert, session, rrdp_base_uri, rsync_jail, repo_base_dir) = details.unpack();

        let key_id = id_cert.subject_public_key_info().key_identifier();

        let stats = RepoStats::new(session);

        let rrdp = RrdpServer::new(rrdp_base_uri, &repo_base_dir, session);
        let rsync = RsyncdStore::new(rsync_jail, &repo_base_dir);

        Ok(Repository {
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
            EvtDet::PublisherAdded(publisher_handle, publisher) => {
                self.stats.new_publisher(&publisher_handle);
                self.publishers.insert(publisher_handle, publisher);
            }
            EvtDet::PublisherRemoved(publisher_handle, update) => {
                self.publishers.remove(&publisher_handle);
                self.rrdp.apply_update(update);
                self.stats.remove_publisher(&publisher_handle, &self.rrdp.notification);
            }
            EvtDet::Published(publisher_handle, update) => {
                // update content for publisher
                self.update_publisher(&publisher_handle, &update);

                let time = update.time();

                // update RRDP server
                self.rrdp.apply_update(update);

                // Can only have events for existing publishers, so unwrap is okay
                let publisher = self.get_publisher(&publisher_handle).unwrap();
                let publisher_stats = PublisherStats::new(publisher, time);

                let notification = &self.rrdp.notification;

                self.stats.publish(&publisher_handle, publisher_stats, notification)
            }
            EvtDet::RrdpSessionReset(reset) => {
                self.stats.session_reset(&reset);
                self.rrdp.apply_reset(reset);
            }
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        info!(
            "Sending command to publisher '{}', version: {}: {}",
            self.handle, self.version, command
        );

        match command.into_details() {
            CmdDet::AddPublisher(publisher_request) => self.add_publisher(publisher_request),
            CmdDet::RemovePublisher(publisher) => self.remove_publisher(publisher),
            CmdDet::Publish(publisher_handle, delta) => self.publish(publisher_handle, delta),
            CmdDet::SessionReset => self.session_reset(),
        }
    }
}

/// # Manage publishers
///
impl Repository {
    fn add_publisher(&self, publisher_request: rfc8183::PublisherRequest) -> Result<Vec<Evt>, Error> {
        let (_tag, handle, id_cert) = publisher_request.unpack();

        if self.publishers.contains_key(&handle) {
            Err(Error::PublisherDuplicate(handle))
        } else {
            let base_uri = uri::Rsync::from_string(format!("{}{}/", self.rsync.base_uri, handle)).unwrap();
            let publisher = Publisher::new(id_cert, base_uri, CurrentObjects::default());

            Ok(vec![EvtDet::publisher_added(
                &self.handle,
                self.version,
                handle,
                publisher,
            )])
        }
    }

    /// Removes a publisher and all its content
    fn remove_publisher(&self, publisher_handle: PublisherHandle) -> Result<Vec<Evt>, Error> {
        let publisher = self.get_publisher(&publisher_handle)?;

        let withdraws = publisher
            .current_objects()
            .elements()
            .iter()
            .map(|p| p.as_withdraw())
            .collect();
        let elements = DeltaElements::new(vec![], vec![], withdraws);
        let update = self.rrdp.publish(elements)?;

        Ok(vec![EvtDet::publisher_removed(
            &self.handle,
            self.version,
            publisher_handle,
            update,
        )])
    }

    pub fn repo_info_for(&self, publisher: &PublisherHandle) -> RepoInfo {
        let publisher_rsync_base = uri::Rsync::from_str(&format!("{}{}/", self.rsync.base_uri, publisher)).unwrap();

        RepoInfo::new(publisher_rsync_base, self.rrdp.notification_uri())
    }

    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher_handle: &PublisherHandle,
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        let publisher = self.get_publisher(publisher_handle)?;
        let rsync_base = publisher.base_uri();
        let service_uri = rfc8183::ServiceUri::Https(rfc8181_uri);

        let repo_info = RepoInfo::new(rsync_base.clone(), self.rrdp.notification_uri());

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

    pub fn stats(&self) -> &RepoStats {
        &self.stats
    }

    pub fn publishers(&self) -> Vec<PublisherHandle> {
        self.publishers.keys().cloned().collect()
    }

    fn update_publisher(&mut self, publisher: &PublisherHandle, update: &RrdpUpdate) {
        self.publishers
            .get_mut(publisher)
            .unwrap()
            .apply_delta(update.elements().clone())
    }
}

/// # Publish
///
impl Repository {
    fn session_reset(&self) -> Result<Vec<Evt>, Error> {
        let session_reset = self.rrdp.session_reset()?;
        Ok(vec![EvtDet::rrdp_session_reset(
            &self.handle,
            self.version,
            session_reset,
        )])
    }

    fn publish(&self, publisher_handle: PublisherHandle, delta: PublishDelta) -> Result<Vec<Evt>, Error> {
        let publisher = self.get_publisher(&publisher_handle)?;
        let delta_elements = DeltaElements::from(delta);
        publisher.verify_delta(&delta_elements)?;
        let rrdp_update = self.rrdp.publish(delta_elements)?;

        Ok(vec![EvtDet::published(
            &self.handle,
            self.version,
            publisher_handle,
            rrdp_update,
        )])
    }

    /// Update the RRPD and Rsync files on disk.
    pub fn write(&self) -> Result<(), Error> {
        // update RRDP
        self.rrdp.write()?;

        // re-sync RRDP snapshot to rsync files
        let snapshot = self.rrdp.snapshot();
        self.rsync.write(snapshot)?;

        Ok(())
    }
}

/// # Miscellaneous
///
impl Repository {
    pub fn regenerate_stats(&mut self) {
        let mut stats = RepoStats::default();
        for (handle, details) in &self.publishers {
            let publisher_stats: PublisherStats = details.current_objects().into();
            stats.publishers.insert(handle.clone(), publisher_stats);
        }
        stats.serial = self.rrdp.serial;
        stats.session = self.rrdp.session;

        self.stats = stats;
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

    pub fn session_reset(&mut self, reset: &RrdpSessionReset) {
        let notification = reset.notification();
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
    pub fn new(publisher: &Publisher, last_update: Time) -> Self {
        let objects = publisher.current_objects().len();
        let size = publisher.current_objects().size();
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

//------------ Tests ---------------------------------------------------------
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn deserialize_0_4_2_snapshot() {
        let json = include_str!("../../test-resources/repository/snapshot-v042.json");
        let mut repo: Repository = serde_json::from_str(json).unwrap();
        repo.regenerate_stats();
    }
}
