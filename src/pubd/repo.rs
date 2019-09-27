use std::path::PathBuf;
use std::{fs, io};

use chrono::Duration;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::rrdp::{
    Delta, DeltaElements, DeltaRef, FileRef, Notification, NotificationUpdate, Snapshot,
    SnapshotRef,
};
use crate::commons::api::Handle;
use crate::commons::eventsourcing::{Aggregate, CommandDetails, SentCommand, StoredEvent};
use crate::commons::util::file;

const RRDP_FOLDER: &str = "rrdp";
const RSYNC_FOLDER: &str = "rsync";

pub const ID: &str = "rrdp_server";
pub fn id() -> Handle {
    Handle::from_str_unsafe(ID)
}

//------------ RrdpInit ------------------------------------------------------

pub type RrdpInit = StoredEvent<RrdpInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RrdpInitDetails {
    session: String,
    base_uri: uri::Https,
    repo_dir: PathBuf,
}

impl RrdpInitDetails {
    pub fn init_new(base_uri: uri::Https, repo_dir: PathBuf) -> RrdpInit {
        use uuid::Uuid;
        let session = format!("{}", Uuid::new_v4());

        StoredEvent::new(
            &id(),
            0,
            RrdpInitDetails {
                session,
                base_uri,
                repo_dir,
            },
        )
    }
}

//------------ RrdpEvent ------------------------------------------------------

pub type RrdpEvent = StoredEvent<RrdpEventDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum RrdpEventDetails {
    AddedDelta(Delta),
    UpdatedNotification(NotificationUpdate),
    CleanedUp(Time),
}

impl RrdpEventDetails {
    fn added_delta(id: &Handle, ver: u64, delta: Delta) -> RrdpEvent {
        StoredEvent::new(id, ver, RrdpEventDetails::AddedDelta(delta))
    }

    fn updated_notification(id: &Handle, ver: u64, notif: NotificationUpdate) -> RrdpEvent {
        StoredEvent::new(id, ver, RrdpEventDetails::UpdatedNotification(notif))
    }

    fn cleaned_up(id: &Handle, ver: u64, time: Time) -> RrdpEvent {
        StoredEvent::new(id, ver, RrdpEventDetails::CleanedUp(time))
    }
}

//------------ RrdpCommand ---------------------------------------------------

pub type RrdpCommand = SentCommand<RrdpCommandDetails>;

#[derive(Clone, Debug)]
pub enum RrdpCommandDetails {
    AddDelta(DeltaElements),
    Publish,
    Cleanup(RetentionTime),
}

/// The retention time for snapshot and delta files no longer referenced.
pub type RetentionTime = Duration;

impl CommandDetails for RrdpCommandDetails {
    type Event = RrdpEvent;
}

impl RrdpCommandDetails {
    pub fn add_delta(delta: DeltaElements) -> RrdpCommand {
        SentCommand::new(&id(), None, RrdpCommandDetails::AddDelta(delta))
    }

    pub fn publish() -> RrdpCommand {
        SentCommand::new(&id(), None, RrdpCommandDetails::Publish)
    }

    pub fn clean_up(retention: RetentionTime) -> RrdpCommand {
        SentCommand::new(&id(), None, RrdpCommandDetails::Cleanup(retention))
    }
}

//------------ RrdpServerError -----------------------------------------------

#[derive(Debug, Display)]
pub enum RrdpServerError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),
}

impl From<io::Error> for RrdpServerError {
    fn from(e: io::Error) -> Self {
        RrdpServerError::IoError(e)
    }
}

impl std::error::Error for RrdpServerError {}

//------------ RrdpResult ----------------------------------------------------

pub type RrdpResult = Result<Vec<RrdpEvent>, RrdpServerError>;

//------------ RrdpServer ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RrdpServer {
    // aggregate ID is fixed using a const str RRDP_ID
    version: u64,

    session: String,
    serial: u64,

    /// The base URI for notification, snapshot and delta files.
    base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    rrdp_base: PathBuf,

    notification: Notification,
    snapshot: Snapshot,
    deltas: Vec<Delta>,
}

/// # Publishing
///
impl RrdpServer {
    fn process_published_delta(&mut self, delta: Delta) {
        self.snapshot.apply_delta(delta.clone());
        self.deltas.insert(0, delta);

        // Keep a minimum of 2 deltas, and a maximum for which the combined
        // number of elements does not exceed the number of elements in the
        // snapshot.
        {
            let size_snapshot = self.snapshot.len();
            let mut total_deltas = 0;
            let mut count = 0;

            self.deltas.retain(|d| {
                count += 1;
                total_deltas += d.len();
                count <= 2 || total_deltas < size_snapshot
            });
        }

        self.serial += 1;
    }

    /// Creates a delta for the delta elements. Assumes (for now) that the
    /// delta elements have been verified for the publisher.
    fn add_delta(&self, elements: DeltaElements) -> RrdpResult {
        let next = self.serial + 1;
        let session = self.session.clone();
        let delta = Delta::new(session, next, elements);

        Ok(vec![RrdpEventDetails::added_delta(
            &id(),
            self.version,
            delta,
        )])
    }

    /// Publishes the latest notification, snapshot and delta file to disk.
    /// Return event to move old files to clean-up list.
    fn publish(&self) -> RrdpResult {
        let snapshot_hash = self.snapshot.write_xml(&self.snapshot_path())?;
        let snapshot_ref =
            SnapshotRef::new(self.snapshot_uri(), self.snapshot_path(), snapshot_hash);

        // Note we always have at least 1 delta when publishing.
        let last_delta = &self.deltas[0];
        let delta_hash = last_delta.write_xml(&self.delta_path(last_delta.serial()))?;
        let delta_ref = DeltaRef::new(
            last_delta.serial(),
            FileRef::new(
                self.delta_uri(last_delta.serial()),
                self.delta_path(last_delta.serial()),
                delta_hash,
            ),
        );

        let update = NotificationUpdate::new(
            Time::now(),
            None,
            snapshot_ref,
            delta_ref,
            self.deltas.last().unwrap().serial(),
        );

        let mut notification = self.notification.clone();
        notification.update(update.clone());
        notification.write_xml(&self.notification_path())?;

        Ok(vec![RrdpEventDetails::updated_notification(
            &id(),
            self.version,
            update,
        )])
    }

    /// Cleans out old files on disk, returns event for cleaning up the state.
    fn cleanup(&self, retention: RetentionTime) -> RrdpResult {
        let cut_off = Time::now() - retention;
        for old in self.notification.old_refs() {
            if old.0 <= cut_off {
                // Don't care if it were already deleted.
                let _ = file::clean_file_and_path(&old.1.path());
            }
        }

        Ok(vec![RrdpEventDetails::cleaned_up(
            &id(),
            self.version,
            cut_off,
        )])
    }
}

/// rrdp paths and uris
///
impl RrdpServer {
    pub fn notification_uri(&self) -> uri::Https {
        uri::Https::from_string(format!("{}notification.xml", self.base_uri.to_string())).unwrap() // Cannot fail. Config checked at startup.
    }

    fn notification_path(&self) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push("notification.xml");
        path
    }

    fn snapshot_rel(session: &str, serial: u64) -> String {
        format!("{}/{}/snapshot.xml", session, serial)
    }

    fn new_snapshot_path(base: &PathBuf, session: &str, serial: u64) -> PathBuf {
        let mut path = base.clone();
        path.push(Self::snapshot_rel(session, serial));
        path
    }

    fn snapshot_path(&self) -> PathBuf {
        Self::new_snapshot_path(&self.rrdp_base, &self.session, self.serial)
    }

    fn new_snapshot_uri(base: &uri::Https, session: &str, serial: u64) -> uri::Https {
        uri::Https::from_string(format!(
            "{}{}",
            base.to_string(),
            Self::snapshot_rel(session, serial)
        ))
        .unwrap() // Cannot fail. Config checked at startup.
    }

    fn snapshot_uri(&self) -> uri::Https {
        Self::new_snapshot_uri(&self.base_uri, &self.session, self.serial)
    }

    fn delta_rel(session: &str, serial: u64) -> String {
        format!("{}/{}/delta.xml", session, serial)
    }

    fn delta_uri(&self, serial: u64) -> uri::Https {
        uri::Https::from_string(format!(
            "{}{}",
            self.base_uri.to_string(),
            Self::delta_rel(&self.session, serial)
        ))
        .unwrap() // Cannot fail. Config checked at startup.
    }

    fn delta_path(&self, serial: u64) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push(Self::delta_rel(&self.session, serial));
        path
    }
}

impl Aggregate for RrdpServer {
    type Command = RrdpCommand;
    type Event = RrdpEvent;
    type InitEvent = RrdpInit;
    type Error = RrdpServerError;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let init = event.into_details();
        let version = 1;
        let session = init.session;
        let base_uri = init.base_uri;
        let mut rrdp_base = init.repo_dir.clone();
        rrdp_base.push(RRDP_FOLDER);

        let serial = 0;
        let snapshot = Snapshot::new(session.clone());

        let snapshot_path = Self::new_snapshot_path(&rrdp_base, &session, 0);
        let snapshot_uri = Self::new_snapshot_uri(&base_uri, &session, 0);
        let snapshot_hash = snapshot.write_xml(&snapshot_path)?;

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let notification = Notification::create(session.clone(), snapshot_ref);
        let deltas = vec![];

        Ok(RrdpServer {
            version,
            session,
            base_uri,
            rrdp_base,
            serial,
            notification,
            snapshot,
            deltas,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        match event.into_details() {
            RrdpEventDetails::AddedDelta(delta) => self.process_published_delta(delta),
            RrdpEventDetails::UpdatedNotification(notification) => {
                self.notification.update(notification)
            }
            RrdpEventDetails::CleanedUp(time) => self.notification.clean_up(time),
        }
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> RrdpResult {
        match command.into_details() {
            RrdpCommandDetails::AddDelta(els) => self.add_delta(els),
            RrdpCommandDetails::Publish => self.publish(),
            RrdpCommandDetails::Cleanup(retention) => self.cleanup(retention),
        }
    }
}

//------------ RsyncdStore ---------------------------------------------------

/// This type is responsible for publishing files on disk in a structure so
/// that an rscynd can be set up to serve this (RPKI) data. Note that the
/// rsync host name and module are part of the path, so make sure that the
/// rsyncd modules and paths are setup properly for each supported rsync
/// base uri used.
#[derive(Clone, Debug)]
pub struct RsyncdStore {
    rsync_dir: PathBuf,
}

/// # Construct
///
impl RsyncdStore {
    pub fn build(repo_dir: &PathBuf) -> Result<Self, io::Error> {
        let mut rsync_dir = PathBuf::from(repo_dir);
        rsync_dir.push(RSYNC_FOLDER);
        if !rsync_dir.is_dir() {
            fs::create_dir_all(&rsync_dir)?;
        }
        Ok(RsyncdStore { rsync_dir })
    }
}

/// # Publishing
///
impl RsyncdStore {
    /// Saves all the publishes and updates, deletes all the withdraws.
    pub fn publish(&self, delta: &DeltaElements) -> Result<(), io::Error> {
        for p in delta.publishes() {
            file::save_with_rsync_uri(&p.base64().to_bytes(), &self.rsync_dir, p.uri())?;
        }

        for u in delta.updates() {
            file::save_with_rsync_uri(&u.base64().to_bytes(), &self.rsync_dir, u.uri())?;
        }

        for w in delta.withdraws() {
            file::delete_with_rsync_uri(&self.rsync_dir, w.uri())?;
        }
        Ok(())
    }
}
