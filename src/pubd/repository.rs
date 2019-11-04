use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::commons::api::rrdp::{
    CurrentObjects, Delta, DeltaElements, DeltaRef, FileRef, Notification, RrdpSession, Snapshot,
    SnapshotRef,
};
use crate::commons::api::{Handle, HexEncodedHash, PublishDelta, PublisherHandle, RepoInfo};
use crate::commons::eventsourcing::Aggregate;
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::constants::{REPOSITORY_RRDP_DIR, REPOSITORY_RSYNC_DIR};
use crate::pubd::publishers::Publisher;
use crate::pubd::{Cmd, CmdDet, Error, Evt, EvtDet, Ini, RrdpUpdate};

//------------ RsyncdStore ---------------------------------------------------

/// This type is responsible for publishing files on disk in a structure so
/// that an rscynd can be set up to serve this (RPKI) data. Note that the
/// rsync host name and module are part of the path, so make sure that the
/// rsyncd modules and paths are setup properly for each supported rsync
/// base uri used.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RsyncdStore {
    base_uri: uri::Rsync,
    rsync_dir: PathBuf,
}

/// # Construct
///
impl RsyncdStore {
    pub fn new(base_uri: uri::Rsync, repo_dir: &PathBuf) -> Self {
        let mut rsync_dir = PathBuf::from(repo_dir);
        rsync_dir.push(REPOSITORY_RSYNC_DIR);
        RsyncdStore {
            base_uri,
            rsync_dir,
        }
    }
}

/// # Publishing
///
impl RsyncdStore {
    /// Write all the files to disk for rsync to a tmp-dir, then switch
    /// things over in an effort to minimise the chance of people getting
    /// inconsistent syncs..
    pub fn write(&self, snapshot: &Snapshot) -> Result<(), Error> {
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
    snapshot: Snapshot,
    deltas: Vec<Delta>,
}

impl RrdpServer {
    fn new(rrdp_base_uri: uri::Https, repo_dir: &PathBuf, session: RrdpSession) -> Self {
        let mut rrdp_base_dir = PathBuf::from(repo_dir);
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let serial = 0;
        let snapshot = Snapshot::new(session);

        let snapshot_uri = Self::new_snapshot_uri(&rrdp_base_uri, &session, serial);
        let snapshot_path = Self::new_snapshot_path(&rrdp_base_dir, &session, serial);
        let snapshot_hash = HexEncodedHash::from_content(snapshot.xml().as_slice());

        let snapshot_ref = SnapshotRef::new(snapshot_uri, snapshot_path, snapshot_hash);

        let deltas = vec![];
        let notification = Notification::create(session, snapshot_ref);

        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            session,
            serial,
            notification,
            snapshot,
            deltas,
        }
    }

    fn snapshot(&self) -> &Snapshot {
        &self.snapshot
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
        let (delta, notification) = update.unpack();

        self.serial = notification.serial();

        self.notification = notification;

        let mut snapshot = self.snapshot.clone();
        snapshot.apply_delta(delta.clone());
        self.snapshot = snapshot;

        let last_delta = self.notification.last_delta().unwrap(); // always at least 1 delta
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

        // something changes, update notification file
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
                    fs::remove_dir_all(path)?;
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
                // Clean up old serial dirs
                if let Some(last) = self.notification.last_delta() {
                    if serial < last {
                        if path.is_dir() {
                            fs::remove_dir_all(path)?;
                        } else {
                            fs::remove_file(path)?;
                        }

                        continue;
                    }
                }

                // Clean up snapshots in all dirs except the current
                if serial != self.serial {
                    let snapshot_path =
                        Self::new_snapshot_path(&self.rrdp_base_dir, &self.session, serial);
                    if snapshot_path.exists() {
                        fs::remove_file(snapshot_path)?;
                    }
                }
            } else {
                // clean up dirs or files under the base dir which are not sessions
                if path.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
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
        uri::Https::from_string(format!(
            "{}notification.xml",
            self.rrdp_base_uri.to_string()
        ))
        .unwrap() // Cannot fail. Config checked at startup.
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
        uri::Https::from_string(format!(
            "{}{}",
            base.to_string(),
            Self::snapshot_rel(session, serial)
        ))
        .unwrap() // Cannot fail. Config checked at startup.
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
    type Event = Evt;
    type InitEvent = Ini;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unwrap();
        let (id_cert, session, rrdp_base_uri, rsync_jail, repo_base_dir) = details.unpack();

        let key_id = id_cert.subject_public_key_info().key_identifier();

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
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            EvtDet::PublisherAdded(publisher_handle, publisher) => {
                self.publishers.insert(publisher_handle, publisher);
            }
            EvtDet::PublisherRemoved(publisher_handle, update) => {
                self.publishers.remove(&publisher_handle);
                self.rrdp.apply_update(update);
            }
            EvtDet::Published(publisher_handle, update) => {
                // update content for publisher
                self.update_publisher(&publisher_handle, &update);

                // update RRDP server
                self.rrdp.apply_update(update);
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
        }
    }
}

/// # Manage publishers
///
impl Repository {
    fn add_publisher(
        &self,
        publisher_request: rfc8183::PublisherRequest,
    ) -> Result<Vec<Evt>, Error> {
        let (_tag, handle, id_cert) = publisher_request.unpack();

        if self.publishers.contains_key(&handle) {
            Err(Error::DuplicatePublisher(handle))
        } else {
            let base_uri =
                uri::Rsync::from_string(format!("{}{}/", self.rsync.base_uri, handle)).unwrap();
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
        let publisher_rsync_base =
            uri::Rsync::from_str(&format!("{}{}/", self.rsync.base_uri, publisher)).unwrap();

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

    pub fn publisher(&self, publisher_handle: &PublisherHandle) -> Option<&Publisher> {
        self.publishers.get(publisher_handle)
    }

    pub fn get_publisher(&self, publisher_handle: &PublisherHandle) -> Result<&Publisher, Error> {
        self.publisher(publisher_handle)
            .ok_or_else(|| Error::UnknownPublisher(publisher_handle.clone()))
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

/// Publish
///
impl Repository {
    fn publish(
        &self,
        publisher_handle: PublisherHandle,
        delta: PublishDelta,
    ) -> Result<Vec<Evt>, Error> {
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
