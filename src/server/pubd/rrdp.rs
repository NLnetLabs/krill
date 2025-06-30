//! Management of content for RRDP.

use std::{error, fmt, fs, io, mem};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use chrono::Duration;
use log::{debug, error, info, warn};
use rpki::uri;
use rpki::ca::publication;
use rpki::ca::idexchange::PublisherHandle;
use rpki::ca::publication::Base64;
use rpki::repository::manifest::Manifest;
use rpki::repository::x509::Time;
use rpki::rrdp::{DeltaInfo, Hash, NotificationFile, SnapshotInfo};
use rpki::xml::decode::Name;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use crate::api::admin::PublishedFile;
use crate::api::pubd::{PublisherManifestStats, PublisherStats};
use crate::commons::file;
use crate::commons::KrillResult;
use crate::commons::error::{Error, KrillIoError};
use crate::constants::{
    REPOSITORY_RRDP_ARCHIVE_DIR, REPOSITORY_RRDP_DIR,
    RRDP_FIRST_SERIAL,
};
use crate::config::RrdpUpdatesConfig;


//------------ RRDP name definitions -----------------------------------------

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";

const SNAPSHOT: Name = Name::unqualified(b"snapshot");
const DELTA: Name = Name::unqualified(b"delta");
const PUBLISH: Name = Name::unqualified(b"publish");
const WITHDRAW: Name = Name::unqualified(b"withdraw");


//------------ RrdpServer ----------------------------------------------------

/// The RRDP server used by a repository instance.
///
/// This isn’t the actual server but creates the data to be served by an
/// HTTP server.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RrdpServer {
    /// The base URI for RRDP files.
    rrdp_base_uri: uri::Https,

    /// The directory where RRDP files will be published.
    rrdp_base_dir: PathBuf,

    /// The directory where RRDP files will be archived.
    rrdp_archive_dir: PathBuf,

    /// The current RRDP session.
    session: RrdpSession,

    /// The current serial number within the session.
    serial: u64,

    /// The time we last updated our data.
    last_update: Time,

    /// The data of the current snapshot.
    snapshot: SnapshotData,

    /// The deltas we currently have.
    deltas: VecDeque<DeltaData>,

    /// The elements staged for publishing by each publisher.
    #[serde(default)]
    staged_elements: HashMap<PublisherHandle, StagedElements>,
}

impl RrdpServer {
    /// Create a new instance.
    ///
    /// Intended to be used by migration code only and therefore
    /// marked as deprecated.
    #[deprecated]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        rrdp_base_uri: uri::Https,
        rrdp_base_dir: PathBuf,
        rrdp_archive_dir: PathBuf,
        session: RrdpSession,
        serial: u64,
        last_update: Time,
        snapshot: SnapshotData,
        deltas: VecDeque<DeltaData>,
        staged_elements: HashMap<PublisherHandle, StagedElements>,
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

    /// Creates an RRDP server.
    pub fn create(
        rrdp_base_uri: uri::Https,
        repo_dir: &Path,
        session: RrdpSession,
    ) -> Self {
        let mut rrdp_base_dir = repo_dir.to_path_buf();
        rrdp_base_dir.push(REPOSITORY_RRDP_DIR);

        let mut rrdp_archive_dir = repo_dir.to_path_buf();
        rrdp_archive_dir.push(REPOSITORY_RRDP_ARCHIVE_DIR);

        let serial = RRDP_FIRST_SERIAL;
        let last_update = Time::now();
        let snapshot = SnapshotData::empty();

        RrdpServer {
            rrdp_base_uri,
            rrdp_base_dir,
            rrdp_archive_dir,
            session,
            serial,
            last_update,
            snapshot,
            deltas: VecDeque::new(),
            staged_elements: HashMap::new(),
        }
    }

    /// Removes all files created by the RRDP server.
    pub fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rrdp_base_dir);
        let _ = fs::remove_dir_all(&self.rrdp_archive_dir);
    }

    /// Returns the base of the URI of any RRDP file.
    pub fn rrdp_base_uri(&self) -> &uri::Https {
        &self.rrdp_base_uri
    }

    /// Returns the current RRDP session.
    pub fn session(&self) -> RrdpSession {
        self.session
    }

    /// Returns the current serial number within the current session.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the time of the last update.
    pub fn last_update(&self) -> Time {
        self.last_update
    }

    /// Returns a reference to the snapshot data.
    pub fn snapshot(&self) -> &SnapshotData {
        &self.snapshot
    }

    /// Converts the RRDP path portion of a HTTP request URI to a path.
    ///
    /// The `path` should contain everything after the `/rrdp/` portion of
    /// the URI’s path. If the path is in principle valid, i.e., could
    /// represent an RRDP resource generated by this RRDP sever, the method
    /// will return a file system path representing this path. This does not
    /// mean there will actually be a file there. The file may have been
    /// deleted or may have never existed at all. This is necessary since
    /// the RRDP server doesn’t track past files, only the currently valid
    /// set of resources.
    ///
    /// If the path is definitely not valid, returns `None`. This should
    /// probably be translated into a 404 Not Found response.
    pub fn resolve_request_path(
        &self, path: &str
    ) -> Option<PathBuf> {
        Self::is_request_path_valid(path).map(|_| {
            self.rrdp_base_dir.join(path)
        })
    }

    /// Check if a request path is in principle valid.
    ///
    /// This returns an option so we can use the question mark operator in
    /// the implementation.
    fn is_request_path_valid(path: &str) -> Option<()> {
        // Literal "notification.xml" is fine.
        if path == "notification.xml" {
            return Some(())
        }

        // All other paths are session, serial, random, and then either
        // "snapshot.xml" or "delta.xml"
        let mut path = path.split('/');

        // Check that the three interior items only contains letters, numbers,
        // and hyphens. Technically we only do lower case letters, but since
        // we are also using the Display impls of stuff, that may quietly
        // change.
        for item in [path.next()?, path.next()?, path.next()?] {
            for &ch in item.as_bytes() {
                if !ch.is_ascii_alphanumeric() && ch != b'-' {
                    return None
                }
            }
        }

        // Next is the file name.
        match path.next()? {
            "snapshot.xml" | "delta.xml" => { }
            _ => return None,
        }

        // And then we need to be done.
        if path.next().is_some() {
            return None
        }

        Some(())
    }

    /// Lists all known publishers based on current objects and staged deltas.
    pub fn publishers(&self) -> Vec<PublisherHandle> {
        let publisher_current_objects =
            self.snapshot.publishers_current_objects();

        let mut publishers: Vec<_> =
            publisher_current_objects.keys().cloned().collect();

        for staged_publisher in self.staged_elements.keys() {
            if !publisher_current_objects.contains_key(staged_publisher) {
                publishers.push(staged_publisher.clone())
            }
        }

        publishers
    }

    /// Returns the staged elements for a publisher.
    pub fn get_publisher_staged(
        &self, publisher: &PublisherHandle
    ) -> Option<&StagedElements> {
        self.staged_elements.get(publisher)
    }

    /// Returns a RRDP session reset.
    ///
    /// This will contain a copy of the current snapshot.
    pub fn reset_session(&self) -> RrdpSessionReset {
        let last_update = Time::now();
        let session = RrdpSession::random();
        let snapshot = self.snapshot.clone_with_new_random();

        RrdpSessionReset {
            last_update,
            snapshot,
            session,
        }
    }

    /// Applies the data from an RRDP session reset.
    pub fn apply_session_reset(&mut self, reset: RrdpSessionReset) {
        self.snapshot = reset.snapshot;
        self.session = reset.session;
        self.last_update = reset.last_update;
        self.serial = RRDP_FIRST_SERIAL;
        self.deltas = VecDeque::new();
    }

    /// Applies a change that a publisher was added.
    ///
    /// Cannot fail, so this is made idempotent. No publisher is added
    /// if the publisher already exists. This cannot happen in practice,
    /// because the change would not be created in that case: i.e. the
    /// command to add the publisher would have failed.
    pub fn apply_publisher_added(&mut self, publisher: PublisherHandle) {
        self.snapshot.apply_publisher_added(publisher);
    }

    /// Apples a change that a publisher was removed.
    pub fn apply_publisher_removed(&mut self, publisher: &PublisherHandle) {
        self.snapshot.apply_publisher_removed(publisher);
    }

    /// Applies staged delta elements.
    pub fn apply_rrdp_staged(
        &mut self,
        publisher: PublisherHandle,
        elements: DeltaElements,
    ) {
        self.staged_elements.entry(
            publisher
        ).or_default().merge_new_elements(elements);
    }

    /// Applies the data from an RrdpUpdated change.
    pub fn apply_rrdp_updated(&mut self, update: RrdpUpdated) {
        self.serial += 1;

        let mut staged_elements = HashMap::default();
        mem::swap(&mut self.staged_elements, &mut staged_elements);

        let mut rrdp_delta_elements = DeltaElements::default();
        for (publisher, staged_elements) in staged_elements {
            let delta: DeltaElements = staged_elements.into();
            // update snapshot
            self.snapshot.apply_delta(&publisher, delta.clone());

            // extend next RRDP delta with elements for this publisher.
            rrdp_delta_elements.append(delta);
        }

        let delta = DeltaData::new(
            self.serial,
            update.time,
            update.random,
            rrdp_delta_elements,
        );

        self.deltas.truncate(update.deltas_truncate);
        self.deltas.push_front(delta);
        self.deltas_truncate_size();

        self.last_update = update.time;
    }

    /// Checks whether an RRDP update is needed
    pub fn update_rrdp_needed(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> RrdpUpdateNeeded {
        // Check if there are any staged elements entries with staged
        // elements. A simple .is_empty() on the map won't do because there
        // could be (only) entries for publishers containing an empty set of
        // staged elements.
        if self.staged_elements.values().any(|el| !el.0.is_empty()) {
            // There is staged content. Check if it should be published now,
            // or later.
            let interval = Duration::seconds(
                rrdp_updates_config.rrdp_delta_interval_min_seconds.into(),
            );
            let next_update_time = self.last_update + interval;
            if next_update_time > Time::now() {
                debug!(
                    "RRDP update is delayed to: {}",
                    next_update_time.to_rfc3339()
                );
                RrdpUpdateNeeded::Later(next_update_time)
            } else {
                debug!("RRDP update is needed");
                RrdpUpdateNeeded::Yes
            }
        } else {
            debug!("No RRDP update is needed, there are no staged changes");
            RrdpUpdateNeeded::No
        }
    }

    /// Updates the RRDP server with the staged delta elements.
    pub fn update_rrdp(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<RrdpUpdated> {
        let time = Time::now();
        let random = RrdpFileRandom::default();

        let deltas_truncate =
            self.find_deltas_truncate_age(rrdp_updates_config);

        Ok(RrdpUpdated {
            time,
            random,
            deltas_truncate,
        })
    }

    /// Truncate excessive deltas based on size.
    ///
    /// This is done after applying an RrdpUpdate because the outcome is
    /// deterministic. Compared to truncating the deltas based on age and
    /// number, because *that* depends on when the update was generated,
    /// and what the RrdpUpdatesConfig was set to at the time.
    fn deltas_truncate_size(&mut self) {
        let snapshot_size = self.snapshot().size_approx();
        let mut total_deltas_size = 0;
        let mut keep = 0;

        for delta in &self.deltas {
            total_deltas_size += delta.elements().size_approx();
            if total_deltas_size > snapshot_size {
                // never keep more than the size of the snapshot
                break;
            } else {
                keep += 1;
            }
        }

        self.deltas.truncate(keep);
    }

    /// Returns the position to truncate excessive deltas.
    ///
    ///  - always keep 'rrdp_delta_files_min_nr' files
    ///  - always keep 'rrdp_delta_files_min_seconds' files
    ///  - beyond this:
    ///     - never keep more than 'rrdp_delta_files_max_nr'
    ///     - never keep older than 'rrdp_delta_files_max_seconds'
    ///     - keep the others
    fn find_deltas_truncate_age(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> usize {
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
            } else if keep == max_nr - 1
                || delta.older_than_seconds(max_secs.into())
            {
                // never keep more than 'rrdp_delta_files_max_nr'
                //    we need max_nr -1 because we will add the new new delta
                // later never keep older than
                // 'rrdp_delta_files_max_seconds'
                break;
            } else {
                // keep the remainder
                keep += 1;
            }
        }

        keep
    }

    /// Writes the (missing) RRDP files to disk.
    ///
    /// Also removes the files no longer referenced in the notification file.
    pub fn update_rrdp_files(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> Result<(), Error> {
        // Get the current notification file from disk, if it exists, so
        // we can determine which (new) snapshot and delta files to write,
        // and which old snapshot and delta files may be removed.
        debug!(
            "Write updated RRDP state to disk - \n
            if there are any updates that is."
        );

        // Get the current notification file - as long as it's present and can
        // be parsed. If it cannot be parsed we just ignore it. I.e. we will
        // generate all current files in that case.
        let old_notification_opt: Option<NotificationFile> = file::read(
            &self.notification_path()
        ).ok().and_then(|bytes| {
            rpki::rrdp::NotificationFile::parse(bytes.as_ref()).ok()
        });

        if let Some(old_notification) = old_notification_opt.as_ref() {
            if old_notification.serial() == self.serial
                && old_notification.session_id() == self.session.uuid()
            {
                debug!(
                    "Existing notification file matches current session \
                     and serial. Nothing to write."
                );
                return Ok(());
            }
        }

        let deltas = self.write_delta_files(old_notification_opt)?;
        let snapshot = self.write_snapshot_file()?;
        self.write_notification_file(snapshot, deltas)?;

        // clean up under the base dir:
        self.cleanup_old_rrdp_files(rrdp_updates_config)
    }

    /// Writes the missing delta files.
    fn write_delta_files(
        &self,
        old_notification_opt: Option<NotificationFile>,
    ) -> KrillResult<Vec<DeltaInfo>> {
        // Find existing deltas in current file, if present and still
        // applicable:
        // - there is a notification that can be parsed
        // - session did not change
        // - deltas have an overlap with current deltas (otherwise just
        //   regenerate new deltas)
        //
        // We will assume that files for deltas still exist on disk and were
        // not changed, so we will not regenerate them.
        //
        // NOTE: if both session and serial remain unchanged we just return
        // with Ok(()). There is no work.
        let mut deltas_from_old_notification = match old_notification_opt {
            None => {
                debug!("No old notification file found");
                vec![]
            }
            Some(mut old_notification) => {
                if old_notification.session_id()
                        == self.session.uuid()
                {
                    // Sort the deltas from lowest serial up, and make
                    // sure that there are no gaps.
                    if old_notification.sort_and_verify_deltas(None) {
                        debug!(
                            "Found existing notification file for \
                             current session with deltas."
                        );
                        old_notification.deltas().to_vec()
                    }
                    else {
                        debug!(
                            "Found existing notification file with \
                             incomplete deltas, will regenerate files."
                        );
                        vec![]
                    }
                }
                else {
                    debug!(
                        "Existing notification file was for different \
                        session, will regenerate all files."
                    );
                    vec![]
                }
            }
        };

        // Go over the deltas we found and discard any delta with a serial
        // that we no longer kept. The deltas in the RrdpServer are
        // sorted from highest to lowest serial (to make it easier to
        // truncate).
        if let Some(last) = self.deltas.back() {
            // Only keep deltas are still kept.
            deltas_from_old_notification .retain(|delta| {
                delta.serial() >= last.serial()
            });
        }
        else if !deltas_from_old_notification.is_empty() {
            // We would expect the existing deltas to be empty as well in this
            // case. But in any case, wiping them will ensure we
            // generate a new sane NotificationFile
            deltas_from_old_notification = vec![];
        }

        // Write new delta files and add their DeltaInfo to the list to
        // include in the new notification file. I.e. skip deltas that
        // are still included in the curated list we got from the old
        // notification.
        let last_written_serial = deltas_from_old_notification.last();
        let mut deltas = vec![];
        for delta in &self.deltas {
            if let Some(last) = last_written_serial {
                if delta.serial() <= last.serial() {
                    // Already included. We can skip this and assume that it
                    // was written to disk before.
                    // And no one went in and messed with it..
                    debug!(
                        "Skip writing delta for serial {}. \
                        File should exist.",
                        delta.serial()
                    );
                    continue;
                }
            }
            // New delta, write it and add its distinctiveness to deltas
            // (DeltaInfo vec) to include in the notification file
            // that we will write.
            let path = delta.path(
                self.session, delta.serial(), &self.rrdp_base_dir
            );
            let uri = delta.uri(
                self.session, delta.serial(), &self.rrdp_base_uri
            );
            let xml_bytes = delta.xml(self.session, delta.serial());
            let hash = Hash::from_data(xml_bytes.as_slice());

            debug!("Write delta file to: {}", path.to_string_lossy());
            file::save(&xml_bytes, &path)?;

            deltas.push(DeltaInfo::new(delta.serial(), uri, hash));
        }

        // Reverse the order of the (old) deltas so that it also goes high to
        // low, and we can get the new complete list to include in the
        // notification file.
        deltas_from_old_notification.reverse();
        deltas.append(&mut deltas_from_old_notification);

        Ok(deltas)
    }

    /// Writes a new snapshot file.
    fn write_snapshot_file(&self) -> KrillResult<SnapshotInfo> {
        let path = self.snapshot().path(
            self.session, self.serial, &self.rrdp_base_dir,
        );
        let uri = self.snapshot().uri(
            self.session, self.serial, &self.rrdp_base_uri,
        );
        let xml_bytes = self.snapshot().xml(self.session, self.serial);
        let hash = Hash::from_data(&xml_bytes);

        debug!("Write snapshot file to: {}", path.to_string_lossy());
        file::save(&xml_bytes, &path)?;

        Ok(SnapshotInfo::new(uri, hash))
    }

    /// Writes the new notification file.
    fn write_notification_file(
        &self, snapshot: SnapshotInfo, deltas: Vec<DeltaInfo>,
    ) -> KrillResult<()> {
        // Write new notification file to new file first.
        // Prevent that half-overwritten files are served.
        let notification = NotificationFile::new(
            self.session.uuid(), self.serial, snapshot, deltas,
        );
        let notification_path_new = self.notification_path_new();
        let mut notification_file_new =
            file::create_file_with_path(&notification_path_new)?;
        notification
            .write_xml(&mut notification_file_new)
            .map_err(|e| {
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
        fs::rename(&notification_path_new, &notification_path).map_err(
            |e| {
                KrillIoError::new(
                    format!(
                    "Could not rename notification file from '{}' to '{}'",
                    notification_path_new.to_string_lossy(),
                    notification_path.to_string_lossy()
                ),
                    e,
                )
            },
        )?;

        Ok(())
    }

    /// Removes old unreferences RRDP delta file.
    fn cleanup_old_rrdp_files(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
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
            if self.session.to_string() == entry.file_name().to_string_lossy()
            {
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

        // Get the delta range to keep. We use 0 as a special value, because
        // it is never used for deltas: i.e. no delta dirs will match
        // if our delta list is empty.
        let lowest_delta =
            self.deltas.back().map(|delta| delta.serial()).unwrap_or(0);
        let highest_delta =
            self.deltas.front().map(|delta| delta.serial()).unwrap_or(0);

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
            if let Ok(serial) =
                u64::from_str(entry.file_name().to_string_lossy().as_ref())
            {
                // Skip the current serial
                if serial == self.serial {
                    continue;
                // Clean up old serial dirs once deltas are out of scope
                } else if serial < lowest_delta || serial > highest_delta {
                    if rrdp_updates_config.rrdp_files_archive {
                        // If archiving is enabled, then move these
                        // directories under the archive base

                        let mut dest = self.rrdp_archive_dir.clone();
                        dest.push(self.session.to_string());
                        dest.push(format!("{serial}"));

                        info!(
                            "Archiving RRDP serial '{}' to '{}",
                            serial,
                            dest.to_string_lossy()
                        );
                        let _ = fs::create_dir_all(&dest);
                        let _ = fs::rename(path, dest);
                    } else if path.is_dir() {
                        let _best_effort_rm = fs::remove_dir_all(path);
                    } else {
                        let _best_effort_rm = fs::remove_file(path);
                    }
                // We still need this old serial dir for the delta, but may
                // not need the snapshot in it unless
                // archiving is enabled.. in that case leave them and move
                // them when the complete serial dir goes out
                // of scope above.
                } else if !rrdp_updates_config.rrdp_files_archive {
                    // If the there is a snapshot file do a best effort
                    // removal. It shares the same
                    // random dir as the delta that we still need to keep for
                    // this serial, so we just remove the
                    // file and leave its parent directory in place.
                    if let Ok(Some(snapshot_file_to_remove)) =
                        Self::session_dir_snapshot(&session_dir, serial)
                    {
                        if let Err(e) =
                            fs::remove_file(&snapshot_file_to_remove)
                        {
                            warn!(
                                "Could not delete snapshot file '{}'. \
                                 Error was: {}",
                                snapshot_file_to_remove.to_string_lossy(),
                                e
                            );
                        }
                    }
                } else {
                    // archiving was enabled, keep the old snapshot file until
                    // the directory is archived
                }
            } else {
                // clean up dirs or files under the base dir which are not
                // sessions
                warn!(
                    "Found unexpected file or dir in RRDP repository - \
                     will try to remove: {}",
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
impl RrdpServer {
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

    pub fn session_dir_snapshot(
        session_path: &Path,
        serial: u64,
    ) -> KrillResult<Option<PathBuf>> {
        Self::find_in_serial_dir(session_path, serial, "snapshot.xml")
    }

    /// Expects files (like delta.xml or snapshot.xml) under dir structure
    /// like: `<session_path>/<serial>/<some random>/<filename>`.
    pub fn find_in_serial_dir(
        session_path: &Path,
        serial: u64,
        filename: &str,
    ) -> KrillResult<Option<PathBuf>> {
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


//------------ RrdpUpdateNeeded ----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RrdpUpdateNeeded {
    Yes,
    No,
    Later(Time),
}


//------------ RrdpSessionReset ----------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpSessionReset {
    pub last_update: Time,
    pub session: RrdpSession,
    pub snapshot: SnapshotData,
}


//------------ RrdpUpdated ---------------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpUpdated {
    pub time: Time,
    pub random: RrdpFileRandom,
    pub deltas_truncate: usize,
}


//------------ RrdpSession ---------------------------------------------------

/// An RRDP session.
///
/// A session is identified by a UUID. By default, a new session will be
/// created with a random V4 UUID.
///
//  *Warning:* This type is used in stored state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RrdpSession(Uuid);

impl RrdpSession {
    /// Creates a new session with a random identifier.
    pub fn random() -> Self {
        Self::default()
    }

    /// Creates a session from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns a reference to the session’s UUID.
    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

//--- Default

impl Default for RrdpSession {
    fn default() -> Self {
        RrdpSession(Uuid::new_v4())
    }
}


//--- Display

impl fmt::Display for RrdpSession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}


//--- Deserialize and Serialize

impl<'de> Deserialize<'de> for RrdpSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&string).map_err(de::Error::custom)?;

        Ok(RrdpSession(uuid))
    }
}

impl Serialize for RrdpSession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}


//------------ SnapshotData --------------------------------------------------

/// The data needed to create an RRDP Snapshot.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotData {
    /// A random value to make the URI unique.
    random: RrdpFileRandom,

    /// The objects of each publisher.
    ///
    /// We keep objects per publisher so that we can respond to
    /// list and publication queries more efficiently.
    publishers_current_objects: HashMap<PublisherHandle, CurrentObjects>,
}

impl SnapshotData {
    /// Creates a new snapshot from its components.
    pub fn new(
        random: RrdpFileRandom,
        publishers_current_objects: HashMap<PublisherHandle, CurrentObjects>,
    ) -> Self {
        SnapshotData {
            random,
            publishers_current_objects,
        }
    }

    /// Creates a new, empty snapshot.
    pub fn empty() -> Self {
        SnapshotData::new(RrdpFileRandom::default(), HashMap::default())
    }

    /// Clones the snapshot but gives it a new random component.
    pub fn clone_with_new_random(&self) -> Self {
        SnapshotData::new(
            RrdpFileRandom::default(),
            self.publishers_current_objects.clone(),
        )
    }

    /// Returns a reference to the map of current objects per publisher.
    pub fn publishers_current_objects(
        &self,
    ) -> &HashMap<PublisherHandle, CurrentObjects> {
        &self.publishers_current_objects
    }

    /// Sets the random component to the given value.
    pub fn set_random(&mut self, random: RrdpFileRandom) {
        self.random = random;
    }

    /// Returns the approximate size for all current objects.
    pub fn size_approx(&self) -> usize {
        self.publishers_current_objects.values().fold(
            0, |tot, objects| tot + objects.size_approx()
        )
    }

    /// Returns the current objects for the given publisher if available.
    pub fn get_publisher_objects(
        &self,
        publisher: &PublisherHandle,
    ) -> Option<&CurrentObjects> {
        self.publishers_current_objects.get(publisher)
    }

    /// Applies the delta for a publisher to this snapshot.
    ///
    /// This assumes that the delta had been checked before.
    pub fn apply_delta(
        &mut self,
        publisher: &PublisherHandle,
        delta: DeltaElements,
    ) {
        if let Some(objects)
            = self.publishers_current_objects.get_mut(publisher)
        {
            objects.apply_delta(delta);
            if objects.is_empty() {
                self.publishers_current_objects.remove(publisher);
            }
        }
        else {
            // This is a new publisher without existing objects. So, just
            // create an default -empty- object set for it, so we
            // can apply the delta to it.
            let mut objects = CurrentObjects::default();
            objects.apply_delta(delta);
            self.publishers_current_objects.insert(
                publisher.clone(), objects
            );
        }
    }

    /// Applies the addition of new publisher with an empty object set.
    ///
    /// This is a no-op in case the publisher already exists.
    pub fn apply_publisher_added(&mut self, publisher: PublisherHandle) {
        self.publishers_current_objects.entry(publisher).or_default();
    }

    /// Applies the removal of a publisher.
    ///
    /// This is a no-op in case the publisher does not exists.
    pub fn apply_publisher_removed(&mut self, publisher: &PublisherHandle) {
        self.publishers_current_objects.remove(publisher);
    }

    /// Creates the relative URI path for the snapshot.
    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/snapshot.xml", session, serial, self.random.0)
    }

    /// Returns the URI for the snapshot.
    pub fn uri(
        &self,
        session: RrdpSession,
        serial: u64,
        rrdp_base_uri: &uri::Https,
    ) -> uri::Https {
        rrdp_base_uri.join(self.rel_path(session, serial).as_ref()).unwrap()
    }

    /// Returns the file system path for the snapshot.
    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    /// Writes the snapshot XML to a file under `path`.
    pub fn write_xml(
        &self,
        session: RrdpSession,
        serial: u64,
        path: &Path,
    ) -> Result<(), KrillIoError> {
        debug!("Writing snapshot file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f).map_err(|e| {
            KrillIoError::new(
                format!(
                    "cannot write snapshot xml to: {}",
                    path.to_string_lossy()
                ),
                e,
            )
        })?;

        debug!("Finished snapshot xml");
        Ok(())
    }

    /// Returns the snapshot XML.
    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Writes the snapshot XML.
    //
    // Note: we do not use the rpki-rs Snapshot implementation because we
    // would need to transform and copy quite a lot of data
    fn write_xml_to_writer(
        &self,
        session: RrdpSession,
        serial: u64,
        writer: &mut impl io::Write,
    ) -> Result<(), io::Error> {
        let mut writer = rpki::xml::encode::Writer::new(writer);
        writer
            .element(SNAPSHOT)?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("session_id", &session)?
            .attr("serial", &serial)?
            .content(|content| {
                for publisher_objects in
                    self.publishers_current_objects.values()
                {
                    for (uri, base64) in publisher_objects.iter() {
                        content
                            .element(PUBLISH)?
                            .attr("uri", uri.as_str())?
                            .content(|content| {
                                content.raw(base64.as_str())
                            })?;
                    }
                }
                Ok(())
            })?;
        writer.done()
    }
}


//------------ CurrentObjects ------------------------------------------------

/// The current set of published objects.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<CurrentObjectUri, Base64>);

impl CurrentObjects {
    /// Returns the number of objects in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the approximate size of all objects.
    pub fn size_approx(&self) -> usize {
        self.0.values().fold(0, |tot, el| tot + el.size_approx())
    }

    /// Extends the objects by another set.
    ///
    /// The content of objects already present will be overwritten.
    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0)
    }

    /// Returns the delta elements needed to turn this set into the other.
    pub fn diff(&self, other: &Self) -> KrillResult<DeltaElements> {
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        // find new and updated stuff
        for (uri_key, base64) in &other.0 {
            match self.0.get(uri_key) {
                None => {
                    publishes.push(PublishElement {
                        uri: uri_key.try_into()?,
                        base64: base64.clone(),
                    });
                }
                Some(existing_b64) => {
                    if base64 != existing_b64 {
                        updates.push(UpdateElement {
                            uri: uri_key.try_into()?,
                            hash: existing_b64.to_hash(),
                            base64: base64.clone()
                        });
                    }
                }
            }
        }

        // find removed stuff
        for (uri_key, base64) in &self.0 {
            if !other.0.contains_key(uri_key) {
                let wdr = WithdrawElement {
                    uri: uri_key.try_into()?,
                    hash: base64.to_hash(),
                };
                withdraws.push(wdr);
            }
        }

        Ok(DeltaElements::new(publishes, updates, withdraws))
    }

    /// Returns an iterator over the current objects.
    pub fn iter(&self) -> impl Iterator<Item = (&CurrentObjectUri, &Base64)> {
        self.0.iter()
    }

    /// Converts the set into a list of publish elements.
    pub fn try_into_published_files(
        self,
    ) -> KrillResult<Vec<PublishedFile>> {
        let mut elements = Vec::new();

        for (uri_key, base64) in self.0.into_iter() {
            elements.push(PublishedFile { uri: uri_key.try_into()?, base64 });
        }

        Ok(elements)
    }

    /// Creates a list of withdraw elements for all current objects.
    pub fn try_to_withdraw_elements(
        &self
    ) -> KrillResult<Vec<WithdrawElement>> {
        let mut elements = Vec::new();

        for (uri_key, base64) in self.0.iter() {
            elements.push(WithdrawElement {
                uri: uri_key.try_into()?,
                hash: base64.to_hash(),
            });
        }

        Ok(elements)
    }

    /// Verifies that a delta can be applied to this set of objects.
    ///
    /// Checks that all object URIs are under `jail`, that published objects
    /// aren’t in the set, and that updated and deleted objects are in the set
    /// with the
    /// given hash.
    pub fn verify_delta_applies(
        &self,
        delta: &DeltaElements,
        jail: &uri::Rsync,
    ) -> Result<(), PublicationDeltaError> {
        for p in delta.publishes() {
            if !jail.is_parent_of(&p.uri) {
                return Err(PublicationDeltaError::outside(jail, &p.uri));
            }
            if self.0.contains_key(&CurrentObjectUri::from(&p.uri)) {
                return Err(PublicationDeltaError::present(&p.uri));
            }
        }

        for u in delta.updates() {
            if !jail.is_parent_of(&u.uri) {
                return Err(PublicationDeltaError::outside(jail, &u.uri));
            }
            if !self.contains(u.hash, &u.uri) {
                return Err(PublicationDeltaError::no_match(&u.uri));
            }
        }

        for w in delta.withdraws() {
            if !jail.is_parent_of(&w.uri) {
                return Err(PublicationDeltaError::outside(jail, &w.uri));
            }
            if !self.contains(w.hash, &w.uri) {
                return Err(PublicationDeltaError::no_match(&w.uri));
            }
        }

        Ok(())
    }

    /// Returns whether the set contains an object with the given URI and hash.
    fn contains(&self, hash: Hash, uri: &uri::Rsync) -> bool {
        match self.0.get(&CurrentObjectUri::from(uri)) {
            Some(base64) => base64.to_hash() == hash,
            None => false,
        }
    }

    /// Applies a delta to CurrentObjects.
    ///
    /// Assumes that the delta was checked using
    /// [`Self::verify_delta_applies`].
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unpack();

        for p in publishes {
            self.0.insert(CurrentObjectUri::from(p.uri), p.base64);
        }

        for u in updates {
            // we ignore the hash of the old object when inserting
            // the update, as it has already been verified.
            self.0.insert(CurrentObjectUri::from(u.uri), u.base64);
        }

        for w in withdraws {
            self.0.remove(&CurrentObjectUri::from(w.uri));
        }
    }

    /// Returns the withdraws for elements matching the given URI.
    pub fn get_matching_withdraws(
        &self,
        match_uri: &uri::Rsync,
    ) -> KrillResult<Vec<WithdrawElement>> {
        let match_uri = CurrentObjectUri::from(match_uri);

        let mut withdraws = Vec::new();
        for (uri_key, base64) in &self.0 {
            if uri_key == &match_uri
                || (match_uri.as_str().ends_with('/')
                    && uri_key.as_str().starts_with(match_uri.as_str()))
            {
                withdraws.push(WithdrawElement {
                    uri: uri_key.try_into()?,
                    hash: base64.to_hash(),
                });
            }
        }

        Ok(withdraws)
    }

    /// Creates a publication list reply for the set.
    pub fn get_list_reply(&self) -> KrillResult<publication::ListReply> {
        let mut elements = Vec::new();

        for (key, base64) in &self.0 {
            elements.push(publication::ListElement::new(
                key.try_into()?, base64.to_hash()
            ));
        }

        Ok(publication::ListReply::new(elements))
    }

    /// Returns the stats.
    pub fn get_stats(&self) -> PublisherStats {
        let mut manifests = vec![];
        for (uri_key, base64) in self.iter() {
            // Add all manifests - as long as they are syntactically correct -
            // do not crash on incorrect objects.
            if uri_key.as_str().ends_with("mft") {
                if let Ok(mft) =
                    Manifest::decode(base64.to_bytes().as_ref(), false)
                {
                    if let Ok(stats) = PublisherManifestStats::try_from(&mft)
                    {
                        manifests.push(stats)
                    }
                }
            }
        }

        PublisherStats {
            objects: self.len(),
            size: self.size_approx(),
            manifests,
        }
    }
}


//--- FromIterator

impl<K> FromIterator<(K, Base64)> for CurrentObjects
where K: Into<CurrentObjectUri> {
    fn from_iter<T: IntoIterator<Item = (K, Base64)>>(
        iter: T
    ) -> Self {
        Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}


//------------ CurrentObjectUri ----------------------------------------------

/// An object’s rsync URI as a simple map key.
///
/// We use this separate type rather than [`rpki::uri::Rsync`] because the
/// latter is not very suitable for use in hash maps: it is mutable and
/// its hash function is slow due to the fact that it needs
/// to accommodate for the fact that the URI scheme and hostname are
/// case insensitive.
///
/// This type can still be cloned cheaply since it holds an arc to an
/// allocated string.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CurrentObjectUri(Arc<str>);

impl CurrentObjectUri {
    /// Returns a string reference of the rsync URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&uri::Rsync> for CurrentObjectUri {
    fn from(value: &uri::Rsync) -> Self {
        // use canonical scheme and hostname (converts to lowercase if needed)
        CurrentObjectUri(
            format!("{}{}", value.canonical_module(), value.path()).into()
        )
    }
}

impl From<uri::Rsync> for CurrentObjectUri {
    fn from(value: uri::Rsync) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&CurrentObjectUri> for uri::Rsync {
    type Error = Error;

    fn try_from(key: &CurrentObjectUri) -> Result<Self, Self::Error> {
        uri::Rsync::from_slice(key.0.as_bytes()).map_err(|e| {
            Error::Custom(format!(
                "Found invalid object uri: {}. Error: {}",
                key.0, e
            ))
        })
    }
}

impl TryFrom<CurrentObjectUri> for uri::Rsync {
    type Error = Error;

    fn try_from(key: CurrentObjectUri) -> Result<Self, Self::Error> {
        uri::Rsync::try_from(&key)
    }
}


//------------ RrdpFileRandom ------------------------------------------------

/// A random component included in the name of RRDP files.
///
/// The component will make the URIs unguessable and prevent cache poisoning
/// (through CDNs caching a 404 not found).
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpFileRandom(String);

impl Default for RrdpFileRandom {
    fn default() -> Self {
        let mut bytes = [0; 8];
        openssl::rand::rand_bytes(&mut bytes).unwrap();
        let s = hex::encode(bytes);
        RrdpFileRandom(s)
    }
}


//------------ DeltaData -----------------------------------------------------

/// The data needed to create an RRDP delta XML file.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaData {
    /// A random value to make the URI unique.
    random: RrdpFileRandom,

    /// The serial number of the delta.
    ///
    /// The session is implied by owning RRDP server, but deltas carry a
    /// serial.
    serial: u64,

    /// The time the delta was created at.
    ///
    /// This is used to determine how long we need to keep it around for.
    time: Time,

    /// The objects changed by this delta.
    ///
    /// Note that we do not need to keep track of the owning publisher in this
    /// context. This value represents a change that has already been
    /// applied.
    elements: DeltaElements,
}

impl DeltaData {
    /// Creates a new delta from its components.
    pub fn new(
        serial: u64,
        time: Time,
        random: RrdpFileRandom,
        elements: DeltaElements,
    ) -> Self {
        DeltaData {
            serial,
            random,
            time,
            elements,
        }
    }

    /// Returns the serial number of the delta.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the random component of the delta URI.
    pub fn random(&self) -> &RrdpFileRandom {
        &self.random
    }

    /// Returns whether the delta is older than the given number of seconds.
    pub fn older_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time < then
    }

    /// Returns whether the delta is younger than the given number of seconds.
    pub fn younger_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time > then
    }

    /// Returns a reference to the delta elements.
    pub fn elements(&self) -> &DeltaElements {
        &self.elements
    }

    /// Returns the relative path to the delta.
    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/delta.xml", session, serial, self.random.0)
    }

    /// Returns the RRDP URI for the delta.
    pub fn uri(
        &self,
        session: RrdpSession,
        serial: u64,
        rrdp_base_uri: &uri::Https,
    ) -> uri::Https {
        rrdp_base_uri
            .join(self.rel_path(session, serial).as_ref())
            .unwrap()
    }

    /// Returns the local file path for the delta.
    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    /// Returns the delta XML.
    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Writes the delta XML.
    //
    // Note: we do not use the rpki-rs Delta implementation because we
    // potentially would need to transform and copy quite a lot of data.
    fn write_xml_to_writer(
        &self,
        session: RrdpSession,
        serial: u64,
        writer: &mut impl io::Write,
    ) -> Result<(), io::Error> {
        let mut writer = rpki::xml::encode::Writer::new(writer);
        writer
            .element(DELTA)?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("session_id", &session)?
            .attr("serial", &serial)?
            .content(|content| {
                for el in self.elements().publishes() {
                    content
                        .element(PUBLISH.into_unqualified())?
                        .attr("uri", &el.uri)?
                        .content(|content| {
                            content.raw(el.base64.as_str())
                        })?;
                }
                for el in self.elements().updates() {
                    content
                        .element(PUBLISH.into_unqualified())?
                        .attr("uri", &el.uri)?
                        .attr("hash", &el.hash)?
                        .content(|content| {
                            content.raw(el.base64.as_str())
                        })?;
                }
                for el in self.elements().withdraws() {
                    content
                        .element(WITHDRAW.into_unqualified())?
                        .attr("uri", &el.uri)?
                        .attr("hash", &el.hash)?;
                }
                Ok(())
            })?;

        writer.done()
    }
}


//------------ DeltaElements -------------------------------------------------

/// The elements of an RRDP delta.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaElements {
    /// The objects to be published.
    publishes: Vec<PublishElement>,

    /// The objects to be updated.
    updates: Vec<UpdateElement>,

    /// The objects to be withdrawn.
    withdraws: Vec<WithdrawElement>,
}

impl DeltaElements {
    /// Creates the delta from the various elements.
    pub fn new(
        publishes: Vec<PublishElement>,
        updates: Vec<UpdateElement>,
        withdraws: Vec<WithdrawElement>,
    ) -> Self {
        DeltaElements {
            publishes,
            updates,
            withdraws,
        }
    }

    /// Converts the value into its three constituent portions.
    pub fn unpack(
        self
    ) -> (
        Vec<PublishElement>,
        Vec<UpdateElement>,
        Vec<WithdrawElement>,
    ) {
        (self.publishes, self.updates, self.withdraws)
    }

    /// Returns the overall number of elements.
    pub fn len(&self) -> usize {
        self.publishes.len() + self.updates.len() + self.withdraws.len()
    }

    /// Returns whether there are no delta elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the approximate size of the published and updated objects.
    pub fn size_approx(&self) -> usize {
        let sum_publishes = self
            .publishes
            .iter()
            .fold(0, |sum, p| sum + p.base64.size_approx());
        let sum_updates =
            self.updates.iter().fold(0, |sum, u| sum + u.base64.size_approx());

        sum_publishes + sum_updates
    }

    /// Appends all elements from `other` to `self`.
    ///
    /// The method performs a dumb append, i.e., it will not check for
    /// duplicate operations such as withdrawing a previously published
    /// objected.
    pub fn append(&mut self, mut other: Self) {
        self.publishes.append(&mut other.publishes);
        self.updates.append(&mut other.updates);
        self.withdraws.append(&mut other.withdraws);
    }

    /// Returns a reference to the published elements.
    pub fn publishes(&self) -> &[PublishElement] {
        &self.publishes
    }

    /// Returns a reference to the updated elements.
    pub fn updates(&self) -> &[UpdateElement] {
        &self.updates
    }

    /// Returns a reference to the withdrawn elements.
    pub fn withdraws(&self) -> &[WithdrawElement] {
        &self.withdraws
    }
}


//--- From

impl From<publication::PublishDelta> for DeltaElements {
    fn from(d: publication::PublishDelta) -> Self {
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        for el in d.into_elements() {
            match el {
                publication::PublishDeltaElement::Publish(p) => {
                    publishes.push(p.into())
                }
                publication::PublishDeltaElement::Update(u) => {
                    updates.push(u.into())
                }
                publication::PublishDeltaElement::Withdraw(w) => {
                    withdraws.push(w.into())
                }
            }
        }

        DeltaElements {
            publishes,
            updates,
            withdraws,
        }
    }
}


//------------ StagedElements ------------------------------------------------

/// This type is used to combine staged delta elements for publishers.
///
/// It uses a map with object URIs as key, because this is the unique key that
/// identifies objects in the publication protocol.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StagedElements(HashMap<uri::Rsync, DeltaElement>);

impl StagedElements {
    /// Merge a new DeltaElements into this existing (unpublished)
    /// StagedElements.
    ///
    /// It is assumed that both sets make sense with regards to the current
    /// files as published in the RRDP snapshot. I.e. *this* StagedElements
    /// is assumed to be verified and can be applied to the current snapshot.
    ///
    /// The new StagedElements is assumed to be verified against the current
    /// snapshot after *this* existing StagedElements has been applied.
    ///
    /// We keep a single StagedElements per CA, for simplicity. The
    /// StagedElements contains all changes that the CA published at the
    /// Publication Server, which are not *yet* published in the public
    /// RPKI repository.
    ///
    /// CAs may wish to publish further changes, even before the staged
    /// changes become visible in the public RPKI repository. When merging
    /// these changes we need to take care to ensure that the changes make
    /// sense in relation to the current published *snapshot*.
    ///
    /// This operation is not entirely trivial as we need to make sure that
    /// any hashes in updates and withdraws after merge match the current
    /// snapshot, i.e. the new snapshot could refer to hashes of not yet
    /// published objects. We may also simply "forget" objects that were
    /// staged for publication, and then withdrawn, without ever have been
    /// published.
    ///
    /// Also note (again) that all changes have been verified before when
    /// this is called. That means that while certain corner cases could be
    /// problematic (e.g. double withdraw of an object), we will largely
    /// ignore such issues here. We need to do this, because we get these
    /// changes as write-ahead-log (WAL) changes and therefore applying
    /// them is not allowed to fail. In these cases we will log a warning
    /// that a "publish merge conflict" was found and resolved.
    fn merge_new_elements(&mut self, elements: DeltaElements) {
        let (publishes, updates, withdraws) = elements.unpack();

        let general_merge_message = "Non-critical publish merge conflict resolved. Please contact rpki-team@nlnetlabs.nl if this happens more frequently.";

        for pbl in publishes {
            let uri = pbl.uri.clone();
            match self.0.get_mut(&uri) {
                Some(DeltaElement::Publish(staged_publish)) => {
                    error!(
                        "{} Received new publish element for {} with content hash {} while another publish element with content hash {} was already staged. Expected new *update* element instead. Will use new publish.",
                        general_merge_message,
                        uri,
                        pbl.base64.to_hash(),
                        staged_publish.base64.to_hash()
                    );
                    self.0.insert(uri, DeltaElement::Publish(pbl));
                }

                Some(DeltaElement::Update(staged_update)) => {
                    error!(
                        "{} Received new publish element for {} with content hash {} while an *update* with content hash {} was already staged. Expected new *update* element instead. Will merge content of publish into staged update.",
                        general_merge_message,
                        uri,
                        pbl.base64.to_hash(),
                        staged_update.base64.to_hash()
                    );
                    staged_update.base64 = pbl.base64;
                }
                Some(DeltaElement::Withdraw(staged_withdraw)) => {
                    // A new publish that follows a withdraw for the same URI
                    // should be an Update of the original
                    // file.
                    let hash = staged_withdraw.hash;
                    let update = UpdateElement {
                        uri: uri.clone(), hash, base64: pbl.base64
                    };
                    self.0.insert(uri, DeltaElement::Update(update));
                }
                None => {
                    // This is just a fresh publish element, nothing to merge,
                    // we can just insert it.
                    self.0.insert(uri, DeltaElement::Publish(pbl));
                }
            }
        }

        for mut upd in updates {
            let uri = upd.uri.clone();
            match self.0.get_mut(&uri) {
                Some(DeltaElement::Publish(staged_publish)) => {
                    // An update that follows a *staged* publish, should be
                    // merged into a fresh new publish
                    // with the updated content.
                    //
                    // To the outside world (RRDP delta in particular) this
                    // will look like a single publish.
                    staged_publish.base64 = upd.base64;
                }
                Some(DeltaElement::Update(staged_update)) => {
                    // An update that follows a *staged* update, should be
                    // merged into an update with the
                    // updated content, but it should keep
                    // the hash (i.e. object it replaces) from the existing
                    // staged update.
                    //
                    // To the outside world (RRDP delta in particular) this
                    // will look like a single update.
                    staged_update.base64 = upd.base64;
                }
                Some(DeltaElement::Withdraw(staged_withdraw)) => {
                    error!(
                        "{} Received new update element for {} with content hash {} and replacing object hash {}, while a *withdraw* for content hash {} was already staged. Expected new *update* element instead. Will stage the update instead of withdraw.",
                        general_merge_message,
                        uri,
                        upd.base64.to_hash(),
                        upd.hash,
                        staged_withdraw.hash,
                    );
                    upd.hash = staged_withdraw.hash;
                    self.0.insert(uri, DeltaElement::Update(upd));
                }
                None => {
                    // A new update, nothing to merge. Just include it.
                    self.0.insert(uri, DeltaElement::Update(upd));
                }
            }
        }

        for mut wdr in withdraws {
            let uri = wdr.uri.clone();
            match self.0.get(&uri) {
                Some(DeltaElement::Publish(_)) => {
                    // We had a staged fresh publish for this object. So when
                    // combining we should just remove the
                    // staged entry completely. I.e. it won't
                    // have been visible to the outside world.
                    self.0.remove(&uri);
                }
                Some(DeltaElement::Update(staged_update)) => {
                    // We had a staged update for a file we now wish to
                    // remove. But, the staged updated
                    // files was never visible in public RRDP. Therefore,
                    // we should update the hash of the withdraw to the
                    // original hash.
                    wdr.hash = staged_update.hash;
                    self.0.insert(uri, DeltaElement::Withdraw(wdr));
                }
                Some(DeltaElement::Withdraw(staged_wdr)) => {
                    // This should never happen. But leave the original
                    // withdraw in place because
                    // that already matches the current file in public RRDP.
                    error!("{} We received a withdraw for an object that was already withdrawn.\nExisting withdraw: {} {}\nReceived withdraw: {} {}\n", general_merge_message, staged_wdr.hash, staged_wdr.uri, wdr.hash, wdr.uri)
                }
                None => {
                    // No staged changes for this element, so we can just add
                    // the withdraw as-is. It should match
                    // the current file in public RRDP.
                    self.0.insert(uri, DeltaElement::Withdraw(wdr));
                }
            }
        }
    }
}

impl From<StagedElements> for DeltaElements {
    fn from(staged: StagedElements) -> Self {
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        for el in staged.0.into_values() {
            match el {
                DeltaElement::Publish(publish) => publishes.push(publish),
                DeltaElement::Update(update) => updates.push(update),
                DeltaElement::Withdraw(withdraw) => withdraws.push(withdraw),
            }
        }
        DeltaElements::new(publishes, updates, withdraws)
    }
}


//============ RRDP Elements =================================================


//------------ PublishElement ------------------------------------------------

/// A publish element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishElement {
    /// The URI identifying the object to be published.
    pub uri: uri::Rsync,

    /// The Base64 encoded content of the object to be published.
    pub base64: Base64,
}

impl From<publication::Publish> for PublishElement {
    fn from(p: publication::Publish) -> Self {
        let (_tag, uri, base64) = p.unpack();
        PublishElement { base64, uri }
    }
}


//------------ UpdateElement -------------------------------------------------

/// An update element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateElement {
    /// The URI identifying the object to be updated.
    pub uri: uri::Rsync,

    /// The hash of the current content of the object to be updated.
    pub hash: Hash,

    /// The new content of the object to be updated.
    pub base64: Base64,
}

impl UpdateElement {
    /// Converts the update element into a publish element.
    pub fn into_publish(self) -> PublishElement {
        PublishElement {
            uri: self.uri,
            base64: self.base64,
        }
    }
}

impl From<publication::Update> for UpdateElement {
    fn from(u: publication::Update) -> Self {
        let (_tag, uri, base64, hash) = u.unpack();
        UpdateElement { uri, hash, base64 }
    }
}


//------------ WithdrawElement -----------------------------------------------

/// A withdraw element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
//
//  *Warning:* This type is used in stored state.
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawElement {
    /// The URI identifying the object to be withdrawn.
    pub uri: uri::Rsync,

    /// The hash of the current content of the object to be withdrawn.
    pub hash: Hash,
}

impl From<publication::Withdraw> for WithdrawElement {
    fn from(w: publication::Withdraw) -> Self {
        let (_tag, uri, hash) = w.unpack();
        WithdrawElement { uri, hash }
    }
}


//------------ DeltaElement --------------------------------------------------

/// An element in an RRDP delta.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeltaElement {
    Publish(PublishElement),
    Update(UpdateElement),
    Withdraw(WithdrawElement),
}


//============ Error Types ===================================================

//------------ PublicationDeltaError -----------------------------------------

/// An error happened while verifying a delta.
#[derive(Clone, Debug)]
pub enum PublicationDeltaError {
    /// An object URI is outside the rsync base path.
    UriOutsideJail(uri::Rsync, uri::Rsync),

    /// A published object is already present.
    ObjectAlreadyPresent(uri::Rsync),

    /// An updated or deleted object is not present with the right hash.
    NoObjectForHashAndOrUri(uri::Rsync),
}

impl PublicationDeltaError {
    fn outside(jail: &uri::Rsync, uri: &uri::Rsync) -> Self {
        PublicationDeltaError::UriOutsideJail(uri.clone(), jail.clone())
    }

    fn present(uri: &uri::Rsync) -> Self {
        PublicationDeltaError::ObjectAlreadyPresent(uri.clone())
    }

    fn no_match(uri: &uri::Rsync) -> Self {
        PublicationDeltaError::NoObjectForHashAndOrUri(uri.clone())
    }
}

impl fmt::Display for PublicationDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicationDeltaError::UriOutsideJail(uri, jail) => {
                write!(f,
                    "Publishing '{uri}' outside of jail URI '{jail}'"
                )
            }
            PublicationDeltaError::ObjectAlreadyPresent(uri) => {
                write!(f,
                    "File already exists for uri (use update!): {uri}"
                )
            }
            PublicationDeltaError::NoObjectForHashAndOrUri(uri) => {
                write!(f, "File does not match hash at uri: {uri}")
            }
        }
    }
}

impl error::Error for PublicationDeltaError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use crate::commons::test::*;
    use super::*;

    #[test]
    fn current_objects_delta() {
        let jail = rsync("rsync://example.krill.cloud/repo/publisher");
        let file1_uri =
            rsync("rsync://example.krill.cloud/repo/publisher/file1.txt");

        let file1_content = Base64::from_content(&[1]);
        let file1_content_2 = Base64::from_content(&[1, 2]);
        let file2_content = Base64::from_content(&[2]);

        let mut objects = CurrentObjects::default();

        let publish_file1 = DeltaElements {
            publishes: vec![PublishElement {
                uri: file1_uri.clone(),
                base64: file1_content.clone(),
            }],
            updates: vec![],
            withdraws: vec![],
        };

        // adding a file to an empty current objects is okay
        assert!(objects.verify_delta_applies(&publish_file1, &jail).is_ok());

        // The actual application of the delta is infallible, because event
        // replays may not fail. It is assumed deltas were verified
        // before they were persisted in events.
        objects.apply_delta(publish_file1.clone());

        // Now adding the same file for the same URI and same hash, as a
        // publish will fail.
        assert!(objects.verify_delta_applies(&publish_file1, &jail).is_err());

        // Adding a different file as a publish element, rather than update,
        // for the same URI will also fail. Checks fix for issue #981.
        let publish_file2 = DeltaElements {
            publishes: vec![PublishElement {
                uri: file1_uri.clone(),
                base64: file2_content,
            }],
            updates: vec![],
            withdraws: vec![],
        };
        assert!(objects.verify_delta_applies(&publish_file2, &jail).is_err());

        // Updates

        // Updating a file should work
        let update_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![UpdateElement {
                uri: file1_uri.clone(),
                hash: file1_content.to_hash(),
                base64: file1_content_2.clone(),
            }],
            withdraws: vec![],
        };
        assert!(objects.verify_delta_applies(&update_file1, &jail).is_ok());
        objects.apply_delta(update_file1.clone());

        // Updating again with the same delta will now fail - there is no
        // longer and object with that uri and hash it was updated to
        // the new content.
        assert!(objects.verify_delta_applies(&update_file1, &jail).is_err());

        // Withdraws

        // Withdrawing file with wrong hash should fail
        let withdraw_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement {
                uri: file1_uri.clone(),
                hash: file1_content.to_hash(),
            }],
        };
        assert!(
            objects.verify_delta_applies(&withdraw_file1, &jail).is_err()
        );

        // Withdrawing file with the right hash should work
        let withdraw_file1_updated = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement {
                uri: file1_uri,
                hash: file1_content_2.to_hash(),
            }],
        };
        assert!(
            objects.verify_delta_applies(
                &withdraw_file1_updated, &jail
            ).is_ok()
        );
    }

    #[test]
    fn current_objects_deltas() {
        fn file_rsync_uri(name: &str) -> uri::Rsync {
            let jail = rsync("rsync://example.krill.cloud/repo/publisher");
            jail.join(name.as_bytes()).unwrap()
        }

        fn file_uri(name: &str) -> CurrentObjectUri {
            CurrentObjectUri(
                format!(
                    "rsync://example.krill.cloud/repo/publisher/{name}"
                )
                .into(),
            )
        }

        fn random_content() -> Base64 {
            let mut bytes = [0; 8];
            openssl::rand::rand_bytes(&mut bytes).unwrap();
            Base64::from_content(&bytes)
        }

        // True if the delta contains the same content, even if the ordering
        // is different.
        pub fn equivalent(
            mut this: DeltaElements, mut other: DeltaElements
        ) -> bool {
            this.publishes
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.publishes
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            this.updates
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.updates
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            this.withdraws
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.withdraws
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));

            this.publishes == other.publishes
                && this.updates == other.updates
                && this.withdraws == other.withdraws
        }

        let mut objects: HashMap<CurrentObjectUri, Base64> = HashMap::new();
        objects.insert(file_uri("file1"), random_content());
        objects.insert(file_uri("file2"), random_content());
        objects.insert(file_uri("file3"), random_content());
        objects.insert(file_uri("file4"), random_content());

        let publishes = vec![
            PublishElement {
                uri: file_rsync_uri("file5"), base64: random_content()
            },
            PublishElement {
                uri: file_rsync_uri("file6"), base64: random_content(), 
            },
        ];

        let updates = vec![
            UpdateElement {
                uri: file_rsync_uri("file1"),
                hash: objects.get(&file_uri("file1")).unwrap().to_hash(),
                base64: random_content(),
            },
            UpdateElement {
                uri: file_rsync_uri("file2"),
                hash: objects.get(&file_uri("file2")).unwrap().to_hash(),
                base64: random_content(),
            },
        ];

        let withdraws = vec![WithdrawElement {
            uri: file_rsync_uri("file3"),
            hash: objects.get(&file_uri("file3")).unwrap().to_hash(),
        }];

        let delta_a_b = DeltaElements::new(publishes, updates, withdraws);
        let objects_a = CurrentObjects(objects);

        let mut objects_b = objects_a.clone();
        objects_b.apply_delta(delta_a_b.clone());
        let derived_delta_a_b = objects_a.diff(&objects_b).unwrap();

        // eprintln!("-----------------GIVEN--------------------");
        // eprintln!("objects: ");
        // eprintln!("{}", serde_json::to_string_pretty(&objects_a).unwrap());
        // eprintln!("delta: ");
        // eprintln!("{}", serde_json::to_string_pretty(&delta_a_b).unwrap());
        // eprintln!("------------------------------------------");

        // eprintln!();

        // eprintln!("-----------------RESULT B------------------");
        // eprintln!("{}", serde_json::to_string_pretty(&objects_b).unwrap());
        // eprintln!("------------------------------------------");

        // eprintln!();

        // eprintln!("-----------------DERIVE A -> B -----------");
        // eprintln!("{}",
        // serde_json::to_string_pretty(&derived_delta_a_b).unwrap());
        // eprintln!("------------------------------------------");

        assert!(equivalent(delta_a_b, derived_delta_a_b));

        let derived_delta_b_a = objects_b.diff(&objects_a).unwrap();
        // eprintln!();
        // eprintln!("-----------------DERIVE B -> A -----------");
        // eprintln!("{}",
        // serde_json::to_string_pretty(&derived_delta_b_a).unwrap());
        // eprintln!("------------------------------------------");

        let mut objects_a_from_b = objects_b.clone();
        objects_a_from_b.apply_delta(derived_delta_b_a);

        // eprintln!();
        // eprintln!("-----------------RESULT B------------------");
        // eprintln!("{}",
        // serde_json::to_string_pretty(&objects_a_from_b).unwrap());
        // eprintln!("------------------------------------------");

        assert_eq!(objects_a, objects_a_from_b);
    }
}

