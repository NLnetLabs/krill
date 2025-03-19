//! Managing content for rsyncd.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use rpki::uri;
use serde::{Deserialize, Serialize};
use crate::commons::KrillResult;
use crate::commons::error::{Error, KrillIoError};
use crate::commons::util::file;
use crate::constants::REPOSITORY_RSYNC_DIR;
use super::rrdp::SnapshotData;

//------------ RsyncdStore ---------------------------------------------------

/// Manages content to be published with rsyncd.
///
/// This type is responsible for publishing files on disk in a structure so
/// that an rsyncd can be set up to serve this (RPKI) data. Note that the
/// rsync host name and module are part of the path, so make sure that the
/// rsyncd modules and paths are setup properly for each supported rsync
/// base uri used.
///
/// The type is to be deprecated! We have implemented this logic better in
/// krill-sync and should use that instead in future. Doing so will allow us
/// to simplify things here, and it will also remove the requirement to write
/// things to disk. We can then have the RRDP component server RRDP over
/// HTTPs and let krill-sync do the writing with all the caveats that that
/// involves.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RsyncdStore {
    /// The base URI for our store.
    base_uri: uri::Rsync,

    /// The path to the directory we will keep our files in.
    rsync_dir: PathBuf,

    /// An access lock for updating the store.
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "Default::default"
    )]
    lock: Arc<Mutex<()>>,
}

impl RsyncdStore {
    /// Creates a new rsyncd store.
    pub fn new(base_uri: uri::Rsync, repo_dir: &Path) -> Self {
        let mut rsync_dir = repo_dir.to_path_buf();
        rsync_dir.push(REPOSITORY_RSYNC_DIR);
        RsyncdStore {
            base_uri,
            rsync_dir,
            lock: Default::default(),
        }
    }

    /// Returns the base URI of the store.
    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    /// Writes all the files to disk.
    ///
    /// First writes the files a tmp-dir, then switches that directory over
    /// to the final directory in an effort to minimize the chance of people
    /// getting inconsistent syncs..
    pub fn write(
        &self,
        serial: u64,
        snapshot: &SnapshotData,
    ) -> KrillResult<()> {
        let _lock = self.lock.lock().map_err(|_| {
            Error::custom("Could not get write lock for rsync repo")
        })?;

        let mut new_dir = self.rsync_dir.clone();
        new_dir.push(format!("tmp-{}", serial));
        fs::create_dir_all(&new_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not create dir(s) '{}' for publishing rsync",
                    new_dir.display()
                ),
                e,
            )
        })?;

        for current in snapshot.publishers_current_objects().values() {
            for (uri_key, base64) in current.iter() {
                // Note that this check should not be needed here, as the
                // content already verified before it was
                // accepted into the snapshot.
                let uri = uri::Rsync::try_from(uri_key)?;
                let rel = uri.relative_to(&self.base_uri).ok_or_else(|| {
                    Error::publishing_outside_jail(&uri, &self.base_uri)
                })?;

                let mut path = new_dir.clone();
                path.push(rel);

                file::save(&base64.to_bytes(), &path)?;
            }
        }

        let mut current_dir = self.rsync_dir.clone();
        current_dir.push("current");

        let mut old_dir = self.rsync_dir.clone();
        old_dir.push("old");

        if current_dir.exists() {
            fs::rename(&current_dir, &old_dir).map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not rename current rsync dir from \
                         '{}' to '{}' while publishing",
                        current_dir.display(),
                        old_dir.display()
                    ),
                    e,
                )
            })?;
        }

        fs::rename(&new_dir, &current_dir).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not rename new rsync dir from \
                     '{}' to '{}' while publishing",
                    new_dir.display(),
                    current_dir.display()
                ),
                e,
            )
        })?;

        if old_dir.exists() {
            fs::remove_dir_all(&old_dir).map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not remove up old rsync dir '{}' \
                         while publishing",
                        old_dir.display()
                    ),
                    e,
                )
            })?;
        }

        Ok(())
    }

    /// Deletes all data.
    pub fn clear(&self) {
        let _ = fs::remove_dir_all(&self.rsync_dir);
    }
}

