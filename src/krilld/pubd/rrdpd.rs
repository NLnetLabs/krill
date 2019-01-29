use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use rpki::uri;
use crate::api::publication;
use crate::api::rrdp_data::{self, Notification, NotificationBuilder};
use crate::api::rrdp_data::FileInfo;
use crate::api::rrdp_data::DeltaRef;
use crate::api::rrdp_data::SnapshotRef;
use crate::util::file::{self, RecursorError};
use crate::util::xml::{XmlWriter};

const VERSION: &'static str = "1";
const NS: &'static str = "http://www.ripe.net/rpki/rrdp";
const RRDP_FOLDER: &'static str = "rrdp";
const FS_FOLDER: &'static str = "rsync";


/// This type publishes RRDP notifications, snapshots and deltas so that they
/// can be served to relying parties.
#[derive(Clone, Debug)]
pub struct RrdpServer {
    // The base URI path for notification, snapshot and delta files.
    base_uri:  uri::Http,

    // Dir for notification, snapshot and delta files.
    rrdp_base: PathBuf,

    // Dir for file_store (so that snapshots can be derived)
    fs_base:   PathBuf
}

/// # Setup and initialisation
impl RrdpServer {

    /// Creates a new RrdpServer.
    ///
    /// This will pick up the saved state from the notification.xml if
    /// present, or initialise a new server with a random session_id,
    /// starting at serial 1, and including a snapshot for everything
    /// currently stored in the rsync file_store.
    pub fn new(
        base_uri: &uri::Http,
        work_dir: &PathBuf
    ) -> Result<Self, Error>
    {
        if ! base_uri.to_string().ends_with("/") {
            return Err(Error::UriConfigError)
        }

        let rrdp_base = file::sub_dir(work_dir, RRDP_FOLDER)?;
        let fs_base = file::sub_dir(work_dir, FS_FOLDER)?;
        Ok(RrdpServer { base_uri: base_uri.clone(), rrdp_base, fs_base })
    }
}

/// # Publishing
///
impl RrdpServer {

    /// Process an update PublishQuery and produce a new delta, snapshot
    /// and notification file. Assumes that this is called *after* the
    /// ['FileStore'] has published, so files should already be saved to
    /// disk and the snapshots can be derived from this.
    pub fn publish(
        &mut self,
        delta: &publication::PublishDelta
    ) -> Result<(), Error> {
        let current_notification = Notification::build(
            &self.notification_path(),
            &self.base_uri,
            &self.rrdp_base
        );

        let session_id = match &current_notification {
            Some(n) => n.session_id().clone(),
            None => {
                use rand::{thread_rng, Rng};
                let mut rng = thread_rng();
                let rnd: u32 = rng.gen();
                format!("{}", rnd)
            }
        };
        let serial = match &current_notification {
            Some(n) => n.serial() + 1,
            None    => 1
        };

        let snapshot = self.save_snapshot(&session_id, serial)?;
        let delta_file = self.save_delta(&session_id, serial, delta)?;

        let mut notif_builder = NotificationBuilder::new();

        notif_builder.with_session_id(session_id);
        notif_builder.with_serial(serial);
        notif_builder.with_snapshot(snapshot);

        if let Some(notification) = current_notification {
            notif_builder.with_deltas(notification.deltas().clone())
        }

        notif_builder.add_delta_to_start(delta_file);

        let notification = notif_builder.build();
        notification.save(&self.notification_path())
            .map_err(|e| Error::RrdpData(e))
    }


    /// Saves the RFC8181 PublishQuery as an RFC8182 delta file.
    fn save_delta(
        &mut self,
        session_id: &String,
        serial: usize,
        delta: &publication::PublishDelta
    ) -> Result<DeltaRef, Error>
    {
        let path = self.delta_path(session_id, serial);
        debug!("Writing delta: {}", path.to_string_lossy());
        let mut file = file::create_file_with_path(&path)?;

        XmlWriter::encode_to_file(& mut file, |w| {

            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", session_id),
                ("serial", &format!("{}", serial)),
            ];

            w.put_element(
                "delta",
                Some(&a),
                |w| {
                    for publish in delta.publishes() {
                        let uri = publish.uri().to_string();
                        let a = [
                            ("uri", uri.as_ref())
                        ];
                        w.put_element(
                            "publish",
                            Some(&a),
                            |w| {
                                w.put_blob(publish.content())
                            }
                        )?
                    }

                    for update in delta.updates() {
                        let uri = update.uri().to_string();
                        let hash = hex::encode(update.hash());
                        let a = [
                            ("uri", uri.as_ref()),
                            ("hash", hash.as_ref())
                        ];
                        w.put_element(
                            "publish",
                            Some(&a),
                            |w| {
                                w.put_blob(update.content())
                            }
                        )?
                    }

                    for withdraw in delta.withdraws() {
                        let uri = withdraw.uri().to_string();
                        let hash = hex::encode(withdraw.hash());
                        let a = [
                            ("uri", uri.as_ref()),
                            ("hash", hash.as_ref())
                        ];
                        w.put_element(
                            "withdraw",
                            Some(&a),
                            |w| {
                                w.empty()
                            }
                        )?
                    }
                    Ok(())
                })
        })?;

        let file_info = FileInfo::for_path(
            &path,
            &self.base_uri,
            &self.rrdp_base
        )?;
        Ok(DeltaRef::new(serial, file_info))
    }


    /// Saves the current snapshot, based on the state of the ['FileStore']
    /// base directory.
    fn save_snapshot(
        &mut self,
        session_id: &String,
        serial: usize
    ) -> Result<SnapshotRef, Error> {
        let path = self.snapshot_path(session_id, serial);
        debug!("Writing snapshot: {}", path.to_string_lossy());
        let mut file = file::create_file_with_path(&path)?;
        let current_files = file::crawl_derive_rsync_uri(&self.fs_base)?;

        XmlWriter::encode_to_file(& mut file, |w| {

            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", session_id),
                ("serial", &format!("{}", serial)),
            ];

            w.put_element(
                "snapshot",
                Some(&a),
                |w| {
                    for cf in current_files {
                        let uri = cf.uri().to_string();
                        let a = [ ("xmlns", uri.as_ref()) ];
                        w.put_element(
                            "publish",
                            Some(&a),
                            |w| {
                                w.put_blob(cf.content())
                            }
                        )?;
                    }
                    Ok(())
                }
            )
        })?;

        let file_info = FileInfo::for_path(
            &path,
            &self.base_uri,
            &self.rrdp_base
        )?;

        Ok(SnapshotRef::new(file_info))
    }

    pub fn notification_uri(&self) -> uri::Http {
        uri::Http::from_string(
            format!("{}notification.xml", self.base_uri.to_string())
        ).unwrap() // Cannot fail. Config checked at startup.
    }

    pub fn notification_path(&self) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push("notification.xml");
        path
    }

    pub fn delta_path(&self, session: &str, serial: usize) -> PathBuf {
        let mut path = self.serial_path(session, serial);
        path.push("delta.xml");
        path
    }

    pub fn snapshot_path(&self, session: &str, serial: usize) -> PathBuf {
        let mut path = self.serial_path(session, serial);
        path.push("snapshot.xml");
        path
    }

    fn serial_path(&self, session: &str, serial: usize) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push(session);
        path.push(format!("{}", serial));
        path
    }
}




//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    RecursorError(RecursorError),

    #[display(fmt="{}", _0)]
    UriError(uri::Error),

    #[display(fmt="File already exists for uri (use update!): {}", _0)]
    ObjectAlreadyPresent(uri::Rsync),

    #[display(fmt="Np file present for uri: {}", _0)]
    NoObjectPresent(uri::Rsync),

    #[display(fmt="File does not match hash")]
    NoObjectMatchingHash,

    #[display(fmt="Publishing outside of base URI is not allowed.")]
    OutsideBaseUri,

    #[display(fmt="Issue deriving RRDP URI, check config. Base URI must end with a '/'!")]
    UriConfigError,

    #[display(fmt="Error deserializing existing notification.xml")]
    NotificationFileError,

    #[display(fmt="{}", _0)]
    ParseIntError(ParseIntError),

    #[display(fmt="{}", _0)]
    RrdpData(rrdp_data::Error)
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self { Error::UriError(e) }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self { Error::ParseIntError(e) }
}

impl From<rrdp_data::Error> for Error {
    fn from(e: rrdp_data::Error) -> Self { Error::RrdpData(e) }
}

impl From<RecursorError> for Error {
    fn from(e: RecursorError) -> Self { Error::RecursorError(e) }
}

