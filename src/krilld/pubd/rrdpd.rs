use std::io;
use std::fs;
use std::num::ParseIntError;
use std::path::PathBuf;
use bytes::Bytes;
use rpki::uri;
use crate::api::publication;
use crate::api::rrdp_data::{self, Notification};
use crate::api::rrdp_data::Snapshot;
use crate::api::rrdp_data::PublishedObject;
use crate::util::file::{self, RecursorError};
use crate::storage::keystore::{self, Key, KeyStore};
use crate::storage::caching_ks::CachingDiskKeyStore;
use std::sync::Arc;
use std::collections::HashMap;
use storage::keystore::Info;
use api::rrdp_data::FileInfo;
use api::rrdp_data::DeltaRef;
use util::xml::XmlWriter;
use api::rrdp_data::NotificationBuilder;
use api::rrdp_data::SnapshotRef;

//const VERSION: &'static str = "1";
//const NS: &'static str = "http://www.ripe.net/rpki/rrdp";
const RRDP_FOLDER: &str = "rrdp";
const FS_FOLDER: &str = "rsync";

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";



/// This type publishes RRDP notifications, snapshots and deltas so that they
/// can be served to relying parties.
#[derive(Clone, Debug)]
pub struct RrdpServer {
    store: CachingDiskKeyStore,

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
    pub fn build(
        base_uri: &uri::Http,
        work_dir: &PathBuf
    ) -> Result<Self, Error>
    {
        if ! base_uri.to_string().ends_with('/') {
            return Err(Error::UriConfigError)
        }

        let mut rrdp_store_dir = PathBuf::from(work_dir);
        rrdp_store_dir.push("rrdp_store");
        if ! rrdp_store_dir.is_dir() {
            fs::create_dir_all(&rrdp_store_dir)?;
        }

        let store = CachingDiskKeyStore::build(rrdp_store_dir)?;

        let rrdp_base = file::sub_dir(work_dir, RRDP_FOLDER)?;
        let fs_base = file::sub_dir(work_dir, FS_FOLDER)?;
        Ok(RrdpServer { store, base_uri: base_uri.clone(), rrdp_base, fs_base })
    }
}

/// # Storing, Retrieving, and referencing Notification, Snapshot, Deltas
///
impl RrdpServer {

//    const REL_NOTIFICATION: &'static str = "notification.xml";

    fn key_notification() -> Key {
        Key::new("notification")
    }

    fn key_snapshot(session: &str, serial: usize) -> Key {
        Key::new(&format!("{}-{}-snapshot", session, serial))
    }

    pub fn get_notification(
        &self
    ) -> Result<Option<Arc<Notification>>, Error> {
        let key = Self::key_notification();
        self.store.get(&key).map_err(Error::Keystore)
    }

    pub fn get_snapshot(
        &self,
        session: &str,
        serial: usize
    ) -> Result<Option<Arc<Snapshot>>, Error> {
        let key = Self::key_snapshot(session, serial);
        self.store.get(&key).map_err(Error::Keystore )
    }

    pub fn save_notification(
        &mut self,
        notification: Notification
    ) -> Result<(), Error> {
        let key = Self::key_notification();
        self.store.store(
            key,
            notification,
            Info::now("server", "notification")
        ).map_err(Error::Keystore)
    }

    pub fn save_snapshot(
        &mut self,
        session: &str,
        serial: usize,
        snapshot: Snapshot
    ) -> Result<(), Error> {
        let key = Self::key_snapshot(session, serial);
        self.store.store(
            key,
            snapshot,
            Info::now("server", "notification")
        ).map_err(Error::Keystore)
    }
}

/// # Publishing
///
impl RrdpServer {

    fn verified_rel(
        uri: &uri::Rsync,
        base_uri: &uri::Rsync
    ) -> Result<String, Error> {
        match uri.relative_to(base_uri) {
            Some(rel) => unsafe { // uri ensures characters are safe
                Ok(std::str::from_utf8_unchecked(rel).to_string())
            },
            None => Err(Error::OutsideBaseUri)
        }
    }


    /// Process an update PublishQuery and produce a new delta, snapshot
    /// and notification file. Assumes that this is called *after* the
    /// ['FileStore'] has published, so files should already be saved to
    /// disk and the snapshots can be derived from this.
    pub fn publish(
        &mut self,
        delta: &publication::PublishDelta,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {

        let (session, serial, deltas) = match self.get_notification()? {
            Some(notification) => {
                (
                    notification.session_id().clone(),
                    notification.serial(),
                    notification.deltas().clone()
                )
            },
            None => {
                (
                    {
                        use rand::{thread_rng, Rng};
                        let mut rng = thread_rng();
                        let rnd: u32 = rng.gen();
                        format!("{}", rnd)
                    },
                    0,
                    Vec::new()
                )
            }
        };

        let mut all_objects = match self.get_snapshot(&session, serial)? {
            Some(snapshot) => snapshot.objects().clone(),
            None => HashMap::new()
        };

        let mut objects = match all_objects.get(&base_uri.to_string()) {
            Some(objects) => objects.clone(),
            None => Vec::new()
        };

        for p in delta.publishes() {
            let _rel = Self::verified_rel(p.uri(), base_uri)?;
            let object = PublishedObject::new(p.uri().clone(), p.content().clone());
            if objects.contains(&object) {
                return Err(Error::ObjectAlreadyPresent(p.uri().clone()))
            }
            objects.push(object);
        }

        for u in delta.updates() {
            let _rel = Self::verified_rel(u.uri(), base_uri)?;

            match objects.iter().position(|cur| {cur.uri() == u.uri()}) {
                None => return Err(Error::NoObjectPresent(u.uri().clone())),
                Some(pos) => {
                    if objects[pos].hash() != u.hash() {
                        return Err(Error::NoObjectMatchingHash)
                    } else {
                        objects.remove(pos);
                    }
                }
            }

            let object = PublishedObject::new(u.uri().clone(), u.content().clone());
            objects.push(object);
        }

        for w in delta.withdraws() {
            let _rel = Self::verified_rel(w.uri(), base_uri)?;
            match objects.iter().position(|cur| {cur.uri() == w.uri()}) {
                None => return Err(Error::NoObjectPresent(w.uri().clone())),
                Some(pos) => {
                    if objects[pos].hash() != w.hash() {
                        return Err(Error::NoObjectMatchingHash)
                    } else {
                        objects.remove(pos);
                    }
                }
            }
        }

        all_objects.insert(base_uri.to_string(), objects);

        let new_serial = serial + 1;

        // Create new snapshot
        let snapshot = Snapshot::new(
            session.clone(),
            new_serial,
            all_objects
        );

        // Save the xml to disk
        let snapshot_ref = {
            let xml = snapshot.to_xml();
            let path = self.snapshot_path(&session, new_serial);
            file::save(&Bytes::from(xml), &path)?;
            SnapshotRef::new(
                FileInfo::for_path_and_uri(
                    &path, self.snapshot_uri(&session, new_serial)
                )?
            )
        };

        // save to store
        self.save_snapshot(&session, new_serial, snapshot)?;

        // Create new delta
        let delta_ref = self.save_delta(&session, new_serial, delta)?;

        // Create new notification file
        let new_notification = {
            let mut builder = NotificationBuilder::new();
            builder.with_session_id(session);
            builder.with_serial(new_serial);
            builder.with_deltas(deltas);
            builder.add_delta_to_start(delta_ref);
            builder.with_snapshot(snapshot_ref);
            builder.build()
        };


        let path = self.notification_path();
        new_notification.save(&path)?;

        self.save_notification(new_notification)?;

        Ok(())
    }


    /// Saves the RFC8181 PublishQuery as an RFC8182 delta file.
    fn save_delta(
        &mut self,
        session_id: &str,
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

    pub fn notification_uri(&self) -> uri::Http {
        uri::Http::from_string(
            format!("{}notification.xml", self.base_uri.to_string())
        ).unwrap() // Cannot fail. Config checked at startup.
    }

    pub fn snapshot_uri(&self, session: &str, serial: usize) -> uri::Http {
        uri::Http::from_string(
            format!("{}{}/{}/snapshot.xml",
                    self.base_uri.to_string(),
                    session,
                    serial
            )
        ).unwrap() // Cannot fail. Config checked at startup.
    }

    pub fn delta_uri(&self, session: &str, serial: usize) -> uri::Http {
        uri::Http::from_string(
            format!("{}{}/{}/snapshot.xml",
                    self.base_uri.to_string(),
                    session,
                    serial
            )
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
    Keystore(keystore::Error),

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

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self { Error::Keystore(e) }
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

