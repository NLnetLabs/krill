use std::fs::File;
use std::io;
use std::num::ParseIntError;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use file;
use file::RecursorError;
use repo::file_store::FS_FOLDER;
use rpki::publication::query::PublishElement;
use rpki::publication::query::PublishQuery;
use rpki::remote::xml::AttributesError;
use rpki::remote::xml::XmlReader;
use rpki::remote::xml::XmlReaderErr;
use rpki::remote::xml::XmlWriter;
use rpki::uri;

const VERSION: &'static str = "1";
const NS: &'static str = "http://www.ripe.net/rpki/rrdp";
const RRDP_FOLDER: &'static str = "rrdp";

/// Derives the notification uri based on the RRDP base uri (from config)
/// Panics in case of (config) issues, and is called during bootstrapping.
pub fn notification_uri(base: &uri::Http) -> uri::Http {
    let base_string = base.to_string();
    if ! base_string.ends_with("/") {
        panic!("RRDP base path should end with a '/', got:{}", base_string);
    }
    uri::Http::from_string(
        format!("{}notification.xml", base.to_string())
    ).unwrap() // Can only fail at startup if mis-configured.
}

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
    pub fn publish(&mut self, update: &PublishQuery) -> Result<(), Error> {
        let current_notification = Notification::derive(
            &self.notification_path(),
            &self.base_uri,
            &self.rrdp_base
        );

        let session_id = match &current_notification {
            Some(n) => n.session_id.clone(),
            None => {
                use rand::{thread_rng, Rng};
                let mut rng = thread_rng();
                let rnd: u32 = rng.gen();
                format!("{}", rnd)
            }
        };
        let serial = match &current_notification {
            Some(n) => n.serial + 1,
            None    => 1
        };

        let snapshot = self.save_snapshot(&session_id, serial)?;
        let delta = self.save_delta(&session_id, serial, update)?;

        let mut notif_builder = NotificationBuilder::new();

        notif_builder.with_session_id(session_id);
        notif_builder.with_serial(serial);
        notif_builder.with_snapshot(snapshot);

        if let Some(notification) = current_notification {
            notif_builder.with_deltas(notification.deltas)
        }

        notif_builder.add_delta_to_start(delta);

        let notification = notif_builder.build();
        notification.save(&self.notification_path())
    }


    /// Saves the RFC8181 PublishQuery as an RFC8182 delta file.
    fn save_delta(
        &mut self,
        session_id: &String,
        serial: usize,
        update: &PublishQuery
    ) -> Result<DeltaRef, Error>
    {
        let path = self.delta_path(session_id, serial);
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
                    for el in update.elements() {
                        match el {
                            PublishElement::Publish(el) => {
                                let uri = el.uri().to_string();
                                let a = [
                                    ("uri", uri.as_ref())
                                ];
                                w.put_element(
                                    "publish",
                                    Some(&a),
                                    |w| {
                                        w.put_blob(el.object())
                                    }
                                )?
                            },
                            PublishElement::Update(el) => {
                                let uri = el.uri().to_string();
                                let hash = hex::encode(el.hash());
                                let a = [
                                    ("uri", uri.as_ref()),
                                    ("hash", hash.as_ref())
                                ];
                                w.put_element(
                                    "publish",
                                    Some(&a),
                                    |w| {
                                        w.put_blob(el.object())
                                    }
                                )?
                            },
                            PublishElement::Withdraw(el) => {
                                let uri = el.uri().to_string();
                                let hash = hex::encode(el.hash());
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
                            },
                        };
                    }
               Ok(())
           })
        })?;

        let file_info = FileInfo::for_path(
            &path,
            &self.base_uri,
            &self.rrdp_base
        )?;
        Ok(DeltaRef { serial, file_info })
    }


    /// Saves the current snapshot, based on the state of the ['FileStore']
    /// base directory.
    fn save_snapshot(
        &mut self,
        session_id: &String,
        serial: usize
    ) -> Result<SnapshotRef, Error> {
        let path = self.snapshot_path(session_id, serial);
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

        Ok(SnapshotRef { file_info })
    }


    fn notification_path(&self) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push("notification.xml");
        path
    }

    fn delta_path(&self, session_id: &String, serial: usize) -> PathBuf {
        let mut path = self.serial_path(session_id, serial);
        path.push("delta.xml");
        path
    }

    fn snapshot_path(&self, session_id: &String, serial: usize) -> PathBuf {
        let mut path = self.serial_path(session_id, serial);
        path.push("snapshot.xml");
        path
    }

    fn serial_path(&self, session_id: &String, serial: usize) -> PathBuf {
        let mut path = self.rrdp_base.clone();
        path.push(session_id);
        path.push(format!("{}", serial));
        path
    }
}


//------------ Notification --------------------------------------------------

#[derive(Clone, Debug)]
pub struct Notification {
    session_id: String,
    serial:     usize,
    snapshot:   SnapshotRef,
    deltas:     Vec<DeltaRef>
}

/// # Accessors
///
impl Notification {
    pub fn serial(&self) -> &usize {
        &self.serial
    }

    pub fn deltas(&self) -> &Vec<DeltaRef> {
        &self.deltas
    }
}

/// # Load and save
///
impl Notification {

    pub fn derive(
        path: &PathBuf,
        base_uri: &uri::Http,
        rrdp_base: &PathBuf
    ) -> Option<Notification> {
        let mut builder = NotificationBuilder::new();

        match XmlReader::open(path, |r| -> Result<(), Error> {
            r.take_named_element("notification", |mut a, r| {
                {
                    // process attributes
                    builder.with_session_id(a.take_req("session_id")?);
                    let serial = usize::from_str(a.take_req("serial")?.as_ref())?;
                    builder.with_serial(serial);
                    // about NS
                }

                {
                    // expect snapshot ref
                    r.take_named_element(
                        "snapshot",
                        |mut a, _r| -> Result<(), Error> {
                            let uri = uri::Http::from_string(a.take_req("uri")?)?;
                            let file_info = FileInfo::for_uri(
                                &uri,
                                base_uri,
                                rrdp_base
                            )?;

                            builder.with_snapshot(
                                SnapshotRef { file_info }
                            );
                            Ok(())
                        })?;
                }

                {
                    // deltas
                    loop {
                        let d = r.take_opt_element(|t, mut a, _r| {
                            match t.name.as_ref() {
                                "delta" => {
                                    let uri = uri::Http::from_string(
                                        a.take_req("uri")?
                                    )?;
                                    let serial = usize::from_str(
                                        a.take_req("serial")?.as_ref()
                                    )?;
                                    let file_info = FileInfo::for_uri(
                                        &uri,
                                        base_uri,
                                        rrdp_base
                                    )?;

                                    Ok(Some(DeltaRef {
                                        serial,
                                        file_info
                                    }))
                                },
                                _ => Err(Error::NotificationFileError)
                            }
                        })?;
                        match d {
                            None => break,
                            Some(d) => builder.add_delta(d)
                        }
                    }
                    Ok(())
                }
            })
        }).map_err(|_| Error::NotificationFileError) {
            Ok(_) => Some(builder.build()),
            Err(_) => None
        }
    }

    /// Saves a notification file as RFC8182 XML.
    fn save(&self, path: &PathBuf) -> Result<(), Error> {
        let mut file = file::create_file_with_path(&path)?;

        XmlWriter::encode_to_file(& mut file, |w| {

            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", self.session_id.as_ref()),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element(
                "notification",
                Some(&a),
                |w| {
                    {
                        // snapshot ref
                        let uri = self.snapshot.uri.to_string();
                        let hash = &self.snapshot.hash;
                        let a = [
                            ("uri", uri.as_str()),
                            ("hash", hash)
                        ];
                        w.put_element(
                            "snapshot",
                            Some(&a),
                            |w| { w.empty() }
                        )?;
                    }

                    {
                        // delta refs
                        for delta in &self.deltas {
                            let serial = format!("{}", delta.serial);
                            let uri = delta.uri.to_string();
                            let hash = &delta.hash;
                            let a = [
                                ("serial", serial.as_ref()),
                                ("uri", uri.as_str()),
                                ("hash", hash)
                            ];
                            w.put_element(
                                "delta",
                                Some(&a),
                                |w| { w.empty() }
                            )?;
                        }
                    }

                    Ok(())
                }
            )
        })?;

        Ok(())
    }
}


//------------ SnapshotRef ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct SnapshotRef {
    file_info:  FileInfo
}

impl Deref for SnapshotRef {
    type Target = FileInfo;

    fn deref(&self) -> &FileInfo {
        &self.file_info
    }
}


//------------ DeltaRef ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DeltaRef {
    serial:     usize,
    file_info:  FileInfo,
}

impl DeltaRef {
    pub fn serial(&self) -> &usize {
        &self.serial
    }
}


impl Deref for DeltaRef {
    type Target = FileInfo;

    fn deref(&self) -> &FileInfo {
        &self.file_info
    }
}


//------------ FileInfo ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FileInfo {
    uri:   uri::Http,
    hash:  String,
    size:  usize
}

impl FileInfo {
    fn new(uri: uri::Http, hash: String, size: usize) -> FileInfo {
        FileInfo { uri, hash, size}
    }

    pub fn for_path_and_uri(
        path: &PathBuf,
        uri: uri::Http
    ) -> Result<FileInfo, Error> {
        let bytes = {
            use std::io::Read;

            let mut f = File::open(path)?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            bytes
        };

        let size = bytes.len();

        let hash = {
            use rpki::publication;
            use bytes::Bytes;

            hex::encode(&publication::hash(&Bytes::from(bytes)))
        };

        Ok(FileInfo::new(uri, hash, size))
    }

    pub fn for_uri(
        uri: &uri::Http,
        base_uri: &uri::Http,
        rrdp_base: &PathBuf
    ) -> Result<FileInfo, Error> {
        let base_string = base_uri.to_string();
        let uri_string  = uri.to_string();

        if ! uri_string.as_str().starts_with(base_string.as_str()) {
            Err(Error::NotificationFileError)
        } else {
            let (_, rel) = uri_string.split_at(base_string.len());
            let mut path = rrdp_base.clone();
            path.push(rel);

            FileInfo::for_path_and_uri(&path, uri.clone())
        }
    }

    fn for_path(
        path: &PathBuf,
        base_uri: &uri::Http,
        rrdp_base: &PathBuf
    ) -> Result<FileInfo, Error> {
        let relative = path.strip_prefix(rrdp_base)
            .map_err(|_| Error::UriConfigError)?.to_string_lossy();
        let base_uri = base_uri.to_string();
        let uri = uri::Http::from_string(
            format!("{}{}", base_uri, relative)
        ).map_err(|_| Error::UriConfigError)?;

        FileInfo::for_path_and_uri(path, uri)
    }


}


//------------ NotificationBuilder -------------------------------------------

struct NotificationBuilder {
    serial: Option<usize>,
    session_id: Option<String>,
    snapshot: Option<SnapshotRef>,
    deltas: Vec<DeltaRef>
}

impl NotificationBuilder {
    fn new() -> Self {
        NotificationBuilder {
            serial: None,
            session_id: None,
            snapshot: None,
            deltas: Vec::new()
        }
    }

    fn with_serial(&mut self, serial: usize) {
        self.serial = Some(serial);
    }

    fn with_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    fn with_snapshot(&mut self, snapshot: SnapshotRef) {
        self.snapshot = Some(snapshot);
    }

    fn with_deltas(&mut self, deltas: Vec<DeltaRef>) {
        self.deltas = deltas;
    }

    fn add_delta(&mut self, delta: DeltaRef) {
        self.deltas.push(delta);
    }

    fn add_delta_to_start(&mut self, delta: DeltaRef) {
        self.deltas.insert(0, delta);
    }

    /// Keeps at least two deltas, and beyond that only if the size is
    /// smaller than the snapshot.
    ///
    /// Note we may add something to exclude old deltas later, if we find
    /// that e.g. access to old deltas is very infrequent and excluding
    /// them would shrink the notification file size.
    fn curate_deltas(&mut self) {
        let size_snapshot = match &self.snapshot {
            Some(snapshot) => snapshot.size,
            None => 0
        };
        let mut total_deltas = 0;
        let mut count = 0;

        self.deltas.retain(|d| {
            count = count + 1;
            total_deltas = total_deltas + d.size;
            count <= 2 || total_deltas < size_snapshot
        })

    }


    /// Builds the notification, panics if any of the options are not set.
    /// This can only happen if there is a bug.
    fn build(mut self) -> Notification {
        self.curate_deltas();
        Notification {
            serial: self.serial.unwrap(),
            session_id: self.session_id.unwrap(),
            snapshot: self.snapshot.unwrap(),
            deltas: self.deltas
        }
    }


}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    IoError(io::Error),

    #[fail(display="{}", _0)]
    RecursorError(RecursorError),

    #[fail(display="Issue deriving RRDP URI, check config!")]
    UriConfigError,

    #[fail(display="Error deserializing existing notification.xml")]
    NotificationFileError,

    #[fail(display="{}", _0)]
    XmlReaderErr(XmlReaderErr),

    #[fail(display="{}", _0)]
    AttributesError(AttributesError),

    #[fail(display="{}", _0)]
    UriError(uri::Error),

    #[fail(display="{}", _0)]
    ParseIntError(ParseIntError)
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<RecursorError> for Error {
    fn from(e: RecursorError) -> Self {
        Error::RecursorError(e)
    }
}

impl From<XmlReaderErr> for Error {
    fn from(e: XmlReaderErr) -> Self {
        Error::XmlReaderErr(e)
    }
}

impl From<AttributesError> for Error {
    fn from(e: AttributesError) -> Self {
        Error::AttributesError(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::ParseIntError(e)
    }
}


// Tested through repository.rs
