use std::fs;
use std::fs::File;
use std::io;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use file;
use file::RecursorError;
use repo::file_store::FS_FOLDER;
use rpki::publication::query::PublishQuery;
use rpki::remote::xml::XmlReader;
use rpki::remote::xml::XmlWriter;
use rpki::publication::query::PublishElement;
use rpki::uri;
use rpki::remote::xml::XmlReaderErr;
use rpki::remote::xml::AttributesError;
use std::num::ParseIntError;

const VERSION: &'static str = "1";
const NS: &'static str = "http://www.ripe.net/rpki/rrdp";
const RRDP_FOLDER: &'static str = "rrdp";


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

/// # Accessors
///
impl RrdpServer {

}

/// # Publishing
///
impl RrdpServer {

    /// Process an update PublishQuery and produce a new delta, snapshot
    /// and notification file. Assumes that this is called *after* the
    /// ['FileStore'] has published, so files should already be saved to
    /// disk and the snapshots can be derived from this.
    pub fn publish(&mut self, update: &PublishQuery) -> Result<(), Error> {
        Ok(())
    }


    /// Reconstructs a Notification file by deserializing the saved
    /// 'notification.xml' file, and scanning the references for their sizes.
    /// Returns None if no notification file is found, or in case there is
    /// any issue wi
    fn derive_notification(&self) -> Option<Notification> {
        let path = self.notification_path();

        let mut builder = NotificationBuilder::new();

        match XmlReader::open(path, |r| -> Result<(), Error> {
            r.take_named_element("notification", |mut a, r| {
                {
                    // process attributes
                    builder.with_session_id(a.take_req("session_id")?);
                    let serial = usize::from_str(a.take_req("serial")?.as_ref())?;
                    builder.with_serial(serial);
                    a.exhausted()?;
                }

                {
                    // expect snapshot ref
                    r.take_named_element(
                        "snapshot",
                        |mut a,r| -> Result<(), Error> {
                            let uri = uri::Http::from_string(a.take_req("uri")?)?;
                            let file_info = self.file_info_for_uri(&uri)?;

                            builder.with_snapshot(
                                SnapshotRef { file_info }
                            );
                            Ok(())
                    })?;
                }

                {
                    // deltas
                    loop {
                        let d = r.take_opt_element(|t, mut a, r| {
                            match t.name.as_ref() {
                                "delta" => {
                                    let uri = uri::Http::from_string(
                                        a.take_req("uri")?
                                    )?;
                                    let serial = usize::from_str(
                                        a.take_req("serial")?.as_ref()
                                    )?;
                                    let info = self.file_info_for_uri(&uri)?;

                                    Ok(Some(DeltaRef {
                                        serial,
                                        file_info: info
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
            Ok(_)  => Some(builder.build()),
            Err(_) => None
        }
    }



    /// Saves a notification file as RFC8182 XML.
    fn save_notification(
        &mut self,
        notification: &Notification
    ) -> Result<(), Error> {
        let path = self.notification_path();
        let mut file = file::create_file_with_path(&path)?;

        XmlWriter::encode_to_file(& mut file, |w| {

            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", notification.session_id.as_ref()),
                ("serial", &format!("{}", notification.serial)),
            ];

            w.put_element(
                "notification",
                Some(&a),
                |w| {
                    {
                        // snapshot ref
                        let uri = notification.snapshot.uri.to_string();
                        let hash = &notification.snapshot.hash;
                        let a = [
                            ("uri", uri.as_str()),
                            ("hash", hash)
                        ];
                        w.put_element(
                            "snapshot",
                            Some(&a),
                            |w| { w.empty() }
                        );
                    }

                    {
                        // delta refs
                        for delta in &notification.deltas {
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
                            );
                        }
                    }

                    Ok(())
                }
            )
        })?;

        Ok(())
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

        let file_info = self.file_info_for_path(&path)?;
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

        let file_info = self.file_info_for_path(&path)?;
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

    fn file_info_for_uri(&self, uri: &uri::Http) -> Result<FileInfo, Error> {
        let base_string = self.base_uri.to_string();
        let uri_string  = uri.to_string();

        if ! uri_string.as_str().starts_with(base_string.as_str()) {
            Err(Error::NotificationFileError)
        } else {
            let (_, rel) = uri_string.split_at(base_string.len());
            let mut path = self.rrdp_base.clone();
            path.push(rel);

            self.file_info(&path, uri.clone())
        }
    }

    fn file_info_for_path(&self, path: &PathBuf) -> Result<FileInfo, Error> {
        let relative = path.strip_prefix(&self.rrdp_base)
            .map_err(|_| Error::UriConfigError)?.to_string_lossy();
        let base_uri = self.base_uri.to_string();
        let uri = uri::Http::from_string(
            format!("{}{}", base_uri, relative)
        ).map_err(|_| Error::UriConfigError)?;

        self.file_info(path, uri)
    }

    fn file_info(
        &self,
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


}


//------------ Notification --------------------------------------------------

#[derive(Clone, Debug)]
struct Notification {
    session_id: String,
    serial:     usize,
    snapshot:   SnapshotRef,
    deltas:     Vec<DeltaRef>
}

#[derive(Clone, Debug)]
struct SnapshotRef {
    file_info:  FileInfo
}

impl Deref for SnapshotRef {
    type Target = FileInfo;

    fn deref(&self) -> &FileInfo {
        &self.file_info
    }
}

#[derive(Clone, Debug)]
struct DeltaRef {
    serial:     usize,
    file_info:  FileInfo,
}

impl Deref for DeltaRef {
    type Target = FileInfo;

    fn deref(&self) -> &FileInfo {
        &self.file_info
    }
}


#[derive(Clone, Debug)]
struct FileInfo {
    uri:   uri::Http,
    hash:  String,
    size:  usize
}

impl FileInfo {
    fn new(uri: uri::Http, hash: String, size: usize) -> FileInfo {
        FileInfo { uri, hash, size}
    }
}


impl Notification {
    /// Creates a new notification file, with a random session_id, starting
    /// with version 1. Needs a snapshot ref, but the actual snapshot may of
    /// course be empty.
    pub fn new(snapshot: SnapshotRef, deltas: Vec<DeltaRef>) -> Self {
        let session_id = {
            use rand::{thread_rng, Rng};
            let mut rng = thread_rng();
            let rnd: u32 = rng.gen();
            format!("{}", rnd)
        };
        let serial = 1;

        Notification {
            session_id, serial, snapshot, deltas
        }
    }



    fn encode<W: io::Write>(
        &self,
        target: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        Ok(())
    }
}


//------------ Error ---------------------------------------------------------

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

    fn add_delta(&mut self, delta: DeltaRef) {
        self.deltas.push(delta);
    }

    /// Builds the notification, panics if any of the options are not set.
    /// This can only happen if there is a bug.
    fn build(self) -> Notification {
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



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test;
    use bytes::Bytes;
    use file::CurrentFile;

    #[test]
    fn should_make_snapshot() {
        let uri = test::http_uri("http://localhost:3000/rrdp/");
        test::test_with_tmp_dir(|d| {
            let mut rrdps = RrdpServer::new(&uri, &d).unwrap();
            let session_id = "session".to_string();
            let serial = 1;
            let _info = rrdps.save_snapshot(&session_id, serial).unwrap();
        })
    }

}
