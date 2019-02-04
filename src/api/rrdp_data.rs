use std::collections::HashMap;
use std::io;
use std::fs::File;
use std::num::ParseIntError;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use bytes::Bytes;
use rpki::uri;
use crate::util::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};
use crate::util::file::{self, RecursorError};
use crate::util::ext_serde;
use util::sha256;

const VERSION: &'static str = "1";
const NS: &'static str = "http://www.ripe.net/rpki/rrdp";

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct PublishedObject {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    uri: uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    content: Bytes,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    hash: Bytes
}

impl PublishedObject {
    pub fn new(uri: uri::Rsync, content: Bytes) -> Self {
        let hash = sha256(&content);
        PublishedObject { uri , content, hash }
    }

    pub fn uri(&self) -> &uri::Rsync{ &self.uri }
    pub fn content(&self) -> &Bytes { &self.content }
    pub fn hash(&self) -> &Bytes { &self.hash }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    session: String,
    serial: usize,
    objects: HashMap<String, Vec<PublishedObject>>
}

impl Snapshot {
    pub fn new(
        session: String,
        serial: usize,
        objects: HashMap<String, Vec<PublishedObject>>
    ) -> Self {
        Snapshot { session, serial, objects }
    }

    pub fn objects(&self) -> &HashMap<String, Vec<PublishedObject>> {
        &self.objects
    }

    pub fn to_xml(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", self.session.as_ref()),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element(
                "snapshot",
                Some(&a),
                |w| {
                    for uri in self.objects.keys() {
                        let objects = self.objects.get(uri).unwrap();
                        for cf in objects {
                            let uri = cf.uri.to_string();
                            let a = [ ("uri", uri.as_ref()) ];
                            w.put_element(
                                "publish",
                                Some(&a),
                                |w| {
                                    w.put_blob(&cf.content)
                                }
                            )?;
                        }
                    }
                    Ok(())
                }
            )
        })
    }
}



//------------ Notification --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Notification {
    session_id: String,
    serial:     usize,
    snapshot:   SnapshotRef,
    deltas:     Vec<DeltaRef>
}

/// # Accessors
///
impl Notification {
    pub fn serial(&self) -> usize {
        self.serial
    }
    pub fn session_id(&self) -> &String { &self.session_id }

    pub fn deltas(&self) -> &Vec<DeltaRef> {
        &self.deltas
    }
}

/// # Load and save
///
impl Notification {

    /// Build up the current notification based on what's on disk.
    /// Note that this will return None, if there is nothing on disk.
    ///
    /// Also note that in future we may want to cache things for
    /// efficiency (but make it work with multi master).
    pub fn build(
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
    pub fn save(&self, path: &PathBuf) -> Result<(), Error> {
        debug!("Writing notification file: {}", path.to_string_lossy());
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnapshotRef {
    file_info:  FileInfo
}

impl SnapshotRef {
    pub fn new(file_info: FileInfo) -> Self {
        SnapshotRef { file_info }
    }
}

impl Deref for SnapshotRef {
    type Target = FileInfo;

    fn deref(&self) -> &FileInfo {
        &self.file_info
    }
}


//------------ DeltaRef ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeltaRef {
    serial:     usize,
    file_info:  FileInfo,
}

impl DeltaRef {
    pub fn new(serial: usize, file_info: FileInfo) -> Self {
        DeltaRef { serial, file_info }
    }
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileInfo {
    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
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
            use crate::util::sha256;
            use bytes::Bytes;

            hex::encode(&sha256(&Bytes::from(bytes)))
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

    pub fn for_path(
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

pub struct NotificationBuilder {
    serial: Option<usize>,
    session_id: Option<String>,
    snapshot: Option<SnapshotRef>,
    deltas: Vec<DeltaRef>
}

impl NotificationBuilder {
    pub fn new() -> Self {
        NotificationBuilder {
            serial: None,
            session_id: None,
            snapshot: None,
            deltas: Vec::new()
        }
    }

    pub fn with_serial(&mut self, serial: usize) {
        self.serial = Some(serial);
    }

    pub fn with_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    pub fn with_snapshot(&mut self, snapshot: SnapshotRef) {
        self.snapshot = Some(snapshot);
    }

    pub fn with_deltas(&mut self, deltas: Vec<DeltaRef>) {
        self.deltas = deltas;
    }

    pub fn add_delta(&mut self, delta: DeltaRef) {
        self.deltas.push(delta);
    }

    pub fn add_delta_to_start(&mut self, delta: DeltaRef) {
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
    pub fn build(mut self) -> Notification {
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

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    RecursorError(RecursorError),

    #[display(fmt="{}", _0)]
    UriError(uri::Error),

    #[display(fmt="{}", _0)]
    XmlReaderErr(XmlReaderErr),

    #[display(fmt="{}", _0)]
    AttributesError(AttributesError),

    #[display(fmt="{}", _0)]
    ParseIntError(ParseIntError),

    #[display(fmt="Error with notification file.")]
    NotificationFileError,

    #[display(fmt="Error with uri config.")]
    UriConfigError
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

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self { Error::UriError(e) }
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

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self { Error::ParseIntError(e) }
}