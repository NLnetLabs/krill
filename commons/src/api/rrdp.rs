//! Data objects used in the (RRDP) repository. I.e. the publish, update, and
//! withdraw elements, as well as the notification, snapshot and delta file
//! definitions.
use crate::api::publication;
use crate::api::Base64;
use crate::api::EncodedHash;
use crate::util::file;
use crate::util::xml::XmlWriter;
use crate::util::Time;
use bytes::Bytes;
use rpki::uri;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";

//------------ PublishElement ------------------------------------------------

/// The publishes as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishElement {
    base64: Base64,
    uri: uri::Rsync,
}

impl PublishElement {
    pub fn new(base64: Base64, uri: uri::Rsync) -> Self {
        PublishElement { base64, uri }
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
}

impl From<publication::Publish> for PublishElement {
    fn from(p: publication::Publish) -> Self {
        let (_tag, uri, base64) = p.unwrap();
        PublishElement { uri, base64 }
    }
}

//------------ UpdateElement -------------------------------------------------

/// The updates as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateElement {
    uri: uri::Rsync,
    hash: EncodedHash,
    base64: Base64,
}

impl UpdateElement {
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &EncodedHash {
        &self.hash
    }
    pub fn base64(&self) -> &Base64 {
        &self.base64
    }
}

impl From<publication::Update> for UpdateElement {
    fn from(u: publication::Update) -> Self {
        let (_tag, uri, base64, hash) = u.unwrap();
        UpdateElement { uri, base64, hash }
    }
}

impl Into<PublishElement> for UpdateElement {
    fn into(self) -> PublishElement {
        PublishElement {
            uri: self.uri,
            base64: self.base64,
        }
    }
}

//------------ WithdrawElement -----------------------------------------------

/// The withdraws as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawElement {
    uri: uri::Rsync,
    hash: EncodedHash,
}

impl WithdrawElement {
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &EncodedHash {
        &self.hash
    }
}

impl From<publication::Withdraw> for WithdrawElement {
    fn from(w: publication::Withdraw) -> Self {
        let (_tag, uri, hash) = w.unwrap();
        WithdrawElement { uri, hash }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Notification {
    session: String,
    serial: u64,
    time: Time,
    snapshot: SnapshotRef,
    deltas: Vec<DeltaRef>,
    old_refs: Vec<(Time, FileRef)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationUpdate {
    time: Time,
    session: Option<String>,
    snapshot: SnapshotRef,
    delta: DeltaRef,
    last_delta: u64,
}

impl NotificationUpdate {
    pub fn new(
        time: Time,
        session: Option<String>,
        snapshot: SnapshotRef,
        delta: DeltaRef,
        last_delta: u64,
    ) -> Self {
        NotificationUpdate {
            time,
            session,
            snapshot,
            delta,
            last_delta,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationCreate {
    session: String,
    snapshot: SnapshotRef,
}

impl NotificationUpdate {
    pub fn unwrap(self) -> (Time, Option<String>, SnapshotRef, DeltaRef, u64) {
        (
            self.time,
            self.session,
            self.snapshot,
            self.delta,
            self.last_delta,
        )
    }
}

impl Notification {
    pub fn old_refs(&self) -> &Vec<(Time, FileRef)> {
        &self.old_refs
    }

    pub fn update(&mut self, update: NotificationUpdate) {
        let (time, session_opt, snapshot, delta, last_delta) = update.unwrap();
        if let Some(session) = session_opt {
            self.session = session;
        }

        self.serial += 1;
        self.time = time;

        let mut refs_to_retire = vec![];

        refs_to_retire.push((Time::now(), self.snapshot.clone()));
        self.snapshot = snapshot;

        for d in &self.deltas {
            if d.serial < last_delta {
                refs_to_retire.push((Time::now(), d.file_ref.clone()));
            }
        }

        self.deltas.insert(0, delta);
        self.deltas.retain(|delta| delta.serial >= last_delta);
        self.old_refs.append(&mut refs_to_retire);
    }

    /// Cleans up all old references from before the given time.
    pub fn clean_up(&mut self, t: Time) {
        self.old_refs.retain(|old_ref| !old_ref.0.on_or_before(&t))
    }

    pub fn create(session: String, snapshot: SnapshotRef) -> Self {
        Notification {
            session,
            serial: 0,
            time: Time::now(),
            snapshot,
            deltas: vec![],
            old_refs: vec![],
        }
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<(), io::Error> {
        debug!("Writing notification file: {}", path.to_string_lossy());
        let mut file = file::create_file_with_path(&path)?;

        XmlWriter::encode_to_file(&mut file, |w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", self.session.as_ref()),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element("notification", Some(&a), |w| {
                {
                    // snapshot ref
                    let uri = self.snapshot.uri.to_string();
                    let a = [("uri", uri.as_str()), ("hash", self.snapshot.hash.as_ref())];
                    w.put_element("snapshot", Some(&a), |w| w.empty())?;
                }

                {
                    // delta refs
                    for delta in &self.deltas {
                        let serial = format!("{}", delta.serial);
                        let uri = delta.file_ref.uri.to_string();
                        let a = [
                            ("serial", serial.as_ref()),
                            ("uri", uri.as_str()),
                            ("hash", delta.file_ref.hash.as_ref()),
                        ];
                        w.put_element("delta", Some(&a), |w| w.empty())?;
                    }
                }

                Ok(())
            })
        })?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileRef {
    uri: uri::Https,
    path: PathBuf,
    hash: EncodedHash,
}

impl FileRef {
    pub fn new(uri: uri::Https, path: PathBuf, hash: EncodedHash) -> Self {
        FileRef { uri, path, hash }
    }
    pub fn uri(&self) -> &uri::Https {
        &self.uri
    }
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    pub fn hash(&self) -> &EncodedHash {
        &self.hash
    }
}

pub type SnapshotRef = FileRef;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeltaRef {
    serial: u64,
    file_ref: FileRef,
}

impl DeltaRef {
    pub fn new(serial: u64, file_ref: FileRef) -> Self {
        DeltaRef { serial, file_ref }
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }
}

impl AsRef<FileRef> for DeltaRef {
    fn as_ref(&self) -> &FileRef {
        &self.file_ref
    }
}

//------------ CurrentObjects ------------------------------------------------

/// Defines a current set of published elements.
///
// Note this is mapped internally for speedy access, by hash, rather than uri
// for two reasons:
// a) URIs in RPKI may change in future
// b) The publish element as it appears in an RFC8182 snapshot.xml includes
// the uri and the base64, but not the hash. So keeping the actual elements
// around means we can be more efficient in producing that output.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentObjects(HashMap<EncodedHash, PublishElement>);

impl Default for CurrentObjects {
    fn default() -> Self {
        CurrentObjects(HashMap::new())
    }
}

impl CurrentObjects {
    fn elements(&self) -> Vec<&PublishElement> {
        let mut res = vec![];
        for el in self.0.values() {
            res.push(el)
        }
        res
    }
}

//------------ VerificationError ---------------------------------------------

/// Issues with relation to verifying deltas.
#[derive(Clone, Debug, Display)]
pub enum VerificationError {
    #[display(
        fmt = "Publishing ({}) outside of jail URI ({}) is not allowed.",
        _0,
        _1
    )]
    UriOutsideJail(uri::Rsync, uri::Rsync),

    #[display(fmt = "File already exists for uri (use update!): {}", _0)]
    ObjectAlreadyPresent(uri::Rsync),

    #[display(fmt = "File does not match hash at uri: {}", _0)]
    NoObjectForHashAndOrUri(uri::Rsync),
}

impl VerificationError {
    fn outside(jail: &uri::Rsync, uri: &uri::Rsync) -> Self {
        VerificationError::UriOutsideJail(uri.clone(), jail.clone())
    }

    fn present(uri: &uri::Rsync) -> Self {
        VerificationError::ObjectAlreadyPresent(uri.clone())
    }

    fn no_match(uri: &uri::Rsync) -> Self {
        VerificationError::NoObjectForHashAndOrUri(uri.clone())
    }
}

impl CurrentObjects {
    fn has_match(&self, hash: &EncodedHash, uri: &uri::Rsync) -> bool {
        match self.0.get(hash) {
            Some(el) => el.uri() == uri,
            None => false,
        }
    }

    pub fn verify_delta(
        &self,
        delta: &DeltaElements,
        jail: &uri::Rsync,
    ) -> Result<(), VerificationError> {
        for p in delta.publishes() {
            if !jail.is_parent_of(p.uri()) {
                return Err(VerificationError::outside(jail, p.uri()));
            }
            let hash = p.base64().to_encoded_hash();
            if self.0.contains_key(&hash) {
                return Err(VerificationError::present(p.uri()));
            }
        }

        for u in delta.updates() {
            if !self.has_match(u.hash(), u.uri()) {
                return Err(VerificationError::no_match(u.uri()));
            }
        }

        for w in delta.withdraws() {
            if !self.has_match(w.hash(), w.uri()) {
                return Err(VerificationError::no_match(w.uri()));
            }
        }

        Ok(())
    }

    /// Applies a delta to CurrentObjects. This will asume that the delta
    /// contains only valid updates for this delta.
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unwrap();

        for p in publishes {
            let hash = p.base64().to_encoded_hash();
            self.0.insert(hash, p);
        }

        for u in updates {
            self.0.remove(u.hash());
            let p: PublishElement = u.into();
            let hash = p.base64().to_encoded_hash();
            self.0.insert(hash, p);
        }

        for w in withdraws {
            self.0.remove(w.hash());
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_list_reply(&self) -> publication::ListReply {
        let elements = self
            .0
            .iter()
            .map(|el| {
                let hash = el.0.clone();
                let uri = el.1.uri().clone();
                publication::ListElement::new(uri, hash)
            })
            .collect();

        publication::ListReply::new(elements)
    }
}

//------------ Snapshot ------------------------------------------------------

/// A structure to contain the RRDP snapshot data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    session: String,
    serial: u64,
    current_objects: CurrentObjects,
}

impl Snapshot {
    pub fn new(session: String) -> Self {
        let current_objects = CurrentObjects::default();
        Snapshot {
            session,
            serial: 0,
            current_objects,
        }
    }

    pub fn apply_delta(&mut self, delta: Delta) {
        let (session, serial, elements) = delta.unwrap();
        self.session = session;
        self.serial = serial;
        self.current_objects.apply_delta(elements)
    }

    pub fn len(&self) -> usize {
        self.current_objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current_objects.is_empty()
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<EncodedHash, io::Error> {
        let vec = XmlWriter::encode_vec(|w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", self.session.as_ref()),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element("snapshot", Some(&a), |w| {
                for el in self.current_objects.elements() {
                    let uri = el.uri.to_string();
                    let atr = [("uri", uri.as_ref())];
                    w.put_element("publish", Some(&atr), |w| w.put_text(el.base64.as_ref()))?;
                }
                Ok(())
            })
        });
        let bytes = Bytes::from(vec);

        file::save(&bytes, path)?;
        let hash = EncodedHash::from_content(&bytes);

        Ok(hash)
    }
}

//------------ DeltaElements -------------------------------------------------

/// Defines the elements for an RRDP delta.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeltaElements {
    publishes: Vec<PublishElement>,
    updates: Vec<UpdateElement>,
    withdraws: Vec<WithdrawElement>,
}

impl From<publication::PublishDelta> for DeltaElements {
    fn from(d: publication::PublishDelta) -> Self {
        let (pbls, upds, wdrs) = d.unwrap();

        let publishes = pbls.into_iter().map(PublishElement::from).collect();
        let updates = upds.into_iter().map(UpdateElement::from).collect();
        let withdraws = wdrs.into_iter().map(WithdrawElement::from).collect();

        DeltaElements {
            publishes,
            updates,
            withdraws,
        }
    }
}

impl DeltaElements {
    pub fn unwrap(
        self,
    ) -> (
        Vec<PublishElement>,
        Vec<UpdateElement>,
        Vec<WithdrawElement>,
    ) {
        (self.publishes, self.updates, self.withdraws)
    }

    pub fn len(&self) -> usize {
        self.publishes.len() + self.updates.len() + self.withdraws.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn publishes(&self) -> &Vec<PublishElement> {
        &self.publishes
    }

    pub fn updates(&self) -> &Vec<UpdateElement> {
        &self.updates
    }

    pub fn withdraws(&self) -> &Vec<WithdrawElement> {
        &self.withdraws
    }
}

//------------ Delta ---------------------------------------------------------

/// Defines an RRDP delta.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Delta {
    session: String,
    serial: u64,
    time: Time,
    elements: DeltaElements,
}

impl Delta {
    pub fn new(session: String, serial: u64, elements: DeltaElements) -> Self {
        Delta {
            session,
            time: Time::now(),
            serial,
            elements,
        }
    }

    pub fn session(&self) -> &str {
        &self.session
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn time(&self) -> &Time {
        &self.time
    }
    pub fn elements(&self) -> &DeltaElements {
        &self.elements
    }

    /// Total number of elements
    ///
    /// This is a cheap approximation of the size of the delta that can help
    /// in determining the choice of how many deltas to include in a
    /// notification file.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn unwrap(self) -> (String, u64, DeltaElements) {
        (self.session, self.serial, self.elements)
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<EncodedHash, io::Error> {
        let vec = XmlWriter::encode_vec(|w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", self.session.as_ref()),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element("delta", Some(&a), |w| {
                for el in &self.elements.publishes {
                    let uri = el.uri.to_string();
                    let atr = [("uri", uri.as_ref())];
                    w.put_element("publish", Some(&atr), |w| w.put_text(el.base64.as_ref()))?;
                }

                for el in &self.elements.updates {
                    let uri = el.uri.to_string();
                    let atr = [("uri", uri.as_ref()), ("hash", el.hash.as_ref())];
                    w.put_element("publish", Some(&atr), |w| w.put_text(el.base64.as_ref()))?;
                }

                for el in &self.elements.withdraws {
                    let uri = el.uri.to_string();
                    let atr = [("uri", uri.as_ref()), ("hash", el.hash.as_ref())];
                    w.put_element("withdraw", Some(&atr), |w| w.empty())?;
                }

                Ok(())
            })
        });

        let bytes = Bytes::from(vec);
        file::save(&bytes, &path)?;
        let hash = EncodedHash::from_content(&bytes);

        Ok(hash)
    }
}
