//! Data objects used in the (RRDP) repository. I.e. the publish, update, and
//! withdraw elements, as well as the notification, snapshot and delta file
//! definitions.
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;

use bytes::Bytes;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::publication;
use crate::commons::api::Base64;
use crate::commons::api::HexEncodedHash;
use crate::commons::util::file;
use crate::commons::util::xml::XmlWriter;

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";

//------------ RrdpSession ---------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RrdpSession(Uuid);

impl Default for RrdpSession {
    fn default() -> Self {
        RrdpSession(Uuid::new_v4())
    }
}

impl RrdpSession {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AsRef<Uuid> for RrdpSession {
    fn as_ref(&self) -> &Uuid {
        &self.0
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

impl fmt::Display for RrdpSession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_hyphenated())
    }
}

//------------ PublishElement ------------------------------------------------

/// The publishes as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    pub fn size(&self) -> usize {
        self.base64.size()
    }

    pub fn as_withdraw(&self) -> WithdrawElement {
        WithdrawElement {
            uri: self.uri.clone(),
            hash: self.base64.to_encoded_hash(),
        }
    }

    pub fn unpack(self) -> (uri::Rsync, Base64) {
        (self.uri, self.base64)
    }
}

impl From<publication::Publish> for PublishElement {
    fn from(p: publication::Publish) -> Self {
        let (_tag, uri, base64) = p.unpack();
        PublishElement { uri, base64 }
    }
}

//------------ UpdateElement -------------------------------------------------

/// The updates as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateElement {
    uri: uri::Rsync,
    hash: HexEncodedHash,
    base64: Base64,
}

impl UpdateElement {
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
    pub fn base64(&self) -> &Base64 {
        &self.base64
    }
    pub fn size(&self) -> usize {
        self.base64.size()
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawElement {
    uri: uri::Rsync,
    hash: HexEncodedHash,
}

impl WithdrawElement {
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
}

impl From<publication::Withdraw> for WithdrawElement {
    fn from(w: publication::Withdraw) -> Self {
        let (_tag, uri, hash) = w.unwrap();
        WithdrawElement { uri, hash }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Notification {
    session: RrdpSession,
    serial: u64,
    time: Time,
    snapshot: SnapshotRef,
    deltas: Vec<DeltaRef>,
    last_delta: Option<u64>,
}

impl Notification {
    pub fn new(
        session: RrdpSession,
        serial: u64,
        snapshot: SnapshotRef,
        deltas: Vec<DeltaRef>,
    ) -> Self {
        let last_delta = Self::find_last_delta(&deltas);
        Notification {
            session,
            serial,
            time: Time::now(),
            snapshot,
            deltas,
            last_delta,
        }
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn session(&self) -> RrdpSession {
        self.session
    }

    pub fn last_delta(&self) -> Option<u64> {
        self.last_delta
    }

    fn find_last_delta(deltas: &[DeltaRef]) -> Option<u64> {
        if deltas.is_empty() {
            None
        } else {
            let mut serial = deltas[0].serial;
            for d in deltas {
                if d.serial < serial {
                    serial = d.serial
                }
            }

            Some(serial)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationUpdate {
    time: Time,
    session: Option<RrdpSession>,
    snapshot: SnapshotRef,
    delta: DeltaRef,
    last_delta: u64,
}

impl NotificationUpdate {
    pub fn new(
        time: Time,
        session: Option<RrdpSession>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationCreate {
    session: RrdpSession,
    snapshot: SnapshotRef,
}

impl NotificationUpdate {
    pub fn unwrap(self) -> (Time, Option<RrdpSession>, SnapshotRef, DeltaRef, u64) {
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
    pub fn update_old_way(&mut self, update: NotificationUpdate) {
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
    }

    pub fn create(session: RrdpSession, snapshot: SnapshotRef) -> Self {
        Notification::new(session, 0, snapshot, vec![])
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<(), io::Error> {
        trace!("Writing notification file: {}", path.to_string_lossy());
        let mut file = file::create_file_with_path(&path)?;

        XmlWriter::encode_to_file(&mut file, |w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", &format!("{}", self.session)),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRef {
    uri: uri::Https,
    path: PathBuf,
    hash: HexEncodedHash,
}

impl FileRef {
    pub fn new(uri: uri::Https, path: PathBuf, hash: HexEncodedHash) -> Self {
        FileRef { uri, path, hash }
    }
    pub fn uri(&self) -> &uri::Https {
        &self.uri
    }
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
}

pub type SnapshotRef = FileRef;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<HexEncodedHash, PublishElement>);

impl Default for CurrentObjects {
    fn default() -> Self {
        CurrentObjects(HashMap::new())
    }
}

impl CurrentObjects {
    pub fn elements(&self) -> Vec<&PublishElement> {
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
pub enum PublicationDeltaError {
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

impl CurrentObjects {
    fn has_match(&self, hash: &HexEncodedHash, uri: &uri::Rsync) -> bool {
        match self.0.get(hash) {
            Some(el) => el.uri() == uri,
            None => false,
        }
    }

    pub fn verify_delta(
        &self,
        delta: &DeltaElements,
        jail: &uri::Rsync,
    ) -> Result<(), PublicationDeltaError> {
        for p in delta.publishes() {
            if !jail.is_parent_of(p.uri()) {
                return Err(PublicationDeltaError::outside(jail, p.uri()));
            }
            let hash = p.base64().to_encoded_hash();
            if self.0.contains_key(&hash) {
                return Err(PublicationDeltaError::present(p.uri()));
            }
        }

        for u in delta.updates() {
            if !self.has_match(u.hash(), u.uri()) {
                return Err(PublicationDeltaError::no_match(u.uri()));
            }
        }

        for w in delta.withdraws() {
            if !self.has_match(w.hash(), w.uri()) {
                return Err(PublicationDeltaError::no_match(w.uri()));
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

    pub fn size(&self) -> usize {
        self.0.values().fold(0, |tot, el| tot + el.size())
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
    session: RrdpSession,
    serial: u64,
    current_objects: CurrentObjects,
}

impl Snapshot {
    pub fn new(session: RrdpSession) -> Self {
        let current_objects = CurrentObjects::default();
        Snapshot {
            session,
            serial: 0,
            current_objects,
        }
    }

    pub fn elements(&self) -> Vec<&PublishElement> {
        self.current_objects.elements()
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn apply_delta(&mut self, delta: Delta) {
        let (session, serial, elements) = delta.unwrap();
        self.session = session;
        self.serial = serial;
        self.current_objects.apply_delta(elements)
    }

    pub fn size(&self) -> usize {
        self.current_objects
            .elements()
            .iter()
            .fold(0, |sum, p| sum + p.size())
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<(), io::Error> {
        trace!("Writing snapshot file: {}", path.to_string_lossy());
        let vec = self.xml();
        let bytes = Bytes::from(vec);

        file::save(&bytes, path)?;

        Ok(())
    }

    pub fn xml(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", &format!("{}", self.session)),
                ("serial", &format!("{}", self.serial)),
            ];

            w.put_element("snapshot", Some(&a), |w| {
                for el in self.current_objects.elements() {
                    let uri = el.uri.to_string();
                    let atr = [("uri", uri.as_ref())];
                    w.put_element("publish", Some(&atr), |w| w.put_text(el.base64.as_ref()))
                        .unwrap();
                }
                Ok(())
            })
        })
    }
}

//------------ DeltaElements -------------------------------------------------

/// Defines the elements for an RRDP delta.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaElements {
    publishes: Vec<PublishElement>,
    updates: Vec<UpdateElement>,
    withdraws: Vec<WithdrawElement>,
}

impl DeltaElements {
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

    pub fn size(&self) -> usize {
        let sum_publishes = self.publishes.iter().fold(0, |sum, p| sum + p.size());
        let sum_updates = self.updates.iter().fold(0, |sum, u| sum + u.size());

        sum_publishes + sum_updates
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

//------------ Delta ---------------------------------------------------------

/// Defines an RRDP delta.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Delta {
    session: RrdpSession,
    serial: u64,
    time: Time,
    elements: DeltaElements,
}

impl Delta {
    pub fn new(session: RrdpSession, serial: u64, elements: DeltaElements) -> Self {
        Delta {
            session,
            time: Time::now(),
            serial,
            elements,
        }
    }

    pub fn session(&self) -> RrdpSession {
        self.session
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

    pub fn unwrap(self) -> (RrdpSession, u64, DeltaElements) {
        (self.session, self.serial, self.elements)
    }

    pub fn write_xml(&self, path: &PathBuf) -> Result<(), io::Error> {
        trace!("Writing delta file: {}", path.to_string_lossy());
        let vec = self.xml();
        let bytes = Bytes::from(vec);
        file::save(&bytes, &path)?;

        Ok(())
    }

    pub fn xml(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("session_id", &format!("{}", self.session)),
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
        })
    }
}
