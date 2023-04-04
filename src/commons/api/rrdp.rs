//! Data objects used in the (RRDP) repository. I.e. the publish, update, and
//! withdraw elements, as well as the notification, snapshot and delta file
//! definitions.
use std::{
    fmt, io,
    ops::{Add, AddAssign},
    path::PathBuf,
    {collections::HashMap, path::Path},
};

use chrono::Duration;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use rpki::{
    ca::publication,
    ca::{idexchange::PublisherHandle, publication::Base64},
    repository::x509::Time,
    rrdp::Hash,
    uri,
    xml::decode::Name,
};

use crate::commons::{error::KrillIoError, util::file};

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";

const SNAPSHOT: Name = Name::unqualified(b"snapshot");
const DELTA: Name = Name::unqualified(b"delta");
const PUBLISH: Name = Name::unqualified(b"publish");
const WITHDRAW: Name = Name::unqualified(b"withdraw");

//------------ RrdpSession ---------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RrdpSession(Uuid);

impl Default for RrdpSession {
    fn default() -> Self {
        RrdpSession(Uuid::new_v4())
    }
}

impl RrdpSession {
    pub fn random() -> Self {
        Self::default()
    }
}

impl AsRef<Uuid> for RrdpSession {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl From<RrdpSession> for Uuid {
    fn from(rrdp_session: RrdpSession) -> Self {
        rrdp_session.0
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
        write!(f, "{}", self.0.hyphenated())
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

    /// Changes the content for this publish, but leaves the uri
    /// unchanged.
    pub fn with_updated_content(&mut self, base64: Base64) {
        self.base64 = base64;
    }

    pub fn size_approx(&self) -> usize {
        self.base64.size_approx()
    }

    pub fn as_withdraw(&self) -> WithdrawElement {
        WithdrawElement {
            uri: self.uri.clone(),
            hash: self.base64.to_hash(),
        }
    }

    pub fn unpack(self) -> (uri::Rsync, Base64) {
        (self.uri, self.base64)
    }

    /// Writes the publish element’s XML.
    fn write_xml(&self, content: &mut rpki::xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
        content
            .element(PUBLISH)?
            .attr("uri", &self.uri)?
            .content(|content| content.raw(self.base64().as_str()))?;
        Ok(())
    }
}

impl From<publication::Publish> for PublishElement {
    fn from(p: publication::Publish) -> Self {
        let (_tag, uri, base64) = p.unpack();
        PublishElement { base64, uri }
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
    hash: Hash,
    base64: Base64,
}

impl UpdateElement {
    pub fn new(uri: uri::Rsync, hash: Hash, base64: Base64) -> Self {
        UpdateElement { uri, hash, base64 }
    }
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    pub fn into_base64(self) -> Base64 {
        self.base64
    }

    pub fn size_approx(&self) -> usize {
        self.base64.size_approx()
    }

    /// Changes this UpdateElement hash to that of the previous
    /// staged update so that it matches the currently published
    /// file in public (i.e. not staged) RRDP.
    pub fn with_updated_hash(&mut self, hash: Hash) {
        self.hash = hash;
    }

    /// Changes the content for this update, but leaves the uri
    /// and hash of object to update unchanged.
    pub fn with_updated_content(&mut self, base64: Base64) {
        self.base64 = base64;
    }

    pub fn into_publish(self) -> PublishElement {
        PublishElement {
            base64: self.base64,
            uri: self.uri,
        }
    }
}

impl From<publication::Update> for UpdateElement {
    fn from(u: publication::Update) -> Self {
        let (_tag, uri, base64, hash) = u.unpack();
        UpdateElement { uri, hash, base64 }
    }
}

impl From<UpdateElement> for PublishElement {
    fn from(el: UpdateElement) -> Self {
        PublishElement {
            uri: el.uri,
            base64: el.base64,
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
    hash: Hash,
}

impl WithdrawElement {
    pub fn new(uri: uri::Rsync, hash: Hash) -> Self {
        WithdrawElement { uri, hash }
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Changes this WithdrawElement hash to that of the previous
    /// staged update so that it matches the currently published
    /// file in public (i.e. not staged) RRDP.
    pub fn updates_staged(&mut self, staged: &UpdateElement) {
        self.hash = staged.hash;
    }
}

impl From<publication::Withdraw> for WithdrawElement {
    fn from(w: publication::Withdraw) -> Self {
        let (_tag, uri, hash) = w.unpack();
        WithdrawElement { uri, hash }
    }
}

//------------ CurrentObjects ------------------------------------------------

/// Defines a current set of published elements.
///
// Note this is mapped internally by hash, rather than uri, because:
//
// PublishedElement maps to the RFC 8182 publish element, and that does
// not contain the hash for the object, just the uri and content. Yet,
// we need to compare hashes for update and delete, so keeping it around
// means that do not need to recalculate it for objects.
//
// Secondly, we could map things by uri, but then we would not only have
// to recalculate that hash.. things would also slow down because the
// hashing for rpki::uri::Rsync is slow due to the fact that it needs
// to accommodate for the fact that the URI scheme and hostname are
// case insensitive.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<Hash, PublishElement>);

impl CurrentObjects {
    pub fn new(map: HashMap<Hash, PublishElement>) -> Self {
        CurrentObjects(map)
    }

    pub fn elements(&self) -> Vec<&PublishElement> {
        let mut res = vec![];
        for el in self.0.values() {
            res.push(el)
        }
        res
    }

    pub fn into_elements(self) -> Vec<PublishElement> {
        self.0.into_values().collect()
    }

    fn has_match(&self, hash: &Hash, uri: &uri::Rsync) -> bool {
        match self.0.get(hash) {
            Some(el) => el.uri() == uri,
            None => false,
        }
    }

    pub fn verify_delta(&self, delta: &DeltaElements, jail: &uri::Rsync) -> Result<(), PublicationDeltaError> {
        for p in delta.publishes() {
            if !jail.is_parent_of(p.uri()) {
                return Err(PublicationDeltaError::outside(jail, p.uri()));
            }
            if self.0.values().any(|existing| existing.uri() == p.uri()) {
                return Err(PublicationDeltaError::present(p.uri()));
            }
        }

        for u in delta.updates() {
            if !jail.is_parent_of(u.uri()) {
                return Err(PublicationDeltaError::outside(jail, u.uri()));
            }
            if !self.has_match(u.hash(), u.uri()) {
                return Err(PublicationDeltaError::no_match(u.uri()));
            }
        }

        for w in delta.withdraws() {
            if !jail.is_parent_of(w.uri()) {
                return Err(PublicationDeltaError::outside(jail, w.uri()));
            }
            if !self.has_match(w.hash(), w.uri()) {
                return Err(PublicationDeltaError::no_match(w.uri()));
            }
        }

        Ok(())
    }

    /// Applies a delta to CurrentObjects.
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unpack();

        for p in publishes {
            let hash = p.base64().to_hash();
            self.0.insert(hash, p);
        }

        for u in updates {
            self.0.remove(u.hash());
            let p: PublishElement = u.into();
            let hash = p.base64().to_hash();
            self.0.insert(hash, p);
        }

        for w in withdraws {
            self.0.remove(w.hash());
        }
    }

    /// Returns a copy of self where elements matching the given URI
    /// are removed if there are any matches. Otherwise, returns None.
    pub fn with_matching_uri_deleted(&self, uri: &uri::Rsync) -> Option<Self> {
        let mut withdraws = vec![];

        // We first loop through the elements to avoid having to clone in case there is no work
        for (hash, el) in &self.0 {
            if el.uri() == uri || (uri.as_str().ends_with('/') && el.uri().as_str().starts_with(uri.as_str())) {
                withdraws.push(hash)
            }
        }

        if withdraws.is_empty() {
            None
        } else {
            let mut copy_of_self = self.clone();
            for hash in withdraws {
                copy_of_self.0.remove(hash);
            }
            Some(copy_of_self)
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn size_approx(&self) -> usize {
        self.0.values().fold(0, |tot, el| tot + el.size_approx())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_list_reply(&self) -> publication::ListReply {
        let elements = self
            .0
            .iter()
            .map(|el| {
                let hash = *el.0;
                let uri = el.1.uri().clone();
                publication::ListElement::new(uri, hash)
            })
            .collect();

        publication::ListReply::new(elements)
    }
}

//------------ PublicationDeltaError ---------------------------------------------

/// Issues with relation to verifying deltas.
#[derive(Clone, Debug)]
pub enum PublicationDeltaError {
    UriOutsideJail(uri::Rsync, uri::Rsync),
    ObjectAlreadyPresent(uri::Rsync),
    NoObjectForHashAndOrUri(uri::Rsync),
}

impl fmt::Display for PublicationDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicationDeltaError::UriOutsideJail(uri, jail) => {
                write!(f, "Publishing ({}) outside of jail URI ({}) is not allowed.", uri, jail)
            }
            PublicationDeltaError::ObjectAlreadyPresent(uri) => {
                write!(f, "File already exists for uri (use update!): {}", uri)
            }
            PublicationDeltaError::NoObjectForHashAndOrUri(uri) => {
                write!(f, "File does not match hash at uri: {}", uri)
            }
        }
    }
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

//------------ RrdpFileRandom ------------------------------------------------
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

//------------ SnapshotData --------------------------------------------------

/// A structure to contain the data needed to create an RRDP Snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotData {
    // The random value will be used to make the snapshot URI unguessable and
    // prevent cache poisoning (through CDN cached 404 not founds).
    random: RrdpFileRandom,

    // We keep objects per publisher so that we can respond to
    // list and publication queries more efficiently.
    current_objects: HashMap<PublisherHandle, CurrentObjects>,
}

impl SnapshotData {
    pub fn new(random: RrdpFileRandom, current_objects: HashMap<PublisherHandle, CurrentObjects>) -> Self {
        SnapshotData {
            random,
            current_objects,
        }
    }

    pub fn create() -> Self {
        let random = RrdpFileRandom::default();
        let current_objects = HashMap::default();
        SnapshotData::new(random, current_objects)
    }

    /// Creates a new snapshot based on this snapshot's objects
    /// but using a new session and resetting the serial.
    pub fn with_new_random(&self) -> Self {
        let random = RrdpFileRandom::default();
        let current_objects = self.current_objects.clone();
        SnapshotData::new(random, current_objects)
    }

    pub fn unpack(self) -> HashMap<PublisherHandle, CurrentObjects> {
        self.current_objects
    }

    // Get the approximate size for all current objects held by all publishers.
    pub fn size_approx(&self) -> usize {
        self.current_objects
            .values()
            .fold(0, |tot, objects| tot + objects.size_approx())
    }

    pub fn current_objects_for(&self, publisher: &PublisherHandle) -> Option<&CurrentObjects> {
        self.current_objects.get(publisher)
    }

    pub fn publishers_current_objects(&self) -> &HashMap<PublisherHandle, CurrentObjects> {
        &self.current_objects
    }

    pub fn set_random(&mut self, random: RrdpFileRandom) {
        self.random = random;
    }

    /// Applies the delta for a publisher to this snapshot.
    ///
    /// This assumes that the delta had been checked before. This should not be
    /// any issue as deltas are verified when they are submitted.
    pub fn apply_delta(&mut self, publisher: &PublisherHandle, delta: DeltaElements) {
        if let Some(objects) = self.current_objects.get_mut(publisher) {
            objects.apply_delta(delta);
            if objects.is_empty() {
                self.current_objects.remove(publisher);
            }
        } else {
            // This is a new publisher without existing objects. So, just create
            // an default -empty- object set for it, so we can apply the delta
            // to it.
            let mut objects = CurrentObjects::default();
            objects.apply_delta(delta);
            self.current_objects.insert(publisher.clone(), objects);
        }
    }

    /// Applies the addition of new publisher with an empty object set.
    ///
    /// This is a no-op in case the publisher already exists.
    pub fn apply_publisher_added(&mut self, publisher: PublisherHandle) {
        self.current_objects
            .entry(publisher)
            .or_insert(CurrentObjects::default());
    }

    /// Applies the removal of a publisher.
    ///
    /// This is a no-op in case the publisher does not exists.
    pub fn apply_publisher_removed(&mut self, publisher: &PublisherHandle) {
        self.current_objects.remove(publisher);
    }

    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/snapshot.xml", session, serial, self.random.0)
    }

    pub fn uri(&self, session: RrdpSession, serial: u64, rrdp_base_uri: &uri::Https) -> uri::Https {
        rrdp_base_uri.join(self.rel_path(session, serial).as_ref()).unwrap()
    }

    pub fn path(&self, session: RrdpSession, serial: u64, base_path: &Path) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    pub fn write_xml(&self, session: RrdpSession, serial: u64, path: &Path) -> Result<(), KrillIoError> {
        debug!("Writing snapshot file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f)
            .map_err(|e| KrillIoError::new(format!("cannot write snapshot xml to: {}", path.to_string_lossy()), e))?;

        debug!("Finished snapshot xml");
        Ok(())
    }

    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Write the snapshot XML.
    ///
    /// Note: we do not use the rpki-rs Snapshot implementation because we would
    /// need to transform and copy quite a lot of data - for big repositories that
    /// is..
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
                for publisher_objects in self.current_objects.values() {
                    for el in publisher_objects.elements() {
                        el.write_xml(content)?;
                    }
                }
                Ok(())
            })?;
        writer.done()
    }
}

//------------ DeltaElements -------------------------------------------------

/// Defines the elements for an RRDP delta.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaElements {
    publishes: Vec<PublishElement>,
    updates: Vec<UpdateElement>,
    withdraws: Vec<WithdrawElement>,
}

impl DeltaElements {
    pub fn new(publishes: Vec<PublishElement>, updates: Vec<UpdateElement>, withdraws: Vec<WithdrawElement>) -> Self {
        DeltaElements {
            publishes,
            updates,
            withdraws,
        }
    }

    pub fn unpack(self) -> (Vec<PublishElement>, Vec<UpdateElement>, Vec<WithdrawElement>) {
        (self.publishes, self.updates, self.withdraws)
    }

    pub fn len(&self) -> usize {
        self.publishes.len() + self.updates.len() + self.withdraws.len()
    }

    pub fn size_approx(&self) -> usize {
        let sum_publishes = self.publishes.iter().fold(0, |sum, p| sum + p.size_approx());
        let sum_updates = self.updates.iter().fold(0, |sum, u| sum + u.size_approx());

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
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        for el in d.into_elements() {
            match el {
                publication::PublishDeltaElement::Publish(p) => publishes.push(p.into()),
                publication::PublishDeltaElement::Update(u) => updates.push(u.into()),
                publication::PublishDeltaElement::Withdraw(w) => withdraws.push(w.into()),
            }
        }

        DeltaElements {
            publishes,
            updates,
            withdraws,
        }
    }
}

impl Add for DeltaElements {
    type Output = DeltaElements;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl AddAssign for DeltaElements {
    fn add_assign(&mut self, mut other: Self) {
        self.publishes.append(&mut other.publishes);
        self.updates.append(&mut other.updates);
        self.withdraws.append(&mut other.withdraws);
    }
}

//------------ DeltaData -----------------------------------------------------

/// Contains the data needed to make an RRDP delta XML file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaData {
    // The random value will be used to make the snapshot URI unguessable and
    // prevent cache poisoning (through CDN cached 404 not founds).
    random: RrdpFileRandom,

    // Session is implied by owning RrdpServer, but deltas have a serial
    serial: u64,

    // Tells us when this delta was created, this is used to determine how long
    // we need to keep it around for.
    time: Time,

    // The actual changes in this delta: publishes/updates/withdrawals
    //
    // Note that we do not need to keep track of the owning publisher in this
    // context. This DeltaData represents a change that has already been applied.
    elements: DeltaElements,
}

impl DeltaData {
    pub fn new(serial: u64, time: Time, random: RrdpFileRandom, elements: DeltaElements) -> Self {
        DeltaData {
            serial,
            random,
            time,
            elements,
        }
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn random(&self) -> &RrdpFileRandom {
        &self.random
    }

    pub fn older_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time < then
    }

    pub fn younger_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time > then
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

    pub fn into_elements(self) -> DeltaElements {
        self.elements
    }

    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/delta.xml", session, serial, self.random.0)
    }

    pub fn uri(&self, session: RrdpSession, serial: u64, rrdp_base_uri: &uri::Https) -> uri::Https {
        rrdp_base_uri.join(self.rel_path(session, serial).as_ref()).unwrap()
    }

    pub fn path(&self, session: RrdpSession, serial: u64, base_path: &Path) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    pub fn write_xml(&self, session: RrdpSession, serial: u64, path: &Path) -> Result<(), KrillIoError> {
        debug!("Writing delta file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f)
            .map_err(|e| KrillIoError::new(format!("cannot write delta xml to: {}", path.to_string_lossy()), e))?;

        debug!("Done creating XML");
        Ok(())
    }

    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Write the delta XML.
    ///
    /// Note: we do not use the rpki-rs Delta implementation because we potentially would
    /// need to transform and copy quite a lot of data.
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
                        .attr("uri", el.uri())?
                        .content(|content| content.raw(el.base64().as_str()))?;
                }
                for el in self.elements().updates() {
                    content
                        .element(PUBLISH.into_unqualified())?
                        .attr("uri", el.uri())?
                        .attr("hash", el.hash())?
                        .content(|content| content.raw(el.base64().as_str()))?;
                }
                for el in self.elements().withdraws() {
                    content
                        .element(WITHDRAW.into_unqualified())?
                        .attr("uri", el.uri())?
                        .attr("hash", el.hash())?;
                }
                Ok(())
            })?;

        writer.done()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test::*;

    #[test]
    fn current_objects_delta() {
        let jail = rsync("rsync://example.krill.cloud/repo/publisher");
        let file1_uri = rsync("rsync://example.krill.cloud/repo/publisher/file1.txt");

        let file1_content = Base64::from_content(&[1]);
        let file1_content_2 = Base64::from_content(&[1, 2]);
        let file2_content = Base64::from_content(&[2]);

        let mut objects = CurrentObjects::default();

        let publish_file1 = DeltaElements {
            publishes: vec![PublishElement::new(file1_content.clone(), file1_uri.clone())],
            updates: vec![],
            withdraws: vec![],
        };

        // adding a file to an empty current objects is okay
        assert!(objects.verify_delta(&publish_file1, &jail).is_ok());

        // The actual application of the delta is infallible, because event replays
        // may not fail. It is assumed deltas were verified before they were persisted
        // in events.
        objects.apply_delta(publish_file1.clone());

        // Now adding the same file for the same URI and same hash, as a publish will fail.
        assert!(objects.verify_delta(&publish_file1, &jail).is_err());

        // Adding a different file as a publish element, rather than update,
        // for the same URI will also fail. Checks fix for issue #981.
        let publish_file2 = DeltaElements {
            publishes: vec![PublishElement::new(file2_content, file1_uri.clone())],
            updates: vec![],
            withdraws: vec![],
        };
        assert!(objects.verify_delta(&publish_file2, &jail).is_err());

        // Updates

        // Updating a file should work
        let update_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![UpdateElement::new(
                file1_uri.clone(),
                file1_content.to_hash(),
                file1_content_2.clone(),
            )],
            withdraws: vec![],
        };
        assert!(objects.verify_delta(&update_file1, &jail).is_ok());
        objects.apply_delta(update_file1.clone());

        // Updating again with the same delta will now fail - there is no longer and object
        // with that uri and hash it was updated to the new content.
        assert!(objects.verify_delta(&update_file1, &jail).is_err());

        // Withdraws

        // Withdrawing file with wrong hash should fail
        let withdraw_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement::new(file1_uri.clone(), file1_content.to_hash())],
        };
        assert!(objects.verify_delta(&withdraw_file1, &jail).is_err());

        // Withdrawing file with the right hash should work
        let withdraw_file1_updated = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement::new(file1_uri, file1_content_2.to_hash())],
        };
        assert!(objects.verify_delta(&withdraw_file1_updated, &jail).is_ok());
    }
}
