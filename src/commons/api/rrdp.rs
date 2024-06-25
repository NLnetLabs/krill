//! Data objects used in the (RRDP) repository. I.e. the publish, update, and
//! withdraw elements, as well as the notification, snapshot and delta file
//! definitions.
use std::{
    fmt, io,
    ops::{Add, AddAssign, Deref},
    path::PathBuf,
    sync::Arc,
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

use crate::commons::{
    error::{Error, KrillIoError},
    util::file,
    KrillResult,
};

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

    pub fn unpack(self) -> (uri::Rsync, Base64) {
        (self.uri, self.base64)
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

    pub fn unpack(self) -> (uri::Rsync, Hash, Base64) {
        (self.uri, self.hash, self.base64)
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn hash(&self) -> Hash {
        self.hash
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
    pub fn hash(&self) -> Hash {
        self.hash
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

//------------ CurrentObjectKey ----------------------------------------------

/// Maps to the URI for the object.
///
/// We use this separate type rather than rpki::uri::Rsync because the
/// latter is not very suitable for use in HashMaps: it is mutable and
/// its hash function is slow due to the fact that it needs
/// to accommodate for the fact that the URI scheme and hostname are
/// case insensitive.
///
/// We use an inner Arc<str> so that we can clone this cheaply. We provide
/// no way to create this type other than by providing a valid uri::Rsync.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CurrentObjectUri(Arc<str>);

impl CurrentObjectUri {
    pub fn as_str(&self) -> &str {
        self.as_ref()
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

impl From<&uri::Rsync> for CurrentObjectUri {
    fn from(value: &uri::Rsync) -> Self {
        // use canonical scheme and hostname (converts to lowercase if needed)
        let s = format!("{}{}", value.canonical_module(), value.path());
        CurrentObjectUri(s.into())
    }
}

impl Deref for CurrentObjectUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for CurrentObjectUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Defines a current set of published elements.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<CurrentObjectUri, Base64>);

impl CurrentObjects {
    pub fn new(map: HashMap<CurrentObjectUri, Base64>) -> Self {
        CurrentObjects(map)
    }

    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0)
    }

    /// Returns the DeltaElements needed to turn this into other.
    pub fn diff(&self, other: &Self) -> KrillResult<DeltaElements> {
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        // find new and updated stuff
        for (uri_key, base64) in &other.0 {
            let uri = uri_key.try_into()?;
            match self.0.get(uri_key) {
                None => {
                    let pbl = PublishElement::new(base64.clone(), uri);
                    publishes.push(pbl);
                }
                Some(existing_b64) => {
                    if base64 != existing_b64 {
                        let hash = existing_b64.to_hash();
                        let upd =
                            UpdateElement::new(uri, hash, base64.clone());
                        updates.push(upd);
                    }
                }
            }
        }

        // find removed stuff
        for (uri_key, base64) in &self.0 {
            let uri = uri_key.try_into()?;
            if !other.0.contains_key(uri_key) {
                let hash = base64.to_hash();
                let wdr = WithdrawElement::new(uri, hash);
                withdraws.push(wdr);
            }
        }

        Ok(DeltaElements::new(publishes, updates, withdraws))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&CurrentObjectUri, &Base64)> {
        self.0.iter()
    }

    pub fn try_into_publish_elements(
        self,
    ) -> KrillResult<Vec<PublishElement>> {
        let mut elements = vec![];

        for (uri_key, base64) in self.0.into_iter() {
            let uri = uri_key.try_into()?;
            let el = PublishElement::new(base64, uri);
            elements.push(el);
        }

        Ok(elements)
    }

    pub fn to_withdraw_elements(&self) -> KrillResult<Vec<WithdrawElement>> {
        let mut elements = vec![];

        for (uri_key, base64) in self.0.iter() {
            let uri = uri_key.try_into()?;
            let hash = base64.to_hash();
            let el = WithdrawElement::new(uri, hash);
            elements.push(el);
        }

        Ok(elements)
    }

    fn has_match(&self, hash: Hash, uri: &uri::Rsync) -> bool {
        let key = CurrentObjectUri::from(uri);
        match self.0.get(&key) {
            Some(base64) => base64.to_hash() == hash,
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
            let key = CurrentObjectUri::from(p.uri());
            if self.0.contains_key(&key) {
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
    ///
    /// Assumes that the delta was checked using [`verify_delta`].
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unpack();

        for p in publishes {
            let (uri, base64) = p.unpack();
            let key = CurrentObjectUri::from(&uri);
            self.0.insert(key, base64);
        }

        for u in updates {
            // we ignore the hash of the old object when inserting
            // the update, as it has already been verified.
            let (uri, _hash, base64) = u.unpack();
            let key = CurrentObjectUri::from(&uri);
            self.0.insert(key, base64);
        }

        for w in withdraws {
            let key = CurrentObjectUri::from(w.uri());
            self.0.remove(&key);
        }
    }

    /// Returns a vec with withdraws for elements matching the given URI.
    pub fn make_matching_withdraws(
        &self,
        match_uri: &uri::Rsync,
    ) -> KrillResult<Vec<WithdrawElement>> {
        let match_uri = CurrentObjectUri::from(match_uri);

        let mut withdraws = vec![];
        for (uri_key, base64) in &self.0 {
            if uri_key == &match_uri
                || (match_uri.ends_with('/')
                    && uri_key.starts_with(match_uri.as_ref()))
            {
                let uri = uri_key.try_into()?;
                let hash = base64.to_hash();
                let wdr = WithdrawElement::new(uri, hash);
                withdraws.push(wdr);
            }
        }

        Ok(withdraws)
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

    pub fn to_list_reply(&self) -> KrillResult<publication::ListReply> {
        let mut elements = vec![];

        for (key, base64) in &self.0 {
            let uri = key.try_into()?;
            let hash = base64.to_hash();
            elements.push(publication::ListElement::new(uri, hash));
        }

        Ok(publication::ListReply::new(elements))
    }
}

//------------ PublicationDeltaError
//------------ ---------------------------------------------

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
                write!(
                    f,
                    "File already exists for uri (use update!): {}",
                    uri
                )
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
    publishers_current_objects: HashMap<PublisherHandle, CurrentObjects>,
}

impl SnapshotData {
    pub fn new(
        random: RrdpFileRandom,
        publishers_current_objects: HashMap<PublisherHandle, CurrentObjects>,
    ) -> Self {
        SnapshotData {
            random,
            publishers_current_objects,
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
        let current_objects = self.publishers_current_objects.clone();
        SnapshotData::new(random, current_objects)
    }

    pub fn unpack(self) -> HashMap<PublisherHandle, CurrentObjects> {
        self.publishers_current_objects
    }

    // Get the approximate size for all current objects held by all
    // publishers.
    pub fn size_approx(&self) -> usize {
        self.publishers_current_objects
            .values()
            .fold(0, |tot, objects| tot + objects.size_approx())
    }

    pub fn current_objects_for(
        &self,
        publisher: &PublisherHandle,
    ) -> Option<&CurrentObjects> {
        self.publishers_current_objects.get(publisher)
    }

    pub fn publishers_current_objects(
        &self,
    ) -> &HashMap<PublisherHandle, CurrentObjects> {
        &self.publishers_current_objects
    }

    pub fn set_random(&mut self, random: RrdpFileRandom) {
        self.random = random;
    }

    /// Applies the delta for a publisher to this snapshot.
    ///
    /// This assumes that the delta had been checked before. This should not
    /// be any issue as deltas are verified when they are submitted.
    pub fn apply_delta(
        &mut self,
        publisher: &PublisherHandle,
        delta: DeltaElements,
    ) {
        if let Some(objects) =
            self.publishers_current_objects.get_mut(publisher)
        {
            objects.apply_delta(delta);
            if objects.is_empty() {
                self.publishers_current_objects.remove(publisher);
            }
        } else {
            // This is a new publisher without existing objects. So, just
            // create an default -empty- object set for it, so we
            // can apply the delta to it.
            let mut objects = CurrentObjects::default();
            objects.apply_delta(delta);
            self.publishers_current_objects
                .insert(publisher.clone(), objects);
        }
    }

    /// Applies the addition of new publisher with an empty object set.
    ///
    /// This is a no-op in case the publisher already exists.
    pub fn apply_publisher_added(&mut self, publisher: PublisherHandle) {
        self.publishers_current_objects
            .entry(publisher)
            .or_default();
    }

    /// Applies the removal of a publisher.
    ///
    /// This is a no-op in case the publisher does not exists.
    pub fn apply_publisher_removed(&mut self, publisher: &PublisherHandle) {
        self.publishers_current_objects.remove(publisher);
    }

    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/snapshot.xml", session, serial, self.random.0)
    }

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

    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    pub fn write_xml(
        &self,
        session: RrdpSession,
        serial: u64,
        path: &Path,
    ) -> Result<(), KrillIoError> {
        debug!("Writing snapshot file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f)
            .map_err(|e| {
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

    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Write the snapshot XML.
    ///
    /// Note: we do not use the rpki-rs Snapshot implementation because we
    /// would need to transform and copy quite a lot of data - for big
    /// repositories that is..
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

//------------ DeltaElements -------------------------------------------------

/// Defines the elements for an RRDP delta.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

    pub fn unpack(
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

    pub fn size_approx(&self) -> usize {
        let sum_publishes = self
            .publishes
            .iter()
            .fold(0, |sum, p| sum + p.size_approx());
        let sum_updates =
            self.updates.iter().fold(0, |sum, u| sum + u.size_approx());

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

    // Tells us when this delta was created, this is used to determine how
    // long we need to keep it around for.
    time: Time,

    // The actual changes in this delta: publishes/updates/withdrawals
    //
    // Note that we do not need to keep track of the owning publisher in this
    // context. This DeltaData represents a change that has already been
    // applied.
    elements: DeltaElements,
}

impl DeltaData {
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

    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    pub fn write_xml(
        &self,
        session: RrdpSession,
        serial: u64,
        path: &Path,
    ) -> Result<(), KrillIoError> {
        debug!("Writing delta file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f)
            .map_err(|e| {
                KrillIoError::new(
                    format!(
                        "cannot write delta xml to: {}",
                        path.to_string_lossy()
                    ),
                    e,
                )
            })?;

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
    /// Note: we do not use the rpki-rs Delta implementation because we
    /// potentially would need to transform and copy quite a lot of data.
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
                        .content(|content| {
                            content.raw(el.base64().as_str())
                        })?;
                }
                for el in self.elements().updates() {
                    content
                        .element(PUBLISH.into_unqualified())?
                        .attr("uri", el.uri())?
                        .attr("hash", &el.hash())?
                        .content(|content| {
                            content.raw(el.base64().as_str())
                        })?;
                }
                for el in self.elements().withdraws() {
                    content
                        .element(WITHDRAW.into_unqualified())?
                        .attr("uri", el.uri())?
                        .attr("hash", &el.hash())?;
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
        let file1_uri =
            rsync("rsync://example.krill.cloud/repo/publisher/file1.txt");

        let file1_content = Base64::from_content(&[1]);
        let file1_content_2 = Base64::from_content(&[1, 2]);
        let file2_content = Base64::from_content(&[2]);

        let mut objects = CurrentObjects::default();

        let publish_file1 = DeltaElements {
            publishes: vec![PublishElement::new(
                file1_content.clone(),
                file1_uri.clone(),
            )],
            updates: vec![],
            withdraws: vec![],
        };

        // adding a file to an empty current objects is okay
        assert!(objects.verify_delta(&publish_file1, &jail).is_ok());

        // The actual application of the delta is infallible, because event
        // replays may not fail. It is assumed deltas were verified
        // before they were persisted in events.
        objects.apply_delta(publish_file1.clone());

        // Now adding the same file for the same URI and same hash, as a
        // publish will fail.
        assert!(objects.verify_delta(&publish_file1, &jail).is_err());

        // Adding a different file as a publish element, rather than update,
        // for the same URI will also fail. Checks fix for issue #981.
        let publish_file2 = DeltaElements {
            publishes: vec![PublishElement::new(
                file2_content,
                file1_uri.clone(),
            )],
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

        // Updating again with the same delta will now fail - there is no
        // longer and object with that uri and hash it was updated to
        // the new content.
        assert!(objects.verify_delta(&update_file1, &jail).is_err());

        // Withdraws

        // Withdrawing file with wrong hash should fail
        let withdraw_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement::new(
                file1_uri.clone(),
                file1_content.to_hash(),
            )],
        };
        assert!(objects.verify_delta(&withdraw_file1, &jail).is_err());

        // Withdrawing file with the right hash should work
        let withdraw_file1_updated = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement::new(
                file1_uri,
                file1_content_2.to_hash(),
            )],
        };
        assert!(objects.verify_delta(&withdraw_file1_updated, &jail).is_ok());
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
                    "rsync://example.krill.cloud/repo/publisher/{}",
                    name
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
        pub fn equivalent(this: DeltaElements, other: DeltaElements) -> bool {
            let (mut this_publishes, mut this_updates, mut this_withdraws) =
                this.unpack();
            let (mut other_publishes, mut other_updates, mut other_withdraws) =
                other.unpack();

            this_publishes
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));
            other_publishes
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));
            this_updates
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));
            other_updates
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));
            this_withdraws
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));
            other_withdraws
                .sort_by(|a, b| a.uri().as_str().cmp(b.uri().as_str()));

            this_publishes == other_publishes
                && this_updates == other_updates
                && this_withdraws == other_withdraws
        }

        let mut objects: HashMap<CurrentObjectUri, Base64> = HashMap::new();
        objects.insert(file_uri("file1"), random_content());
        objects.insert(file_uri("file2"), random_content());
        objects.insert(file_uri("file3"), random_content());
        objects.insert(file_uri("file4"), random_content());

        let publishes = vec![
            PublishElement::new(random_content(), file_rsync_uri("file5")),
            PublishElement::new(random_content(), file_rsync_uri("file6")),
        ];

        let updates = vec![
            UpdateElement::new(
                file_rsync_uri("file1"),
                objects.get(&file_uri("file1")).unwrap().to_hash(),
                random_content(),
            ),
            UpdateElement::new(
                file_rsync_uri("file2"),
                objects.get(&file_uri("file2")).unwrap().to_hash(),
                random_content(),
            ),
        ];

        let withdraws = vec![WithdrawElement::new(
            file_rsync_uri("file3"),
            objects.get(&file_uri("file3")).unwrap().to_hash(),
        )];

        let delta_a_b = DeltaElements::new(publishes, updates, withdraws);
        let objects_a = CurrentObjects::new(objects);

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
