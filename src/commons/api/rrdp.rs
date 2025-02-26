//! Data objects used in the RRDP repository.
//!
//! This includes the publish, update, and withdraw elements, as well as the
//! notification, snapshot and delta file definitions.

use std::{error, fmt, io};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use chrono::Duration;
use log::debug;
use rpki::uri;
use rpki::ca::publication;
use rpki::ca::idexchange::PublisherHandle;
use rpki::ca::publication::Base64;
use rpki::repository::x509::Time;
use rpki::rrdp::Hash;
use rpki::xml::decode::Name;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use crate::commons::KrillResult;
use crate::commons::error::{Error, KrillIoError};
use crate::commons::util::file;


//------------ RRDP name definitions -----------------------------------------

const VERSION: &str = "1";
const NS: &str = "http://www.ripe.net/rpki/rrdp";

const SNAPSHOT: Name = Name::unqualified(b"snapshot");
const DELTA: Name = Name::unqualified(b"delta");
const PUBLISH: Name = Name::unqualified(b"publish");
const WITHDRAW: Name = Name::unqualified(b"withdraw");


//------------ RrdpSession ---------------------------------------------------

/// An RRDP session.
///
/// A session is identified by a UUID. By default, a new session will be
/// created with a random V4 UUID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RrdpSession(Uuid);

impl RrdpSession {
    /// Creates a new session with a random identifier.
    pub fn random() -> Self {
        Self::default()
    }

    /// Creates a session from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns a reference to the session’s UUID.
    pub fn uuid(&self) -> &Uuid {
        &self.0
    }

    /// Converts the session into its UUID.
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

//--- Default

impl Default for RrdpSession {
    fn default() -> Self {
        RrdpSession(Uuid::new_v4())
    }
}


//--- Display

impl fmt::Display for RrdpSession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}


//--- Deserialize and Serialize

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

impl Serialize for RrdpSession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}


//------------ PublishElement ------------------------------------------------

/// A publish element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishElement {
    /// The URI identifying the object to be published.
    pub uri: uri::Rsync,

    /// The Base64 encoded content of the object to be published.
    pub base64: Base64,
}

impl From<publication::Publish> for PublishElement {
    fn from(p: publication::Publish) -> Self {
        let (_tag, uri, base64) = p.unpack();
        PublishElement { base64, uri }
    }
}


//------------ UpdateElement -------------------------------------------------

/// An update element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateElement {
    /// The URI identifying the object to be updated.
    pub uri: uri::Rsync,

    /// The hash of the current content of the object to be updated.
    pub hash: Hash,

    /// The new content of the object to be updated.
    pub base64: Base64,
}

impl UpdateElement {
    /// Converts the update element into a publish element.
    pub fn into_publish(self) -> PublishElement {
        PublishElement {
            uri: self.uri,
            base64: self.base64,
        }
    }
}

impl From<publication::Update> for UpdateElement {
    fn from(u: publication::Update) -> Self {
        let (_tag, uri, base64, hash) = u.unpack();
        UpdateElement { uri, hash, base64 }
    }
}


//------------ WithdrawElement -----------------------------------------------

/// A withdraw element as used in the RRDP protocol.
///
/// Note that the difference with the publication protocol is the absence of
/// the tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawElement {
    /// The URI identifying the object to be withdrawn.
    pub uri: uri::Rsync,

    /// The hash of the current content of the object to be withdrawn.
    pub hash: Hash,
}

impl From<publication::Withdraw> for WithdrawElement {
    fn from(w: publication::Withdraw) -> Self {
        let (_tag, uri, hash) = w.unpack();
        WithdrawElement { uri, hash }
    }
}


//------------ CurrentObjectUri ----------------------------------------------

/// An object’s rsync URI as a simple map key.
///
/// We use this separate type rather than [`rpki::uri::Rsync`] because the
/// latter is not very suitable for use in hash maps: it is mutable and
/// its hash function is slow due to the fact that it needs
/// to accommodate for the fact that the URI scheme and hostname are
/// case insensitive.
///
/// This type can still be cloned cheaply since it holds an arc to an
/// allocated string.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CurrentObjectUri(Arc<str>);

impl CurrentObjectUri {
    /// Returns a string reference of the rsync URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&uri::Rsync> for CurrentObjectUri {
    fn from(value: &uri::Rsync) -> Self {
        // use canonical scheme and hostname (converts to lowercase if needed)
        CurrentObjectUri(
            format!("{}{}", value.canonical_module(), value.path()).into()
        )
    }
}

impl From<uri::Rsync> for CurrentObjectUri {
    fn from(value: uri::Rsync) -> Self {
        Self::from(&value)
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


//------------ CurrentObjects ------------------------------------------------

/// The current set of published objects.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<CurrentObjectUri, Base64>);

impl CurrentObjects {
    /// Returns the number of objects in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the approximate size of all objects.
    pub fn size_approx(&self) -> usize {
        self.0.values().fold(0, |tot, el| tot + el.size_approx())
    }

    /// Extends the objects by another set.
    ///
    /// The content of objects already present will be overwritten.
    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0)
    }

    /// Returns the delta elements needed to turn this set into the other.
    pub fn diff(&self, other: &Self) -> KrillResult<DeltaElements> {
        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];

        // find new and updated stuff
        for (uri_key, base64) in &other.0 {
            match self.0.get(uri_key) {
                None => {
                    publishes.push(PublishElement {
                        uri: uri_key.try_into()?,
                        base64: base64.clone(),
                    });
                }
                Some(existing_b64) => {
                    if base64 != existing_b64 {
                        updates.push(UpdateElement {
                            uri: uri_key.try_into()?,
                            hash: existing_b64.to_hash(),
                            base64: base64.clone()
                        });
                    }
                }
            }
        }

        // find removed stuff
        for (uri_key, base64) in &self.0 {
            if !other.0.contains_key(uri_key) {
                let wdr = WithdrawElement {
                    uri: uri_key.try_into()?,
                    hash: base64.to_hash(),
                };
                withdraws.push(wdr);
            }
        }

        Ok(DeltaElements::new(publishes, updates, withdraws))
    }

    /// Returns an iterator over the current objects.
    pub fn iter(&self) -> impl Iterator<Item = (&CurrentObjectUri, &Base64)> {
        self.0.iter()
    }

    /// Converts the set into a list of publish elements.
    pub fn try_into_publish_elements(
        self,
    ) -> KrillResult<Vec<PublishElement>> {
        let mut elements = Vec::new();

        for (uri_key, base64) in self.0.into_iter() {
            elements.push(PublishElement { uri: uri_key.try_into()?, base64 });
        }

        Ok(elements)
    }

    /// Creates a list of withdraw elements for all current objects.
    pub fn try_to_withdraw_elements(
        &self
    ) -> KrillResult<Vec<WithdrawElement>> {
        let mut elements = Vec::new();

        for (uri_key, base64) in self.0.iter() {
            elements.push(WithdrawElement {
                uri: uri_key.try_into()?,
                hash: base64.to_hash(),
            });
        }

        Ok(elements)
    }

    /// Verifies that a delta can be applied to this set of objects.
    ///
    /// Checks that all object URIs are under `jail`, that published objects
    /// aren’t in the set, and that updated and deleted objects are in the set
    /// with the
    /// given hash.
    pub fn verify_delta_applies(
        &self,
        delta: &DeltaElements,
        jail: &uri::Rsync,
    ) -> Result<(), PublicationDeltaError> {
        for p in delta.publishes() {
            if !jail.is_parent_of(&p.uri) {
                return Err(PublicationDeltaError::outside(jail, &p.uri));
            }
            if self.0.contains_key(&CurrentObjectUri::from(&p.uri)) {
                return Err(PublicationDeltaError::present(&p.uri));
            }
        }

        for u in delta.updates() {
            if !jail.is_parent_of(&u.uri) {
                return Err(PublicationDeltaError::outside(jail, &u.uri));
            }
            if !self.contains(u.hash, &u.uri) {
                return Err(PublicationDeltaError::no_match(&u.uri));
            }
        }

        for w in delta.withdraws() {
            if !jail.is_parent_of(&w.uri) {
                return Err(PublicationDeltaError::outside(jail, &w.uri));
            }
            if !self.contains(w.hash, &w.uri) {
                return Err(PublicationDeltaError::no_match(&w.uri));
            }
        }

        Ok(())
    }

    /// Returns whether the set contains an object with the given URI and hash.
    fn contains(&self, hash: Hash, uri: &uri::Rsync) -> bool {
        match self.0.get(&CurrentObjectUri::from(uri)) {
            Some(base64) => base64.to_hash() == hash,
            None => false,
        }
    }

    /// Applies a delta to CurrentObjects.
    ///
    /// Assumes that the delta was checked using
    /// [`Self::verify_delta_applies`].
    pub fn apply_delta(&mut self, delta: DeltaElements) {
        let (publishes, updates, withdraws) = delta.unpack();

        for p in publishes {
            self.0.insert(CurrentObjectUri::from(p.uri), p.base64);
        }

        for u in updates {
            // we ignore the hash of the old object when inserting
            // the update, as it has already been verified.
            self.0.insert(CurrentObjectUri::from(u.uri), u.base64);
        }

        for w in withdraws {
            self.0.remove(&CurrentObjectUri::from(w.uri));
        }
    }

    /// Returns the withdraws for elements matching the given URI.
    pub fn get_matching_withdraws(
        &self,
        match_uri: &uri::Rsync,
    ) -> KrillResult<Vec<WithdrawElement>> {
        let match_uri = CurrentObjectUri::from(match_uri);

        let mut withdraws = Vec::new();
        for (uri_key, base64) in &self.0 {
            if uri_key == &match_uri
                || (match_uri.as_str().ends_with('/')
                    && uri_key.as_str().starts_with(match_uri.as_str()))
            {
                withdraws.push(WithdrawElement {
                    uri: uri_key.try_into()?,
                    hash: base64.to_hash(),
                });
            }
        }

        Ok(withdraws)
    }

    /// Creates a publication list reply for the set.
    pub fn get_list_reply(&self) -> KrillResult<publication::ListReply> {
        let mut elements = Vec::new();

        for (key, base64) in &self.0 {
            elements.push(publication::ListElement::new(
                key.try_into()?, base64.to_hash()
            ));
        }

        Ok(publication::ListReply::new(elements))
    }
}


//--- FromIterator

impl<K> FromIterator<(K, Base64)> for CurrentObjects
where K: Into<CurrentObjectUri> {
    fn from_iter<T: IntoIterator<Item = (K, Base64)>>(
        iter: T
    ) -> Self {
        Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}


//------------ SnapshotData --------------------------------------------------

/// The data needed to create an RRDP Snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotData {
    /// A random value to make the URI unique.
    random: RrdpFileRandom,

    /// The objects of each publisher.
    ///
    /// We keep objects per publisher so that we can respond to
    /// list and publication queries more efficiently.
    objects: HashMap<PublisherHandle, CurrentObjects>,
}

impl SnapshotData {
    /// Creates a new snapshot from its components.
    pub fn new(
        random: RrdpFileRandom,
        publishers_current_objects: HashMap<PublisherHandle, CurrentObjects>,
    ) -> Self {
        SnapshotData {
            random,
            objects: publishers_current_objects,
        }
    }

    /// Creates a new, empty snapshot.
    pub fn empty() -> Self {
        SnapshotData::new(RrdpFileRandom::default(), HashMap::default())
    }

    /// Clones the snapshot but gives it a new random component.
    pub fn clone_with_new_random(&self) -> Self {
        SnapshotData::new(
            RrdpFileRandom::default(),
            self.objects.clone(),
        )
    }

    /// Returns a reference to the map of current objects per publisher.
    pub fn publishers_current_objects(
        &self,
    ) -> &HashMap<PublisherHandle, CurrentObjects> {
        &self.objects
    }

    /// Sets the random component to the given value.
    pub fn set_random(&mut self, random: RrdpFileRandom) {
        self.random = random;
    }

    /// Returns the approximate size for all current objects.
    pub fn size_approx(&self) -> usize {
        self.objects.values().fold(
            0, |tot, objects| tot + objects.size_approx()
        )
    }

    /// Returns the current objects for the given publisher if available.
    pub fn get_publisher_objects(
        &self,
        publisher: &PublisherHandle,
    ) -> Option<&CurrentObjects> {
        self.objects.get(publisher)
    }

    /// Applies the delta for a publisher to this snapshot.
    ///
    /// This assumes that the delta had been checked before.
    pub fn apply_delta(
        &mut self,
        publisher: &PublisherHandle,
        delta: DeltaElements,
    ) {
        if let Some(objects) = self.objects.get_mut(publisher) {
            objects.apply_delta(delta);
            if objects.is_empty() {
                self.objects.remove(publisher);
            }
        }
        else {
            // This is a new publisher without existing objects. So, just
            // create an default -empty- object set for it, so we
            // can apply the delta to it.
            let mut objects = CurrentObjects::default();
            objects.apply_delta(delta);
            self.objects.insert(publisher.clone(), objects);
        }
    }

    /// Applies the addition of new publisher with an empty object set.
    ///
    /// This is a no-op in case the publisher already exists.
    pub fn apply_publisher_added(&mut self, publisher: PublisherHandle) {
        self.objects.entry(publisher).or_default();
    }

    /// Applies the removal of a publisher.
    ///
    /// This is a no-op in case the publisher does not exists.
    pub fn apply_publisher_removed(&mut self, publisher: &PublisherHandle) {
        self.objects.remove(publisher);
    }

    /// Creates the relative URI path for the snapshot.
    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/snapshot.xml", session, serial, self.random.0)
    }

    /// Returns the URI for the snapshot.
    pub fn uri(
        &self,
        session: RrdpSession,
        serial: u64,
        rrdp_base_uri: &uri::Https,
    ) -> uri::Https {
        rrdp_base_uri.join(self.rel_path(session, serial).as_ref()).unwrap()
    }

    /// Returns the file system path for the snapshot.
    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    /// Writes the snapshot XML to a file under `path`.
    pub fn write_xml(
        &self,
        session: RrdpSession,
        serial: u64,
        path: &Path,
    ) -> Result<(), KrillIoError> {
        debug!("Writing snapshot file: {}", path.to_string_lossy());

        let mut f = file::create_file_with_path(path)?;
        self.write_xml_to_writer(session, serial, &mut f).map_err(|e| {
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

    /// Returns the snapshot XML.
    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Writes the snapshot XML.
    //
    // Note: we do not use the rpki-rs Snapshot implementation because we
    // would need to transform and copy quite a lot of data
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
                for publisher_objects in self.objects.values() {
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

/// The elements of an RRDP delta.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaElements {
    /// The objects to be published.
    publishes: Vec<PublishElement>,

    /// The objects to be updated.
    updates: Vec<UpdateElement>,

    /// The objects to be withdrawn.
    withdraws: Vec<WithdrawElement>,
}

impl DeltaElements {
    /// Creates the delta from the various elements.
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

    /// Converts the value into its three constituent portions.
    pub fn unpack(
        self
    ) -> (
        Vec<PublishElement>,
        Vec<UpdateElement>,
        Vec<WithdrawElement>,
    ) {
        (self.publishes, self.updates, self.withdraws)
    }

    /// Returns the overall number of elements.
    pub fn len(&self) -> usize {
        self.publishes.len() + self.updates.len() + self.withdraws.len()
    }

    /// Returns whether there are no delta elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the approximate size of the published and updated objects.
    pub fn size_approx(&self) -> usize {
        let sum_publishes = self
            .publishes
            .iter()
            .fold(0, |sum, p| sum + p.base64.size_approx());
        let sum_updates =
            self.updates.iter().fold(0, |sum, u| sum + u.base64.size_approx());

        sum_publishes + sum_updates
    }

    /// Appends all elements from `other` to `self`.
    ///
    /// The method performs a dumb append, i.e., it will not check for
    /// duplicate operations such as withdrawing a previously published
    /// objected.
    pub fn append(&mut self, mut other: Self) {
        self.publishes.append(&mut other.publishes);
        self.updates.append(&mut other.updates);
        self.withdraws.append(&mut other.withdraws);
    }

    /// Returns a reference to the published elements.
    pub fn publishes(&self) -> &[PublishElement] {
        &self.publishes
    }

    /// Returns a reference to the updated elements.
    pub fn updates(&self) -> &[UpdateElement] {
        &self.updates
    }

    /// Returns a reference to the withdrawn elements.
    pub fn withdraws(&self) -> &[WithdrawElement] {
        &self.withdraws
    }
}


//--- From

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


//------------ DeltaData -----------------------------------------------------

/// The data needed to create an RRDP delta XML file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaData {
    /// A random value to make the URI unique.
    random: RrdpFileRandom,

    /// The serial number of the delta.
    ///
    /// The session is implied by owning RRDP server, but deltas carry a
    /// serial.
    serial: u64,

    /// The time the delta was created at.
    ///
    /// This is used to determine how long we need to keep it around for.
    time: Time,

    /// The objects changed by this delta.
    ///
    /// Note that we do not need to keep track of the owning publisher in this
    /// context. This value represents a change that has already been
    /// applied.
    elements: DeltaElements,
}

impl DeltaData {
    /// Creates a new delta from its components.
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

    /// Returns the serial number of the delta.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the random component of the delta URI.
    pub fn random(&self) -> &RrdpFileRandom {
        &self.random
    }

    /// Returns whether the delta is older than the given number of seconds.
    pub fn older_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time < then
    }

    /// Returns whether the delta is younger than the given number of seconds.
    pub fn younger_than_seconds(&self, seconds: i64) -> bool {
        let then = Time::now() - Duration::seconds(seconds);
        self.time > then
    }

    /// Returns a reference to the delta elements.
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

    /// Returns whether the delta is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Converts the delta into its elements.
    pub fn into_elements(self) -> DeltaElements {
        self.elements
    }

    /// Returns the relative path to the delta.
    fn rel_path(&self, session: RrdpSession, serial: u64) -> String {
        format!("{}/{}/{}/delta.xml", session, serial, self.random.0)
    }

    /// Returns the RRDP URI for the delta.
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

    /// Returns the local file path for the delta.
    pub fn path(
        &self,
        session: RrdpSession,
        serial: u64,
        base_path: &Path,
    ) -> PathBuf {
        base_path.join(self.rel_path(session, serial))
    }

    /// Writes the delta XML to a file under `path`.
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

    /// Returns the delta XML.
    pub fn xml(&self, session: RrdpSession, serial: u64) -> Vec<u8> {
        let mut res = vec![];
        self.write_xml_to_writer(session, serial, &mut res).unwrap();
        res
    }

    /// Writes the delta XML.
    //
    // Note: we do not use the rpki-rs Delta implementation because we
    // potentially would need to transform and copy quite a lot of data.
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
                        .attr("uri", &el.uri)?
                        .content(|content| {
                            content.raw(el.base64.as_str())
                        })?;
                }
                for el in self.elements().updates() {
                    content
                        .element(PUBLISH.into_unqualified())?
                        .attr("uri", &el.uri)?
                        .attr("hash", &el.hash)?
                        .content(|content| {
                            content.raw(el.base64.as_str())
                        })?;
                }
                for el in self.elements().withdraws() {
                    content
                        .element(WITHDRAW.into_unqualified())?
                        .attr("uri", &el.uri)?
                        .attr("hash", &el.hash)?;
                }
                Ok(())
            })?;

        writer.done()
    }
}


//------------ RrdpFileRandom ------------------------------------------------

/// A random component included in the name of RRDP files.
///
/// The component will make the URIs unguessable and prevent cache poisoning
/// (through CDNs caching a 404 not found).
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


//============ Error Types ===================================================

//------------ PublicationDeltaError -----------------------------------------

/// An error happened while verifying a delta.
#[derive(Clone, Debug)]
pub enum PublicationDeltaError {
    /// An object URI is outside the rsync base path.
    UriOutsideJail(uri::Rsync, uri::Rsync),

    /// A published object is already present.
    ObjectAlreadyPresent(uri::Rsync),

    /// An updated or deleted object is not present with the right hash.
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

impl fmt::Display for PublicationDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicationDeltaError::UriOutsideJail(uri, jail) => {
                write!(f,
                    "Publishing '{}' outside of jail URI '{}'",
                    uri, jail
                )
            }
            PublicationDeltaError::ObjectAlreadyPresent(uri) => {
                write!(f,
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

impl error::Error for PublicationDeltaError { }


//============ Tests =========================================================

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
            publishes: vec![PublishElement {
                uri: file1_uri.clone(),
                base64: file1_content.clone(),
            }],
            updates: vec![],
            withdraws: vec![],
        };

        // adding a file to an empty current objects is okay
        assert!(objects.verify_delta_applies(&publish_file1, &jail).is_ok());

        // The actual application of the delta is infallible, because event
        // replays may not fail. It is assumed deltas were verified
        // before they were persisted in events.
        objects.apply_delta(publish_file1.clone());

        // Now adding the same file for the same URI and same hash, as a
        // publish will fail.
        assert!(objects.verify_delta_applies(&publish_file1, &jail).is_err());

        // Adding a different file as a publish element, rather than update,
        // for the same URI will also fail. Checks fix for issue #981.
        let publish_file2 = DeltaElements {
            publishes: vec![PublishElement {
                uri: file1_uri.clone(),
                base64: file2_content,
            }],
            updates: vec![],
            withdraws: vec![],
        };
        assert!(objects.verify_delta_applies(&publish_file2, &jail).is_err());

        // Updates

        // Updating a file should work
        let update_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![UpdateElement {
                uri: file1_uri.clone(),
                hash: file1_content.to_hash(),
                base64: file1_content_2.clone(),
            }],
            withdraws: vec![],
        };
        assert!(objects.verify_delta_applies(&update_file1, &jail).is_ok());
        objects.apply_delta(update_file1.clone());

        // Updating again with the same delta will now fail - there is no
        // longer and object with that uri and hash it was updated to
        // the new content.
        assert!(objects.verify_delta_applies(&update_file1, &jail).is_err());

        // Withdraws

        // Withdrawing file with wrong hash should fail
        let withdraw_file1 = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement {
                uri: file1_uri.clone(),
                hash: file1_content.to_hash(),
            }],
        };
        assert!(
            objects.verify_delta_applies(&withdraw_file1, &jail).is_err()
        );

        // Withdrawing file with the right hash should work
        let withdraw_file1_updated = DeltaElements {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![WithdrawElement {
                uri: file1_uri,
                hash: file1_content_2.to_hash(),
            }],
        };
        assert!(
            objects.verify_delta_applies(
                &withdraw_file1_updated, &jail
            ).is_ok()
        );
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
        pub fn equivalent(
            mut this: DeltaElements, mut other: DeltaElements
        ) -> bool {
            this.publishes
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.publishes
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            this.updates
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.updates
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            this.withdraws
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));
            other.withdraws
                .sort_by(|a, b| a.uri.as_str().cmp(b.uri.as_str()));

            this.publishes == other.publishes
                && this.updates == other.updates
                && this.withdraws == other.withdraws
        }

        let mut objects: HashMap<CurrentObjectUri, Base64> = HashMap::new();
        objects.insert(file_uri("file1"), random_content());
        objects.insert(file_uri("file2"), random_content());
        objects.insert(file_uri("file3"), random_content());
        objects.insert(file_uri("file4"), random_content());

        let publishes = vec![
            PublishElement {
                uri: file_rsync_uri("file5"), base64: random_content()
            },
            PublishElement {
                uri: file_rsync_uri("file6"), base64: random_content(), 
            },
        ];

        let updates = vec![
            UpdateElement {
                uri: file_rsync_uri("file1"),
                hash: objects.get(&file_uri("file1")).unwrap().to_hash(),
                base64: random_content(),
            },
            UpdateElement {
                uri: file_rsync_uri("file2"),
                hash: objects.get(&file_uri("file2")).unwrap().to_hash(),
                base64: random_content(),
            },
        ];

        let withdraws = vec![WithdrawElement {
            uri: file_rsync_uri("file3"),
            hash: objects.get(&file_uri("file3")).unwrap().to_hash(),
        }];

        let delta_a_b = DeltaElements::new(publishes, updates, withdraws);
        let objects_a = CurrentObjects(objects);

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

