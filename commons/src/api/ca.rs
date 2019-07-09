//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::str;
use std::str::FromStr;

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::{Cert, Overclaim};
use rpki::crypto::{PublicKey, KeyIdentifier};
use rpki::resources::{
    AsBlocks,
    AsResources,
    IpBlocks,
    IpResources,
    Ipv4Resources,
    Ipv6Resources,
};
use rpki::uri;
use rpki::x509::{
    Serial,
    Time,
};

use crate::api::{
    Base64,
    EncodedHash,
};
use crate::api::admin::{
    Handle,
    Token
};
use crate::api::publication;
use crate::util::ext_serde;
use crate::util::softsigner::SignerKeyId;
use crate::rpki::crl::{
    Crl,
    CrlEntry,
};
use crate::rpki::manifest::{
    FileAndHash,
    Manifest,
};


//------------ ChildCa -------------------------------------------------------

/// This type defines a Child Certificate Authority under a parent
/// Certificate Authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCa {
    handle: Handle,
    details: ChildCaDetails
}

impl ChildCa {
    pub fn new(handle: Handle, details: ChildCaDetails) -> Self {
        ChildCa { handle, details }
    }

    pub fn without_resources(handle: Handle, token: Token) -> Self {
        let details = ChildCaDetails::new(token);
        ChildCa { handle, details }
    }

    pub fn add_resources(&mut self, name: &str, resources: ResourceSet) {
        self.details.add_resources(name, resources);
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn details(&self) -> &ChildCaDetails {
        &self.details
    }

    pub fn unwrap(self) -> (Handle, ChildCaDetails) {
        (self.handle, self.details )
    }
}


//------------ ChildCaDetails ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaDetails {
    token: Token,
    resources: HashMap<String, ChildResources>
}

impl ChildCaDetails {
    pub fn new(token: Token) -> Self {
        ChildCaDetails { token, resources: HashMap::new() }
    }

    pub fn token(&self) -> &Token { &self.token }

    pub fn resource_sets(&self) -> Vec<&ResourceSet> {
        self.resources.iter().map(|e| &e.1.resources ).collect()
    }

    pub fn resources(&self, class: &str) -> Option<&ChildResources> {
        self.resources.get(class)
    }

    pub fn add_resources(&mut self, name: &str, resources: ResourceSet) {
        self.resources.insert(
            name.to_string(),
            ChildResources::new(resources)
        );
    }

    pub fn add_cert(&mut self, class_name: &str, cert: IssuedCert) {
        // Note the resource class MUST exist, or no cert would have
        // been issued to it. So, it's safe to unwrap here.
        self.resources.get_mut(class_name).unwrap().add_cert(cert)
    }

}

/// This type defines a reference to PublicKey for easy storage and lookup.
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, PartialEq, Serialize)]
pub struct KeyRef(String);

impl From<&KeyIdentifier> for KeyRef {
    fn from(ki: &KeyIdentifier) -> Self {
        let hex = ki.into_hex();
        let s = unsafe {
            str::from_utf8_unchecked(&hex)
        };
        KeyRef(s.to_string())
    }
}

impl From<&Cert> for KeyRef {
    fn from(c: &Cert) -> Self {
        Self::from(&c.subject_key_identifier())
    }
}


//------------ ChildResources ------------------------------------------------

/// This type defines the resource entitlements for a child CA within
/// a given resource class. Includes the set of current certificates
/// issued to the child CA.
///
/// See: https://tools.ietf.org/html/rfc6492#section-3.3.2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildResources {
    resources: ResourceSet,
    not_after: Time,
    certs: HashMap<KeyRef, IssuedCert>
}

impl ChildResources {

    pub fn new(resources: ResourceSet) -> Self {
        ChildResources {
            resources,
            not_after: Time::next_year(),
            certs: HashMap::new()
        }
    }

    pub fn resources(&self) -> &ResourceSet { &self.resources }

    /// Give back the not_after time that would be used on newly
    /// issued certificates. See `resource_set_notafter` in
    /// section 3.3.2 of RFC6492.
    ///
    /// This is the stored 'not_after' time for this ChildResources,
    /// or if this time is less than 3 months away, an updated time
    /// which is now + one year.
    pub fn not_after(&self) -> Time {
        let cut_off = Time::now() + Duration::weeks(13);

        if self.not_after.validate_not_before(cut_off).is_err() {
            Time::next_year()
        } else {
            self.not_after
        }
    }

    pub fn certs(&self) -> impl Iterator<Item=&IssuedCert> {
        self.certs.values()
    }

    pub fn cert(&self, pub_key: &PublicKey) -> Option<&IssuedCert> {
        let key_ref = KeyRef::from(&pub_key.key_identifier());
        self.certs.get(&key_ref)
    }

    pub fn add_cert(&mut self, cert: IssuedCert) {
        let key_ref = KeyRef::from(cert.cert());

        self.not_after = cert.cert().validity().not_after();
        self.certs.insert(key_ref, cert);
    }

}


//------------ IssuedCert ----------------------------------------------------

/// This type defines an issued certificate, including its publication
/// point and resource set. Intended for use in list responses defined
/// in RFC6492, section 3.3.2.
///
// Note that [`Cert`] includes the resources extensions, but only
// exposes these when it's coerced into a [`ResourceCert`], which
// can only be done through validation. The latter type cannot be
// deserialized. Therefore opting for some duplication in this case,
// which should actually also help with readability and debug-ability
// of the stored json structures.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuedCert {
    uri: uri::Rsync, // where this cert is published
    resource_set: ResourceSet,
    cert: Cert
}

impl IssuedCert {
    pub fn new(
        uri: uri::Rsync,
        resource_set: ResourceSet,
        cert: Cert
    ) -> Self {
        IssuedCert { uri, resource_set, cert }
    }

    pub fn unwrap(self) -> (uri::Rsync, ResourceSet, Cert) {
        (self.uri, self.resource_set, self.cert)
    }

    pub fn cert(&self) -> &Cert { &self.cert }
}

impl PartialEq for IssuedCert {
    fn eq(&self, other: &IssuedCert) -> bool {
        self.uri == other.uri &&
        self.resource_set == other.resource_set &&
        self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for IssuedCert {}


//------------ RcvdCert ------------------------------------------------------

/// Contains a CA Certificate that has been issued to this CA, for some key.
///
/// Note, this may be a self-signed TA Certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RcvdCert {
    cert: Cert,
    uri: uri::Rsync,
    resources: ResourceSet
}

impl RcvdCert {

    pub fn new(cert: Cert, uri: uri::Rsync) -> Self {
        let resources = ResourceSet::from(&cert);
        RcvdCert { cert, uri, resources }
    }

    pub fn cert(&self) -> &Cert { &self.cert }
    pub fn uri(&self) -> &uri::Rsync { &self.uri }
    pub fn crl_uri(&self) -> uri::Rsync {
        self.uri_for_object(
            ObjectName::new(&self.cert.subject_key_identifier(), "crl")
        )
    }

    pub fn uri_for_object(&self, name: impl Into<ObjectName>) -> uri::Rsync {
        let name: ObjectName = name.into();
        self.cert.ca_repository().unwrap().join(name.as_bytes())
    }

    pub fn resources(&self) -> &ResourceSet { &self.resources }

    pub fn der_encoded(&self) -> Bytes {
        self.cert.to_captured().into_bytes()
    }
}

impl From<IssuedCert> for RcvdCert {
    fn from(issued: IssuedCert) -> Self {
        RcvdCert {
            cert: issued.cert,
            uri: issued.uri,
            resources: issued.resource_set
        }
    }
}

impl AsRef<Cert> for RcvdCert {
    fn as_ref(&self) -> &Cert {
        &self.cert
    }
}

impl PartialEq for RcvdCert {
    fn eq(&self, other: &RcvdCert) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() &&
            self.uri == other.uri
    }
}

impl Eq for RcvdCert {}


//------------ TrustAnchorLocator --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>, // We won't create TALs with rsync, this is not for parsing.

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    encoded_ski: Bytes,
}

impl TrustAnchorLocator {
    /// Creates a new TAL, panics when the provided Cert is not a TA cert.
    pub fn new(uris: Vec<uri::Https>, cert: &Cert) -> Self {
        if cert.authority_key_identifier().is_some() {
            panic!("Trying to create TAL for a non-TA certificate.")
        }
        let encoded_ski = cert.subject_public_key_info().to_info_bytes();
        TrustAnchorLocator { uris, encoded_ski }
    }
}

impl fmt::Display for TrustAnchorLocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base64 = Base64::from_content(&self.encoded_ski).to_string();

        for uri in self.uris.iter() {
            writeln!(f, "{}", uri)?;
        }
        writeln!(f)?;

        let len = base64.len();
        let wrap = 64;

        for i in 0..=(len / wrap) {
            if (i * wrap + wrap) < len {
                writeln!(f, "{}", &base64[i * wrap .. i * wrap + wrap])?;
            } else {
                write!(f, "{}", &base64[i * wrap .. ])?;
            }
        }

        Ok(())
    }
}


//------------ RepoInfo ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rpki_notify: uri::Https
}

impl RepoInfo {
    pub fn new(base_uri: uri::Rsync, rpki_notify: uri::Https) -> Self {
        RepoInfo { base_uri, rpki_notify }
    }

    pub fn base_uri(&self) -> &uri::Rsync { &self.base_uri }

    /// Returns the ca repository uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn ca_repository(&self, name_space: &str) -> uri::Rsync {
        match name_space {
            "" => self.base_uri.clone(),
            _  => self.base_uri.join(name_space.as_ref()).join(b"/")
        }
    }

    /// Returns the rpki manifest uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn rpki_manifest(
        &self,
        name_space: &str,
        signing_key: &KeyIdentifier
    ) -> uri::Rsync {
        self.resolve(name_space, &Self::mft_name(signing_key))
    }

    /// Returns the rpki notify uri.
    /// (Note that this is the same for all namespaces).
    pub fn rpki_notify(&self) -> uri::Https {
        self.rpki_notify.clone()
    }

    pub fn resolve(&self, name_space: &str, file_name: &str) -> uri::Rsync {
        self.ca_repository(name_space).join(file_name.as_ref())
    }

    pub fn mft_name(signing_key: &KeyIdentifier) -> ObjectName {
        ObjectName::new(signing_key, "mft")
    }

    pub fn crl_name(signing_key: &KeyIdentifier) -> ObjectName {
        ObjectName::new(signing_key, "crl")
    }
}

impl PartialEq for RepoInfo {
    fn eq(&self, other: &RepoInfo) -> bool {
        self.base_uri == other.base_uri &&
        self.rpki_notify.as_str() == other.rpki_notify.as_str()
    }
}

impl Eq for RepoInfo {}


//------------ CertifiedKey --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CertifiedKey {
    key_id: SignerKeyId,
    incoming_cert: RcvdCert,
    current_set: CurrentObjectSet
}

impl CertifiedKey {
    pub fn new(key_id: SignerKeyId, incoming_cert: RcvdCert) -> Self {
        let current_set = CurrentObjectSet::default();

        CertifiedKey {
            key_id, incoming_cert, current_set
        }
    }

    pub fn key_id(&self) -> &SignerKeyId { &self.key_id }
    pub fn incoming_cert(&self) -> &RcvdCert { &self.incoming_cert }
    pub fn current_set(&self) -> &CurrentObjectSet { &self.current_set }

    pub fn needs_publication(&self) -> bool {
        self.current_set.number == 1 ||
        self.current_set.next_update < Time::now() + Duration::hours(8)
    }

    pub fn with_new_cert(mut self, cert: RcvdCert) -> Self {
        self.incoming_cert = cert;
        self
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.current_set.apply_delta(delta)
    }
}


//------------ CurrentObject -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObject {
    content: Base64,
    serial: Serial,
    expires: Time
}

impl CurrentObject {
    pub fn content(&self) -> &Base64 { &self.content }
    pub fn serial(&self) -> Serial { self.serial }
    pub fn expires(&self) -> Time { self.expires }
}

impl From<&Cert> for CurrentObject {
    fn from(cert: &Cert) -> Self {
        let content = Base64::from(cert);
        let serial = cert.serial_number();
        let expires = cert.validity().not_after();
        CurrentObject {
            content, serial, expires
        }
    }
}

impl From<&Crl> for CurrentObject {
    fn from(crl: &Crl) -> Self {
        let content = Base64::from(crl);
        let serial = crl.crl_number();  // never revoked
        let expires = crl.next_update();

        CurrentObject {
            content, serial, expires
        }
    }
}

impl From<&Manifest> for CurrentObject {
    fn from(mft: &Manifest) -> Self {
        let content = Base64::from(mft);
        let serial = mft.cert().serial_number();
        let expires = mft.content().next_update();

        CurrentObject {
            content, serial, expires
        }
    }
}


//------------ ObjectName ----------------------------------------------------

/// This type is used to represent the (deterministic) file names for
/// RPKI repository objects.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ObjectName(String);

impl ObjectName {
    pub fn new(ki: &KeyIdentifier, extension: &str) -> Self {
        ObjectName(format!("{}.{}", KeyRef::from(ki), extension))
    }
}

impl From<&Cert> for ObjectName {
    fn from(c: &Cert) -> Self {
        Self::new(&c.subject_key_identifier(), "cer")
    }
}

impl From<&Manifest> for ObjectName {
    fn from(m: &Manifest) -> Self {
        Self::new(&m.cert().authority_key_identifier().unwrap(), "mft")
    }
}

impl From<&Crl> for ObjectName {
    fn from(c: &Crl) -> Self {
        Self::new(c.authority_key_identifier(), "crl")
    }
}

impl AsRef<str> for ObjectName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for ObjectName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


//------------ CurrentObjects ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<ObjectName, CurrentObject>);

impl Default for CurrentObjects {
    fn default() -> Self {
        CurrentObjects(HashMap::new())
    }
}

impl CurrentObjects {
    pub fn insert(
        &mut self,
        name: ObjectName,
        object: CurrentObject
    ) -> Option<CurrentObject> {
        self.0.insert(name, object)
    }

    pub fn apply_delta(&mut self, delta: ObjectsDelta) {

        for add in delta.added.into_iter() {
            self.0.insert(add.name, add.object);
        }
        for upd in delta.updated.into_iter() {
            self.0.insert(upd.name, upd.object);
        }
        for wdr in delta.withdrawn.into_iter() {
            self.0.remove(&wdr.name);
        }
    }

    pub fn object_for(&self, name: &ObjectName) -> Option<&CurrentObject> {
        self.0.get(name)
    }

    /// Returns Manifest Entries, i.e. excluding the manifest itself
    pub fn mft_entries(&self) -> Vec<FileAndHash<Bytes, Bytes>> {
        self.0.keys().filter(|k| !k.as_ref().ends_with("mft")).map(|k| {
            let name_bytes = Bytes::from(k.as_str());
            let hash_bytes = self.0[k].content.to_encoded_hash().into();
            FileAndHash::new(name_bytes, hash_bytes)
        }).collect()
    }
}


//------------ AllCurrentObjects ---------------------------------------------

/// This type contains a mapping of all name spaces for parent & resource
/// classes to CurrentObjects for each space.
pub struct AllCurrentObjects<'a>(HashMap<&'a str, &'a CurrentObjects>);

impl<'a> AllCurrentObjects<'a> {
    pub fn empty() -> Self {
        AllCurrentObjects(HashMap::new())
    }

    pub fn for_name_space(
        name_space: &'a str,
        current_objects: &'a CurrentObjects
    ) -> Self {
        let mut res = Self::empty();
        res.add_name_space(name_space, current_objects);
        res
    }

    pub fn add_name_space(
        &mut self,
        name_space: &'a str,
        current_objects: &'a CurrentObjects
    ) {
        self.0.insert(name_space, current_objects);
    }
}


//------------ Revocation ----------------------------------------------------

/// A Crl Revocation. Note that this type differs from CrlEntry in
/// that it implements De/Serialize and Eq/PartialEq
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    serial: Serial,
    revocation_date: Time
}

impl From<&CurrentObject> for Revocation {
    fn from(co: &CurrentObject) -> Self {
        Revocation {
            serial: co.serial,
            revocation_date: Time::now()
        }
    }
}

impl From<&Manifest> for Revocation {
    fn from(m: &Manifest) -> Self {
        let serial = m.cert().serial_number();
        let revocation_date = Time::now();
        Revocation { serial, revocation_date }
    }
}


//------------ Revocations ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        self.0.iter()
            .map(|r| CrlEntry::new(r.serial, r.revocation_date))
            .collect()
    }

    /// Purges all expired revocations, and returns them.
    pub fn purge(&mut self) -> Vec<Revocation> {

        let (relevant, expired) = self.0.iter().partition(|r| {
            r.revocation_date.validate_not_after(Time::now()).is_ok()
        });
        self.0 = relevant;
        expired
    }

    pub fn add(&mut self, revocation: Revocation) {
        self.0.push(revocation);
    }

    pub fn apply_delta(&mut self, delta: RevocationsDelta) {
        self.0.retain(|r| !delta.dropped.contains(r));
        for r in delta.added {
            self.add(r);
        }
    }
}

impl Default for Revocations {
    fn default() -> Self {
        Revocations(vec![])
    }
}


//------------ RevocationsDelta ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationsDelta {
    added: Vec<Revocation>,
    dropped: Vec<Revocation>
}

impl Default for RevocationsDelta {
    fn default() -> Self {
        RevocationsDelta {
            added: vec![],
            dropped: vec![]
        }
    }
}

impl RevocationsDelta {
    pub fn add(&mut self, revocation: Revocation) {
        self.added.push(revocation);
    }
    pub fn drop(&mut self, revocation: Revocation) {
        self.dropped.push(revocation);
    }
}

//------------ CurrentObjectSet ----------------------------------------------

/// This type describes the complete current set of objects for CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSet {
    this_update: Time,
    next_update: Time,
    number: u64,
    revocations: Revocations,
    objects: CurrentObjects
}

impl Default for CurrentObjectSet {
    fn default() -> Self {
        CurrentObjectSet {
            this_update: Time::now(),
            next_update: Time::tomorrow(),
            number: 1,
            revocations: Revocations::default(),
            objects: CurrentObjects::default()
        }
    }
}

impl CurrentObjectSet {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn revocations(&self) -> &Revocations {
        &self.revocations
    }
    pub fn objects(&self) -> &CurrentObjects {
        &self.objects
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.this_update = delta.this_update;
        self.next_update = delta.next_update;
        self.number = delta.number;
        self.revocations.apply_delta(delta.revocations);
        self.objects.apply_delta(delta.objects)
    }
}


//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationDelta {
    this_update: Time,
    next_update: Time,
    number: u64,
    revocations: RevocationsDelta,
    objects: ObjectsDelta
}

impl PublicationDelta {
    pub fn new(
        this_update: Time,
        next_update: Time,
        number: u64,
        revocations: RevocationsDelta,
        objects: ObjectsDelta
    ) -> Self {
        PublicationDelta {
            this_update, next_update, number, revocations, objects
        }
    }

    pub fn objects(&self) -> &ObjectsDelta {
        &self.objects
    }
}


//------------ ObjectsDelta --------------------------------------------------

/// This type defines the changes to be published under a resource class,
/// so it includes the base 'ca_repo' and all objects that are added,
/// updated, or withdrawn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectsDelta {
    ca_repo: uri::Rsync,
    added: Vec<AddedObject>,
    updated: Vec<UpdatedObject>,
    withdrawn: Vec<WithdrawnObject>
}

impl ObjectsDelta {
    /// Creates an empty ObjectsDelta for a key. Requires the ca_repo uri
    /// for this key.
    pub fn new(ca_repo: uri::Rsync) -> Self {
        ObjectsDelta {
            ca_repo,
            added: vec![],
            updated: vec![],
            withdrawn: vec![]
        }
    }

    pub fn add(&mut self, added: AddedObject) {
        self.added.push(added);
    }
    pub fn update(&mut self, updated: UpdatedObject) {
        self.updated.push(updated);
    }
    pub fn withdraw(&mut self, withdrawn: WithdrawnObject) {
        self.withdrawn.push(withdrawn);
    }
}

impl Into<publication::PublishDelta> for ObjectsDelta {
    fn into(self) -> publication::PublishDelta {
        let mut builder = publication::PublishDeltaBuilder::new();

        for a in self.added.into_iter() {
            let publish = publication::Publish::new(
                None,
                self.ca_repo.join(a.name.as_bytes()),
                a.object.content
            );
            builder.add_publish(publish);
        }
        for u in self.updated.into_iter() {
            let update = publication::Update::new(
                None,
                self.ca_repo.join(u.name.as_bytes()),
                u.object.content,
                u.old
            );
            builder.add_update(update);
        }
        for w in self.withdrawn.into_iter() {
            let withdraw = publication::Withdraw::new(
                None,
                self.ca_repo.join(w.name.as_bytes()),
                w.hash
            );
            builder.add_withdraw(withdraw);
        }
        builder.finish()
    }
}


//------------ AddedObject ---------------------------------------------------

/// An object that is newly added to the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddedObject {
    name: ObjectName,
    object: CurrentObject
}

impl AddedObject {
    pub fn new(
        name: ObjectName,
        object: CurrentObject
    ) -> Self {
        AddedObject { name, object }
    }
}

//------------ UpdatedObject -------------------------------------------------

/// A new object that replaces an earlier version by this name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdatedObject {
    name: ObjectName,
    object: CurrentObject,
    old: EncodedHash
}

impl UpdatedObject {
    pub fn new(
        name: ObjectName,
        object: CurrentObject,
        old: EncodedHash
    ) -> Self {
        UpdatedObject { name, object, old }
    }
}


//------------ WithdrawnObject -----------------------------------------------

/// An object that is to be withdrawn from the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: EncodedHash
}

impl WithdrawnObject {
    pub fn new(
        name: ObjectName,
        hash: EncodedHash
    ) -> Self {
        WithdrawnObject { name, hash}
    }
}


//------------ ResourceSet ---------------------------------------------------

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSet {
    asn: AsResources,
    v4: Ipv4Resources,
    v6: Ipv6Resources
}

impl ResourceSet {
    pub fn from_strs(asn: &str, v4: &str, v6: &str) -> Result<Self, ResSetErr> {
        let asn = AsResources::from_str(asn).map_err(|_| ResSetErr::Asn)?;
        let v4 = Ipv4Resources::from_str(v4).map_err(|_| ResSetErr::V4)?;
        let v6 = Ipv6Resources::from_str(v6).map_err(|_| ResSetErr::V6)?;
        Ok(ResourceSet { asn , v4, v6 })
    }

    pub fn all_resources() -> Self {
        let asns = "AS0-AS4294967295";
        let v4 = "0.0.0.0/0";
        let v6 = "::/0";
        ResourceSet::from_strs(asns, v4, v6).unwrap()
    }

    pub fn asn(&self) -> &AsResources {
        &self.asn
    }

    pub fn v4(&self) -> &Ipv4Resources {
        &self.v4
    }

    pub fn v6(&self) -> &Ipv6Resources {
        &self.v6
    }

    /// Check of the other set is contained by this set. If this set
    /// contains inherited resources, then any explicit corresponding
    /// resources in the other set will be considered to fall outside of
    /// this set.
    pub fn contains(&self, other: &ResourceSet) -> bool {
        if (self.asn.is_inherited() && ! other.asn.is_inherited()) ||
           (self.v4.is_inherited() && ! other.v4.is_inherited())||
           (self.v6.is_inherited() && ! other.v6.is_inherited()) {
            return false;
        }

        if let Some(asn) = self.asn.as_blocks() {


            if asn.validate_issued(
                Some(&other.asn),
                Overclaim::Refuse
            ).is_err() {
                return false;
            }
        }

        if let Some(v4) = self.v4.as_blocks() {
            if v4.validate_issued(
                Some(&other.v4),
                Overclaim::Refuse
            ).is_err() {
                return false;
            }
        }

        if let Some(v6) = self.v6.as_blocks() {
            if v6.validate_issued(
                Some(&other.v6),
                Overclaim::Refuse
            ).is_err() {
                return false;
            }
        }

        true
    }
}

impl Default for ResourceSet {
    fn default() -> Self {
        ResourceSet {
            asn: AsResources::blocks(AsBlocks::empty()),
            v4: Ipv4Resources::blocks(IpBlocks::empty()),
            v6: Ipv6Resources::blocks(IpBlocks::empty()),
        }
    }
}

impl From<&Cert> for ResourceSet {
    fn from(cert: &Cert) -> Self {
        let asn = match cert.as_resources() {
            None => AsResources::blocks(AsBlocks::empty()),
            Some(set) => set.clone()
        };

        let v4 = {
            let v4 = match cert.v4_resources() {
                None => IpResources::blocks(IpBlocks::empty()),
                Some(res) => res.clone()
            };
            match v4.to_blocks() {
                Ok(blocks) => Ipv4Resources::blocks(blocks),
                Err(_) => Ipv4Resources::inherit()
            }
        };

        let v6 = {
            let v6 = match cert.v6_resources() {
                None => IpResources::blocks(IpBlocks::empty()),
                Some(res) => res.clone()
            };
            match v6.to_blocks() {
                Ok(blocks) => Ipv6Resources::blocks(blocks),
                Err(_) => Ipv6Resources::inherit()
            }
        };


        ResourceSet { asn, v4, v6 }
    }
}


//------------ TrustAnchorInfo -----------------------------------------------

/// This type represents the TrustAnchor details that need to be accessible
/// through the API (CLI and UI).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorInfo {
    resources: ResourceSet,
    repo_info: RepoInfo,
    children: HashMap<Handle, ChildCaDetails>,
    cert:     RcvdCert,
    tal:      TrustAnchorLocator
}

impl TrustAnchorInfo {
    pub fn new(
        resources: ResourceSet,
        repo_info: RepoInfo,
        children: HashMap<Handle, ChildCaDetails>,
        cert:     RcvdCert,
        tal: TrustAnchorLocator
    ) -> Self {

        TrustAnchorInfo {
            resources,
            repo_info,
            children,
            cert,
            tal
        }
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn children(&self) -> &HashMap<Handle, ChildCaDetails> {
        &self.children
    }

    pub fn cert(&self) -> &RcvdCert {
        &self.cert
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }
}

//------------ ResSetErr -----------------------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ResSetErr {
    #[display(fmt="Cannot parse ASN resources")]
    Asn,

    #[display(fmt="Cannot parse IPv4 resources")]
    V4,

    #[display(fmt="Cannot parse IPv6 resources")]
    V6,

    #[display(fmt="Mixed Address Families in configured resource set")]
    Mix,
}


//============ Tests =========================================================

#[cfg(test)]
mod test {

    use super::*;
    use bytes::Bytes;

    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;
    use crate::util::test;
    use crate::util::softsigner::OpenSslSigner;

    fn base_uri() -> uri::Rsync {
        test::rsync("rsync://localhost/repo/ta/")
    }

    fn rrdp_uri() -> uri::Https {
        test::https("https://localhost/rrdp/notification.xml")
    }

    fn info() -> RepoInfo {
        RepoInfo { base_uri: base_uri(), rpki_notify: rrdp_uri() }
    }

    #[test]
    fn signed_objects_uri() {
        let signed_objects_uri = info().ca_repository("");
        assert_eq!(base_uri(), signed_objects_uri)
    }

    #[test]
    fn mft_uri() {
        test::test_under_tmp(|d| {
            let mut signer = OpenSslSigner::build(&d).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::default()).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().rpki_manifest("", &pub_key.key_identifier());

            unsafe {
                use std::str;

                let mft_path = str::from_utf8_unchecked(
                    mft_uri.relative_to(&base_uri()).unwrap()
                );

                assert_eq!(44, mft_path.len());

                // the file name should be the hexencoded pub key info
                // not repeating that here, but checking that the name
                // part is validly hex encoded.
                let name = &mft_path[..40];
                hex::decode(name).unwrap();

                // and the extension is '.mft'
                let ext = &mft_path[40..];
                assert_eq!(ext, ".mft");
            }
        });
    }

    #[test]
    fn serialize_deserialize_asn_blocks() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "";
        let ipv6s = "";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }

    #[test]
    fn serialize_deserialize_resource_set() {
        let asns = "inherit";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }

    #[test]
    fn serialize_deserialise_repo_info() {
        let info = RepoInfo::new(
            test::rsync("rsync://some/module/folder/"),
            test::https("https://host/notification.xml")
        );

        let json = serde_json::to_string(&info).unwrap();
        let deser_info = serde_json::from_str(&json).unwrap();

        assert_eq!(info, deser_info);
    }

    #[test]
    fn create_and_display_tal() {
        let der = include_bytes!("../../test-resources/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();
        let uri = test::https("https://localhost/ta.cer");

        let tal = TrustAnchorLocator::new(vec![uri], &cert);

        let expected_tal = include_str!("../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);

    }
}
