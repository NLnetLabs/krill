//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::{from_utf8_unchecked, FromStr};
use std::{fmt, ops, str};

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::cert::Cert;
use rpki::crl::{Crl, CrlEntry};
use rpki::crypto::KeyIdentifier;
use rpki::manifest::{FileAndHash, Manifest};
use rpki::resources::{AsBlocks, AsResources, IpBlocks, IpBlocksForFamily, IpResources};
use rpki::roa::Roa;
use rpki::uri;
use rpki::x509::{Serial, Time};

use crate::commons::api::publication;
use crate::commons::api::publication::Publish;
use crate::commons::api::{
    Base64, ChildHandle, Handle, HexEncodedHash, IssuanceRequest, ListReply, ParentCaContact,
    ParentHandle, RepositoryContact, RequestResourceLimit, RoaDefinition,
};
use crate::commons::eventsourcing::AggregateHistory;
use crate::commons::remote::id::IdCert;
use crate::commons::util::ext_serde;
use crate::daemon::ca::{self, CertAuth, RouteAuthorization, Signer};

//------------ ResourceClassName -------------------------------------------

/// This type represents a resource class name, as used in RFC6492. The protocol
/// allows for any arbitrary set of utf8 characters to be used as the name, though
/// in practice names can be expected to be short and plain ascii or even numbers.
///
/// We store the name in a Bytes for cheap cloning, as these names need to be passed
/// around quite a bit and end up being stored as owned values in events.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceClassName {
    name: Bytes,
}

impl Default for ResourceClassName {
    fn default() -> ResourceClassName {
        ResourceClassName::from(0)
    }
}

impl From<u32> for ResourceClassName {
    fn from(nr: u32) -> ResourceClassName {
        ResourceClassName {
            name: Bytes::from(format!("{}", nr)),
        }
    }
}

impl From<&str> for ResourceClassName {
    fn from(s: &str) -> ResourceClassName {
        ResourceClassName {
            name: Bytes::from(s),
        }
    }
}

impl From<String> for ResourceClassName {
    fn from(s: String) -> ResourceClassName {
        ResourceClassName {
            name: Bytes::from(s),
        }
    }
}

impl fmt::Display for ResourceClassName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = unsafe { from_utf8_unchecked(self.name.as_ref()) };
        write!(f, "{}", s)
    }
}

impl Serialize for ResourceClassName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceClassName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ResourceClassName, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Ok(ResourceClassName::from(string))
    }
}

//------------ IdCertPem -----------------------------------------------------

/// A PEM encoded IdCert and sha256 of the encoding, for easier
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdCertPem {
    pem: String,
    hash: HexEncodedHash,
}

impl IdCertPem {
    pub fn pem(&self) -> &str {
        &self.pem
    }

    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
}

impl From<&IdCert> for IdCertPem {
    fn from(cer: &IdCert) -> Self {
        let base64 = base64::encode(&cer.to_bytes());
        let mut pem = "-----BEGIN CERTIFICATE-----\n".to_string();

        for line in base64
            .as_bytes()
            .chunks(64)
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
        {
            pem.push_str(line);
            pem.push_str("\n");
        }

        pem.push_str("-----END CERTIFICATE-----\n");

        let hash = HexEncodedHash::from_content(pem.as_bytes());

        IdCertPem { pem, hash }
    }
}

//------------ ChildCaInfo ---------------------------------------------------

/// This type represents information about a child CA that is shared through the API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaInfo {
    id_cert: Option<IdCertPem>,
    entitled_resources: ResourceSet,
}

impl ChildCaInfo {
    pub fn new(id_cert: Option<&IdCert>, entitled_resources: ResourceSet) -> Self {
        ChildCaInfo {
            id_cert: id_cert.map(IdCertPem::from),
            entitled_resources,
        }
    }

    pub fn id_cert(&self) -> Option<&IdCertPem> {
        self.id_cert.as_ref()
    }

    pub fn entitled_resources(&self) -> &ResourceSet {
        &self.entitled_resources
    }
}

impl fmt::Display for ChildCaInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(id) = &self.id_cert {
            writeln!(f, "{}", id.pem())?;
            writeln!(f, "SHA256 hash of PEM encoded certificate: {}", id.hash())?;
        }
        writeln!(f, "resources: {}", self.entitled_resources)
    }
}

//------------ RevokedObject -------------------------------------------------

pub type RevokedObject = ReplacedObject;

//------------ ReplacedObject ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplacedObject {
    revocation: Revocation,
    hash: HexEncodedHash,
}

impl ReplacedObject {
    pub fn new(revocation: Revocation, hash: HexEncodedHash) -> Self {
        ReplacedObject { revocation, hash }
    }

    pub fn revocation(&self) -> Revocation {
        self.revocation
    }

    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
}

impl From<&Cert> for ReplacedObject {
    fn from(c: &Cert) -> Self {
        let revocation = Revocation::from(c);
        let hash = HexEncodedHash::from_content(c.to_captured().as_slice());
        ReplacedObject { revocation, hash }
    }
}

impl From<&IssuedCert> for ReplacedObject {
    fn from(issued: &IssuedCert) -> Self {
        Self::from(issued.cert())
    }
}

impl From<&CurrentObject> for ReplacedObject {
    fn from(current: &CurrentObject) -> Self {
        let revocation = Revocation::from(current);
        let hash = current.to_hex_hash();
        ReplacedObject { revocation, hash }
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
    uri: uri::Rsync,             // where this cert is published
    limit: RequestResourceLimit, // the limit on the request
    resource_set: ResourceSet,
    cert: Cert,
    replaces: Option<ReplacedObject>,
}

impl IssuedCert {
    pub fn new(
        uri: uri::Rsync,
        limit: RequestResourceLimit,
        resource_set: ResourceSet,
        cert: Cert,
        replaces: Option<ReplacedObject>,
    ) -> Self {
        IssuedCert {
            uri,
            limit,
            resource_set,
            cert,
            replaces,
        }
    }

    pub fn unpack(self) -> (uri::Rsync, RequestResourceLimit, ResourceSet, Cert) {
        (self.uri, self.limit, self.resource_set, self.cert)
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn limit(&self) -> &RequestResourceLimit {
        &self.limit
    }
    pub fn resource_set(&self) -> &ResourceSet {
        &self.resource_set
    }
    pub fn cert(&self) -> &Cert {
        &self.cert
    }
    pub fn replaces(&self) -> Option<&ReplacedObject> {
        self.replaces.as_ref()
    }
}

impl PartialEq for IssuedCert {
    fn eq(&self, other: &IssuedCert) -> bool {
        self.uri == other.uri
            && self.limit == other.limit
            && self.resource_set == other.resource_set
            && self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for IssuedCert {}

impl Deref for IssuedCert {
    type Target = Cert;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

//------------ RcvdCert ------------------------------------------------------

/// Contains a CA Certificate that has been issued to this CA, for some key.
///
/// Note, this may be a self-signed TA Certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RcvdCert {
    cert: Cert,
    uri: uri::Rsync,
    resources: ResourceSet,
}

impl RcvdCert {
    pub fn new(cert: Cert, uri: uri::Rsync, resources: ResourceSet) -> Self {
        RcvdCert {
            cert,
            uri,
            resources,
        }
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    /// The name of the CRL published by THIS certificate.
    pub fn crl_name(&self) -> ObjectName {
        ObjectName::new(&self.cert.subject_key_identifier(), "crl")
    }

    /// The URI of the CRL published BY THIS certificate, i.e. the uri to use
    /// on certs issued by this.
    pub fn crl_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.crl_name())
    }

    /// The name of the MFT published by THIS certificate.
    pub fn mft_name(&self) -> ObjectName {
        ObjectName::new(&self.cert.subject_key_identifier(), "mft")
    }

    /// Return the CA repository URI where this certificate publishes.
    pub fn ca_repository(&self) -> &uri::Rsync {
        self.cert().ca_repository().unwrap()
    }

    /// The URI of the MFT published by THIS certificate.
    pub fn mft_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.mft_name())
    }

    pub fn uri_for_object(&self, name: impl Into<ObjectName>) -> uri::Rsync {
        let name: ObjectName = name.into();
        self.cert.ca_repository().unwrap().join(name.as_bytes())
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn der_encoded(&self) -> Bytes {
        self.cert.to_captured().into_bytes()
    }
}

impl From<IssuedCert> for RcvdCert {
    fn from(issued: IssuedCert) -> Self {
        RcvdCert {
            cert: issued.cert,
            uri: issued.uri,
            resources: issued.resource_set,
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
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes()
            && self.uri == other.uri
    }
}

impl Eq for RcvdCert {}

//------------ TrustAnchorLocator --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>, // We won't create TALs with rsync, this is not for parsing.

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes"
    )]
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
                writeln!(f, "{}", &base64[i * wrap..i * wrap + wrap])?;
            } else {
                write!(f, "{}", &base64[i * wrap..])?;
            }
        }

        Ok(())
    }
}

//------------ RepoInfo ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rpki_notify: uri::Https,
}

impl RepoInfo {
    pub fn new(base_uri: uri::Rsync, rpki_notify: uri::Https) -> Self {
        RepoInfo {
            base_uri,
            rpki_notify,
        }
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    /// Returns the ca repository uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn ca_repository(&self, name_space: &str) -> uri::Rsync {
        match name_space {
            "" => self.base_uri.clone(),
            _ => self.base_uri.join(name_space.as_ref()),
        }
    }

    /// Returns the rpki manifest uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn rpki_manifest(&self, name_space: &str, signing_key: &KeyIdentifier) -> uri::Rsync {
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
        self.base_uri == other.base_uri && self.rpki_notify.as_str() == other.rpki_notify.as_str()
    }
}

impl Eq for RepoInfo {}

//------------ PendingKeyInfo ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKeyInfo {
    key_id: KeyIdentifier,
}

impl PendingKeyInfo {
    pub fn new(key_id: KeyIdentifier) -> Self {
        PendingKeyInfo { key_id }
    }
}

//------------ CertifiedKeyInfo ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CertifiedKeyInfo {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    request: Option<IssuanceRequest>,
}

impl CertifiedKeyInfo {
    pub fn new(key_id: KeyIdentifier, incoming_cert: RcvdCert) -> Self {
        CertifiedKeyInfo {
            key_id,
            incoming_cert,
            request: None,
        }
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn incoming_cert(&self) -> &RcvdCert {
        &self.incoming_cert
    }
    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
}

//------------ CurrentObject -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObject {
    content: Base64,
    serial: Serial,
    expires: Time,
}

impl CurrentObject {
    pub fn content(&self) -> &Base64 {
        &self.content
    }
    pub fn serial(&self) -> Serial {
        self.serial
    }
    pub fn expires(&self) -> Time {
        self.expires
    }

    pub fn to_hex_hash(&self) -> HexEncodedHash {
        let bytes = self.content.to_bytes();
        HexEncodedHash::from_content(bytes.as_ref())
    }
}

impl From<&Cert> for CurrentObject {
    fn from(cert: &Cert) -> Self {
        let content = Base64::from(cert);
        let serial = cert.serial_number();
        let expires = cert.validity().not_after();
        CurrentObject {
            content,
            serial,
            expires,
        }
    }
}

impl From<&Crl> for CurrentObject {
    fn from(crl: &Crl) -> Self {
        let content = Base64::from(crl);
        let serial = crl.crl_number(); // never revoked
        let expires = crl.next_update();

        CurrentObject {
            content,
            serial,
            expires,
        }
    }
}

impl From<&Manifest> for CurrentObject {
    fn from(mft: &Manifest) -> Self {
        let content = Base64::from(mft);
        let serial = mft.cert().serial_number();
        let expires = mft.content().next_update();

        CurrentObject {
            content,
            serial,
            expires,
        }
    }
}

impl From<&Roa> for CurrentObject {
    fn from(roa: &Roa) -> Self {
        let content = Base64::from(roa);
        let serial = roa.cert().serial_number();
        let expires = roa.cert().validity().not_after();

        CurrentObject {
            content,
            serial,
            expires,
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
        ObjectName(format!("{}.{}", ki, extension))
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

impl From<&RouteAuthorization> for ObjectName {
    fn from(auth: &RouteAuthorization) -> Self {
        ObjectName(format!("{}.roa", hex::encode(auth.to_string())))
    }
}

impl From<&RoaDefinition> for ObjectName {
    fn from(def: &RoaDefinition) -> Self {
        ObjectName(format!("{}.roa", hex::encode(def.to_string())))
    }
}

impl Into<Bytes> for ObjectName {
    fn into(self) -> Bytes {
        Bytes::from(self.0)
    }
}

impl AsRef<str> for ObjectName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
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
    pub fn insert(&mut self, name: ObjectName, object: CurrentObject) -> Option<CurrentObject> {
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

    pub fn deactivate(&mut self) {
        self.0
            .retain(|name, _| name.ends_with(".mft") || name.ends_with(".crl"))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &ObjectName> {
        self.0.keys()
    }

    pub fn object_for(&self, name: &ObjectName) -> Option<&CurrentObject> {
        self.0.get(name)
    }

    /// Returns withdraws for all the objects in this set. E.g. when the resource
    /// class containing this set is removed, or the key is destroyed.
    pub fn withdraw(&self) -> Vec<WithdrawnObject> {
        self.0
            .iter()
            .map(|(name, object)| WithdrawnObject::for_current(name.clone(), object))
            .collect()
    }

    /// Returns publish's for all objects in this set.
    pub fn publish(&self, base_uri: &RepoInfo, name_space: &str) -> Vec<Publish> {
        let ca_repo = base_uri.ca_repository(name_space);
        self.0
            .iter()
            .map(|(name, object)| {
                Publish::new(None, ca_repo.join(name.as_bytes()), object.content.clone())
            })
            .collect()
    }

    /// Returns Manifest Entries, i.e. excluding the manifest itself
    pub fn mft_entries(&self) -> Vec<FileAndHash<Bytes, Bytes>> {
        self.0
            .keys()
            .filter(|k| !k.as_ref().ends_with("mft"))
            .map(|k| {
                let name_bytes = Bytes::from(k.as_str());
                let hash_bytes = self.0[k].content.to_encoded_hash().into();
                FileAndHash::new(name_bytes, hash_bytes)
            })
            .collect()
    }
}

impl ops::Add for CurrentObjects {
    type Output = CurrentObjects;

    fn add(self, other: CurrentObjects) -> CurrentObjects {
        let mut map = self.0;
        for (name, object) in other.0.into_iter() {
            map.insert(name, object);
        }
        CurrentObjects(map)
    }
}

//------------ Revocation ----------------------------------------------------

/// A Crl Revocation. Note that this type differs from CrlEntry in
/// that it implements De/Serialize and Eq/PartialEq
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    serial: Serial,
    expires: Time,
}

impl From<&CurrentObject> for Revocation {
    fn from(co: &CurrentObject) -> Self {
        Revocation {
            serial: co.serial(),
            expires: co.expires(),
        }
    }
}

impl From<&Cert> for Revocation {
    fn from(cer: &Cert) -> Self {
        Revocation {
            serial: cer.serial_number(),
            expires: cer.validity().not_after(),
        }
    }
}

impl From<&Manifest> for Revocation {
    fn from(m: &Manifest) -> Self {
        Self::from(m.cert())
    }
}

impl From<&Roa> for Revocation {
    fn from(r: &Roa) -> Self {
        Self::from(r.cert())
    }
}

//------------ Revocations ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        self.0
            .iter()
            .map(|r| CrlEntry::new(r.serial, r.expires))
            .collect()
    }

    /// Purges all expired revocations, and returns them.
    pub fn purge(&mut self) -> Vec<Revocation> {
        let (relevant, expired) = self.0.iter().partition(|r| r.expires > Time::now());
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
    dropped: Vec<Revocation>,
}

impl Default for RevocationsDelta {
    fn default() -> Self {
        RevocationsDelta {
            added: vec![],
            dropped: vec![],
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
pub struct CurrentObjectSetInfo {
    this_update: Time,
    next_update: Time,
    number: u64,
    revocations: Revocations,
    objects: CurrentObjects,
}

impl Default for CurrentObjectSetInfo {
    fn default() -> Self {
        CurrentObjectSetInfo {
            this_update: Time::now(),
            next_update: Time::tomorrow(),
            number: 1,
            revocations: Revocations::default(),
            objects: CurrentObjects::default(),
        }
    }
}

impl CurrentObjectSetInfo {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn revocations(&self) -> &Revocations {
        &self.revocations
    }
    pub fn objects(&self) -> &CurrentObjects {
        &self.objects
    }
}

//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationDeltaInfo {
    this_update: Time,
    next_update: Time,
    number: u64,
    revocations: RevocationsDelta,
    objects: ObjectsDelta,
}

impl PublicationDeltaInfo {
    pub fn new(
        this_update: Time,
        next_update: Time,
        number: u64,
        revocations: RevocationsDelta,
        objects: ObjectsDelta,
    ) -> Self {
        PublicationDeltaInfo {
            this_update,
            next_update,
            number,
            revocations,
            objects,
        }
    }

    pub fn unpack(self) -> (Time, Time, u64, RevocationsDelta, ObjectsDelta) {
        (
            self.this_update,
            self.next_update,
            self.number,
            self.revocations,
            self.objects,
        )
    }

    pub fn objects(&self) -> &ObjectsDelta {
        &self.objects
    }
}

impl Into<publication::PublishDelta> for PublicationDeltaInfo {
    fn into(self) -> publication::PublishDelta {
        self.objects.into()
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
    withdrawn: Vec<WithdrawnObject>,
}

impl ObjectsDelta {
    /// Creates an empty ObjectsDelta for a key. Requires the ca_repo uri
    /// for this key.
    pub fn new(ca_repo: uri::Rsync) -> Self {
        ObjectsDelta {
            ca_repo,
            added: vec![],
            updated: vec![],
            withdrawn: vec![],
        }
    }

    pub fn add(&mut self, added: AddedObject) {
        self.added.push(added);
    }

    pub fn added(&self) -> &Vec<AddedObject> {
        &self.added
    }

    pub fn update(&mut self, updated: UpdatedObject) {
        self.updated.push(updated);
    }

    pub fn updated(&self) -> &Vec<UpdatedObject> {
        &self.updated
    }

    pub fn withdraw(&mut self, withdrawn: WithdrawnObject) {
        self.withdrawn.push(withdrawn);
    }

    pub fn withdrawn(&self) -> &Vec<WithdrawnObject> {
        &self.withdrawn
    }

    pub fn len(&self) -> usize {
        self.added.len() + self.updated.len() + self.withdrawn.len()
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.withdrawn.is_empty()
    }
}

impl Into<publication::PublishDelta> for ObjectsDelta {
    fn into(self) -> publication::PublishDelta {
        let mut builder = publication::PublishDeltaBuilder::new();

        for a in self.added.into_iter() {
            let publish = publication::Publish::new(
                None,
                self.ca_repo.join(a.name.as_bytes()),
                a.object.content,
            );
            builder.add_publish(publish);
        }
        for u in self.updated.into_iter() {
            let update = publication::Update::new(
                None,
                self.ca_repo.join(u.name.as_bytes()),
                u.object.content,
                u.old,
            );
            builder.add_update(update);
        }
        for w in self.withdrawn.into_iter() {
            let withdraw =
                publication::Withdraw::new(None, self.ca_repo.join(w.name.as_bytes()), w.hash);
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
    object: CurrentObject,
}

impl AddedObject {
    pub fn new(name: ObjectName, object: CurrentObject) -> Self {
        AddedObject { name, object }
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn object(&self) -> &CurrentObject {
        &self.object
    }
}

impl From<&Cert> for AddedObject {
    fn from(cert: &Cert) -> Self {
        let name = ObjectName::from(cert);
        let object = CurrentObject::from(cert);
        AddedObject { name, object }
    }
}

//------------ UpdatedObject -------------------------------------------------

/// A new object that replaces an earlier version by this name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdatedObject {
    name: ObjectName,
    object: CurrentObject,
    old: HexEncodedHash,
}

impl UpdatedObject {
    pub fn new(name: ObjectName, object: CurrentObject, old: HexEncodedHash) -> Self {
        UpdatedObject { name, object, old }
    }

    pub fn for_cert(new: &Cert, old: HexEncodedHash) -> Self {
        let name = ObjectName::from(new);
        let object = CurrentObject::from(new);
        UpdatedObject { name, object, old }
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn object(&self) -> &CurrentObject {
        &self.object
    }

    pub fn old(&self) -> &HexEncodedHash {
        &self.old
    }
}

//------------ WithdrawnObject -----------------------------------------------

/// An object that is to be withdrawn from the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: HexEncodedHash,
}

impl WithdrawnObject {
    pub fn new(name: ObjectName, hash: HexEncodedHash) -> Self {
        WithdrawnObject { name, hash }
    }

    pub fn for_current(name: ObjectName, current: &CurrentObject) -> Self {
        WithdrawnObject {
            name,
            hash: current.to_hex_hash(),
        }
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }
}

impl From<&Cert> for WithdrawnObject {
    fn from(c: &Cert) -> Self {
        let name = ObjectName::from(c);
        let hash = HexEncodedHash::from_content(c.to_captured().as_slice());
        WithdrawnObject { name, hash }
    }
}

//------------ ResourceSet ---------------------------------------------------

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceSet {
    asn: AsBlocks,

    #[serde(
        deserialize_with = "ext_serde::de_ip_blocks_4",
        serialize_with = "ext_serde::ser_ip_blocks_4"
    )]
    v4: IpBlocks,

    #[serde(
        deserialize_with = "ext_serde::de_ip_blocks_6",
        serialize_with = "ext_serde::ser_ip_blocks_6"
    )]
    v6: IpBlocks,
}

impl ResourceSet {
    pub fn new(asn: AsBlocks, v4: IpBlocks, v6: IpBlocks) -> Self {
        ResourceSet { asn, v4, v6 }
    }

    pub fn from_strs(asn: &str, v4: &str, v6: &str) -> Result<Self, ResSetErr> {
        let asn = AsBlocks::from_str(asn).map_err(|_| ResSetErr::Asn)?;
        if v4.contains(':') || v6.contains('.') {
            return Err(ResSetErr::Mix);
        }
        let v4 = IpBlocks::from_str(v4).map_err(|_| ResSetErr::V4)?;
        let v6 = IpBlocks::from_str(v6).map_err(|_| ResSetErr::V6)?;
        Ok(ResourceSet { asn, v4, v6 })
    }

    pub fn all_resources() -> Self {
        let asns = "AS0-AS4294967295";
        let v4 = "0.0.0.0/0";
        let v6 = "::/0";
        ResourceSet::from_strs(asns, v4, v6).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self == &ResourceSet::default()
    }

    pub fn asn(&self) -> &AsBlocks {
        &self.asn
    }

    pub fn v4(&self) -> IpBlocksForFamily {
        self.v4.as_v4()
    }

    pub fn v6(&self) -> IpBlocksForFamily {
        self.v6.as_v6()
    }

    pub fn to_as_resources(&self) -> AsResources {
        AsResources::blocks(self.asn.clone())
    }

    pub fn to_ip_resources_v4(&self) -> IpResources {
        IpResources::blocks(self.v4.clone())
    }

    pub fn to_ip_resources_v6(&self) -> IpResources {
        IpResources::blocks(self.v6.clone())
    }

    /// Apply a limit to this set, will return an error in case the limit
    /// exceeds the set.
    pub fn apply_limit(&self, limit: &RequestResourceLimit) -> Result<Self, ResSetErr> {
        if limit.is_empty() {
            return Ok(self.clone());
        }

        let asn = {
            match limit.asn() {
                None => self.asn.clone(),
                Some(asn) => {
                    if self.asn.contains(asn) {
                        asn.clone()
                    } else {
                        return Err(ResSetErr::LimitExceedsResources);
                    }
                }
            }
        };

        let v4 = {
            match limit.v4() {
                None => self.v4.clone(),
                Some(v4) => {
                    if self.v4.contains(v4) {
                        v4.clone()
                    } else {
                        return Err(ResSetErr::LimitExceedsResources);
                    }
                }
            }
        };

        let v6 = {
            match limit.v6() {
                None => self.v6.clone(),
                Some(v6) => {
                    if self.v6.contains(v6) {
                        v6.clone()
                    } else {
                        return Err(ResSetErr::LimitExceedsResources);
                    }
                }
            }
        };

        Ok(ResourceSet { asn, v4, v6 })
    }

    /// Check of the other set is contained by this set. If this set
    /// contains inherited resources, then any explicit corresponding
    /// resources in the other set will be considered to fall outside of
    /// this set.
    pub fn contains(&self, other: &ResourceSet) -> bool {
        self.asn.contains(other.asn()) && self.v4.contains(&other.v4) && self.v6.contains(&other.v6)
    }

    /// Returns the union of this ResourceSet and the other. I.e. a new
    /// ResourceSet containing all resources found in one or both.
    pub fn union(&self, other: &ResourceSet) -> Self {
        let asn = self.asn.union(&other.asn);
        let v4 = self.v4.union(&other.v4);
        let v6 = self.v6.union(&other.v6);
        ResourceSet { asn, v4, v6 }
    }

    /// Returns the intersection of this ResourceSet and the other. I.e. a new
    /// ResourceSet containing all resources found in both sets.
    pub fn intersection(&self, other: &ResourceSet) -> Self {
        let asn = self.asn.intersection(&other.asn);
        let v4 = self.v4.intersection(&other.v4);
        let v6 = self.v6.intersection(&other.v6);
        ResourceSet { asn, v4, v6 }
    }
}

impl Default for ResourceSet {
    fn default() -> Self {
        ResourceSet {
            asn: AsBlocks::empty(),
            v4: IpBlocks::empty(),
            v6: IpBlocks::empty(),
        }
    }
}

impl TryFrom<&Cert> for ResourceSet {
    type Error = ResSetErr;

    fn try_from(cert: &Cert) -> Result<Self, Self::Error> {
        let asn = match cert.as_resources() {
            None => AsBlocks::empty(),
            Some(as_resources) => match as_resources.to_blocks() {
                Ok(as_blocks) => as_blocks,
                Err(_) => return Err(ResSetErr::InheritOnCaCert),
            },
        };

        let v4 = match cert.v4_resources() {
            None => IpBlocks::empty(),
            Some(res) => match res.to_blocks() {
                Ok(blocks) => blocks,
                Err(_) => return Err(ResSetErr::InheritOnCaCert),
            },
        };

        let v6 = match cert.v6_resources() {
            None => IpBlocks::empty(),
            Some(res) => match res.to_blocks() {
                Ok(blocks) => blocks,
                Err(_) => return Err(ResSetErr::InheritOnCaCert),
            },
        };

        Ok(ResourceSet { asn, v4, v6 })
    }
}

impl fmt::Display for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "asn: {}, v4: {}, v6: {}", self.asn, self.v4(), self.v6())
    }
}

// TODO: Implement equals better on enclosed AsBlocks and IpBlocks, and check corner cases
impl PartialEq for ResourceSet {
    fn eq(&self, other: &Self) -> bool {
        if let (Ok(self_str), Ok(other_str)) =
            (serde_json::to_string(&self), serde_json::to_string(other))
        {
            self_str == other_str
        } else {
            false
        }
    }
}

impl Eq for ResourceSet {}

//------------ CertAuthList --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthList {
    cas: Vec<CertAuthSummary>,
}

impl CertAuthList {
    pub fn new(cas: Vec<CertAuthSummary>) -> Self {
        CertAuthList { cas }
    }

    pub fn cas(&self) -> &Vec<CertAuthSummary> {
        &self.cas
    }
}

//------------ CertAuthSummary -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthSummary {
    handle: Handle,
}

impl CertAuthSummary {
    pub fn new(name: Handle) -> Self {
        CertAuthSummary { handle: name }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

//------------ ParentKindInfo ------------------------------------------------
#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentKindInfo {
    #[display(fmt = "This CA is a TA")]
    Ta,

    #[display(fmt = "Embedded parent")]
    Embedded,

    #[display(fmt = "RFC 6492 Parent")]
    Rfc6492,
}

//------------ ParentInfo ----------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentInfo {
    handle: ParentHandle,
    kind: ParentKindInfo,
}

impl ParentInfo {
    pub fn new(handle: ParentHandle, contact: ParentCaContact) -> Self {
        let kind = match contact {
            ParentCaContact::Ta(_) => ParentKindInfo::Ta,
            ParentCaContact::Embedded => ParentKindInfo::Embedded,
            ParentCaContact::Rfc6492(_) => ParentKindInfo::Rfc6492,
        };
        ParentInfo { handle, kind }
    }
}

impl fmt::Display for ParentInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle: {} Kind: {}", self.handle, self.kind)
    }
}

//------------ CertAuthInfo --------------------------------------------------

/// This type represents the details of a CertAuth that need
/// to be exposed through the API/CLI/UI
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInfo {
    handle: Handle,
    repo_info: RepoInfo,
    parents: Vec<ParentInfo>,
    resources: HashMap<ResourceClassName, ResourceClassInfo>,
    children: Vec<ChildHandle>,
}

impl CertAuthInfo {
    pub fn new(
        handle: Handle,
        repo_info: RepoInfo,
        parents: HashMap<ParentHandle, ParentCaContact>,
        resources: HashMap<ResourceClassName, ResourceClassInfo>,
        children: Vec<ChildHandle>,
    ) -> Self {
        let parents = parents
            .into_iter()
            .map(|(handle, contact)| ParentInfo::new(handle, contact))
            .collect();

        CertAuthInfo {
            handle,
            repo_info,
            parents,
            resources,
            children,
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn repo_repo(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn parents(&self) -> &Vec<ParentInfo> {
        &self.parents
    }

    pub fn resources(&self) -> &HashMap<ResourceClassName, ResourceClassInfo> {
        &self.resources
    }

    pub fn children(&self) -> &Vec<ChildHandle> {
        &self.children
    }

    pub fn published_objects(&self) -> Vec<Publish> {
        let mut res = vec![];
        for (_rc_name, rc) in self.resources.iter() {
            let name_space = rc.name_space();
            res.append(&mut rc.current_objects().publish(self.repo_repo(), name_space));
        }
        res
    }
}

//------------ CertAuthHistory -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthHistory {
    init: ca::Ini,
    events: Vec<ca::Evt>,
}

impl<S: Signer> From<AggregateHistory<CertAuth<S>>> for CertAuthHistory {
    fn from(history: AggregateHistory<CertAuth<S>>) -> Self {
        let (init, events) = history.unpack();
        CertAuthHistory { init, events }
    }
}

impl fmt::Display for CertAuthHistory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.init)?;
        for evt in &self.events {
            writeln!(f, "{}", evt)?;
        }
        Ok(())
    }
}

//------------ KeyStateInfo -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassInfo {
    name_space: String,
    parent_handle: ParentHandle,
    keys: ResourceClassKeysInfo,
    current_objects: CurrentObjects,
}

impl ResourceClassInfo {
    pub fn new(
        name_space: String,
        parent_handle: ParentHandle,
        keys: ResourceClassKeysInfo,
        current_objects: CurrentObjects,
    ) -> Self {
        ResourceClassInfo {
            name_space,
            parent_handle,
            keys,
            current_objects,
        }
    }

    pub fn name_space(&self) -> &str {
        &self.name_space
    }
    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }
    pub fn keys(&self) -> &ResourceClassKeysInfo {
        &self.keys
    }

    pub fn current_key(&self) -> Option<&CertifiedKeyInfo> {
        self.keys.current_key()
    }

    pub fn current_resources(&self) -> Option<&ResourceSet> {
        self.current_key().map(|k| k.incoming_cert().resources())
    }

    pub fn current_objects(&self) -> &CurrentObjects {
        &self.current_objects
    }
}

//------------ ResourceClassKeysInfo -----------------------------------------

/// Contains the current key status for a resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClassKeysInfo {
    Pending(PendingInfo),
    Active(ActiveInfo),
    RollPending(RollPendingInfo),
    RollNew(RollNewInfo),
    RollOld(RollOldInfo),
}

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "pending")]
pub struct PendingInfo {
    #[serde(rename = "pending_key")]
    pub _pending_key: PendingKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "active")]
pub struct ActiveInfo {
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "roll phase 1: pending and active key")]
pub struct RollPendingInfo {
    #[serde(rename = "pending_key")]
    pub _pending_key: PendingKeyInfo,
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "roll phase 2: new and active key")]
pub struct RollNewInfo {
    #[serde(rename = "new_key")]
    pub _new_key: CertifiedKeyInfo,
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "roll phase 3: active and old key")]
pub struct RollOldInfo {
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
    #[serde(rename = "old_key")]
    pub _old_key: CertifiedKeyInfo,
}

impl ResourceClassKeysInfo {
    pub fn current_key(&self) -> Option<&CertifiedKeyInfo> {
        match &self {
            ResourceClassKeysInfo::Active(current) => Some(&current._active_key),
            ResourceClassKeysInfo::RollPending(pending) => Some(&pending._active_key),
            ResourceClassKeysInfo::RollNew(new) => Some(&new._active_key),
            ResourceClassKeysInfo::RollOld(old) => Some(&old._active_key),
            _ => None,
        }
    }
}

impl fmt::Display for ResourceClassKeysInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = String::new();

        res.push_str("State: ");

        match &self {
            ResourceClassKeysInfo::Pending(p) => {
                res.push_str(&p.to_string());
            }
            ResourceClassKeysInfo::Active(a) => {
                res.push_str(&a.to_string());
            }
            ResourceClassKeysInfo::RollPending(r) => {
                res.push_str(&r.to_string());
            }
            ResourceClassKeysInfo::RollNew(r) => {
                res.push_str(&r.to_string());
            }
            ResourceClassKeysInfo::RollOld(r) => {
                res.push_str(&r.to_string());
            }
        }

        if let Some(key) = self.current_key() {
            let resources = key.incoming_cert().resources();
            res.push_str("    Resources:\n");
            res.push_str(&format!("    ASNs: {}\n", resources.asn()));
            res.push_str(&format!("    IPv4: {}\n", resources.v4()));
            res.push_str(&format!("    IPv6: {}\n", resources.v6()));
        }

        res.fmt(f)
    }
}

//------------ CaRepoDetails -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentRepoState {
    List(ListReply),
    Error(String),
}

impl CurrentRepoState {
    pub fn list(list: ListReply) -> Self {
        CurrentRepoState::List(list)
    }

    pub fn error(e: impl fmt::Display) -> Self {
        CurrentRepoState::Error(e.to_string())
    }

    pub fn as_list(&self) -> &ListReply {
        match &self {
            CurrentRepoState::List(list) => list,
            CurrentRepoState::Error(e) => panic!("{}", e),
        }
    }
}

/// This struct contains the API details for the configure Repository server,
/// and objects published there, for a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaRepoDetails {
    contact: RepositoryContact,
    state: CurrentRepoState,
}

impl CaRepoDetails {
    pub fn new(contact: RepositoryContact, state: CurrentRepoState) -> Self {
        CaRepoDetails { contact, state }
    }

    pub fn contact(&self) -> &RepositoryContact {
        &self.contact
    }

    pub fn state(&self) -> &CurrentRepoState {
        &self.state
    }
}

//------------ ResSetErr -----------------------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ResSetErr {
    #[display(fmt = "Cannot parse ASN resources")]
    Asn,

    #[display(fmt = "Cannot parse IPv4 resources")]
    V4,

    #[display(fmt = "Cannot parse IPv6 resources")]
    V6,

    #[display(fmt = "Mixed Address Families in configured resource set")]
    Mix,

    #[display(fmt = "Found inherited resources on CA certificate")]
    InheritOnCaCert,

    #[display(fmt = "RequestResourceLimit exceeds resources")]
    LimitExceedsResources,
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;

    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::commons::util::test;

    use super::*;

    fn base_uri() -> uri::Rsync {
        test::rsync("rsync://localhost/repo/ta/")
    }

    fn rrdp_uri() -> uri::Https {
        test::https("https://localhost/rrdp/notification.xml")
    }

    fn info() -> RepoInfo {
        RepoInfo {
            base_uri: base_uri(),
            rpki_notify: rrdp_uri(),
        }
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

                let mft_path = str::from_utf8_unchecked(mft_uri.relative_to(&base_uri()).unwrap());

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
    fn serialize_deserialize_resource_set() {
        let asns = "AS65000-AS65003, AS65005";
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
            test::https("https://host/notification.xml"),
        );

        let json = serde_json::to_string(&info).unwrap();
        let deser_info = serde_json::from_str(&json).unwrap();

        assert_eq!(info, deser_info);
    }

    #[test]
    fn create_and_display_tal() {
        let der = include_bytes!("../../../test-resources/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();
        let uri = test::https("https://localhost/ta.cer");

        let tal = TrustAnchorLocator::new(vec![uri], &cert);

        let expected_tal = include_str!("../../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);
    }

    #[test]
    fn resource_set_eq() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let resource_set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let asns_2 = "AS65000-AS65003";
        let ipv4s_2 = "192.168.0.0";
        let ipv6s_2 = "2001:db8::/32";

        let resource_set_asn_differs = ResourceSet::from_strs(asns_2, ipv4s, ipv6s).unwrap();
        let resource_set_v4_differs = ResourceSet::from_strs(asns, ipv4s_2, ipv6s).unwrap();
        let resource_set_v6_differs = ResourceSet::from_strs(asns, ipv4s, ipv6s_2).unwrap();
        let resource_set_2 = ResourceSet::from_strs(asns_2, ipv4s_2, ipv6s_2).unwrap();

        assert_eq!(resource_set, resource_set);
        assert_eq!(resource_set_asn_differs, resource_set_asn_differs);
        assert_eq!(resource_set_v4_differs, resource_set_v4_differs);
        assert_eq!(resource_set_v6_differs, resource_set_v6_differs);
        assert_eq!(resource_set_2, resource_set_2);

        assert_ne!(resource_set, resource_set_asn_differs);
        assert_ne!(resource_set, resource_set_v4_differs);
        assert_ne!(resource_set, resource_set_v6_differs);
        assert_ne!(resource_set, resource_set_2);

        let default_set = ResourceSet::default();
        let certified = ResourceSet::from_strs(
            "",
            "10.0.0.0/16, 192.168.0.0/16",
            "2001:db8::/32, 2000:db8::/32",
        )
        .unwrap();
        assert_ne!(default_set, certified);
        assert_ne!(resource_set, certified);
    }

    #[test]
    fn id_cert_pem_match_openssl() {
        let ncc_id = {
            let bytes = include_bytes!("../../../test-resources/remote/ncc-id.der");
            IdCert::decode(bytes.as_ref()).unwrap()
        };

        let ncc_id_openssl_pem = include_str!("../../../test-resources/remote/ncc-id.pem");
        let ncc_id_pem = IdCertPem::from(&ncc_id);

        assert_eq!(ncc_id_pem.pem(), ncc_id_openssl_pem);
    }
}
