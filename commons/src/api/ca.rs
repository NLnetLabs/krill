//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::str::{from_utf8_unchecked, FromStr};
use std::{fmt, ops, str};

use bytes::Bytes;
use chrono::Duration;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::resources::{AsBlocks, AsResources, IpBlocks, IpBlocksForFamily, IpResources};
use rpki::roa::Roa;
use rpki::uri;
use rpki::x509::{Serial, Time};

use crate::api::admin::{Handle, ParentCaContact};
use crate::api::publication;
use crate::api::publication::Publish;
use crate::api::RouteAuthorization;
use crate::api::{
    Base64, EncodedHash, IssuanceRequest, RequestResourceLimit, RevocationRequest,
    RevocationResponse,
};
use crate::remote::id::IdCert;
use crate::rpki::crl::{Crl, CrlEntry};
use crate::rpki::manifest::{FileAndHash, Manifest};
use crate::util::ext_serde;

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

//------------ ChildCaInfo ---------------------------------------------------

/// This type represents information about a child CA that is safe to share
/// through the API. I.e. it does not contain the child Token, but may contain
/// the IdCert for the child since this only includes a public key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaInfo {
    id_cert: Option<IdCert>,
    resources: HashMap<ResourceClassName, ChildResources>,
}

impl ChildCaInfo {
    pub fn id_cert(&self) -> Option<&IdCert> {
        self.id_cert.as_ref()
    }

    pub fn resources(&self) -> &HashMap<ResourceClassName, ChildResources> {
        &self.resources
    }

    pub fn resources_for_class(&self, class: &ResourceClassName) -> Option<&ChildResources> {
        self.resources.get(class)
    }
}

impl From<ChildCaDetails> for ChildCaInfo {
    fn from(d: ChildCaDetails) -> Self {
        ChildCaInfo {
            id_cert: d.id_cert,
            resources: d.resources,
        }
    }
}

//------------ ChildCaDetails ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaDetails {
    id_cert: Option<IdCert>,
    resources: HashMap<ResourceClassName, ChildResources>,
}

impl ChildCaDetails {
    pub fn new(id_cert: Option<IdCert>) -> Self {
        ChildCaDetails {
            id_cert,
            resources: HashMap::new(),
        }
    }

    pub fn id_cert(&self) -> Option<&IdCert> {
        self.id_cert.as_ref()
    }

    pub fn set_id_cert(&mut self, id_cert: IdCert) {
        self.id_cert = Some(id_cert);
    }

    pub fn resources(&self) -> &HashMap<ResourceClassName, ChildResources> {
        &self.resources
    }

    pub fn remove_resource(&mut self, class_name: &ResourceClassName) {
        self.resources.remove(class_name);
    }

    /// This function will update the resource entitlements for an existing class
    /// or create a new class if needed
    pub fn set_resources_for_class(&mut self, class: ResourceClassName, resources: ResourceSet) {
        if self.resources.contains_key(&class) {
            self.resources
                .get_mut(&class)
                .unwrap()
                .set_resources(resources);
        } else {
            self.add_new_resource_class(class, resources)
        }
    }

    pub fn resources_for_class(&self, class: &ResourceClassName) -> Option<&ChildResources> {
        self.resources.get(class)
    }

    pub fn add_new_resource_class(&mut self, name: ResourceClassName, resources: ResourceSet) {
        self.resources.insert(name, ChildResources::new(resources));
    }

    pub fn add_cert(&mut self, class_name: &ResourceClassName, cert: IssuedCert) {
        // Note the resource class MUST exist, or no cert would have
        // been issued to it. So, it's safe to unwrap here.
        self.resources.get_mut(class_name).unwrap().add_cert(cert)
    }

    pub fn revoke_key(&mut self, revocation: RevocationResponse) {
        let (class_name, key_id) = revocation.unpack();
        self.resources.get_mut(&class_name).unwrap().revoke(&key_id)
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
    shrink_pending: Option<Time>,
    not_after: Time,
    certs: HashMap<KeyIdentifier, IssuedCert>,
}

impl ChildResources {
    pub fn new(resources: ResourceSet) -> Self {
        ChildResources {
            resources,
            shrink_pending: None,
            not_after: Time::next_year(),
            certs: HashMap::new(),
        }
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn set_resources(&mut self, resources: ResourceSet) {
        if !resources.contains(&self.resources) {
            self.shrink_pending = Some(Time::now());
        }
        self.resources = resources;
    }

    /// Give back the not_after time that would be used on newly
    /// issued certificates. See `resource_set_notafter` in
    /// section 3.3.2 of RFC6492.
    ///
    /// This is the stored 'not_after' time for this ChildResources,
    /// or if this time is less than 3 months away, an updated time
    /// which is now + one year.
    pub fn not_after(&self) -> Time {
        let cut_off = Time::now() + Duration::weeks(13);

        if self.not_after < cut_off {
            Time::next_year()
        } else {
            self.not_after
        }
    }

    pub fn certs_iter(&self) -> impl Iterator<Item = &IssuedCert> {
        self.certs.values()
    }

    pub fn certs(&self) -> &HashMap<KeyIdentifier, IssuedCert> {
        &self.certs
    }

    pub fn cert(&self, key_id: &KeyIdentifier) -> Option<&IssuedCert> {
        self.certs.get(key_id)
    }

    pub fn add_cert(&mut self, cert: IssuedCert) {
        // We can assume that the correct not_after date was used when the certificate
        // was issued - because the `not_after` function was called. Therefore we can update
        // the not_after value for this child resource class for future use.
        self.not_after = cert.cert().validity().not_after();

        // Update the certificate for this key, or insert it for a new key.
        self.certs
            .insert(cert.cert().subject_key_identifier(), cert);

        // If a shrink was pending, check that it's still applicable.
        if self.shrink_pending.is_some()
            && self
                .certs
                .values()
                .find(|c| !self.resources.contains(c.resource_set()))
                .is_none()
        {
            self.shrink_pending = None;
        }
    }

    pub fn shrink_pending(&self) -> Option<Time> {
        self.shrink_pending
    }

    pub fn revoke(&mut self, key_id: &KeyIdentifier) {
        self.certs.remove(&key_id);
    }
}

//------------ RevokedObject -------------------------------------------------

pub type RevokedObject = ReplacedObject;

//------------ ReplacedObject ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplacedObject {
    revocation: Revocation,
    hash: EncodedHash,
}

impl ReplacedObject {
    pub fn new(revocation: Revocation, hash: EncodedHash) -> Self {
        ReplacedObject { revocation, hash }
    }

    pub fn revocation(&self) -> Revocation {
        self.revocation
    }

    pub fn hash(&self) -> &EncodedHash {
        &self.hash
    }
}

impl From<&Cert> for ReplacedObject {
    fn from(c: &Cert) -> Self {
        let revocation = Revocation::from(c);
        let hash = EncodedHash::from_content(c.to_captured().as_slice());
        ReplacedObject { revocation, hash }
    }
}

impl From<&IssuedCert> for ReplacedObject {
    fn from(issued: &IssuedCert) -> Self {
        Self::from(issued.cert())
    }
}

impl From<&Roa> for ReplacedObject {
    fn from(r: &Roa) -> Self {
        let revocation = Revocation::from(r);
        let hash = EncodedHash::from_content(r.to_captured().as_slice());
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

    pub fn unwrap(self) -> (uri::Rsync, RequestResourceLimit, ResourceSet, Cert) {
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

    /// The URI of the CRL published BY THIS certificate, i.e. the uri to use
    /// on certs issued by this.
    pub fn crl_uri(&self) -> uri::Rsync {
        self.uri_for_object(ObjectName::new(&self.cert.subject_key_identifier(), "crl"))
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

//------------ PendingKey ----------------------------------------------------

/// A Pending Key in a resource class. Should usually have an open
/// IssuanceRequest, and will be move to a 'new' or 'current' CertifiedKey
/// when a certificate is received.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKey {
    key_id: KeyIdentifier,
    request: Option<IssuanceRequest>,
}

impl PendingKey {
    pub fn new(key_id: KeyIdentifier) -> Self {
        PendingKey {
            key_id,
            request: None,
        }
    }
    pub fn unwrap(self) -> (KeyIdentifier, Option<IssuanceRequest>) {
        (self.key_id, self.request)
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }
    pub fn clear_request(&mut self) {
        self.request = None
    }
}

//------------ OldKey --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct OldKey {
    key: CertifiedKey,
    revoke_req: RevocationRequest,
}

impl OldKey {
    pub fn new(key: CertifiedKey, revoke_req: RevocationRequest) -> Self {
        OldKey { key, revoke_req }
    }

    pub fn key(&self) -> &CertifiedKey {
        &self.key
    }
    pub fn revoke_req(&self) -> &RevocationRequest {
        &self.revoke_req
    }
}

impl Deref for OldKey {
    type Target = CertifiedKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl DerefMut for OldKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key
    }
}

//------------ CertifiedKey --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is certified. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CertifiedKey {
    key_id: KeyIdentifier,
    incoming_cert: RcvdCert,
    current_set: CurrentObjectSet,
    request: Option<IssuanceRequest>,
}

impl CertifiedKey {
    pub fn new(key_id: KeyIdentifier, incoming_cert: RcvdCert) -> Self {
        let current_set = CurrentObjectSet::default();

        CertifiedKey {
            key_id,
            incoming_cert,
            current_set,
            request: None,
        }
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn incoming_cert(&self) -> &RcvdCert {
        &self.incoming_cert
    }
    pub fn set_incoming_cert(&mut self, incoming_cert: RcvdCert) {
        self.request = None;
        self.incoming_cert = incoming_cert;
    }

    pub fn current_set(&self) -> &CurrentObjectSet {
        &self.current_set
    }

    pub fn request(&self) -> Option<&IssuanceRequest> {
        self.request.as_ref()
    }
    pub fn add_request(&mut self, req: IssuanceRequest) {
        self.request = Some(req)
    }

    pub fn wants_update(&self, new_resources: &ResourceSet, new_not_after: Time) -> bool {
        let not_after = self.incoming_cert().cert.validity().not_after();
        self.incoming_cert.resources() != new_resources || not_after != new_not_after
    }

    pub fn close_to_next_update(&self) -> bool {
        self.current_set.number == 1 // The first set is empty (not even crl/mft)
            || self.current_set.next_update < Time::now() + Duration::hours(8)
    }

    pub fn with_new_cert(mut self, cert: RcvdCert) -> Self {
        self.incoming_cert = cert;
        self
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.current_set.apply_delta(delta)
    }

    pub fn deactivate(&mut self) {
        self.current_set.deactivate()
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

    pub fn to_hash(&self) -> EncodedHash {
        let bytes = self.content.to_bytes();
        EncodedHash::from_content(bytes.as_ref())
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
pub struct CurrentObjectSet {
    this_update: Time,
    next_update: Time,
    number: u64,
    revocations: Revocations,
    objects: CurrentObjects,
}

impl Default for CurrentObjectSet {
    fn default() -> Self {
        CurrentObjectSet {
            this_update: Time::now(),
            next_update: Time::tomorrow(),
            number: 1,
            revocations: Revocations::default(),
            objects: CurrentObjects::default(),
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

    /// TODO: Remove when ROAs and Certs are no longer stored here. See issue #68
    ///
    /// For now... remove all but the mft and crl from the set, so that when the
    /// key is withdrawn only the CRL and MFT are removed.
    pub fn deactivate(&mut self) {
        self.objects.deactivate()
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
    objects: ObjectsDelta,
}

impl PublicationDelta {
    pub fn new(
        this_update: Time,
        next_update: Time,
        number: u64,
        revocations: RevocationsDelta,
        objects: ObjectsDelta,
    ) -> Self {
        PublicationDelta {
            this_update,
            next_update,
            number,
            revocations,
            objects,
        }
    }

    pub fn objects(&self) -> &ObjectsDelta {
        &self.objects
    }
}

impl Into<publication::PublishDelta> for PublicationDelta {
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
    old: EncodedHash,
}

impl UpdatedObject {
    pub fn new(name: ObjectName, object: CurrentObject, old: EncodedHash) -> Self {
        UpdatedObject { name, object, old }
    }

    pub fn for_cert(new: &Cert, old: EncodedHash) -> Self {
        let name = ObjectName::from(new);
        let object = CurrentObject::from(new);
        UpdatedObject { name, object, old }
    }
}

//------------ WithdrawnObject -----------------------------------------------

/// An object that is to be withdrawn from the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: EncodedHash,
}

impl WithdrawnObject {
    pub fn new(name: ObjectName, hash: EncodedHash) -> Self {
        WithdrawnObject { name, hash }
    }

    pub fn for_current(name: ObjectName, current: &CurrentObject) -> Self {
        WithdrawnObject {
            name,
            hash: current.to_hash(),
        }
    }
}

impl From<&Cert> for WithdrawnObject {
    fn from(c: &Cert) -> Self {
        let name = ObjectName::from(c);
        let hash = EncodedHash::from_content(c.to_captured().as_slice());
        WithdrawnObject { name, hash }
    }
}

//------------ ResourceSet ---------------------------------------------------

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

//------------ TrustAnchorInfo -----------------------------------------------

/// This type represents the TrustAnchor details that need to be accessible
/// through the API (CLI and UI).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorInfo {
    resources: ResourceSet,
    repo_info: RepoInfo,
    children: HashMap<Handle, ChildCaDetails>,
    cert: RcvdCert,
    tal: TrustAnchorLocator,
}

impl TrustAnchorInfo {
    pub fn new(
        resources: ResourceSet,
        repo_info: RepoInfo,
        children: HashMap<Handle, ChildCaDetails>,
        cert: RcvdCert,
        tal: TrustAnchorLocator,
    ) -> Self {
        TrustAnchorInfo {
            resources,
            repo_info,
            children,
            cert,
            tal,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthSummary {
    name: Handle,
}

impl CertAuthSummary {
    pub fn new(name: Handle) -> Self {
        CertAuthSummary { name }
    }

    pub fn name(&self) -> &Handle {
        &self.name
    }
}

//------------ CertAuthInfo --------------------------------------------------

/// This type represents the details of a CertAuth that need
/// to be exposed through the API/CLI/UI
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInfo {
    handle: Handle,
    base_repo: RepoInfo,
    parents: HashMap<Handle, ParentCaContact>,
    resources: HashMap<ResourceClassName, ResourceClassInfo>,
    children: HashMap<Handle, ChildCaDetails>,
    route_authorizations: HashSet<RouteAuthorization>,
}

impl CertAuthInfo {
    pub fn new(
        handle: Handle,
        base_repo: RepoInfo,
        parents: HashMap<Handle, ParentCaContact>,
        resources: HashMap<ResourceClassName, ResourceClassInfo>,
        children: HashMap<Handle, ChildCaDetails>,
        route_authorizations: HashSet<RouteAuthorization>,
    ) -> Self {
        CertAuthInfo {
            handle,
            base_repo,
            parents,
            resources,
            children,
            route_authorizations,
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn base_repo(&self) -> &RepoInfo {
        &self.base_repo
    }

    pub fn parents(&self) -> &HashMap<Handle, ParentCaContact> {
        &self.parents
    }

    pub fn parent(&self, parent: &Handle) -> Option<&ParentCaContact> {
        self.parents.get(parent)
    }

    pub fn resources(&self) -> &HashMap<ResourceClassName, ResourceClassInfo> {
        &self.resources
    }

    pub fn children(&self) -> &HashMap<Handle, ChildCaDetails> {
        &self.children
    }

    pub fn route_authorizations(&self) -> &HashSet<RouteAuthorization> {
        &self.route_authorizations
    }

    pub fn published_objects(&self) -> Vec<Publish> {
        let mut res = vec![];
        for (_rc_name, rc) in self.resources.iter() {
            let name_space = rc.name_space();
            res.append(&mut rc.objects().publish(self.base_repo(), name_space));
        }
        res
    }
}

//------------ ResourceClassInfo ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassInfo {
    name_space: String,
    keys: ResourceClassKeysInfo,
}

impl ResourceClassInfo {
    pub fn new(name_space: String, keys: ResourceClassKeysInfo) -> Self {
        ResourceClassInfo { name_space, keys }
    }

    pub fn name_space(&self) -> &str {
        &self.name_space
    }
    pub fn keys(&self) -> &ResourceClassKeysInfo {
        &self.keys
    }

    pub fn current_resources(&self) -> Option<&ResourceSet> {
        match &self.keys {
            ResourceClassKeysInfo::Active(current)
            | ResourceClassKeysInfo::RollPending(_, current)
            | ResourceClassKeysInfo::RollNew(_, current)
            | ResourceClassKeysInfo::RollOld(current, _) => {
                Some(current.incoming_cert().resources())
            }
            _ => None,
        }
    }

    pub fn objects(&self) -> CurrentObjects {
        let mut res = CurrentObjects::default();
        match &self.keys {
            ResourceClassKeysInfo::Pending(_) => {}
            ResourceClassKeysInfo::Active(current)
            | ResourceClassKeysInfo::RollPending(_, current) => {
                res = res + current.current_set().objects().clone();
            }
            ResourceClassKeysInfo::RollNew(new, current) => {
                res = res + new.current_set().objects().clone();
                res = res + current.current_set().objects().clone();
            }
            ResourceClassKeysInfo::RollOld(current, old) => {
                res = res + current.current_set().objects().clone();
                res = res + old.current_set().objects().clone();
            }
        }
        res
    }
}

//------------ ResourceClassKeysInfo -----------------------------------------

/// Contains the current key status for a resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ResourceClassKeysInfo {
    Pending(PendingKey),
    Active(CurrentKey),
    RollPending(PendingKey, CurrentKey),
    RollNew(NewKey, CurrentKey),
    RollOld(CurrentKey, OldKey),
}

type NewKey = CertifiedKey;
type CurrentKey = CertifiedKey;

impl fmt::Display for ResourceClassKeysInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = String::new();

        match &self {
            ResourceClassKeysInfo::Pending(_) => {
                res.push_str("State: pending\n");
            }
            ResourceClassKeysInfo::Active(_) => {
                res.push_str("State: active\n");
            }
            ResourceClassKeysInfo::RollPending(_, _) => {
                res.push_str("State: key-roll phase 1: pending key for key roll\n");
            }
            ResourceClassKeysInfo::RollNew(_, _) => {
                res.push_str("State: key-roll phase 2: new key with certificate\n");
            }
            ResourceClassKeysInfo::RollOld(_, _) => {
                res.push_str("State: key-roll phase 3: old key pending revocation by parent\n");
            }
        }

        match &self {
            ResourceClassKeysInfo::Active(current)
            | ResourceClassKeysInfo::RollPending(_, current)
            | ResourceClassKeysInfo::RollNew(_, current)
            | ResourceClassKeysInfo::RollOld(current, _) => {
                res.push_str("    Resources:\n");
                let inrs = current.incoming_cert().resources();
                res.push_str(&format!("    ASNs: {}\n", inrs.asn()));
                res.push_str(&format!("    IPv4: {}\n", inrs.v4()));
                res.push_str(&format!("    IPv6: {}\n", inrs.v6()));
            }
            _ => {}
        }

        res.fmt(f)
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

    use super::*;
    use bytes::Bytes;

    use crate::util::softsigner::OpenSslSigner;
    use crate::util::test;
    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;

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
        let der = include_bytes!("../../test-resources/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();
        let uri = test::https("https://localhost/ta.cer");

        let tal = TrustAnchorLocator::new(vec![uri], &cert);

        let expected_tal = include_str!("../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);
    }
}
