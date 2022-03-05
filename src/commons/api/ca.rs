//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::{self, Deref};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, str};

use bytes::Bytes;
use chrono::{Duration, TimeZone, Utc};
use rpki::repository::aspa::Aspa;
use rpki::repository::resources::{AsBlock, AsBlocksBuilder, AsId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::{
    repository::{
        cert::Cert,
        crl::{Crl, CrlEntry},
        crypto::KeyIdentifier,
        manifest::Manifest,
        resources::{AsBlocks, AsResources, IpBlocks, IpBlocksForFamily, IpResources},
        roa::{Roa, RoaIpAddress},
        x509::{Serial, Time},
    },
    uri,
};

use crate::commons::util::KrillVersion;
use crate::{
    commons::{
        api::{
            rrdp::PublishElement, AspaDefinition, Base64, ChildHandle, EntitlementClass, Entitlements, ErrorResponse,
            Handle, HexEncodedHash, IssuanceRequest, ParentCaContact, ParentHandle, RepositoryContact,
            RequestResourceLimit, RoaAggregateKey, RoaDefinition, SigningCert,
        },
        crypto::IdCert,
        remote::rfc8183::ServiceUri,
        util::ext_serde,
    },
    daemon::ca::RouteAuthorization,
};

//------------ ResourceClassName -------------------------------------------

/// This type represents a resource class name, as used in RFC6492. The protocol
/// allows for any arbitrary set of utf8 characters to be used as the name, though
/// in practice names can be expected to be short and plain ascii or even numbers.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct ResourceClassName {
    name: Arc<str>,
}

pub type ParentResourceClassName = ResourceClassName;

impl Default for ResourceClassName {
    fn default() -> ResourceClassName {
        ResourceClassName::from(0)
    }
}

impl AsRef<str> for ResourceClassName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl From<u32> for ResourceClassName {
    fn from(nr: u32) -> ResourceClassName {
        ResourceClassName {
            name: format!("{}", nr).into(),
        }
    }
}

impl From<&str> for ResourceClassName {
    fn from(s: &str) -> ResourceClassName {
        ResourceClassName { name: s.into() }
    }
}

impl From<String> for ResourceClassName {
    fn from(s: String) -> ResourceClassName {
        ResourceClassName { name: s.into() }
    }
}

impl fmt::Display for ResourceClassName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
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
            pem.push('\n');
        }

        pem.push_str("-----END CERTIFICATE-----\n");

        let hash = HexEncodedHash::from_content(&cer.to_bytes());

        IdCertPem { pem, hash }
    }
}

//------------ ChildState ----------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    Active,
    Suspended,
}

impl Default for ChildState {
    fn default() -> Self {
        ChildState::Active
    }
}

impl fmt::Display for ChildState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ChildState::Active => "active",
            ChildState::Suspended => "suspended",
        }
        .fmt(f)
    }
}

//------------ ChildCaInfo ---------------------------------------------------

/// This type represents information about a child CA that is shared through the API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaInfo {
    state: ChildState,
    id_cert: IdCertPem,
    entitled_resources: ResourceSet,
}

impl ChildCaInfo {
    pub fn new(state: ChildState, id_cert: IdCertPem, entitled_resources: ResourceSet) -> Self {
        ChildCaInfo {
            state,
            id_cert,
            entitled_resources,
        }
    }

    pub fn state(&self) -> ChildState {
        self.state
    }

    pub fn id_cert(&self) -> &IdCertPem {
        &self.id_cert
    }

    pub fn entitled_resources(&self) -> &ResourceSet {
        &self.entitled_resources
    }
}

impl fmt::Display for ChildCaInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.id_cert.pem())?;
        writeln!(f, "SHA256 hash of PEM encoded certificate: {}", self.id_cert.hash())?;
        writeln!(f, "resources: {}", self.entitled_resources)?;
        writeln!(f, "state: {}", self.state)
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

impl From<&Roa> for ReplacedObject {
    fn from(roa: &Roa) -> Self {
        let revocation = Revocation::from(roa.cert());
        let hash = HexEncodedHash::from_content(roa.to_captured().as_slice());
        ReplacedObject { revocation, hash }
    }
}

impl From<&Aspa> for ReplacedObject {
    fn from(aspa: &Aspa) -> Self {
        let revocation = Revocation::from(aspa.cert());
        let hash = HexEncodedHash::from_content(aspa.to_captured().as_slice());
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
    #[serde(skip_serializing_if = "Option::is_none")]
    replaces: Option<ReplacedObject>,
}

pub type SuspendedCert = IssuedCert;
pub type UnsuspendedCert = IssuedCert;

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

    /// Returns a (possibly empty) set of reduced applicable resources which is the intersection
    /// of the encompassing resources and this certificate's current resources.
    /// Returns None if the current resource set is not overclaiming and does not need to be
    /// reduced.
    pub fn reduced_applicable_resources(&self, encompassing: &ResourceSet) -> Option<ResourceSet> {
        if encompassing.contains(&self.resource_set) {
            None
        } else {
            Some(encompassing.intersection(&self.resource_set))
        }
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
        RcvdCert { cert, uri, resources }
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
        self.cert.ca_repository().unwrap()
    }

    /// The URI of the MFT published by THIS certificate.
    pub fn mft_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.mft_name())
    }

    pub fn uri_for_object(&self, name: impl Into<ObjectName>) -> uri::Rsync {
        self.uri_for_name(&name.into())
    }

    pub fn uri_for_name(&self, name: &ObjectName) -> uri::Rsync {
        // unwraps here are safe
        self.cert.ca_repository().unwrap().join(name.as_bytes()).unwrap()
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

impl Deref for RcvdCert {
    type Target = Cert;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

impl PartialEq for RcvdCert {
    fn eq(&self, other: &RcvdCert) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() && self.uri == other.uri
    }
}

impl Eq for RcvdCert {}

//------------ TrustAnchorLocator --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rsync_uri: Option<uri::Rsync>,

    #[serde(deserialize_with = "ext_serde::de_bytes", serialize_with = "ext_serde::ser_bytes")]
    encoded_ski: Bytes,
}

impl TrustAnchorLocator {
    /// Creates a new TAL, panics when the provided Cert is not a TA cert.
    pub fn new(uris: Vec<uri::Https>, rsync_uri: Option<uri::Rsync>, cert: &Cert) -> Self {
        if cert.authority_key_identifier().is_some() {
            panic!("Trying to create TAL for a non-TA certificate.")
        }
        let encoded_ski = cert.subject_public_key_info().to_info_bytes();
        TrustAnchorLocator {
            uris,
            rsync_uri,
            encoded_ski,
        }
    }
}

impl fmt::Display for TrustAnchorLocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base64 = Base64::from_content(&self.encoded_ski).to_string();

        for uri in self.uris.iter() {
            writeln!(f, "{}", uri)?;
        }
        if let Some(rsync_uri) = &self.rsync_uri {
            writeln!(f, "{}", rsync_uri)?;
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

/// Contains the rsync and RRDP base URIs for a repository,
/// or publisher inside a repository.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rpki_notify: uri::Https,
}

impl RepoInfo {
    pub fn new(base_uri: uri::Rsync, rpki_notify: uri::Https) -> Self {
        RepoInfo { base_uri, rpki_notify }
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    /// Returns the ca repository uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn ca_repository(&self, name_space: &str) -> uri::Rsync {
        match name_space {
            "" => self.base_uri.clone(),
            _ => self.base_uri.join(name_space.as_ref()).unwrap(),
        }
    }

    /// Returns the rpki manifest uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn rpki_manifest(&self, name_space: &str, signing_key: &KeyIdentifier) -> uri::Rsync {
        self.resolve(name_space, &Self::mft_name(signing_key))
    }

    /// Returns the CRL Distribution Point (rsync URI) for this RepoInfo, given the
    /// namespace and signing key.
    pub fn crl_distribution_point(&self, name_space: &str, signing_key: &KeyIdentifier) -> uri::Rsync {
        self.resolve(name_space, &Self::crl_name(signing_key))
    }

    /// Returns the rpki notify uri.
    /// (Note that this is the same for all namespaces).
    pub fn rpki_notify(&self) -> uri::Https {
        self.rpki_notify.clone()
    }

    pub fn resolve(&self, name_space: &str, file_name: &str) -> uri::Rsync {
        self.ca_repository(name_space).join(file_name.as_ref()).unwrap()
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

//------------ ObjectName ----------------------------------------------------

/// This type is used to represent the (deterministic) file names for
/// RPKI repository objects.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ObjectName(String);

impl ObjectName {
    pub fn new(ki: &KeyIdentifier, extension: &str) -> Self {
        ObjectName(format!("{}.{}", ki, extension))
    }

    pub fn aspa(customer: AsId) -> Self {
        ObjectName(format!("{}.asa", customer))
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

impl From<&RoaAggregateKey> for ObjectName {
    fn from(roa_group: &RoaAggregateKey) -> Self {
        ObjectName(match roa_group.group() {
            None => format!("AS{}.roa", roa_group.asn()),
            Some(number) => format!("AS{}-{}.roa", roa_group.asn(), number),
        })
    }
}

impl From<&AspaDefinition> for ObjectName {
    fn from(aspa: &AspaDefinition) -> Self {
        Self::aspa(aspa.customer())
    }
}

impl From<&str> for ObjectName {
    fn from(s: &str) -> Self {
        ObjectName(s.to_string())
    }
}

impl From<ObjectName> for Bytes {
    fn from(object_name: ObjectName) -> Self {
        Bytes::from(object_name.0)
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

//------------ Revocation ----------------------------------------------------

/// A Crl Revocation. Note that this type differs from CrlEntry in
/// that it implements De/Serialize and Eq/PartialEq
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    serial: Serial,
    expires: Time,
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

impl From<&Aspa> for Revocation {
    fn from(aspa: &Aspa) -> Self {
        Self::from(aspa.cert())
    }
}

//------------ Revocations ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        // Todo: include the revocation time in ['Revocation'] and use that.
        //       this will require that we reprocess history to get this
        //       value. We do know when an object was removed or replaced,
        //       so we can get it - but it's not entirely trivial.
        //
        // See issue #788. This issue was added to the 0.10.0 backlog.
        // For now we just do a quick hack and use 'now' rather than the
        // future dated 'expires' time for the CRL entry.
        self.0.iter().map(|r| CrlEntry::new(r.serial, Time::now())).collect()
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

    pub fn remove(&mut self, revocation: &Revocation) {
        self.0.retain(|existing| existing != revocation);
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

//------------ ResourceSetSummary --------------------------------------------
/// This type defines a summary of a set of Internet Number Resources, for
/// use in concise reporting.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceSetSummary {
    asns: usize,
    ipv4: usize,
    ipv6: usize,
}

impl ResourceSetSummary {
    pub fn asn_blocks(&self) -> usize {
        self.asns
    }
    pub fn ipv4_blocks(&self) -> usize {
        self.ipv4
    }
    pub fn ipv6_blocks(&self) -> usize {
        self.ipv6
    }
}

impl From<&ResourceSet> for ResourceSetSummary {
    fn from(rs: &ResourceSet) -> Self {
        let asns = rs.asn().iter().count();
        let ipv4 = rs.v4.iter().count();
        let ipv6 = rs.v6.iter().count();
        ResourceSetSummary { asns, ipv4, ipv6 }
    }
}

impl fmt::Display for ResourceSetSummary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "asn: {} blocks, v4: {} blocks, v6: {} blocks",
            self.asns, self.ipv4, self.ipv6
        )
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

    pub fn from_strs(asn: &str, v4: &str, v6: &str) -> Result<Self, ResourceSetError> {
        let asn = AsBlocks::from_str(asn).map_err(|_| ResourceSetError::asn(asn))?;
        if v4.contains(':') || v6.contains('.') {
            return Err(ResourceSetError::Mix);
        }
        let v4 = IpBlocks::from_str(v4).map_err(|_| ResourceSetError::v4(v4))?;
        let v6 = IpBlocks::from_str(v6).map_err(|_| ResourceSetError::v6(v6))?;
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

    pub fn summary(&self) -> ResourceSetSummary {
        ResourceSetSummary::from(self)
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
    pub fn apply_limit(&self, limit: &RequestResourceLimit) -> Result<Self, ResourceSetError> {
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
                        return Err(ResourceSetError::Limit);
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
                        return Err(ResourceSetError::Limit);
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
                        return Err(ResourceSetError::Limit);
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

    /// Check if the resource set contains the given AsId
    pub fn contains_asn(&self, asn: AsId) -> bool {
        let mut blocks = AsBlocksBuilder::new();
        blocks.push(AsBlock::Id(asn));
        let blocks = blocks.finalize();
        self.asn.contains(&blocks)
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

    /// Returns the difference from another ResourceSet towards `self`.
    pub fn difference(&self, other: &ResourceSet) -> ResourceSetDiff {
        let added = ResourceSet {
            asn: self.asn.difference(&other.asn),
            v4: self.v4.difference(&other.v4),
            v6: self.v6.difference(&other.v6),
        };
        let removed = ResourceSet {
            asn: other.asn.difference(&self.asn),
            v4: other.v4.difference(&self.v4),
            v6: other.v6.difference(&self.v6),
        };
        ResourceSetDiff { added, removed }
    }

    pub fn contains_roa_address(&self, roa_address: &RoaIpAddress) -> bool {
        self.v4.contains_roa(roa_address) || self.v6.contains_roa(roa_address)
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

impl FromStr for ResourceSet {
    type Err = ResourceSetError;

    // Expects formatting like we use in Display, i.e.:
    // asn: AS1-2, v4: 10.0.0.0/16, v6: ::0/128
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // min len for empty set is 12: 'asn: , v4: ,v6: '
        if s.len() < 16 || !s.starts_with("asn: ") {
            return Err(ResourceSetError::FromString);
        }
        let v4_start = s.find(", v4: ").ok_or(ResourceSetError::FromString)?;
        let v6_start = s.find(", v6: ").ok_or(ResourceSetError::FromString)?;

        let asn = &s[5..v4_start];
        let v4 = &s[v4_start + 6..v6_start];
        let v6 = &s[v6_start + 6..];

        ResourceSet::from_strs(asn, v4, v6)
    }
}

impl TryFrom<&Cert> for ResourceSet {
    type Error = ResourceSetError;

    fn try_from(cert: &Cert) -> Result<Self, Self::Error> {
        let asn = match cert.as_resources().to_blocks() {
            Ok(as_blocks) => as_blocks,
            Err(_) => return Err(ResourceSetError::InheritOnCaCert),
        };

        let v4 = match cert.v4_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => return Err(ResourceSetError::InheritOnCaCert),
        };

        let v6 = match cert.v6_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => return Err(ResourceSetError::InheritOnCaCert),
        };

        Ok(ResourceSet { asn, v4, v6 })
    }
}

impl fmt::Display for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "asn: {}, v4: {}, v6: {}", self.asn, self.v4(), self.v6())
    }
}

//------------ ResourceSetDiff -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSetDiff {
    added: ResourceSet,
    removed: ResourceSet,
}

impl ResourceSetDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl fmt::Display for ResourceSetDiff {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "<no changes in resources>")?;
        }
        if !self.added.is_empty() {
            write!(f, "Added:")?;
            if !self.added.asn.is_empty() {
                write!(f, " asn: {}", self.added.asn)?;
            }
            if !self.added.v4.is_empty() {
                write!(f, " ipv4: {}", self.added.v4())?;
            }
            if !self.added.v6.is_empty() {
                write!(f, " ipv6: {}", self.added.v6())?;
            }

            if !self.removed.is_empty() {
                write!(f, " ")?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, "Removed:")?;

            if !self.removed.asn.is_empty() {
                write!(f, " asn: {}", self.removed.asn)?;
            }
            if !self.removed.v4.is_empty() {
                write!(f, " ipv4: {}", self.removed.v4())?;
            }
            if !self.removed.v6.is_empty() {
                write!(f, " ipv6: {}", self.removed.v6())?;
            }
        }

        Ok(())
    }
}

//------------ CertAuthList --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthList {
    // Even though we only have 1 field, we chose not to use a tuple struct here
    // to allow for future extensions more easily.. we could then just add new
    // fields and associated JSON members without affecting consumers of the API
    // too much.
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

impl fmt::Display for CertAuthList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ca in self.cas() {
            writeln!(f, "{}", ca.handle())?;
        }

        Ok(())
    }
}

impl AsRef<Vec<CertAuthSummary>> for CertAuthList {
    fn as_ref(&self) -> &Vec<CertAuthSummary> {
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentKindInfo {
    Ta,
    Embedded,
    Rfc6492,
}

impl fmt::Display for ParentKindInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParentKindInfo::Ta => write!(f, "This CA is a TA"),
            ParentKindInfo::Embedded => write!(f, "Embedded parent"),
            ParentKindInfo::Rfc6492 => write!(f, "RFC 6492 Parent"),
        }
    }
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

//------------ ParentStatuses ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatuses(HashMap<ParentHandle, ParentStatus>);

impl ParentStatuses {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, parent: &ParentHandle) -> Option<&ParentStatus> {
        self.0.get(parent)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ParentHandle, &ParentStatus)> {
        self.0.iter()
    }

    /// Get the first synchronization candidates based on the following:
    /// - take the given ca_parents for which no current status exists first
    /// - then sort by last exchange, minute grade granularity - oldest first
    ///    - where failures come before success within the same minute
    /// - then take the first N parents for this batch
    pub fn sync_candidates(&self, ca_parents: Vec<&ParentHandle>, batch: usize) -> Vec<ParentHandle> {
        let mut parents = vec![];

        // Add any parent for which no current status is known to the candidate list first.
        for parent in ca_parents {
            if !self.0.contains_key(parent) {
                parents.push(parent.clone());
            }
        }

        // Then add the ones for which we do have a status, sorted by their
        // last exchange.
        let mut parents_by_last_exchange = self.sorted_by_last_exchange();
        parents.append(&mut parents_by_last_exchange);

        // But truncate to the specified batch size
        parents.truncate(batch);

        parents
    }

    // Return the parents sorted by last exchange, i.e. let the parents
    // without an exchange be first, and then from longest ago to most recent.
    // Uses minute grade granularity and in cases where the exchanges happened in
    // the same minute failures take precedence (come before) successful exchanges.
    pub fn sorted_by_last_exchange(&self) -> Vec<ParentHandle> {
        let mut sorted_parents: Vec<(&ParentHandle, &ParentStatus)> = self.iter().collect();
        sorted_parents.sort_by(|a, b| {
            // we can map the 'no last exchange' case to 1970..
            let a_last_exchange = a.1.last_exchange.as_ref();
            let b_last_exchange = b.1.last_exchange.as_ref();

            let a_last_exchange_time = a_last_exchange.map(|e| i64::from(e.timestamp)).unwrap_or(0) / 60;
            let b_last_exchange_time = b_last_exchange.map(|e| i64::from(e.timestamp)).unwrap_or(0) / 60;

            if a_last_exchange_time == b_last_exchange_time {
                // compare success / failure
                let a_last_exchange_res = a_last_exchange.map(|e| e.result().was_success()).unwrap_or(false);
                let b_last_exchange_res = b_last_exchange.map(|e| e.result().was_success()).unwrap_or(false);
                a_last_exchange_res.cmp(&b_last_exchange_res)
            } else {
                a_last_exchange_time.cmp(&b_last_exchange_time)
            }
        });

        sorted_parents.into_iter().map(|(handle, _)| handle).cloned().collect()
    }

    pub fn set_failure(&mut self, parent: &ParentHandle, uri: &ServiceUri, error: ErrorResponse, next_seconds: i64) {
        self.get_mut_status(parent)
            .set_failure(uri.clone(), error, next_seconds);
    }

    pub fn set_entitlements(
        &mut self,
        parent: &ParentHandle,
        uri: &ServiceUri,
        entitlements: &Entitlements,
        next_seconds: i64,
    ) {
        self.get_mut_status(parent)
            .set_entitlements(uri.clone(), entitlements, next_seconds);
    }

    pub fn set_last_updated(&mut self, parent: &ParentHandle, uri: &ServiceUri, next_seconds: i64) {
        self.get_mut_status(parent).set_last_updated(uri.clone(), next_seconds);
    }

    fn get_mut_status(&mut self, parent: &ParentHandle) -> &mut ParentStatus {
        if !self.0.contains_key(parent) {
            self.0.insert(parent.clone(), ParentStatus::default());
        }

        self.0.get_mut(parent).unwrap()
    }

    pub fn remove(&mut self, parent: &ParentHandle) {
        self.0.remove(parent);
    }
}

impl IntoIterator for ParentStatuses {
    type Item = (ParentHandle, ParentStatus);
    type IntoIter = std::collections::hash_map::IntoIter<ParentHandle, ParentStatus>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Default for ParentStatuses {
    fn default() -> Self {
        ParentStatuses(HashMap::new())
    }
}

impl fmt::Display for ParentStatuses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (parent, status) in self.0.iter() {
            writeln!(f, "Parent: {}", parent)?;
            match &status.last_exchange {
                None => writeln!(f, "Status: connection still pending")?,
                Some(exchange) => {
                    writeln!(f, "URI: {}", exchange.uri)?;
                    writeln!(f, "Status: {}", exchange.result)?;
                    writeln!(f, "Last contacted: {}", exchange.timestamp().to_rfc3339())?;
                    writeln!(
                        f,
                        "Next contact on or before: {}",
                        status.next_exchange_before().to_rfc3339()
                    )?;

                    if exchange.was_success() {
                        write!(f, "Resource Entitlements:")?;
                    } else {
                        write!(f, "LAST KNOWN Resource Entitlements:")?;
                    }

                    if status.entitlements.is_empty() {
                        writeln!(f, " None")?;
                    } else {
                        writeln!(f, " {}", status.all_resources)?;
                        for (rc, set) in status.entitlements.iter() {
                            writeln!(f, "  resource class: {}", rc)?;
                            writeln!(f, "  issuing cert uri: {}", set.parent_cert.uri)?;
                            writeln!(f, "  received certificate(s):")?;
                            for rcvd in set.received.iter() {
                                writeln!(f, "    published at: {}", rcvd.uri)?;
                                writeln!(f, "    resources:    {}", rcvd.resources)?;
                                writeln!(f, "    cert PEM:\n\n{}\n", rcvd.cert_pem)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KnownEntitlement {
    parent_cert: ParentStatusIssuingCert,
    received: Vec<ParentStatusCert>,
}

impl KnownEntitlement {
    fn resource_set(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for rcvd in &self.received {
            resources = resources.union(&rcvd.resources)
        }
        resources
    }
}

impl From<&EntitlementClass> for KnownEntitlement {
    fn from(entitlement: &EntitlementClass) -> Self {
        let parent_cert = entitlement.issuer().into();
        let received = entitlement.issued().iter().map(|issued| issued.into()).collect();

        KnownEntitlement { parent_cert, received }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatusIssuingCert {
    uri: uri::Rsync,
    cert_pem: String,
}

impl From<&SigningCert> for ParentStatusIssuingCert {
    fn from(signing: &SigningCert) -> Self {
        let cert = base64::encode(signing.cert().to_captured().as_slice());
        let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert);

        ParentStatusIssuingCert {
            uri: signing.uri().clone(),
            cert_pem,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatusCert {
    uri: uri::Rsync,
    resources: ResourceSet,
    cert_pem: String,
}

impl From<&IssuedCert> for ParentStatusCert {
    fn from(issued: &IssuedCert) -> Self {
        let cert = base64::encode(issued.cert.to_captured().as_slice());
        let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert);
        ParentStatusCert {
            uri: issued.uri().clone(),
            resources: issued.resource_set().clone(),
            cert_pem,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatus {
    last_exchange: Option<ParentExchange>,
    last_success: Option<Timestamp>,
    next_exchange_before: Timestamp,
    all_resources: ResourceSet,
    entitlements: HashMap<ResourceClassName, KnownEntitlement>,
}

impl ParentStatus {
    fn next_exchange_before(&self) -> Timestamp {
        self.next_exchange_before
    }

    pub fn last_success(&self) -> Option<Timestamp> {
        self.last_success
    }

    pub fn last_exchange(&self) -> Option<&ParentExchange> {
        self.last_exchange.as_ref()
    }

    pub fn entitlements(&self) -> &HashMap<ResourceClassName, KnownEntitlement> {
        &self.entitlements
    }

    pub fn to_failure_opt(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().map(|e| e.to_failure_opt()).flatten()
    }

    fn set_next_exchange(&mut self, next_run_seconds: i64) {
        self.next_exchange_before = Timestamp::now_plus_seconds(next_run_seconds);
    }

    fn set_failure(&mut self, uri: ServiceUri, error: ErrorResponse, next_run_seconds: i64) {
        self.last_exchange = Some(ParentExchange {
            timestamp: Timestamp::now(),
            uri,
            result: ExchangeResult::Failure(error),
        });
        self.set_next_exchange(next_run_seconds);
    }

    fn set_entitlements(&mut self, uri: ServiceUri, entitlements: &Entitlements, next_run_seconds: i64) {
        self.set_last_updated(uri, next_run_seconds);

        self.entitlements = entitlements
            .classes()
            .iter()
            .map(|rc| {
                let resource_class_name = rc.class_name().clone();
                let known_entitlements = rc.into();
                (resource_class_name, known_entitlements)
            })
            .collect();

        let mut all_resources = ResourceSet::default();
        for entitlement in self.entitlements.values() {
            all_resources = all_resources.union(&entitlement.resource_set())
        }

        self.all_resources = all_resources;
        self.set_next_exchange(next_run_seconds);
    }

    fn set_last_updated(&mut self, uri: ServiceUri, next_run_seconds: i64) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });
        self.last_success = Some(timestamp);
        self.set_next_exchange(next_run_seconds);
    }
}

impl Default for ParentStatus {
    fn default() -> Self {
        ParentStatus {
            last_exchange: None,
            last_success: None,
            all_resources: ResourceSet::default(),
            next_exchange_before: Timestamp::now() + Duration::hours(1),
            entitlements: HashMap::new(),
        }
    }
}

//------------ RepoStatus ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStatus {
    last_exchange: Option<ParentExchange>,
    last_success: Option<Timestamp>,
    next_exchange_before: Timestamp,
    published: Vec<PublishElement>,
}

impl Default for RepoStatus {
    fn default() -> Self {
        RepoStatus {
            last_exchange: None,
            last_success: None,
            next_exchange_before: Timestamp::now_plus_hours(1),
            published: vec![],
        }
    }
}

impl RepoStatus {
    pub fn next_exchange_before(&self) -> Timestamp {
        self.next_exchange_before
    }

    pub fn last_exchange(&self) -> Option<&ParentExchange> {
        self.last_exchange.as_ref()
    }

    pub fn last_success(&self) -> Option<Timestamp> {
        self.last_success
    }

    pub fn to_failure_opt(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().map(|e| e.to_failure_opt()).flatten()
    }
}

impl RepoStatus {
    pub fn set_failure(&mut self, uri: ServiceUri, error: ErrorResponse) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Failure(error),
        });
        self.next_exchange_before = timestamp.plus_minutes(5);
    }

    pub fn set_published(&mut self, uri: ServiceUri, published: Vec<PublishElement>, next_update: Timestamp) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });
        self.published = published;
        self.last_success = Some(timestamp);
        self.next_exchange_before = next_update;
    }

    pub fn set_last_updated(&mut self, uri: ServiceUri, next_update: Timestamp) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });
        self.last_success = Some(timestamp);
        self.next_exchange_before = next_update;
    }
}

impl fmt::Display for RepoStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.last_exchange {
            None => writeln!(f, "Status: connection still pending")?,
            Some(exchange) => {
                Time::now();

                writeln!(f, "URI: {}", exchange.uri())?;
                writeln!(f, "Status: {}", exchange.result)?;
                writeln!(f, "Last contacted: {}", exchange.timestamp().to_rfc3339())?;
                if let Some(success) = self.last_success() {
                    writeln!(f, "Last successful contact: {}", success.to_rfc3339())?;
                }
                writeln!(
                    f,
                    "Next contact on or before: {}",
                    self.next_exchange_before().to_rfc3339()
                )?;
            }
        }
        Ok(())
    }
}

//------------ ParentExchange ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentExchange {
    timestamp: Timestamp,
    uri: ServiceUri,
    result: ExchangeResult,
}

impl ParentExchange {
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn uri(&self) -> &ServiceUri {
        &self.uri
    }

    pub fn result(&self) -> &ExchangeResult {
        &self.result
    }

    pub fn was_success(&self) -> bool {
        self.result.was_success()
    }

    pub fn to_failure_opt(&self) -> Option<ErrorResponse> {
        match &self.result {
            ExchangeResult::Success => None,
            ExchangeResult::Failure(error) => Some(error.clone()),
        }
    }
}

//------------ ExchangeResult ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ExchangeResult {
    Success,
    Failure(ErrorResponse),
}

impl ExchangeResult {
    pub fn was_success(&self) -> bool {
        match self {
            ExchangeResult::Success => true,
            ExchangeResult::Failure(_) => false,
        }
    }
}

impl fmt::Display for ExchangeResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExchangeResult::Success => write!(f, "success"),
            ExchangeResult::Failure(e) => write!(f, "failure: {}", e.msg()),
        }
    }
}

//------------ ChildConnectionStats ------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildrenConnectionStats {
    children: Vec<ChildConnectionStats>,
}

impl ChildrenConnectionStats {
    pub fn new(children: Vec<ChildConnectionStats>) -> Self {
        ChildrenConnectionStats { children }
    }

    pub fn suspension_candidates(&self, threshold_seconds: i64) -> Vec<ChildHandle> {
        self.children
            .iter()
            .filter(|child| child.is_suspension_candidate(threshold_seconds))
            .map(|child| child.handle.clone())
            .collect()
    }
}

impl fmt::Display for ChildrenConnectionStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.children.is_empty() {
            writeln!(f, "handle,user_agent,last_exchange,result,state")?;
            for child in &self.children {
                match &child.last_exchange {
                    None => {
                        writeln!(f, "{},n/a,never,n/a,{}", child.handle, child.state)?;
                    }
                    Some(exchange) => {
                        let agent = exchange.user_agent.as_deref().unwrap_or("");

                        writeln!(
                            f,
                            "{},{},{},{},{}",
                            child.handle,
                            agent,
                            exchange.timestamp.to_rfc3339(),
                            exchange.result,
                            child.state
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildConnectionStats {
    handle: ChildHandle,
    last_exchange: Option<ChildExchange>,
    state: ChildState,
}

impl ChildConnectionStats {
    pub fn new(handle: ChildHandle, last_exchange: Option<ChildExchange>, state: ChildState) -> Self {
        ChildConnectionStats {
            handle,
            last_exchange,
            state,
        }
    }

    /// The child is considered a candidate for suspension if:
    ///  - it is Krill 0.9.2-rc and up (see #670)
    ///  - the last exchange is longer ago than the specified threshold hours
    ///  - and the child is not already suspended
    pub fn is_suspension_candidate(&self, threshold_seconds: i64) -> bool {
        if self.state == ChildState::Suspended {
            false
        } else {
            self.last_exchange
                .as_ref()
                .map(|exchange| exchange.is_krill_above_0_9_1() && exchange.more_than_seconds_ago(threshold_seconds))
                .unwrap_or(false)
        }
    }
}

//------------ ChildStatus ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildStatus {
    last_exchange: Option<ChildExchange>,
    last_success: Option<Timestamp>,
    suspended: Option<Timestamp>,
}

impl ChildStatus {
    pub fn set_success(&mut self, user_agent: Option<String>) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ChildExchange {
            result: ExchangeResult::Success,
            timestamp,
            user_agent,
        });
        self.last_success = Some(timestamp);
        self.suspended = None;
    }

    pub fn set_failure(&mut self, user_agent: Option<String>, error_response: ErrorResponse) {
        self.last_exchange = Some(ChildExchange {
            timestamp: Timestamp::now(),
            result: ExchangeResult::Failure(error_response),
            user_agent,
        });
        self.suspended = None;
    }

    pub fn set_suspended(&mut self) {
        self.suspended = Some(Timestamp::now())
    }

    pub fn last_exchange(&self) -> Option<&ChildExchange> {
        self.last_exchange.as_ref()
    }

    pub fn last_success(&self) -> Option<Timestamp> {
        self.last_success
    }

    pub fn suspended(&self) -> Option<Timestamp> {
        self.suspended
    }

    pub fn child_state(&self) -> ChildState {
        if self.suspended.is_none() {
            ChildState::Active
        } else {
            ChildState::Suspended
        }
    }
}

impl Default for ChildStatus {
    fn default() -> Self {
        ChildStatus {
            last_exchange: None,
            last_success: None,
            suspended: None,
        }
    }
}

impl From<ChildStatus> for Option<ChildExchange> {
    fn from(status: ChildStatus) -> Self {
        status.last_exchange
    }
}

//------------ ChildExchange -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildExchange {
    timestamp: Timestamp,
    result: ExchangeResult,
    user_agent: Option<String>,
}

impl ChildExchange {
    pub fn was_success(&self) -> bool {
        self.result.was_success()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn user_agent(&self) -> Option<&String> {
        self.user_agent.as_ref()
    }

    pub fn more_than_seconds_ago(&self, seconds: i64) -> bool {
        self.timestamp < Timestamp::now_minus_seconds(seconds)
    }

    pub fn is_krill_above_0_9_1(&self) -> bool {
        if let Some(agent) = &self.user_agent {
            // local-child is used by local children, it is extremely
            // unlikely that they would become suspend candidates in
            // the real world - but.. we have to use these to test the
            // auto-suspend logic in the high-level "suspend.rs" test
            if agent == "local-child" {
                return true;
            } else if let Some(version) = agent.strip_prefix("krill/") {
                if let Ok(krill_version) = KrillVersion::from_str(version) {
                    return krill_version > KrillVersion::release(0, 9, 1);
                }
            }
        }
        false
    }
}

//------------ Timestamp -----------------------------------------------------

/// A wrapper for unix timestamps with second precision, with some convenient stuff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(Time::now().timestamp())
    }

    pub fn now_plus_hours(hours: i64) -> Self {
        Timestamp::now().plus_hours(hours)
    }

    pub fn plus_hours(self, hours: i64) -> Self {
        self + Duration::hours(hours)
    }

    pub fn now_minus_hours(hours: i64) -> Self {
        Timestamp::now().minus_hours(hours)
    }

    pub fn minus_hours(self, hours: i64) -> Self {
        self - Duration::hours(hours)
    }

    pub fn now_plus_minutes(minutes: i64) -> Self {
        Timestamp::now().plus_minutes(minutes)
    }

    pub fn plus_minutes(self, minutes: i64) -> Self {
        self + Duration::minutes(minutes)
    }

    pub fn minus_seconds(self, seconds: i64) -> Self {
        self - Duration::seconds(seconds)
    }

    pub fn plus_seconds(self, seconds: i64) -> Self {
        self + Duration::seconds(seconds)
    }

    pub fn now_minus_seconds(seconds: i64) -> Self {
        Timestamp::now().minus_seconds(seconds)
    }

    pub fn now_plus_seconds(seconds: i64) -> Self {
        Timestamp::now().plus_seconds(seconds)
    }

    pub fn to_rfc3339(self) -> String {
        Time::from(self).to_rfc3339()
    }
}

impl From<Timestamp> for Time {
    fn from(timestamp: Timestamp) -> Self {
        Time::new(Utc.timestamp(timestamp.0, 0))
    }
}

impl From<Time> for Timestamp {
    fn from(time: Time) -> Self {
        Timestamp(time.timestamp())
    }
}

impl From<Timestamp> for i64 {
    fn from(t: Timestamp) -> Self {
        t.0
    }
}

//--- Display

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//--- Add

impl ops::Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        Timestamp(self.0 + duration.num_seconds())
    }
}

impl ops::AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, duration: Duration) {
        self.0 += duration.num_seconds();
    }
}

//--- Sub

impl ops::Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self::Output {
        Timestamp(self.0 - duration.num_seconds())
    }
}

impl ops::SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, duration: Duration) {
        self.0 -= duration.num_seconds()
    }
}

//------------ CertAuthInfo --------------------------------------------------

/// This type represents the details of a CertAuth that need
/// to be exposed through the API/CLI/UI
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInfo {
    handle: Handle,
    id_cert: IdCertPem,
    repo_info: Option<RepoInfo>,
    parents: Vec<ParentInfo>,
    resources: ResourceSet,
    resource_classes: HashMap<ResourceClassName, ResourceClassInfo>,
    children: Vec<ChildHandle>,
    suspended_children: Vec<ChildHandle>,
}

impl CertAuthInfo {
    pub fn new(
        handle: Handle,
        id_cert: IdCertPem,
        repo_info: Option<RepoInfo>,
        parents: HashMap<ParentHandle, ParentCaContact>,
        resource_classes: HashMap<ResourceClassName, ResourceClassInfo>,
        children: Vec<ChildHandle>,
        suspended_children: Vec<ChildHandle>,
    ) -> Self {
        let parents = parents
            .into_iter()
            .map(|(handle, contact)| ParentInfo::new(handle, contact))
            .collect();

        let empty = ResourceSet::default();
        let resources = resource_classes.values().fold(ResourceSet::default(), |res, rci| {
            let rc_resources = rci.current_resources().unwrap_or(&empty);
            res.union(rc_resources)
        });

        CertAuthInfo {
            handle,
            id_cert,
            repo_info,
            parents,
            resources,
            resource_classes,
            children,
            suspended_children,
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn id_cert(&self) -> &IdCertPem {
        &self.id_cert
    }

    pub fn repo_info(&self) -> Option<&RepoInfo> {
        self.repo_info.as_ref()
    }

    pub fn parents(&self) -> &Vec<ParentInfo> {
        &self.parents
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn resource_classes(&self) -> &HashMap<ResourceClassName, ResourceClassInfo> {
        &self.resource_classes
    }

    pub fn children(&self) -> &Vec<ChildHandle> {
        &self.children
    }

    pub fn suspended_children(&self) -> &Vec<ChildHandle> {
        &self.suspended_children
    }
}

impl fmt::Display for CertAuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Name:     {}", self.handle())?;
        writeln!(f)?;

        if let Some(repo_info) = self.repo_info() {
            let base_uri = repo_info.base_uri();
            let rrdp_uri = repo_info.rpki_notify();
            writeln!(f, "Base uri: {}", base_uri)?;
            writeln!(f, "RRDP uri: {}", rrdp_uri)?;
        } else {
            writeln!(f, "No repository configured.")?;
        }
        writeln!(f)?;

        writeln!(f, "ID cert PEM:\n{}", self.id_cert().pem())?;
        writeln!(f, "Hash: {}", self.id_cert().hash())?;
        writeln!(f)?;

        let resources = self.resources();
        if resources.is_empty() {
            writeln!(f, "Total resources: <none>")?;
        } else {
            writeln!(f, "Total resources:")?;
            writeln!(f, "    ASNs: {}", resources.asn())?;
            writeln!(f, "    IPv4: {}", resources.v4())?;
            writeln!(f, "    IPv6: {}", resources.v6())?;
        }
        writeln!(f)?;

        writeln!(f, "Parents:")?;
        if !self.parents().is_empty() {
            for parent in self.parents().iter() {
                writeln!(f, "{}", parent)?;
            }
            writeln!(f)?;
        } else {
            writeln!(f, "<none>")?;
        }

        for (name, rc) in self.resource_classes() {
            writeln!(f, "Resource Class: {}", name,)?;
            writeln!(f, "Parent: {}", rc.parent_handle())?;
            writeln!(f, "{}", rc.keys())?;
        }

        writeln!(f, "Children:")?;
        if !self.children().is_empty() {
            for child_handle in self.children() {
                writeln!(f, "{}", child_handle)?;
            }
        } else {
            writeln!(f, "<none>")?;
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
}

impl ResourceClassInfo {
    pub fn new(name_space: String, parent_handle: ParentHandle, keys: ResourceClassKeysInfo) -> Self {
        ResourceClassInfo {
            name_space,
            parent_handle,
            keys,
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

    pub fn new_key(&self) -> Option<&CertifiedKeyInfo> {
        self.keys.new_key()
    }

    pub fn current_resources(&self) -> Option<&ResourceSet> {
        self.current_key().map(|k| k.incoming_cert().resources())
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingInfo {
    #[serde(rename = "pending_key")]
    pub _pending_key: PendingKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveInfo {
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollPendingInfo {
    #[serde(rename = "pending_key")]
    pub _pending_key: PendingKeyInfo,
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollNewInfo {
    #[serde(rename = "new_key")]
    pub _new_key: CertifiedKeyInfo,
    #[serde(rename = "active_key")]
    pub _active_key: CertifiedKeyInfo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    pub fn new_key(&self) -> Option<&CertifiedKeyInfo> {
        if let ResourceClassKeysInfo::RollNew(new) = self {
            Some(&new._new_key)
        } else {
            None
        }
    }
}

impl fmt::Display for ResourceClassKeysInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = String::new();

        res.push_str("State: ");

        match &self {
            ResourceClassKeysInfo::Pending(_) => res.push_str("pending"),
            ResourceClassKeysInfo::Active(_) => res.push_str("active"),
            ResourceClassKeysInfo::RollPending(_) => res.push_str("roll phase 1: pending and active key"),
            ResourceClassKeysInfo::RollNew(_) => res.push_str("roll phase 2: new and active key"),
            ResourceClassKeysInfo::RollOld(_) => res.push_str("roll phase 3: active and old key"),
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

/// This struct contains the API details for the configure Repository server,
/// and objects published there, for a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaRepoDetails {
    contact: RepositoryContact,
}

impl CaRepoDetails {
    pub fn new(contact: RepositoryContact) -> Self {
        CaRepoDetails { contact }
    }

    pub fn contact(&self) -> &RepositoryContact {
        &self.contact
    }
}

impl fmt::Display for CaRepoDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Repository Details:")?;
        writeln!(f, "  service uri: {}", self.contact.service_uri())?;
        let repo_info = self.contact.repo_info();
        writeln!(f, "  base_uri:    {}", repo_info.base_uri())?;
        writeln!(f, "  rpki_notify: {}", repo_info.rpki_notify())?;
        writeln!(f)?;

        Ok(())
    }
}

//------------ AllCertAuthIssues ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllCertAuthIssues {
    cas: HashMap<Handle, CertAuthIssues>,
}

impl Default for AllCertAuthIssues {
    fn default() -> Self {
        AllCertAuthIssues { cas: HashMap::new() }
    }
}

impl AllCertAuthIssues {
    pub fn add(&mut self, ca: Handle, ca_issues: CertAuthIssues) {
        self.cas.insert(ca, ca_issues);
    }

    pub fn cas(&self) -> &HashMap<Handle, CertAuthIssues> {
        &self.cas
    }
}

impl fmt::Display for AllCertAuthIssues {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cas = self.cas();
        if cas.is_empty() {
            writeln!(f, "no issues found")?;
        } else {
            for (ca, issues) in cas.iter() {
                writeln!(f, "Found issue for CA '{}':", ca)?;

                if let Some(repo_issue) = issues.repo_issue() {
                    writeln!(f, "   Repository Issue: {}", repo_issue)?;
                }
                let parent_issues = issues.parent_issues();
                if !parent_issues.is_empty() {
                    for parent_issue in parent_issues.iter() {
                        writeln!(
                            f,
                            "   Parent '{}' has issue: {}",
                            parent_issue.parent, parent_issue.issue
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

//------------ CertAuthIssues ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthIssues {
    repo_issue: Option<ErrorResponse>,
    parent_issues: Vec<CertAuthParentIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthParentIssue {
    pub parent: ParentHandle,
    pub issue: ErrorResponse,
}

impl Default for CertAuthIssues {
    fn default() -> Self {
        CertAuthIssues {
            repo_issue: None,
            parent_issues: vec![],
        }
    }
}

impl CertAuthIssues {
    pub fn add_repo_issue(&mut self, issue: ErrorResponse) {
        self.repo_issue = Some(issue);
    }

    pub fn repo_issue(&self) -> Option<&ErrorResponse> {
        self.repo_issue.as_ref()
    }

    pub fn add_parent_issue(&mut self, parent: ParentHandle, issue: ErrorResponse) {
        let parent_issue = CertAuthParentIssue { parent, issue };
        self.parent_issues.push(parent_issue);
    }

    pub fn parent_issues(&self) -> &Vec<CertAuthParentIssue> {
        &self.parent_issues
    }

    pub fn is_empty(&self) -> bool {
        self.repo_issue.is_none() && self.parent_issues.is_empty()
    }
}

impl fmt::Display for CertAuthIssues {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            writeln!(f, "no issues found")?;
        } else {
            if let Some(repo_issue) = self.repo_issue() {
                writeln!(f, "Repository Issue: {}", repo_issue)?;
            }
            let parent_issues = self.parent_issues();
            if !parent_issues.is_empty() {
                for parent_issue in parent_issues.iter() {
                    writeln!(f, "Parent '{}' has issue: {}", parent_issue.parent, parent_issue.issue)?;
                }
            }
        }
        Ok(())
    }
}

//------------ CertAuthStats -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthStats {
    roa_count: usize,
    child_count: usize,
    bgp_stats: BgpStats,
}

impl CertAuthStats {
    pub fn new(roa_count: usize, child_count: usize, bgp_stats: BgpStats) -> Self {
        CertAuthStats {
            roa_count,
            child_count,
            bgp_stats,
        }
    }

    pub fn roa_count(&self) -> usize {
        self.roa_count
    }

    pub fn child_count(&self) -> usize {
        self.child_count
    }

    pub fn bgp_stats(&self) -> &BgpStats {
        &self.bgp_stats
    }
}

//------------ BgpStats ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpStats {
    pub announcements_valid: usize,
    pub announcements_invalid_asn: usize,
    pub announcements_invalid_length: usize,
    pub announcements_disallowed: usize,
    pub announcements_not_found: usize,
    pub roas_too_permissive: usize,
    pub roas_redundant: usize,
    pub roas_stale: usize,
    pub roas_disallowing: usize,
    pub roas_not_held: usize,
    pub roas_total: usize,
}

impl Default for BgpStats {
    fn default() -> Self {
        BgpStats {
            announcements_valid: 0,
            announcements_invalid_asn: 0,
            announcements_invalid_length: 0,
            announcements_disallowed: 0,
            announcements_not_found: 0,
            roas_too_permissive: 0,
            roas_redundant: 0,
            roas_stale: 0,
            roas_disallowing: 0,
            roas_not_held: 0,
            roas_total: 0,
        }
    }
}

impl BgpStats {
    pub fn increment_valid(&mut self) {
        self.announcements_valid += 1;
    }

    pub fn increment_invalid_asn(&mut self) {
        self.announcements_invalid_asn += 1;
    }

    pub fn increment_invalid_length(&mut self) {
        self.announcements_invalid_length += 1;
    }

    pub fn increment_disallowed(&mut self) {
        self.announcements_disallowed += 1;
    }

    pub fn increment_not_found(&mut self) {
        self.announcements_not_found += 1;
    }

    pub fn increment_roas_too_permissive(&mut self) {
        self.roas_too_permissive += 1;
    }

    pub fn increment_roas_redundant(&mut self) {
        self.roas_redundant += 1;
    }

    pub fn increment_roas_not_held(&mut self) {
        self.roas_not_held += 1;
    }

    pub fn increment_roas_stale(&mut self) {
        self.roas_stale += 1;
    }

    pub fn increment_roas_disallowing(&mut self) {
        self.roas_disallowing += 1;
    }

    pub fn increment_roas_total(&mut self) {
        self.roas_total += 1;
    }
}

pub type RtaName = String;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaList(Vec<RtaName>);

impl RtaList {
    pub fn new(list: Vec<RtaName>) -> Self {
        RtaList(list)
    }
}

impl fmt::Display for RtaList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for name in &self.0 {
            writeln!(f, "{}", name)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaPrepResponse(Vec<KeyIdentifier>);

impl RtaPrepResponse {
    pub fn new(keys: Vec<KeyIdentifier>) -> Self {
        RtaPrepResponse(keys)
    }
}

impl From<RtaPrepResponse> for Vec<KeyIdentifier> {
    fn from(r: RtaPrepResponse) -> Self {
        r.0
    }
}

impl fmt::Display for RtaPrepResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Created the following keys")?;
        for key in &self.0 {
            writeln!(f, "  {}", key)?;
        }
        Ok(())
    }
}

//------------ ResSetErr -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceSetError {
    Asn(String),
    V4(String),
    V6(String),
    Mix,
    InheritOnCaCert,
    Limit,
    FromString,
}

impl fmt::Display for ResourceSetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResourceSetError::Asn(s) => write!(f, "Cannot parse ASN resource: {}", s),
            ResourceSetError::V4(s) => write!(f, "Cannot parse IPv4 resource: {}", s),
            ResourceSetError::V6(s) => write!(f, "Cannot parse IPv6 resource: {}", s),
            ResourceSetError::Mix => write!(f, "Mixed Address Families in configured resource set"),
            ResourceSetError::InheritOnCaCert => write!(f, "Found inherited resources on CA certificate"),
            ResourceSetError::Limit => write!(f, "Limit in CSR exceeds resource entitlements."),
            ResourceSetError::FromString => write!(
                f,
                "Cannot parse resource set string, expected: 'asn: <ASNs>, ipv4: <IPv4s>, ipv6: <IPv6s>'."
            ),
        }
    }
}

impl ResourceSetError {
    fn asn(asn: impl fmt::Display) -> Self {
        ResourceSetError::Asn(asn.to_string())
    }

    fn v4(v4: impl fmt::Display) -> Self {
        ResourceSetError::V4(v4.to_string())
    }

    fn v6(v6: impl fmt::Display) -> Self {
        ResourceSetError::V6(v6.to_string())
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use rpki::repository::crypto::{signer::Signer, PublicKeyFormat};

    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::test;

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
    fn all_resources() {
        let asns = "0-4294967295";
        let v4 = "0.0.0.0-255.255.255.255";
        let v6 = "::0/0";

        let _set = ResourceSet::from_strs(asns, v4, v6).unwrap();
    }

    #[test]
    fn signed_objects_uri() {
        let signed_objects_uri = info().ca_repository("");
        assert_eq!(base_uri(), signed_objects_uri)
    }

    #[test]
    fn mft_uri() {
        test::test_under_tmp(|d| {
            let signer = OpenSslSigner::build(&d).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::Rsa).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().rpki_manifest("", &pub_key.key_identifier());

            let mft_path = mft_uri.relative_to(&base_uri()).unwrap();

            assert_eq!(44, mft_path.len());

            // the file name should be the hexencoded pub key info
            // not repeating that here, but checking that the name
            // part is validly hex encoded.
            let name = &mft_path[..40];
            hex::decode(name).unwrap();

            // and the extension is '.mft'
            let ext = &mft_path[40..];
            assert_eq!(ext, ".mft");
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
    fn serialize_deserialize_repo_info() {
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
        let rsync_uri = Some(test::rsync("rsync://localhost/ta/ta.cer"));

        let tal = TrustAnchorLocator::new(vec![uri], rsync_uri, &cert);

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

        assert_ne!(resource_set, resource_set_asn_differs);
        assert_ne!(resource_set, resource_set_v4_differs);
        assert_ne!(resource_set, resource_set_v6_differs);
        assert_ne!(resource_set, resource_set_2);

        let default_set = ResourceSet::default();
        let certified =
            ResourceSet::from_strs("", "10.0.0.0/16, 192.168.0.0/16", "2001:db8::/32, 2000:db8::/32").unwrap();
        assert_ne!(default_set, certified);
        assert_ne!(resource_set, certified);
    }

    #[test]
    fn resource_set_equivalent() {
        let set: ResourceSet =
            serde_json::from_str(include_str!("../../../test-resources/resources/parent_resources.json")).unwrap();
        let equivalent: ResourceSet = serde_json::from_str(include_str!(
            "../../../test-resources/resources/parent_resources_reordered.json"
        ))
        .unwrap();

        assert_eq!(set, equivalent);
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

    #[test]
    fn test_resource_set_intersection() {
        let child_resources_json = include_str!("../../../test-resources/resources/child_resources.json");
        let child_resources: ResourceSet = serde_json::from_str(child_resources_json).unwrap();

        let parent_resources_json = include_str!("../../../test-resources/resources/parent_resources.json");
        let parent_resources: ResourceSet = serde_json::from_str(parent_resources_json).unwrap();

        let intersection = parent_resources.intersection(&child_resources);

        assert_eq!(intersection, child_resources);
    }

    #[test]
    fn resource_set_to_from_string() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set_string = format!("asn: {}, v4: {}, v6: {}", asns, ipv4s, ipv6s);

        let set = ResourceSet::from_str(set_string.as_str()).unwrap();
        let to_string = set.to_string();
        assert_eq!(set_string, to_string);

        let empty_set = ResourceSet::default();
        let empty_set_string = empty_set.to_string();
        let empty_set_from_string = ResourceSet::from_str(&empty_set_string).unwrap();
        assert_eq!(empty_set, empty_set_from_string);
    }

    #[test]
    fn resource_set_difference() {
        let set1_asns = "AS65000-AS65003, AS65005";
        let set2_asns = "AS65000, AS65003, AS65005";
        let asn_added = "AS65001-AS65002";

        let set1_ipv4s = "10.0.0.0-10.4.5.6, 192.168.0.0";
        let set2_ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv4_removed = "10.4.5.7-10.255.255.255";

        let set1_ipv6s = "::1, 2001:db8::/32";
        let set2_ipv6s = "::1, 2001:db8::/56";
        let ipv6_added = "2001:db8:0:100::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";

        let set1 = ResourceSet::from_strs(set1_asns, set1_ipv4s, set1_ipv6s).unwrap();
        let set2 = ResourceSet::from_strs(set2_asns, set2_ipv4s, set2_ipv6s).unwrap();

        let diff = set1.difference(&set2);

        let expected_diff = ResourceSetDiff {
            added: ResourceSet::from_strs(asn_added, "", ipv6_added).unwrap(),
            removed: ResourceSet::from_strs("", ipv4_removed, "").unwrap(),
        };

        assert!(!diff.is_empty());
        assert_eq!(expected_diff, diff);
    }

    #[test]
    fn serde_cert_auth_issues() {
        let mut issues = CertAuthIssues::default();

        use crate::commons::error::Error;
        use crate::commons::util::httpclient;

        issues.add_repo_issue(
            Error::HttpClientError(httpclient::Error::forbidden("https://example.com/")).to_error_response(),
        );
        issues.add_parent_issue(
            Handle::from_str("parent").unwrap(),
            Error::Rfc6492SignatureInvalid.to_error_response(),
        );

        // println!("{}", serde_json::to_string_pretty(&issues).unwrap());
        let serialized = serde_json::to_string_pretty(&issues).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();

        assert_eq!(issues, deserialized);
    }

    #[test]
    fn recognize_suspension_candidate() {
        let handle = Handle::from_str("ca").unwrap();

        let threshold_seconds = 4 * 3600;

        fn new_exchange(agent: &str) -> ChildExchange {
            let user_agent = if agent.is_empty() {
                None
            } else {
                Some(agent.to_string())
            };

            ChildExchange {
                timestamp: Timestamp::now(),
                result: ExchangeResult::Success,
                user_agent,
            }
        }

        fn old_exchange(agent: &str) -> ChildExchange {
            let user_agent = if agent.is_empty() {
                None
            } else {
                Some(agent.to_string())
            };

            ChildExchange {
                timestamp: Timestamp::now_minus_hours(5),
                result: ExchangeResult::Success,
                user_agent,
            }
        }

        fn ca_stats_active_no_exchange(handle: &Handle) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: handle.clone(),
                last_exchange: None,
                state: ChildState::Active,
            }
        }

        fn ca_stats_active(handle: &Handle, exchange: ChildExchange) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: handle.clone(),
                last_exchange: Some(exchange),
                state: ChildState::Active,
            }
        }

        let new_ca = ca_stats_active_no_exchange(&handle);

        let recent_krill_pre_0_9_2 = ca_stats_active(&handle, new_exchange("krill"));
        let recent_krill_post_0_9_1 = ca_stats_active(&handle, new_exchange("krill/0.9.2-rc2"));
        let recent_other_agent = ca_stats_active(&handle, new_exchange("other"));
        let recent_no_agent = ca_stats_active(&handle, new_exchange(""));

        let old_krill_pre_0_9_2 = ca_stats_active(&handle, old_exchange("krill"));
        let old_krill_post_0_9_1 = ca_stats_active(&handle, old_exchange("krill/0.9.2-rc2"));
        let old_other_agent = ca_stats_active(&handle, old_exchange("other"));
        let old_no_agent = ca_stats_active(&handle, old_exchange(""));

        assert!(!new_ca.is_suspension_candidate(threshold_seconds));

        assert!(!recent_krill_pre_0_9_2.is_suspension_candidate(threshold_seconds));
        assert!(!recent_krill_post_0_9_1.is_suspension_candidate(threshold_seconds));
        assert!(!recent_other_agent.is_suspension_candidate(threshold_seconds));
        assert!(!recent_no_agent.is_suspension_candidate(threshold_seconds));

        assert!(!old_krill_pre_0_9_2.is_suspension_candidate(threshold_seconds));
        assert!(!old_other_agent.is_suspension_candidate(threshold_seconds));
        assert!(!old_no_agent.is_suspension_candidate(threshold_seconds));

        assert!(old_krill_post_0_9_1.is_suspension_candidate(threshold_seconds));
    }

    #[test]
    fn find_sync_candidates() {
        let uri = ServiceUri::try_from("https://example.com/rfc6492/child/".to_string()).unwrap();

        let in_five_seconds = Timestamp::now_plus_seconds(5);
        let five_seconds_ago = Timestamp::now_minus_seconds(5);
        let five_mins_ago = Timestamp::now_minus_seconds(300);

        let p1_new_parent = ParentHandle::from_str("p1").unwrap();
        let p2_new_parent = ParentHandle::from_str("p2").unwrap();
        let p3_no_exchange = ParentHandle::from_str("p3").unwrap();
        let p4_success = ParentHandle::from_str("p4").unwrap();
        let p5_failure = ParentHandle::from_str("p5").unwrap();
        let p6_success_long_ago = ParentHandle::from_str("p6").unwrap();

        let p3_status_no_exchange = ParentStatus {
            last_exchange: None,
            last_success: None,
            next_exchange_before: in_five_seconds,
            all_resources: ResourceSet::default(),
            entitlements: HashMap::new(),
        };

        let p4_status_success = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_seconds_ago,
                uri: uri.clone(),
                result: ExchangeResult::Success,
            }),
            last_success: None,
            next_exchange_before: in_five_seconds,
            all_resources: ResourceSet::default(),
            entitlements: HashMap::new(),
        };

        let p5_status_failure = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_seconds_ago,
                uri: uri.clone(),
                result: ExchangeResult::Failure(ErrorResponse::new("err", "err!")),
            }),
            last_success: None,
            next_exchange_before: in_five_seconds,
            all_resources: ResourceSet::default(),
            entitlements: HashMap::new(),
        };

        let p6_status_success_long_ago = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_mins_ago,
                uri: uri.clone(),
                result: ExchangeResult::Success,
            }),
            last_success: None,
            next_exchange_before: in_five_seconds,
            all_resources: ResourceSet::default(),
            entitlements: HashMap::new(),
        };

        let mut inner_statuses = HashMap::new();
        inner_statuses.insert(p3_no_exchange.clone(), p3_status_no_exchange);
        inner_statuses.insert(p4_success.clone(), p4_status_success);
        inner_statuses.insert(p5_failure.clone(), p5_status_failure);
        inner_statuses.insert(p6_success_long_ago.clone(), p6_status_success_long_ago);

        let parent_statuses = ParentStatuses(inner_statuses);

        let ca_parents = vec![
            &p1_new_parent,
            &p2_new_parent,
            &p3_no_exchange,
            &p4_success,
            &p5_failure,
            &p6_success_long_ago,
        ];

        let candidates = parent_statuses.sync_candidates(ca_parents.clone(), 10);

        let expected = vec![
            p1_new_parent.clone(),
            p2_new_parent.clone(),
            p3_no_exchange.clone(),
            p6_success_long_ago.clone(),
            p5_failure.clone(),
            p4_success.clone(),
        ];

        assert_eq!(candidates, expected);

        let candidates_trimmed = parent_statuses.sync_candidates(ca_parents, 1);
        let expected_trimmed = vec![p1_new_parent];

        assert_eq!(candidates_trimmed, expected_trimmed);
    }
}
