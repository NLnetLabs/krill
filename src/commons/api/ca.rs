//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::HashMap;
use std::ops::{self};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, str};

use bytes::Bytes;
use chrono::{Duration, TimeZone, Utc};
use rpki::ca::publication::{PublishDelta, PublishDeltaElement};
use rpki::repository::x509::{Name, Validity};
use serde::{Deserialize, Serialize};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{CaHandle, ChildHandle, ParentHandle, RepoInfo, ServiceUri},
        provisioning::{
            IssuanceRequest, IssuedCert, RequestResourceLimit, ResourceClassEntitlements, ResourceClassListResponse,
            ResourceClassName, SigningCert,
        },
        publication::Base64,
    },
    crypto::{KeyIdentifier, PublicKey},
    repository::{
        aspa::Aspa,
        cert::Cert,
        crl::{Crl, CrlEntry},
        manifest::Manifest,
        resources::{Asn, ResourceSet},
        roa::Roa,
        x509::{Serial, Time},
    },
    rrdp::Hash,
    uri,
};

use crate::commons::crypto::CsrInfo;
use crate::daemon::ca::BgpSecCertInfo;
use crate::{
    commons::{
        api::{
            rrdp::PublishElement, AspaDefinition, ErrorResponse, ParentCaContact, RepositoryContact, RoaAggregateKey,
            RoaPayload,
        },
        util::KrillVersion,
    },
    daemon::ca::RoaPayloadJsonMapKey,
};

use super::{rrdp, BgpSecAsnKey};

//------------ IdCertInfo ----------------------------------------------------

/// A PEM encoded IdCert and sha256 of the encoding, for easier
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdCertInfo {
    public_key: PublicKey,
    base64: Base64,
    hash: Hash,
}

impl IdCertInfo {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn pem(&self) -> String {
        let mut pem = "-----BEGIN CERTIFICATE-----\n".to_string();

        for line in self
            .base64
            .as_str()
            .as_bytes() // so we can use chunks
            .chunks(64)
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
        {
            pem.push_str(line);
            pem.push('\n');
        }

        pem.push_str("-----END CERTIFICATE-----\n");

        pem
    }
}

impl From<&IdCert> for IdCertInfo {
    fn from(cer: &IdCert) -> Self {
        let bytes = cer.to_bytes();

        let public_key = cer.public_key().clone();
        let base64 = Base64::from_content(&bytes);
        let hash = Hash::from_data(&bytes);

        IdCertInfo {
            public_key,
            base64,
            hash,
        }
    }
}

impl From<IdCert> for IdCertInfo {
    fn from(cer: IdCert) -> Self {
        Self::from(&cer) // we need to encode anyhow, we can't move any data
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
    id_cert: IdCertInfo,
    entitled_resources: ResourceSet,
}

impl ChildCaInfo {
    pub fn new(state: ChildState, id_cert: IdCertInfo, entitled_resources: ResourceSet) -> Self {
        ChildCaInfo {
            state,
            id_cert,
            entitled_resources,
        }
    }

    pub fn state(&self) -> ChildState {
        self.state
    }

    pub fn id_cert(&self) -> &IdCertInfo {
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

//------------ ReceivedCert --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Received;

/// A certificate which was received from a parent CA.
pub type ReceivedCert = CertInfo<Received>;

//------------ IssuedCertificate ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Issued;

/// A certificate which has been issued to a delegated (child) CA
pub type IssuedCertificate = CertInfo<Issued>;

//------------ SuspendedCertificate ------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Suspended;

/// An issued certificate which has been (temporarily) suspended because the child is inactive.
pub type SuspendedCert = CertInfo<Suspended>;

//------------ UnsuspendedCertificate ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Unsuspended;

/// A suspended certificate which is to be re-activated.
pub type UnsuspendedCert = CertInfo<Unsuspended>;

//------------ CertInfo ------------------------------------------------------

/// Contains all relevant info about an RPKI certificate.
///
/// Note that while it would be tempting to keep the actual rpki-rs Cert, unfortunately
/// this causes fragility with regards to keeping these objects in history and stricter
/// parsing and validation in future. See issue #819.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertInfo<T> {
    // Where this certificate is published by the parent
    uri: uri::Rsync,

    // The name of this certificate as used on a manifest
    name: ObjectName,

    // Resources contained
    resources: ResourceSet,

    // the limit on the request (default limit is no limits)
    limit: RequestResourceLimit,

    // The subject chosen by the parent. Note that Krill will
    // derive the subject from the public key, but other parents
    // may use a different strategy.
    subject: Name,

    // The validity time for this certificate.
    validity: Validity,

    // The serial number of this certificate (needed for revocation)
    serial: Serial,

    // Contains the public key and SIA
    #[serde(flatten)]
    csr_info: CsrInfo,

    // The actual certificate in base64 format.
    base64: Base64,

    // The certificate's hash
    hash: Hash,

    // So that we can have different types based on the same structure.
    marker: std::marker::PhantomData<T>,
}

impl<T> CertInfo<T> {
    pub fn create(
        cert: Cert,
        uri: uri::Rsync,
        resources: ResourceSet,
        limit: RequestResourceLimit,
    ) -> Result<Self, InvalidCert> {
        let name = {
            let path = uri.path();
            let after_last_slash = path.rfind('/').unwrap_or(0) + 1;
            // certificate file names must end with .cer and have at least
            // one more character before the .cer filename extension - i.e. we
            // expect 5 characters after the last slash.
            if !path.ends_with(".cer") || path.len() < after_last_slash + 5 {
                Err(InvalidCert::Uri(uri.clone()))
            } else {
                Ok(ObjectName(path[after_last_slash..].into()))
            }
        }?;

        let key = cert.subject_public_key_info().clone();
        let ca_repository = cert.ca_repository().ok_or(InvalidCert::CaRepositoryMissing)?.clone();
        let rpki_manifest = cert.rpki_manifest().ok_or(InvalidCert::RpkiManifestMissing)?.clone();
        let rpki_notify = cert.rpki_notify().cloned();

        let csr_info = CsrInfo::new(ca_repository, rpki_manifest, rpki_notify, key);

        let subject = cert.subject().clone();
        let validity = cert.validity();
        let serial = cert.serial_number();
        let base64 = Base64::from(&cert);
        let hash = base64.to_hash();

        base64.to_hash();
        Ok(CertInfo {
            uri,
            name,
            resources,
            limit,
            subject,
            validity,
            serial,
            csr_info,
            base64,
            hash,
            marker: std::marker::PhantomData,
        })
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn limit(&self) -> &RequestResourceLimit {
        &self.limit
    }

    pub fn subject(&self) -> &Name {
        &self.subject
    }

    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    pub fn serial(&self) -> Serial {
        self.serial
    }

    pub fn csr_info(&self) -> &CsrInfo {
        &self.csr_info
    }

    pub fn key_identifier(&self) -> KeyIdentifier {
        self.csr_info.key_id()
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn to_cert(&self) -> Result<Cert, InvalidCert> {
        Cert::decode(self.to_bytes().as_ref()).map_err(|e| InvalidCert::CannotDecode(e.to_string()))
    }

    /// Represent as an RFC 6492 IssuedCert
    pub fn to_rfc6492_issued_cert(&self) -> Result<IssuedCert, InvalidCert> {
        let cert = self.to_cert()?;
        Ok(IssuedCert::new(self.uri.clone(), self.limit.clone(), cert))
    }

    pub fn to_bytes(&self) -> Bytes {
        self.base64.to_bytes()
    }

    /// Clones and then converts this into a certificate of another type.
    pub fn convert<Y>(&self) -> CertInfo<Y> {
        CertInfo {
            uri: self.uri.clone(),
            name: self.name.clone(),
            resources: self.resources.clone(),
            limit: self.limit.clone(),
            subject: self.subject.clone(),
            validity: self.validity,
            serial: self.serial,
            csr_info: self.csr_info.clone(),
            base64: self.base64.clone(),
            hash: self.hash,
            marker: std::marker::PhantomData,
        }
    }

    /// Converts this into a certificate of another type.
    pub fn into_converted<Y>(self) -> CertInfo<Y> {
        CertInfo {
            uri: self.uri,
            name: self.name,
            resources: self.resources,
            limit: self.limit,
            subject: self.subject,
            validity: self.validity,
            serial: self.serial,
            csr_info: self.csr_info,
            base64: self.base64,
            hash: self.hash,
            marker: std::marker::PhantomData,
        }
    }

    /// Returns a (possibly empty) set of reduced applicable resources which is the intersection
    /// of the encompassing resources and this certificate's current resources.
    /// Returns None if the current resource set is not overclaiming and does not need to be
    /// reduced.
    pub fn reduced_applicable_resources(&self, encompassing: &ResourceSet) -> Option<ResourceSet> {
        if encompassing.contains(&self.resources) {
            None
        } else {
            Some(encompassing.intersection(&self.resources))
        }
    }

    /// The name for this certificate
    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    /// The name of the CRL published by THIS certificate.
    pub fn crl_name(&self) -> ObjectName {
        ObjectName::new(&self.key_identifier(), "crl")
    }

    /// The URI of the CRL published BY THIS certificate, i.e. the uri to use
    /// on certs issued by this.
    pub fn crl_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.crl_name())
    }

    /// The name of the MFT published by THIS certificate.
    pub fn mft_name(&self) -> ObjectName {
        ObjectName::new(&self.key_identifier(), "mft")
    }

    /// Return the CA repository URI where this certificate publishes.
    pub fn ca_repository(&self) -> &uri::Rsync {
        self.csr_info.ca_repository()
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
        self.ca_repository().join(name.as_ref()).unwrap()
    }

    /// Returns a Revocation for this certificate
    pub fn revocation(&self) -> Revocation {
        Revocation::new(self.serial, self.validity.not_after())
    }
}

#[derive(Clone, Debug)]
pub enum InvalidCert {
    CaRepositoryMissing,
    RpkiManifestMissing,
    Uri(uri::Rsync),
    CannotDecode(String),
}

impl fmt::Display for InvalidCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidCert::CaRepositoryMissing => write!(
                f,
                "CA certificate lacks id-ad-caRepository (see section 4.8.8.1 of RFC 6487)"
            ),
            InvalidCert::RpkiManifestMissing => write!(
                f,
                "CA certificate lacks id-ad-rpkiManifest (see section 4.8.8.1 of RFC 6487)"
            ),
            InvalidCert::Uri(s) => write!(f, "Cannot derive filename from URI: {}", s),
            InvalidCert::CannotDecode(s) => write!(f, "Cannot decode binary certificate: {}", s),
        }
    }
}

impl std::error::Error for InvalidCert {}

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
    incoming_cert: ReceivedCert,
    request: Option<IssuanceRequest>,
}

impl CertifiedKeyInfo {
    pub fn new(key_id: KeyIdentifier, incoming_cert: ReceivedCert) -> Self {
        CertifiedKeyInfo {
            key_id,
            incoming_cert,
            request: None,
        }
    }

    pub fn key_id(&self) -> &KeyIdentifier {
        &self.key_id
    }
    pub fn incoming_cert(&self) -> &ReceivedCert {
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
pub struct ObjectName(Arc<str>);

impl ObjectName {
    pub fn new(ki: &KeyIdentifier, extension: &str) -> Self {
        ObjectName(format!("{}.{}", ki, extension).into())
    }

    pub fn cer_for_key(ki: &KeyIdentifier) -> Self {
        ObjectName::new(ki, "cer")
    }

    pub fn mft_for_key(ki: &KeyIdentifier) -> Self {
        ObjectName::new(ki, "mft")
    }

    pub fn crl_for_key(ki: &KeyIdentifier) -> Self {
        ObjectName::new(ki, "crl")
    }

    pub fn aspa(customer: Asn) -> Self {
        ObjectName(format!("{}.asa", customer).into())
    }

    pub fn bgpsec(asn: Asn, key: KeyIdentifier) -> Self {
        ObjectName(format!("ROUTER-{:08X}-{}.cer", asn.into_u32(), key).into())
    }
}

impl From<&Cert> for ObjectName {
    fn from(c: &Cert) -> Self {
        Self::cer_for_key(&c.subject_key_identifier())
    }
}

impl From<&Manifest> for ObjectName {
    fn from(m: &Manifest) -> Self {
        Self::mft_for_key(&m.cert().authority_key_identifier().unwrap())
    }
}

impl From<&Crl> for ObjectName {
    fn from(c: &Crl) -> Self {
        Self::crl_for_key(c.authority_key_identifier())
    }
}

impl From<&RoaPayloadJsonMapKey> for ObjectName {
    fn from(auth: &RoaPayloadJsonMapKey) -> Self {
        ObjectName(format!("{}.roa", hex::encode(auth.to_string())).into())
    }
}

impl From<&RoaPayload> for ObjectName {
    fn from(def: &RoaPayload) -> Self {
        ObjectName(format!("{}.roa", hex::encode(def.to_string())).into())
    }
}

impl From<&RoaAggregateKey> for ObjectName {
    fn from(roa_group: &RoaAggregateKey) -> Self {
        ObjectName(
            match roa_group.group() {
                None => format!("AS{}.roa", roa_group.asn()),
                Some(number) => format!("AS{}-{}.roa", roa_group.asn(), number),
            }
            .into(),
        )
    }
}

impl From<&AspaDefinition> for ObjectName {
    fn from(aspa: &AspaDefinition) -> Self {
        Self::aspa(aspa.customer())
    }
}

impl From<&BgpSecCertInfo> for ObjectName {
    fn from(info: &BgpSecCertInfo) -> Self {
        Self::bgpsec(info.asn(), info.public_key().key_identifier())
    }
}

impl From<&BgpSecAsnKey> for ObjectName {
    fn from(asn_key: &BgpSecAsnKey) -> Self {
        Self::bgpsec(asn_key.asn(), asn_key.key_identifier())
    }
}

impl From<&str> for ObjectName {
    fn from(s: &str) -> Self {
        ObjectName(s.into())
    }
}

impl AsRef<str> for ObjectName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for ObjectName {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ Revocation ----------------------------------------------------

/// This type represents an entry to be used on a Certificate Revocation List (CRL).
///
/// The "revocation_date" will be used for the "revocationDate" as described in
/// section 5.1 of RFC 5280. The "expires" time is used to determine when a CRL
/// entry can be purged (i.e. removed) because the entry is no longer relevant.
///
/// The "revocation_date" is set to the time that this object is first created,
/// but it will be persisted for future use. In other words: there is no support
/// for future or past dating this time.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    serial: Serial,
    #[serde(default = "Time::now")]
    revocation_date: Time,
    expires: Time,
}

impl Revocation {
    pub fn new(serial: Serial, expires: Time) -> Self {
        Revocation {
            serial,
            revocation_date: Time::now(),
            expires,
        }
    }
}

impl From<&Cert> for Revocation {
    fn from(cer: &Cert) -> Self {
        Revocation::new(cer.serial_number(), cer.validity().not_after())
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

impl From<&BgpSecCertInfo> for Revocation {
    fn from(info: &BgpSecCertInfo) -> Self {
        Revocation::new(info.serial(), info.expires())
    }
}

//------------ Revocations ---------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        self.0
            .iter()
            .map(|r| CrlEntry::new(r.serial, r.revocation_date))
            .collect()
    }

    /// Purges all expired revocations, and returns them.
    pub fn purge_expired(&mut self) -> Vec<Revocation> {
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

//------------ RevocationsDelta ----------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationsDelta {
    added: Vec<Revocation>,
    dropped: Vec<Revocation>,
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
        let ipv4 = rs.ipv4().iter().count();
        let ipv6 = rs.ipv6().iter().count();
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
    handle: CaHandle,
}

impl CertAuthSummary {
    pub fn new(name: CaHandle) -> Self {
        CertAuthSummary { handle: name }
    }

    pub fn handle(&self) -> &CaHandle {
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

    pub fn get_mut_status(&mut self, parent: &ParentHandle) -> &mut ParentStatus {
        if !self.0.contains_key(parent) {
            self.0.insert(parent.clone(), ParentStatus::default());
        }

        self.0.get_mut(parent).unwrap()
    }

    pub fn remove(&mut self, parent: &ParentHandle) {
        self.0.remove(parent);
    }

    pub fn insert(&mut self, parent: ParentHandle, status: ParentStatus) {
        self.0.insert(parent, status);
    }
}

impl IntoIterator for ParentStatuses {
    type Item = (ParentHandle, ParentStatus);
    type IntoIter = std::collections::hash_map::IntoIter<ParentHandle, ParentStatus>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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

                    if exchange.was_success() {
                        write!(f, "Resource Entitlements:")?;
                    } else {
                        write!(f, "LAST KNOWN Resource Entitlements:")?;
                    }

                    if status.classes.is_empty() {
                        writeln!(f, " None")?;
                    } else {
                        writeln!(f, " {}", status.all_resources)?;
                        for class in &status.classes {
                            writeln!(f, "  resource class:     {}", class.class_name())?;
                            writeln!(f, "  entitled resources: {}", class.resource_set())?;
                            writeln!(f, "  entitled not after: {}", class.not_after().to_rfc3339())?;

                            let parent_cert: ParentStatusIssuingCert = class.signing_cert().into();
                            writeln!(f, "  issuing cert uri: {}", parent_cert.uri)?;
                            writeln!(f, "  issuing cert PEM:\n\n{}\n", parent_cert.cert_pem)?;

                            writeln!(f, "  received certificate(s):")?;
                            for issued in class.issued_certs().iter() {
                                let issued: ParentStatusCert = issued.into();

                                writeln!(f, "    published at: {}", issued.uri)?;
                                writeln!(f, "    cert PEM:\n\n{}\n", issued.cert_pem)?;
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
pub struct ParentStatusIssuingCert {
    uri: uri::Rsync,
    cert_pem: String,
}

impl From<&SigningCert> for ParentStatusIssuingCert {
    fn from(signing: &SigningCert) -> Self {
        let cert = base64::encode(signing.cert().to_captured().as_slice());
        let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert);

        ParentStatusIssuingCert {
            uri: signing.url().clone(),
            cert_pem,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatusCert {
    uri: uri::Rsync,
    cert_pem: String,
}

impl From<&IssuedCert> for ParentStatusCert {
    fn from(issued: &IssuedCert) -> Self {
        let cert = base64::encode(issued.cert().to_captured().as_slice());
        let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert);
        ParentStatusCert {
            uri: issued.uri().clone(),
            cert_pem,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatus {
    last_exchange: Option<ParentExchange>,
    last_success: Option<Timestamp>,
    all_resources: ResourceSet,

    // The struct changed - we did not record classes in 0.9.5 and below.
    // Just default to an empty vec in case this field is missing, and
    // ignore the 'entitlements' field that used to be there. This will
    // be updated as soon as the CA synchronizes with its parent again.
    #[serde(default)]
    classes: Vec<ResourceClassEntitlements>,
}

impl ParentStatus {
    pub fn last_success(&self) -> Option<Timestamp> {
        self.last_success
    }

    pub fn last_exchange(&self) -> Option<&ParentExchange> {
        self.last_exchange.as_ref()
    }

    pub fn classes(&self) -> &Vec<ResourceClassEntitlements> {
        &self.classes
    }

    pub fn to_failure_opt(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().and_then(|e| e.to_failure_opt())
    }

    pub fn set_failure(&mut self, uri: ServiceUri, error: ErrorResponse) {
        self.last_exchange = Some(ParentExchange {
            timestamp: Timestamp::now(),
            uri,
            result: ExchangeResult::Failure(error),
        });
    }

    pub fn set_entitlements(&mut self, uri: ServiceUri, entitlements: &ResourceClassListResponse) {
        self.set_last_updated(uri);

        self.classes = entitlements.classes().clone();

        let mut all_resources = ResourceSet::default();
        for class in &self.classes {
            all_resources = all_resources.union(class.resource_set())
        }

        self.all_resources = all_resources;
    }

    pub fn set_last_updated(&mut self, uri: ServiceUri) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });
        self.last_success = Some(timestamp);
    }
}

//------------ RepoStatus ----------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStatus {
    last_exchange: Option<ParentExchange>,
    last_success: Option<Timestamp>,
    published: Vec<PublishElement>,
}

impl RepoStatus {
    pub fn last_exchange(&self) -> Option<&ParentExchange> {
        self.last_exchange.as_ref()
    }

    pub fn last_success(&self) -> Option<Timestamp> {
        self.last_success
    }

    pub fn to_failure_opt(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().and_then(|e| e.to_failure_opt())
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
    }

    pub fn update_published(&mut self, uri: ServiceUri, delta: PublishDelta) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });

        for element in delta.into_elements() {
            match element {
                PublishDeltaElement::Publish(publish) => {
                    self.published.push(publish.into());
                }
                PublishDeltaElement::Update(update) => {
                    let update = rrdp::UpdateElement::from(update);
                    self.published.retain(|el| el.uri() != update.uri());
                    self.published.push(update.into_publish());
                }
                PublishDeltaElement::Withdraw(withdraw) => {
                    let (_tag, uri, _hash) = withdraw.unpack();
                    self.published.retain(|el| el.uri() != &uri);
                }
            }
        }

        self.last_success = Some(timestamp);
    }

    pub fn set_last_updated(&mut self, uri: ServiceUri) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Success,
        });
        self.last_success = Some(timestamp);
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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
    pub fn new(ts: i64) -> Self {
        Timestamp(ts)
    }

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
    handle: CaHandle,
    id_cert: IdCertInfo,
    repo_info: Option<RepoInfo>,
    parents: Vec<ParentInfo>,
    resources: ResourceSet,
    resource_classes: HashMap<ResourceClassName, ResourceClassInfo>,
    children: Vec<ChildHandle>,
    suspended_children: Vec<ChildHandle>,
}

impl CertAuthInfo {
    pub fn new(
        handle: CaHandle,
        id_cert: IdCertInfo,
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

    pub fn handle(&self) -> &CaHandle {
        &self.handle
    }

    pub fn id_cert(&self) -> &IdCertInfo {
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
            let rrdp_uri = repo_info.rpki_notify().map(|uri| uri.as_str()).unwrap_or("<none>");

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
            writeln!(f, "    IPv4: {}", resources.ipv4())?;
            writeln!(f, "    IPv6: {}", resources.ipv6())?;
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
        write!(f, "State: ")?;

        match &self {
            ResourceClassKeysInfo::Pending(_) => write!(f, "pending")?,
            ResourceClassKeysInfo::Active(_) => write!(f, "active")?,
            ResourceClassKeysInfo::RollPending(_) => write!(f, "roll phase 1: pending and active key")?,
            ResourceClassKeysInfo::RollNew(_) => write!(f, "roll phase 2: new and active key")?,
            ResourceClassKeysInfo::RollOld(_) => write!(f, "roll phase 3: active and old key")?,
        }

        if let Some(key) = self.current_key() {
            let resources = key.incoming_cert().resources();
            writeln!(f, "    Resources:")?;
            writeln!(f, "    ASNs: {}", resources.asn())?;
            writeln!(f, "    IPv4: {}", resources.ipv4())?;
            writeln!(f, "    IPv6: {}", resources.ipv6())?;
        }

        Ok(())
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
        let repo_info = self.contact.repo_info();
        let server_info = self.contact.server_info();
        let rrdp_uri = repo_info.rpki_notify().map(|uri| uri.as_str()).unwrap_or("<none>");

        writeln!(f, "Repository Details:")?;
        writeln!(f, "  service uri:    {}", server_info.service_uri())?;
        writeln!(f, "  key identifier: {}", server_info.public_key().key_identifier())?;
        writeln!(f, "  base_uri:       {}", repo_info.base_uri())?;
        writeln!(f, "  rpki_notify:    {}", rrdp_uri)?;
        writeln!(f)?;

        Ok(())
    }
}

//------------ AllCertAuthIssues ---------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllCertAuthIssues {
    cas: HashMap<CaHandle, CertAuthIssues>,
}

impl AllCertAuthIssues {
    pub fn add(&mut self, ca: CaHandle, ca_issues: CertAuthIssues) {
        self.cas.insert(ca, ca_issues);
    }

    pub fn cas(&self) -> &HashMap<CaHandle, CertAuthIssues> {
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthIssues {
    repo_issue: Option<ErrorResponse>,
    parent_issues: Vec<CertAuthParentIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthParentIssue {
    pub parent: ParentHandle,
    pub issue: ErrorResponse,
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use std::convert::TryFrom;

    use rpki::crypto::PublicKeyFormat;

    use crate::{commons::crypto::OpenSslSigner, daemon::ta::TrustAnchorLocator, test};

    use super::*;

    fn base_uri() -> uri::Rsync {
        test::rsync("rsync://localhost/repo/ta/")
    }

    fn rrdp_uri() -> uri::Https {
        test::https("https://localhost/rrdp/notification.xml")
    }

    fn info() -> RepoInfo {
        RepoInfo::new(base_uri(), Some(rrdp_uri()))
    }

    #[test]
    fn signed_objects_uri() {
        let signed_objects_uri = info().ca_repository("");
        assert_eq!(base_uri(), signed_objects_uri)
    }

    #[test]
    fn mft_uri() {
        test::test_under_tmp(|d| {
            let signer = OpenSslSigner::build(&d, "dummy", None).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::Rsa).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().resolve("", ObjectName::mft_for_key(&pub_key.key_identifier()).as_ref());

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
    fn serialize_deserialize_repo_info() {
        let info = RepoInfo::new(
            test::rsync("rsync://some/module/folder/"),
            Some(test::https("https://host/notification.xml")),
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
        let rsync_uri = test::rsync("rsync://localhost/ta/ta.cer");

        let tal = TrustAnchorLocator::new(vec![uri], rsync_uri, cert.subject_public_key_info());

        let expected_tal = include_str!("../../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);
    }

    #[test]
    fn id_cert_pem_match_openssl() {
        let ncc_id = {
            let bytes = include_bytes!("../../../test-resources/remote/ncc-id.der");
            IdCert::decode(bytes.as_ref()).unwrap()
        };

        let ncc_id_openssl_pem = include_str!("../../../test-resources/remote/ncc-id.pem");
        let ncc_id_pem = IdCertInfo::from(&ncc_id);

        assert_eq!(ncc_id_pem.pem(), ncc_id_openssl_pem);
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
            ParentHandle::from_str("parent").unwrap(),
            Error::Rfc6492InvalidCsrSent("invalid csr".to_string()).to_error_response(),
        );

        // println!("{}", serde_json::to_string_pretty(&issues).unwrap());
        let serialized = serde_json::to_string_pretty(&issues).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();

        assert_eq!(issues, deserialized);
    }

    #[test]
    fn recognize_suspension_candidate() {
        let ca_handle = CaHandle::from_str("ca").unwrap();

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

        fn ca_stats_active_no_exchange(child: &CaHandle) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: child.convert(),
                last_exchange: None,
                state: ChildState::Active,
            }
        }

        fn ca_stats_active(child: &CaHandle, exchange: ChildExchange) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: child.convert(),
                last_exchange: Some(exchange),
                state: ChildState::Active,
            }
        }

        let new_ca = ca_stats_active_no_exchange(&ca_handle);

        let recent_krill_pre_0_9_2 = ca_stats_active(&ca_handle, new_exchange("krill"));
        let recent_krill_post_0_9_1 = ca_stats_active(&ca_handle, new_exchange("krill/0.9.2-rc2"));
        let recent_other_agent = ca_stats_active(&ca_handle, new_exchange("other"));
        let recent_no_agent = ca_stats_active(&ca_handle, new_exchange(""));

        let old_krill_pre_0_9_2 = ca_stats_active(&ca_handle, old_exchange("krill"));
        let old_krill_post_0_9_1 = ca_stats_active(&ca_handle, old_exchange("krill/0.9.2-rc2"));
        let old_other_agent = ca_stats_active(&ca_handle, old_exchange("other"));
        let old_no_agent = ca_stats_active(&ca_handle, old_exchange(""));

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
            all_resources: ResourceSet::default(),
            classes: vec![],
        };

        let p4_status_success = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_seconds_ago,
                uri: uri.clone(),
                result: ExchangeResult::Success,
            }),
            last_success: None,
            all_resources: ResourceSet::default(),
            classes: vec![],
        };

        let p5_status_failure = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_seconds_ago,
                uri: uri.clone(),
                result: ExchangeResult::Failure(ErrorResponse::new("err", "err!")),
            }),
            last_success: None,
            all_resources: ResourceSet::default(),
            classes: vec![],
        };

        let p6_status_success_long_ago = ParentStatus {
            last_exchange: Some(ParentExchange {
                timestamp: five_mins_ago,
                uri,
                result: ExchangeResult::Success,
            }),
            last_success: None,
            all_resources: ResourceSet::default(),
            classes: vec![],
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

        #[allow(clippy::redundant_clone)] // false positive in rust 1.63
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
