//! Certificate authorities.

use std::{fmt, ops, str};
use std::collections::hash_map;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::engine::Engine as _;
use bytes::Bytes;
use chrono::{Duration, TimeZone, Utc};
use rpki::uri;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, RepoInfo, ServiceUri,
};
use rpki::ca::provisioning::{
    IssuanceRequest, IssuedCert, RequestResourceLimit,
    ResourceClassEntitlements, ResourceClassListResponse,
    ResourceClassName,
};
use rpki::ca::publication::{Base64, PublishDelta, PublishDeltaElement};
use rpki::crypto::{KeyIdentifier, PublicKey};
use rpki::repository::aspa::Aspa;
use rpki::repository::cert::Cert;
use rpki::repository::crl::{Crl, CrlEntry};
use rpki::repository::manifest::Manifest;
use rpki::repository::resources::{Asn, ResourceSet};
use rpki::repository::roa::Roa;
use rpki::repository::x509::{Name, Serial, Time, Validity};
use rpki::rrdp::Hash;
use serde::{Deserialize, Serialize};
use crate::commons::crypto::CsrInfo;
use crate::commons::error;
use crate::daemon::ca::BgpSecCertInfo;
use crate::commons::util::KrillVersion;
use super::admin::{ParentCaContact, PublishedFile, RepositoryContact};
use super::aspa::AspaDefinition;
use super::bgpsec::BgpSecAsnKey;
use super::error::ErrorResponse;
use super::roa::{RoaPayload, RoaPayloadJsonMapKey};


//------------ IdCertInfo ----------------------------------------------------

/// A encoded ID certificate and SHA256 hash of the encoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdCertInfo {
    /// The public key of the ID certificate.
    pub public_key: PublicKey,

    /// The enocoded ID certificate.
    pub base64: Base64,

    /// The SHA-256 hash over the ID certificate.
    pub hash: Hash,
}

impl IdCertInfo {
    /// Returns the PEM encoding of the certificate.
    pub fn pem(&self) -> IdCertPem {
        IdCertPem { base64: &self.base64 }
    }
}

impl From<&IdCert> for IdCertInfo {
    fn from(cer: &IdCert) -> Self {
        let bytes = cer.to_bytes();
        IdCertInfo {
            public_key: cer.public_key().clone(),
            base64: Base64::from_content(&bytes),
            hash: Hash::from_data(&bytes),
        }
    }
}

impl From<IdCert> for IdCertInfo {
    fn from(cer: IdCert) -> Self {
        Self::from(&cer)
    }
}

impl TryFrom<&IdCertInfo> for IdCert {
    type Error = error::Error;

    fn try_from(info: &IdCertInfo) -> Result<Self, Self::Error> {
        IdCert::decode(info.base64.to_bytes().as_ref()).map_err(|e| {
            error::Error::Custom(format!(
                "Could not decode IdCertInfo into IdCert: {}",
                e
            ))
        })
    }
}

impl fmt::Display for IdCertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.pem())
    }
}


//------------ IdCertPem -----------------------------------------------------

/// A helper type for writing a PEM-encoded ID certifiate.
///
/// A value of this type is returned by [`IdCertInfo::pem`].
pub struct IdCertPem<'a> {
    base64: &'a Base64,
}

impl fmt::Display for IdCertPem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("-----BEGIN CERTIFICATE-----\n")?;

        for line in self
            .base64
            .as_str()
            .as_bytes() // so we can use chunks
            .chunks(64)
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
        {
            f.write_str(line)?;
            f.write_str("\n")?;
        }

        f.write_str("-----END CERTIFICATE-----\n")
    }
}

//------------ ChildState ----------------------------------------------------

/// The suspension status of a child CA.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    /// The child CA is active, i.e., not suspended.
    #[default]
    Active,

    /// The child CA has been suspended.
    Suspended,
}

impl fmt::Display for ChildState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            match &self {
                ChildState::Active => "active",
                ChildState::Suspended => "suspended",
            }
        )
    }
}

//------------ ChildCaInfo ---------------------------------------------------

/// Information about a child CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildCaInfo {
    /// The child CA’s status vis-a-vis suspension.
    pub state: ChildState,

    /// The ID certificate used by the child CA for communication.
    pub id_cert: IdCertInfo,

    /// The resources set assigned to the child CA.
    pub entitled_resources: ResourceSet,
}

impl fmt::Display for ChildCaInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.id_cert.pem())?;
        writeln!(
            f,
            "SHA256 hash of PEM encoded certificate: {}",
            self.id_cert.hash
        )?;
        writeln!(f, "resources: {}", self.entitled_resources)?;
        writeln!(f, "state: {}", self.state)
    }
}


//------------ ReceivedCert --------------------------------------------------

/// A marker indicating that a certificate has been received from a parent CA.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Received;

/// A certificate that was received from a parent CA.
pub type ReceivedCert = CertInfo<Received>;


//------------ IssuedCertificate ---------------------------------------------

/// A marker indicating that a certificate has been issued to a child CA.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Issued;

/// A certificate which has been issued to a child CA.
pub type IssuedCertificate = CertInfo<Issued>;


//------------ SuspendedCertificate ------------------------------------------

/// A marker indicating that a certificate has been suspended.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Suspended;

/// An certificate which has been suspended because the child is inactive.
pub type SuspendedCert = CertInfo<Suspended>;


//------------ UnsuspendedCertificate ----------------------------------------

/// A marker indicating that a certificate needs to be re-activated.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Unsuspended;

/// A certificate that has been unsuspended and needs to be re-activated.
pub type UnsuspendedCert = CertInfo<Unsuspended>;


//------------ CertInfo ------------------------------------------------------

/// All information about an RPKI CA certificate.
///
/// For robustness, we keep all information about the certificate in this
/// separate type rather than just storing the final certificate.
///
/// This type is generic over a marker type `T` indicating the status of the
/// certificate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertInfo<T> {
    /// Where this certificate is published by the parent
    pub uri: uri::Rsync,

    /// The name of this certificate as used on a manifest
    pub name: ObjectName,

    /// The resources assigned to the CA.
    pub resources: ResourceSet,

    /// The resource limit on the signing request.
    ///
    /// The default is to have no limit.
    pub limit: RequestResourceLimit,

    /// The subject chosen by the parent.
    ///
    /// Note that Krill will derive the subject from the public key, but
    /// other parents may use a different strategy.
    pub subject: Name,

    /// The validity time for this certificate.
    pub validity: Validity,

    /// The serial number of this certificate.
    ///
    /// This is needed for revocatio.
    pub serial: Serial,

    /// The certifcate signing request for the certificate.
    ///
    /// This contains the public key and SIA.
    #[serde(flatten)]
    pub csr_info: CsrInfo,

    /// The actual encoded certificate.
    pub base64: Base64,

    /// The SHA-256 hash of the encoded certificate.
    pub hash: Hash,

    /// Marker for the certificate type.
    marker: std::marker::PhantomData<T>,
}

impl<T> CertInfo<T> {
    /// Creates a new value from all parts.
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
        let ca_repository = cert
            .ca_repository()
            .ok_or(InvalidCert::CaRepositoryMissing)?
            .clone();
        let rpki_manifest = cert
            .rpki_manifest()
            .ok_or(InvalidCert::RpkiManifestMissing)?
            .clone();
        let rpki_notify = cert.rpki_notify().cloned();

        let csr_info =
            CsrInfo::new(ca_repository, rpki_manifest, rpki_notify, key);

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

    /// Returns the key identifier for the certificate’s public key.
    pub fn key_identifier(&self) -> KeyIdentifier {
        self.csr_info.key_id()
    }

    /// Returns the expiry time of the certificate.
    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    /// Decodes the certificate.
    pub fn to_cert(&self) -> Result<Cert, CertInfoDecodeError> {
        Cert::decode(
            self.to_bytes().as_ref()
        ).map_err(|e| CertInfoDecodeError(e.to_string()))
    }

    /// Converts the CA certificate to an RFC 6492 issued certificate.
    pub fn to_rfc6492_issued_cert(
        &self
    ) -> Result<IssuedCert, CertInfoDecodeError> {
        let cert = self.to_cert()?;
        Ok(IssuedCert::new(self.uri.clone(), self.limit.clone(), cert))
    }

    /// Returns the raw bytes of the encoded certificate.
    pub fn to_bytes(&self) -> Bytes {
        self.base64.to_bytes()
    }

    /// Clones and then converts this into a certificate of another type.
    pub fn to_converted<Y>(&self) -> CertInfo<Y> {
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

    /// Returns a set of reduced applicable resources.
    ///
    /// This set is the intersection of the encompassing resources and this
    /// certificate's current resources.
    ///
    /// Returns `None` if the current resource set is not overclaiming and
    /// does not need to be reduced.
    pub fn reduced_applicable_resources(
        &self, encompassing: &ResourceSet,
    ) -> Option<ResourceSet> {
        if encompassing.contains(&self.resources) {
            None
        } else {
            Some(encompassing.intersection(&self.resources))
        }
    }

    /// Returns the name of the CRL published by this certificate.
    pub fn crl_name(&self) -> ObjectName {
        ObjectName::from_key(&self.key_identifier(), "crl")
    }

    /// Returns the URI of the CRL published by this certificate.
    ///
    /// This is the URI to use on certs issued by this certificate.
    pub fn crl_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.crl_name())
    }

    /// Returns the name of the manifest published by this certificate.
    pub fn mft_name(&self) -> ObjectName {
        ObjectName::from_key(&self.key_identifier(), "mft")
    }

    /// Returns the URI of the manifest published by this certificate.
    pub fn mft_uri(&self) -> uri::Rsync {
        self.uri_for_object(self.mft_name())
    }

    /// Returns the CA repository URI where this certificate publishes.
    pub fn ca_repository(&self) -> &uri::Rsync {
        self.csr_info.ca_repository()
    }

    /// Returns the URI for an object published by this CA.
    pub fn uri_for_object(&self, name: impl Into<ObjectName>) -> uri::Rsync {
        self.uri_for_name(&name.into())
    }

    /// Returns the URI for an object published by this CA.
    pub fn uri_for_name(&self, name: &ObjectName) -> uri::Rsync {
        // unwraps here are safe
        self.ca_repository().join(name.as_ref()).unwrap()
    }

    /// Returns the revocation information for this certificate
    pub fn revocation(&self) -> Revocation {
        Revocation::new(self.serial, self.validity.not_after())
    }
}


//------------ PendingKeyInfo ------------------------------------------------

/// Information about a pending key in a resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingKeyInfo {
    /// The key identifier of the pending key.
    pub key_id: KeyIdentifier,
}


//------------ CertifiedKeyInfo ----------------------------------------------

/// Information about a certified key.
///
/// Such a key has received an incoming certificate and has at least a
/// manifest and CRL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertifiedKeyInfo {
    /// The key identifier of the key.
    pub key_id: KeyIdentifier,

    /// The certificate received from the parent CA.
    pub incoming_cert: ReceivedCert,

    /// The certification request sent to the parent if available.
    pub request: Option<IssuanceRequest>,
}


//------------ ObjectName ----------------------------------------------------

/// Represents the (deterministic) file names of an RPKI repository object.
///
/// Values of this type can be cloned relatively cheaply. They contain the
/// allocated name behind an arc.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ObjectName(Arc<str>);

impl ObjectName {
    /// Creates a new object.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self(name.into())
    }

    /// Creates a new object name from a key identifer and a file extension.
    pub fn from_key(ki: &KeyIdentifier, extension: &str) -> Self {
        ObjectName(format!("{}.{}", ki, extension).into())
    }

    /// Creates the name for a CA certificate from its key.
    pub fn cer_from_key(ki: &KeyIdentifier) -> Self {
        ObjectName::from_key(ki, "cer")
    }

    /// Creates the name of a manifest from the key of its CA.
    pub fn mft_from_ca_key(ki: &KeyIdentifier) -> Self {
        ObjectName::from_key(ki, "mft")
    }

    /// Creates the name of a CRL from the key of its CA.
    pub fn crl_from_ca_key(ki: &KeyIdentifier) -> Self {
        ObjectName::from_key(ki, "crl")
    }

    /// Creates the name of an ASPA object from the customer ASN.
    pub fn aspa_from_customer(customer: Asn) -> Self {
        ObjectName(format!("{}.asa", customer).into())
    }

    /// Creates the name of a router key from ASN and key identifer.
    pub fn bgpsec(asn: Asn, key: KeyIdentifier) -> Self {
        ObjectName(
            format!("ROUTER-{:08X}-{}.cer", asn.into_u32(), key).into(),
        )
    }
}

impl From<&Cert> for ObjectName {
    fn from(c: &Cert) -> Self {
        Self::cer_from_key(&c.subject_key_identifier())
    }
}

impl From<&Manifest> for ObjectName {
    fn from(m: &Manifest) -> Self {
        Self::mft_from_ca_key(&m.cert().authority_key_identifier().unwrap())
    }
}

impl From<&Crl> for ObjectName {
    fn from(c: &Crl) -> Self {
        Self::crl_from_ca_key(c.authority_key_identifier())
    }
}

impl From<RoaPayloadJsonMapKey> for ObjectName {
    fn from(auth: RoaPayloadJsonMapKey) -> Self {
        ObjectName(format!("{}.roa", hex::encode(auth.to_string())).into())
    }
}

impl From<RoaPayload> for ObjectName {
    fn from(def: RoaPayload) -> Self {
        ObjectName(format!("{}.roa", hex::encode(def.to_string())).into())
    }
}

impl From<&AspaDefinition> for ObjectName {
    fn from(aspa: &AspaDefinition) -> Self {
        Self::aspa_from_customer(aspa.customer)
    }
}

impl From<&BgpSecCertInfo> for ObjectName {
    fn from(info: &BgpSecCertInfo) -> Self {
        Self::bgpsec(info.asn(), info.public_key().key_identifier())
    }
}

impl From<&BgpSecAsnKey> for ObjectName {
    fn from(asn_key: &BgpSecAsnKey) -> Self {
        Self::bgpsec(asn_key.asn, asn_key.key)
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

/// Information for an entry on a CRL.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    /// The serial number of the certificate to be revoked.
    serial: Serial,

    /// The revocation date.
    ///
    /// This is the "revocationDate" as described in section 5.1 of RFC 5280.
    ///
    /// It is set to the time that this object was first created, but it will
    /// be persisted for future use. There is no support for future or past
    /// dating this time.
    #[serde(default = "Time::now")]
    revocation_date: Time,

    /// The expiry time of the revoked object.
    ///
    /// This is used to determine when a CRL entry can be deleted because it
    /// is no longer relevant.
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

/// The list of revocation entries of a CRL.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    /// Converts the revocations to a list of CRL entries.
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        self.0.iter().map(|r| {
            CrlEntry::new(r.serial, r.revocation_date)
        }).collect()
    }

    /// Removes all expired revocations, and returns them.
    pub fn remove_expired(&mut self) -> Vec<Revocation> {
        let (relevant, expired) = self.0.iter().partition(|r| {
            r.expires > Time::now()
        });
        self.0 = relevant;
        expired
    }

    /// Adds a revociation entry to the list.
    ///
    /// The entry is added at the end of the list.
    pub fn add(&mut self, revocation: Revocation) {
        self.0.push(revocation);
    }

    /// Removes the given revocation entry from the list if present.
    pub fn remove(&mut self, revocation: &Revocation) {
        self.0.retain(|existing| existing != revocation);
    }

    /// Applies a revocation delta to the list.
    pub fn apply_delta(&mut self, delta: RevocationsDelta) {
        self.0.retain(|r| !delta.dropped.contains(r));
        for r in delta.added {
            self.add(r);
        }
    }
}


//------------ RevocationsDelta ----------------------------------------------

/// A change to a revocation list.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationsDelta {
    /// The revocation entries to be added.
    added: Vec<Revocation>,

    /// The revocation entries to be removed.
    dropped: Vec<Revocation>,
}

impl RevocationsDelta {
    /// Adds a revocation entry to be added to the revocation list.
    pub fn add(&mut self, revocation: Revocation) {
        self.added.push(revocation);
    }

    /// Adds a revocation entry to be removed from the revocation list.
    pub fn drop(&mut self, revocation: Revocation) {
        self.dropped.push(revocation);
    }
}


//------------ ResourceSetSummary --------------------------------------------

/// A summary of a set of Internet Number Resources.
///
/// This is used for concise reporting.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceSetSummary {
    /// The number of ASN blocks in the set.
    pub asn_blocks: usize,

    /// The number of blocks of IPv4 prefixes in the set.
    pub ipv4_blocks: usize,

    /// The number of blocks of IPv6 prefixes in the set.
    pub ipv6_blocks: usize,
}

impl From<&ResourceSet> for ResourceSetSummary {
    fn from(rs: &ResourceSet) -> Self {
        ResourceSetSummary {
            asn_blocks: rs.asn().iter().count(),
            ipv4_blocks: rs.ipv4().iter().count(),
            ipv6_blocks: rs.ipv6().iter().count(),
        }
    }
}

impl fmt::Display for ResourceSetSummary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "asn: {} blocks, v4: {} blocks, v6: {} blocks",
            self.asn_blocks, self.ipv4_blocks, self.ipv6_blocks
        )
    }
}


//------------ CertAuthList --------------------------------------------------

/// A list of CA summaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthList {
    /// The list of CA summaries.
    ///
    /// Even though we only have one field, we chose not to use a tuple struct
    /// here to allow for future extensions more easily.
    pub cas: Vec<CertAuthSummary>,
}

impl fmt::Display for CertAuthList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ca in &self.cas {
            writeln!(f, "{}", ca.handle)?;
        }

        Ok(())
    }
}


//------------ CertAuthSummary -----------------------------------------------

/// The summary of a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthSummary {
    /// The handle identifying the CA.
    pub handle: CaHandle,
}


//------------ ParentKindInfo ------------------------------------------------

/// The kind of a parent CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentKindInfo {
    /// The CA is a trust anchor and does not have a parent.
    Ta,

    /// The parent is a CA in the same Krill instance.
    Embedded,

    /// The parent is a remote CA with communication via RFC 6492.
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

/// Information about a parent of a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentInfo {
    /// The handle identifying the parent CA.
    pub handle: ParentHandle,

    /// The kind of parent.
    pub kind: ParentKindInfo,
}

impl fmt::Display for ParentInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle: {} Kind: {}", self.handle, self.kind)
    }
}

//------------ ParentStatuses ------------------------------------------------

/// The synchronization status of all parent CAs of a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatuses(HashMap<ParentHandle, ParentStatus>);

impl ParentStatuses {
    /// Returns the number of parent CAs.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether there are no parents.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the status of the parent with the given handle.
    pub fn get(&self, parent: &ParentHandle) -> Option<&ParentStatus> {
        self.0.get(parent)
    }

    /// Returns a mutable reference to the status adding the default if missing.
    pub fn get_or_default_mut(
        &mut self,
        parent: &ParentHandle,
    ) -> &mut ParentStatus {
        if !self.0.contains_key(parent) {
            self.0.insert(parent.clone(), ParentStatus::default());
        }

        self.0.get_mut(parent).unwrap()
    }

    /// Removes the given parent CA.
    pub fn remove(&mut self, parent: &ParentHandle) {
        self.0.remove(parent);
    }

    /// Inserts the status for the given parent CA.
    ///
    /// Overwrites an existing status if the parent CA is already present.
    pub fn insert(&mut self, parent: ParentHandle, status: ParentStatus) {
        self.0.insert(parent, status);
    }

    /// Iterates over pairs of parent handles and their status.
    pub fn iter(&self) -> hash_map::Iter<ParentHandle, ParentStatus> {
        self.0.iter()
    }

    /// Creates a sorted list of parents to be synchronized first.
    ///
    /// All parents given in `ca_parents` are considered as well as all
    /// parents part of `self`.
    ///
    /// Parents which have no current synchronization status are first. The
    /// remaining parents are sorted by their last exchange. Within the same
    /// minute, parents that had a synchronization failure are sorted first.
    pub fn sync_candidates(
        &self,
        ca_parents: Vec<&ParentHandle>,
        batch: usize,
    ) -> Vec<ParentHandle> {
        let mut parents = vec![];

        // Add any parent for which no current status is known to the
        // candidate list first.
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

    /// Return the parents sorted by last exchange.
    ///
    /// The parents without an exchange are sorted first. The remaining
    /// parents are added with longest ago first.
    ///
    /// Uses minute grade granularity and in cases where the exchanges
    /// happened in the same minute failures take precedence (come before)
    /// successful exchanges.
    fn sorted_by_last_exchange(&self) -> Vec<ParentHandle> {
        let mut sorted_parents: Vec<(&ParentHandle, &ParentStatus)> =
            self.iter().collect();
        sorted_parents.sort_by(|a, b| {
            // we can map the 'no last exchange' case to 1970..
            let a_last_exchange = a.1.last_exchange.as_ref();
            let b_last_exchange = b.1.last_exchange.as_ref();

            let a_last_exchange_time =
                a_last_exchange.map(|e| i64::from(e.timestamp)).unwrap_or(0)
                    / 60;
            let b_last_exchange_time =
                b_last_exchange.map(|e| i64::from(e.timestamp)).unwrap_or(0)
                    / 60;

            if a_last_exchange_time == b_last_exchange_time {
                // compare success / failure
                let a_last_exchange_res = a_last_exchange
                    .map(|e| e.result.was_success())
                    .unwrap_or(false);
                let b_last_exchange_res = b_last_exchange
                    .map(|e| e.result.was_success())
                    .unwrap_or(false);
                a_last_exchange_res.cmp(&b_last_exchange_res)
            } else {
                a_last_exchange_time.cmp(&b_last_exchange_time)
            }
        });

        sorted_parents
            .into_iter()
            .map(|(handle, _)| handle)
            .cloned()
            .collect()
    }
}

impl IntoIterator for ParentStatuses {
    type Item = (ParentHandle, ParentStatus);
    type IntoIter = hash_map::IntoIter<ParentHandle, ParentStatus>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ParentStatuses {
    type Item = (&'a ParentHandle, &'a ParentStatus);
    type IntoIter = hash_map::Iter<'a, ParentHandle, ParentStatus>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
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
                    writeln!(
                        f,
                        "Last contacted: {}",
                        exchange.timestamp.into_rfc3339()
                    )?;

                    if exchange.result.was_success() {
                        write!(f, "Resource Entitlements:")?;
                    } else {
                        write!(f, "LAST KNOWN Resource Entitlements:")?;
                    }

                    if status.classes.is_empty() {
                        writeln!(f, " None")?;
                    } else {
                        writeln!(f, " {}", status.all_resources)?;
                        for class in &status.classes {
                            writeln!(
                                f,
                                "  resource class:     {}",
                                class.class_name()
                            )?;
                            writeln!(
                                f,
                                "  entitled resources: {}",
                                class.resource_set()
                            )?;
                            writeln!(
                                f,
                                "  entitled not after: {}",
                                class.not_after().to_rfc3339()
                            )?;

                            let uri = class.signing_cert().url();
                            let cert = BASE64_ENGINE.encode(
                                class.signing_cert().cert()
                                    .to_captured().as_slice()
                            );
                            writeln!(f, "  issuing cert uri: {uri}")?;
                            writeln!(
                                f,
                                "  issuing cert PEM:\n\n\
                                 -----BEGIN CERTIFICATE-----\n\
                                 {cert}\n\
                                 -----END CERTIFICATE-----\n\n",
                            )?;

                            writeln!(f, "  received certificate(s):")?;
                            for issued in class.issued_certs().iter() {
                                let uri = issued.uri();
                                let cert = BASE64_ENGINE.encode(
                                    issued.cert().to_captured().as_slice()
                                );

                                writeln!(f, "    published at: {uri}")?;
                                writeln!(
                                    f,
                                    "    cert PEM:\n\n\
                                     -----BEGIN CERTIFICATE-----\n\
                                     {cert}\n\
                                     -----END CERTIFICATE-----\n\n"
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}


//------------ ParentStatus --------------------------------------------------

/// The synchronization status of a parent CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentStatus {
    /// The last synchronization exchange with the parent.
    ///
    /// This is `None` if there never was an exchange.
    pub last_exchange: Option<ParentExchange>,

    /// The time of the last successful synchronization exchange.
    ///
    /// This is `None` if there never was a successful exchange.
    pub last_success: Option<Timestamp>,

    /// All resources received from the parent.
    pub all_resources: ResourceSet,

    /// The list of resource classes.
    ///
    /// The struct changed - we did not record classes in 0.9.5 and below.
    /// Just default to an empty vec in case this field is missing, and
    /// ignore the 'entitlements' field that used to be there. This will
    /// be updated as soon as the CA synchronizes with its parent again.
    #[serde(default)]
    pub classes: Vec<ResourceClassEntitlements>,
}

impl ParentStatus {
    /// Returns the error response in case the last exchange failed.
    pub fn opt_failure(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().and_then(|e| e.opt_failure())
    }

    /// Sets the last exchange to the given error response.
    pub fn set_failure(&mut self, uri: ServiceUri, error: ErrorResponse) {
        self.last_exchange = Some(ParentExchange {
            timestamp: Timestamp::now(),
            uri,
            result: ExchangeResult::Failure(error),
        });
    }

    /// Sets the entitlements from the given response.
    pub fn set_entitlements(
        &mut self,
        uri: ServiceUri,
        entitlements: &ResourceClassListResponse,
    ) {
        self.set_last_updated(uri);

        self.classes.clone_from(entitlements.classes());

        let mut all_resources = ResourceSet::default();
        for class in &self.classes {
            all_resources = all_resources.union(class.resource_set())
        }

        self.all_resources = all_resources;
    }

    /// Sets the last update to now.
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

/// The repository synchronization status.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStatus {
    /// The last synchronization exchange with the repository.
    ///
    /// This is `None` if there never was an exchange.
    pub last_exchange: Option<ParentExchange>,

    /// The time of the last successful synchronization exchange.
    ///
    /// This is `None` if there never was a successful exchange.
    pub last_success: Option<Timestamp>,

    /// The list of published objects.
    pub published: Vec<PublishedFile>,
}

impl RepoStatus {
    /// Returns the error response in case the last exchange failed.
    pub fn opt_failure(&self) -> Option<ErrorResponse> {
        self.last_exchange.as_ref().and_then(|e| e.opt_failure())
    }

    /// Sets the last exchange to the given error response.
    pub fn set_failure(&mut self, uri: ServiceUri, error: ErrorResponse) {
        let timestamp = Timestamp::now();
        self.last_exchange = Some(ParentExchange {
            timestamp,
            uri,
            result: ExchangeResult::Failure(error),
        });
    }

    /// Updates the published objects from the given delta.
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
                    let (_tag, uri, base64) = publish.unpack();
                    self.published.push(PublishedFile { uri, base64 });
                }
                PublishDeltaElement::Update(update) => {
                    let (_tag, uri, base64, _hash) = update.unpack();
                    self.published.retain(|el| el.uri != uri);
                    self.published.push(PublishedFile { uri, base64 });
                }
                PublishDeltaElement::Withdraw(withdraw) => {
                    let (_tag, uri, _hash) = withdraw.unpack();
                    self.published.retain(|el| el.uri != uri);
                }
            }
        }

        self.last_success = Some(timestamp);
    }

    /// Sets the last update to now.
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

                writeln!(f, "URI: {}", exchange.uri)?;
                writeln!(f, "Status: {}", exchange.result)?;
                writeln!(
                    f,
                    "Last contacted: {}",
                    exchange.timestamp.into_rfc3339()
                )?;
                if let Some(success) = self.last_success.as_ref() {
                    writeln!(
                        f,
                        "Last successful contact: {}",
                        success.into_rfc3339()
                    )?;
                }
            }
        }
        Ok(())
    }
}


//------------ ParentExchange ------------------------------------------------

/// Information about an exchange with a remote server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentExchange {
    /// The time of the exchange.
    pub timestamp: Timestamp,

    /// The service URI of the remote server.
    pub uri: ServiceUri,

    /// The result of the exchange.
    pub result: ExchangeResult,
}

impl ParentExchange {
    pub fn opt_failure(&self) -> Option<ErrorResponse> {
        match &self.result {
            ExchangeResult::Success => None,
            ExchangeResult::Failure(error) => Some(error.clone()),
        }
    }
}


//------------ ExchangeResult ------------------------------------------------

/// The result of an exchange with a remote server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ExchangeResult {
    /// The exchange was concluded successfully.
    Success,

    /// The exchange failed with the given error response.
    Failure(ErrorResponse),
}

impl ExchangeResult {
    /// Returns whether the exchange was a success.
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
            ExchangeResult::Failure(e) => write!(f, "failure: {}", e.msg),
        }
    }
}


//------------ ChildrenConnectionStats ---------------------------------------

/// The synchronization status of all child CAs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildrenConnectionStats {
    /// The synchronization status of all child CAs.
    pub children: Vec<ChildConnectionStats>,
}

impl ChildrenConnectionStats {
    /// Returns a list of all the candidates for suspension.
    ///
    /// See [`ChildConnectionStats::is_suspension_candidate`] for details.
    pub fn suspension_candidates(
        &self,
        threshold_seconds: i64,
    ) -> Vec<ChildHandle> {
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
                        writeln!(
                            f,
                            "{},n/a,never,n/a,{}",
                            child.handle, child.state
                        )?;
                    }
                    Some(exchange) => {
                        let agent =
                            exchange.user_agent.as_deref().unwrap_or("");

                        writeln!(
                            f,
                            "{},{},{},{},{}",
                            child.handle,
                            agent,
                            exchange.timestamp.into_rfc3339(),
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


//------------ ChildConnectionStats ------------------------------------------

/// The synchronization status of a child CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildConnectionStats {
    /// The local handle of the child CA.
    pub handle: ChildHandle,

    /// The last synchronization exchange with the child CA.
    ///
    /// This is `None` if there never was an exchange.
    pub last_exchange: Option<ChildExchange>,

    /// The status of the child CA.
    pub state: ChildState,
}

impl ChildConnectionStats {
    /// Returns whether the child is considered a candidate for suspension.
    ///
    /// The child is considered a candidate for suspension if:
    ///
    ///  * it is Krill 0.9.2-rc and up as we only know the synchronization
    ///    interval for those servers,
    ///  * the last exchange is longer ago than the specified threshold, and
    ///  * the child is not already suspended.
    pub fn is_suspension_candidate(&self, threshold_seconds: i64) -> bool {
        if self.state == ChildState::Suspended {
            false
        }
        else {
            self.last_exchange.as_ref().map(|exchange| {
                exchange.is_krill_above_0_9_1()
                    && exchange.more_than_seconds_ago(threshold_seconds)
            }).unwrap_or(false)
        }
    }
}


//------------ ChildStatus ---------------------------------------------------

/// The synchronization status of a child CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildStatus {
    /// The last synchronization exchange with the child CA.
    ///
    /// This is `None` if there never was an exchange.
    pub last_exchange: Option<ChildExchange>,

    /// The time of the last successful synchronization exchange.
    ///
    /// This is `None` if there never was a successful exchange.
    pub last_success: Option<Timestamp>,

    /// The time the child CA was suspended.
    ///
    /// This is `None` if the child CA isn’t suspended.
    pub suspended: Option<Timestamp>,
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

    pub fn set_failure(
        &mut self,
        user_agent: Option<String>,
        error_response: ErrorResponse,
    ) {
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

/// A synchronization exchange with a child CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildExchange {
    /// The time of the exchange.
    pub timestamp: Timestamp,

    /// The result of the exchange.
    pub result: ExchangeResult,

    /// The user agent of the child CA’s server.
    pub user_agent: Option<String>,
}

impl ChildExchange {
    /// Returns whether the exchange was longer than the given time ago.
    pub fn more_than_seconds_ago(&self, seconds: i64) -> bool {
        self.timestamp < Timestamp::now_minus_seconds(seconds)
    }

    /// Returns whether the child used Krill 0.9.2-rc1 or above.
    pub fn is_krill_above_0_9_1(&self) -> bool {
        if let Some(agent) = &self.user_agent {
            // local-child is used by local children, it is extremely
            // unlikely that they would become suspend candidates in
            // the real world -- but we have to use these to test the
            // auto-suspend logic in the high-level "suspend.rs" test
            if agent == "local-child" {
                return true;
            }
            else if let Some(version) = agent.strip_prefix("krill/") {
                if let Ok(krill_version) = KrillVersion::from_str(version) {
                    return krill_version > KrillVersion::release(0, 9, 1);
                }
            }
        }
        false
    }
}


//------------ Timestamp -----------------------------------------------------

/// A Unix timestamp with second precision in UTC.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd,
    Serialize,
)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Returns a new timestamp from the seconds since the Unix epoch.
    pub fn new(ts: i64) -> Self {
        Timestamp(ts)
    }

    /// Returns a timestamp for the current time.
    pub fn now() -> Self {
        Timestamp(Time::now().timestamp())
    }

    /// Returns a timestamp for the given hours from now.
    pub fn now_plus_hours(hours: i64) -> Self {
        Timestamp::now().plus_hours(hours)
    }

    /// Returns a timestamp the given number of hours past this timestamp.
    pub fn plus_hours(self, hours: i64) -> Self {
        self + Duration::hours(hours)
    }

    /// Returns a timestamp for the given hours ago from now.
    pub fn now_minus_hours(hours: i64) -> Self {
        Timestamp::now().minus_hours(hours)
    }

    /// Returns a timestamp the given number of hours before this timestamp.
    pub fn minus_hours(self, hours: i64) -> Self {
        self - Duration::hours(hours)
    }

    /// Returns a timestamp for the given minutes from now.
    pub fn now_plus_minutes(minutes: i64) -> Self {
        Timestamp::now().plus_minutes(minutes)
    }

    /// Returns a timestamp the given number of minutes past this timestamp.
    pub fn plus_minutes(self, minutes: i64) -> Self {
        self + Duration::minutes(minutes)
    }

    /// Returns a timestamp the given number of seconds before this timestamp.
    pub fn minus_seconds(self, seconds: i64) -> Self {
        self - Duration::seconds(seconds)
    }

    /// Returns a timestamp the given number of seconds past this timestamp.
    pub fn plus_seconds(self, seconds: i64) -> Self {
        self + Duration::seconds(seconds)
    }

    /// Returns a timestamp for the given seconds ago from now.
    pub fn now_minus_seconds(seconds: i64) -> Self {
        Timestamp::now().minus_seconds(seconds)
    }

    /// Returns a timestamp for the given seconds from now.
    pub fn now_plus_seconds(seconds: i64) -> Self {
        Timestamp::now().plus_seconds(seconds)
    }

    /// Converts the timestamp to a string in RFC 3339 format.
    pub fn into_rfc3339(self) -> String {
        Time::from(self).to_rfc3339()
    }
}


//--- From

impl From<Timestamp> for Time {
    fn from(timestamp: Timestamp) -> Self {
        Time::new(
            Utc.timestamp_opt(timestamp.0, 0)
                .single()
                .expect("timestamp out-of-range"),
        )
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

//--- Add, AddAssign, Sub, SubAssign

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


//--- Display

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ CertAuthInfo --------------------------------------------------

/// Detailed information of a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInfo {
    /// The local handle of the CA.
    pub handle: CaHandle,

    /// The identity certifcate used to communicate with the CA.
    pub id_cert: IdCertInfo,

    /// Information about the repository this CA publishes to.
    ///
    /// This is `None` if the CA publishes to the built-in repository.
    pub repo_info: Option<RepoInfo>,

    /// Information about the parent CAs of this CA.
    pub parents: Vec<ParentInfo>,

    /// The resources this CA is entitled to.
    pub resources: ResourceSet,

    /// The resource classes of this CA.
    pub resource_classes: HashMap<ResourceClassName, ResourceClassInfo>,

    /// The local handles of the child CAs of this CA.
    pub children: Vec<ChildHandle>,

    /// The handles fo the child CAs that are currently suspended.
    pub suspended_children: Vec<ChildHandle>,
}

impl CertAuthInfo {
    /// Creates a new value from various details.
    pub fn new(
        handle: CaHandle,
        id_cert: IdCertInfo,
        repo_info: Option<RepoInfo>,
        parents: HashMap<ParentHandle, ParentCaContact>,
        resource_classes: HashMap<ResourceClassName, ResourceClassInfo>,
        children: Vec<ChildHandle>,
        suspended_children: Vec<ChildHandle>,
    ) -> Self {
        let parents = parents.into_keys().map(|handle| {
            ParentInfo { handle, kind: ParentKindInfo::Rfc6492 }
        }).collect();

        let empty = ResourceSet::default();
        let resources = resource_classes.values().fold(
            ResourceSet::default(),
            |res, rci| {
                let rc_resources
                    = rci.keys.current_resources().unwrap_or(&empty);
                res.union(rc_resources)
            },
        );

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
}

impl fmt::Display for CertAuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Name:     {}", self.handle)?;
        writeln!(f)?;

        if let Some(repo_info) = self.repo_info.as_ref() {
            let base_uri = repo_info.base_uri();
            let rrdp_uri = repo_info
                .rpki_notify()
                .map(|uri| uri.as_str())
                .unwrap_or("<none>");

            writeln!(f, "Base uri: {}", base_uri)?;
            writeln!(f, "RRDP uri: {}", rrdp_uri)?;
        } else {
            writeln!(f, "No repository configured.")?;
        }
        writeln!(f)?;

        writeln!(f, "ID cert PEM:\n{}", self.id_cert.pem())?;
        writeln!(f, "Hash: {}", self.id_cert.hash)?;
        writeln!(f)?;

        let resources = &self.resources;
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
        if !self.parents.is_empty() {
            for parent in &self.parents {
                writeln!(f, "{}", parent)?;
            }
            writeln!(f)?;
        } else {
            writeln!(f, "<none>")?;
        }

        for (name, rc) in &self.resource_classes {
            writeln!(f, "Resource Class: {}", name,)?;
            writeln!(f, "Parent: {}", rc.parent_handle)?;
            writeln!(f, "{}", rc.keys)?;
        }

        writeln!(f, "Children:")?;
        if !self.children.is_empty() {
            for child_handle in &self.children {
                writeln!(f, "{}", child_handle)?;
            }
        } else {
            writeln!(f, "<none>")?;
        }

        Ok(())
    }
}


//------------ ResourceClassInfo --------------------------------------------

/// Information about a resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassInfo {
    /// The name space of the resource class.
    pub name_space: String,

    /// The handle of the parent owning the resource class.
    pub parent_handle: ParentHandle,

    /// Information about the keys for the resource class.
    pub keys: ResourceClassKeysInfo,
}


//------------ ResourceClassKeysInfo -----------------------------------------

/// The current key status for a resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClassKeysInfo {
    /// There is a pending key.
    Pending(PendingInfo),

    /// There is an active key.
    Active(ActiveInfo),

    /// Phase 1 of a key roll: pending and active key.
    RollPending(RollPendingInfo),

    /// Phase 2 of a key roll: new and active key.
    RollNew(RollNewInfo),

    /// Phase 3 of a key roll: active and old key.
    RollOld(RollOldInfo),
}

/// Key information for the pending key status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingInfo {
    /// Information about the pending key.
    pub pending_key: PendingKeyInfo,
}

/// Key information for the active key status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveInfo {
    /// Information about the active key.
    pub active_key: CertifiedKeyInfo,
}


/// Key information for phase 1 of a key roll.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollPendingInfo {
    /// Information about the pending key.
    pub pending_key: PendingKeyInfo,

    /// Information about the active key.
    pub active_key: CertifiedKeyInfo,
}

/// Key information for phase 2 of a key roll.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollNewInfo {
    /// Information about the new key.
    pub new_key: CertifiedKeyInfo,

    /// Information about the active key.
    pub active_key: CertifiedKeyInfo,
}

/// Key information for phase 3 of a key roll.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollOldInfo {
    /// Information about the active key.
    pub active_key: CertifiedKeyInfo,

    /// Information about the old key.
    pub old_key: CertifiedKeyInfo,
}

impl ResourceClassKeysInfo {
    /// Returns the currently active key if available.
    pub fn current_key(&self) -> Option<&CertifiedKeyInfo> {
        match &self {
            ResourceClassKeysInfo::Active(current) => {
                Some(&current.active_key)
            }
            ResourceClassKeysInfo::RollPending(pending) => {
                Some(&pending.active_key)
            }
            ResourceClassKeysInfo::RollNew(new) => Some(&new.active_key),
            ResourceClassKeysInfo::RollOld(old) => Some(&old.active_key),
            _ => None,
        }
    }

    /// Returns the new key if available.
    pub fn new_key(&self) -> Option<&CertifiedKeyInfo> {
        if let ResourceClassKeysInfo::RollNew(new) = self {
            Some(&new.new_key)
        } else {
            None
        }
    }

    /// Returns the resources for the currently active key.
    pub fn current_resources(&self) -> Option<&ResourceSet> {
        self.current_key().map(|k| &k.incoming_cert.resources)
    }
}

impl fmt::Display for ResourceClassKeysInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "State: ")?;

        match &self {
            ResourceClassKeysInfo::Pending(_) => write!(f, "pending")?,
            ResourceClassKeysInfo::Active(_) => write!(f, "active")?,
            ResourceClassKeysInfo::RollPending(_) => {
                write!(f, "roll phase 1: pending and active key")?
            }
            ResourceClassKeysInfo::RollNew(_) => {
                write!(f, "roll phase 2: new and active key")?
            }
            ResourceClassKeysInfo::RollOld(_) => {
                write!(f, "roll phase 3: active and old key")?
            }
        }

        if let Some(key) = self.current_key() {
            let resources = &key.incoming_cert.resources;
            writeln!(f, "    Resources:")?;
            writeln!(f, "    ASNs: {}", resources.asn())?;
            writeln!(f, "    IPv4: {}", resources.ipv4())?;
            writeln!(f, "    IPv6: {}", resources.ipv6())?;
        }

        Ok(())
    }
}


//------------ CaRepoDetails -------------------------------------------------

/// Details for the configured repository server for a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaRepoDetails {
    /// Details for the configured repository server for the CA.
    pub contact: RepositoryContact,
}

impl fmt::Display for CaRepoDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let rrdp_uri = self.contact.repo_info
            .rpki_notify()
            .map(|uri| uri.as_str())
            .unwrap_or("<none>");

        writeln!(f, "Repository Details:")?;
        writeln!(
            f, "  service uri:    {}", self.contact.server_info.service_uri
        )?;
        writeln!(
            f,
            "  key identifier: {}",
            self.contact.server_info.public_key.key_identifier()
        )?;
        writeln!(
            f, "  base_uri:       {}", self.contact.repo_info.base_uri()
        )?;
        writeln!(f, "  rpki_notify:    {}", rrdp_uri)?;
        writeln!(f)?;

        Ok(())
    }
}


//------------ AllCertAuthIssues ---------------------------------------------

/// All issues for all CAs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllCertAuthIssues {
    /// The issues for each CA, keyed by its handle.
    pub cas: HashMap<CaHandle, CertAuthIssues>,
}

impl fmt::Display for AllCertAuthIssues {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.cas.is_empty() {
            writeln!(f, "no issues found")?;
        }
        else {
            for (ca, issues) in &self.cas {
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

/// A report of issues happening when synchronizing a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthIssues {
    /// An error happened when synchronizing the repository.
    pub repo_issue: Option<ErrorResponse>,

    /// Errors happened when synchronizing the parent CAs..
    pub parent_issues: Vec<CertAuthParentIssue>,
}

impl CertAuthIssues {
    pub fn repo_issue(&self) -> Option<&ErrorResponse> {
        self.repo_issue.as_ref()
    }

    pub fn add_parent_issue(
        &mut self,
        parent: ParentHandle,
        issue: ErrorResponse,
    ) {
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
        }
        else {
            if let Some(repo_issue) = self.repo_issue.as_ref() {
                writeln!(f, "Repository Issue: {}", repo_issue)?;
            }
            if !self.parent_issues.is_empty() {
                for parent_issue in &self.parent_issues {
                    writeln!(
                        f,
                        "Parent '{}' has issue: {}",
                        parent_issue.parent, parent_issue.issue
                    )?;
                }
            }
        }
        Ok(())
    }
}


//------------ CertAuthParentIssue -------------------------------------------

/// An issue occured when synchronizing with a parent CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthParentIssue {
    /// The local handle of the parent CA.
    pub parent: ParentHandle,

    /// The error response from the last synchronization attempt.
    pub issue: ErrorResponse,
}


//------------ CertAuthStats -------------------------------------------------

/// Statistics about a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthStats {
    /// The number of ROAs published by the CA.
    pub roa_count: usize,

    /// The number of child CAs.
    pub child_count: usize,

    /// The BGP statistics for the published ROAs.
    pub bgp_stats: BgpStats,
}


//------------ BgpStats ------------------------------------------------------

/// Statistics about the consequences of published ROAs as seen in BGP.
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


//------------ RtaName -------------------------------------------------------

/// The name of an RTA.
pub type RtaName = String;


//------------ RtaList -------------------------------------------------------

/// A list of RTAs.
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


//------------ RtaPrepResponse -----------------------------------------------

/// The response to an RTA preparation requeest.
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


//============ Error Types ===================================================

//------------ InvalidCert ---------------------------------------------------

/// A certificate cannot be processed.
#[derive(Clone, Debug)]
pub enum InvalidCert {
    /// The caRepository URI is missing.
    CaRepositoryMissing,

    /// The rpkiManifest URI is missing.
    RpkiManifestMissing,

    /// The file name cannot be derived from the rsync URI.
    Uri(uri::Rsync),
}

impl fmt::Display for InvalidCert {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CaRepositoryMissing => {
                f.write_str(
                    "CA certificate lacks id-ad-caRepository \
                     (see section 4.8.8.1 of RFC 6487)"
                )
            }
            Self::RpkiManifestMissing => {
                f.write_str(
                    "CA certificate lacks id-ad-rpkiManifest \
                     (see section 4.8.8.1 of RFC 6487)"
                )
            }
            Self::Uri(s) => {
                write!(f, "Cannot derive filename from URI: {}", s)
            }
        }
    }
}

impl std::error::Error for InvalidCert {}


//------------ CertInfoDecodeError -------------------------------------------

/// Decoding a `CertInfo<_>` value has failed.
#[derive(Clone, Debug)]
pub struct CertInfoDecodeError(String);

impl fmt::Display for CertInfoDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cannot decode binary certificate: {}", self.0)
    }
}

impl std::error::Error for CertInfoDecodeError {}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use rpki::crypto::PublicKeyFormat;
    use crate::test;
    use crate::commons::crypto::OpenSslSigner;
    use crate::ta::TrustAnchorLocator;
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
        test::test_in_memory(|storage_uri| {
            let signer =
                OpenSslSigner::build(storage_uri, "dummy", None).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::Rsa).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().resolve(
                "",
                ObjectName::mft_from_ca_key(&pub_key.key_identifier()).as_ref(),
            );

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

        let tal = TrustAnchorLocator::new(
            vec![uri],
            rsync_uri,
            cert.subject_public_key_info(),
        );

        let expected_tal = include_str!("../../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);
    }

    #[test]
    fn id_cert_pem_match_openssl() {
        let ncc_id = {
            let bytes =
                include_bytes!("../../../test-resources/remote/ncc-id.der");
            IdCert::decode(bytes.as_ref()).unwrap()
        };

        let ncc_id_openssl_pem =
            include_str!("../../../test-resources/remote/ncc-id.pem");
        let ncc_id_pem = IdCertInfo::from(&ncc_id);

        assert_eq!(ncc_id_pem.pem().to_string(), ncc_id_openssl_pem);
    }

    #[test]
    fn serde_cert_auth_issues() {
        let mut issues = CertAuthIssues::default();

        use crate::commons::error::Error;
        use crate::commons::util::httpclient;

        issues.repo_issue = Some(
            Error::HttpClientError(httpclient::Error::forbidden(
                "https://example.com/",
            ))
            .to_error_response(),
        );
        issues.add_parent_issue(
            ParentHandle::from_str("parent").unwrap(),
            Error::Rfc6492InvalidCsrSent("invalid csr".to_string())
                .to_error_response(),
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

        fn ca_stats_active_no_exchange(
            child: &CaHandle,
        ) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: child.convert(),
                last_exchange: None,
                state: ChildState::Active,
            }
        }

        fn ca_stats_active(
            child: &CaHandle,
            exchange: ChildExchange,
        ) -> ChildConnectionStats {
            ChildConnectionStats {
                handle: child.convert(),
                last_exchange: Some(exchange),
                state: ChildState::Active,
            }
        }

        let new_ca = ca_stats_active_no_exchange(&ca_handle);

        let recent_krill_pre_0_9_2 =
            ca_stats_active(&ca_handle, new_exchange("krill"));
        let recent_krill_post_0_9_1 =
            ca_stats_active(&ca_handle, new_exchange("krill/0.9.2-rc2"));
        let recent_other_agent =
            ca_stats_active(&ca_handle, new_exchange("other"));
        let recent_no_agent = ca_stats_active(&ca_handle, new_exchange(""));

        let old_krill_pre_0_9_2 =
            ca_stats_active(&ca_handle, old_exchange("krill"));
        let old_krill_post_0_9_1 =
            ca_stats_active(&ca_handle, old_exchange("krill/0.9.2-rc2"));
        let old_other_agent =
            ca_stats_active(&ca_handle, old_exchange("other"));
        let old_no_agent = ca_stats_active(&ca_handle, old_exchange(""));

        assert!(!new_ca.is_suspension_candidate(threshold_seconds));

        assert!(!recent_krill_pre_0_9_2
            .is_suspension_candidate(threshold_seconds));
        assert!(!recent_krill_post_0_9_1
            .is_suspension_candidate(threshold_seconds));
        assert!(
            !recent_other_agent.is_suspension_candidate(threshold_seconds)
        );
        assert!(!recent_no_agent.is_suspension_candidate(threshold_seconds));

        assert!(
            !old_krill_pre_0_9_2.is_suspension_candidate(threshold_seconds)
        );
        assert!(!old_other_agent.is_suspension_candidate(threshold_seconds));
        assert!(!old_no_agent.is_suspension_candidate(threshold_seconds));

        assert!(
            old_krill_post_0_9_1.is_suspension_candidate(threshold_seconds)
        );
    }

    #[test]
    fn find_sync_candidates() {
        let uri = ServiceUri::try_from(
            "https://example.com/rfc6492/child/".to_string(),
        )
        .unwrap();

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
                result: ExchangeResult::Failure(ErrorResponse::new(
                    "err", "err!",
                )),
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
        inner_statuses
            .insert(p6_success_long_ago.clone(), p6_status_success_long_ago);

        let parent_statuses = ParentStatuses(inner_statuses);

        let ca_parents = vec![
            &p1_new_parent,
            &p2_new_parent,
            &p3_no_exchange,
            &p4_success,
            &p5_failure,
            &p6_success_long_ago,
        ];

        let candidates =
            parent_statuses.sync_candidates(ca_parents.clone(), 10);

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

        let candidates_trimmed =
            parent_statuses.sync_candidates(ca_parents, 1);
        let expected_trimmed = vec![p1_new_parent];

        assert_eq!(candidates_trimmed, expected_trimmed);
    }
}
