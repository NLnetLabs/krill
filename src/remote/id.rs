use bcder::{Mode, OctetString, Oid, Tag, Unsigned};
use bcder::{decode, encode};
use bcder::encode::Values;
use bcder::encode::Constructed;
use bytes::Bytes;
use crate::util::ext_serde;
use rpki::uri;
use rpki::x509::Time;
use rpki::x509::ValidationError;
use rpki::cert::ext::BasicCa;
use rpki::cert::ext::SubjectKeyIdentifier;
use rpki::cert::ext::AuthorityKeyIdentifier;
use util::softsigner::SignerKeyId;
use rpki::x509::SignedData;
use rpki::crypto::SignatureAlgorithm;
use rpki::x509::Name;
use rpki::cert::Validity;
use rpki::crypto::PublicKey;


//------------ MyIdentity ----------------------------------------------------

/// This type stores identity details for a client or server involved in RPKI
/// publishing (up-down) or publication.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MyIdentity {
    name: String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert: IdCert,

    #[serde(
    deserialize_with = "ext_serde::de_key_id",
    serialize_with = "ext_serde::ser_key_id")]
    key_id: SignerKeyId
}

impl MyIdentity {
    pub fn new(name: &str, id_cert: IdCert, key_id: SignerKeyId) -> Self {
        MyIdentity {
            name: name.to_string(),
            id_cert,
            key_id
        }
    }

    /// The name for this actor.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The identity certificate for this actor.
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    /// The identifier that the Signer needs to use the key for the identity
    /// certificate.
    pub fn key_id(&self) -> &SignerKeyId {
        &self.key_id
    }
}

impl PartialEq for MyIdentity {
    fn eq(&self, other: &MyIdentity) -> bool {
        self.name == other.name &&
            self.id_cert.to_bytes() == other.id_cert.to_bytes() &&
            self.key_id == other.key_id
    }
}

impl Eq for MyIdentity {}


//------------ ParentInfo ----------------------------------------------------

/// This type stores details about a parent publication server: in
/// particular, its identity and where it may be contacted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParentInfo {
    publisher_handle: String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert: IdCert,

    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
    service_uri: uri::Http,
}

impl ParentInfo {
    pub fn new(
        publisher_handle: String,
        id_cert: IdCert,
        service_uri: uri::Http,
    ) -> Self {
        ParentInfo {
            publisher_handle,
            id_cert,
            service_uri,
        }
    }

    /// The Identity Certificate used by the parent.
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    /// The service URI where the client should send requests.
    pub fn service_uri(&self) -> &uri::Http {
        &self.service_uri
    }

    /// The name the publication server prefers to go by
    pub fn publisher_handle(&self) -> &String {
        &self.publisher_handle
    }
}

impl PartialEq for ParentInfo {
    fn eq(&self, other: &ParentInfo) -> bool {
        self.id_cert.to_bytes() == other.id_cert.to_bytes() &&
            self.service_uri == other.service_uri &&
            self.publisher_handle == other.publisher_handle
    }
}

impl Eq for ParentInfo {}


//------------ MyRepoInfo ----------------------------------------------------

/// This type stores details about the repository URIs available to a
/// publisher.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MyRepoInfo {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    sia_base: uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
    notify_sia: uri::Http
}

impl MyRepoInfo {
    pub fn new(
        sia_base: uri::Rsync,
        notify_sia: uri::Http
    ) -> Self {
        MyRepoInfo { sia_base, notify_sia }
    }

    /// The base rsync directory under which the publisher may publish.
    // XXX TODO: Read whether standards allow sub-dirs
    pub fn sia_base(&self) -> &uri::Rsync {
        &self.sia_base
    }

    pub fn notify_sia(&self) -> &uri::Http {
        &self.notify_sia
    }
}

impl PartialEq for MyRepoInfo {
    fn eq(&self, other: &MyRepoInfo) -> bool {
        self.sia_base == other.sia_base &&
            self.notify_sia == other.notify_sia
    }
}

impl Eq for MyRepoInfo {}


//------------ IdCert --------------------------------------------------------

/// An Identity Certificate.
///
/// Identity Certificates are used in the provisioning and publication
/// protocol. Initially the parent and child CAs and/or the publishing CA
/// and publication server exchange self-signed Identity Certificates, wrapped
/// in XML messages defined in the 'oob.rs' module.
///
/// The private keys corresponding to the subject public keys in these
/// certificates are then used to sign identity EE certificates used to sign
/// CMS messages in support of the provisioning and publication protocols.
///
/// NOTE: For the moment only V3 certificates are supported, because we insist
/// that a TA certificate is self-signed and has the CA bit set, and that an
/// EE certificate does not have this bit set, but does have an AKI that
/// matches the issuer's SKI. Maybe we should take this out... and just care
/// that things are validly signed, or only check AKI/SKI if it's version 3,
/// but skip this for lower versions.
#[derive(Clone, Debug)]
pub struct IdCert {
    /// The outer structure of the certificate.
    signed_data: SignedData,

    /// The serial number.
    serial_number: Unsigned,

    /// The algorithm used for signing the certificate.
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// It isn’t really relevant in RPKI.
    issuer: Name,

    /// The validity of the certificate.
    validity: Validity,

    /// The name of the subject of this certificate.
    ///
    /// This isn’t really relevant in RPKI.
    subject: Name,

    /// Information about the public key of this certificate.
    subject_public_key_info: PublicKey,

    /// The certificate extensions.
    extensions: IdExtensions,
}

/// # Data Access
///
impl IdCert {
    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &[u8] {
        self.subject_public_key_info.bits()
    }

    /// Returns a reference to the subject key identifier.
    pub fn subject_key_identifier(&self) -> &OctetString {
        &self.extensions.subject_key_id.subject_key_id()
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &PublicKey {
        &self.subject_public_key_info
    }

    /// Returns a reference to the certificate’s serial number.
    pub fn serial_number(&self) -> &Unsigned {
        &self.serial_number
    }
}

/// # Decoding and Encoding
///
impl IdCert {
    /// Decodes a source as a certificate.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;

        signed_data.data().clone().decode(|cons| {
            cons.take_sequence(|cons| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                Ok(IdCert {
                    signed_data,
                    serial_number: Unsigned::take_from(cons)?,
                    signature: SignatureAlgorithm::x509_take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    validity: Validity::take_from(cons)?,
                    subject: Name::take_from(cons)?,
                    subject_public_key_info: PublicKey::take_from(cons)?,
                    extensions: cons.take_constructed_if(
                        Tag::CTX_3,
                        IdExtensions::take_from
                    )?,
                })
            })
        }).map_err(Into::into)
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed_data.encode()
    }

    pub fn to_bytes(&self) -> Bytes {
        self.encode().to_captured(Mode::Der).into_bytes()
    }
}

/// # Validation
///
impl IdCert {
    /// Validates the certificate as a trust anchor.
    ///
    /// This validates that the certificate “is a current, self-signed RPKI
    /// CA certificate that conforms to the profile as specified in
    /// RFC6487” (RFC7730, section 3, step 2).
    pub fn validate_ta(&self) -> Result<(), ValidationError> {
        self.validate_ta_at(Time::now())
    }

    pub fn validate_ta_at(&self, now: Time) -> Result<(), ValidationError> {
        self.validate_basics(now)?;
        self.validate_ca_basics()?;

        // Authority Key Identifier. May be present, if so, must be
        // equal to the subject key identifier.
        if let Some(aki) = self.extensions.authority_key_id() {
            if aki != self.extensions.subject_key_id() {
                return Err(ValidationError);
            }
        }

        // Verify that this is self signed
        self.signed_data.verify_signature(&self.subject_public_key_info)?;

        Ok(())
    }

    /// Validates the certificate as an EE certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ee(
        &self,
        issuer: &IdCert,
    ) -> Result<(), ValidationError> {
        self.validate_ee_at(issuer, Time::now())
    }

    pub fn validate_ee_at(
        &self,
        issuer: &IdCert,
        now: Time,
    ) -> Result<(), ValidationError> {
        self.validate_basics(now)?;
        self.validate_issued(issuer)?;

        // Basic Constraints: Must not be present.
        if self.extensions.basic_ca != None {
            return Err(ValidationError)
        }

        // Verify that this is signed by the issuer
        self.validate_signature(issuer)?;
        Ok(())
    }


    //--- Validation Components

    /// Validates basic compliance with RFC8183 and RFC6492
    ///
    /// Note the the standards are pretty permissive in this context.
    fn validate_basics(&self, now: Time) -> Result<(), ValidationError> {
        // Validity. Check according to RFC 5280.
        self.validity.validate_at(now)?;

        // Subject Key Identifer. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.extensions.subject_key_id().as_slice().unwrap()
            != self.subject_public_key_info().key_identifier().as_ref()
        {
            return Err(ValidationError)
        }

        Ok(())
    }

    /// Validates that the certificate is a correctly issued certificate.
    ///
    /// Note this check is used to check that an EE certificate in an RFC8183,
    /// or RFC6492 message is validly signed by the TA certificate that was
    /// exchanged.
    ///
    /// This check assumes for now that we are always dealing with V3
    /// certificates and AKI and SKI have to match.
    fn validate_issued(
        &self,
        issuer: &IdCert,
    ) -> Result<(), ValidationError> {
        // Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if let Some(aki) = self.extensions.authority_key_id() {
            if aki != issuer.extensions.subject_key_id() {
                return Err(ValidationError)
            }
        }
        else {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates that the certificate is a valid CA certificate.
    ///
    /// Checks the parts that are common in normal and trust anchor CA
    /// certificates.
    fn validate_ca_basics(&self) -> Result<(), ValidationError> {
        // 4.8.1. Basic Constraints: For a CA it must be present (RFC6487)
        // und the “cA” flag must be set (RFC5280).
        if let Some(ref ca) = self.extensions.basic_ca {
            if ca.ca() == true {
                return  Ok(())
            }
        }

        Err(ValidationError)
    }

    /// Validates the certificate’s signature.
    fn validate_signature(
        &self,
        issuer: &IdCert
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.subject_public_key_info())
    }
}


//--- AsRef

impl AsRef<IdCert> for IdCert {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ IdExtensions --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdExtensions {
    /// Basic Constraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<BasicCa>,

    /// Subject Key Identifier.
    subject_key_id: SubjectKeyIdentifier,

    /// Authority Key Identifier
    authority_key_id: Option<AuthorityKeyIdentifier>,
}

/// # Decoding
///
impl IdExtensions {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |content| {
                    if id == oid::CE_BASIC_CONSTRAINTS {
                        BasicCa::take(content, critical, &mut basic_ca)
                    } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                        SubjectKeyIdentifier::take(
                            content, critical, &mut subject_key_id
                        )
                    } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        AuthorityKeyIdentifier::take(
                            content, critical, &mut authority_key_id
                        )
                    } else if critical {
                        xerr!(Err(decode::Malformed))
                    } else {
                        // RFC 5280 says we can ignore non-critical
                        // extensions we don’t know of. RFC 6487
                        // agrees. So let’s do that.
                        Ok(())
                    }
                })?;
                Ok(())
            })? {}
            Ok(IdExtensions {
                basic_ca,
                subject_key_id: subject_key_id.ok_or(decode::Malformed)?,
                authority_key_id,
            })
        })
    }
}

/// # Encoding
///
// We have to do this the hard way because some extensions are optional.
// Therefore we need logic to determine which ones to encode.
impl IdExtensions {

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        Constructed::new(
            Tag::CTX_3,
            encode::sequence(
                (
                    self.basic_ca.as_ref().map(|s| s.encode()),
                    self.subject_key_id.encode(),
                    self.authority_key_id.as_ref().map(|s| s.encode())
                )
            )
        )
    }

}


/// # Creating
///
impl IdExtensions {

    /// Creates extensions to be used on a self-signed TA IdCert
    pub fn for_id_ta_cert(key: &PublicKey) -> Self {
        IdExtensions{
            basic_ca: Some(BasicCa::new(true, true)),
            subject_key_id: SubjectKeyIdentifier::new(key),
            authority_key_id: Some(AuthorityKeyIdentifier::new(key))
        }
    }

    /// Creates extensions to be used on an EE IdCert in a protocol CMS
    pub fn for_id_ee_cert(
        subject_key: &PublicKey,
        issuing_key: &PublicKey
    ) -> Self {
        IdExtensions{
            basic_ca: None,
            subject_key_id: SubjectKeyIdentifier::new(subject_key),
            authority_key_id: Some(AuthorityKeyIdentifier::new(issuing_key))
        }
    }
}

/// # Data Access
///
impl IdExtensions {
    pub fn subject_key_id(&self) -> &OctetString {
        &self.subject_key_id.subject_key_id()
    }

    pub fn authority_key_id(&self) -> Option<&OctetString> {
        match &self.authority_key_id {
            Some(a) => Some(a.authority_key_id()),
            None => None
        }
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use bcder::Oid;

    pub const CE_BASIC_CONSTRAINTS: Oid<&[u8]> = Oid(&[85, 29, 19]);
    pub const CE_SUBJECT_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 14]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
}


//------------ Tests ---------------------------------------------------------

// is pub so that we can use a parsed test IdCert for now for testing
#[cfg(test)]
pub mod tests {
    use super::*;
    use bytes::Bytes;

    // Useful until we can create IdCerts of our own
    pub fn test_id_certificate() -> IdCert {
        let data = include_bytes!("../../test/oob/id_publisher_ta.cer");
        IdCert::decode(Bytes::from_static(data)).unwrap()
    }

    #[test]
    fn should_parse_id_publisher_ta_cert() {
        test_id_certificate().validate_ta_at(
            Time::utc(2012, 1, 1, 0, 0, 0)
        ).unwrap();
    }
}
