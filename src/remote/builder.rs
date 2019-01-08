//! Support for building RPKI Certificates and Objects

use bcder::{BitString, Mode, OctetString, Oid, Tag};
use bcder::encode;
use bcder::encode::{Constructed, PrimitiveContent, Values};
use bytes::Bytes;
use chrono::Utc;
use rpki::cert::{SubjectPublicKeyInfo, Validity};
use rpki::cert::ext::{
    AuthorityKeyIdentifier, CrlNumber, Extensions, KeyIdentifier
};
use rpki::crl::Crl;
use rpki::signing;
use rpki::signing::digest;
use rpki::signing::SignatureAlgorithm;
use rpki::signing::signer::{KeyId, KeyUseError, OneOffSignature, Signer};
use rpki::sigobj;
use rpki::x509::{Name, Time};
use crate::remote::id::{IdCert, IdExtensions};
use crate::remote::publication::pubmsg::Message;


//------------ TbsCertificate ------------------------------------------------

/// The supported extension types for our RPKI TbsCertificate
pub enum RpkiTbsExtension {
    ResourceExtensions(Extensions),
    IdExtensions(IdExtensions)
}

/// This type represents the signed content part of an RPKI Certificate.
pub struct RpkiTbsCertificate {

    // The General structure is documented in section 4.1 or RFC5280
    //
    //    TBSCertificate  ::=  SEQUENCE  {
    //        version         [0]  EXPLICIT Version DEFAULT v1,
    //        serialNumber         CertificateSerialNumber,
    //        signature            AlgorithmIdentifier,
    //        issuer               Name,
    //        validity             Validity,
    //        subject              Name,
    //        subjectPublicKeyInfo SubjectPublicKeyInfo,
    //        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        extensions      [3]  EXPLICIT Extensions OPTIONAL
    //                             -- If present, version MUST be v3
    //        }
    //
    //  In the RPKI we always use Version 3 Certificates with certain
    //  extensions (SubjectKeyIdentifier in particular). issuerUniqueID and
    //  subjectUniqueID are not used.
    //

    // version is always 3
    serial_number: u32,
    // signature is always Sha256WithRsaEncryption
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    // issuerUniqueID is not used
    // subjectUniqueID is not used
    extensions: RpkiTbsExtension,
}

/// # Encoding
///
impl RpkiTbsCertificate {

    /// Encodes this certificate.
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {

        match self.extensions {
            RpkiTbsExtension::IdExtensions(ref id_ext) => {
                encode::sequence((
                    (
                        Constructed::new(
                            Tag::CTX_0,
                            2.encode() // Version 3 is encoded as 2
                        ),
                        self.serial_number.encode(),
                        SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                        self.issuer.encode(),
                    ),
                    (
                        self.validity.encode(),
                        self.subject.encode(),
                        self.subject_public_key_info.encode(),
                        id_ext.encode()
                    )
                ))
            },
            RpkiTbsExtension::ResourceExtensions(ref _ext) => {
                unimplemented!()
            }
        }
    }
}

/// # Creating
///
impl RpkiTbsCertificate {
    pub fn new(
        serial_number: u32,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        extensions: RpkiTbsExtension
    ) -> Self {
        Self {
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions
        }
    }
}

//------------ IdCertBuilder -------------------------------------------------

/// An IdCertBuilder to be used with the Signer trait.
pub struct IdCertBuilder;

impl IdCertBuilder {
    /// Creates an IdCertBuilder to be signed with the Signer trait.
    ///
    /// There is some magic here. Since we always use a structure where we
    /// have one self-signed CA certificate used as identity trust anchors,
    /// or EE certificates signed directly below this, we can make some
    /// assumptions and save on method parameters.
    ///
    /// If the issuing_key and the subject_key are the same we will assume
    /// that this is for a self-signed CA (TA even) certificate. So we will
    /// set the appropriate extensions: basic_ca and subject_key_id, but no
    /// authority_key_id.
    ///
    /// If the issuing_key and the subject_key are different then we will use
    /// the extensions: subject_key_id and authority_key_id, but no basic_ca.
    fn make_tbs_certificate_request(
        serial_number: u32,
        duration: ::chrono::Duration,
        issuing_key: &SubjectPublicKeyInfo,
        subject_key: &SubjectPublicKeyInfo,
        ext: IdExtensions
    ) -> RpkiTbsCertificate
    {
        let issuer = Name::from_pub_key(issuing_key);
        let validity = Validity::from_duration(duration);
        let subject = Name::from_pub_key(subject_key);

        RpkiTbsCertificate {
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info: subject_key.clone(),
            extensions: RpkiTbsExtension::IdExtensions(ext)
        }
    }

    fn create_signed_cert(
        issuing_key: &KeyId,
        subject_key: &SubjectPublicKeyInfo,
        ext: IdExtensions,
        signer: &mut impl Signer
    ) -> Result<IdCert, KeyUseError> {

        let issuing_key_info = signer.get_key_info(issuing_key)?;

        let dur = ::chrono::Duration::weeks(52000);

        let tbs = Self::make_tbs_certificate_request(
            1,
            dur,
            &issuing_key_info,
            &subject_key,
            ext
        );

        let enc_cert = tbs.encode();
        let enc_cert_c = enc_cert.to_captured(Mode::Der);
        let enc_cert_b: &Bytes = enc_cert_c.as_ref();

        let signature = BitString::new(
            0,
            signer.sign(issuing_key, enc_cert_b)?.into_bytes()
        );

        let captured_cert = encode::sequence (
            (
                enc_cert,
                SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                signature.encode()
            )
        ).to_captured(Mode::Der);

        let id_cert = IdCert::decode(captured_cert.as_ref())?;

        Ok(id_cert)
    }

    /// Creates a new TA IdCertSignRequest to be used with the Signer trait.
    ///
    /// Essentially this all the content that goes into the SignedData
    /// component.
    pub fn new_ta_id_cert(
        issuing_key: &KeyId,
        signer: &mut impl Signer
    ) -> Result<IdCert, KeyUseError> {
        let subject_key = signer.get_key_info(&issuing_key)?;
        let ext = IdExtensions::for_id_ta_cert(&subject_key);

        IdCertBuilder::create_signed_cert(
            issuing_key,
            &subject_key,
            ext,
            signer
        )
    }

    pub fn new_ee_cert(
        issuing_key: &KeyId,
        subject_key: &SubjectPublicKeyInfo,
        signer: &mut impl Signer
    ) -> Result<IdCert, KeyUseError> {
        let issuing_key_info = signer.get_key_info(issuing_key)?;
        let ext = IdExtensions::for_id_ee_cert(subject_key, &issuing_key_info);

        IdCertBuilder::create_signed_cert(
            issuing_key,
            subject_key,
            ext,
            signer
        )
    }
}


//------------ SignedMessageBuilder ------------------------------------------

pub struct SignedMessageBuilder {
    content: OctetString,
    signer_info: SignedSignerInfo,
    ee_cert: IdCert,
    crl: Crl
}

impl SignedMessageBuilder {
    pub fn new(
        issuing_key: &KeyId,
        signer: &mut impl Signer,
        message: Message
    ) -> Result<SignedMessageBuilder, KeyUseError> {
        let content = OctetString::new(message.into_bytes());

        let signer_info = SignerInfoBuilder::new(
            signer,
            &content.to_bytes()
        )?;

        let ee_cert = IdCertBuilder::new_ee_cert(
            issuing_key,
            signer_info.one_off_key(),
            signer
        )?;

        let crl = CrlBuilder::new(issuing_key, signer)?;

        Ok(
            SignedMessageBuilder {
                content,
                signer_info,
                ee_cert,
                crl
            }
        )
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {

        // ContentInfo ::= SEQUENCE {
        //           contentType ContentType,
        //           content [0] EXPLICIT ANY DEFINED BY contentType }
        //
        // content is SignedData:
        //
        // SignedData ::= SEQUENCE {
        //        version CMSVersion,
        //        digestAlgorithms DigestAlgorithmIdentifiers,
        //        encapContentInfo EncapsulatedContentInfo,
        //        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        //        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //        signerInfos SignerInfos }

        //    EncapsulatedContentInfo ::= SEQUENCE {
        //      eContentType ContentType,
        //      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
        //
        //  The eContentType for the RPKI Protocol Message object is defined as
        //  id-ct-xml, and has the numerical value of 1.2.840.113549.1.9.16.1.28.

        let digest_algorithms = encode::set(
            encode::sequence(
                signing::oid::SHA256.encode()
            )
        );

        let encap_content_info = encode::sequence(
            (
                sigobj::oid::PROTOCOL_CONTENT_TYPE.encode(),
                Constructed::new(Tag::CTX_0, self.content.encode())
            )
        );

        let certificates = Constructed::new(
            Tag::CTX_0,
            self.ee_cert.encode()
        );

        let crls = Constructed::new(
            Tag::CTX_1,
            self.crl.encode()
        );

        let signer_infos = encode::set(self.signer_info.encode());

        encode::sequence(
            (
                sigobj::oid::SIGNED_DATA.encode(),
                Constructed::new(
                    Tag::CTX_0,
                    encode::sequence(
                        (
                            (
                                3.encode(),
                                digest_algorithms,
                                encap_content_info
                            ),
                            (
                                certificates,
                                crls,
                                signer_infos
                            )
                        )
                    )
                )
            )
        )
    }
}


/// This type represent Signed Attributes in Signer Info.
///
/// ```text
/// This appears in the SignerInfo as:
///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///
/// Where:
///     SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
///
///     Attribute ::= SEQUENCE {
///         attrType OBJECT IDENTIFIER,
///         attrValues SET OF AttributeValue }
///
///     AttributeValue ::= ANY
///
/// See section 2.1.6.4 of RFC 6488 for specifications.
/// ```
pub struct SignedAttributes {
    content_type: &'static Oid<& 'static [u8]>,
    digest: OctetString,
    signing_time: Time
}

impl SignedAttributes {

    /// Creates a new SignedAttributes.
    ///
    /// Needs the content type for this specific kind of CMS (protocol, ROA,
    /// etc), as well as a reference to the eContent bytes, excluding the
    /// OctetString tag and length.
    ///
    /// This implementation will include a signing-time attribute using the
    /// time that the SignedAttributes was created.
    pub fn new(
        content_type: &'static Oid<&'static [u8]>,
        content: &Bytes
    ) -> Self {

        let content_digest = digest::digest(
            &digest::SHA256,
            content.as_ref()
        );

        let digest = Bytes::from(content_digest.as_ref());
        let digest = OctetString::new(digest);

        Self {
            content_type,
            digest,
            signing_time: Time::now()
        }
    }

    /// Encodes the SignedAttributes for inclusion in a CMS.
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        (
            encode::sequence(
                (
                    sigobj::oid::CONTENT_TYPE.encode(),
                    encode::set(
                        self.content_type.encode()
                    )
                )
            ),
            encode::sequence(
                (
                    sigobj::oid::MESSAGE_DIGEST.encode(),
                    encode::set(
                        self.digest.encode()
                    )
                )
            ),
            encode::sequence (
                (
                    // This implementation will include a signing-time
                    // attribute using the time that the SignedAttributes
                    // was created.
                    sigobj::oid::SIGNING_TIME.encode(),
                    encode::set(
                        self.signing_time.encode()
                    )
                )
            )
        )

    }

    /// Generates a signature using a one time key
    pub fn sign(&self, signer: &mut impl Signer)
        -> Result<OneOffSignature, KeyUseError> {
        // See section 5.4 of RFC 5652
        //  ...The IMPLICIT [0] tag in the signedAttrs is not used for the DER
        //  encoding, rather an EXPLICIT SET OF tag is used...
        let encode_in_set = encode::set(self.encode()).to_captured(Mode::Der);
        signer.sign_one_off(encode_in_set.as_slice())
    }

}


//------------ SignedSignerInfo ----------------------------------------------

pub struct SignedSignerInfo {
    signed_attributes: SignedAttributes,
    key: SubjectPublicKeyInfo,
    key_id: KeyIdentifier,
    signature: OctetString
}

impl SignedSignerInfo {
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a  {
        // SignerInfo ::= SEQUENCE {
        //      version CMSVersion,
        //      sid SignerIdentifier,
        //      digestAlgorithm DigestAlgorithmIdentifier,
        //      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        //      signatureAlgorithm SignatureAlgorithmIdentifier,
        //      signature SignatureValue,
        //      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

        let version = 3.encode();

        // The sid is defined as:
        //      SignerIdentifier ::= CHOICE {
        //          issuerAndSerialNumber IssuerAndSerialNumber,
        //          subjectKeyIdentifier [0] SubjectKeyIdentifier }
        //
        // We MUST use the SubjectKeyIdentifier from the EE certificate.
        // I.e. the hashed thing in an OctetString, rather than the full
        // X509 Extension.
        let sid = self.key_id.encode_as(Tag::CTX_0);

        //  digestAlgorithm DigestAlgorithmIdentifier,
        let digest_algo = encode::sequence(signing::oid::SHA256.encode());

        let signed_attrs = Constructed::new(
            Tag::CTX_0,
            self.signed_attributes.encode()
        );

        encode::sequence(
            (
                (
                    version,
                    sid,
                    digest_algo,
                    signed_attrs
                ),
                (
                    SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                    self.signature.encode()
                )
            )
        )
    }

    pub fn one_off_key(&self) -> &SubjectPublicKeyInfo {
        &self.key
    }
}



//------------ SignerInfoBuilder ---------------------------------------------

pub struct SignerInfoBuilder;

impl SignerInfoBuilder {
    /// Creates a new SignerInfo.
    ///
    /// This is used in the CMS profile for both RPKI Signed Objects such as
    /// ROAs and Manifests, as well as protocol messages for the provisioning
    /// and publication protocols.
    ///
    /// A lot of this is pretty well restricted in RFCs 6488 amd 6492. We
    /// really only require some bits.
    pub fn new(
        signer: &mut impl Signer,
        message: &Bytes
    ) -> Result<SignedSignerInfo, KeyUseError> {

        let signed_attributes = SignedAttributes::new(
            &sigobj::oid::PROTOCOL_CONTENT_TYPE, // XXX TODO: derive from message
            message
        );

        let one_off_signature = signed_attributes.sign(signer)?;
        let (key, signature) = one_off_signature.into_parts();

        let key_id = KeyIdentifier::new(&key);
        let signature = OctetString::new(signature.into_bytes());


        Ok(
            SignedSignerInfo {
                signed_attributes,
                key,
                key_id,
                signature
            }
        )
    }

}




//------------ CrlBuilder ----------------------------------------------------

pub struct CrlBuilder;

impl CrlBuilder {

    /// Creates a CRL for use with protocol messages. I.e. it revokes nothing,
    /// because smart people use single use keys for EE certs, and it's valid
    /// for, like, forever -- cause really this thing is useless. Still it is
    /// mandatory, so make one (1) and re-use it.
    ///
    /// This will all be changed in future when we implement generating CRLs
    /// for the RPKI CA.
    pub fn new(
        issuing_key: &KeyId,
        signer: &mut impl Signer
    ) -> Result<Crl, KeyUseError>
    {
        let pub_key = signer.get_key_info(issuing_key)?;
        let name = Name::from_pub_key(&pub_key);
        let now = Time::new(Utc::now());
        let eternity = Time::new(Utc::now()+::chrono::Duration::weeks(52000));

        let crl_number = CrlNumber::new(1);
        let aki = AuthorityKeyIdentifier::new(&pub_key);

        let extensions = Constructed::new(
            Tag::CTX_0,
            encode::sequence(
                (
                    aki.encode(),
                    crl_number.encode()
                )
            )
        );

        let crl_data = encode::sequence(
            (
                (
                    1.encode(),
                    SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                    name.encode()
                ),
                (
                    now.encode(),
                    eternity.encode(),
                    // Real revocations go here
                    extensions
                )
            )
        );

        let signature = BitString::new(
            0,
            signer.sign(
                issuing_key,
                crl_data.to_captured(Mode::Der).as_slice()
            )?.into_bytes()
        );

        let crl_obj = encode::sequence(
            (
                crl_data,
                SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                signature.encode()
            )
        );

        let crl = Crl::decode(crl_obj.to_captured(Mode::Der).as_ref())?;

        Ok(crl)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "softkeys")]
pub mod tests {

    use super::*;
    use signing::softsigner::OpenSslSigner;
    use signing::PublicKeyAlgorithm;
    use remote::sigmsg::SignedMessage;
    use publication::query::ListQuery;

    #[test]
    fn should_create_self_signed_ta_id_cert() {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();

        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, & mut s).unwrap();
        id_cert.validate_ta().unwrap();
    }

    #[test]
    fn should_create_crl_for_protocol() {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        let key_info = s.get_key_info(&key_id).unwrap();

        let crl = CrlBuilder::new(&key_id, & mut s).unwrap();
        crl.validate(&key_info).unwrap();
    }

    #[test]
    fn should_create_signed_publication_message() {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, & mut s).unwrap();

        let message = ListQuery::build_message();

        let builder = SignedMessageBuilder::new(
            &key_id,
            &mut s,
            message.clone()
        ).unwrap();

        let encoded_cms = builder.encode().to_captured(Mode::Der);

        let msg = SignedMessage::decode(encoded_cms.as_ref(), true).unwrap();
        msg.validate(&id_cert).unwrap();

        let parsed_message = Message::from_signed_message(&msg).unwrap();

        assert_eq!(message, parsed_message);
    }


}


