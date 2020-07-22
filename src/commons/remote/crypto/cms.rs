//! CMS structure that is used to encompass publication and publishing
//! messages.

use bytes::Bytes;
use chrono::Utc;

use bcder::encode::{Constructed, PrimitiveContent, Values};
use bcder::string::OctetString;
use bcder::{decode, encode, BitString, Unsigned};
use bcder::{Mode, Oid, Tag};

use rpki::crypto::{DigestAlgorithm, KeyIdentifier, PublicKey, Signature, SignatureAlgorithm};
use rpki::oid;
use rpki::sigobj::{MessageDigest, SignedAttrs};
use rpki::x509::{update_once, Name, SignedData, Time, ValidationError};

use super::IdCert;
use crate::commons::remote::crypto::{Error, IdCertBuilder, SignedAttributes};
use crate::daemon::ca::Signer;

//------------ ProtocolCmsBuilder ------------------------------------------

pub struct ProtocolCmsBuilder {
    content: OctetString,
    signer_info: ProtocolSignerInfo,
    ee_cert: IdCert,
    crl: ProtocolCrl,
}

impl ProtocolCmsBuilder {
    pub fn create<S: Signer>(
        issuing_key: &S::KeyId,
        signer: &S,
        message: Bytes,
    ) -> Result<ProtocolCmsBuilder, Error<S::Error>> {
        let content = OctetString::new(message);

        let signer_info = ProtocolSignerInfoBuilder::create(signer, &content.to_bytes())?;

        let ee_cert = IdCertBuilder::new_ee_cert(issuing_key, signer_info.one_off_key(), signer)?;

        let crl = ProtocolCrlBuilder::create(issuing_key, signer)?;

        Ok(ProtocolCmsBuilder {
            content,
            signer_info,
            ee_cert,
            crl,
        })
    }

    pub fn as_bytes(&self) -> Bytes {
        self.encode().to_captured(Mode::Der).into_bytes()
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

        let digest_algorithms = encode::set(encode::sequence(rpki::oid::SHA256.encode()));

        let encap_content_info = encode::sequence((
            oid::PROTOCOL_CONTENT_TYPE.encode(),
            Constructed::new(Tag::CTX_0, self.content.clone().encode()),
        ));

        let certificates = Constructed::new(Tag::CTX_0, self.ee_cert.encode());

        let crls = Constructed::new(Tag::CTX_1, self.crl.encode_ref());

        let signer_infos = encode::set(self.signer_info.encode());

        encode::sequence((
            oid::SIGNED_DATA.encode(),
            Constructed::new(
                Tag::CTX_0,
                encode::sequence((
                    (3.encode(), digest_algorithms, encap_content_info),
                    (certificates, crls, signer_infos),
                )),
            ),
        ))
    }
}

//------------ Cms -----------------------------------------------------------

/// A protocol CMS.
///
/// This is a signed CMS object that contains XML messages used in the
/// provisioning and publication protocols, and that is signed using an
/// EE IdCert, signed under a TA IdCert.
#[derive(Clone, Debug)]
pub struct ProtocolCms {
    //--- From SignedData
    //
    digest_algorithm: DigestAlgorithm,
    content_type: Oid<Bytes>,
    content: OctetString,
    id_cert: IdCert,
    crl: ProtocolCrl,

    //--- From SignerInfo
    //
    sid: KeyIdentifier,
    signed_attrs: SignedAttrs,
    signature: Signature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
}

/// # Decoding
///
impl ProtocolCms {
    pub fn decode<S: decode::Source>(source: S, strict: bool) -> Result<Self, S::Err> {
        if strict { Mode::Der } else { Mode::Ber }.decode(source, Self::take_from)
    }
}

/// # Accessors
///
impl ProtocolCms {
    pub fn content(&self) -> &OctetString {
        &self.content
    }
}

/// # Parsing
///
impl ProtocolCms {
    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3

            let digest_algorithm = DigestAlgorithm::take_set_from(cons)?;

            let (content_type, content) = {
                cons.take_sequence(|cons| {
                    // encapContentInfo
                    Ok((
                        Oid::take_from(cons)?,
                        cons.take_constructed_if(Tag::CTX_0, OctetString::take_from)?,
                    ))
                })?
            };
            if content_type != oid::PROTOCOL_CONTENT_TYPE {
                return xerr!(Err(decode::Malformed.into()));
            }

            let id_cert = Self::take_certificates(cons)?;

            let crl = Self::take_crl(cons)?;

            let (sid, attrs, signature) = {
                // signerInfos
                cons.take_set(|cons| {
                    cons.take_sequence(|cons| {
                        cons.skip_u8_if(3)?;
                        let sid = cons.take_value_if(Tag::CTX_0, |content| {
                            KeyIdentifier::from_content(content)
                        })?;
                        let alg = DigestAlgorithm::take_from(cons)?;
                        if alg != digest_algorithm {
                            return Err(decode::Malformed.into());
                        }
                        let attrs = SignedAttrs::take_from_signed_message(cons)?;
                        if attrs.2 != content_type {
                            return Err(decode::Malformed.into());
                        }
                        let signature = Signature::new(
                            SignatureAlgorithm::cms_take_from(cons)?,
                            OctetString::take_from(cons)?.into_bytes(),
                        );
                        // no unsignedAttributes
                        Ok((sid, attrs, signature))
                    })
                })?
            };

            Ok(Self {
                digest_algorithm,
                content_type,
                content,
                id_cert,
                crl,

                sid,
                signed_attrs: attrs.0,
                signature,

                message_digest: attrs.1,
            })
        })
    }

    pub fn take_from<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<IdCert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| match tag {
                Tag::SEQUENCE => IdCert::from_constructed(cons),
                _ => xerr!(Err(decode::Unimplemented.into())),
            })
        })
    }

    // Take the CRL, if present.
    //
    // In theory there could be multiple CRLs, one for each CA certificate included in signing
    // this object. However, nobody seems to do this, and it's rather poorly defined how (and why)
    // this would be done. So.. just expecting 1 CRL here.
    fn take_crl<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<ProtocolCrl, S::Err> {
        cons.take_constructed_if(Tag::CTX_1, |cons| ProtocolCrl::take_from(cons))
    }
}

/// # Validation
///
impl ProtocolCms {
    /// Validates the signed message.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    pub fn validate(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        self.validate_at(issuer, Time::now())
    }

    /// Validates a signed message for a given point in time.
    pub fn validate_at(&self, issuer: &IdCert, now: Time) -> Result<(), ValidationError> {
        self.id_cert.validate_ee_at(issuer, now)?;
        self.verify_signature()?;
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self) -> Result<(), ValidationError> {
        let digest = {
            let mut context = self.digest_algorithm.start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.message_digest.as_ref() {
            return Err(ValidationError);
        }
        let msg = self.signed_attrs.encode_verify();
        self.id_cert
            .subject_public_key_info()
            .verify(&msg, &self.signature)
            .map_err(Into::into)
    }
}

//------------ ProtocolSignerInfo ----------------------------------------------

struct ProtocolSignerInfo {
    signed_attributes: SignedAttributes,
    key: PublicKey,
    key_id: KeyIdentifier,
    signature: OctetString,
}

impl ProtocolSignerInfo {
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        // SignerInfo ::= SEQUENCE {
        //      version CMSVersion,
        //      sid SignerIdentifier,
        //      digestAlgorithm DigestAlgorithmIdentifier,
        //      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        //      signatureAlgorithm SignatureAlgorithmIdentifier,
        //      signature SignatureValue,
        //      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
        //
        let version = 3.encode();

        // The sid is defined as:
        //      SignerIdentifier ::= CHOICE {
        //          issuerAndSerialNumber IssuerAndSerialNumber,
        //          subjectKeyIdentifier [0] SubjectKeyIdentifier }
        //
        let sid = self.key_id.encode_as(Tag::CTX_0);

        // digestAlgorithm DigestAlgorithmIdentifier,
        // it seems this MUST NOT include the explicit NULL here
        let digest_algo = encode::sequence(oid::SHA256.encode());

        let signed_attrs = Constructed::new(Tag::CTX_0, self.signed_attributes.encode());

        encode::sequence((
            (version, sid, digest_algo, signed_attrs),
            (
                SignatureAlgorithm::default().cms_encode(),
                self.signature.clone().encode(),
            ),
        ))
    }

    pub fn one_off_key(&self) -> &PublicKey {
        &self.key
    }
}

//------------ ProtocolSignerInfoBuilder ---------------------------------------------

struct ProtocolSignerInfoBuilder;

impl ProtocolSignerInfoBuilder {
    /// Creates a new SignerInfo.
    ///
    /// This is used in the CMS profile for both RPKI Signed Objects such as
    /// ROAs and Manifests, as well as protocol messages for the provisioning
    /// and publication protocols.
    ///
    /// A lot of this is pretty well restricted in RFCs 6488 amd 6492. We
    /// really only require some bits.
    fn create<S: Signer>(
        signer: &S,
        message: &Bytes,
    ) -> Result<ProtocolSignerInfo, Error<S::Error>> {
        let signed_attributes = SignedAttributes::new(
            &oid::PROTOCOL_CONTENT_TYPE, // XXX TODO: derive from message
            message,
        );

        let (signature, key) = signed_attributes.sign(signer)?;

        let key_id = KeyIdentifier::from_public_key(&key);
        let signature = OctetString::new(signature.value().clone());

        Ok(ProtocolSignerInfo {
            signed_attributes,
            key,
            key_id,
            signature,
        })
    }
}

//------------ CrlBuilder ----------------------------------------------------

struct ProtocolCrlBuilder;

impl ProtocolCrlBuilder {
    /// Creates a CRL for use with protocol messages. This revokes nothing,
    /// because we use single use keys for EE certs.
    fn create<S: Signer>(
        issuing_key: &S::KeyId,
        signer: &S,
    ) -> Result<ProtocolCrl, Error<S::Error>> {
        let pub_key = signer.get_key_info(issuing_key)?;
        let name = Name::from_pub_key(&pub_key);
        let just_now = Time::new(Utc::now()) - ::chrono::Duration::minutes(5);
        let in_a_bit = Time::new(Utc::now() + ::chrono::Duration::minutes(5));

        let crl_number = CrlNumber::new(1);
        let extensions = Constructed::new(Tag::CTX_0, encode::sequence(crl_number.encode()));

        let crl_data = encode::sequence((
            (
                1.encode(),
                SignatureAlgorithm::default().x509_encode(),
                name.encode_ref(),
            ),
            (
                just_now.encode_varied(),
                in_a_bit.encode_varied(),
                // Real revocations go here
                extensions,
            ),
        ));

        let signature = BitString::new(
            0,
            signer
                .sign(
                    issuing_key,
                    SignatureAlgorithm::default(),
                    crl_data.to_captured(Mode::Der).as_slice(),
                )?
                .value()
                .clone(),
        );

        let crl_obj = encode::sequence((
            crl_data,
            SignatureAlgorithm::default().x509_encode(),
            signature.encode(),
        ));

        let crl = ProtocolCrl::decode(crl_obj.to_captured(Mode::Der).as_ref())?;

        Ok(crl)
    }
}

//------------ ProtocolCrl -----------------------------------------------------

/// An RPKI certificate revocation list used in RFC6492 and RFC8181 protocol signed
/// messages.
#[derive(Clone, Debug)]
struct ProtocolCrl {
    /// The outer structure of the CRL.
    signed_data: SignedData,
}

/// # Decode, Validate, and Encode
///
impl ProtocolCrl {
    /// Parses a source as a certificate revocation list.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CRL from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate revocation list.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        Ok(Self { signed_data })
    }

    /// Validates the certificate revocation list.
    ///
    /// The CRL’s signature is validated against the provided public key.
    ///
    /// Note that this method is used to test that our own CRLs are valid.
    /// However, it seems rather pointless to check the included ProtocolCrl
    /// in the ProtocolCms to see if the sender might have revoked the included
    /// EE certificate.
    #[cfg(test)]
    pub fn validate(&self, public_key: &PublicKey) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(public_key)
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed_data.encode_ref()
    }
}

//------------ CrlNumber -----------------------------------------------------

/// This extension is used in CRLs.
#[derive(Clone, Debug)]
pub struct CrlNumber {
    number: Unsigned,
}

/// # Creating
///
impl CrlNumber {
    pub fn new(number: u32) -> Self {
        CrlNumber {
            number: number.into(),
        }
    }
}

/// # Decoding and Encoding
///
impl CrlNumber {
    /// Parses the CRL Number Extension.
    ///
    /// Must be present
    ///
    /// ```text
    /// CRLNumber ::= INTEGER (0..MAX)
    /// ```
    pub fn take<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        _critical: bool,
        crl_number: &mut Option<Self>,
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            Ok(CrlNumber {
                number: Unsigned::take_from(cons)?,
            })
        })
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            oid::CE_CRL_NUMBER.encode(),
            OctetString::encode_wrapped(Mode::Der, self.number.encode()),
        ))
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commons::api::Handle;
    use crate::commons::remote::rfc6492::Message;
    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::test::test_under_tmp;
    use rpki::crypto::{PublicKeyFormat, Signer};
    use std::str::FromStr;

    #[test]
    fn should_parse_and_validate_signed_message() {
        let der = include_bytes!("../../../../test-resources/remote/pdu_200.der");
        let msg = ProtocolCms::decode(Bytes::from_static(der), false).unwrap();

        let b = include_bytes!("../../../../test-resources/remote/cms_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        msg.validate_at(&id_cert, Time::utc(2012, 1, 1, 0, 0, 0))
            .unwrap();
    }

    #[test]
    fn should_reject_invalid_signed_message() {
        let der = include_bytes!("../../../../test-resources/remote/pdu_200.der");
        let msg = ProtocolCms::decode(Bytes::from_static(der), false).unwrap();

        let b = include_bytes!("../../../../test-resources/oob/id_publisher_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        assert_eq!(
            msg.validate_at(&id_cert, Time::utc(2012, 1, 1, 0, 0, 0))
                .unwrap_err(),
            ValidationError,
        );
    }

    #[test]
    fn should_create_crl_for_protocol() {
        test_under_tmp(|d| {
            let mut s = OpenSslSigner::build(&d).unwrap();
            let key_id = s.create_key(PublicKeyFormat::default()).unwrap();
            let key_info = s.get_key_info(&key_id).unwrap();

            let crl = ProtocolCrlBuilder::create(&key_id, &s).unwrap();
            crl.validate(&key_info).unwrap();
        })
    }

    #[test]
    fn should_create_signed_publication_message() {
        test_under_tmp(|d| {
            let mut s = OpenSslSigner::build(&d).unwrap();
            let key_id = s.create_key(PublicKeyFormat::default()).unwrap();
            let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &s).unwrap();

            let sender = Handle::from_str("sender").unwrap();
            let rcpt = Handle::from_str("rcpt").unwrap();

            let message = Message::list(sender, rcpt);

            let builder =
                ProtocolCmsBuilder::create(&key_id, &s, message.clone().into_bytes()).unwrap();

            let encoded_cms = builder.encode().to_captured(Mode::Der);

            let msg = ProtocolCms::decode(encoded_cms.as_ref(), true).unwrap();
            msg.validate(&id_cert).unwrap();

            let parsed_message = Message::from_signed_message(&msg).unwrap();

            assert_eq!(message, parsed_message);
        });
    }
}
