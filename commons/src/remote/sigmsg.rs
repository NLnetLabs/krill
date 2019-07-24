//! CMS structure that is used to encompass publication and publishing
//! messages.

use bytes::Bytes;

use bcder::decode;
use bcder::{Mode, Oid, Tag};
use bcder::string::OctetString;

use rpki::crypto::{
    DigestAlgorithm,
    KeyIdentifier,
    Signature,
    SignatureAlgorithm
};
use rpki::oid;
use rpki::sigobj::{
    SignedAttrs,
    MessageDigest
};
use rpki::x509::{Time, ValidationError};

use crate::remote::id::IdCert;

//------------ Cms -----------------------------------------------------------

/// A protocol CMS.
///
/// This is a signed CMS object that contains XML messages used in the
/// provisioning and publication protocols, and that is signed using an
/// EE IdCert, signed under a TA IdCert.
#[derive(Clone, Debug)]
pub struct SignedMessage {
    //--- From SignedData
    //
    digest_algorithm: DigestAlgorithm,
    content_type: Oid<Bytes>,
    content: OctetString,
    id_cert: IdCert,

    //--- From SignerInfo
    //
    sid: KeyIdentifier,
    signed_attrs: SignedAttrs,
    signature: Signature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest
}

/// # Decoding
///
impl SignedMessage {

    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        if strict { Mode::Der }
            else { Mode::Ber }
            .decode(source, Self::take_from)
    }

}

/// # Accessors
///
impl SignedMessage {
    pub fn content(&self) -> &OctetString {
        &self.content
    }
}

/// # Parsing
///
impl SignedMessage {

    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3

            let digest_algorithm =
                DigestAlgorithm::take_set_from(cons)?;

            let (content_type, content) = {
                cons.take_sequence(|cons| { // encapContentInfo
                    Ok((
                        Oid::take_from(cons)?,
                        cons.take_constructed_if(
                            Tag::CTX_0,
                            OctetString::take_from
                        )?
                    ))
                })?
            };
            if content_type != oid::PROTOCOL_CONTENT_TYPE {
                return xerr!(Err(decode::Malformed.into()))
            }

            let id_cert = Self::take_certificates(cons)?;

            let _whatever = Self::drop_crls(cons);


            let (sid, attrs, signature) = { // signerInfos
                cons.take_set(|cons| {
                    cons.take_sequence(|cons| {
                        cons.skip_u8_if(3)?;
                        let sid = cons.take_value_if(
                            Tag::CTX_0, |content| {
                                KeyIdentifier::from_content(content)
                            }
                        )?;
                        let alg = DigestAlgorithm::take_from(cons)?;
                        if alg != digest_algorithm {
                            return Err(decode::Malformed.into())
                        }
                        let attrs = SignedAttrs::take_from_signed_message(cons)?;
                        if attrs.2 != content_type {
                            return Err(decode::Malformed.into())
                        }
                        let signature = Signature::new(
                            SignatureAlgorithm::cms_take_from(cons)?,
                            OctetString::take_from(cons)?.into_bytes()
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

                sid,
                signed_attrs: attrs.0,
                signature,

                message_digest: attrs.1
            })

        })
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<IdCert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| {
                match tag {
                    Tag::SEQUENCE => IdCert::from_constructed(cons),
                    _ => {
                        xerr!(Err(decode::Unimplemented.into()))
                    }
                }
            })
        })
    }

    // Drop the CRLs, if present.
    //
    // The ones from DRL don't seem to parse, and their value is
    // is very limited.
    //
    // These CRLs only really protect if an operator use multi-use
    // keys for their EE certificates and is given some frequently
    // re-signed CRL by the CA cert for inclusion.. then if the EE
    // key is stolen you get a bit of protection.
    //
    fn drop_crls<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_constructed_if(Tag::CTX_1, |cons| {
            cons.skip_all()
        })
    }
}


/// # Validation
///
impl SignedMessage {
    /// Validates the signed message.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    pub fn validate(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        self.validate_at(issuer, Time::now())
    }

    /// Validates a signed message for a given point in time.
    pub fn validate_at(
        &self,
        issuer: &IdCert,
        now: Time
    ) -> Result<(), ValidationError> {
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
            return Err(ValidationError)
        }
        let msg = self.signed_attrs.encode_verify();
        self.id_cert.subject_public_key_info().verify(
            &msg,
            &self.signature
        ).map_err(Into::into)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_and_validate_signed_message() {
        let der = include_bytes!("../../test-resources/remote/pdu_200.der");
        let msg = SignedMessage::decode(
            Bytes::from_static(der), false
        ).unwrap();

        let b = include_bytes!("../../test-resources/remote/cms_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        msg.validate_at(&id_cert, Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

    #[test]
    fn should_reject_invalid_signed_message() {
        let der = include_bytes!("../../test-resources/remote/pdu_200.der");
        let msg = SignedMessage::decode(
            Bytes::from_static(der), false
        ).unwrap();

        let b = include_bytes!("../../test-resources/oob/id_publisher_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        assert_eq!(
            msg.validate_at(
                &id_cert, Time::utc(2012, 1, 1, 0, 0, 0)
            ).unwrap_err(),
            ValidationError,
        );
    }

    #[test]
    fn parse_lacnic_issue_response() {
        let der = include_bytes!("../../test-resources/remote/lacnic-res-2.der");
        let _msg = SignedMessage::decode(
            Bytes::from_static(der),
            false
        ).unwrap();
    }
}
