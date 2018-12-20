//! CMS structure that is used to encompass publication and provisioning
//! messages.

use bcder::decode;
use bcder::{Mode, Oid, Tag};
use bcder::string::OctetString;
use bytes::Bytes;
use rpki::crl::Crl;
use rpki::signing::DigestAlgorithm;
use rpki::sigobj::oid;
use rpki::sigobj::{SignedObject, SignerInfo};
use rpki::x509::{Time, ValidationError};
use super::idcert::IdCert;

use untrusted::Input;
use ring::digest;


//------------ Cms -----------------------------------------------------------

/// A protocol CMS.
///
/// This is a signed CMS object that contains XML messages used in the
/// provisioning and publication protocols, and that is signed using an
/// EE IdCert, signed under a TA IdCert.
#[derive(Clone, Debug)]
pub struct SignedMessage {
    content_type: Oid<Bytes>,
    content: OctetString,
    id_cert: IdCert,
    crl: Crl,
    signer_info: SignerInfo,
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

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3
            DigestAlgorithm::skip_set(cons)?; // digestAlgorithms
            let (content_type, content)
            = SignedObject::take_encap_content_info(cons)?;

            if content_type != oid::PROTOCOL_CONTENT_TYPE {
                return xerr!(Err(decode::Malformed.into()))
            }

            let id_cert = Self::take_certificates(cons)?;
            let crl = Self::take_crls(cons)?;

            let signer_info = cons.take_set(SignerInfo::take_from)?;

            Ok(SignedMessage {
                content_type,
                content,
                id_cert,
                crl,
                signer_info
            })
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


    fn take_crls<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Crl, S::Err> {
        cons.take_constructed_if(Tag::CTX_1, |cons| {
            Crl::take_from(cons)
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
        self.verify_signature()?;
        self.id_cert.validate_ee_at(issuer, now)?;
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self) -> Result<(), ValidationError> {
        let digest = {
            let mut context = digest::Context::new(&digest::SHA256);
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.signer_info.message_digest() {
            return Err(ValidationError)
        }
        let msg = self.signer_info.signed_attrs().encode_verify();
        ::ring::signature::verify(
            &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
            Input::from(self.id_cert.public_key().as_ref()),
            Input::from(&msg),
            Input::from(self.signer_info.signature_value().to_bytes().as_ref())
        ).map_err(|_| ValidationError)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_and_validate_signed_message() {
        let der = include_bytes!("../../test/remote/pdu_200.der");
        let msg = SignedMessage::decode(
            Bytes::from_static(der), false
        ).unwrap();

        let b = include_bytes!("../../test/remote/cms_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        msg.validate_at(&id_cert, Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

    #[test]
    fn should_reject_invalid_signed_message() {
        let der = include_bytes!("../../test/remote/pdu_200.der");
        let msg = SignedMessage::decode(
            Bytes::from_static(der), false
        ).unwrap();

        let b = include_bytes!("../../test/oob/id_publisher_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        assert_eq!(
            msg.validate_at(
                &id_cert, Time::utc(2012, 1, 1, 0, 0, 0)
            ).unwrap_err(),
            ValidationError,
        );
    }
}
