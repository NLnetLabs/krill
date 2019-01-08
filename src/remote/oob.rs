//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.

use std::io;
use base64::DecodeError;
use bcder::decode;
use rpki::uri;
use rpki::x509;
use rpki::x509::Time;
use crate::remote::idcert::IdCert;
use crate::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};


//------------ PublisherRequest ----------------------------------------------

pub const VERSION: &'static str = "1";
pub const NS: &'static str = "http://www.hactrn.net/uris/rpki/rpki-setup/";

/// Type representing a <publisher_request/>
///
/// This is the XML message with identity information that a CA sends to a
/// Publication Server.
///
/// For more info, see: https://tools.ietf.org/html/rfc8183#section-5.2.3
#[derive(Debug)]
pub struct PublisherRequest {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The name the publishing CA likes to call itself by
    publisher_handle: String,

    /// The encoded Identity Certificate
    /// (for now, will be replaced by a concrete IdCert once it's defined)
    id_cert: IdCert,
}

impl PublisherRequest {

    /// Parses a <publisher_request /> message.
    pub fn decode<R>(reader: R) -> Result<Self, PublisherRequestError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("publisher_request", |mut a, r| {
                match a.take_req("version") {
                    Ok(s) => {
                        if s != "1" {
                            return Err(PublisherRequestError::InvalidVersion)
                        }
                    }
                    _ => return Err(PublisherRequestError::InvalidVersion)
                }

                let tag = a.take_opt("tag");
                let ph = a.take_req("publisher_handle")?;

                a.exhausted()?;

                let cert = r.take_named_element("publisher_bpki_ta", |a, r| {
                    a.exhausted()?;
                    r.take_bytes_characters()
                })?;

                Ok(PublisherRequest{
                    tag: tag.map(Into::into),
                    publisher_handle: ph.into(),
                    id_cert: IdCert::decode(cert)?
                })
            })
        })
    }

    pub fn validate(&self) -> Result<(), PublisherRequestError> {
        self.validate_at(Time::now())
    }

    pub fn validate_at(&self, now: Time) -> Result<(), PublisherRequestError> {
        Ok(self.id_cert.validate_ta_at(now)?)
    }

    /// Encodes a <publisher_request> to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {

            let mut a = vec![
                ("xmlns", NS),
                ("version", VERSION),
                ("publisher_handle", self.publisher_handle.as_ref())
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element(
                "publisher_request",
                Some(a.as_ref()),
                |w| {
                    w.put_element(
                        "publisher_bpki_ta",
                        None,
                        |w| {
                            w.put_blob(&self.id_cert.to_bytes())
                        }
                    )
                }

            )
        })
    }

    pub fn new(tag: Option<&str>, publisher_handle: &str, id_cert: IdCert) -> Self {
        PublisherRequest {
            tag: tag.map(|s| { s.to_string() }),
            publisher_handle: publisher_handle.to_string(),
            id_cert
        }
    }

    /// Consumes this object so its values can be re-used.
    pub fn into_parts(self) -> (Option<String>, String, IdCert) {
        (self.tag, self.publisher_handle, self.id_cert)
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn handle(&self) -> &String {
        &self.publisher_handle
    }
}


//------------ PublisherRequestError -----------------------------------------

#[derive(Debug, Fail)]
pub enum PublisherRequestError {
    #[fail(display = "Invalid XML for Publisher Request")]
    InvalidXml,

    #[fail(display = "Invalid version for Publisher Request")]
    InvalidVersion,

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[fail(display = "Invalid base64: {}", _0)]
    Base64Error(DecodeError),

    #[fail(display = "Cannot parse identity certificate: {}", _0)]
    CannotParseIdCert(decode::Error),

    #[fail(display = "Invalid identity certificate: {}", _0)]
    InvalidIdCert(x509::ValidationError),
}

impl From<XmlReaderErr> for PublisherRequestError {
    fn from(e: XmlReaderErr) -> PublisherRequestError{
        PublisherRequestError::XmlReadError(e)
    }
}

impl From<AttributesError> for PublisherRequestError {
    fn from(e: AttributesError) -> PublisherRequestError{
        PublisherRequestError::XmlAttributesError(e)
    }
}

impl From<DecodeError> for PublisherRequestError {
    fn from(e: DecodeError) -> PublisherRequestError {
        PublisherRequestError::Base64Error(e)
    }
}

impl From<decode::Error> for PublisherRequestError {
    fn from(e: decode::Error) -> PublisherRequestError {
        PublisherRequestError::CannotParseIdCert(e)
    }
}

impl From<x509::ValidationError> for PublisherRequestError {
    fn from(e: x509::ValidationError) -> PublisherRequestError {
        PublisherRequestError::InvalidIdCert(e)
    }
}

//------------ RepositoryResponse --------------------------------------------

/// Type representing a <repository_response/>
///
/// This is the response sent to a CA by the publication server. It contains
/// the details needed by the CA to send publication messages to the server.
///
/// See https://tools.ietf.org/html/rfc8183#section-5.2.4
#[derive(Debug)]
pub struct RepositoryResponse {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The name the publication server decided to call the CA by.
    /// Note that this may not be the same as the handle the CA asked for.
    publisher_handle: String,

    /// The Publication Server Identity Certificate
    id_cert: IdCert,

    /// The URI where the CA needs to send its publication messages
    service_uri: uri::Http,

    /// The Rsync base directory for objects published by the CA
    sia_base: uri::Rsync,

    /// The HTTPS notification URI that the CA can use
    rrdp_notification_uri: uri::Http
}

impl RepositoryResponse {

    /// Creates a new response.
    pub fn new(
        tag: Option<String>,
        publisher_handle: String,
        id_cert: IdCert,
        service_uri: uri::Http,
        sia_base: uri::Rsync,
        rrdp_notification_uri: uri::Http
    ) -> Self {
        RepositoryResponse {
            tag,
            publisher_handle,
            id_cert,
            service_uri,
            sia_base,
            rrdp_notification_uri
        }
    }

    /// Parses a <repository_response /> message.
    pub fn decode<R>(reader: R) -> Result<Self, RepositoryResponseError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("repository_response", |mut a, r| {
                match a.take_req("version") {
                    Ok(s) => if s != "1" {
                        return Err(RepositoryResponseError::InvalidVersion)
                    }
                    _ => return Err(RepositoryResponseError::InvalidVersion)
                }

                let tag = a.take_opt("tag");
                let publisher_handle = a.take_req("publisher_handle")?;
                let service_uri = uri::Http::from_string(
                    a.take_req("service_uri")?)?;
                let sia_base = uri::Rsync::from_string(
                    a.take_req("sia_base")?)?;
                let rrdp_notification_uri = uri::Http::from_string(
                    a.take_req("rrdp_notification_uri")?)?;

                a.exhausted()?;

                let id_cert = r.take_named_element(
                    "repository_bpki_ta", |a, r| {
                        a.exhausted()?;
                        r.take_bytes_characters()})?;

                Ok(RepositoryResponse{
                    tag: tag.map(Into::into),
                    publisher_handle: publisher_handle.into(),
                    id_cert: IdCert::decode(id_cert)?,
                    service_uri,
                    sia_base,
                    rrdp_notification_uri
                })
            })
        })
    }


    pub fn validate(&self) -> Result<(), RepositoryResponseError> {
        self.validate_at(Time::now())
    }

    pub fn validate_at(
        &self,
        now: Time
    ) -> Result<(), RepositoryResponseError> {
        Ok(self.id_cert.validate_ta_at(now)?)
    }

    /// Encodes the <repository_response/> to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {

            let service_uri = self.service_uri.to_string();
            let sia_base = self.sia_base.to_string();
            let rrdp_notification_uri = self.rrdp_notification_uri.to_string();

            let mut a = vec![
                ("xmlns", NS),
                ("version", VERSION),
                ("publisher_handle", self.publisher_handle.as_ref()),
                ("service_uri", service_uri.as_ref()),
                ("sia_base", sia_base.as_ref()),
                ("rrdp_notification_uri", rrdp_notification_uri.as_ref())
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element(
                "repository_response",
                Some(&a),
                |w| {
                    w.put_element(
                        "repository_bpki_ta",
                        None,
                        |w| {
                            w.put_blob(&self.id_cert.to_bytes())
                        }
                    )
                }

            )
        })
    }
}

/// # Accessors
impl RepositoryResponse {
    pub fn tag(&self) -> &Option<String> {
        &self.tag
    }

    pub fn publisher_handle(&self) -> &String {
        &self.publisher_handle
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn service_uri(&self) -> &uri::Http {
        &self.service_uri
    }

    pub fn sia_base(&self) -> &uri::Rsync {
        &self.sia_base
    }

    pub fn rrdp_notification_uri(&self) -> &uri::Http {
        &self.rrdp_notification_uri
    }
}


//------------ RepositoryResponseError ---------------------------------------

#[derive(Debug, Fail)]
pub enum RepositoryResponseError {
    #[fail(display = "Invalid XML for Publisher Request")]
    InvalidXml,

    #[fail(display = "Invalid version for Publisher Request")]
    InvalidVersion,

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[fail(display = "Invalid base64: {}", _0)]
    Base64Error(DecodeError),

    #[fail(display = "Cannot parse identity certificate: {}", _0)]
    CannotParseIdCert(decode::Error),

    #[fail(display = "Invalid identity certificate: {}", _0)]
    InvalidIdCert(x509::ValidationError),

    #[fail(display = "Invalid URI on Repository Response: {}", _0)]
    InvalidUri(uri::Error),

}

impl From<uri::Error> for RepositoryResponseError {
    fn from(e: uri::Error) -> RepositoryResponseError {
        RepositoryResponseError::InvalidUri(e)
    }
}

impl From<XmlReaderErr> for RepositoryResponseError {
    fn from(e: XmlReaderErr) -> RepositoryResponseError{
        RepositoryResponseError::XmlReadError(e)
    }
}

impl From<AttributesError> for RepositoryResponseError {
    fn from(e: AttributesError) -> RepositoryResponseError{
        RepositoryResponseError::XmlAttributesError(e)
    }
}

impl From<DecodeError> for RepositoryResponseError {
    fn from(e: DecodeError) -> RepositoryResponseError {
        RepositoryResponseError::Base64Error(e)
    }
}

impl From<decode::Error> for RepositoryResponseError {
    fn from(e: decode::Error) -> RepositoryResponseError {
        RepositoryResponseError::CannotParseIdCert(e)
    }
}

impl From<x509::ValidationError> for RepositoryResponseError {
    fn from(e: x509::ValidationError) -> RepositoryResponseError {
        RepositoryResponseError::InvalidIdCert(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str;
    use rpki::x509::Time;
    use super::*;

    fn example_rrdp_uri() -> uri::Http {
        uri::Http::from_str(
            "https://rpki.example/rrdp/notify.xml").unwrap()
    }

    fn example_sia_base() -> uri::Rsync {
        uri::Rsync::from_str(
            "rsync://a.example/rpki/Alice/Bob-42/").unwrap()
    }

    fn example_service_uri() -> uri::Http {
        uri::Http::from_str(
            "http://a.example/publication/Alice/Bob-42").unwrap()
    }

    #[test]
    fn should_parse_publisher_request() {
        let xml = include_str!("../../test/oob/publisher_request.xml");
        let pr = PublisherRequest::decode(xml.as_bytes()).unwrap();
        assert_eq!("Bob".to_string(), pr.publisher_handle);
        assert_eq!(Some("A0001".to_string()), pr.tag);

        pr.id_cert.validate_ta_at(Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

    #[test]
    fn should_parse_repository_response() {
        let xml = include_str!("../../test/oob/repository_response.xml");
        let rr = RepositoryResponse::decode(xml.as_bytes()).unwrap();
        assert_eq!(Some("A0001".to_string()), rr.tag);
        assert_eq!("Alice/Bob-42".to_string(), rr.publisher_handle);
        assert_eq!(example_service_uri(), rr.service_uri);
        assert_eq!(example_rrdp_uri(), rr.rrdp_notification_uri);
        assert_eq!(example_sia_base(), rr.sia_base);

        rr.id_cert.validate_ta_at(Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

    #[test]
    fn should_generate_publisher_request() {
        let cert = ::remote::idcert::tests::test_id_certificate();

        let pr = PublisherRequest {
            tag: Some("tag".to_string()),
            publisher_handle: "tim".to_string(),
            id_cert: cert
        };

        let enc = pr.encode_vec();

        PublisherRequest::decode(
            str::from_utf8(&enc).unwrap().as_bytes()
        ).unwrap().validate_at(Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

    #[test]
    fn should_generate_repository_response() {
        let cert = ::remote::idcert::tests::test_id_certificate();

        let pr = RepositoryResponse {
            tag: Some("tag".to_string()),
            publisher_handle: "tim".to_string(),
            rrdp_notification_uri: example_rrdp_uri(),
            sia_base: example_sia_base(),
            service_uri: example_service_uri(),
            id_cert: cert
        };

        let enc = pr.encode_vec();

        RepositoryResponse::decode(
            str::from_utf8(&enc).unwrap().as_bytes()
        ).unwrap().validate_at(Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }
}

