//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};
use std::{fmt, io};

use base64::DecodeError;
use bcder::decode;
use bytes::Bytes;

use rpki::uri;
use rpki::uri::Https;
use rpki::x509;
use rpki::x509::Time;

use crate::api::admin::Handle;
use crate::util::file;
use crate::util::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};

use crate::remote::id::IdCert;

pub const VERSION: &str = "1";
pub const NS: &str = "http://www.hactrn.net/uris/rpki/rpki-setup/";

//------------ ChildRequest --------------------------------------------------

/// Type representing a <child_request /> defined in section 5.2.1 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildRequest {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The handle the child wants to use for itself. This may not be honored
    /// by the parent.
    child_handle: Handle,

    /// The self-signed IdCert containing the child's public key.
    id_cert: IdCert,
}

/// # Data Access
///
impl ChildRequest {
    pub fn new(child_handle: Handle, id_cert: IdCert) -> Self {
        ChildRequest {
            tag: None,
            child_handle,
            id_cert,
        }
    }

    pub fn unwrap(self) -> (Option<String>, Handle, IdCert) {
        (self.tag, self.child_handle, self.id_cert)
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
    pub fn child_handle(&self) -> &Handle {
        &self.child_handle
    }
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}

/// # Validation
///
impl ChildRequest {
    /// Parses a <child_request /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        Self::validate_at(reader, Time::now())
    }

    /// Parses a <child_request /> message.
    fn validate_at<R>(reader: R, now: Time) -> Result<Self, Error>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("child_request", |mut a, r| {
                if a.take_req("version")? != VERSION {
                    return Err(Error::InvalidVersion);
                }

                let tag = a.take_opt("tag");
                let child_handle = Handle::from(a.take_req("child_handle")?);

                if a.take_opt("valid_until").is_some() {
                    warn!(
                        "Found deprecated attribute 'valid_until' used by \
                         old rpkid implementations. Ignoring this, but other \
                         things may break."
                    )
                }

                a.exhausted()?;

                let bytes = r.take_named_element("child_bpki_ta", |a, r| {
                    a.exhausted()?;
                    r.take_bytes_std()
                })?;
                let id_cert = IdCert::decode(bytes)?;
                id_cert.validate_ta_at(now)?;

                Ok(ChildRequest {
                    child_handle,
                    tag,
                    id_cert,
                })
            })
        })
    }
}

/// # Encoding
///
impl ChildRequest {
    /// Encodes the <child_request/> to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let mut a = vec![
                ("xmlns", NS),
                ("version", VERSION),
                ("child_handle", self.child_handle.as_ref()),
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element("child_request", Some(a.as_ref()), |w| {
                w.put_element("child_bpki_ta", None, |w| {
                    w.put_base64_std(&self.id_cert.to_bytes())
                })
            })
        })
    }
}

impl fmt::Display for ChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.encode_vec();
        let s = unsafe { from_utf8_unchecked(s.as_slice()) };
        s.fmt(f)
    }
}

//------------ ParentResponse ------------------------------------------------

/// Type representing a <parent_response /> defined in section 5.2.2 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentResponse {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The parent CA's IdCert
    id_cert: IdCert,

    /// The handle of the parent CA.
    parent_handle: Handle,

    /// The handle chosen for the child CA. Note that this may not be the
    /// same as the handle the CA asked for.
    child_handle: Handle,

    /// The URI where the CA needs to send its RFC6492 messages
    service_uri: ServiceUri,
}

/// # Construct and Data Access
///
impl ParentResponse {
    pub fn new(
        tag: Option<String>,
        id_cert: IdCert,
        parent_handle: Handle,
        child_handle: Handle,
        service_uri: ServiceUri,
    ) -> Self {
        ParentResponse {
            tag,
            id_cert,
            parent_handle,
            child_handle,
            service_uri,
        }
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
    pub fn parent_handle(&self) -> &Handle {
        &self.parent_handle
    }
    pub fn child_handle(&self) -> &Handle {
        &self.child_handle
    }
    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }
}

/// # Validation
///
impl ParentResponse {
    pub fn validate<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        Self::validate_at(reader, Time::now())
    }

    fn validate_at<R>(reader: R, now: Time) -> Result<Self, Error>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("parent_response", |mut a, r| {
                if a.take_req("version")? != VERSION {
                    return Err(Error::InvalidVersion);
                }

                let tag = a.take_opt("tag");
                let parent_handle = Handle::from(a.take_req("parent_handle")?);
                let child_handle = Handle::from(a.take_req("child_handle")?);
                let service_uri = ServiceUri::try_from(a.take_req("service_uri")?)?;

                if a.take_opt("valid_until").is_some() {
                    warn!(
                        "Found deprecated attribute 'valid_until' used by \
                         old rpkid implementations. Ignoring this, but other \
                         things may break."
                    )
                }

                a.exhausted()?;

                let bytes = r.take_named_element("parent_bpki_ta", |a, r| {
                    a.exhausted()?;
                    r.take_bytes_std()
                })?;
                let id_cert = IdCert::decode(bytes)?;
                id_cert.validate_ta_at(now)?;

                /// We don't do anything with <offer/> or <referral /> in
                /// responses given to us, and we do not include them in
                /// our own responses given to children.
                ///
                /// I.e. the child needs to set up their publication server
                /// exchange separately, and explicitly.
                fn ignore_offer_or_referral<R>(r: &mut XmlReader<R>) -> Result<(), Error>
                where
                    R: io::Read,
                {
                    r.take_opt_element(|tag, _a, r| {
                        match tag.name.as_str() {
                            "offer" => {
                                r.take_empty()?;
                                Ok(None)
                            }
                            "referral" => {
                                let chars = r.take_chars()?;
                                Ok(Some(chars)) // help return type inference.
                            }
                            _ => Err(Error::InvalidXml),
                        }
                    })?;
                    Ok(())
                }

                while r.next_start_name().is_some() {
                    ignore_offer_or_referral(r)?;
                }

                Ok(ParentResponse {
                    tag,
                    id_cert,
                    parent_handle,
                    child_handle,
                    service_uri,
                })
            })
        })
    }
}

/// # Encoding
///
impl ParentResponse {
    /// Encodes the <parent_response/> to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let service_uri = self.service_uri.to_string();

            let mut a = vec![
                ("xmlns", NS),
                ("version", VERSION),
                ("service_uri", service_uri.as_ref()),
                ("child_handle", self.child_handle.as_ref()),
                ("parent_handle", self.parent_handle.as_ref()),
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element("parent_response", Some(a.as_ref()), |w| {
                w.put_element("parent_bpki_ta", None, |w| {
                    w.put_base64_std(&self.id_cert.to_bytes())
                })
            })
        })
    }
}

//------------ PublisherRequest ----------------------------------------------

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

    /// The self-signed IdCert containing the publisher's public key.
    id_cert: IdCert,
}

/// # Construct and Data Access
///
impl PublisherRequest {
    pub fn new(tag: Option<&str>, publisher_handle: &str, id_cert: IdCert) -> Self {
        PublisherRequest {
            tag: tag.map(|s| s.to_string()),
            publisher_handle: publisher_handle.to_string(),
            id_cert,
        }
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn client_handle(&self) -> Handle {
        Handle::from(self.publisher_handle.as_str())
    }
}

/// # Validation
///
impl PublisherRequest {
    pub fn validate<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        Self::validate_at(reader, Time::now())
    }

    /// Parses a <publisher_request /> message.
    fn validate_at<R>(reader: R, now: Time) -> Result<Self, Error>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("publisher_request", |mut a, r| {
                if a.take_req("version")? != "1" {
                    return Err(Error::InvalidVersion);
                }

                let tag = a.take_opt("tag");
                let publisher_handle = a.take_req("publisher_handle")?;
                a.exhausted()?;

                let bytes = r.take_named_element("publisher_bpki_ta", |a, r| {
                    a.exhausted()?;
                    r.take_bytes_std()
                })?;

                let id_cert = IdCert::decode(bytes)?;
                id_cert.validate_ta_at(now)?;

                Ok(PublisherRequest {
                    tag,
                    publisher_handle,
                    id_cert,
                })
            })
        })
    }
}

/// Encoding
///
impl PublisherRequest {
    /// Encodes a <publisher_request> to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            let mut a = vec![
                ("xmlns", NS),
                ("version", VERSION),
                ("publisher_handle", self.publisher_handle.as_ref()),
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element("publisher_request", Some(a.as_ref()), |w| {
                w.put_element("publisher_bpki_ta", None, |w| {
                    w.put_base64_std(&self.id_cert.to_bytes())
                })
            })
        })
    }

    /// Saves this as an XML file
    pub fn save(&self, full_path: &PathBuf) -> Result<(), io::Error> {
        let xml = self.encode_vec();
        file::save(&Bytes::from(xml), full_path)
    }
}

//------------ RepositoryResponse --------------------------------------------

/// Type representing a <repository_response/>
///
/// This is the response sent to a CA by the publication server. It contains
/// the details needed by the CA to send publication messages to the server.
///
/// See https://tools.ietf.org/html/rfc8183#section-5.2.4
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct RepositoryResponse {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The name the publication server decided to call the CA by.
    /// Note that this may not be the same as the handle the CA asked for.
    publisher_handle: String,

    /// The Publication Server Identity Certificate
    id_cert: IdCert,

    /// The URI where the CA needs to send its RFC8181 messages
    service_uri: ServiceUri,

    /// The Rsync base directory for objects published by the CA
    sia_base: uri::Rsync,

    /// The HTTPS notification URI that the CA can use
    rrdp_notification_uri: uri::Https,
}

/// # Construct and Data Access
///
impl RepositoryResponse {
    /// Creates a new response.
    pub fn new(
        tag: Option<String>,
        publisher_handle: String,
        id_cert: IdCert,
        service_uri: ServiceUri,
        sia_base: uri::Rsync,
        rrdp_notification_uri: uri::Https,
    ) -> Self {
        RepositoryResponse {
            tag,
            publisher_handle,
            id_cert,
            service_uri,
            sia_base,
            rrdp_notification_uri,
        }
    }

    pub fn tag(&self) -> &Option<String> {
        &self.tag
    }

    pub fn publisher_handle(&self) -> &String {
        &self.publisher_handle
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }

    pub fn sia_base(&self) -> &uri::Rsync {
        &self.sia_base
    }

    pub fn rrdp_notification_uri(&self) -> &uri::Https {
        &self.rrdp_notification_uri
    }
}

/// # Validation
///
impl RepositoryResponse {
    /// Parses a <repository_response /> message.
    pub fn validate<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        Self::validate_at(reader, Time::now())
    }

    fn validate_at<R>(reader: R, now: Time) -> Result<Self, Error>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("repository_response", |mut a, r| {
                if a.take_req("version")? != VERSION {
                    return Err(Error::InvalidVersion);
                }

                let tag = a.take_opt("tag");
                let publisher_handle = a.take_req("publisher_handle")?;
                let service_uri = ServiceUri::try_from(a.take_req("service_uri")?)?;
                let sia_base = uri::Rsync::from_string(a.take_req("sia_base")?)?;
                let rrdp_notification_uri =
                    uri::Https::from_string(a.take_req("rrdp_notification_uri")?)?;

                a.exhausted()?;

                let id_cert = r.take_named_element("repository_bpki_ta", |a, r| {
                    a.exhausted()?;
                    r.take_bytes_std()
                })?;

                let id_cert = IdCert::decode(id_cert)?;
                id_cert.validate_ta_at(now)?;

                Ok(RepositoryResponse {
                    tag,
                    publisher_handle,
                    id_cert,
                    service_uri,
                    sia_base,
                    rrdp_notification_uri,
                })
            })
        })
    }
}

/// # Encoding
///
impl RepositoryResponse {
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
                ("rrdp_notification_uri", rrdp_notification_uri.as_ref()),
            ];

            if let Some(ref t) = self.tag {
                a.push(("tag", t.as_ref()));
            }

            w.put_element("repository_response", Some(&a), |w| {
                w.put_element("repository_bpki_ta", None, |w| {
                    w.put_base64_std(&self.id_cert.to_bytes())
                })
            })
        })
    }

    /// Saves this as an XML file
    pub fn save(&self, full_path: &PathBuf) -> Result<(), io::Error> {
        let xml = self.encode_vec();
        file::save(&Bytes::from(xml), full_path)
    }
}

//------------ ServiceUri ----------------------------------------------------

/// The service URI where a child or publisher needs to send its
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub enum ServiceUri {
    Https(uri::Https),
    Http(String),
}

impl TryFrom<String> for ServiceUri {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with("http://") {
            // TODO: Check a bit better? It will blow up when the uri is used..
            Ok(ServiceUri::Http(value))
        } else {
            Ok(ServiceUri::Https(Https::from_str(&value)?))
        }
    }
}

impl fmt::Display for ServiceUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceUri::Http(string) => string.fmt(f),
            ServiceUri::Https(https) => https.fmt(f),
        }
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Invalid XML")]
    InvalidXml,

    #[display(fmt = "Invalid version")]
    InvalidVersion,

    #[display(fmt = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[display(fmt = "Invalid XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[display(fmt = "Invalid base64: {}", _0)]
    Base64Error(DecodeError),

    #[display(fmt = "Cannot parse identity certificate: {}", _0)]
    CannotParseIdCert(decode::Error),

    #[display(fmt = "Invalid identity certificate: {}", _0)]
    InvalidIdCert(x509::ValidationError),

    #[display(fmt = "{}", _0)]
    Uri(uri::Error),
}

impl From<XmlReaderErr> for Error {
    fn from(e: XmlReaderErr) -> Error {
        Error::XmlReadError(e)
    }
}

impl From<AttributesError> for Error {
    fn from(e: AttributesError) -> Error {
        Error::XmlAttributesError(e)
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Base64Error(e)
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Error {
        Error::CannotParseIdCert(e)
    }
}

impl From<x509::ValidationError> for Error {
    fn from(e: x509::ValidationError) -> Error {
        Error::InvalidIdCert(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::Uri(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::id::tests::test_id_certificate;
    use crate::util::test;
    use rpki::x509::Time;

    fn rpkid_time() -> Time {
        Time::utc(2012, 1, 1, 0, 0, 0)
    }

    fn example_rrdp_uri() -> uri::Https {
        test::https("https://rpki.example/rrdp/notify.xml")
    }

    fn example_sia_base() -> uri::Rsync {
        test::rsync("rsync://a.example/rpki/Alice/Bob-42/")
    }

    fn example_service_uri() -> ServiceUri {
        ServiceUri::Https(test::https("https://a.example/publication/Alice/Bob-42"))
    }

    #[test]
    fn validate_rpkid_publisher_request() {
        let xml = include_str!("../../test-resources/oob/publisher_request.xml");
        let pr = PublisherRequest::validate_at(xml.as_bytes(), rpkid_time()).unwrap();
        assert_eq!("Bob".to_string(), pr.publisher_handle);
        assert_eq!(Some("A0001".to_string()), pr.tag);
    }

    #[test]
    fn validate_rpkid_repository_response() {
        let xml = include_str!("../../test-resources/oob/repository_response.xml");
        let rr = RepositoryResponse::validate_at(xml.as_bytes(), rpkid_time()).unwrap();
        assert_eq!(Some("A0001".to_string()), rr.tag);
        assert_eq!("Alice/Bob-42".to_string(), rr.publisher_handle);
        assert_eq!(example_service_uri(), rr.service_uri);
        assert_eq!(example_rrdp_uri(), rr.rrdp_notification_uri);
        assert_eq!(example_sia_base(), rr.sia_base);
    }

    #[test]
    fn publisher_request() {
        let cert = test_id_certificate();

        let pr = PublisherRequest {
            tag: Some("tag".to_string()),
            publisher_handle: "tim".to_string(),
            id_cert: cert,
        };

        let enc = pr.encode_vec();

        PublisherRequest::validate_at(enc.as_slice(), rpkid_time()).unwrap();
    }

    #[test]
    fn repository_response() {
        let cert = test_id_certificate();

        let pr = RepositoryResponse {
            tag: Some("tag".to_string()),
            publisher_handle: "tim".to_string(),
            rrdp_notification_uri: example_rrdp_uri(),
            sia_base: example_sia_base(),
            service_uri: example_service_uri(),
            id_cert: cert,
        };

        let enc = pr.encode_vec();

        RepositoryResponse::validate_at(enc.as_slice(), rpkid_time()).unwrap();
    }

    #[test]
    fn child_request() {
        let xml = include_str!("../../test-resources/remote/rpkid-child-id.xml");
        let req = ChildRequest::validate_at(xml.as_bytes(), rpkid_time()).unwrap();

        assert_eq!(&Handle::from("Carol"), req.child_handle());
        assert_eq!(None, req.tag());

        let encoded = req.encode_vec();
        let decoded = ChildRequest::validate_at(encoded.as_slice(), rpkid_time()).unwrap();

        assert_eq!(req, decoded);
    }

    #[test]
    fn validate_rpkid_parent_response_referral() {
        let xml = include_str!("../../test-resources/remote/rpkid-parent-response-referral.xml");
        let _res = ParentResponse::validate_at(xml.as_bytes(), rpkid_time()).unwrap();
    }

    #[test]
    fn parent_response() {
        let xml = include_str!("../../test-resources/remote/rpkid-parent-response-offer.xml");
        let res = ParentResponse::validate_at(xml.as_bytes(), rpkid_time()).unwrap();

        let encoded = res.encode_vec();
        let decoded = ParentResponse::validate_at(encoded.as_slice(), rpkid_time()).unwrap();

        assert_eq!(res, decoded);
    }
}
