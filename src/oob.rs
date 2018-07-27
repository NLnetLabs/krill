//
// Support for the RFC8183 out-of-band setup requests and responses
// used to exchange identity and configuration between CAs and their
// parent CA and/or RPKI Publication Servers.
//

use std::io;
use std::path::Path;
use base64;
use xml_support::{XmlReader, XmlReaderErr};
use xml_support::AttributesError;
use base64::DecodeError;

/// Type representing a <publisher_request/>
///
/// For more info see: https://tools.ietf.org/html/rfc8183#section-5.2.3
#[derive(Debug)]
pub struct PublisherRequest {
    tag: Option<String>,
    publisher_handle: String,
    encoded_cert: Vec<u8>,
}

impl PublisherRequest {

    pub fn open<P: AsRef<Path>>(path: P)
        -> Result<Self, PublisherRequestError> {

        let mut r = XmlReader::open(path)?;
        r.start_document()?;

        let att = r.expect_element("publisher_request")?;

        match att.get_opt("version") {
            Some(version) => {
                if version != "1".to_string() {
                    return Err(PublisherRequestError::InvalidVersion)
                }
            },
            _ => return Err(PublisherRequestError::InvalidVersion)
        }

        let tag = att.get_opt("tag");
        let publisher_handle = att.get_req("publisher_handle")?;

        r.expect_element("publisher_bpki_ta")?;

        let base64_cert = r.expect_characters()?;
        let encoded_cert = base64::decode_config(&base64_cert, base64::MIME)?;

        r.expect_close("publisher_bpki_ta")?;
        r.expect_close("publisher_request")?;
        r.end_document()?;

        Ok(PublisherRequest{tag, publisher_handle, encoded_cert})
    }

}

#[derive(Debug, Fail)]
pub enum PublisherRequestError {

    #[fail(display = "Invalid XML for Publisher Request")]
    InvalidXml,

    #[fail(display = "Invalid version for Publisher Request")]
    InvalidVersion,

    #[fail(display = "Could not parse XML file: {}", _0)]
    FileError(io::Error),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[fail(display = "Invalid base64: {}", _0)]
    Base64Error(DecodeError)

}

impl From<io::Error> for PublisherRequestError {
    fn from(e: io::Error) -> PublisherRequestError{
        PublisherRequestError::FileError(e)
    }
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


#[cfg(test)]
mod tests {
    use super::*;

    # [test]
    fn test_parse_publisher_request() {
        let pr = PublisherRequest::open("test/publisher_request.xml").unwrap();

        assert_eq!("Bob", pr.publisher_handle);
        assert_eq!(Some("A0001".to_string()), pr.tag);
    }
}