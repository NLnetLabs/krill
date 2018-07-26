//
// Support for the RFC8183 out-of-band setup requests and responses
// used to exchange identity and configuration between CAs and their
// parent CA and/or RPKI Publication Servers.
//
extern crate xml;

use base64;
use std::fs::File;
use std::collections::HashMap;
use xml::reader::{ParserConfig, XmlEvent};
use xml::attribute::OwnedAttribute;

pub struct PublisherRequest {
    tag: Option<String>,
    publisher_handle: String,
    encoded_cert: Vec<u8>,
    // publisher_certificate
}

fn attributes_into_map(attributes: Vec<OwnedAttribute>) -> HashMap<String, String> {
    let mut att_map = HashMap::new();
    for a in attributes {
        att_map.insert(a.name.local_name, a.value);
    }
    att_map
}

fn get_required_attribute(map: &HashMap<String, String>, name: &str)
    -> Result<String, PublisherRequestError> {

    match map.get(name) {
        Some(val) => Ok(val.to_string()),
        None => Err(PublisherRequestError::MissingRequiredAttribute(name.to_string()))
    }
}

fn get_optional_attribute(map: &HashMap<String, String>, name: &str) -> Option<String> {
    match map.get(name) {
        Some(val) => Some(val.to_string()),
        None => None
    }
}


fn parse_publisher_request(path: &str) -> Result<PublisherRequest, PublisherRequestError> {
    let file = File::open(path).unwrap();

    let config = ParserConfig::new().ignore_comments(true).trim_whitespace(true);
    let mut reader = config.create_reader(file);

    let publisher_handle: String;
    let tag: Option<String>;
    let encoded_cert: Vec<u8>;

    // Expect start of document
    match reader.next() {
        Ok(XmlEvent::StartDocument {..}) => {},
        _ => return Err(PublisherRequestError::InvalidXml)
    };

    // Expect <publisher_request> with some attributes
    match reader.next() {
        Ok(XmlEvent::StartElement { name, attributes, .. }) => {
            if name.local_name != "publisher_request" {
                return Err(PublisherRequestError::InvalidXml);
            }

            let att_map = attributes_into_map(attributes);

            let version = get_required_attribute(&att_map, "version")?;
            if version != "1" {
                return Err(PublisherRequestError::InvalidVersion);
            }

            tag = get_optional_attribute(&att_map, "tag");
            publisher_handle = get_required_attribute(&att_map, "publisher_handle")?;
        }
        _ => return Err(PublisherRequestError::InvalidXml)
    }

    // next expect a publisher_bpki_ta element
    match reader.next() {
            Ok(XmlEvent::StartElement { name, attributes, ..}) => {
                if name.local_name != "publisher_bpki_ta" || attributes.len() > 0 {
                    return Err(PublisherRequestError::InvalidXml)
                }
            },
            _ => return Err(PublisherRequestError::InvalidXml)
    }

    // next expect characters that form a base64 encoded id certificate
    match reader.next() {
        Ok(XmlEvent::Characters(base64_enc_cer)) => {
            encoded_cert = base64::decode_config(&base64_enc_cer, base64::MIME)?;
        }
        _ => return Err(PublisherRequestError::InvalidXml)
    }

    // expect </publisher_bpki_ta> element
    match reader.next() {
        Ok(XmlEvent::EndElement { name }) => {
            if name.local_name != "publisher_bpki_ta" {
                return Err(PublisherRequestError::InvalidXml)
            }
        },
        _ => return Err(PublisherRequestError::InvalidXml)
    };
    // expect </publisher_request>
    match reader.next() {
        Ok(XmlEvent::EndElement { name }) => {
            if name.local_name != "publisher_request" {
                return Err(PublisherRequestError::InvalidXml)
            }
        },
        _ => return Err(PublisherRequestError::InvalidXml)
    };

    // expect end of document
    match reader.next() {
        Ok(XmlEvent::EndDocument {..}) => {},
        _ => return Err(PublisherRequestError::InvalidXml)
    };

    Ok(PublisherRequest{tag, publisher_handle, encoded_cert})
}

#[derive(Debug, Fail)]
pub enum PublisherRequestError {

    #[fail(display = "Parse error: {}", _0)]
    InvalidBase64Certificate(base64::DecodeError),

    #[fail(display = "Parse error: {}", _0)]
    MalformedXmlError(xml::reader::Error),

    #[fail(display = "Missing required attribute: {}", _0)]
    MissingRequiredAttribute(String),

    #[fail(display = "Invalid XML for Publisher Request")]
    InvalidXml,

    #[fail(display = "Invalid version for Publisher Request")]
    InvalidVersion,
}

impl From<xml::reader::Error> for PublisherRequestError {
    fn from(e: xml::reader::Error) -> PublisherRequestError {
        PublisherRequestError::MalformedXmlError(e)
    }
}

impl From<base64::DecodeError> for PublisherRequestError {
    fn from(e: base64::DecodeError) -> PublisherRequestError {
        PublisherRequestError::InvalidBase64Certificate(e)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    # [test]
    fn test_parse_publisher_request() {
        assert!(parse_publisher_request("test/publisher_request.xml").is_ok());



    }
}