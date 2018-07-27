// Some convenience stuff for handling the RPKI xml structures

use std::{fs, io};
use std::path::Path;
use xml::EventReader;
use xml::ParserConfig;
use xml::reader::XmlEvent;
use xml::attribute::OwnedAttribute;

/// Wrapper for convenient XML parsing
///
/// This type only exposes things we need for the RPKI XML structures.
pub struct XmlReader<R: io::Read> {
    reader: EventReader<R>
}

impl <R: io::Read> XmlReader<R> {

    pub fn create(source: R) -> Result<Self, io::Error> {
        let mut config = ParserConfig::new();
        config.trim_whitespace = true;
        config.ignore_comments = true;
        let reader = config.create_reader(source);
        Ok(XmlReader{reader})
    }

    pub fn start_document(&mut self) -> Result<bool, XmlReaderErr> {
        match self.reader.next() {
            Ok(XmlEvent::StartDocument {..}) => { Ok(true)},
            _ => return Err(XmlReaderErr::ExpectedStartDocument)
        }
    }

    pub fn expect_element(
        &mut self,
        exp: &str) -> Result<Attributes, XmlReaderErr> {
        match self.reader.next() {
            Ok(XmlEvent::StartElement { name, attributes, ..}) => {
                if name.local_name == exp {
                    Ok(Attributes{attributes})
                } else {
                    Err(XmlReaderErr::ExpectedStart(exp.to_string()))
                }
            },
            _ => return Err(XmlReaderErr::ExpectedStart(exp.to_string()))
        }
    }

    pub fn expect_close(&mut self, exp: &str) -> Result<bool, XmlReaderErr> {
        match self.reader.next() {
            Ok(XmlEvent::EndElement { name, ..}) => {
                if name.local_name == exp {
                    Ok(true)
                } else {
                    Err(XmlReaderErr::ExpectedClose(exp.to_string()))
                }
            }
            _ => Err(XmlReaderErr::ExpectedClose(exp.to_string()))
        }
    }

    pub fn expect_characters(&mut self) -> Result<String, XmlReaderErr> {
        match self.reader.next() {
            Ok(XmlEvent::Characters(chars)) => { Ok(chars) }
            _ => return Err(XmlReaderErr::ExpectedCharacters)
        }
    }

    pub fn end_document(&mut self) -> Result<bool, XmlReaderErr> {
        match self.reader.next() {
            Ok(XmlEvent::EndDocument) => Ok(true),
            _ => Err(XmlReaderErr::ExpectedEnd)
        }
    }


}

impl XmlReader<fs::File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        Self::create(fs::File::open(path)?)
    }
}

#[derive(Debug, Fail)]
pub enum XmlReaderErr {

    #[fail(display = "Expected Start of Document")]
    ExpectedStartDocument,

    #[fail(display = "Expected Start Element with name: {}", _0)]
    ExpectedStart(String),

    #[fail(display = "Expected Characters Element")]
    ExpectedCharacters,

    #[fail(display = "Expected Close Element with name: {}", _0)]
    ExpectedClose(String),

    #[fail(display = "Expected End of Document")]
    ExpectedEnd
}

/// Wrapper for XML tag attributes
pub struct Attributes {
    attributes: Vec<OwnedAttribute>
}

impl Attributes {
    pub fn get_opt(&self, name: &str) -> Option<String> {
        self.attributes.iter()
            .find(|a| a.name.local_name == name)
            .map(|a| a.value.to_string())
    }

    pub fn get_req(&self, name: &str) -> Result<String, AttributesError> {
        self.get_opt(name)
            .ok_or(AttributesError::MissingAttribute(name.to_string()))
    }
}

#[derive(Debug, Fail)]
pub enum AttributesError {
    #[fail(display = "Required attribute missing: {}", _0)]
    MissingAttribute(String),
}



#[cfg(test)]
mod tests {
    use super::*;

    # [test]
    fn test_parse_publisher_request() {
        let mut r = XmlReader::open("test/publisher_request.xml").unwrap();
        r.start_document().unwrap();
        let att = r.expect_element("publisher_request").unwrap();
        assert_eq!(Some("1".to_string()), att.get_opt("version"));
        assert_eq!(Some("A0001".to_string()), att.get_opt("tag"));
        assert_eq!(Some("Bob".to_string()), att.get_opt("publisher_handle"));

        let ta_att = r.expect_element("publisher_bpki_ta").unwrap();
        assert_eq!(0, ta_att.attributes.len());

        let chars = r.expect_characters().unwrap();
        assert!(chars.starts_with("MIIDIDCCAg"));

        r.expect_close("publisher_bpki_ta").unwrap();
        r.expect_close("publisher_request").unwrap();

        r.end_document().unwrap();
    }
}