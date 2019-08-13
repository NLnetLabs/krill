//! Support for RPKI XML structures.
use std::fs::File;
use std::path::Path;
use std::{fs, io};

use base64;
use base64::DecodeError;
use bytes::Bytes;
use hex;
use hex::FromHexError;
use xmlrs::attribute::OwnedAttribute;
use xmlrs::reader::XmlEvent;
use xmlrs::{reader, writer};
use xmlrs::{EmitterConfig, EventReader, EventWriter, ParserConfig};

//------------ XmlReader -----------------------------------------------------

/// A convenience wrapper for RPKI XML parsing
///
/// This type only exposes things we need for the RPKI XML structures.
pub struct XmlReader<R: io::Read> {
    /// The underlying xml-rs reader
    reader: EventReader<R>,

    /// Placeholder for an event so that 'peak' can be supported, as
    /// well as temporarily caching a close event in case a list of
    /// inner elements is processed.
    cached_event: Option<XmlEvent>,

    /// Name of the next start element, if any
    next_start_name: Option<String>,
}

/// Reader methods
impl<R: io::Read> XmlReader<R> {
    /// Gets the next XmlEvent
    ///
    /// Will take cached event if there is one
    fn next(&mut self) -> Result<XmlEvent, XmlReaderErr> {
        match self.cached_event.take() {
            Some(e) => Ok(e),
            None => Ok(self.reader.next()?),
        }
    }

    /// Puts an XmlEvent back so that it can be retrieved by 'next'
    fn cache(&mut self, e: XmlEvent) {
        self.cached_event = Some(e);
    }
}

/// Basic operations to parse the XML.
///
/// These methods are private because they are used by the higher level
/// closure based methods, defined below, that one should use to parse
/// XML safely.
impl<R: io::Read> XmlReader<R> {
    /// Takes the next element and expects a start of document.
    fn start_document(&mut self) -> Result<(), XmlReaderErr> {
        match self.next() {
            Ok(reader::XmlEvent::StartDocument { .. }) => Ok(()),
            _ => Err(XmlReaderErr::ExpectedStartDocument),
        }
    }

    /// Takes the next element and expects a start element with the given name.
    fn expect_element(&mut self) -> Result<(Tag, Attributes), XmlReaderErr> {
        match self.next() {
            Ok(reader::XmlEvent::StartElement {
                name, attributes, ..
            }) => Ok((
                Tag {
                    name: name.local_name,
                },
                Attributes { attributes },
            )),
            _ => Err(XmlReaderErr::ExpectedStart),
        }
    }

    /// Takes the next element and expects a close element with the given name.
    fn expect_close(&mut self, tag: Tag) -> Result<(), XmlReaderErr> {
        match self.next() {
            Ok(reader::XmlEvent::EndElement { name, .. }) => {
                if name.local_name == tag.name {
                    Ok(())
                } else {
                    Err(XmlReaderErr::ExpectedClose(tag.name))
                }
            }
            _ => Err(XmlReaderErr::ExpectedClose(tag.name)),
        }
    }

    /// Takes the next element and expects the end of document.
    ///
    /// Returns Ok(true) if the element is the end of document, or
    /// an error otherwise.
    fn end_document(&mut self) -> Result<(), XmlReaderErr> {
        match self.next() {
            Ok(reader::XmlEvent::EndDocument) => Ok(()),
            _ => Err(XmlReaderErr::ExpectedEnd),
        }
    }
}

/// Closure based parsing of XML.
///
/// This approach ensures that the consumer can only get opening tags, or
/// content (such as Characters), and process the enclosed content. In
/// particular it ensures that the consumer cannot accidentally get close
/// tags - so it forces that execution returns.
impl<R: io::Read> XmlReader<R> {
    /// Decodes an XML structure
    ///
    /// This method checks that the document starts, then passes a reader
    /// instance to the provided closure, and will return the result from
    /// that after checking that the XML document is fully processed.
    pub fn decode<F, T, E>(source: R, op: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<XmlReaderErr>,
    {
        let mut config = ParserConfig::new();
        config.trim_whitespace = true;
        config.ignore_comments = true;

        let mut xml = XmlReader {
            reader: config.create_reader(source),
            cached_event: None,
            next_start_name: None,
        };

        xml.start_document()?;
        let res = op(&mut xml)?;
        xml.end_document()?;

        Ok(res)
    }

    /// Takes an element and process it in a closure
    ///
    /// This method checks that the next element is indeed a Start Element,
    /// and passes the Tag and Attributes and this reader to a closure. After
    /// the closure completes it will verify that the next element is the
    /// Close Element for this Tag, and returns the result from the closure.
    pub fn take_element<F, T, E>(&mut self, op: F) -> Result<T, E>
    where
        F: FnOnce(&Tag, Attributes, &mut Self) -> Result<T, E>,
        E: From<XmlReaderErr>,
    {
        let (tag, attr) = self.expect_element()?;
        let res = op(&tag, attr, self)?;
        self.expect_close(tag)?;
        Ok(res)
    }

    /// Takes a named element and process it in a closure
    ///
    /// Checks that the element has the expected name and passed the closure
    /// to the generic take_element method.
    pub fn take_named_element<F, T, E>(&mut self, name: &str, op: F) -> Result<T, E>
    where
        F: FnOnce(Attributes, &mut Self) -> Result<T, E>,
        E: From<XmlReaderErr>,
    {
        self.take_element(|t, a, r| {
            if t.name != name {
                Err(XmlReaderErr::ExpectedNamedStart(name.to_string()).into())
            } else {
                op(a, r)
            }
        })
    }

    /// Takes the next element that is part of a list of elements under the
    /// current element, and processes it using a closure. When the end of the
    /// list is encountered, i.e. the next element is not a start element, then
    /// the closure is not executed and Ok(None) is returned. The element is
    /// put back on the cache for processing by the parent structure.
    ///
    /// Note: This will break if we encounter a parent XML element that has
    /// both a list of children XML elements *and* some (character) content.
    /// However, this is not used by the RPKI XML structures. Also, provided
    /// that a 'take_*' method with a closure was used for the parent element,
    /// then we will get a clear error there (expect end element).
    pub fn take_opt_element<F, T, E>(&mut self, op: F) -> Result<Option<T>, E>
    where
        F: FnOnce(&Tag, Attributes, &mut Self) -> Result<Option<T>, E>,
        E: From<XmlReaderErr>,
    {
        let n = self.next()?;
        match n {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                let tag = Tag {
                    name: name.local_name,
                };
                let res = op(&tag, Attributes { attributes }, self)?;
                self.expect_close(tag)?;
                Ok(res)
            }
            _ => {
                self.cache(n);
                Ok(None)
            }
        }
    }

    /// Takes characters
    pub fn take_chars(&mut self) -> Result<String, XmlReaderErr> {
        match self.next() {
            Ok(reader::XmlEvent::Characters(chars)) => Ok(chars),
            _ => Err(XmlReaderErr::ExpectedCharacters),
        }
    }

    /// Takes base64 encoded bytes from the next 'characters' event.
    pub fn take_bytes_std(&mut self) -> Result<Bytes, XmlReaderErr> {
        self.take_bytes(base64::STANDARD_NO_PAD)
    }

    fn take_bytes(&mut self, config: base64::Config) -> Result<Bytes, XmlReaderErr> {
        let chars = self.take_chars()?;
        // strip whitespace and padding (we are liberal in what we accept here)
        // TODO: Avoid allocation, pass in an AsRef<[u8]> that
        //       removes any whitespace on the fly.
        let chars: Vec<u8> = chars
            .into_bytes()
            .into_iter()
            .filter(|c| !b" \n\t\r\x0b\x0c=".contains(c))
            .collect();

        let b64 = base64::decode_config(&chars, config)?;
        Ok(Bytes::from(b64))
    }

    pub fn take_empty(&mut self) -> Result<(), XmlReaderErr> {
        Ok(())
    }

    /// Returns the name of the next start element or None if the next
    /// element is not a start element. Also ensures that the next element
    /// is kept in the cache for normal subsequent processing.
    pub fn next_start_name(&mut self) -> Option<&str> {
        match self.next() {
            Err(_) => None,
            Ok(e) => {
                if let XmlEvent::StartElement { ref name, .. } = e {
                    // XXX not the most efficient.. but need a different
                    //     underlying XML parser to get around ownership
                    //     issues.
                    self.next_start_name = Some(name.local_name.clone())
                } else {
                    self.next_start_name = None;
                }
                self.cache(e);
                self.next_start_name.as_ref().map(AsRef::as_ref)
            }
        }
    }
}

impl XmlReader<fs::File> {
    /// Opens a file and decodes it as an XML file.
    pub fn open<P, F, T, E>(path: P, op: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        P: AsRef<Path>,
        E: From<XmlReaderErr> + From<io::Error>,
    {
        Self::decode(fs::File::open(path)?, op)
    }
}

//------------ XmlReaderErr --------------------------------------------------

#[derive(Debug, Display)]
pub enum XmlReaderErr {
    #[display(fmt = "Expected Start of Document")]
    ExpectedStartDocument,

    #[display(fmt = "Expected Start Element")]
    ExpectedStart,

    #[display(fmt = "Expected Start Element with name: {}", _0)]
    ExpectedNamedStart(String),

    #[display(fmt = "Expected Characters Element")]
    ExpectedCharacters,

    #[display(fmt = "Expected Close Element with name: {}", _0)]
    ExpectedClose(String),

    #[display(fmt = "Expected End of Document")]
    ExpectedEnd,

    #[display(fmt = "Error reading file: {}", _0)]
    IoError(io::Error),

    #[display(fmt = "Attributes Error: {}", _0)]
    AttributesError(AttributesError),

    #[display(fmt = "XML Reader Error: {}", _0)]
    ReaderError(reader::Error),

    #[display(fmt = "Base64 decoding issue: {}", _0)]
    Base64Error(DecodeError),
}

impl From<io::Error> for XmlReaderErr {
    fn from(e: io::Error) -> XmlReaderErr {
        XmlReaderErr::IoError(e)
    }
}

impl From<AttributesError> for XmlReaderErr {
    fn from(e: AttributesError) -> XmlReaderErr {
        XmlReaderErr::AttributesError(e)
    }
}

impl From<reader::Error> for XmlReaderErr {
    fn from(e: reader::Error) -> XmlReaderErr {
        XmlReaderErr::ReaderError(e)
    }
}

impl From<DecodeError> for XmlReaderErr {
    fn from(e: DecodeError) -> XmlReaderErr {
        XmlReaderErr::Base64Error(e)
    }
}

//------------ Attributes ----------------------------------------------------

/// A convenient wrapper for XML tag attributes
pub struct Attributes {
    /// The underlying xml-rs structure
    attributes: Vec<OwnedAttribute>,
}

impl Attributes {
    /// Takes an optional attribute by name
    pub fn take_opt(&mut self, name: &str) -> Option<String> {
        let i = self
            .attributes
            .iter()
            .position(|a| a.name.local_name == name);
        match i {
            Some(i) => {
                let a = self.attributes.swap_remove(i);
                Some(a.value)
            }
            None => None,
        }
    }

    /// Takes an optional hexencoded attribute and converts it to Bytes
    pub fn take_opt_hex(&mut self, name: &str) -> Option<Bytes> {
        self.take_req_hex(name).ok()
    }

    /// Takes a required attribute by name
    pub fn take_req(&mut self, name: &str) -> Result<String, AttributesError> {
        self.take_opt(name)
            .ok_or_else(|| AttributesError::MissingAttribute(name.to_string()))
    }

    /// Takes a required hexencoded attribute and converts it to Bytes
    pub fn take_req_hex(&mut self, name: &str) -> Result<Bytes, AttributesError> {
        match hex::decode(self.take_req(name)?) {
            Err(e) => Err(AttributesError::HexError(e)),
            Ok(b) => Ok(Bytes::from(b)),
        }
    }

    /// Verifies that there are no more attributes
    pub fn exhausted(&self) -> Result<(), AttributesError> {
        if self.attributes.is_empty() {
            Ok(())
        } else {
            Err(AttributesError::extras(&self.attributes))
        }
    }
}

//------------ AttributesError -----------------------------------------------

#[derive(Debug, Display)]
pub enum AttributesError {
    #[display(fmt = "Required attribute missing: {}", _0)]
    MissingAttribute(String),

    #[display(fmt = "Extra attributes found: {}", _0)]
    ExtraAttributes(String),

    #[display(fmt = "Wrong hex encoding: {}", _0)]
    HexError(FromHexError),
}

impl AttributesError {
    fn extras(atts: &[OwnedAttribute]) -> Self {
        let atts: Vec<String> = atts.iter().map(|a| format!("{}", a)).collect();
        let atts = atts.join(", ");
        AttributesError::ExtraAttributes(atts)
    }
}

//------------ Tag -----------------------------------------------------------

pub struct Tag {
    pub name: String,
}

//------------ XmlWriter -----------------------------------------------------

/// A convenience wrapper for RPKI XML generation
///
/// This type only exposes things we need for the RPKI XML structures.
pub struct XmlWriter<W> {
    /// The underlying xml-rs writer
    writer: EventWriter<W>,
}

/// Generate the XML.
impl<W: io::Write> XmlWriter<W> {
    fn unwrap_emitter_error<T>(r: Result<T, writer::Error>) -> Result<T, io::Error> {
        match r {
            Ok(t) => Ok(t),
            Err(e) => {
                match e {
                    writer::Error::Io(io) => Err(io),
                    _ => {
                        // The other errors can only happen for stuff like
                        // not closing tags, starting a doc twice etc. But
                        // the XmlWriter lib already ensures that these things
                        // do not happen. They are not dependent on input.
                        panic!("XmlWriter library error: {:?}", e)
                    }
                }
            }
        }
    }

    /// Adds an element
    pub fn put_element<F>(
        &mut self,
        name: &str,
        attr: Option<&[(&str, &str)]>,
        op: F,
    ) -> Result<(), io::Error>
    where
        F: FnOnce(&mut Self) -> Result<(), io::Error>,
    {
        let mut start = writer::XmlEvent::start_element(name);

        if let Some(v) = attr {
            for a in v {
                start = start.attr(a.0, a.1);
            }
        }

        Self::unwrap_emitter_error(self.writer.write(start))?;
        op(self)?;
        Self::unwrap_emitter_error(self.writer.write(writer::XmlEvent::end_element()))?;

        Ok(())
    }

    /// Puts some String in a characters element
    pub fn put_text(&mut self, text: &str) -> Result<(), io::Error> {
        Self::unwrap_emitter_error(self.writer.write(writer::XmlEvent::Characters(text)))?;
        Ok(())
    }

    /// Converts bytes to base64 encoded Characters as the content, using the
    /// Standard character set, without padding.
    pub fn put_base64_std(&mut self, bytes: &Bytes) -> Result<(), io::Error> {
        let b64 = base64::encode_config(bytes, base64::STANDARD);
        self.put_text(b64.as_ref())
    }

    /// Use this for convenience where empty content is required
    pub fn empty(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    /// Sets up the writer config and returns a closure that is expected
    /// to add the actual content of the XML.
    ///
    /// This method is private because one should use the pub encode_vec
    /// method, and in future others like it, to set up the writer for a
    /// specific type (Vec<u8>, File, etc.).
    fn encode<F>(w: W, op: F) -> Result<(), io::Error>
    where
        F: FnOnce(&mut Self) -> Result<(), io::Error>,
    {
        let writer = EmitterConfig::new()
            .write_document_declaration(false)
            .normalize_empty_elements(true)
            .perform_indent(true)
            .create_writer(w);

        let mut x = XmlWriter { writer };

        op(&mut x)
    }
}

impl XmlWriter<()> {
    /// Call this to encode XML into a Vec<u8>
    pub fn encode_vec<F>(op: F) -> Vec<u8>
    where
        F: FnOnce(&mut XmlWriter<&mut Vec<u8>>) -> Result<(), io::Error>,
    {
        let mut b = Vec::new();
        XmlWriter::encode(&mut b, op).unwrap(); // IO error impossible for vec
        b
    }

    pub fn encode_to_file<F>(file: &mut File, op: F) -> Result<(), io::Error>
    where
        F: FnOnce(&mut XmlWriter<&mut File>) -> Result<(), io::Error>,
    {
        XmlWriter::encode(file, op)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;

    #[test]
    fn should_write_xml() {
        let xml = XmlWriter::encode_vec(|w| {
            w.put_element("a", Some(&[("xmlns", "http://ns/"), ("c", "d")]), |w| {
                w.put_element("b", None, |w| w.put_base64_std(&Bytes::from("X")))
            })
        });

        assert_eq!(
            str::from_utf8(&xml).unwrap(),
            "<a xmlns=\"http://ns/\" c=\"d\">\n  <b>WA==</b>\n</a>"
        );
    }
}
