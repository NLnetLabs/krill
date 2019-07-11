use std::io;

use krill_commons::util::xml::{XmlReader, XmlReaderErr, AttributesError, XmlWriter};

const VERSION: &str = "1";
const NS: &str = "http://www.apnic.net/specs/rescerts/up-down/";

//------------ Message -------------------------------------------------------

/// This type represents all Provisioning Messages defined in RFC6492.
///
/// Note this is all very similar to, yet subtly different from, the
/// Publication Messages defined in RFC8181.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    sender: String,
    recipient: String,
    content: MessageContent
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageContent {
    Query(Query),
    Reply
}

impl MessageContent {
    fn msg_type(&self) -> &str {
        match self {
            MessageContent::Query(q) => q.query_type(),
            MessageContent::Reply => unimplemented!()
        }
    }
}

/// # Decoding
///
impl Message {
    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, Error> where R: io::Read {
        XmlReader::decode(reader, |r| {
            r.take_named_element("message",|mut a, r| {

                match a.take_req("version")?.as_ref() {
                    VERSION => { },
                    _ => return Err(Error::InvalidVersion)
                }
                let sender = a.take_req("sender")?;
                let recipient = a.take_req("recipient")?;
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                let content = match msg_type.as_ref() {
                    "list" => {
                        Ok(MessageContent::Query(Query::decode(&msg_type, r)?))
                    },
                    _ => Err(Error::UnknownMessageType)
                }?;

                Ok(Message { sender, recipient, content })
            })
        })
    }

    /// Encode into XML
    pub fn encode<W: io::Write>(
        &self,
        target: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {

        let msg_type = self.content.msg_type();

        let attrs = [
            ("xmlns", NS),
            ("version", VERSION),
            ("sender", &self.sender),
            ("recipient", &self.recipient),
            ("type", msg_type)
        ];

        target.put_element(
            "message",
            Some(&attrs),
            |w| {
                match &self.content {
                    MessageContent::Query(q) => q.encode(w),
                    MessageContent::Reply => unimplemented!()
                }
            }
        )
    }

    /// Encodes to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {
            self.encode(w)
        })
    }


}


//------------ Query ---------------------------------------------------------

/// This type defines the various RFC6492 queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Query {
    List
}


impl Query {
    fn query_type(&self) -> &str {
        match self {
            Query::List => "list"
        }
    }

    fn decode<R>(
        query_type: &str,
        r: &mut XmlReader<R>
    ) -> Result<Self, Error> where R: io::Read {
        match query_type {
            "list" => Ok(Query::List),
            _ => Err(Error::UnknownMessageType)
        }
    }

    pub fn encode<W: io::Write>(
        &self,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        match self {
            Query::List => w.empty()
        }
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[display(fmt = "Invalid use of attributes in XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[display(fmt = "Unknown message type")]
    UnknownMessageType,

    #[display(fmt = "Invalid protocol version, MUST be 1")]
    InvalidVersion,
}

impl From<XmlReaderErr> for Error {
    fn from(e: XmlReaderErr) -> Self {
        Error::XmlReadError(e)
    }
}

impl From<AttributesError> for Error {
    fn from(e: AttributesError) -> Self {
        Error::XmlAttributesError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;

    fn assert_re_encode_equals(object: Message, xml: &str) {
        let vec = object.encode_vec();
        let encoded_xml = str::from_utf8(&vec).unwrap();
        let object_from_encoded_xml = Message::decode(encoded_xml.as_bytes()).unwrap();
        assert_eq!(object, object_from_encoded_xml);
        assert_eq!(xml, encoded_xml);
    }

    #[test]
    fn parse_list_query() {
        let xml = include_str!("../test/provisioning/list.xml");
        let list_query = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list_query, xml);
    }

}