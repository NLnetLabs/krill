//! Common components for publication protocol messages

use std::io;
use bytes::Bytes;
use rpki::uri;
use crate::remote::publication::query::{ListQuery, PublishQuery};
use crate::remote::publication::reply::{ErrorReply, ListReply, SuccessReply};
use crate::remote::sigmsg::SignedMessage;
use crate::util::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};

pub const VERSION: &'static str = "4";
pub const NS: &'static str = "http://www.hactrn.net/uris/rpki/publication-spec/";


//------------ QueryMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryMessage {
    PublishQuery(PublishQuery),
    ListQuery(ListQuery)
}

/// # Decoding and Encoding
///
impl QueryMessage {
    fn decode<R>(r: &mut XmlReader<R>) -> Result<Self, MessageError>
        where R: io::Read {
        match r.next_start_name() {
            Some("list") =>{
                Ok(QueryMessage::ListQuery(ListQuery::decode(r)?))
            },
            Some("publish") | Some("withdraw") => {
                Ok(QueryMessage::PublishQuery(PublishQuery::decode(r)?))
            },
            None => {
                // empty publish query
                Ok(QueryMessage::PublishQuery(PublishQuery::decode(r)?))
            },
            _ => {
                Err(MessageError::ExpectedStart(
                    "list, publish, or withdraw".to_string()))
            }
        }
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        match self {
            QueryMessage::PublishQuery(q) => { q.encode(w)?; }
            QueryMessage::ListQuery(l)    => { l.encode(w)?; }
        }
        Ok(())
    }

    /// Consumes this and returns the embedded publish query, or
    /// throws an error if a list query was contained.
    pub fn as_publish(self) -> Result<PublishQuery, MessageError> {
        match self {
            QueryMessage::PublishQuery(p) => Ok(p),
            _ => Err(MessageError::WrongMessageType)
        }
    }

    /// Consumes this and returns the embedded list query, or
    /// throws an error if a list query was contained.
    pub fn as_list(self) -> Result<ListQuery, MessageError> {
        match self {
            QueryMessage::ListQuery(l) => Ok(l),
            _ => Err(MessageError::WrongMessageType)
        }
    }
}

/// # Create
///
impl QueryMessage {
    pub fn new() -> Self {
        QueryMessage::ListQuery(ListQuery)
    }
}

//------------ ReplyMessage --------------------------------------------------

/// This type represents reply type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyMessage {
    SuccessReply(SuccessReply),
    ListReply(ListReply),
    ErrorReply(ErrorReply)
}

/// # Decoding and Encoding
///
impl ReplyMessage {
    fn decode<R>(r: &mut XmlReader<R>) -> Result<Self, MessageError>
        where R: io::Read {
        match r.next_start_name() {
            Some("success") => {
                Ok(ReplyMessage::SuccessReply(SuccessReply::decode(r)?))
            },
            Some("report_error") => {
                Ok(ReplyMessage::ErrorReply(ErrorReply::decode(r)?))
            },
            Some("list") => {
                Ok(ReplyMessage::ListReply(ListReply::decode(r)?))
            },
            None => {
                // An empty list response
                Ok(ReplyMessage::ListReply(ListReply::decode(r)?))
            },
            _ => Err(MessageError::ExpectedStart(
                "success, list or report_error".to_string()))
        }
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        match self {
            ReplyMessage::SuccessReply(s) => { s.encode(w)?; }
            ReplyMessage::ListReply(l)    => { l.encode(w)?; }
            ReplyMessage::ErrorReply(e)   => { e.encode(w)?; }
        }
        Ok(())
    }
}


//------------ Message -------------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    QueryMessage(QueryMessage),
    ReplyMessage(ReplyMessage)
}

/// # Decoding and Encoding
///
impl Message {
    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, MessageError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("msg", |mut a, r| {

                match a.take_req("version")?.as_ref() {
                    VERSION => { },
                    _ => return Err(MessageError::InvalidVersion)
                }
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                match msg_type.as_ref() {
                    "query" => {
                        Ok(Message::QueryMessage(QueryMessage::decode(r)?))
                    },
                    "reply" => {
                        Ok(Message::ReplyMessage(ReplyMessage::decode(r)?))
                    }
                    _ => {
                        return Err(MessageError::UnknownMessageType)
                    }
                }
            })
        })
    }

    pub fn encode<W: io::Write>(&self, target: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        let msg_type = match self {
            Message::QueryMessage(_) => "query",
            Message::ReplyMessage(_) => "reply"
        };
        let a = [
            ("xmlns", NS),
            ("version", VERSION),
            ("type", msg_type),
        ];

        target.put_element(
            "msg",
            Some(&a),
            |w| {
                match self {
                    Message::ReplyMessage(r) => { r.encode(w) }
                    Message::QueryMessage(q) => { q.encode(w) }
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

    /// Consumes the message and turns it into bytes
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.encode_vec())
    }

    /// Parses the content of a SignedMessage as a Message.
    pub fn from_signed_message(
        msg: &SignedMessage
    ) -> Result<Message, MessageError> {
        Message::decode(msg.content().to_bytes().as_ref())
    }

    /// Consumes this message and returns the contained query, or
    /// an error if you tried this on a reply.
    pub fn as_query(self) -> Result<QueryMessage, MessageError> {
        match self {
            Message::QueryMessage(q) => Ok(q),
            _ => Err(MessageError::WrongMessageType)
        }
    }

    /// Consumes this message and returns the contained query, or
    /// an error if you tried this on a reply.
    pub fn as_reply(self) -> Result<ReplyMessage, MessageError> {
        match self {
            Message::ReplyMessage(r) => Ok(r),
            _ => Err(MessageError::WrongMessageType)
        }
    }

    pub fn message_type(&self) -> String {
        match self {
            Message::QueryMessage(QueryMessage::ListQuery(_)) =>
                "list query",
            Message::QueryMessage(QueryMessage::PublishQuery(_)) =>
                "publish query",
            Message::ReplyMessage(ReplyMessage::SuccessReply(_)) =>
                "success reply",
            Message::ReplyMessage(ReplyMessage::ListReply(_)) =>
                "list reply",
            Message::ReplyMessage(ReplyMessage::ErrorReply(_)) =>
                "error reply",
        }.to_string()
    }
}


//------------ PublicationMessageError ---------------------------------------

#[derive(Debug, Display)]
pub enum MessageError {
    #[display(fmt = "Invalid version")]
    InvalidVersion,

    #[display(fmt = "Unknown message type")]
    UnknownMessageType,

    #[display(fmt = "Unexpected XML Start Tag: {}", _0)]
    UnexpectedStart(String),

    #[display(fmt = "Expected some XML Start Tag: {}", _0)]
    ExpectedStart(String),

    #[display(fmt = "Missing content in XML: {}", _0)]
    MissingContent(String),

    #[display(fmt = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[display(fmt = "Invalid use of attributes in XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[display(fmt = "Invalid URI: {}", _0)]
    UriError(uri::Error),

    #[display(fmt = "Invalid error code: {}", _0)]
    InvalidErrorCode(String),

    #[display(fmt = "Wrong message type.")]
    WrongMessageType,
}

impl From<XmlReaderErr> for MessageError {
    fn from(e: XmlReaderErr) -> MessageError {
        MessageError::XmlReadError(e)
    }
}

impl From<AttributesError> for MessageError {
    fn from(e: AttributesError) -> MessageError {
        MessageError::XmlAttributesError(e)
    }
}

impl From<uri::Error> for MessageError {
    fn from(e: uri::Error) -> MessageError {
        MessageError::UriError(e)
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
    fn should_parse_and_encode_multi_element_query() {
        let xml = include_str!("../../../test/publication/publish.xml");
        let pm = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(pm, xml);
    }

    #[test]
    fn should_parse_and_encode_list_query() {
        let xml = include_str!("../../../test/publication/list.xml");
        let l = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(l, xml);
    }

    #[test]
    fn should_parse_and_encode_success_reply() {
        let xml = include_str!("../../../test/publication/success.xml");
        let s = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(s, xml);
    }

    #[test]
    fn should_parse_and_encode_list_reply() {
        let xml = include_str!("../../../test/publication/list_reply.xml");
        let r = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(r, xml);
    }

    #[test]
    fn should_parse_and_encode_minimal_error() {
        let xml = include_str!(
            "../../../test/publication/report_error_minimal.xml"
        );
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_and_encode_complex_error() {
        let xml = include_str!(
            "../../../test/publication/report_error_complex.xml"
        );
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_empty_list_reply() {
        let xml = include_str!(
            "../../../test/publication/list_reply_empty.xml"
        );
        let _ = Message::decode(xml.as_bytes()).unwrap();
    }

}
