//! RFC8181 Messages
use std::{fmt, io};

use bytes::Bytes;

use rpki::uri;

use crate::commons::api::{
    Base64, HexEncodedHash, ListElement, ListReply, Publish, PublishDelta, PublishDeltaBuilder, PublishRequest, Update,
    Withdraw,
};
use crate::commons::crypto::ProtocolCms;
use crate::commons::util::xml::{Attributes, AttributesError, XmlReader, XmlReaderErr, XmlWriter};

pub const VERSION: &str = "4";
pub const NS: &str = "http://www.hactrn.net/uris/rpki/publication-spec/";
pub const CONTENT_TYPE: &str = "application/rpki-publication";

//------------ Message -------------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    QueryMessage(QueryMessage),
    ReplyMessage(ReplyMessage),
}

/// # Decoding and Encoding
///
impl Message {
    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, MessageError>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("msg", |mut a, r| {
                match a.take_req("version")?.as_ref() {
                    VERSION => {}
                    _ => return Err(MessageError::InvalidVersion),
                }
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                match msg_type.as_ref() {
                    "query" => Ok(Message::QueryMessage(QueryMessage::decode(r)?)),
                    "reply" => Ok(Message::ReplyMessage(ReplyMessage::decode(r)?)),
                    _ => Err(MessageError::UnknownMessageType),
                }
            })
        })
    }

    pub fn encode<W: io::Write>(&self, target: &mut XmlWriter<W>) -> Result<(), io::Error> {
        let msg_type = match self {
            Message::QueryMessage(_) => "query",
            Message::ReplyMessage(_) => "reply",
        };
        let a = [("xmlns", NS), ("version", VERSION), ("type", msg_type)];

        target.put_element("msg", Some(&a), |w| match self {
            Message::ReplyMessage(r) => r.encode(w),
            Message::QueryMessage(q) => q.encode(w),
        })
    }

    /// Encodes to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| self.encode(w))
    }

    /// Consumes the message and turns it into bytes
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.encode_vec())
    }

    /// Parses the content of a ProtocolCms as a Message.
    pub fn from_signed_message(msg: &ProtocolCms) -> Result<Message, MessageError> {
        Message::decode(msg.content().to_bytes().as_ref())
    }

    /// Consumes this message and returns the contained query, or
    /// an error if you tried this on a reply.
    pub fn into_query(self) -> Result<QueryMessage, MessageError> {
        match self {
            Message::QueryMessage(q) => Ok(q),
            _ => Err(MessageError::WrongMessageType),
        }
    }

    /// Consumes this message and returns the contained query, or
    /// an error if you tried this on a reply.
    pub fn into_reply(self) -> Result<ReplyMessage, MessageError> {
        match self {
            Message::ReplyMessage(r) => Ok(r),
            _ => Err(MessageError::WrongMessageType),
        }
    }
}

/// Constructing
///
impl Message {
    pub fn list_reply(reply: ListReply) -> Self {
        Message::ReplyMessage(ReplyMessage::ListReply(reply))
    }

    pub fn success_reply() -> Self {
        Message::ReplyMessage(ReplyMessage::SuccessReply)
    }

    pub fn publish_delta_query(delta: PublishDelta) -> Self {
        Message::QueryMessage(QueryMessage::PublishDelta(delta))
    }

    pub fn list_query() -> Self {
        Message::QueryMessage(QueryMessage::ListQuery)
    }
}

//------------ QueryMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryMessage {
    PublishDelta(PublishDelta),
    ListQuery,
}

/// # Decoding and Encoding
///
impl QueryMessage {
    fn decode<R>(r: &mut XmlReader<R>) -> Result<Self, MessageError>
    where
        R: io::Read,
    {
        match r.next_start_name() {
            Some("list") => {
                Self::decode_list_query(r)?;
                Ok(QueryMessage::ListQuery)
            }
            Some("publish") | Some("withdraw") => Ok(QueryMessage::PublishDelta(PublishDeltaXml::decode(r)?)),
            None => {
                // empty publish query
                Ok(QueryMessage::PublishDelta(PublishDeltaXml::decode(r)?))
            }
            _ => Err(MessageError::ExpectedStart("list, publish, or withdraw".to_string())),
        }
    }

    fn decode_list_query<R: io::Read>(r: &mut XmlReader<R>) -> Result<(), MessageError> {
        r.take_named_element("list", |_, r| r.take_empty())?;
        Ok(())
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        match self {
            QueryMessage::PublishDelta(d) => {
                PublishDeltaXml::encode(d, w)?;
            }
            QueryMessage::ListQuery => {
                Self::encode_list_query(w)?;
            }
        }
        Ok(())
    }

    fn encode_list_query<W: io::Write>(w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        w.put_element("list", None, |w| w.empty())?;

        Ok(())
    }

    /// Consumes this and returns this a PublishRequest for our (json) API
    pub fn into_publish_request(self) -> PublishRequest {
        match self {
            QueryMessage::ListQuery => PublishRequest::List,
            QueryMessage::PublishDelta(d) => PublishRequest::Delta(d),
        }
    }
}

//------------ PublishDeltaXml -----------------------------------------------

/// Marker struct to give a name space to all code related to decoding, and
/// encoding ['request::PublishDelta'].
pub struct PublishDeltaXml;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishDeltaElement {
    Publish(Publish),
    Update(Update),
    Withdraw(Withdraw),
}

impl PublishDeltaElement {
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        match self {
            PublishDeltaElement::Publish(p) => PublishDeltaXml::encode_publish(p, w),
            PublishDeltaElement::Update(u) => PublishDeltaXml::encode_update(u, w),
            PublishDeltaElement::Withdraw(wd) => PublishDeltaXml::encode_withdraw(wd, w),
        }
    }
}

/// # Decoding
///
impl PublishDeltaXml {
    /// Decodes a <publish> element from XML, producing either a simple, new,
    /// Publish element, or an Update - wrapped in a PublishElement.
    fn decode_publish_or_update<R: io::Read>(
        a: &mut Attributes,
        r: &mut XmlReader<R>,
    ) -> Result<PublishDeltaElement, MessageError> {
        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;
        let base64_string = r.take_chars()?;
        let base64 = Base64::from(base64_string);

        let res = match a.take_opt("hash") {
            Some(hash_str) => {
                let hash = HexEncodedHash::from(hash_str);
                let update = Update::new(Some(tag), uri, base64, hash);
                Ok(PublishDeltaElement::Update(update))
            }
            None => {
                let publish = Publish::new(Some(tag), uri, base64);
                Ok(PublishDeltaElement::Publish(publish))
            }
        };

        a.exhausted()?;
        res
    }

    /// Decodes a <withdraw/> XML element.
    fn decode_withdraw(a: &mut Attributes) -> Result<PublishDeltaElement, MessageError> {
        let hash_str = a.take_req("hash")?;
        let hash = HexEncodedHash::from(hash_str);
        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;

        a.exhausted()?;

        let withdraw = Withdraw::new(Some(tag), uri, hash);
        Ok(PublishDeltaElement::Withdraw(withdraw))
    }

    /// Decodes from an XML input. Used for processing a list of elements.
    /// Will return None when there is no (more) applicable element.
    fn decode_opt<R: io::Read>(r: &mut XmlReader<R>) -> Result<Option<PublishDeltaElement>, MessageError> {
        r.take_opt_element(|t, mut a, r| match t.name.as_ref() {
            "publish" => Ok(Some(Self::decode_publish_or_update(&mut a, r)?)),
            "withdraw" => Ok(Some(Self::decode_withdraw(&mut a)?)),
            _ => Err(MessageError::UnexpectedStart(t.name.clone())),
        })
    }

    /// Decodes a query XML structure. Expects that the outer <msg> element
    /// is processed by PublicationMessage::decode
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>) -> Result<PublishDelta, MessageError> {
        let mut bld = PublishDeltaBuilder::new();

        while let Some(pde) = Self::decode_opt(r)? {
            match pde {
                PublishDeltaElement::Publish(p) => bld.add_publish(p),
                PublishDeltaElement::Update(u) => bld.add_update(u),
                PublishDeltaElement::Withdraw(w) => bld.add_withdraw(w),
            }
        }

        Ok(bld.finish())
    }
}

/// # Encoding
///
impl PublishDeltaXml {
    /// Encodes a PublishDelta to XML in the given writer, for inclusion in an
    /// RFC8181 CMS.
    pub fn encode<W: io::Write>(delta: &PublishDelta, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        for p in delta.publishes() {
            Self::encode_publish(p, w)?;
        }
        for u in delta.updates() {
            Self::encode_update(u, w)?;
        }
        for wd in delta.withdraws() {
            Self::encode_withdraw(wd, w)?;
        }
        Ok(())
    }

    fn encode_publish<W: io::Write>(publish: &Publish, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        let uri = publish.uri().to_string();
        let tag = publish.tag_for_xml();
        let content = publish.content().to_string();

        let a = [("tag", tag.as_ref()), ("uri", uri.as_ref())];

        w.put_element("publish", Some(&a), |w| w.put_text(content.as_ref()))
    }

    fn encode_update<W: io::Write>(update: &Update, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        let uri = update.uri().to_string();
        let tag = update.tag_for_xml();

        let a = [
            ("tag", tag.as_ref()),
            ("hash", update.hash().as_ref()),
            ("uri", uri.as_ref()),
        ];

        w.put_element("publish", Some(&a), |w| w.put_text(update.content().as_ref()))
    }

    fn encode_withdraw<W: io::Write>(withdraw: &Withdraw, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        let uri = withdraw.uri().to_string();
        let tag = withdraw.tag_for_xml();

        let a = [
            ("hash", withdraw.hash().as_ref()),
            ("tag", tag.as_ref()),
            ("uri", uri.as_ref()),
        ];

        w.put_element("withdraw", Some(&a), |w| w.empty())
    }
}

//------------ ReplyMessage --------------------------------------------------

/// This type represents reply type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyMessage {
    SuccessReply,
    ListReply(ListReply),
    ErrorReply(ErrorReply),
}

/// # Decoding and Encoding
///
impl ReplyMessage {
    /// Decodes XML into a ReplyMessage containing either a Success, List or
    /// Error.
    fn decode<R>(r: &mut XmlReader<R>) -> Result<Self, MessageError>
    where
        R: io::Read,
    {
        match r.next_start_name() {
            Some("success") => {
                Self::decode_success_reply(r)?;
                Ok(ReplyMessage::SuccessReply)
            }
            Some("report_error") => Ok(ReplyMessage::ErrorReply(ErrorReply::decode(r)?)),
            Some("list") => Ok(ReplyMessage::ListReply(Self::decode_list_reply(r)?)),
            None => {
                // An empty list response
                Ok(ReplyMessage::ListReply(Self::decode_list_reply(r)?))
            }
            _ => Err(MessageError::ExpectedStart("success, list or report_error".to_string())),
        }
    }

    /// Decodes a <success/> reply from XML.
    pub fn decode_success_reply<R: io::Read>(r: &mut XmlReader<R>) -> Result<(), MessageError> {
        r.take_named_element("success", |_, r| r.take_empty())?;
        Ok(())
    }

    /// Decodes XML to a ListReply.
    fn decode_list_reply<R: io::Read>(r: &mut XmlReader<R>) -> Result<ListReply, MessageError> {
        let mut elements = vec![];

        loop {
            let e = r.take_opt_element(|t, mut a, _r| match t.name.as_ref() {
                "list" => {
                    let hash = HexEncodedHash::from(a.take_req("hash")?);
                    let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
                    a.exhausted()?;

                    Ok(Some(ListElement::new(uri, hash)))
                }
                _ => Err(MessageError::UnexpectedStart(t.name.clone())),
            })?;

            match e {
                Some(e) => elements.push(e),
                None => break,
            }
        }
        Ok(ListReply::new(elements))
    }

    /// Encodes a ReplyMessage for inclusion in an RFC8181 Protocol CMS.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        match self {
            ReplyMessage::SuccessReply => {
                Self::encode_success_reply(w)?;
            }
            ReplyMessage::ListReply(l) => {
                Self::encode_list_reply(l, w)?;
            }
            ReplyMessage::ErrorReply(e) => {
                e.encode(w)?;
            }
        }
        Ok(())
    }

    /// Encodes a ListReply to XML.
    fn encode_list_reply<W: io::Write>(reply: &ListReply, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        for el in reply.elements() {
            let uri = el.uri().to_string();

            w.put_element(
                "list",
                Some(&[("hash", el.hash().as_ref()), ("uri", uri.as_ref())]),
                |w| w.empty(),
            )?;
        }

        Ok(())
    }

    /// Encodes a success reply to xml
    pub fn encode_success_reply<W: io::Write>(w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        w.put_element("success", None, |w| w.empty())?;

        Ok(())
    }
}

//------------ ErrorReply ----------------------------------------------------

/// This type represents the error report as described in
/// https://tools.ietf.org/html/rfc8181#section-3.5 and 3.6
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorReply {
    errors: Vec<ReportError>,
}

impl ErrorReply {
    fn decode_error_text<R: io::Read>(r: &mut XmlReader<R>) -> Result<Option<String>, MessageError> {
        Ok(Some(r.take_named_element(
            "error_text",
            |a, r| -> Result<String, MessageError> {
                a.exhausted()?;
                Ok(r.take_chars()?)
            },
        )?))
    }

    fn decode_failed_pdu<R: io::Read>(r: &mut XmlReader<R>) -> Result<Option<PublishDeltaElement>, MessageError> {
        Ok(Some(r.take_named_element(
            "failed_pdu",
            |a, r| -> Result<PublishDeltaElement, MessageError> {
                a.exhausted()?;
                match PublishDeltaXml::decode_opt(r)? {
                    Some(p) => Ok(p),
                    None => Err(MessageError::MissingContent("Expected PDU".to_string())),
                }
            },
        )?))
    }

    /// Decodes XML into an ErrorReport.
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>) -> Result<Self, MessageError> {
        let mut errors = vec![];
        loop {
            let e = r.take_opt_element(|t, mut a, r| {
                match t.name.as_ref() {
                    "report_error" => {
                        let error_code = ReportErrorCode::from_str(a.take_req("error_code")?.as_ref())?;
                        let tag = a.take_req("tag")?;
                        let mut error_text: Option<String> = None;
                        let mut failed_pdu: Option<PublishDeltaElement> = None;

                        // There may be two optional elements, the order
                        // may not be determined.
                        for _ in 0..2 {
                            match r.next_start_name() {
                                Some("error_text") => {
                                    error_text = Self::decode_error_text(r)?;
                                }
                                Some("failed_pdu") => {
                                    failed_pdu = Self::decode_failed_pdu(r)?;
                                }
                                _ => {}
                            }
                        }

                        Ok(Some(ReportError {
                            error_code,
                            tag,
                            error_text,
                            failed_pdu,
                        }))
                    }
                    _ => Err(MessageError::UnexpectedStart(t.name.clone())),
                }
            })?;
            match e {
                Some(e) => errors.push(e),
                None => break,
            }
        }
        Ok(ErrorReply { errors })
    }

    /// Encodes an ErrorReport into XML.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        for e in &self.errors {
            let error_code = format!("{}", e.error_code);
            let a = [("error_code", error_code.as_ref()), ("tag", e.tag.as_ref())];

            w.put_element("report_error", Some(&a), |w| {
                match &e.error_text {
                    None => {}
                    Some(t) => {
                        w.put_element("error_text", None, |w| w.put_text(t.as_ref()))?;
                    }
                }

                match &e.failed_pdu {
                    None => {}
                    Some(p) => {
                        w.put_element("failed_pdu", None, |w| p.encode(w))?;
                    }
                }

                w.empty()
            })?;
        }

        Ok(())
    }
}

impl ErrorReply {
    /// Creates an ErrorReplyBuilder, to which ErrorReply-s can be added.
    pub fn build() -> ErrorReplyBuilder {
        ErrorReplyBuilder::default()
    }

    /// Creates an ErrorReplyBuilder, to which an expect number of ErrorReply-s
    /// can be added. More, or less elements can be added, but suggesting the
    /// right capacity will make things more efficient as vec growth is
    /// avoided.
    pub fn build_with_capacity(n: usize) -> ErrorReplyBuilder {
        ErrorReplyBuilder::with_capacity(n)
    }
}

impl fmt::Display for ErrorReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Got error response: ")?;
        for err in &self.errors {
            match &err.error_text {
                None => write!(f, "error code: {} ", err.error_code)?,
                Some(text) => write!(f, "error code: {}, text: {} ", err.error_code, text)?,
            }
        }
        writeln!(f)?;
        Ok(())
    }
}

//------------ ErrorReplyBuilder ---------------------------------------------

#[derive(Default)]
pub struct ErrorReplyBuilder {
    errors: Vec<ReportError>,
}

impl ErrorReplyBuilder {
    fn with_capacity(n: usize) -> Self {
        ErrorReplyBuilder {
            errors: Vec::with_capacity(n),
        }
    }

    /// Adds a ReportError to the ErrorReply. Multiple allowed.
    pub fn add(&mut self, e: ReportError) {
        self.errors.push(e);
    }

    /// Creates an ErrorReply wrapped in a Message for inclusion in a publication
    /// protocol CMS message.
    pub fn build_message(self) -> Message {
        Message::ReplyMessage(ReplyMessage::ErrorReply(ErrorReply { errors: self.errors }))
    }
}

//------------ ReportError ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportError {
    error_code: ReportErrorCode,
    tag: String,
    error_text: Option<String>,
    failed_pdu: Option<PublishDeltaElement>,
}

impl ReportError {
    /// Creates an entry to include in an ErrorReply. Multiple entries may be
    /// included.
    pub fn reply(error_code: ReportErrorCode, failed_pdu: Option<PublishDeltaElement>) -> Self {
        let tag = match failed_pdu {
            None => "".to_string(),
            Some(ref pdu) => match pdu {
                PublishDeltaElement::Publish(p) => p.tag_for_xml(),
                PublishDeltaElement::Update(u) => u.tag_for_xml(),
                PublishDeltaElement::Withdraw(w) => w.tag_for_xml(),
            },
        };
        let error_text = Some(error_code.to_text());

        ReportError {
            error_code,
            tag,
            error_text,
            failed_pdu,
        }
    }
}

//------------ ReportErrorCodes ----------------------------------------------

/// The allowed error codes defined in RFC8181 section 2.5
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ReportErrorCode {
    #[display(fmt = "xml_error")]
    XmlError,

    #[display(fmt = "permission_failure")]
    PermissionFailure,

    #[display(fmt = "bad_cms_signature")]
    BadCmsSignature,

    #[display(fmt = "object_already_present")]
    ObjectAlreadyPresent,

    #[display(fmt = "no_object_present")]
    NoObjectPresent,

    #[display(fmt = "no_object_matching_hash")]
    NoObjectMatchingHash,

    #[display(fmt = "consistency_problem")]
    ConsistencyProblem,

    #[display(fmt = "other_error")]
    OtherError,
}

impl ReportErrorCode {
    /// Resolves the error type strings used in XML to the correct types.
    fn from_str(v: &str) -> Result<ReportErrorCode, MessageError> {
        match v {
            "xml_error" => Ok(ReportErrorCode::XmlError),
            "permission_failure" => Ok(ReportErrorCode::PermissionFailure),
            "bad_cms_signature" => Ok(ReportErrorCode::BadCmsSignature),
            "object_already_present" => Ok(ReportErrorCode::ObjectAlreadyPresent),
            "no_object_present" => Ok(ReportErrorCode::NoObjectPresent),
            "no_object_matching_hash" => Ok(ReportErrorCode::NoObjectMatchingHash),
            "consistency_problem" => Ok(ReportErrorCode::ConsistencyProblem),
            "other_error" => Ok(ReportErrorCode::OtherError),
            _ => Err(MessageError::InvalidErrorCode(v.to_string())),
        }
    }

    /// Provides default texts for error codes (taken from RFC).
    #[allow(dead_code)]
    fn to_text(&self) -> String {
        match self {
            ReportErrorCode::XmlError => "Encountered an XML problem.",
            ReportErrorCode::PermissionFailure => "Client does not have permission to update this URI.",
            ReportErrorCode::BadCmsSignature => "Encountered bad CMS signature.",
            ReportErrorCode::ObjectAlreadyPresent => "An object is already present at this URI, yet a \"hash\" attribute was not specified.",
            ReportErrorCode::NoObjectPresent => "There is no object present at this URI, yet a \"hash\" attribute was specified.",
            ReportErrorCode::NoObjectMatchingHash => "The \"hash\" attribute supplied does not match the \"hash\" attribute of the object at this URI.",
            ReportErrorCode::ConsistencyProblem => "Server detected an update that looks like it will cause a consistency problem (e.g., an object was deleted, but the manifest was not updated).",
            ReportErrorCode::OtherError => "Found some other issue."
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

    use crate::commons::api::{HexEncodedHash, ListElement, ListReply, Publish, PublishDeltaBuilder, Update, Withdraw};
    use crate::test::rsync;

    struct ListReplyBuilder {
        elements: Vec<ListElement>,
    }

    impl ListReplyBuilder {
        fn with_capacity(n: usize) -> ListReplyBuilder {
            ListReplyBuilder {
                elements: Vec::with_capacity(n),
            }
        }

        pub fn add(&mut self, object: &Bytes, uri: uri::Rsync) {
            let hash = HexEncodedHash::from_content(object);
            let el = ListElement::new(uri, hash);
            self.elements.push(el);
        }

        /// Creates a ListReply wrapped in a Message for inclusion in a publication
        /// protocol CMS message.
        pub fn build_message(self) -> Message {
            Message::list_reply(ListReply::new(self.elements))
        }
    }

    fn assert_re_encode_equals(object: Message, xml: &str) {
        let vec = object.encode_vec();
        let encoded_xml = str::from_utf8(&vec).unwrap();
        let object_from_encoded_xml = Message::decode(encoded_xml.as_bytes()).unwrap();
        assert_eq!(object, object_from_encoded_xml);
        assert_eq!(xml, encoded_xml);
    }

    #[test]
    fn should_parse_and_encode_multi_element_query() {
        let xml = include_str!("../../../test-resources/publication/publish.xml");
        let pm = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(pm, xml);
    }

    #[test]
    fn should_parse_and_encode_list_query() {
        let xml = include_str!("../../../test-resources/publication/list.xml");
        let l = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(l, xml);
    }

    #[test]
    fn should_parse_and_encode_success_reply() {
        let xml = include_str!("../../../test-resources/publication/success.xml");
        let s = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(s, xml);
    }

    #[test]
    fn should_parse_and_encode_list_reply() {
        let xml = include_str!("../../../test-resources/publication/list_reply.xml");
        let r = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(r, xml);
    }

    #[test]
    fn should_parse_and_encode_minimal_error() {
        let xml = include_str!("../../../test-resources/publication/report_error_minimal.xml");
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_and_encode_complex_error() {
        let xml = include_str!("../../../test-resources/publication/report_error_complex.xml");
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_empty_list_reply() {
        let xml = include_str!("../../../test-resources/publication/list_reply_empty.xml");
        let _ = Message::decode(xml.as_bytes()).unwrap();
    }

    #[test]
    fn should_create_success_reply() {
        let m = Message::success_reply();
        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../../test-resources/publication/generated/success_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_list_reply() {
        let object = Bytes::from_static(include_bytes!(
            "../../../test-resources/remote/cms_ta\
             .cer"
        ));
        let object2 = Bytes::from_static(include_bytes!(
            "../../../test-resources/remote/pdu_200\
             .der"
        ));

        let mut b = ListReplyBuilder::with_capacity(2);
        b.add(&object, rsync("rsync://host/path/cms-ta.cer"));
        b.add(&object2, rsync("rsync://host/path/pdu.200.der"));
        let m = b.build_message();

        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../../test-resources/publication/generated/list_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_error_reply() {
        let object = Bytes::from_static(include_bytes!(
            "../../../test-resources/remote/cms_ta\
             .cer"
        ));
        let object = Base64::from_content(&object);
        let publish = Publish::with_hash_tag(rsync("rsync://host/path/cms-ta.cer"), object);
        let error_pdu = PublishDeltaElement::Publish(publish);

        let mut b = ErrorReply::build_with_capacity(2);
        b.add(ReportError::reply(
            ReportErrorCode::ObjectAlreadyPresent,
            Some(error_pdu),
        ));
        b.add(ReportError::reply(ReportErrorCode::OtherError, None));
        let m = b.build_message();

        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../../test-resources/publication/generated/error_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_list_query() {
        let lq = Message::list_query();
        let vec = lq.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();
        let expected_xml = include_str!("../../../test-resources/publication/generated/list_query_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_encode_publish_delta() {
        let object = Bytes::from_static(include_bytes!(
            "../../../test-resources/remote/cms_ta\
             .cer"
        ));
        let object2 = Bytes::from_static(include_bytes!(
            "../../../test-resources/remote/pdu_200\
             .der"
        ));
        let object_hash = HexEncodedHash::from_content(&object);
        let object = Base64::from_content(&object);
        let object2 = Base64::from_content(&object2);

        let mut builder = PublishDeltaBuilder::new();

        builder.add_withdraw(Withdraw::with_hash_tag(
            rsync("rsync://host/path/cms-ta.cer"),
            object_hash.clone(),
        ));

        builder.add_publish(Publish::with_hash_tag(rsync("rsync://host/path/cms-ta.cer"), object));

        builder.add_update(Update::with_hash_tag(
            rsync("rsync://host/path/cms-ta.cer"),
            object2,
            object_hash,
        ));

        let m = Message::publish_delta_query(builder.finish());
        let vec = m.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();

        let expected_xml = include_str!("../../../test-resources/publication/generated/publish_query_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }
}
