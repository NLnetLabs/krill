//! RFC8181 Messages

use std::io;
use bytes::Bytes;
use rpki::uri;
use crate::api::requests;
use crate::api::responses;
use crate::remote::sigmsg::SignedMessage;
use crate::util::hash;
use crate::util::xml::{
    Attributes,
    AttributesError,
    XmlReader,
    XmlReaderErr,
    XmlWriter
};

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

    /// Consumes this and returns this a PublishRequest for our (json) API
    pub fn as_publish_request(self) -> requests::PublishRequest {
        match self {
            QueryMessage::ListQuery(_) => requests::PublishRequest::List,
            QueryMessage::PublishQuery(publish) =>
                requests::PublishRequest::Delta(publish.as_publish_delta())
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

//------------ SuccessReply --------------------------------------------------

/// This type represents the success reply as described in
/// https://tools.ietf.org/html/rfc8181#section-3.4
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessReply;

impl SuccessReply {
    /// Decodes a <success/> reply from XML.
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
                               -> Result<Self, MessageError> {
        r.take_named_element("success", |_, r| { r.take_empty() })?;
        Ok(SuccessReply)
    }

    /// Encodes a SuccessReply to XML.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {

        w.put_element(
            "success",
            None,
            |w| { w.empty() }
        )?;

        Ok(())
    }
}

impl SuccessReply {
    /// Builds a SuccessReply wrapped in a Message for inclusion in a
    /// publication protocol CMS object.
    pub fn build_message() -> Message {
        Message::ReplyMessage(ReplyMessage::SuccessReply(SuccessReply))
    }
}


//------------ ListElement ---------------------------------------------------

/// This type represents a single object that is published at a publication
/// server.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ListElement {
    hash: Bytes,
    uri: uri::Rsync
}

impl ListElement {
    /// Creates an element for an object to be included in a ListReply.
    pub fn reply(object: &Bytes, uri: uri::Rsync) -> Self {
        let hash = hash(object);
        ListElement { hash, uri}
    }

    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
}


//------------ ListReply -----------------------------------------------------

/// This type represents the list reply as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListReply {
    elements: Vec<ListElement>
}

impl ListReply {
    /// Decodes XML to a ListReply.
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>) -> Result<Self, MessageError> {

        let mut elements = vec![];

        loop {
            let e = r.take_opt_element(|t, mut a, _r| {
                match t.name.as_ref() {
                    "list" => {
                        let hash = a.take_req_hex("hash")?;
                        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
                        a.exhausted()?;

                        Ok(Some(ListElement{hash, uri}))
                    },
                    _ => {
                        Err(MessageError::UnexpectedStart(t.name.clone()))
                    }
                }
            })?;

            match e {
                Some(e) => elements.push(e),
                None    => break
            }
        }
        Ok(ListReply{elements})
    }

    /// Encodes a ListReply to XML.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {

        for l in &self.elements {
            let hash = hex::encode(&l.hash);
            let uri = l.uri.to_string();

            w.put_element(
                "list",
                Some(&[("hash", hash.as_ref()), ("uri", uri.as_ref())]),
                |w| { w.empty() }
            )?;
        }

        Ok(())
    }

    pub fn elements(&self) -> &Vec<ListElement> {
        &self.elements
    }

    pub fn build(reply: &responses::ListReply) -> Message {
        let mut elements: Vec<ListElement> = vec![];
        for f in reply.files() {
            elements.push(
                ListElement {
                    uri: f.uri().clone(),
                    hash: f.hash().clone()
                }
            );
        }

        Message::ReplyMessage(
            ReplyMessage::ListReply(
                ListReply { elements }
            )
        )
    }
}


//------------ ErrorReply ----------------------------------------------------

/// This type represents the error report as described in
/// https://tools.ietf.org/html/rfc8181#section-3.5 and 3.6
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorReply {
    errors: Vec<ReportError>
}

impl ErrorReply {
    fn decode_error_text<R: io::Read>(r: &mut XmlReader<R>)
                                      -> Result<Option<String>, MessageError> {

        Ok(Some(r.take_named_element(
            "error_text",
            |a, r| -> Result<String, MessageError> {
                a.exhausted()?;
                Ok(r.take_chars()?)
            }
        )?))
    }

    fn decode_failed_pdu<R: io::Read>(r: &mut XmlReader<R>)
                                      -> Result<Option<PublishElement>, MessageError> {

        Ok(Some(r.take_named_element(
            "failed_pdu",
            |a, r| -> Result<PublishElement, MessageError>{
                a.exhausted()?;
                match PublishElement::decode_opt(r)? {
                    Some(p) => Ok(p),
                    None => {
                        Err(MessageError::MissingContent(
                            "Expected PDU".to_string()))
                    }
                }
            }
        )?))
    }

    /// Decodes XML into an ErrorReport.
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
                               -> Result<Self, MessageError> {

        let mut errors = vec![];
        loop {
            let e = r.take_opt_element(|t, mut a, r| {
                match t.name.as_ref() {
                    "report_error" => {
                        let error_code = ReportErrorCode::from_str(
                            a.take_req("error_code")?.as_ref())?;
                        let tag = a.take_req("tag")?;
                        let mut error_text: Option<String> = None;
                        let mut failed_pdu: Option<PublishElement> = None;

                        // There may be two optional elements, the order
                        // may not be determined.
                        for _ in 0..2 {
                            match r.next_start_name() {
                                Some("error_text") => {
                                    error_text = Self::decode_error_text(r)?;
                                },
                                Some("failed_pdu") => {
                                    failed_pdu = Self::decode_failed_pdu(r)?;
                                },
                                _ => { }
                            }
                        }

                        Ok(Some(
                            ReportError{
                                error_code,
                                tag,
                                error_text,
                                failed_pdu
                            }))
                    },
                    _ => {
                        Err(MessageError::UnexpectedStart(t.name.clone()))
                    }
                }
            })?;
            match e {
                Some(e) => errors.push(e),
                None => break
            }
        }
        Ok(ErrorReply{errors})
    }

    /// Encodes an ErrorReport into XML.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {

        for e in &self.errors {

            let error_code = format!("{}", e.error_code);
            let a = [
                ("error_code", error_code.as_ref()),
                ("tag", e.tag.as_ref())
            ];

            w.put_element(
                "report_error",
                Some(&a),
                |w| {

                    match &e.error_text {
                        None => {},
                        Some(t) => {
                            w.put_element(
                                "error_text",
                                None,
                                |w| { w.put_text(t.as_ref())}
                            )?;
                        }
                    }

                    match &e.failed_pdu {
                        None => {},
                        Some(p) => {
                            w.put_element(
                                "failed_pdu",
                                None,
                                |w| { p.encode(w) }
                            )?;
                        }
                    }

                    w.empty()
                }
            )?;
        }

        Ok(())
    }
}

impl ErrorReply {
    /// Creates an ErrorReplyBuilder, to which ErrorReply-s can be added.
    pub fn build() -> ErrorReplyBuilder {
        ErrorReplyBuilder::new()
    }

    /// Creates an ErrorReplyBuilder, to which an expect number of ErrorReply-s
    /// can be added. More, or less elements can be added, but suggesting the
    /// right capacity will make things more efficient as vec growth is
    /// avoided.
    pub fn build_with_capacity(n: usize) -> ErrorReplyBuilder {
        ErrorReplyBuilder::with_capacity(n)
    }
}


//------------ ErrorReplyBuilder ---------------------------------------------

pub struct ErrorReplyBuilder {
    errors: Vec<ReportError>
}

impl ErrorReplyBuilder {
    fn new() -> Self {
        ErrorReplyBuilder { errors: Vec::new() }
    }

    fn with_capacity(n: usize) -> Self {
        ErrorReplyBuilder { errors: Vec::with_capacity(n) }
    }

    /// Adds a ReportError to the ErrorReply. Multiple allowed.
    pub fn add(&mut self, e: ReportError) {
        self.errors.push(e);
    }

    /// Creates an ErrorReply wrapped in a Message for inclusion in a publication
    /// protocol CMS message.
    pub fn build_message(self) -> Message {
        Message::ReplyMessage(
            ReplyMessage::ErrorReply(
                ErrorReply { errors: self.errors }
            )
        )
    }
}


//------------ ReportError ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportError {
    error_code: ReportErrorCode,
    tag: String,
    error_text: Option<String>,
    failed_pdu: Option<PublishElement>
}

impl ReportError {
    /// Creates an entry to include in an ErrorReply. Multiple entries may be
    /// included.
    pub fn reply(
        error_code: ReportErrorCode,
        failed_pdu: Option<PublishElement>
    ) -> Self {
        let tag = match failed_pdu {
            None => "".to_string(),
            Some(ref pdu) => match pdu {
                PublishElement::Publish(p)  => p.tag().clone(),
                PublishElement::Update(u)   => u.tag().clone(),
                PublishElement::Withdraw(w) => w.tag().clone()
            }
        };
        let error_text = Some(error_code.to_text());

        ReportError {
            error_code, tag, error_text, failed_pdu
        }
    }
}


//------------ ReportErrorCodes ----------------------------------------------

/// The allowed error codes defined in RFC8181 section 2.5
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ReportErrorCode {
    #[display(fmt="xml_error")]
    XmlError,

    #[display(fmt="permission_failure")]
    PermissionFailure,

    #[display(fmt="bad_cms_signature")]
    BadCmsSignature,

    #[display(fmt="object_already_present")]
    ObjectAlreadyPresent,

    #[display(fmt="no_object_present")]
    NoObjectPresent,

    #[display(fmt="no_object_matching_hash")]
    NoObjectMatchingHash,

    #[display(fmt="consistency_problem")]
    ConsistencyProblem,

    #[display(fmt="other_error")]
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
            _ => Err(MessageError::InvalidErrorCode(v.to_string()))
        }
    }

    /// Provides default texts for error codes.
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


//------------ ListQuery -----------------------------------------------------

/// Type representing the list query as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListQuery;

impl ListQuery {
    /// Decodes a ListQuery from XML.
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
                               -> Result<Self, MessageError> {
        r.take_named_element("list", |_, r| { r.take_empty() })?;
        Ok(ListQuery)
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {
        w.put_element(
            "list",
            None,
            |w| { w.empty() }
        )?;

        Ok(())
    }

    /// Creates a ListQuery inside a full Message enum type.
    ///
    /// The `Message` type is used because it's this outer type that needs
    /// to be encoded and included in protocol messages.
    pub fn build_message() -> Message {
        Message::QueryMessage(QueryMessage::ListQuery(ListQuery))
    }
}


//------------ PublishQuery --------------------------------------------------

/// Type representing a multi element query as described in
/// https://tools.ietf.org/html/rfc8181#section-3.7
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishQuery {
    elements: Vec<PublishElement>
}

/// # Access
///
impl PublishQuery {
    pub fn elements(&self) -> &Vec<PublishElement> {
        &self.elements
    }
}

impl PublishQuery {
    /// Decodes a <publish> element from XML, producing either a simple, new,
    /// Publish element, or an Update - wrapped in a PublishElement.
    fn decode_publish<R: io::Read>(
        a: &mut Attributes,
        r: &mut XmlReader<R>
    ) -> Result<PublishElement, MessageError> {

        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;
        let object = r.take_bytes_characters()?;

        let res = match a.take_opt_hex("hash") {
            Some(hash) => {
                Ok(PublishElement::Update(Update{
                    hash, tag, uri, object
                }))
            },
            None => Ok(PublishElement::Publish( Publish { tag, uri, object }))
        };

        a.exhausted()?;
        res
    }

    /// Decodes a <withdraw/> XML element.
    fn decode_withdraw(a: &mut Attributes)
                       -> Result<PublishElement, MessageError> {

        let hash = a.take_req_hex("hash")?;
        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;

        a.exhausted()?;

        Ok(PublishElement::Withdraw(Withdraw {
            hash,
            tag,
            uri
        }))
    }


    /// Decodes a query XML structure. Expects that the outer <msg> element
    /// is processed by PublicationMessage::decode
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
                               -> Result<Self, MessageError> {

        let mut elements = vec![];

        loop {
            let e = PublishElement::decode_opt(r)?;
            match e {
                Some(qe) => elements.push(qe),
                None => break
            }
        }
        Ok(PublishQuery {elements})
    }

    /// Encodes an existing multi-element PublishQuery to XML.
    /// Note that a PublishQuery should be encoded through the
    /// PublicationMessage::encode function.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {

        for e in &self.elements {
            e.encode(w)?;
        }
        Ok(())
    }

    pub fn as_publish_delta(self) -> requests::PublishDelta {
        let mut publishes: Vec<requests::Publish> = vec![];
        let mut updates: Vec<requests::Update> = vec![];
        let mut withdraws: Vec<requests::Withdraw> = vec![];

        for e in self.elements {
            match e {
                PublishElement::Publish(p) => {
                    publishes.push(p.as_requests_publish());
                },
                PublishElement::Update(u) => {
                    updates.push(u.as_requests_update());
                },
                PublishElement::Withdraw(w) => {
                    withdraws.push(w.as_requests_withdraw());
                },
            }
        }

        requests::PublishDelta::new(publishes, updates, withdraws)
    }
}

impl PublishQuery {
    /// Creates a PublishQueryBuilder, to which PublishElements can be added.
    pub fn build() -> PublishQueryBuilder {
        PublishQueryBuilder::new()
    }

    /// Creates a PublishQueryBuilder, to which an expect number of
    /// PublishElements can be added. More, or less elements can be added, but
    /// suggesting the right capacity will make things more efficient as vec
    /// growth is avoided.
    pub fn build_with_capacity(n: usize) -> PublishQueryBuilder {
        PublishQueryBuilder::with_capacity(n)
    }
}


//------------ PublishElement ------------------------------------------------

/// This type represents the three types of requests that can be included
/// in a multi-element query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishElement {
    Publish(Publish),
    Update(Update),
    Withdraw(Withdraw)
}

impl PublishElement {
    /// Decodes from an XML input. Used for processing a list of elements.
    /// Will return None when there is no (more) applicable element.
    pub fn decode_opt<R: io::Read>(r: &mut XmlReader<R>)
                                   -> Result<Option<Self>, MessageError> {

        r.take_opt_element(|t, mut a, r| {
            match t.name.as_ref() {
                "publish"  => {
                    Ok(Some(PublishQuery::decode_publish(&mut a, r)?)) },
                "withdraw" => {
                    Ok(Some(PublishQuery::decode_withdraw(&mut a)?)) },
                _ => {
                    Err(MessageError::UnexpectedStart(t.name.clone()))
                }
            }
        })
    }

    /// Encodes the contained Publish, Update or Withdraw element to XML.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                                -> Result<(), io::Error> {

        match self {
            PublishElement::Publish(p)   => { p.encode(w)?; },
            PublishElement::Update(u)    => { u.encode(w)?; },
            PublishElement::Withdraw(wi) => { wi.encode(w)?; }
        }
        Ok(())
    }
}


//------------ Update -------------------------------------------------------

/// Represents a publish element, that updates an existing object
/// https://tools.ietf.org/html/rfc8181#section-3.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    hash: Bytes,
    tag: String,
    uri: uri::Rsync,
    object: Bytes
}

/// Accessors
impl Update {
    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn tag(&self) -> &String {
        &self.tag
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn object(&self) -> &Bytes {
        &self.object
    }
}

impl Update {
    /// Encodes this into an XML element.
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                            -> Result<(), io::Error> {

        let uri = self.uri.to_string();
        let enc = hex::encode(&self.hash);

        let a = [
            ("tag", self.tag.as_ref()),
            ("hash", enc.as_ref()),
            ("uri", uri.as_ref())
        ];


        w.put_element(
            "publish",
            Some(&a),
            |w| {
                w.put_blob(&self.object)
            }
        )
    }

    /// Produces a PublishElement for inclusion in a PublishRequest.
    pub fn publish(old: &Bytes, new: &Bytes, uri: uri::Rsync) -> PublishElement {
        let tag  = hex::encode(hash(new));
        let hash = hash(old);
        PublishElement::Update(Update { hash, tag, uri, object: new.clone() })
    }

    pub fn as_requests_update(self) -> requests::Update {
        requests::Update::new(self.tag, self.uri, self.object,self.hash)
    }
}


//------------ Publish -------------------------------------------------------

/// Represents a publish element, that does not update any existing object
/// https://tools.ietf.org/html/rfc8181#section-3.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publish {
    tag: String,
    uri: uri::Rsync,
    object: Bytes
}

/// Accessors
impl Publish {
    pub fn tag(&self) -> &String {
        &self.tag
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn object(&self) -> &Bytes {
        &self.object
    }
}

impl Publish {
    /// Encodes this into an XML element.
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                            -> Result<(), io::Error> {

        let uri =  self.uri.to_string();

        let a = [
            ("tag", self.tag.as_ref()),
            ("uri", uri.as_ref()),
        ];

        w.put_element(
            "publish",
            Some(&a),
            |w| {
                w.put_blob(&self.object)
            }
        )
    }

    /// Produces a PublishElement for inclusion in a PublishRequest.
    pub fn publish(object: &Bytes, uri: uri::Rsync) -> PublishElement {
        let hash = hash(object);
        let tag  = hex::encode(&hash);
        PublishElement::Publish(Publish { tag, uri, object: object.clone() })
    }

    pub fn as_requests_publish(self) -> requests::Publish {
        requests::Publish::new(self.tag, self.uri, self.object)
    }
}


//------------ Withdraw ------------------------------------------------------

/// Represents a withdraw element that removes an object from the repository
/// https://tools.ietf.org/html/rfc8181#section-3.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdraw {
    hash: Bytes,
    tag: String,
    uri: uri::Rsync
}

/// Accessors
impl Withdraw {
    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn tag(&self) -> &String {
        &self.tag
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
}

impl Withdraw {
    /// Encodes this into an XML element.
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
                            -> Result<(), io::Error> {

        let uri =  self.uri.to_string();
        let enc = hex::encode(self.hash.clone());

        let a = [
            ("hash", enc.as_ref()),
            ("tag", self.tag.as_ref()),
            ("uri", uri.as_ref())
        ];

        w.put_element(
            "withdraw",
            Some(&a),
            |w| {
                w.empty()
            }
        )
    }

    /// Produces a PublishElement for inclusion in a PublishRequest.
    pub fn for_known_file(object: &Bytes, uri: uri::Rsync) -> PublishElement {
        let hash = hash(object);
        let tag  = hex::encode(&hash);
        PublishElement::Withdraw(Withdraw { hash, tag, uri })
    }

    /// Produces a PublishElement for withdrawing an existing ListElement
    /// as part of a PublishRequest.
    pub fn publish(list_element: &ListElement) -> PublishElement {
        let tag  = hex::encode(&list_element.hash());
        PublishElement::Withdraw(Withdraw {
            hash: list_element.hash().clone(),
            tag,
            uri: list_element.uri().clone()
        })
    }

    pub fn as_requests_withdraw(self) -> requests::Withdraw {
        requests::Withdraw::new(self.tag, self.uri, self.hash)
    }

}

/// This type builds a PublishQuery wrapped in a Message for inclusion in a
/// publication protocol message.
pub struct PublishQueryBuilder {
    elements: Vec<PublishElement>
}

impl PublishQueryBuilder {
    /// Exposed through PublishQuery::build()
    fn new() -> Self {
        PublishQueryBuilder { elements: Vec::new() }
    }

    /// Exposed through PublishQuery::build_with_capacity()
    fn with_capacity(n: usize) -> Self {
        PublishQueryBuilder { elements: Vec::with_capacity(n)}
    }

    /// Add a PublishElement, i.e. Publish, Withdraw or Update to this
    /// PublishQuery. See: Publish::publish(), Withdraw::publish() and
    /// Update::publish() to produce PublishElements.
    pub fn add(&mut self, e: PublishElement) {
        self.elements.push(e)
    }

    /// Produces a Message containing the PublishQuery
    pub fn build_message(self) -> Message {
        Message::QueryMessage(
            QueryMessage::PublishQuery(
                PublishQuery { elements: self.elements }
            )
        )
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
    use rpki::uri::Rsync;

    //------------ ListReplyBuilder ----------------------------------------------

    /// This type is useful for testing
    pub struct ListReplyBuilder {
        elements: Vec<ListElement>
    }

    impl ListReplyBuilder {

        fn with_capacity(n: usize) -> ListReplyBuilder {
            ListReplyBuilder { elements: Vec::with_capacity(n) }
        }

        pub fn add(&mut self, e: ListElement) {
            self.elements.push(e);
        }

        /// Creates a ListReply wrapped in a Message for inclusion in a publication
        /// protocol CMS message.
        pub fn build_message(self) -> Message {
            Message::ReplyMessage(
                ReplyMessage::ListReply(
                    ListReply { elements: self.elements }
                )
            )
        }
    }

    fn rsync_uri(s: &str) -> Rsync {
        Rsync::from_str(s).unwrap()
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
        let xml = include_str!("../../test/publication/publish.xml");
        let pm = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(pm, xml);
    }

    #[test]
    fn should_parse_and_encode_list_query() {
        let xml = include_str!("../../test/publication/list.xml");
        let l = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(l, xml);
    }

    #[test]
    fn should_parse_and_encode_success_reply() {
        let xml = include_str!("../../test/publication/success.xml");
        let s = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(s, xml);
    }

    #[test]
    fn should_parse_and_encode_list_reply() {
        let xml = include_str!("../../test/publication/list_reply.xml");
        let r = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(r, xml);
    }

    #[test]
    fn should_parse_and_encode_minimal_error() {
        let xml = include_str!("../../test/publication/report_error_minimal.xml");
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_and_encode_complex_error() {
        let xml = include_str!("../../test/publication/report_error_complex.xml");
        let e = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(e, xml);
    }

    #[test]
    fn should_parse_empty_list_reply() {
        let xml = include_str!("../../test/publication/list_reply_empty.xml");
        let _ = Message::decode(xml.as_bytes()).unwrap();
    }

    #[test]
    fn should_create_success_reply() {
        let m = SuccessReply::build_message();
        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/success_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_list_reply() {
        let object = Bytes::from_static(include_bytes!("../../test/remote/cms_ta.cer"));
        let object2 = Bytes::from_static(include_bytes!("../../test/remote/pdu_200.der"));
        let mut b = ListReplyBuilder::with_capacity(2);
        b.add(ListElement::reply(
            &object, rsync_uri("rsync://host/path/cms-ta.cer")
        ));
        b.add(ListElement::reply(
            &object2, rsync_uri("rsync://host/path/pdu.200.der")
        ));
        let m = b.build_message();

        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/list_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_error_reply() {
        let object = Bytes::from_static(include_bytes!("../../test/remote/cms_ta.cer"));
        let error_pdu = Publish::publish(
            &object, rsync_uri("rsync://host/path/cms-ta.cer")
        );

        let mut b = ErrorReply::build_with_capacity(2);
        b.add(ReportError::reply(
            ReportErrorCode::ObjectAlreadyPresent, Some(error_pdu))
        );
        b.add(ReportError::reply(
            ReportErrorCode::OtherError, None)
        );
        let m = b.build_message();

        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/error_reply_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_list_query() {
        let lq = ListQuery::build_message();
        let vec = lq.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/list_query_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_publish_query() {
        let object = Bytes::from_static(include_bytes!("../../test/remote/cms_ta.cer"));
        let object2 = Bytes::from_static(include_bytes!("../../test/remote/pdu_200.der"));
        let w = Withdraw::for_known_file(
            &object, rsync_uri("rsync://host/path/cms-ta.cer")
        );
        let p = Publish::publish(
            &object, rsync_uri("rsync://host/path/cms-ta.cer")
        );
        let u = Update::publish(
            &object, &object2, rsync_uri("rsync://host/path/cms-ta.cer")
        );

        let mut b = PublishQuery::build_with_capacity(3);
        b.add(w);
        b.add(p);
        b.add(u);
        let m = b.build_message();
        let vec = m.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/publish_query_result.xml");

        assert_eq!(produced_xml, expected_xml);
    }
}