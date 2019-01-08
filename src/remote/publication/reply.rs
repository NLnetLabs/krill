//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.4 and further

//------------ SuccessReply --------------------------------------------------

use std::io;
use bytes::Bytes;
use hex;
use rpki::uri;
use crate::remote::publication::hash;
use crate::remote::publication::pubmsg::{Message, MessageError, ReplyMessage};
use crate::remote::publication::query::PublishElement;
use crate::util::xml::{XmlReader, XmlWriter};


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


//------------ ListReply -----------------------------------------------------

/// This type represents the list reply as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListReply {
    elements: Vec<ListElement>
}

/// This type represents a single object that is published at a publication
/// server.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ListElement {
    hash: Bytes,
    uri: uri::Rsync
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

    /// Creates a ListReplyBuilder, to which ListElements can be added.
    pub fn build() -> ListReplyBuilder {
        ListReplyBuilder::new()
    }

    /// Creates a ListReplyBuilder, to which an expect number of ListElements
    /// can be added. More, or less elements can be added, but suggesting the
    /// right capacity will make things more efficient as vec growth is
    /// avoided.
    pub fn build_with_capacity(n: usize) -> ListReplyBuilder {
        ListReplyBuilder::with_capacity(n)
    }

    pub fn elements(&self) -> &Vec<ListElement> {
        &self.elements
    }
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


pub struct ListReplyBuilder {
    elements: Vec<ListElement>
}

impl ListReplyBuilder {
    fn new() -> ListReplyBuilder {
        ListReplyBuilder { elements: Vec::new() }
    }

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

    pub fn len(&self) -> usize {
        self.elements.len()
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
#[derive(Debug, Clone, Eq, Fail, PartialEq)]
pub enum ReportErrorCode {

    #[fail(display="xml_error")]
    XmlError,

    #[fail(display="permission_failure")]
    PermissionFailure,

    #[fail(display="bad_cms_signature")]
    BadCmsSignature,

    #[fail(display="object_already_present")]
    ObjectAlreadyPresent,

    #[fail(display="no_object_present")]
    NoObjectPresent,

    #[fail(display="no_object_matching_hash")]
    NoObjectMatchingHash,

    #[fail(display="consistency_problem")]
    ConsistencyProblem,

    #[fail(display="other_error")]
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


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;
    use rpki::uri::Rsync;
    use crate::remote::publication::query::Publish;

    fn rsync_uri(s: &str) -> Rsync {
        Rsync::from_str(s).unwrap()
    }

    #[test]
    fn should_create_success_reply() {
        let m = SuccessReply::build_message();
        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!(
            "../../../test/publication/generated/success_reply_result.xml"
        );

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_list_reply() {
        let object = Bytes::from_static(include_bytes!(
                "../../../test/remote/cms_ta.cer"
        ));
        let object2 = Bytes::from_static(include_bytes!(
                "../../../test/remote/pdu_200.der"
        ));
        let mut b = ListReply::build_with_capacity(2);
        b.add(ListElement::reply(
            &object, rsync_uri("rsync://host/path/cms-ta.cer")
        ));
        b.add(ListElement::reply(
            &object2, rsync_uri("rsync://host/path/pdu.200.der")
        ));
        let m = b.build_message();

        let v = m.encode_vec();
        let produced_xml = str::from_utf8(&v).unwrap();
        let expected_xml = include_str!(
            "../../../test/publication/generated/list_reply_result.xml"
        );

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_error_reply() {
        let object = Bytes::from_static(include_bytes!(
            "../../../test/remote/cms_ta.cer"
        ));
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
        let expected_xml = include_str!(
            "../../../test/publication/generated/error_reply_result.xml"
        );

        assert_eq!(produced_xml, expected_xml);
    }
}
