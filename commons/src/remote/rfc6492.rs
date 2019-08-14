use std::convert::TryFrom;
use std::str::FromStr;
use std::{fmt, io};

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::export::fmt::Display;

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::csr::Csr;
use rpki::uri;
use rpki::x509::Time;

use crate::api::admin::Handle;
use crate::api::ca::{IssuedCert, ResSetErr, ResourceSet};
use crate::api::{
    EntitlementClass, Entitlements, IssuanceRequest, IssuanceResponse, RequestResourceLimit,
    RevocationRequest, RevocationResponse, SigningCert,
};
use crate::remote::sigmsg::SignedMessage;
use crate::rpki::resources::{AsBlocks, IpBlocks};
use crate::util::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};

//------------ Consts --------------------------------------------------------

const VERSION: &str = "1";
const NS: &str = "http://www.apnic.net/specs/rescerts/up-down/";

pub const CONTENT_TYPE: &str = "application/rpki-updown";

const TYPE_LIST_QRY: &str = "list";
const TYPE_LIST_RES: &str = "list_response";
const TYPE_ISSUE_QRY: &str = "issue";
const TYPE_ISSUE_RES: &str = "issue_response";
const TYPE_REVOKE_QRY: &str = "revoke";
const TYPE_REVOKE_RES: &str = "revoke_response";
const TYPE_ERROR_RES: &str = "error_response";

pub type Sender = String;
pub type Recipient = String;

//------------ Message -------------------------------------------------------

/// This type represents all Provisioning Messages defined in RFC6492.
///
/// Note this is all very similar to, yet subtly different from, the
/// Publication Messages defined in RFC8181.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    sender: Sender,
    recipient: Recipient,
    content: Content,
}

/// # Data Access
///
impl Message {
    pub fn unwrap(self) -> (Sender, Recipient, Content) {
        (self.sender, self.recipient, self.content)
    }

    pub fn sender_handle(&self) -> Handle {
        Handle::from(self.sender.as_str())
    }
    pub fn sender(&self) -> &str {
        &self.sender
    }
    pub fn recipient(&self) -> &str {
        &self.recipient
    }
    pub fn content(&self) -> &Content {
        &self.content
    }
}

/// # Convenience accessors
///
impl Message {
    pub fn into_reply(self) -> Result<Res, Error> {
        match self.content {
            Content::Res(res) => Ok(res),
            Content::Qry(_) => Err(Error::WrongMessageType),
        }
    }
}

/// # Constructing
///
impl Message {
    pub fn list(sender: String, recipient: String) -> Self {
        let content = Content::Qry(Qry::List);
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn list_response(sender: String, recipient: String, entitlements: Entitlements) -> Self {
        let content = Content::Res(Res::List(entitlements));
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn issue(sender: String, recipient: String, issuance_request: IssuanceRequest) -> Self {
        let content = Content::Qry(Qry::Issue(issuance_request));
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn issue_response(
        sender: String,
        recipient: String,
        issuance_response: IssuanceResponse,
    ) -> Self {
        let content = Content::Res(Res::Issue(issuance_response));
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn revoke(sender: String, recipient: String, revocation: RevocationRequest) -> Self {
        let content = Content::Qry(Qry::Revoke(revocation));
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn revoke_response(
        sender: String,
        recipient: String,
        revocation: RevocationResponse,
    ) -> Self {
        let content = Content::Res(Res::Revoke(revocation));
        Message {
            sender,
            recipient,
            content,
        }
    }

    pub fn not_performed_response(
        sender: String,
        recipient: String,
        err: NotPerformedResponse,
    ) -> Result<Self, Error> {
        let content = Content::Res(Res::NotPerformed(err));
        Ok(Message {
            sender,
            recipient,
            content,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Content {
    Qry(Qry),
    Res(Res),
}

impl Content {
    fn msg_type(&self) -> &str {
        match self {
            Content::Qry(q) => q.msg_type(),
            Content::Res(r) => r.msg_type(),
        }
    }
}

/// # Decoding and Encoding
///
impl Message {
    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        XmlReader::decode(reader, |r| {
            r.take_named_element("message", |mut a, r| {
                match a.take_req("version")?.as_ref() {
                    VERSION => {}
                    _ => return Err(Error::InvalidVersion),
                }
                let sender = a.take_req("sender")?;
                let recipient = a.take_req("recipient")?;
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                let content = match msg_type.as_ref() {
                    TYPE_LIST_QRY | TYPE_ISSUE_QRY | TYPE_REVOKE_QRY => {
                        Ok(Content::Qry(Qry::decode(&msg_type, r)?))
                    }
                    TYPE_LIST_RES | TYPE_ISSUE_RES | TYPE_REVOKE_RES | TYPE_ERROR_RES => {
                        Ok(Content::Res(Res::decode(&msg_type, r)?))
                    }
                    _ => Err(Error::UnknownMessageType),
                }?;

                Ok(Message {
                    sender,
                    recipient,
                    content,
                })
            })
        })
    }

    /// Parses the content of a SignedMessage as a Message.
    pub fn from_signed_message(msg: &SignedMessage) -> Result<Message, Error> {
        Message::decode(msg.content().to_bytes().as_ref())
    }

    /// Encode into XML
    pub fn encode<W: io::Write>(&self, target: &mut XmlWriter<W>) -> Result<(), io::Error> {
        let msg_type = self.content.msg_type();

        let attrs = [
            ("xmlns", NS),
            ("version", VERSION),
            ("sender", &self.sender),
            ("recipient", &self.recipient),
            ("type", msg_type),
        ];

        target.put_element("message", Some(&attrs), |w| match &self.content {
            Content::Qry(q) => q.encode(w),
            Content::Res(r) => r.encode(w),
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
}

//------------ Query ---------------------------------------------------------

/// This type defines the various RFC6492 queries.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Qry {
    List,
    Issue(IssuanceRequest),
    Revoke(RevocationRequest),
}

/// # Data Access
///
impl Qry {
    fn msg_type(&self) -> &str {
        match self {
            Qry::List => TYPE_LIST_QRY,
            Qry::Issue(_) => TYPE_ISSUE_QRY,
            Qry::Revoke(_) => TYPE_REVOKE_QRY,
        }
    }
}

/// # Decoding
///
impl Qry {
    fn decode<R>(msg_type: &str, r: &mut XmlReader<R>) -> Result<Self, Error>
    where
        R: io::Read,
    {
        match msg_type {
            TYPE_LIST_QRY => Ok(Qry::List),
            TYPE_ISSUE_QRY => Ok(Qry::Issue(Self::decode_issue(r)?)),
            TYPE_REVOKE_QRY => Ok(Qry::Revoke(Self::decode_revoke(r)?)),
            _ => Err(Error::UnknownMessageType),
        }
    }

    fn decode_revoke<R>(r: &mut XmlReader<R>) -> Result<RevocationRequest, Error>
    where
        R: io::Read,
    {
        r.take_named_element("key", |mut a, _r| {
            let class_name = a.take_req("class_name")?;
            let ski = a.take_req("ski")?;
            let ski_bytes = base64::decode_config(&ski, base64::URL_SAFE_NO_PAD)
                .map_err(|_| Error::InvalidSki)?;

            a.exhausted()?;

            let ski =
                KeyIdentifier::try_from(ski_bytes.as_slice()).map_err(|_| Error::InvalidSki)?;
            Ok(RevocationRequest::new(class_name.to_string(), ski))
        })
    }

    fn decode_issue<R>(r: &mut XmlReader<R>) -> Result<IssuanceRequest, Error>
    where
        R: io::Read,
    {
        r.take_named_element("request", |mut a, r| {
            let class_name = a.take_req("class_name")?;
            let mut limit = RequestResourceLimit::default();

            if let Some(asn) = a.take_opt("req_resource_set_as") {
                let asn = AsBlocks::from_str(&asn).map_err(Error::inr_syntax)?;
                limit.with_asn(asn);
            }

            if let Some(ipv4) = a.take_opt("req_resource_set_ipv4") {
                let ipv4 = IpBlocks::from_str(&ipv4).map_err(Error::inr_syntax)?;
                limit.with_ipv4(ipv4);
            }

            if let Some(ipv6) = a.take_opt("req_resource_set_ipv6") {
                let ipv6 = IpBlocks::from_str(&ipv6).map_err(Error::inr_syntax)?;
                limit.with_ipv6(ipv6);
            }

            let csr_bytes = r.take_bytes_std()?;
            let csr = Csr::decode(csr_bytes).map_err(|_| Error::InvalidCsr)?;

            Ok(IssuanceRequest::new(class_name.to_string(), limit, csr))
        })
    }
}

/// # Encoding
///
impl Qry {
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        match self {
            Qry::List => w.empty(),
            Qry::Issue(issue_req) => Self::encode_issue(issue_req, w),
            Qry::Revoke(rev) => Self::encode_revoke(rev, w),
        }
    }

    fn encode_issue<W: io::Write>(
        issue: &IssuanceRequest,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        let class_name = issue.class_name();
        let limit = issue.limit();
        let csr = issue.csr().to_captured().into_bytes();

        // TODO: Use a better xml library so we don't have to do
        //       super-messy allocations. Probably roll our own,
        //       at least for composing.
        let mut attrs_strings = vec![];
        if let Some(asn) = limit.asn() {
            attrs_strings.push(("req_resource_set_as", asn.to_string()));
        }
        if let Some(v4) = limit.v4() {
            attrs_strings.push(("req_resource_set_ipv4", v4.as_v4().to_string()));
        }
        if let Some(v6) = limit.v6() {
            attrs_strings.push(("req_resource_set_ipv6", v6.as_v6().to_string()));
        }

        let mut attrs_str = vec![];
        attrs_str.push(("class_name", class_name));
        for (k, v) in &attrs_strings {
            attrs_str.push((k, v.as_str()));
        }

        w.put_element("request", Some(attrs_str.as_slice()), |w| {
            w.put_base64_std(&csr)
        })
    }

    fn encode_revoke<W: io::Write>(
        rev: &RevocationRequest,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        let bytes = rev.key().as_slice();
        let encoded = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
        let att = [("class_name", rev.class_name()), ("ski", encoded.as_str())];
        w.put_element("key", Some(&att), |w| w.empty())
    }
}

//------------ Res -----------------------------------------------------------

/// This type defines the various RFC6492 queries.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Res {
    List(Entitlements),
    Issue(IssuanceResponse),
    Revoke(RevocationResponse),
    NotPerformed(NotPerformedResponse),
}

/// # Data Access
///
impl Res {
    fn msg_type(&self) -> &str {
        match self {
            Res::List(_) => TYPE_LIST_RES,
            Res::Issue(_) => TYPE_ISSUE_RES,
            Res::Revoke(_) => TYPE_REVOKE_RES,
            Res::NotPerformed(_) => TYPE_ERROR_RES,
        }
    }
}

/// Decoding
///
impl Res {
    fn decode<R>(msg_type: &str, r: &mut XmlReader<R>) -> Result<Self, Error>
    where
        R: io::Read,
    {
        match msg_type {
            TYPE_LIST_RES => {
                let entitlements = Self::decode_entitlements(r)?;
                Ok(Res::List(entitlements))
            }
            TYPE_ISSUE_RES => {
                let issuance_response = Self::decode_issue_response(r)?;
                Ok(Res::Issue(issuance_response))
            }
            TYPE_REVOKE_RES => {
                let request = Qry::decode_revoke(r)?;
                Ok(Res::Revoke(request.into()))
            }
            TYPE_ERROR_RES => {
                let err = Self::decode_error_response(r)?;
                Ok(Res::NotPerformed(err))
            }
            _ => Err(Error::UnknownMessageType),
        }
    }

    fn decode_issue_response<R>(r: &mut XmlReader<R>) -> Result<IssuanceResponse, Error>
    where
        R: io::Read,
    {
        r.take_named_element("class", |mut a, r| {
            let name = a.take_req("class_name")?;
            let cert_url = uri::Rsync::from_str(&a.take_req("cert_url")?)?;

            let asn = a.take_req("resource_set_as")?;
            let v4 = a.take_req("resource_set_ipv4")?;
            let v6 = a.take_req("resource_set_ipv6")?;
            let resource_set = ResourceSet::from_strs(&asn, &v4, &v6)?;

            let not_after = a.take_req("resource_set_notafter")?;
            let not_after = DateTime::<Utc>::from_str(&not_after)?;
            let not_after = Time::new(not_after);

            a.exhausted()?;

            let issued = Self::decode_issued_cert(r)?;

            let cert = r.take_named_element("issuer", |a, r| {
                a.exhausted()?;
                Self::decode_cert(r)
            })?;

            let issuer = SigningCert::new(cert_url, cert);

            Ok(IssuanceResponse::new(
                name,
                issuer,
                resource_set,
                not_after,
                issued,
            ))
        })
    }

    fn decode_entitlements<R>(r: &mut XmlReader<R>) -> Result<Entitlements, Error>
    where
        R: io::Read,
    {
        let mut classes = vec![];
        while let Some(class) = Self::decode_entitlement_class(r)? {
            classes.push(class);
        }
        Ok(Entitlements::new(classes))
    }

    fn decode_entitlement_class<R>(r: &mut XmlReader<R>) -> Result<Option<EntitlementClass>, Error>
    where
        R: io::Read,
    {
        r.take_opt_element(|t, mut a, r| match t.name.as_ref() {
            "class" => {
                let name = a.take_req("class_name")?;
                let cert_url = uri::Rsync::from_str(&a.take_req("cert_url")?)?;

                let asn = a.take_req("resource_set_as")?;
                let v4 = a.take_req("resource_set_ipv4")?;
                let v6 = a.take_req("resource_set_ipv6")?;

                let resource_set = ResourceSet::from_strs(&asn, &v4, &v6)?;

                let not_after = a.take_req("resource_set_notafter")?;
                let not_after = DateTime::<Utc>::from_str(&not_after)?;
                let not_after = Time::new(not_after);

                a.exhausted()?;

                let mut issued = vec![];
                while let Some(issued_cert) = Self::decode_opt_issued_cert(r)? {
                    issued.push(issued_cert);
                }

                let cert = r.take_named_element("issuer", |a, r| {
                    a.exhausted()?;
                    Self::decode_cert(r)
                })?;

                let issuer = SigningCert::new(cert_url, cert);

                Ok(Some(EntitlementClass::new(
                    name,
                    issuer,
                    resource_set,
                    not_after,
                    issued,
                )))
            }
            _ => Err(Error::UnexpectedStart(t.name.clone())),
        })
    }

    fn decode_opt_issued_cert<R>(r: &mut XmlReader<R>) -> Result<Option<IssuedCert>, Error>
    where
        R: io::Read,
    {
        match r.next_start_name() {
            Some("certificate") => {
                let cert = Self::decode_issued_cert(r)?;
                Ok(Some(cert))
            }
            _ => Ok(None),
        }
    }

    fn decode_issued_cert<R>(r: &mut XmlReader<R>) -> Result<IssuedCert, Error>
    where
        R: io::Read,
    {
        r.take_named_element("certificate", |mut a, r| {
            let cert_url =
                uri::Rsync::from_str(&a.take_req("cert_url").map_err(Error::XmlAttributesError)?)?;

            let mut limit = RequestResourceLimit::default();

            if let Some(asn) = a.take_opt("req_resource_set_as") {
                limit.with_asn(AsBlocks::from_str(&asn).map_err(Error::inr_syntax)?);
            }

            if let Some(v4) = a.take_opt("req_resource_set_ipv4") {
                limit.with_ipv4(IpBlocks::from_str(&v4).map_err(Error::inr_syntax)?);
            }

            if let Some(v6) = a.take_opt("req_resource_set_ipv6") {
                limit.with_ipv6(IpBlocks::from_str(&v6).map_err(Error::inr_syntax)?);
            }

            let cert = Self::decode_cert(r)?;
            let resource_set = ResourceSet::try_from(&cert)?;

            Ok(IssuedCert::new(cert_url, limit, resource_set, cert, None))
        })
    }

    fn decode_cert<R>(r: &mut XmlReader<R>) -> Result<Cert, Error>
    where
        R: io::Read,
    {
        let bytes = r.take_bytes_std()?;
        Cert::decode(bytes).map_err(|_| Error::InvalidCert)
    }

    fn decode_error_response<R>(r: &mut XmlReader<R>) -> Result<NotPerformedResponse, Error>
    where
        R: io::Read,
    {
        let code = r.take_named_element("status", |_a, r| r.take_chars())?;

        let desc = r.take_named_element("description", |_a, r| r.take_chars())?;

        match NotPerformedResponse::from_code(&code) {
            Ok(res) => Ok(res),
            Err(e) => {
                error!(
                    "Strange error response with code: {}, description: {}",
                    code, desc
                );
                Err(e)
            }
        }
    }
}

/// # Encoding
///
impl Res {
    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>) -> Result<(), io::Error> {
        match self {
            Res::List(ents) => Self::encode_entitlements(ents, w),
            Res::Issue(response) => Self::encode_issuance_response(response, w),
            Res::Revoke(response) => Self::encode_revoke_reponse(response, w),
            Res::NotPerformed(err) => Self::encode_error_response(err, w),
        }
    }

    fn encode_entitlements<W: io::Write>(
        e: &Entitlements,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        for class in e.classes() {
            Self::encode_entitlement_class(class, w)?;
        }
        Ok(())
    }

    fn encode_issuance_response<W: io::Write>(
        res: &IssuanceResponse,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        Self::encode_class(
            res.class_name(),
            res.issuer().uri(),
            res.not_after(),
            res.resource_set(),
            [res.issued().clone()].iter(),
            res.issuer(),
            w,
        )
    }

    fn encode_entitlement_class<W: io::Write>(
        c: &EntitlementClass,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        Self::encode_class(
            c.class_name(),
            c.issuer().uri(),
            c.not_after(),
            c.resource_set(),
            c.issued().iter(),
            c.issuer(),
            w,
        )
    }

    fn encode_class<'a, W: io::Write>(
        class_name: &str,
        cert_url: &uri::Rsync,
        not_after: Time,
        inrs: &ResourceSet,
        issued: impl Iterator<Item = &'a IssuedCert>,
        issuer: &SigningCert,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        let cert_url = cert_url.to_string();
        let not_after = not_after.to_rfc3339_opts(SecondsFormat::Secs, true);

        let asn = inrs.asn().to_string();
        let v4 = inrs.v4().to_string();
        let v6 = inrs.v6().to_string();

        let mut attrs = vec![];

        attrs.push(("cert_url", cert_url.as_str()));
        attrs.push(("class_name", class_name));
        attrs.push(("resource_set_as", asn.as_str()));
        attrs.push(("resource_set_ipv4", v4.as_str()));
        attrs.push(("resource_set_ipv6", v6.as_str()));
        attrs.push(("resource_set_notafter", not_after.as_str()));

        w.put_element("class", Some(&attrs), |w| {
            for issued in issued {
                Self::encode_issued(issued, w)?;
            }
            let issuer_cert = issuer.cert().to_captured().into_bytes();
            w.put_element("issuer", None, |w| w.put_base64_std(&issuer_cert))
        })
    }

    fn encode_issued<W: io::Write>(
        issued: &IssuedCert,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        let cert_url = issued.uri().to_string();
        let limit = issued.limit();
        let cert_bytes = issued.cert().to_captured().into_bytes();

        // TODO: Use a better xml library so we don't have to do
        //       super-messy allocations. Probably roll our own,
        //       at least for composing.
        let mut attrs_strings = vec![];
        attrs_strings.push(("cert_url", cert_url));

        if let Some(asn) = limit.asn() {
            attrs_strings.push(("resource_set_as", asn.to_string()));
        }
        if let Some(v4) = limit.v4() {
            attrs_strings.push(("resource_set_ipv4", v4.as_v4().to_string()));
        }
        if let Some(v6) = limit.v6() {
            attrs_strings.push(("resource_set_ipv6", v6.as_v6().to_string()));
        }

        let mut attrs_str: Vec<(&str, &str)> = vec![];
        for (k, v) in &attrs_strings {
            attrs_str.push((k, v.as_str()));
        }

        w.put_element("certificate", Some(attrs_str.as_slice()), |w| {
            w.put_base64_std(&cert_bytes)
        })
    }

    fn encode_error_response<W: io::Write>(
        error: &NotPerformedResponse,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        w.put_element("status", None, |w| w.put_text(&format!("{}", error.status)))?;

        let att = [("xml:lang", "en-US")];
        w.put_element("description", Some(&att), |w| {
            w.put_text(&error.description)
        })
    }

    fn encode_revoke_reponse<W: io::Write>(
        res: &RevocationResponse,
        w: &mut XmlWriter<W>,
    ) -> Result<(), io::Error> {
        let bytes = res.key().as_slice();
        let encoded = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
        let att = [("class_name", res.class_name()), ("ski", encoded.as_str())];
        w.put_element("key", Some(&att), |w| w.empty())
    }
}

//------------ NotPerformedResponse ------------------------------------------

/// This type describes the Not-performed responses defined in section 3.6
/// of RFC 6492.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotPerformedResponse {
    status: u64,
    description: String,
}

impl NotPerformedResponse {
    /// Local helper. Please use [`from_code`] to create a response for an
    /// status value defined in RFC6492.
    fn new(status: u64, description: &str) -> Self {
        NotPerformedResponse {
            status,
            description: description.to_string(),
        }
    }

    /// Creates a response for a status value defined in RFC6492. Also adds
    /// the description defined in the RFC.
    pub fn from_code(code: &str) -> Result<Self, Error> {
        match code {
            "1101" => Ok(NotPerformedResponse::new(
                1101,
                "already processing request",
            )),
            "1102" => Ok(NotPerformedResponse::new(1102, "version number error")),
            "1103" => Ok(NotPerformedResponse::new(1103, "unrecognized request type")),
            "1104" => Ok(NotPerformedResponse::new(
                1104,
                "request scheduled for processing",
            )),

            "1201" => Ok(NotPerformedResponse::new(
                1201,
                "request - no such resource class",
            )),
            "1202" => Ok(NotPerformedResponse::new(
                1202,
                "request - no resources allocated in resource class",
            )),
            "1203" => Ok(NotPerformedResponse::new(
                1203,
                "request - badly formed certificate request",
            )),
            "1204" => Ok(NotPerformedResponse::new(
                1204,
                "request - already used key in request",
            )),

            "1301" => Ok(NotPerformedResponse::new(
                1301,
                "revoke - no such resource class",
            )),
            "1302" => Ok(NotPerformedResponse::new(1302, "revoke - no such key")),

            "2001" => Ok(NotPerformedResponse::new(
                2001,
                "Internal Server Error - Request not performed",
            )),
            _ => Err(Error::InvalidErrorCode(code.to_string())),
        }
    }

    pub fn _1101() -> Self {
        Self::from_code("1101").unwrap()
    }
    pub fn _1102() -> Self {
        Self::from_code("1102").unwrap()
    }
    pub fn _1103() -> Self {
        Self::from_code("1103").unwrap()
    }
    pub fn _1104() -> Self {
        Self::from_code("1104").unwrap()
    }

    pub fn _1201() -> Self {
        Self::from_code("1201").unwrap()
    }
    pub fn _1202() -> Self {
        Self::from_code("1202").unwrap()
    }
    pub fn _1203() -> Self {
        Self::from_code("1203").unwrap()
    }
    pub fn _1204() -> Self {
        Self::from_code("1204").unwrap()
    }

    pub fn _1301() -> Self {
        Self::from_code("1301").unwrap()
    }
    pub fn _1302() -> Self {
        Self::from_code("1302").unwrap()
    }

    pub fn _2001() -> Self {
        Self::from_code("2001").unwrap()
    }
}

impl fmt::Display for NotPerformedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "status: {}, description: {}",
            self.status, &self.description
        )
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Unexpected XML Start Tag: {}", _0)]
    UnexpectedStart(String),

    #[display(fmt = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[display(fmt = "Invalid use of attributes in XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[display(fmt = "Unknown message type")]
    UnknownMessageType,

    #[display(fmt = "Unexpected message type")]
    WrongMessageType,

    #[display(fmt = "Invalid protocol version, MUST be 1")]
    InvalidVersion,

    #[display(fmt = "Invalid URI: {}", _0)]
    UriError(uri::Error),

    #[display(fmt = "{}", _0)]
    ResSetErr(ResSetErr),

    #[display(fmt = "Invalid date time syntax: {}", _0)]
    Time(chrono::ParseError),

    #[display(fmt = "Could not parse encoded certificate.")]
    InvalidCert,

    #[display(fmt = "Could not parse encoded certificate request.")]
    InvalidCsr,

    #[display(fmt = "Could not parse SKI in revoke request.")]
    InvalidSki,

    #[display(fmt = "Invalid not-performed error code: {}.", _0)]
    InvalidErrorCode(String),

    #[display(fmt = "{}", _0)]
    InrSyntax(String),
}

impl Error {
    fn inr_syntax(e: impl Display) -> Self {
        Error::InrSyntax(e.to_string())
    }
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

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<ResSetErr> for Error {
    fn from(e: ResSetErr) -> Self {
        Error::ResSetErr(e)
    }
}

impl From<chrono::ParseError> for Error {
    fn from(e: chrono::ParseError) -> Self {
        Error::Time(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::str;
    use std::str::from_utf8_unchecked;

    use crate::remote::id::tests::test_id_certificate;
    use crate::remote::sigmsg::SignedMessage;

    use super::*;
    use remote::id::IdCert;

    /// Test that the we can re-encode the object to xml, parse that
    /// xml, and end up with an equal object.
    fn assert_re_encode_equals(object: Message) {
        let vec = object.encode_vec();
        let encoded_xml = str::from_utf8(&vec).unwrap();
        let object_from_encoded_xml = Message::decode(encoded_xml.as_bytes()).unwrap();
        assert_eq!(object, object_from_encoded_xml);
    }

    fn extract_xml(pdu: &[u8]) -> String {
        let msg = SignedMessage::decode(pdu.as_ref(), false).unwrap();
        let content = msg.content().to_bytes();
        let xml = unsafe { from_utf8_unchecked(content.as_ref()) };
        xml.to_string()
    }

    #[test]
    fn parse_and_encode_list() {
        let xml = extract_xml(include_bytes!(
            "../../test-resources/remote/rpkid-rfc6492-list.der"
        ));
        let list = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list);
    }

    #[test]
    fn parse_and_encode_list_response() {
        let xml = extract_xml(include_bytes!(
            "../../test-resources/remote/rpkid-rfc6492-list_response.der"
        ));
        let list_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list_response);
    }

    #[test]
    fn parse_and_validate_apnic_response() {
        let pdu = include_bytes!("../../test-resources/remote/apnic-list-response.der");

        let msg = SignedMessage::decode(pdu.as_ref(), false).unwrap();
        let content = msg.content().to_bytes();
        let xml = unsafe { from_utf8_unchecked(content.as_ref()) };

        let _list_response = Message::decode(xml.as_bytes()).unwrap();

        let cer_der = include_bytes!("../../test-resources/remote/apnic-id.der");
        let cer = IdCert::decode(cer_der.as_ref()).unwrap();

        msg.validate(&cer).unwrap();
    }

    #[test]
    fn parse_and_encode_issue() {
        let xml = extract_xml(include_bytes!(
            "../../test-resources/remote/rpkid-rfc6492-issue.der"
        ));
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }

    #[test]
    fn parse_and_encode_issue_response() {
        let xml = extract_xml(include_bytes!(
            "../../test-resources/remote/rpkid-rfc6492-issue_response.der"
        ));
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }

    #[test]
    fn encode_and_parse_revocation_request() {
        // No example CMS found for this one, so just composing and
        // reading the XML based on the RFC spec only.
        let cert = test_id_certificate();

        let sender = "child".to_string();
        let rcpt = "parent".to_string();
        let class = "all".to_string();

        let ski = cert.subject_public_key_info().key_identifier();
        let revocation = RevocationRequest::new(class, ski);

        let rev = Message::revoke(sender, rcpt, revocation);

        let decoded_rev = Message::decode(rev.encode_vec().as_slice()).unwrap();

        assert_eq!(rev, decoded_rev);
    }

    #[test]
    fn encode_and_parse_revocation_response() {
        // No example CMS found for this one, so just composing and
        // reading the XML based on the RFC spec only.
        let cert = test_id_certificate();

        let sender = "child".to_string();
        let rcpt = "parent".to_string();
        let class = "all".to_string();

        let ski = cert.subject_public_key_info().key_identifier();
        let revocation = RevocationResponse::new(class, ski);

        let rev = Message::revoke_response(sender, rcpt, revocation);
        let decoded_rev = Message::decode(rev.encode_vec().as_slice()).unwrap();

        assert_eq!(rev, decoded_rev);
    }

    #[test]
    fn encode_and_parse_error_response() {
        // No example CMS found for this one, so just composing and
        // reading the XML based on the RFC spec only.
        let sender = "child".to_string();
        let rcpt = "parent".to_string();
        let err = NotPerformedResponse::_1101();

        let err = Message::not_performed_response(sender, rcpt, err).unwrap();
        let decoded = Message::decode(err.encode_vec().as_slice()).unwrap();

        assert_eq!(err, decoded);
    }
}
