use std::io;
use std::str::FromStr;
use std::convert::TryFrom;

use chrono::{Utc, DateTime, SecondsFormat};
use serde::export::fmt::Display;

use rpki::cert::Cert;
use rpki::crypto::KeyIdentifier;
use rpki::csr::Csr;
use rpki::resources::{AsResources, Ipv4Resources, Ipv6Resources};
use rpki::uri;
use rpki::x509::Time;

use krill_commons::api::{Entitlements, EntitlementClass, SigningCert, RequestResourceLimit, IssuanceRequest, IssuanceResponse, RevocationRequest};
use krill_commons::api::ca::{ResourceSet, ResSetErr, IssuedCert};
use krill_commons::util::xml::{XmlReader, XmlReaderErr, AttributesError, XmlWriter};


//------------ Consts --------------------------------------------------------

const VERSION: &str = "1";
const NS: &str = "http://www.apnic.net/specs/rescerts/up-down/";

const TYPE_LIST_QRY: &str = "list";
const TYPE_LIST_RES: &str = "list_response";
const TYPE_ISSUE_QRY: &str = "issue";
const TYPE_ISSUE_RES: &str = "issue_response";
const TYPE_REVOKE_QRY: &str = "revoke";
const TYPE_REVOKE_RES: &str = "revoke_response";

//------------ Message -------------------------------------------------------

/// This type represents all Provisioning Messages defined in RFC6492.
///
/// Note this is all very similar to, yet subtly different from, the
/// Publication Messages defined in RFC8181.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    sender: String,
    recipient: String,
    content: Content
}

impl Message {
    pub fn list_response(
        sender: String,
        recipient: String,
        entitlements: Entitlements
    ) -> Self {
        let content = Content::Res(Res::List(entitlements));
        Message { sender, recipient, content}
    }

    pub fn revoke(
        sender: String,
        recipient: String,
        revocation: RevocationRequest
    ) -> Self {
        let content = Content::Qry(Qry::Revoke(revocation));
        Message { sender, recipient, content }
    }

    pub fn revoke_response(
        sender: String,
        recipient: String,
        revocation: RevocationRequest
    ) -> Self {
        let content = Content::Res(Res::Revoke(revocation));
        Message { sender, recipient, content }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Content {
    Qry(Qry),
    Res(Res)
}

impl Content {
    fn msg_type(&self) -> &str {
        match self {
            Content::Qry(q) => q.msg_type(),
            Content::Res(r) => r.msg_type()
        }
    }
}

/// # Decoding and Encoding
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
                    TYPE_LIST_QRY | TYPE_ISSUE_QRY | TYPE_REVOKE_QRY => {
                        Ok(Content::Qry(Qry::decode(&msg_type, r)?))
                    },
                    TYPE_LIST_RES | TYPE_ISSUE_RES | TYPE_REVOKE_RES => {
                        Ok(Content::Res(Res::decode(&msg_type, r)?))
                    }
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
                    Content::Qry(q) => q.encode(w),
                    Content::Res(r) => r.encode(w)
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
#[allow(clippy::large_enum_variant)]
pub enum Qry {
    List,
    Issue(IssuanceRequest),
    Revoke(RevocationRequest)
}


impl Qry {
    fn msg_type(&self) -> &str {
        match self {
            Qry::List => TYPE_LIST_QRY,
            Qry::Issue(_) => TYPE_ISSUE_QRY,
            Qry::Revoke(_) => TYPE_REVOKE_QRY
        }
    }

    fn decode<R>(
        msg_type: &str,
        r: &mut XmlReader<R>
    ) -> Result<Self, Error> where R: io::Read {
        match msg_type {
            TYPE_LIST_QRY => Ok(Qry::List),
            TYPE_ISSUE_QRY => Ok(Qry::Issue(Self::decode_issue(r)?)),
            TYPE_REVOKE_QRY => Ok(Qry::Revoke(Self::decode_revoke(r)?)),
            _ => Err(Error::UnknownMessageType)
        }
    }

    fn decode_revoke<R>(
        r: &mut XmlReader<R>
    ) -> Result<RevocationRequest, Error> where R: io::Read {
        r.take_named_element("key", |mut a, r| {
            let class_name = a.take_req("class_name")?;
            a.exhausted()?;

            let ski_bytes = r.take_bytes_url_safe_pad()?;

            let ski = KeyIdentifier::try_from(ski_bytes.as_ref())
                .map_err(|_| Error::InvalidSki)?;

            Ok(RevocationRequest::new(class_name.to_string(), ski))
        })
    }

    fn decode_issue<R>(
        r: &mut XmlReader<R>
    ) -> Result<IssuanceRequest, Error> where R: io::Read {
        r.take_named_element("request", |mut a, r|{
            let class_name = a.take_req("class_name")?;
            let mut limit = RequestResourceLimit::default();

            if let Some(asn) = a.take_opt("req_resource_set_as") {
                let asn = AsResources::from_str(&asn)
                    .map_err(Error::inr_syntax)?;
                limit.with_asn(asn);
            }

            if let Some(ipv4) = a.take_opt("req_resource_set_ipv4") {
                let ipv4 = Ipv4Resources::from_str(&ipv4)
                    .map_err(Error::inr_syntax)?;
                limit.with_ipv4(ipv4);
            }

            if let Some(ipv6) = a.take_opt("req_resource_set_ipv6") {
                let ipv6 = Ipv6Resources::from_str(&ipv6)
                    .map_err(Error::inr_syntax)?;
                limit.with_ipv6(ipv6);
            }

            let csr_bytes = r.take_bytes_characters()?;
            let csr = Csr::decode(csr_bytes).map_err(|_| Error::InvalidCsr)?;

            Ok(IssuanceRequest::new(
                class_name.to_string(),
                limit,
                csr
            ))
        })
    }

    fn encode<W: io::Write>(
        &self,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        match self {
            Qry::List => w.empty(),
            Qry::Issue(issue_req) => Self::encode_issue(issue_req, w),
            Qry::Revoke(rev) => Self::encode_revoke(rev, w)
        }
    }

    fn encode_issue<W: io::Write>(
        issue: &IssuanceRequest,
        w: &mut XmlWriter<W>
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
            attrs_strings.push(("req_resource_set_ipv4", v4.to_string()));
        }
        if let Some(v6) = limit.v6() {
            attrs_strings.push(("req_resource_set_ipv6", v6.to_string()));
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
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        let att = [ ("class_name", rev.class_name() )];
        let bytes = rev.key().as_slice();
        w.put_element("key", Some(&att), |w| {
            w.put_base64_url_safe(bytes)
        })
    }
}


//------------ Reply ---------------------------------------------------------

/// This type defines the various RFC6492 queries.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Res {
    List(Entitlements),
    Issue(IssuanceResponse),
    Revoke(RevocationRequest)
}

impl Res {
    fn msg_type(&self) -> &str {
        match self {
            Res::List(_) => TYPE_LIST_RES,
            Res::Issue(_) => TYPE_ISSUE_RES,
            Res::Revoke(_) => TYPE_REVOKE_RES
        }
    }

    fn decode<R>(
        msg_type: &str,
        r: &mut XmlReader<R>
    ) -> Result<Self, Error> where R: io::Read {
        match msg_type {
            TYPE_LIST_RES => {
                let entitlements = Self::decode_entitlements(r)?;
                Ok(Res::List(entitlements))
            },
            TYPE_ISSUE_RES => {
                let issuance_response = Self::decode_issue_response(r)?;
                Ok(Res::Issue(issuance_response))
            }
            TYPE_REVOKE_RES => {
                let request = Qry::decode_revoke(r)?;
                Ok(Res::Revoke(request))
            }
            _ => Err(Error::UnknownMessageType)
        }
    }

    fn decode_issue_response<R>(
        r: &mut XmlReader<R>
    ) -> Result<IssuanceResponse, Error> where R: io::Read {
        r.take_named_element("class", |mut a, r| {
            let name = a.take_req("class_name")?;
            let cert_url = uri::Rsync::from_str(
                &a.take_req("cert_url")?
            )?;

            let asn = a.take_req("resource_set_as")?;
            let v4  = a.take_req("resource_set_ipv4")?;
            let v6  = a.take_req("resource_set_ipv6")?;
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
                issued
            ))
        })
    }

    fn decode_entitlements<R>(
        r: &mut XmlReader<R>
    ) -> Result<Entitlements, Error> where R: io::Read {
        let mut classes = vec![];
        while let Some(class) = Self::decode_entitlement_class(r)? {
            classes.push(class);
        }
        Ok(Entitlements::new(classes))
    }

    fn decode_entitlement_class<R>(
        r: &mut XmlReader<R>
    ) -> Result<Option<EntitlementClass>, Error> where R: io::Read {
        r.take_opt_element(|t, mut a, r| {
            match t.name.as_ref() {
                "class" => {
                    let name = a.take_req("class_name")?;
                    let cert_url = uri::Rsync::from_str(
                        &a.take_req("cert_url")?
                    )?;

                    let asn = a.take_req("resource_set_as")?;
                    let v4  = a.take_req("resource_set_ipv4")?;
                    let v6  = a.take_req("resource_set_ipv6")?;

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
                        name, issuer, resource_set, not_after, issued
                    )))
                },
                _ => Err(Error::UnexpectedStart(t.name.clone()))
            }
        })
    }

    fn decode_opt_issued_cert<R>(
        r: &mut XmlReader<R>
    ) -> Result<Option<IssuedCert>, Error> where R: io::Read {
        match r.next_start_name() {
            Some("certificate") => {
                let cert = Self::decode_issued_cert(r)?;
                Ok(Some(cert))
            },
            _ => Ok(None)
        }
    }

    fn decode_issued_cert<R>(
        r: &mut XmlReader<R>
    ) -> Result<IssuedCert, Error> where R: io::Read {
        r.take_named_element("certificate", |mut a, r| {
            let cert_url = uri::Rsync::from_str(
                &a.take_req("cert_url").map_err(Error::XmlAttributesError)?
            )?;

            let mut limit = RequestResourceLimit::default();

            if let Some(asn) = a.take_opt("req_resource_set_as") {
                limit.with_asn(
                    AsResources::from_str(&asn).map_err(Error::inr_syntax)?
                );
            }

            if let Some(v4) = a.take_opt("req_resource_set_ipv4") {
                limit.with_ipv4(
                    Ipv4Resources::from_str(&v4).map_err(Error::inr_syntax)?
                );
            }

            if let Some(v6) = a.take_opt("req_resource_set_ipv6") {
                limit.with_ipv6(
                    Ipv6Resources::from_str(&v6).map_err(Error::inr_syntax)?
                );
            }

            let cert = Self::decode_cert(r)?;
            let resource_set = ResourceSet::from(&cert);

            Ok(IssuedCert::new(cert_url, limit, resource_set, cert))
        })
    }


    fn decode_cert<R>(
        r: &mut XmlReader<R>
    ) -> Result<Cert, Error> where R: io::Read {
        let bytes = r.take_bytes_characters()?;
        Cert::decode(bytes).map_err(|_| Error::InvalidCert)
    }

    fn encode<W: io::Write>(
        &self,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        match self {
            Res::List(ents) => Self::encode_entitlements(ents, w),
            Res::Issue(response) => Self::encode_issuance_response(response, w),
            Res::Revoke(request) => Qry::encode_revoke(request, w)
        }
    }

    fn encode_entitlements<W: io::Write>(
        e: &Entitlements,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        for class in e.classes() {
            Self::encode_entitlement_class(class, w)?;
        }
        Ok(())
    }

    fn encode_issuance_response<W: io::Write>(
        res: &IssuanceResponse,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        Self::encode_class(
            res.class_name(),
            res.issuer().uri(),
            res.not_after(),
            res.resource_set(),
            [res.issued().clone()].iter(),
            res.issuer(),
            w
        )
    }

    fn encode_entitlement_class<W: io::Write>(
        c: &EntitlementClass,
        w: &mut XmlWriter<W>
    ) -> Result<(), io::Error> {
        Self::encode_class(
            c.class_name(),
            c.issuer().uri(),
            c.not_after(),
            c.resource_set(),
            c.issued().iter(),
            c.issuer(),
            w
        )
    }

    fn encode_class<'a, W: io::Write>(
        class_name: &str,
        cert_url: &uri::Rsync,
        not_after: Time,
        inrs: &ResourceSet,
        issued: impl Iterator<Item=&'a IssuedCert>,
        issuer: &SigningCert,
        w: &mut XmlWriter<W>
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
            w.put_element("issuer", None, |w| { w.put_base64_std(&issuer_cert) })
        })
    }



    fn encode_issued<W: io::Write>(
        issued: &IssuedCert,
        w: &mut XmlWriter<W>
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
            attrs_strings.push(("resource_set_ipv4", v4.to_string()));
        }
        if let Some(v6) = limit.v6() {
            attrs_strings.push(("resource_set_ipv6", v6.to_string()));
        }

        let mut attrs_str: Vec<(&str, &str)> = vec![];
        for (k, v) in &attrs_strings {
            attrs_str.push((k, v.as_str()));
        }

        w.put_element("certificate", Some(attrs_str.as_slice()), |w| {
            w.put_base64_std(&cert_bytes)
        })
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

    #[display(fmt = "{}", _0)]
    InrSyntax(String),
}

impl Error {
    fn inr_syntax(e: impl Display) -> Self { Error::InrSyntax(e.to_string())}
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

    use crate::sigmsg::SignedMessage;
    use crate::id::tests::test_id_certificate;

    use super::*;

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
        let xml = unsafe {
            from_utf8_unchecked(content.as_ref())
        };
        xml.to_string()
    }

    #[test]
    fn parse_and_encode_list() {
        let xml = extract_xml(
            include_bytes!("../test/remote/rpkid-rfc6492-list.der")
        );
        let list = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list);
    }

    #[test]
    fn parse_and_encode_list_response() {
        let xml = extract_xml(
            include_bytes!("../test/remote/rpkid-rfc6492-list_response.der")
        );
        let list_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list_response);
    }

    #[test]
    fn parse_and_encode_issue() {
        let xml = extract_xml(
            include_bytes!("../test/remote/rpkid-rfc6492-issue.der")
        );
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }

    #[test]
    fn parse_and_encode_issue_response() {
        let xml = extract_xml(
            include_bytes!("../test/remote/rpkid-rfc6492-issue_response.der")
        );
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
        let revocation = RevocationRequest::new(class, ski);

        let rev = Message::revoke_response(sender, rcpt, revocation);

        let decoded_rev = Message::decode(rev.encode_vec().as_slice()).unwrap();

        assert_eq!(rev, decoded_rev);
    }

    #[test]
    #[ignore]
    fn print_cms_content() {
        let xml = extract_xml(
            include_bytes!("../test/remote/rpkid-rfc6492-issue_response.der")
        );

        eprintln!("{}", xml);
    }
}