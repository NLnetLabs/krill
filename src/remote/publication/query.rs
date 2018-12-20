//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.1 and further

use std::io;
use bytes::Bytes;
use hex;
use rpki::uri;
use super::pubmsg::MessageError;
use crate::xml::{Attributes, XmlReader, XmlWriter};
use super::hash;
use super::pubmsg::Message;
use super::pubmsg::QueryMessage;
use super::reply::ListElement;


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


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;
    use rpki::uri::Rsync;

    fn rsync_uri(s: &str) -> Rsync {
        Rsync::from_str(s).unwrap()
    }


    #[test]
    fn should_create_list_query() {
        let lq = ListQuery::build_message();
        let vec = lq.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();
        let expected_xml = include_str!(
            "../../../test/publication/generated/list_query_result.xml"
        );

        assert_eq!(produced_xml, expected_xml);
    }

    #[test]
    fn should_create_publish_query() {
        let object = Bytes::from_static(include_bytes!(
            "../../../test/remote/cms_ta.cer"
        ));
        let object2 = Bytes::from_static(include_bytes!(
            "../../../test/remote/pdu_200.der"
        ));
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
        let expected_xml = include_str!(
            "../../../test/publication/generated/publish_query_result.xml"
        );

        assert_eq!(produced_xml, expected_xml);
    }


}


