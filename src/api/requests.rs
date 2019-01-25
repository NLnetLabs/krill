//! Support for requests sent to the Json API
use bytes::Bytes;
use rpki::uri;
use crate::api::responses;
use crate::util::ext_serde;
use crate::util::hash;

/// This type provides a convenience wrapper to contain the request found
/// inside of a validated RFC8181 request.
pub enum PublishRequest {
    List, // See https://tools.ietf.org/html/rfc8181#section-2.3
    Delta(PublishDelta)
}

/// This type represents a multi element query as described in
/// https://tools.ietf.org/html/rfc8181#section-3.7
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishDelta {
    publishes: Vec<Publish>,
    updates: Vec<Update>,
    withdraws: Vec<Withdraw>
}

impl PublishDelta {
    pub fn new(
        publishes: Vec<Publish>,
        updates: Vec<Update>,
        withdraws: Vec<Withdraw>
    ) -> Self {
        PublishDelta { publishes, updates, withdraws }
    }

    pub fn publishes(&self) -> &Vec<Publish> {
        &self.publishes
    }
    pub fn updates(&self) -> &Vec<Update> {
        &self.updates
    }
    pub fn withdraws(&self) -> &Vec<Withdraw> {
        &self.withdraws
    }

    pub fn len(&self) -> usize {
        self.publishes.len() + self.updates.len() + self.withdraws.len()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

pub struct PublishDeltaBuilder {
    publishes: Vec<Publish>,
    updates: Vec<Update>,
    withdraws: Vec<Withdraw>
}

impl PublishDeltaBuilder {
    pub fn new() -> Self {
        PublishDeltaBuilder {
            publishes: vec![],
            updates: vec![],
            withdraws: vec![]
        }
    }

    pub fn add_publish(&mut self, publish: Publish) {
        self.publishes.push(publish);
    }

    pub fn add_update(&mut self, update: Update) {
        self.updates.push(update);
    }

    pub fn add_withdraw(&mut self, withdraw: Withdraw) {
        self.withdraws.push(withdraw);
    }

    pub fn finish(self) -> PublishDelta {
        PublishDelta {
            publishes: self.publishes,
            updates: self.updates,
            withdraws: self.withdraws
        }
    }
}



/// Type representing a json equivalent to the publish element, that does not
/// update any existing object, defined in:
/// https://tools.ietf.org/html/rfc8181#section-3.1
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publish {
    tag: String,

    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    uri: uri::Rsync,

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    content: Bytes
}

impl Publish {
    pub fn new(tag: Option<String>, uri: uri::Rsync, content: Bytes) -> Self {
        let tag = tag.unwrap_or(hex::encode(hash(&content)));
        Publish { tag, uri, content }
    }

    pub fn tag(&self) -> &String { &self.tag }
    pub fn uri(&self) -> &uri::Rsync{ &self.uri}
    pub fn content(&self) -> &Bytes{ &self.content }
}


/// Type representing a json equivalent to the publish element, that updates
/// an existing object:
/// https://tools.ietf.org/html/rfc8181#section-3.2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Update {
    tag: String,

    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    uri: uri::Rsync,

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    content: Bytes,

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    hash: Bytes,
}

impl Update {
    pub fn new(
        tag: Option<String>,
        uri: uri::Rsync,
        content: Bytes,
        old_hash: Bytes
    ) -> Self {
        let tag = tag.unwrap_or(hex::encode(hash(&content)));
        Update { tag, uri, content, hash: old_hash }
    }

    pub fn tag(&self) -> &String { &self.tag }
    pub fn uri(&self) -> &uri::Rsync { &self.uri}
    pub fn content(&self) -> &Bytes { &self.content }
    pub fn hash(&self) -> &Bytes { &self.hash }
}

/// Type representing a json equivalent to a withdraw element that removes an
/// object from the repository:
/// https://tools.ietf.org/html/rfc8181#section-3.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Withdraw {
    tag: String,

    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    uri: uri::Rsync,

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    hash: Bytes,
}

impl Withdraw {
    pub fn new(tag: Option<String>, uri: uri::Rsync, hash: Bytes) -> Self {
        let tag = tag.unwrap_or(hex::encode(&hash));
        Withdraw { tag, uri, hash }
    }

    pub fn from_list_element(el: &responses::ListElement) -> Self {
        Withdraw {
            tag: "".to_string(),
            uri: el.uri().clone(),
            hash: el.hash().clone()
        }
    }

    pub fn tag(&self) -> &String { &self.tag }
    pub fn uri(&self) -> &uri::Rsync { &self.uri}
    pub fn hash(&self) -> &Bytes { &self.hash }
}