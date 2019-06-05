//! Support for requests sent to the Json API
use rpki::uri;
use crate::api::{ Base64, EncodedHash };
use crate::util::file::CurrentFile;


//------------ PublishRequest ------------------------------------------------

/// This type provides a convenience wrapper to contain the request found
/// inside of a validated RFC8181 request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublishRequest {
    List, // See https://tools.ietf.org/html/rfc8181#section-2.3
    Delta(PublishDelta)
}


//------------ PublishDelta ------------------------------------------------

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

    pub fn unwrap(self) -> (Vec<Publish>, Vec<Update>, Vec<Withdraw>) {
        (self.publishes, self.updates, self.withdraws)
    }
}


//------------ PublishDeltaBuilder -------------------------------------------

#[derive(Default)]
pub struct PublishDeltaBuilder {
    publishes: Vec<Publish>,
    updates: Vec<Update>,
    withdraws: Vec<Withdraw>
}

impl PublishDeltaBuilder {
    pub fn new() -> Self {
        Self::default()
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


//------------ Publish ------------------------------------------------------

/// Type representing a json equivalent to the publish element, that does not
/// update any existing object, defined in:
/// https://tools.ietf.org/html/rfc8181#section-3.1
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publish {
    tag: Option<String>,
    uri: uri::Rsync,
    content: Base64
}

impl Publish {
    pub fn new(tag: Option<String>, uri: uri::Rsync, content: Base64) -> Self {
        Publish { tag, uri, content }
    }
    pub fn with_hash_tag(uri: uri::Rsync, content: Base64) -> Self {
        let tag = Some(content.to_hex_hash());
        Publish { tag, uri, content }
    }

    pub fn tag(&self) -> &Option<String> { &self.tag }
    pub fn tag_for_xml(&self) -> String {
        match &self.tag {
            None => "".to_string(),
            Some(t) => t.clone()
        }
    }
    pub fn uri(&self) -> &uri::Rsync{ &self.uri}
    pub fn content(&self) -> &Base64{ &self.content }

    pub fn unwrap(self) -> (Option<String>, uri::Rsync, Base64) {
        (self.tag, self.uri, self.content)
    }
}


//------------ Update --------------------------------------------------------

/// Type representing a json equivalent to the publish element, that updates
/// an existing object:
/// https://tools.ietf.org/html/rfc8181#section-3.2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Update {
    tag: Option<String>,
    uri: uri::Rsync,
    content: Base64,
    hash: EncodedHash,
}

impl Update {
    pub fn new(
        tag: Option<String>,
        uri: uri::Rsync,
        content: Base64,
        old_hash: EncodedHash
    ) -> Self {
        Update { tag, uri, content, hash: old_hash }
    }
    pub fn with_hash_tag(
        uri: uri::Rsync,
        content: Base64,
        old_hash: EncodedHash
    ) -> Self {
        let tag = Some(content.to_hex_hash());
        Update { tag, uri, content, hash: old_hash }
    }

    pub fn tag(&self) -> &Option<String> { &self.tag }
    pub fn tag_for_xml(&self) -> String {
        match &self.tag {
            Some(t) => t.clone(),
            None => "".to_string()
        }
    }
    pub fn uri(&self) -> &uri::Rsync { &self.uri}
    pub fn content(&self) -> &Base64 { &self.content }
    pub fn hash(&self) -> &EncodedHash { &self.hash }

    pub fn unwrap(self) -> (Option<String>, uri::Rsync, Base64, EncodedHash) {
        (self.tag, self.uri, self.content, self.hash)
    }
}


//------------ Withdraw ------------------------------------------------------

/// Type representing a json equivalent to a withdraw element that removes an
/// object from the repository:
/// https://tools.ietf.org/html/rfc8181#section-3.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Withdraw {
    tag: Option<String>,
    uri: uri::Rsync,
    hash: EncodedHash,
}

impl Withdraw {
    pub fn new(tag: Option<String>, uri: uri::Rsync, hash: EncodedHash) -> Self {
        Withdraw { tag, uri, hash }
    }

    pub fn with_hash_tag(uri: uri::Rsync, hash: EncodedHash) -> Self {
        let tag = Some(hash.to_string());
        Withdraw { tag, uri, hash }
    }

    pub fn from_list_element(el: &ListElement) -> Self {
        Withdraw {
            tag: None,
            uri: el.uri().clone(),
            hash: el.hash().clone()
        }
    }

    pub fn tag(&self) -> &Option<String> { &self.tag }
    pub fn tag_for_xml(&self) -> String {
        match &self.tag {
            Some(t) => t.clone(),
            None => "".to_string()
        }
    }
    pub fn uri(&self) -> &uri::Rsync { &self.uri}
    pub fn hash(&self) -> &EncodedHash { &self.hash }

    pub fn unwrap(self) -> (Option<String>, uri::Rsync, EncodedHash) {
        (self.tag, self.uri, self.hash)
    }
}

//------------ PublishReply --------------------------------------------------

/// This type is used to wrap API responses for publication requests.
pub enum PublishReply {
    Success, // See https://tools.ietf.org/html/rfc8181#section-3.4
    List(ListReply)
}


//------------ ListReply -----------------------------------------------------

/// This type represents the list reply as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListReply {
    elements: Vec<ListElement>
}

impl ListReply {
    pub fn new(elements: Vec<ListElement>) -> Self {
        ListReply { elements }
    }

    pub fn from_files(files: Vec<CurrentFile>) -> Self {
        let elements = files.into_iter().map(CurrentFile::into_list_element).collect();
        ListReply { elements }
    }

    pub fn elements(&self) -> &Vec<ListElement> {
        &self.elements
    }
}


//------------ ListElement ---------------------------------------------------

/// This type represents a single object that is published at a publication
/// server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ListElement {
    uri:     uri::Rsync,
    hash:    EncodedHash
}

impl ListElement {
    pub fn new(uri: uri::Rsync, hash: EncodedHash) -> Self {
        ListElement { uri, hash }
    }

    pub fn uri(&self) -> &uri::Rsync { &self.uri }
    pub fn hash(&self) -> &EncodedHash { &self.hash }
}
