//! Support for admin tasks, such as managing publishers and RFC8181 clients

use rpki::uri;
use crate::api::Link;
use crate::eventsourcing::AggregateId;
use crate::util::ext_serde;
use std::fmt;
use std::fmt::Display;
use std::ops::Deref;

//------------ CaHandle ------------------------------------------------------

pub type CaHandle = AggregateHandle;

//------------ PublisherHandle -----------------------------------------------

pub type PublisherHandle = AggregateHandle;

//------------ AggregateHandle -----------------------------------------------

/// A type for referring to publishers, both in the api as well as to the
/// aggregates.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AggregateHandle(AggregateId);

impl AggregateHandle {
    pub fn name(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for AggregateHandle {
    fn from(s: &str) -> Self {
        AggregateHandle::from(AggregateId::from(s))
    }
}

impl From<String> for AggregateHandle {
    fn from(s: String) -> Self { AggregateHandle::from(AggregateId::from(s))}
}

impl From<AggregateId> for AggregateHandle {
    fn from(id: AggregateId) -> Self {
        AggregateHandle(id)
    }
}

impl From<&AggregateId> for AggregateHandle {
    fn from(id: &AggregateId) -> Self {
        AggregateHandle(id.clone())
    }
}

impl AsRef<str> for AggregateHandle {
    fn as_ref(&self) -> &str {
        self.name()
    }
}

impl AsRef<AggregateId> for AggregateHandle {
    fn as_ref(&self) -> &AggregateId {
        &self.0
    }
}

impl Deref for AggregateHandle {
    type Target = AggregateId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for AggregateHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}


//------------ PublisherRequest ----------------------------------------------

/// This type defines request for a new Publisher (CA that is allowed to
/// publish).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherRequest {
    handle:        String,

    /// The token used by the API
    token:         String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:    uri::Rsync,
}

impl PublisherRequest {
    pub fn new(
        handle:   String,
        token:    String,
        base_uri: uri::Rsync,
    ) -> Self {
        PublisherRequest {
            handle,
            token,
            base_uri,
        }
    }
}

impl PublisherRequest {
    pub fn handle(&self) -> &String {
        &self.handle
    }

    pub fn token(&self) -> &String {
        &self.token
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    /// Return all the values (handle, token, base_uri).
    pub fn unwrap(self) -> (String, String, uri::Rsync) {
        (self.handle, self.token, self.base_uri)
    }
}

impl PartialEq for PublisherRequest {
    fn eq(&self, other: &PublisherRequest) -> bool {
        self.handle == other.handle &&
        self.base_uri == other.base_uri
    }
}

impl Eq for PublisherRequest {}


//------------ PublisherSummaryInfo ------------------------------------------

/// Defines a summary of publisher information to be used in the publisher
/// list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherSummary {
    id: String,
    links: Vec<Link>
}

impl PublisherSummary {
    pub fn from(
        handle: &PublisherHandle,
        path_publishers: &str
    ) -> PublisherSummary {
        let mut links = Vec::new();
        let self_link = Link {
            rel: "self".to_string(),
            link: format!("{}/{}", path_publishers, handle)
        };
        links.push(self_link);

        PublisherSummary {
            id: handle.to_string(),
            links
        }
    }

    pub fn id(&self) -> &str { &self.id }
}


//------------ PublisherList -------------------------------------------------

/// This type represents a list of (all) current publishers to show in the API
#[derive(Clone, Eq, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublisherList {
    publishers: Vec<PublisherSummary>
}

impl PublisherList {
    pub fn build(
        publishers: &[PublisherHandle],
        path_publishers: &str
    ) -> PublisherList {
        let publishers: Vec<PublisherSummary> = publishers.iter().map(|p|
            PublisherSummary::from(&p, path_publishers)
        ).collect();

        PublisherList {
            publishers
        }
    }

    pub fn publishers(&self) -> &Vec<PublisherSummary> {
        &self.publishers
    }
}


//------------ PublisherDetails ----------------------------------------------

/// This type defines the publisher details for:
/// /api/v1/publishers/{handle}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherDetails {
    handle: String,

    deactivated: bool,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri"
    )]
    base_uri: uri::Rsync,
}

impl PublisherDetails {
    pub fn new(handle: &str, deactivated: bool, base_uri: &uri::Rsync) -> Self {
        PublisherDetails {
            handle: handle.to_string(),
            deactivated,
            base_uri: base_uri.clone()
        }
    }

    pub fn handle(&self) -> &str { &self.handle }
    pub fn deactivated(&self) -> bool { self.deactivated }
    pub fn base_uri(&self) -> &uri::Rsync { &self.base_uri }
}

impl PartialEq for PublisherDetails {
    fn eq(&self, other: &PublisherDetails) -> bool {
        match (serde_json::to_string(self), serde_json::to_string(other)) {
            (Ok(ser_self), Ok(ser_other)) => ser_self == ser_other,
            _ => false
        }
    }
}

impl Eq for PublisherDetails {}


