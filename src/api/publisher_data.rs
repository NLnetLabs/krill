//! Support for responses sent by the Json API
//!
//! i.e. this is stuff the the server needs to serialize only, so typically
//! we can work with references here.
use std::fmt;
use std::fmt::Display;
use rpki::uri;
use crate::api::Link;
use crate::eventsourcing::AggregateId;
use crate::krilld::pubd::publishers::Publisher;
use crate::util::ext_serde;


pub const PUBLISHER_TYPE_ID: &str = "publisher";

//------------ PublisherHandle -----------------------------------------------

/// A type for referring to publishers, both in the api as well as to the
/// aggregates.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PublisherHandle(AggregateId);

impl PublisherHandle {
    pub fn name(&self) -> &str {
        self.0.instance_id()
    }
}

impl From<&str> for PublisherHandle {
    fn from(s: &str) -> Self {
        PublisherHandle(AggregateId::new(PUBLISHER_TYPE_ID, s))
    }
}

impl From<String> for PublisherHandle {
    fn from(s: String) -> Self {
        PublisherHandle(AggregateId::new(PUBLISHER_TYPE_ID, &s))
    }
}

impl From<&AggregateId> for PublisherHandle {
    fn from(agg_id: &AggregateId) -> Self {
        PublisherHandle(agg_id.clone())
    }
}

impl From<AggregateId> for PublisherHandle {
    fn from(agg_id: AggregateId) -> Self {
        PublisherHandle(agg_id)
    }
}

impl AsRef<str> for PublisherHandle {
    fn as_ref(&self) -> &str {
        self.name()
    }
}

impl AsRef<AggregateId> for PublisherHandle {
    fn as_ref(&self) -> &AggregateId {
        &self.0
    }
}

impl Display for PublisherHandle {
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

    /// Return all the values (handle, token, base_uri, rfc8181opt).
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
#[derive(Clone, Debug, Serialize)]
pub struct PublisherSummaryInfo {
    id: String,
    links: Vec<Link>
}

impl PublisherSummaryInfo {
    pub fn from(
        handle: &PublisherHandle,
        path_publishers: &str
    ) -> PublisherSummaryInfo  {
        let mut links = Vec::new();
        let self_link = Link {
            rel: "self".to_string(),
            link: format!("{}/{}", path_publishers, handle)
        };
        links.push(self_link);

        PublisherSummaryInfo {
            id: handle.to_string(),
            links
        }
    }
}


//------------ PublisherList -------------------------------------------------

/// This type represents a list of (all) current publishers to show in the API
#[derive(Clone, Debug, Serialize)]
pub struct PublisherList {
    publishers: Vec<PublisherSummaryInfo>
}

impl PublisherList {
    pub fn build(
        publishers: &[PublisherHandle],
        path_publishers: &str
    ) -> PublisherList {
        let publishers: Vec<PublisherSummaryInfo> = publishers.iter().map(|p|
            PublisherSummaryInfo::from(&p, path_publishers)
        ).collect();

        PublisherList {
            publishers
        }
    }

    pub fn publishers(&self) -> &Vec<PublisherSummaryInfo> {
        &self.publishers
    }
}


//------------ PublisherDetails ----------------------------------------------


#[derive(Clone, Debug, Serialize)]
pub struct PublisherDetails<'a> {
    handle: &'a str,

    deactivated: bool,

    #[serde(serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: &'a uri::Rsync,

    links: Vec<Link>
}

impl<'a> PublisherDetails<'a> {
    pub fn from(
        publisher: &'a Publisher,
    ) -> PublisherDetails<'a> {
        let handle = publisher.id().as_ref();
        let base_uri = publisher.base_uri();
        let deactivated = publisher.is_deactivated();

        let links = Vec::new();

        PublisherDetails {
            handle,
            deactivated,
            base_uri,
            links
        }
    }
}
