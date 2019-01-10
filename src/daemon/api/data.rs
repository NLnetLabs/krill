//! Support for the Json API

use std::sync::Arc;
use rpki::uri;
use crate::daemon::publishers::Publisher;
use crate::util::ext_serde;

//------------ Link ----------------------------------------------------------

/// Defines a link element to include as part of a links array in a Json
/// response.
#[derive(Clone, Debug, Serialize)]
pub struct Link<'a> {
    rel: &'a str,
    link: String
}


//------------ PublisherSummaryInfo ------------------------------------------

/// Defines a summary of publisher information to be used in the publisher
/// list.
#[derive(Clone, Debug, Serialize)]
pub struct PublisherSummaryInfo<'a> {
    id: &'a str,
    links: Vec<Link<'a>>
}

impl<'a> PublisherSummaryInfo<'a> {
    pub fn from(
        publisher: &'a Publisher,
        path_publishers: &'a str
    ) -> PublisherSummaryInfo<'a> {
        let id = publisher.name().as_str();
        let mut links = Vec::new();

        let response_link = Link {
            rel: "response.xml",
            link: format!("{}/{}/response.xml", path_publishers, id)
        };
        let self_link = Link {
            rel: "self",
            link: format!("{}/{}", path_publishers, id)
        };

        links.push(response_link);
        links.push(self_link);

        PublisherSummaryInfo {
            id,
            links
        }
    }
}


//------------ PublisherList -------------------------------------------------

/// This type represents a list of (all) current publishers to show in the API
#[derive(Clone, Debug, Serialize)]
pub struct PublisherList<'a> {
    publishers: Vec<PublisherSummaryInfo<'a>>
}

impl<'a> PublisherList<'a> {
    pub fn from(
        publishers: &'a Vec<Arc<Publisher>>,
        path_publishers: &'a str
    ) -> PublisherList<'a> {
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
    publisher_handle: &'a str,
    #[serde(serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: &'a uri::Rsync,
    #[serde(serialize_with = "ext_serde::ser_http_uri")]
    service_uri: &'a uri::Http,
    links: Vec<Link<'a>>
}

impl<'a> PublisherDetails<'a> {
    pub fn from(
        publisher: &'a Arc<Publisher>,
        path_publishers: &'a str
    ) -> PublisherDetails<'a> {
        let handle = publisher.name().as_str();
        let base_uri = publisher.base_uri();
        let service_uri = publisher.service_uri();

        let mut links = Vec::new();
        links.push(Link {
            rel: "response.xml",
            link: format!("{}/{}/response.xml", path_publishers, handle)
        });
        links.push(Link {
            rel: "id.cer",
            link: format!("{}/{}/id.cer", path_publishers, handle)
        });

        PublisherDetails {
            publisher_handle: handle,
            base_uri,
            service_uri,
            links
        }
    }
}
