//! Support for responses sent by the Json API
//!
//! i.e. this is stuff the the server needs to serialize only, so typically
//! we can work with references here.
use std::sync::Arc;
use rpki::uri;
use crate::daemon::publishers::Publisher;
use crate::remote::id::IdCert;
use crate::util::ext_serde;
use crate::util::file::CurrentFile;

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
        let id = publisher.handle().as_str();
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
pub struct Rfc8181Details<'a> {
    #[serde(serialize_with = "ext_serde::ser_http_uri")]
    service_uri: uri::Http,

    #[serde(serialize_with = "ext_serde::ser_id_cert")]
    id_cert: &'a IdCert
}


#[derive(Clone, Debug, Serialize)]
pub struct PublisherDetails<'a> {
    publisher_handle: &'a str,

    #[serde(serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: &'a uri::Rsync,

    rfc8181: Option<Rfc8181Details<'a>>,

    links: Vec<Link<'a>>
}

impl<'a> PublisherDetails<'a> {
    pub fn from(
        publisher: &'a Arc<Publisher>,
        path_publishers: &'a str,
        base_service_uri: &uri::Http
    ) -> PublisherDetails<'a> {
        let handle = publisher.handle().as_str();
        let base_uri = publisher.base_uri();

        // Derive the RFC8181 service URI.
        let service_uri = format!("{}{}", base_service_uri, handle);
        let service_uri = uri::Http::from_string(service_uri).unwrap();

        let rfc8181 = match publisher.cms_auth_data() {
            None => None,
            Some(details) => Some(
                Rfc8181Details {
                    service_uri,
                    id_cert: details.id_cert()
                }
            )
        };

        let mut links = Vec::new();
        links.push(Link {
            rel: "response.xml",
            link: format!("{}/{}/response.xml", path_publishers, handle)
        });

        PublisherDetails {
            publisher_handle: handle,
            base_uri,
            rfc8181,
            links
        }
    }
}

pub enum PublishReply {
    Success,
    List(ListReply)
}

#[derive(Serialize)]
pub struct ListReply{
    files: Vec<CurrentFile>
}

impl ListReply {
    pub fn new(files: Vec<CurrentFile>) -> Self {
        ListReply { files }
    }

    pub fn files(&self) -> &Vec<CurrentFile> {
        &self.files
    }
}