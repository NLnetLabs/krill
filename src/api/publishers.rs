//! Support for responses sent by the Json API
//!
//! i.e. this is stuff the the server needs to serialize only, so typically
//! we can work with references here.
use std::sync::Arc;
use rpki::uri;
use crate::api::Link;
use crate::remote::id::IdCert;
use crate::util::ext_serde;


//------------ CmsAuthData ---------------------------------------------------

/// This type contains the data needed for handling RFC8183 requests/responses,
/// as well authorising the CMS in RFC8181 and RFC6492 messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CmsAuthData {
    // The optional tag in the request. None maps to empty string.
    tag:         String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert:     IdCert
}

impl CmsAuthData {
    pub fn tag(&self) -> &String {
        &self.tag
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}

impl CmsAuthData {
    pub fn new(tag: Option<String>, id_cert: IdCert) -> Self {
        let tag = tag.unwrap_or_else(String::new);
        CmsAuthData { tag, id_cert }
    }
}

impl PartialEq for CmsAuthData {
    fn eq(&self, other: &CmsAuthData) -> bool {
        self.tag == other.tag &&
            self.id_cert.to_bytes() == other.id_cert.to_bytes()
    }
}

impl Eq for CmsAuthData {}


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publisher {
    handle:        String,

    /// The token used by the API
    token:         String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:    uri::Rsync,

    cms_auth_data: Option<CmsAuthData>
}

impl Publisher {
    pub fn new(
        handle:   String,
        token:    String,
        base_uri: uri::Rsync,
        rfc8181:  Option<CmsAuthData>
    ) -> Self {
        Publisher {
            handle,
            token,
            base_uri,
            cms_auth_data: rfc8181
        }
    }
}

impl Publisher {
    pub fn handle(&self) -> &String {
        &self.handle
    }

    pub fn token(&self) -> &String {
        &self.token
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn cms_auth_data(&self) -> &Option<CmsAuthData> {
        &self.cms_auth_data
    }
}

impl PartialEq for Publisher {
    fn eq(&self, other: &Publisher) -> bool {
        self.handle == other.handle &&
            self.base_uri == other.base_uri &&
            self.cms_auth_data == other.cms_auth_data
    }
}

impl Eq for Publisher {}


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
        publishers: &'a[Arc<Publisher>],
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
