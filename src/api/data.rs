//! Data used in both requests and responses.
use rpki::uri;
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
        let tag = tag.unwrap_or("".to_string());
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
