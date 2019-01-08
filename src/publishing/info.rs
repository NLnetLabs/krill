use ext_serde;
use rpki::uri;
use crate::remote::id::IdCert;


//------------ ParentInfo ----------------------------------------------------

/// This type stores details about a parent publication server: in
/// particular, its identity and where it may be contacted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParentInfo {
    publisher_handle: String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert: IdCert,

    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
    service_uri: uri::Http,
}

impl ParentInfo {
    pub fn new(
        publisher_handle: String,
        id_cert: IdCert,
        service_uri: uri::Http,
    ) -> Self {
        ParentInfo {
            publisher_handle,
            id_cert,
            service_uri,
        }
    }

    /// The Identity Certificate used by the parent.
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    /// The service URI where the client should send requests.
    pub fn service_uri(&self) -> &uri::Http {
        &self.service_uri
    }

    /// The name the publication server prefers to go by
    pub fn publisher_handle(&self) -> &String {
        &self.publisher_handle
    }
}

impl PartialEq for ParentInfo {
    fn eq(&self, other: &ParentInfo) -> bool {
        self.id_cert.to_bytes() == other.id_cert.to_bytes() &&
        self.service_uri == other.service_uri &&
        self.publisher_handle == other.publisher_handle
    }
}

impl Eq for ParentInfo {}


//------------ MyRepoInfo ----------------------------------------------------

/// This type stores details about the repository URIs available to a
/// publisher.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MyRepoInfo {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    sia_base: uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_http_uri",
    serialize_with = "ext_serde::ser_http_uri")]
    notify_sia: uri::Http
}

impl MyRepoInfo {
    pub fn new(
        sia_base: uri::Rsync,
        notify_sia: uri::Http
    ) -> Self {
        MyRepoInfo { sia_base, notify_sia }
    }

    /// The base rsync directory under which the publisher may publish.
    // XXX TODO: Read whether standards allow sub-dirs
    pub fn sia_base(&self) -> &uri::Rsync {
        &self.sia_base
    }

    pub fn notify_sia(&self) -> &uri::Http {
        &self.notify_sia
    }
}

impl PartialEq for MyRepoInfo {
    fn eq(&self, other: &MyRepoInfo) -> bool {
        self.sia_base == other.sia_base &&
        self.notify_sia == other.notify_sia
    }
}

impl Eq for MyRepoInfo {}
