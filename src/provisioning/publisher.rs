//! Responsible for storing and retrieving Publisher information.
use ext_serde;
use rpki::remote::idcert::IdCert;
use rpki::uri;


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publisher {
    name:       String,

    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:   uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert:    IdCert
}

impl Publisher {
    pub fn new(name: String, base_uri: uri::Rsync, id_cert: IdCert) -> Self {
        Publisher { name, base_uri, id_cert }
    }

    /// Returns a new Publisher that is the same as this Publisher, except
    /// that it has an updated IdCert
    pub fn with_new_id_cert(&self, id_cert: IdCert) -> Self {
        Publisher {
            name: self.name.clone(),
            base_uri: self.base_uri.clone(),
            id_cert
        }
    }
}

impl Publisher {
    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}