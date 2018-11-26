//! Responsible for storing and retrieving Publisher information.
use ext_serde;
use rpki::remote::idcert::IdCert;
use rpki::uri;


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publisher {
    // The optional tag in the request. None maps to empty string.
    tag:        String,

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
    pub fn new(
        tag: Option<String>,
        name: String,
        base_uri: uri::Rsync,
        id_cert: IdCert
    ) -> Self {

        let tag = match tag {
            None => "".to_string(),
            Some(t) => t
        };

        Publisher {
            tag,
            name,
            base_uri,
            id_cert
        }
    }

    /// Returns a new Publisher that is the same as this Publisher, except
    /// that it has an updated IdCert
    pub fn with_new_id_cert(&self, id_cert: IdCert) -> Self {
        Publisher {
            tag: self.tag.clone(),
            name: self.name.clone(),
            base_uri: self.base_uri.clone(),
            id_cert
        }
    }
}

impl Publisher {
    pub fn tag(&self) -> Option<String> {
        let tag = &self.tag;
        if tag.is_empty() {
            None
        } else {
            Some(tag.clone())
        }
    }

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

impl PartialEq for Publisher {
    fn eq(&self, other: &Publisher) -> bool {
        self.name == other.name &&
        self.base_uri == other.base_uri &&
        self.id_cert.to_bytes() == other.id_cert.to_bytes()
    }
}

impl Eq for Publisher {}