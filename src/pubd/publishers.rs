use rpki::{ca::idcert::IdCert, uri};

//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publisher {
    /// Used by remote RFC8181 publishers
    id_cert: IdCert,

    /// Publication jail for this publisher
    base_uri: uri::Rsync,
}

/// # Accessors
impl Publisher {
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }
}

/// # Life cycle
///
impl Publisher {
    pub fn new(id_cert: IdCert, base_uri: uri::Rsync) -> Self {
        Publisher { id_cert, base_uri }
    }
}
