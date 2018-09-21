use rpki::remote::idcert::IdCert;

/// This type defines Client CAs that are allowed to publish.
pub struct Client {
    id: IdCert
}

