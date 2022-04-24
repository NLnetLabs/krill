use std::fmt;

use rpki::{
    ca::{idcert::IdCert, idexchange::Handle},
    repository::crypto::KeyIdentifier,
    uri,
};

//------------ Client ------------------------------------------------------

/// Represents a known client that can be proxied.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientAuth {
    // Certificate used by the client
    cert: IdCert,
}

impl ClientAuth {
    pub fn new(cert: IdCert) -> Self {
        ClientAuth { cert }
    }
    pub fn cert(&self) -> &IdCert {
        &self.cert
    }
    pub fn set_cert(&mut self, cert: IdCert) {
        self.cert = cert;
    }
}

//------------ ClientInfo ---------------------------------------------------

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientInfo {
    handle: Handle,
    auth: ClientAuth,
}

impl ClientInfo {
    pub fn new(handle: Handle, auth: ClientAuth) -> Self {
        ClientInfo { handle, auth }
    }
    pub fn unwrap(self) -> (Handle, ClientAuth) {
        (self.handle, self.auth)
    }
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
    pub fn auth(&self) -> &ClientAuth {
        &self.auth
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientInfos(Vec<ClientInfo>);

impl fmt::Display for ClientInfos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Clients: ")?;
        for client in self.0.iter() {
            let handle = client.handle();
            let auth = client.auth();
            let ski = auth.cert().ski_hex();

            writeln!(f, "   Handle: {}, Cert (ski): {}\n", handle, ski)?;
        }

        Ok(())
    }
}

//------------ CmsClientInfo -----------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CmsClientInfo {
    handle: Handle,
    server_cert: IdCert,
    key_id: KeyIdentifier,
    publication_uri: uri::Https,
}

impl CmsClientInfo {
    pub fn new(handle: Handle, cert: IdCert, key_id: KeyIdentifier, publication_uri: uri::Https) -> Self {
        CmsClientInfo {
            handle,
            server_cert: cert,
            key_id,
            publication_uri,
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
    pub fn set_handle(&mut self, handle: Handle) {
        self.handle = handle;
    }
    pub fn server_cert(&self) -> &IdCert {
        &self.server_cert
    }
    pub fn set_server_cert(&mut self, cert: IdCert) {
        self.server_cert = cert;
    }
    pub fn key_id(&self) -> KeyIdentifier {
        self.key_id
    }
    pub fn set_key_id(&mut self, key_id: KeyIdentifier) {
        self.key_id = key_id;
    }
    pub fn publication_uri(&self) -> &uri::Https {
        &self.publication_uri
    }
    pub fn set_publication_uri(&mut self, uri: uri::Https) {
        self.publication_uri = uri;
    }
}
