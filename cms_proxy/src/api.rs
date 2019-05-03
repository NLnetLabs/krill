use std::fmt;

use rpki::uri;

use krill_commons::api::admin::AggregateHandle;
use krill_commons::util::softsigner::SignerKeyId;

use crate::id::IdCert;


//------------ ClientHandle --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientHandle(String);

impl From<&str> for ClientHandle {
    fn from(s: &str) -> Self {
        ClientHandle(s.to_string())
    }
}

impl From<&AggregateHandle> for ClientHandle {
    fn from(handle: &AggregateHandle) -> Self { ClientHandle(handle.name().to_string())}
}

impl fmt::Display for ClientHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


//------------ Token ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Token(String);

impl From<&str> for Token {
    fn from(s: &str) -> Self {
        Token(s.to_string())
    }
}

impl From<String> for Token {
    fn from(s: String) -> Self {
        Token(s)
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ Client ------------------------------------------------------

/// Represents a known client that can be proxied.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientAuth {
    // Certificate used by the client
    cert: IdCert,

    // Token known for this client by the krill server
    token: Token
}

impl ClientAuth {
    pub fn new(
        cert: IdCert,
        token: Token,
    ) -> Self {
        ClientAuth { cert, token }
    }
    pub fn cert(&self) -> &IdCert { &self.cert }
    pub fn set_cert(&mut self, cert: IdCert) { self.cert = cert; }
    pub fn token(&self) -> &Token { & self.token }
    pub fn set_token(&mut self, token: Token) { self.token = token; }
}


//------------ ClientInfo ---------------------------------------------------

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientInfo {
    handle: ClientHandle,
    auth: ClientAuth
}

impl ClientInfo {
    pub fn new(handle: ClientHandle, auth: ClientAuth) -> Self {
        ClientInfo { handle, auth }
    }
    pub fn unwrap(self) -> (ClientHandle, ClientAuth ) {
        (self.handle, self.auth)
    }
    pub fn handle(&self) -> &ClientHandle { &self.handle }
    pub fn auth(&self) -> &ClientAuth { &self.auth }
}

//------------ CmsClientInfo -----------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CmsClientInfo {
    handle: ClientHandle,
    server_cert: IdCert,
    key_id: SignerKeyId,
    publication_uri: uri::Https,
}

impl CmsClientInfo {
    pub fn new(
        handle: ClientHandle,
        cert: IdCert,
        key_id: SignerKeyId,
        publication_uri: uri::Https
    ) -> Self {
        CmsClientInfo { handle, server_cert: cert, key_id, publication_uri }
    }

    pub fn handle(&self) -> &ClientHandle { &self.handle }
    pub fn set_handle(&mut self, handle: ClientHandle) { self.handle = handle; }
    pub fn server_cert(&self) -> &IdCert { &self.server_cert }
    pub fn set_server_cert(&mut self, cert: IdCert) { self.server_cert = cert; }
    pub fn key_id(&self) -> &SignerKeyId { &self.key_id }
    pub fn set_key_id(&mut self, key_id: SignerKeyId) { self.key_id = key_id; }
    pub fn publication_uri(&self) -> &uri::Https { &self.publication_uri }
    pub fn set_publication_uri(&mut self, uri: uri::Https) { self.publication_uri = uri; }
}