//! Support for admin tasks, such as managing publishers and RFC8181 clients

use std::fmt;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};

use bytes::Bytes;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::cert::Cert;
use rpki::crypto::Signer;
use rpki::uri;

use crate::commons::api::ca::ResourceSet;
use crate::commons::api::ca::TrustAnchorLocator;
use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::Link;
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc8183;
use crate::commons::remote::rfc8183::ChildRequest;

//------------ Handle --------------------------------------------------------

pub type ParentHandle = Handle;
pub type ChildHandle = Handle;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Handle {
    name: Bytes,
}

impl Handle {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    pub fn from_str_unsafe(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }

    pub fn from_path_unsafe(path: &PathBuf) -> Self {
        let path = path.file_name().unwrap();
        let s = path.to_string_lossy().to_string();
        let s = s.replace("+", "/");
        let s = s.replace("=", "\\");
        Self::from_str(&s).unwrap()
    }

    /// We replace "/" with "+" and "\" with "=" to make file system
    /// safe names.
    pub fn to_path_buf(&self) -> PathBuf {
        let s = self.to_string();
        let s = s.replace("/", "+");
        let s = s.replace("\\", "=");
        PathBuf::from(s)
    }
}

impl FromStr for Handle {
    type Err = InvalidHandle;

    /// Accepted pattern: [-_A-Za-z0-9/]{1,255}
    /// See Appendix A of RFC8183.
    ///
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'/' || b == b'\\')
            && !s.is_empty()
            && s.len() < 256
        {
            Ok(Handle {
                name: Bytes::from(s),
            })
        } else {
            Err(InvalidHandle)
        }
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        unsafe { from_utf8_unchecked(self.name.as_ref()) }
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Handle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D>(deserializer: D) -> Result<Handle, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let handle = Handle::from_str(&string).map_err(de::Error::custom)?;
        Ok(handle)
    }
}

#[derive(Debug, Display)]
#[display(fmt = "Handle MUST have pattern: [-_A-Za-z0-9/]{{1,255}}")]
pub struct InvalidHandle;

//------------ Token ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Token(String);

impl Token {
    pub fn random<S: Signer>(signer: &S) -> Self {
        let mut res = <[u8; 20]>::default();
        signer.rand(&mut res).unwrap();
        let string = hex::encode(res);
        Token(string)
    }
}

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

//------------ PublisherRequest ----------------------------------------------

/// This type defines request for a new Publisher (CA that is allowed to
/// publish).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherRequest {
    handle: Handle,
    token: Token,
    base_uri: uri::Rsync,
}

impl PublisherRequest {
    pub fn new(handle: Handle, token: Token, base_uri: uri::Rsync) -> Self {
        PublisherRequest {
            handle,
            token,
            base_uri,
        }
    }
}

impl PublisherRequest {
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    /// Return all the values (handle, token, base_uri).
    pub fn unwrap(self) -> (Handle, Token, uri::Rsync) {
        (self.handle, self.token, self.base_uri)
    }
}

impl PartialEq for PublisherRequest {
    fn eq(&self, other: &PublisherRequest) -> bool {
        self.handle == other.handle && self.base_uri == other.base_uri
    }
}

impl Eq for PublisherRequest {}

//------------ PublisherSummaryInfo ------------------------------------------

/// Defines a summary of publisher information to be used in the publisher
/// list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherSummary {
    id: String,
    links: Vec<Link>,
}

impl PublisherSummary {
    pub fn from(handle: &Handle, path_publishers: &str) -> PublisherSummary {
        let mut links = Vec::new();
        let self_link = Link {
            rel: "self".to_string(),
            link: format!("{}/{}", path_publishers, handle),
        };
        links.push(self_link);

        PublisherSummary {
            id: handle.to_string(),
            links,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

//------------ PublisherList -------------------------------------------------

/// This type represents a list of (all) current publishers to show in the API
#[derive(Clone, Eq, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublisherList {
    publishers: Vec<PublisherSummary>,
}

impl PublisherList {
    pub fn build(publishers: &[Handle], path_publishers: &str) -> PublisherList {
        let publishers: Vec<PublisherSummary> = publishers
            .iter()
            .map(|p| PublisherSummary::from(&p, path_publishers))
            .collect();

        PublisherList { publishers }
    }

    pub fn publishers(&self) -> &Vec<PublisherSummary> {
        &self.publishers
    }
}

//------------ PublisherDetails ----------------------------------------------

/// This type defines the publisher details for:
/// /api/v1/publishers/{handle}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherDetails {
    handle: String,
    deactivated: bool,
    base_uri: uri::Rsync,
    current_files: Vec<PublishElement>,
}

impl PublisherDetails {
    pub fn new(
        handle: &str,
        deactivated: bool,
        base_uri: &uri::Rsync,
        current_files: Vec<PublishElement>,
    ) -> Self {
        PublisherDetails {
            handle: handle.to_string(),
            deactivated,
            base_uri: base_uri.clone(),
            current_files,
        }
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn deactivated(&self) -> bool {
        self.deactivated
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn current_files(&self) -> &Vec<PublishElement> {
        &self.current_files
    }
}

impl PartialEq for PublisherDetails {
    fn eq(&self, other: &PublisherDetails) -> bool {
        match (serde_json::to_string(self), serde_json::to_string(other)) {
            (Ok(ser_self), Ok(ser_other)) => ser_self == ser_other,
            _ => false,
        }
    }
}

impl Eq for PublisherDetails {}

//------------ PublisherClientRequest ----------------------------------------

/// This type defines request for a new Publisher client, i.e. the proxy that
/// is used by an embedded CA to do the actual publication.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherClientRequest {
    handle: Handle,
    server_info: PubServerContact,
}

impl PublisherClientRequest {
    pub fn new(handle: Handle, server_info: PubServerContact) -> Self {
        PublisherClientRequest {
            handle,
            server_info,
        }
    }

    pub fn embedded(handle: Handle) -> Self {
        let server_info = PubServerContact::embedded();
        PublisherClientRequest {
            handle,
            server_info,
        }
    }

    pub fn krill(handle: Handle, service_uri: uri::Https, token: Token) -> Self {
        let server_info = PubServerContact::for_krill(service_uri, token);
        PublisherClientRequest {
            handle,
            server_info,
        }
    }

    pub fn unwrap(self) -> (Handle, PubServerContact) {
        (self.handle, self.server_info)
    }
}

//------------ PubServerInfo -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Display, Serialize)]
pub enum PubServerContact {
    #[display(fmt = "Embedded server.")]
    Embedded,

    #[display(fmt = "Remote Krill at: {}, using token: {}", _0, _1)]
    KrillServer(uri::Https, Token),
}

impl PubServerContact {
    pub fn embedded() -> Self {
        PubServerContact::Embedded
    }

    pub fn for_krill(service_uri: uri::Https, token: Token) -> Self {
        PubServerContact::KrillServer(service_uri, token)
    }
}

//------------ ParentCaReq ---------------------------------------------------

/// This type defines all parent ca details needed to add a parent to a CA
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddParentRequest {
    handle: Handle,           // the local name the child gave to the parent
    contact: ParentCaContact, // where the parent can be contacted
}

impl AddParentRequest {
    pub fn new(handle: Handle, contact: ParentCaContact) -> Self {
        AddParentRequest { handle, contact }
    }

    pub fn unwrap(self) -> (Handle, ParentCaContact) {
        (self.handle, self.contact)
    }
}

//------------ TaCertDetails -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaCertDetails {
    cert: Cert,
    resources: ResourceSet,
    tal: TrustAnchorLocator,
}

impl TaCertDetails {
    pub fn new(cert: Cert, resources: ResourceSet, tal: TrustAnchorLocator) -> Self {
        TaCertDetails {
            cert,
            resources,
            tal,
        }
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }
}

impl PartialEq for TaCertDetails {
    fn eq(&self, other: &Self) -> bool {
        self.tal == other.tal
            && self.resources == other.resources
            && self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for TaCertDetails {}

//------------ ParentCaContact -----------------------------------------------

/// This type contains the information needed to contact the parent ca
/// for resource provisioning requests (RFC6492).
#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ParentCaContact {
    #[display(fmt = "This CA is a TA")]
    Ta(TaCertDetails),

    #[display(fmt = "Embedded parent")]
    Embedded,

    #[display(fmt = "RFC 6492 Parent")]
    Rfc6492(rfc8183::ParentResponse),
}

impl ParentCaContact {
    pub fn for_rfc6492(response: rfc8183::ParentResponse) -> Self {
        ParentCaContact::Rfc6492(response)
    }

    pub fn to_ta_cert(&self) -> &Cert {
        match &self {
            ParentCaContact::Ta(details) => details.cert(),
            _ => panic!("Not a TA parent"),
        }
    }
}

//------------ CertAuthInit --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInit {
    handle: Handle,
    token: Token,
    pub_mode: CertAuthPubMode,
}

impl CertAuthInit {
    pub fn new(handle: Handle, token: Token, pub_mode: CertAuthPubMode) -> Self {
        CertAuthInit {
            handle,
            token,
            pub_mode,
        }
    }

    pub fn unwrap(self) -> (Handle, Token, CertAuthPubMode) {
        (self.handle, self.token, self.pub_mode)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CertAuthPubMode {
    Embedded,
}

//------------ AddChildRequest -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[display(fmt = "handle '{}' resources '{}' kind '{}'", handle, resources, auth)]
pub struct AddChildRequest {
    handle: Handle,
    resources: ResourceSet,
    auth: ChildAuthRequest,
}

impl AddChildRequest {
    pub fn new(handle: Handle, resources: ResourceSet, auth: ChildAuthRequest) -> Self {
        AddChildRequest {
            handle,
            resources,
            auth,
        }
    }

    pub fn unwrap(self) -> (Handle, ResourceSet, ChildAuthRequest) {
        (self.handle, self.resources, self.auth)
    }
}

//------------ ChildAuthRequest ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ChildAuthRequest {
    #[display(fmt = "embedded")]
    Embedded,
    #[display(fmt = "{}", _0)]
    Rfc8183(ChildRequest),
}

//------------ UpdateChildRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateChildRequest {
    id_cert: Option<IdCert>,
    resources: Option<ResourceSet>,
    force: bool,
}

impl UpdateChildRequest {
    pub fn graceful(id_cert: Option<IdCert>, resources: Option<ResourceSet>) -> Self {
        UpdateChildRequest {
            id_cert,
            resources,
            force: false,
        }
    }

    pub fn force(id_cert: Option<IdCert>, resources: Option<ResourceSet>) -> Self {
        UpdateChildRequest {
            id_cert,
            resources,
            force: true,
        }
    }

    pub fn unpack(self) -> (Option<IdCert>, Option<ResourceSet>, bool) {
        (self.id_cert, self.resources, self.force)
    }

    pub fn is_force(&self) -> bool {
        self.force
    }
}

impl fmt::Display for UpdateChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.id_cert.is_some() {
            write!(f, "new id cert ")?;
        }
        if let Some(resources) = &self.resources {
            write!(f, "new resources: {} ", resources)?;
        }
        if self.force {
            write!(f, "<forced>")?;
        }
        Ok(())
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_accept_rfc8183_handle() {
        // See appendix A of RFC8183
        // handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
        Handle::from_str("abcDEF012/\\-_").unwrap();
    }

    #[test]
    fn should_reject_invalid_handle() {
        // See appendix A of RFC8183
        // handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
        assert!(Handle::from_str("&").is_err());
    }

    #[test]
    fn should_make_file_system_safe() {
        let handle = Handle::from_str("abcDEF012/\\-_").unwrap();
        let expected_path_buf = PathBuf::from("abcDEF012+=-_");
        assert_eq!(handle.to_path_buf(), expected_path_buf);
    }

    #[test]
    fn should_make_handle_from_dir() {
        let path = PathBuf::from("a/b/abcDEF012+=-_");
        let handle = Handle::from_path_unsafe(&path);
        let expected_handle = Handle::from_str("abcDEF012/\\-_").unwrap();
        assert_eq!(handle, expected_handle);
    }
}
