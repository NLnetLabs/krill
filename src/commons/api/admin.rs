//! Support for admin tasks, such as managing publishers and RFC8181 clients

use std::convert::TryFrom;
use std::fmt;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};
use std::sync::Arc;

use chrono::{DateTime, NaiveDateTime, Utc};
use rfc8183::ServiceUri;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::cert::Cert;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::ca::{ResourceSet, TrustAnchorLocator};
use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::RepoInfo;
use crate::commons::crypto::IdCert;
use crate::commons::remote::rfc8183;

//------------ Handle --------------------------------------------------------

// Some type aliases that help make the use of Handles more explicit.
pub type ParentHandle = Handle;
pub type ChildHandle = Handle;
pub type PublisherHandle = Handle;
pub type RepositoryHandle = Handle;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Handle {
    name: Arc<str>,
}

impl Handle {
    pub fn as_str(&self) -> &str {
        self.as_ref()
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

impl TryFrom<&PathBuf> for Handle {
    type Error = InvalidHandle;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        if let Some(path) = path.file_name() {
            let s = path.to_string_lossy().to_string();
            let s = s.replace("+", "/");
            let s = s.replace("=", "\\");
            Self::from_str(&s)
        } else {
            Err(InvalidHandle)
        }
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
            Ok(Handle { name: s.into() })
        } else {
            Err(InvalidHandle)
        }
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl AsRef<[u8]> for Handle {
    fn as_ref(&self) -> &[u8] {
        self.name.as_bytes()
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

#[derive(Debug)]
pub struct InvalidHandle;

impl fmt::Display for InvalidHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle MUST have pattern: [-_A-Za-z0-9/]{{1,255}}")
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

//------------ PublicationServerUris -----------------------------------------

/// Contains the information needed to initialise a new Publication Server
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationServerUris {
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl PublicationServerUris {
    pub fn new(rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync) -> Self {
        PublicationServerUris {
            rrdp_base_uri,
            rsync_jail,
        }
    }

    pub fn rrdp_base_uri(&self) -> &uri::Https {
        &self.rrdp_base_uri
    }

    pub fn rsync_jail(&self) -> &uri::Rsync {
        &self.rsync_jail
    }

    pub fn unpack(self) -> (uri::Https, uri::Rsync) {
        (self.rrdp_base_uri, self.rsync_jail)
    }
}

//------------ PublisherSummaryInfo ------------------------------------------

/// Defines a summary of publisher information to be used in the publisher
/// list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherSummary {
    handle: PublisherHandle,
}

impl PublisherSummary {
    pub fn handle(&self) -> &PublisherHandle {
        &self.handle
    }
}

impl From<&Handle> for PublisherSummary {
    fn from(h: &Handle) -> Self {
        PublisherSummary { handle: h.clone() }
    }
}

//------------ PublisherList -------------------------------------------------

/// This type represents a list of (all) current publishers to show in the API
#[derive(Clone, Eq, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublisherList {
    publishers: Vec<PublisherSummary>,
}

impl PublisherList {
    pub fn build(publishers: &[Handle]) -> PublisherList {
        let publishers: Vec<PublisherSummary> = publishers.iter().map(|p| p.into()).collect();

        PublisherList { publishers }
    }

    pub fn publishers(&self) -> &Vec<PublisherSummary> {
        &self.publishers
    }
}

impl fmt::Display for PublisherList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Publishers: ")?;
        let mut first = true;
        for p in self.publishers() {
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
            write!(f, "{}", p.handle().as_str())?;
        }
        Ok(())
    }
}

//------------ PublisherDetails ----------------------------------------------

/// This type defines the publisher details for:
/// /api/v1/publishers/{handle}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherDetails {
    handle: Handle,
    id_cert: IdCert,
    base_uri: uri::Rsync,
    current_files: Vec<PublishElement>,
}

impl PublisherDetails {
    pub fn new(handle: &Handle, id_cert: IdCert, base_uri: &uri::Rsync, current_files: Vec<PublishElement>) -> Self {
        PublisherDetails {
            handle: handle.clone(),
            id_cert,
            base_uri: base_uri.clone(),
            current_files,
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }
    pub fn current_files(&self) -> &Vec<PublishElement> {
        &self.current_files
    }
}

impl fmt::Display for PublisherDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "handle: {}", self.handle())?;
        writeln!(f, "id: {}", self.id_cert().ski_hex())?;
        writeln!(f, "base uri: {}", self.base_uri().to_string())?;

        Ok(())
    }
}

//------------ PublisherClientRequest ----------------------------------------

/// This type defines request for a new Publisher client, i.e. the proxy that
/// is used by an embedded CA to do the actual publication.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherClientRequest {
    handle: Handle,
    server_info: RepositoryContact,
}

impl PublisherClientRequest {
    pub fn rfc8183(handle: Handle, response: rfc8183::RepositoryResponse) -> Self {
        let server_info = RepositoryContact::rfc8181(response);
        PublisherClientRequest { handle, server_info }
    }

    pub fn embedded(handle: Handle, repo_info: RepoInfo) -> Self {
        let server_info = RepositoryContact::embedded(repo_info);
        PublisherClientRequest { handle, server_info }
    }

    pub fn unwrap(self) -> (Handle, RepositoryContact) {
        (self.handle, self.server_info)
    }
}

//------------ RepositoryUpdate ----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryUpdate {
    Embedded,
    Rfc8181(rfc8183::RepositoryResponse),
}

impl RepositoryUpdate {
    pub fn embedded() -> Self {
        RepositoryUpdate::Embedded
    }

    pub fn rfc8181(response: rfc8183::RepositoryResponse) -> Self {
        RepositoryUpdate::Rfc8181(response)
    }

    pub fn as_response_opt(&self) -> Option<&rfc8183::RepositoryResponse> {
        match self {
            RepositoryUpdate::Embedded => None,
            RepositoryUpdate::Rfc8181(res) => Some(res),
        }
    }
}

//------------ PubServerContact ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum RepositoryContact {
    Embedded {
        info: RepoInfo,
    },
    Rfc8181 {
        server_response: rfc8183::RepositoryResponse,
    },
}

impl RepositoryContact {
    pub fn uri(&self) -> String {
        match self {
            RepositoryContact::Embedded { .. } => "embedded".to_string(),
            RepositoryContact::Rfc8181 { server_response } => server_response.service_uri().to_string(),
        }
    }

    pub fn embedded(info: RepoInfo) -> Self {
        RepositoryContact::Embedded { info }
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self, RepositoryContact::Embedded { .. })
    }

    pub fn rfc8181(server_response: rfc8183::RepositoryResponse) -> Self {
        RepositoryContact::Rfc8181 { server_response }
    }

    pub fn is_rfc8183(&self) -> bool {
        !self.is_embedded()
    }

    pub fn as_reponse_opt(&self) -> Option<&rfc8183::RepositoryResponse> {
        match self {
            RepositoryContact::Embedded { .. } => None,
            RepositoryContact::Rfc8181 { server_response } => Some(server_response),
        }
    }

    pub fn repo_info(&self) -> &RepoInfo {
        match self {
            RepositoryContact::Embedded { info } => info,
            RepositoryContact::Rfc8181 { server_response } => server_response.repo_info(),
        }
    }

    pub fn service_uri_opt(&self) -> Option<&ServiceUri> {
        match self {
            RepositoryContact::Embedded { .. } => None,
            RepositoryContact::Rfc8181 { server_response } => Some(server_response.service_uri()),
        }
    }
}

impl fmt::Display for RepositoryContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            RepositoryContact::Embedded { .. } => "embedded publication server".to_string(),
            RepositoryContact::Rfc8181 { server_response } => {
                format!("remote publication server at {}", server_response.service_uri())
            }
        };
        write!(f, "{}", msg)
    }
}

//------------ ParentCaReq ---------------------------------------------------

/// This type defines all parent ca details needed to add a parent to a CA
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentCaReq {
    handle: ParentHandle,     // the local name the child gave to the parent
    contact: ParentCaContact, // where the parent can be contacted
}

impl fmt::Display for ParentCaReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parent '{}' contact '{}'", self.handle, self.contact)
    }
}

impl ParentCaReq {
    pub fn new(handle: Handle, contact: ParentCaContact) -> Self {
        ParentCaReq { handle, contact }
    }

    pub fn handle(&self) -> &ParentHandle {
        &self.handle
    }

    pub fn contact(&self) -> &ParentCaContact {
        &self.contact
    }

    pub fn unpack(self) -> (Handle, ParentCaContact) {
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
        TaCertDetails { cert, resources, tal }
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum ParentCaContact {
    Ta(TaCertDetails),
    Embedded,
    Rfc6492(rfc8183::ParentResponse),
}

impl ParentCaContact {
    pub fn for_rfc6492(response: rfc8183::ParentResponse) -> Self {
        ParentCaContact::Rfc6492(response)
    }

    pub fn embedded() -> Self {
        ParentCaContact::Embedded
    }

    pub fn for_ta(ta_cert_details: TaCertDetails) -> Self {
        ParentCaContact::Ta(ta_cert_details)
    }

    pub fn to_ta_cert(&self) -> &Cert {
        match &self {
            ParentCaContact::Ta(details) => details.cert(),
            _ => panic!("Not a TA parent"),
        }
    }

    pub fn is_ta(&self) -> bool {
        matches!(*self, ParentCaContact::Ta(_))
    }
}

impl fmt::Display for ParentCaContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParentCaContact::Ta(details) => write!(f, "{}", details.tal()),
            ParentCaContact::Embedded => write!(f, "Embedded parent"),
            ParentCaContact::Rfc6492(response) => {
                let bytes = response.encode_vec();
                let xml = unsafe { from_utf8_unchecked(&bytes) };
                write!(f, "{}", xml)
            }
        }
    }
}

/// This type is used when saving and presenting command history
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorableParentContact {
    Ta,
    Embedded,
    Rfc6492,
}

impl fmt::Display for StorableParentContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableParentContact::Ta => write!(f, "This CA is a TA"),
            StorableParentContact::Embedded => write!(f, "Embedded parent"),
            StorableParentContact::Rfc6492 => write!(f, "RFC 6492 Parent"),
        }
    }
}

impl From<ParentCaContact> for StorableParentContact {
    fn from(parent: ParentCaContact) -> Self {
        match parent {
            ParentCaContact::Ta(_) => StorableParentContact::Ta,
            ParentCaContact::Embedded => StorableParentContact::Embedded,
            ParentCaContact::Rfc6492(_) => StorableParentContact::Rfc6492,
        }
    }
}

//------------ CertAuthInit --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInit {
    handle: Handle,
}

impl fmt::Display for CertAuthInit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl CertAuthInit {
    pub fn new(handle: Handle) -> Self {
        CertAuthInit { handle }
    }

    pub fn unpack(self) -> Handle {
        self.handle
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum CertAuthPubMode {
    Embedded,
    Rfc8181(IdCert),
}

//------------ AddChildRequest -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddChildRequest {
    handle: Handle,
    resources: ResourceSet,
    auth: ChildAuthRequest,
}

impl fmt::Display for AddChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "handle '{}' resources '{}' kind '{}'",
            self.handle, self.resources, self.auth
        )
    }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum ChildAuthRequest {
    Embedded,
    Rfc8183(rfc8183::ChildRequest),
}

impl fmt::Display for ChildAuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChildAuthRequest::Embedded => write!(f, "embedded"),
            ChildAuthRequest::Rfc8183(req) => req.fmt(f),
        }
    }
}

//------------ UpdateChildRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateChildRequest {
    id_cert: Option<IdCert>,
    resources: Option<ResourceSet>,
}

impl UpdateChildRequest {
    pub fn new(id_cert: Option<IdCert>, resources: Option<ResourceSet>) -> Self {
        UpdateChildRequest { id_cert, resources }
    }
    pub fn id_cert(id_cert: IdCert) -> Self {
        UpdateChildRequest {
            id_cert: Some(id_cert),
            resources: None,
        }
    }

    pub fn resources(resources: ResourceSet) -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: Some(resources),
        }
    }

    pub fn unpack(self) -> (Option<IdCert>, Option<ResourceSet>) {
        (self.id_cert, self.resources)
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
        Ok(())
    }
}

//------------ ServerInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerInfo {
    version: String,
    started: i64,
}

impl ServerInfo {
    pub fn new(version: &str, started: Time) -> Self {
        ServerInfo {
            version: version.to_string(),
            started: started.timestamp(),
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn started(&self) -> i64 {
        self.started
    }
}

impl fmt::Display for ServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.started(), 0), Utc);
        let started = Time::new(dt);
        write!(f, "Version: {}\nStarted: {}", self.version(), started.to_rfc3339())
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
        let handle = Handle::try_from(&path).unwrap();
        let expected_handle = Handle::from_str("abcDEF012/\\-_").unwrap();
        assert_eq!(handle, expected_handle);
    }
}
