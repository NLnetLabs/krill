//! Support for admin tasks, such as managing publishers and RFC8181 clients

use std::fmt;

use serde::{Deserialize, Serialize};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle, RepoInfo},
    },
    repository::cert::Cert,
    repository::resources::ResourceSet,
    uri,
};

use crate::commons::api::{ca::TrustAnchorLocator, rrdp::PublishElement, Timestamp};

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

/// Contains the information needed to initialize a new Publication Server
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

impl From<&PublisherHandle> for PublisherSummary {
    fn from(h: &PublisherHandle) -> Self {
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
    pub fn build(publishers: &[PublisherHandle]) -> PublisherList {
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
    handle: PublisherHandle,
    id_cert: IdCert,
    base_uri: uri::Rsync,
    current_files: Vec<PublishElement>,
}

impl PublisherDetails {
    pub fn new(
        handle: &PublisherHandle,
        id_cert: IdCert,
        base_uri: uri::Rsync,
        current_files: Vec<PublishElement>,
    ) -> Self {
        PublisherDetails {
            handle: handle.clone(),
            id_cert,
            base_uri,
            current_files,
        }
    }

    pub fn handle(&self) -> &PublisherHandle {
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
        writeln!(f, "id: {}", self.id_cert().subject_key_id())?;
        writeln!(f, "base uri: {}", self.base_uri())?;
        writeln!(f, "objects:")?;
        for e in &self.current_files {
            writeln!(f, "  {}", e.uri())?;
        }

        Ok(())
    }
}

//------------ PubServerContact ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub struct RepositoryContact {
    repository_response: idexchange::RepositoryResponse,
}

impl RepositoryContact {
    pub fn new(repository_response: idexchange::RepositoryResponse) -> Self {
        RepositoryContact { repository_response }
    }

    pub fn uri(&self) -> String {
        self.repository_response.service_uri().to_string()
    }

    pub fn response(&self) -> &idexchange::RepositoryResponse {
        &self.repository_response
    }

    pub fn repo_info(&self) -> &RepoInfo {
        self.repository_response.repo_info()
    }

    pub fn service_uri(&self) -> &idexchange::ServiceUri {
        self.repository_response.service_uri()
    }
}

impl fmt::Display for RepositoryContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "publication server at {}", self.repository_response.service_uri())
    }
}

impl std::hash::Hash for RepositoryContact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.repository_response.to_string().hash(state)
    }
}

impl std::cmp::PartialEq for RepositoryContact {
    fn eq(&self, other: &Self) -> bool {
        self.repository_response == other.repository_response
    }
}

impl std::cmp::Eq for RepositoryContact {}

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
    pub fn new(handle: ParentHandle, contact: ParentCaContact) -> Self {
        ParentCaReq { handle, contact }
    }

    pub fn handle(&self) -> &ParentHandle {
        &self.handle
    }

    pub fn contact(&self) -> &ParentCaContact {
        &self.contact
    }

    pub fn unpack(self) -> (ParentHandle, ParentCaContact) {
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
    Rfc6492(idexchange::ParentResponse),
}

impl ParentCaContact {
    pub fn for_rfc6492(response: idexchange::ParentResponse) -> Self {
        ParentCaContact::Rfc6492(response)
    }

    pub fn for_ta(ta_cert_details: TaCertDetails) -> Self {
        ParentCaContact::Ta(ta_cert_details)
    }

    pub fn parent_response(&self) -> Option<&idexchange::ParentResponse> {
        match &self {
            ParentCaContact::Ta(_) => None,
            ParentCaContact::Rfc6492(res) => Some(res),
        }
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

    pub fn parent_uri(&self) -> Option<&idexchange::ServiceUri> {
        match &self {
            ParentCaContact::Ta(_) => None,
            ParentCaContact::Rfc6492(parent) => Some(parent.service_uri()),
        }
    }
}

impl fmt::Display for ParentCaContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParentCaContact::Ta(details) => details.tal().fmt(f),
            ParentCaContact::Rfc6492(response) => response.fmt(f),
        }
    }
}

/// This type is used when saving and presenting command history
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorableParentContact {
    Ta,
    Rfc6492,
}

impl fmt::Display for StorableParentContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableParentContact::Ta => write!(f, "This CA is a TA"),
            StorableParentContact::Rfc6492 => write!(f, "RFC 6492 Parent"),
        }
    }
}

impl From<ParentCaContact> for StorableParentContact {
    fn from(parent: ParentCaContact) -> Self {
        match parent {
            ParentCaContact::Ta(_) => StorableParentContact::Ta,
            ParentCaContact::Rfc6492(_) => StorableParentContact::Rfc6492,
        }
    }
}

//------------ CertAuthInit --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInit {
    handle: CaHandle,
}

impl fmt::Display for CertAuthInit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl CertAuthInit {
    pub fn new(handle: CaHandle) -> Self {
        CertAuthInit { handle }
    }

    pub fn unpack(self) -> CaHandle {
        self.handle
    }
}

//------------ AddChildRequest -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddChildRequest {
    handle: ChildHandle,
    resources: ResourceSet,
    id_cert: IdCert,
}

impl fmt::Display for AddChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "handle '{}' resources '{}'", self.handle, self.resources,)
    }
}

impl AddChildRequest {
    pub fn new(handle: ChildHandle, resources: ResourceSet, id_cert: IdCert) -> Self {
        AddChildRequest {
            handle,
            resources,
            id_cert,
        }
    }

    pub fn unpack(self) -> (ChildHandle, ResourceSet, IdCert) {
        (self.handle, self.resources, self.id_cert)
    }
}

//------------ UpdateChildRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateChildRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    id_cert: Option<IdCert>,

    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<ResourceSet>,

    #[serde(skip_serializing_if = "Option::is_none")]
    suspend: Option<bool>,
}

impl UpdateChildRequest {
    pub fn new(id_cert: Option<IdCert>, resources: Option<ResourceSet>, suspend: Option<bool>) -> Self {
        UpdateChildRequest {
            id_cert,
            resources,
            suspend,
        }
    }
    pub fn id_cert(id_cert: IdCert) -> Self {
        UpdateChildRequest {
            id_cert: Some(id_cert),
            resources: None,
            suspend: None,
        }
    }

    pub fn resources(resources: ResourceSet) -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: Some(resources),
            suspend: None,
        }
    }

    pub fn suspend() -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: None,
            suspend: Some(true),
        }
    }

    pub fn unsuspend() -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: None,
            suspend: Some(false),
        }
    }

    pub fn unpack(self) -> (Option<IdCert>, Option<ResourceSet>, Option<bool>) {
        (self.id_cert, self.resources, self.suspend)
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
        if let Some(suspend) = self.suspend {
            write!(f, "change suspend status to: {}", suspend)?;
        }
        Ok(())
    }
}

//------------ ServerInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerInfo {
    version: String,
    started: Timestamp,
}

impl ServerInfo {
    pub fn new(version: &str, started: Timestamp) -> Self {
        ServerInfo {
            version: version.to_string(),
            started,
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn started(&self) -> Timestamp {
        self.started
    }
}

impl fmt::Display for ServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Version: {}\nStarted: {}", self.version(), self.started.to_rfc3339())
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::convert::TryFrom;
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn should_accept_rfc8183_handle() {
        // See appendix A of RFC8183
        // handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
        CaHandle::from_str("abcDEF012/\\-_").unwrap();
    }

    #[test]
    fn should_reject_invalid_handle() {
        // See appendix A of RFC8183
        // handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
        assert!(CaHandle::from_str("&").is_err());
    }

    #[test]
    fn should_make_file_system_safe() {
        let handle = CaHandle::from_str("abcDEF012/\\-_").unwrap();
        let expected_path_buf = PathBuf::from("abcDEF012+=-_");
        assert_eq!(handle.to_path_buf(), expected_path_buf);
    }

    #[test]
    fn should_make_handle_from_dir() {
        let path = PathBuf::from("a/b/abcDEF012+=-_");
        let handle = CaHandle::try_from(&path).unwrap();
        let expected_handle = CaHandle::from_str("abcDEF012/\\-_").unwrap();
        assert_eq!(handle, expected_handle);
    }
}
