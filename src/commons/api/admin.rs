//! Support for admin tasks, such as managing publishers and RFC8181 clients

use std::{convert::TryFrom, fmt};

use serde::{Deserialize, Serialize};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{self, ServiceUri},
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle, RepoInfo},
    },
    crypto::PublicKey,
    repository::resources::ResourceSet,
    uri,
};

use crate::commons::{
    api::{rrdp::PublishElement, IdCertInfo, Timestamp},
    error::Error,
    KrillResult,
};

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
    id_cert: IdCertInfo,
    base_uri: uri::Rsync,
    current_files: Vec<PublishElement>,
}

impl PublisherDetails {
    pub fn new(
        handle: &PublisherHandle,
        id_cert: IdCertInfo,
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
    pub fn id_cert(&self) -> &IdCertInfo {
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
        writeln!(f, "id: {}", self.id_cert.public_key().key_identifier())?;
        writeln!(f, "base uri: {}", self.base_uri())?;
        writeln!(f, "objects:")?;
        for e in &self.current_files {
            writeln!(f, "  {}", e.uri())?;
        }

        Ok(())
    }
}

//------------ PublicationServerInfo -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationServerInfo {
    public_key: PublicKey,
    service_uri: ServiceUri,
}

impl PublicationServerInfo {
    pub fn new(public_key: PublicKey, service_uri: ServiceUri) -> Self {
        PublicationServerInfo {
            public_key,
            service_uri,
        }
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }
}

//------------ ApiRepositoryContact ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
/// This type is provided so that we do not need to change the the API for
///  uploading repository responses as it was in <0.10.0
pub struct ApiRepositoryContact {
    repository_response: idexchange::RepositoryResponse,
}

impl ApiRepositoryContact {
    pub fn new(repository_response: idexchange::RepositoryResponse) -> Self {
        ApiRepositoryContact { repository_response }
    }
}

impl TryFrom<ApiRepositoryContact> for RepositoryContact {
    type Error = Error;

    fn try_from(api_contact: ApiRepositoryContact) -> KrillResult<Self> {
        RepositoryContact::for_response(api_contact.repository_response)
    }
}

//------------ RepositoryContact ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryContact {
    repo_info: RepoInfo,
    server_info: PublicationServerInfo,
}

impl RepositoryContact {
    pub fn new(repo_info: RepoInfo, server_info: PublicationServerInfo) -> Self {
        RepositoryContact { repo_info, server_info }
    }

    pub fn for_response(repository_response: idexchange::RepositoryResponse) -> KrillResult<Self> {
        let id_cert = repository_response.validate().map_err(Error::rfc8183)?;
        let public_key = id_cert.public_key().clone();
        let service_uri = repository_response.service_uri().clone();

        let repo_info = repository_response.repo_info().clone();
        let server_info = PublicationServerInfo {
            public_key,
            service_uri,
        };

        Ok(RepositoryContact { repo_info, server_info })
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn server_info(&self) -> &PublicationServerInfo {
        &self.server_info
    }
}

impl fmt::Display for RepositoryContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "publication server at {}", self.server_info.service_uri)
    }
}

impl std::hash::Hash for RepositoryContact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.server_info.service_uri.as_str().hash(state); // unique for each repo contact
    }
}

impl PartialEq for RepositoryContact {
    fn eq(&self, other: &Self) -> bool {
        self.repo_info == other.repo_info && self.server_info == other.server_info
    }
}

impl Eq for RepositoryContact {}

impl From<RepositoryContact> for RepoInfo {
    fn from(contact: RepositoryContact) -> Self {
        contact.repo_info
    }
}

//------------ ParentCaReq ---------------------------------------------------

/// This type defines all parent ca details needed to add a parent to a CA
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentCaReq {
    handle: ParentHandle, // the child local name for the parent
    #[serde(alias = "contact")] // stay backward compatible to pre 0.10.0
    response: idexchange::ParentResponse,
}

impl fmt::Display for ParentCaReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parent '{}' contact '{}'", self.handle, self.response)
    }
}

impl ParentCaReq {
    pub fn new(handle: ParentHandle, response: idexchange::ParentResponse) -> Self {
        ParentCaReq { handle, response }
    }

    pub fn handle(&self) -> &ParentHandle {
        &self.handle
    }

    pub fn response(&self) -> &idexchange::ParentResponse {
        &self.response
    }

    pub fn unpack(self) -> (ParentHandle, idexchange::ParentResponse) {
        (self.handle, self.response)
    }
}

//------------ ParentServerInfo ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentServerInfo {
    /// The URI where the CA needs to send its RFC6492 messages
    service_uri: ServiceUri,

    /// The handle the parent CA likes to be called by.
    parent_handle: ParentHandle,

    /// The handle the parent CA chose for the child CA.
    child_handle: ChildHandle,

    /// The parent's ID cert.
    id_cert: IdCertInfo,
}

impl ParentServerInfo {
    pub fn new(
        service_uri: ServiceUri,
        parent_handle: ParentHandle,
        child_handle: ChildHandle,
        id_cert: IdCertInfo,
    ) -> Self {
        ParentServerInfo {
            service_uri,
            parent_handle,
            child_handle,
            id_cert,
        }
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }

    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }

    pub fn child_handle(&self) -> &ChildHandle {
        &self.child_handle
    }

    pub fn id_cert(&self) -> &IdCertInfo {
        &self.id_cert
    }
}

impl fmt::Display for ParentServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "service uri:    {}", self.service_uri)?;
        writeln!(f, "parent handle:  {}", self.parent_handle)?;
        writeln!(f, "child handle:   {}", self.child_handle)?;
        writeln!(f, "parent certificate:")?;
        writeln!(f, "   key identifier: {}", self.id_cert().public_key().key_identifier())?;
        writeln!(f, "   hash (of cert): {}", self.id_cert().hash())?;
        writeln!(f, "   PEM:\n\n{}", self.id_cert().pem())
    }
}

//------------ ParentCaContact -----------------------------------------------

/// This type contains the information needed to contact the parent ca
/// for resource provisioning requests (RFC6492).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum ParentCaContact {
    // Note this used to include other, now deprecated, options.
    // This is still an enum for backward compatibility without the need for
    // a data migration of past events, and.. because theoretically we may
    // need other options in future if there is an alternative to RFC 6492
    // one day. Oh.. and having the "type" tag doesn't really hurt that much..
    Rfc6492(ParentServerInfo),
}

impl ParentCaContact {
    pub fn for_parent_server_info(server_info: ParentServerInfo) -> Self {
        ParentCaContact::Rfc6492(server_info)
    }

    pub fn for_rfc8183_parent_response(response: idexchange::ParentResponse) -> Result<Self, idexchange::Error> {
        let id_cert = response.validate()?;
        let id_cert = IdCertInfo::from(&id_cert);

        let service_uri = response.service_uri().clone();
        let parent_handle = response.parent_handle().clone();
        let child_handle = response.child_handle().clone();

        Ok(ParentCaContact::Rfc6492(ParentServerInfo {
            service_uri,
            parent_handle,
            child_handle,
            id_cert,
        }))
    }

    pub fn parent_server_info(&self) -> &ParentServerInfo {
        match &self {
            ParentCaContact::Rfc6492(info) => info,
        }
    }

    pub fn parent_uri(&self) -> &idexchange::ServiceUri {
        match &self {
            ParentCaContact::Rfc6492(parent) => parent.service_uri(),
        }
    }
}

impl fmt::Display for ParentCaContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParentCaContact::Rfc6492(response) => response.fmt(f),
        }
    }
}

/// This type is used when saving and presenting command history
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorableParentContact {
    Rfc6492,
}

impl fmt::Display for StorableParentContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableParentContact::Rfc6492 => write!(f, "RFC 6492 Parent"),
        }
    }
}

impl From<ParentCaContact> for StorableParentContact {
    fn from(parent: ParentCaContact) -> Self {
        match parent {
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

    pub fn handle(&self) -> &ChildHandle {
        &self.handle
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

//------------ RepoFileDeleteCriteria ----------------------------------------

/// This is used to send criteria for purging matching files from the publication
/// server. Currently only needs to support `base_uri` but it could be extended in
/// future and therefore we introduce a type for it now.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RepoFileDeleteCriteria {
    base_uri: uri::Rsync,
}

impl RepoFileDeleteCriteria {
    pub fn new(base_uri: uri::Rsync) -> Self {
        RepoFileDeleteCriteria { base_uri }
    }
}

impl From<RepoFileDeleteCriteria> for uri::Rsync {
    fn from(criteria: RepoFileDeleteCriteria) -> Self {
        criteria.base_uri
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
