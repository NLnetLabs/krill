//! Support for admin tasks, such as managing publishers and RFC8181 clients.

use std::fmt;
use rpki::ca::idexchange;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, PublisherHandle, RepoInfo,
    ServiceUri,
};
use rpki::ca::provisioning::ResourceClassName;
use rpki::crypto::PublicKey;
use rpki::repository::resources::ResourceSet;
use rpki::uri;
use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeStruct;
use crate::commons::error::Error;
use crate::commons::KrillResult;
use super::ca::{IdCertInfo, Timestamp};
use super::rrdp::PublishElement;


//------------ Success -------------------------------------------------------

/// An empty, successful API response.
///
/// This type needs to be used instead of `()` to make conversion into
/// [`Report`][crate::client::report::Report] work.
#[derive(Clone, Copy, Debug)]
pub struct Success;

impl fmt::Display for Success {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Ok")
    }
}

impl Serialize for Success {
    fn serialize<S: Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct("Success", 1)?;
        serializer.serialize_field("status", "Ok")?;
        serializer.end()
    }
}


//------------ Token ---------------------------------------------------------

/// An authentication token.
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

/// The URIs necessasry to initialise a new publication server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationServerUris {
    /// The base URI of the RRDP server.
    pub rrdp_base_uri: uri::Https,

    /// The base URI of the rsync server.
    pub rsync_jail: uri::Rsync,
}


//------------ PublisherSummaryInfo ------------------------------------------

/// The summary of publisher information to be used in the publisher list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherSummary {
    /// The publisher handle.
    pub handle: PublisherHandle,
}

impl PublisherSummary {
    fn from_handle(handle: PublisherHandle) -> Self {
        PublisherSummary { handle }
    }
}


//------------ PublisherList -------------------------------------------------

/// The list of (all) current publishers.
#[derive(Clone, Eq, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublisherList {
    /// The list of publishers.
    pub publishers: Vec<PublisherSummary>,
}

impl PublisherList {
    pub fn from_slice(publishers: &[PublisherHandle]) -> PublisherList {
        PublisherList {
            publishers: publishers.iter().map(|p| {
                PublisherSummary::from_handle(p.clone())
            }).collect(),
        }
    }
}

impl fmt::Display for PublisherList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Publishers: ")?;
        let mut first = true;
        for p in &self.publishers {
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
            write!(f, "{}", p.handle.as_str())?;
        }
        Ok(())
    }
}


//------------ PublisherDetails ----------------------------------------------

/// The details of a single publisher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherDetails {
    /// The handle of the publisher the details are for.
    pub handle: PublisherHandle,

    /// The ID certificate for this publisher.
    pub id_cert: IdCertInfo,

    /// The base rsync URI for this publisher.
    pub base_uri: uri::Rsync,

    /// The currently published files.
    pub current_files: Vec<PublishElement>,
}

impl fmt::Display for PublisherDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "handle: {}", self.handle)?;
        writeln!(f, "id: {}", self.id_cert.public_key.key_identifier())?;
        writeln!(f, "base uri: {}", self.base_uri)?;
        writeln!(f, "objects:")?;
        for e in &self.current_files {
            writeln!(f, "  {}", e.uri)?;
        }

        Ok(())
    }
}


//------------ PublicationServerInfo -----------------------------------------

/// Details of a publication server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationServerInfo {
    /// The public key used by the publication server.
    pub public_key: PublicKey,

    /// The service URI of the publication server.
    pub service_uri: ServiceUri,
}


//------------ ApiRepositoryContact ------------------------------------------

/// A repository response received from a remote contact.
///
/// This type is provided so that we do not need to change the the API for
/// uploading repository responses as it was prior to 0.10.0.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiRepositoryContact {
    /// The reposuitory response.
    pub repository_response: idexchange::RepositoryResponse,
}


//------------ RepositoryContact ---------------------------------------------

/// A contact with a remote repository.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryContact {
    /// Information about the remote repository.
    pub repo_info: RepoInfo,

    /// Information about the remote publication server.
    pub server_info: PublicationServerInfo,
}

impl RepositoryContact {
    /// Tries to create a value from a remote repository response.
    pub fn try_from_response(
        repository_response: idexchange::RepositoryResponse,
    ) -> KrillResult<Self> {
        let id_cert = repository_response.validate().map_err(Error::rfc8183)?;

        Ok(RepositoryContact {
            repo_info: repository_response.repo_info().clone(),
            server_info: PublicationServerInfo {
                public_key: id_cert.public_key().clone(),
                service_uri: repository_response.service_uri().clone(),
            },
        })
    }
}

impl From<RepositoryContact> for RepoInfo {
    fn from(contact: RepositoryContact) -> Self {
        contact.repo_info
    }
}

impl fmt::Display for RepositoryContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "publication server at {}", self.server_info.service_uri)
    }
}

// XXX This impl violates the rule that if k1 == k2 -> hash(k1) == hash(k2).

impl std::hash::Hash for RepositoryContact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.server_info.service_uri.as_str().hash(state); // unique for each
                                                           // repo contact
    }
}

impl PartialEq for RepositoryContact {
    fn eq(&self, other: &Self) -> bool {
        self.repo_info == other.repo_info
            && self.server_info == other.server_info
    }
}

impl Eq for RepositoryContact {}


//------------ ParentCaReq ---------------------------------------------------

/// All the parent CA details needed to add a parent to a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentCaReq {
    /// The child local name for the parent.
    pub handle: ParentHandle,

    /// The parent’s up-down response.
    #[serde(alias = "contact")] // stay backward compatible to pre 0.10.0
    pub response: idexchange::ParentResponse,
}

impl fmt::Display for ParentCaReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parent '{}' contact '{}'", self.handle, self.response)
    }
}


//------------ ParentServerInfo ----------------------------------------------

/// Information about the server of the parent CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentServerInfo {
    /// The URI where the CA needs to send its RFC6492 messages
    pub service_uri: ServiceUri,

    /// The handle the parent CA likes to be called by.
    pub parent_handle: ParentHandle,

    /// The handle the parent CA chose for the child CA.
    pub child_handle: ChildHandle,

    /// The parent's ID cert.
    pub id_cert: IdCertInfo,
}

impl fmt::Display for ParentServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "service uri:    {}", self.service_uri)?;
        writeln!(f, "parent handle:  {}", self.parent_handle)?;
        writeln!(f, "child handle:   {}", self.child_handle)?;
        writeln!(f, "parent certificate:")?;
        writeln!(
            f,
            "   key identifier: {}",
            self.id_cert.public_key.key_identifier()
        )?;
        writeln!(f, "   hash (of cert): {}", self.id_cert.hash)?;
        writeln!(f, "   PEM:\n\n{}", self.id_cert.pem())
    }
}


//------------ ParentCaContact -----------------------------------------------

/// Information to contact the parent CA for resource provisioning requests.
///
/// Note that this used to include other, now deprecated, options.
/// It is still an enum for backward compatibility without the need for
/// a data migration of past events, and because theoretically we may
/// need other options in future if there is an alternative to RFC 6492
/// one day.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum ParentCaContact {
    /// A parent CA contact has to be made via RFC 6492.
    Rfc6492(ParentServerInfo),
}

impl ParentCaContact {
    /// Tries creating a parent CA contact from an RFC 8183 parent response.
    pub fn try_from_rfc8183_parent_response(
        response: idexchange::ParentResponse,
    ) -> Result<Self, idexchange::Error> {
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

    /// Returns a reference to the parent server information.
    pub fn parent_server_info(&self) -> &ParentServerInfo {
        match &self {
            ParentCaContact::Rfc6492(info) => info,
        }
    }

    /// Returns a reference to the parent server’s service URI.
    pub fn parent_uri(&self) -> &idexchange::ServiceUri {
        match self {
            ParentCaContact::Rfc6492(parent) => &parent.service_uri,
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


//------------ StorableParentContact -----------------------------------------

/// The protocol to use when contacting a parent.
///
/// This type is used when saving and presenting the command history.
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

/// Information to initialize a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInit {
    /// The local handle identifying the CA.
    pub handle: CaHandle,
}

impl fmt::Display for CertAuthInit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}


//------------ AddChildRequest -----------------------------------------------

/// Information necessary to request adding a child CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddChildRequest {
    /// The handle to identify the child with.
    pub handle: ChildHandle,

    /// The resources the child should have.
    pub resources: ResourceSet,

    /// The ID certificate the child will use for communication.
    pub id_cert: IdCert,
}

impl fmt::Display for AddChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "handle '{}' resources '{}'", self.handle, self.resources,)
    }
}


//------------ UpdateChildRequest --------------------------------------------

/// Information for a request to update a child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateChildRequest {
    /// The new ID certificate of the child.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_cert: Option<IdCert>,

    /// The new resources of the child.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceSet>,

    /// Whether to (un)suspend a child.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,

    /// Changes to the names of a resource class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_class_name_mapping: Option<ResourceClassNameMapping>,
}

/// A mapping from the name of a resource class in parent and child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassNameMapping {
    /// The name of the resource class at the parent.
    pub name_in_parent: ResourceClassName,

    /// The name of the resource class at the child.
    pub name_for_child: ResourceClassName,
}

impl UpdateChildRequest {
    /// Creates a child update request that only changes the ID certificate.
    pub fn id_cert(id_cert: IdCert) -> Self {
        UpdateChildRequest {
            id_cert: Some(id_cert),
            resources: None,
            suspend: None,
            resource_class_name_mapping: None,
        }
    }

    /// Creates a child update request that only changes the resources.
    pub fn resources(resources: ResourceSet) -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: Some(resources),
            suspend: None,
            resource_class_name_mapping: None,
        }
    }

    /// Creates a child update request that suspends the client.
    pub fn suspend() -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: None,
            suspend: Some(true),
            resource_class_name_mapping: None,
        }
    }

    /// Creates a child update request that unsuspends the client.
    pub fn unsuspend() -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: None,
            suspend: Some(false),
            resource_class_name_mapping: None,
        }
    }

    /// Creates a child update request that changes resource name mapping.
    pub fn resource_class_name_mapping(
        mapping: ResourceClassNameMapping,
    ) -> Self {
        UpdateChildRequest {
            id_cert: None,
            resources: None,
            suspend: None,
            resource_class_name_mapping: Some(mapping),
        }
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

/// Information about this Krill server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerInfo {
    /// The server software version.
    pub version: String,

    /// The time currently running server was started.
    pub started: Timestamp,
}

impl fmt::Display for ServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Version: {}\nStarted: {}",
            self.version,
            self.started.into_rfc3339()
        )
    }
}


//------------ RepoFileDeleteCriteria ----------------------------------------

/// Criteria for selectively deleting repository files.
///
/// This type is used to send criteria for purging matching files from the
/// publication server. Currently only needs to support `base_uri` but it
/// could be extended in future and therefore we introduce a type for it now.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RepoFileDeleteCriteria {
    /// The base rsync URI of the file to be deleted.
    pub base_uri: uri::Rsync,
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
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

