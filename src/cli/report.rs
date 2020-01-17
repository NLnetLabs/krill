use std::str::{from_utf8_unchecked, FromStr};

use crate::commons::api::{
    CaRepoDetails, CertAuthHistory, CertAuthInfo, CertAuthList, ChildCaInfo, CurrentObjects,
    CurrentRepoState, ParentCaContact, PublisherDetails, PublisherHandle, PublisherList,
    RepositoryContact, RoaDefinition,
};
use crate::commons::remote::api::ClientInfo;
use crate::commons::remote::rfc8183;
use crate::pubd::RepoStats;

//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ApiResponse {
    Health,

    CertAuthInfo(CertAuthInfo),
    CertAuthHistory(CertAuthHistory),
    CertAuths(CertAuthList),
    RouteAuthorizations(Vec<RoaDefinition>),

    ParentCaContact(ParentCaContact),

    ChildInfo(ChildCaInfo),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),
    PublisherStaleList(Vec<PublisherHandle>),
    RepoStats(RepoStats),

    Rfc8181ClientList(Vec<ClientInfo>),
    Rfc8183RepositoryResponse(rfc8183::RepositoryResponse),
    Rfc8183ChildRequest(rfc8183::ChildRequest),
    Rfc8183PublisherRequest(rfc8183::PublisherRequest),

    RepoDetails(CaRepoDetails),
    RepoState(CurrentRepoState),

    Empty,               // Typically a successful post just gets an empty 200 response
    GenericBody(String), // For when the server echos Json to a successful post
}

impl ApiResponse {
    pub fn report(&self, fmt: ReportFormat) -> Result<Option<String>, ReportError> {
        if fmt == ReportFormat::None {
            Ok(None)
        } else {
            match self {
                ApiResponse::Health => {
                    if fmt == ReportFormat::Default {
                        Ok(None)
                    } else {
                        Err(ReportError::UnsupportedFormat)
                    }
                }
                ApiResponse::CertAuths(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::CertAuthInfo(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::CertAuthHistory(history) => Ok(Some(history.report(fmt)?)),
                ApiResponse::RouteAuthorizations(auths) => Ok(Some(auths.report(fmt)?)),
                ApiResponse::ParentCaContact(contact) => Ok(Some(contact.report(fmt)?)),
                ApiResponse::ChildInfo(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::PublisherList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::PublisherDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::PublisherStaleList(stale) => Ok(Some(stale.report(fmt)?)),
                ApiResponse::RepoStats(stats) => Ok(Some(stats.report(fmt)?)),
                ApiResponse::Rfc8181ClientList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::Rfc8183ChildRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183PublisherRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183RepositoryResponse(res) => Ok(Some(res.report(fmt)?)),
                ApiResponse::RepoDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::RepoState(state) => Ok(Some(state.report(fmt)?)),
                ApiResponse::GenericBody(body) => Ok(Some(body.clone())),
                ApiResponse::Empty => Ok(None),
            }
        }
    }
}

//------------ ReportFormat --------------------------------------------------

/// This type defines the format to use when representing the api response
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Default, // the normal format for this data type, usually json
    None,
    Json,
    Text,
    Xml,
}

impl FromStr for ReportFormat {
    type Err = ReportError;

    fn from_str(s: &str) -> Result<Self, ReportError> {
        match s {
            "none" => Ok(ReportFormat::None),
            "json" => Ok(ReportFormat::Json),
            "text" => Ok(ReportFormat::Text),
            "xml" => Ok(ReportFormat::Xml),
            _ => Err(ReportError::UnrecognisedFormat(s.to_string())),
        }
    }
}

//------------ ReportError ---------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum ReportError {
    #[display(fmt = "This report format is not supported for this data")]
    UnsupportedFormat,

    #[display(fmt = "This report format is not recognised: {}", _0)]
    UnrecognisedFormat(String),
}

//------------ Report --------------------------------------------------------

/// This trait should be implemented by all api responses, so that the
/// response can be formatted for users.
trait Report {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError>;
}

impl Report for CertAuthList {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();
                for ca in self.cas() {
                    res.push_str(&format!("{}\n", ca.handle()));
                }

                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for CertAuthInfo {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str(&format!("Name:     {}\n", self.handle()));
                res.push_str("\n");

                if let Some(repo_info) = self.repo_info() {
                    let base_uri = repo_info.base_uri();
                    let rrdp_uri = repo_info.rpki_notify();
                    res.push_str(&format!("Base uri: {}\n", base_uri));
                    res.push_str(&format!("RRDP uri: {}\n", rrdp_uri));
                } else {
                    res.push_str("No repository configured.")
                }
                res.push_str("\n");

                res.push_str(&format!("ID cert PEM:\n{}\n", self.id_cert().pem()));
                res.push_str(&format!("Hash: {}\n", self.id_cert().hash()));
                res.push_str("\n");

                let resources = self.resources();
                if resources.is_empty() {
                    res.push_str("Total resources: <none>\n");
                } else {
                    res.push_str("Total resources:\n");
                    res.push_str(&format!("    ASNs: {}\n", resources.asn()));
                    res.push_str(&format!("    IPv4: {}\n", resources.v4()));
                    res.push_str(&format!("    IPv6: {}\n", resources.v6()));
                }
                res.push_str("\n");

                fn print_objects(res: &mut String, objects: &CurrentObjects) {
                    for object in objects.names() {
                        res.push_str(&format!("  {}\n", object));
                    }
                }

                res.push_str("Parents:\n");
                if !self.parents().is_empty() {
                    for parent in self.parents().iter() {
                        res.push_str(&format!("{}\n", parent));
                    }
                    res.push_str("\n");
                } else {
                    res.push_str("<none>\n")
                }

                for (name, rc) in self.resource_classes() {
                    res.push_str(&format!("Resource Class: {}\n", name,));
                    res.push_str(&format!("Parent: {}\n", rc.parent_handle()));
                    res.push_str(&format!("{}", rc.keys()));

                    res.push_str("Current objects:\n");
                    print_objects(&mut res, rc.current_objects());
                    res.push_str("\n");
                }

                res.push_str("Children:\n");
                if !self.children().is_empty() {
                    for child_handle in self.children() {
                        res.push_str(&format!("{}\n", child_handle));
                    }
                } else {
                    res.push_str("<none>\n");
                }

                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for CertAuthHistory {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text => Ok(format!("{}", self)),
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for ParentCaContact {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text | ReportFormat::Xml => {
                let mut res = String::new();
                match self {
                    ParentCaContact::Ta(details) => {
                        res.push_str(&format!("{}", details.tal()));
                    }
                    ParentCaContact::Embedded => {
                        res.push_str("Embedded parent");
                    }
                    ParentCaContact::Rfc6492(response) => {
                        let bytes = response.encode_vec();
                        let xml = unsafe { from_utf8_unchecked(&bytes) };
                        res.push_str(xml);
                    }
                }
                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for ChildCaInfo {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => Ok(self.to_string()),
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for PublisherList {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str("Publishers: ");
                let mut first = true;
                for p in self.publishers() {
                    if !first {
                        res.push_str(", ");
                    } else {
                        first = false;
                    }
                    res.push_str(p.handle().as_str());
                }
                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for RepoStats {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text => {
                let mut res = String::new();

                if let Some(update) = self.last_update() {
                    res.push_str(&format!("RRDP updated: {}\n", update.to_rfc3339()));
                }
                res.push_str(&format!("RRDP session: {}\n", self.session()));
                res.push_str(&format!("RRDP serial:  {}\n", self.serial()));
                res.push_str("\n");
                res.push_str("Publisher, Objects, Size, Last Updated\n");
                for (publisher, stats) in self.get_publishers() {
                    res.push_str(&format!(
                        "{}, {}, {}, ",
                        publisher,
                        stats.objects(),
                        stats.size()
                    ));
                    match stats.last_update() {
                        None => res.push_str("never\n"),
                        Some(update) => res.push_str(&format!("{}\n", update.to_rfc3339())),
                    }
                }

                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for Vec<PublisherHandle> {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text => {
                let strs: Vec<&str> = self.iter().map(|h| h.as_str()).collect();
                Ok(strs.join(", "))
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for PublisherDetails {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str(&format!("handle: {}\n", self.handle()));
                res.push_str(&format!("id: {}", self.id_cert().ski_hex()));
                res.push_str(&format!("base uri: {}\n", self.base_uri().to_string()));

                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for Vec<ClientInfo> {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str("Clients: ");
                for client in self.iter() {
                    let handle = client.handle();
                    let auth = client.auth();
                    let ski = auth.cert().ski_hex();

                    res.push_str(&format!("   Handle: {}, Cert (ski): {}\n", handle, ski));
                }
                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for rfc8183::RepositoryResponse {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Text | ReportFormat::Xml | ReportFormat::Default => {
                let bytes = self.encode_vec();
                let xml = unsafe { from_utf8_unchecked(&bytes) };

                Ok(xml.to_string())
            }
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for rfc8183::ChildRequest {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Text | ReportFormat::Xml | ReportFormat::Default => {
                let bytes = self.encode_vec();
                let xml = unsafe { from_utf8_unchecked(&bytes) };

                Ok(xml.to_string())
            }
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for rfc8183::PublisherRequest {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Text | ReportFormat::Xml | ReportFormat::Default => {
                let bytes = self.encode_vec();
                let xml = unsafe { from_utf8_unchecked(&bytes) };

                Ok(xml.to_string())
            }
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for Vec<RoaDefinition> {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            }
            ReportFormat::Text => {
                let mut res = String::new();
                for a in self.iter() {
                    res.push_str(&format!("{}\n", a));
                }
                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for CaRepoDetails {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text => {
                let mut res = String::new();

                res.push_str("Repository Details:\n");
                match self.contact() {
                    RepositoryContact::Embedded(repo_info) => {
                        res.push_str("  type:        embedded\n");
                        res.push_str(&format!("  base_uri:    {}\n", repo_info.base_uri()));
                        res.push_str(&format!("  rpki_notify: {}\n", repo_info.rpki_notify()));
                    }
                    RepositoryContact::Rfc8181(response) => {
                        res.push_str("  type:        remote\n");
                        res.push_str(&format!("  service uri: {}\n", response.service_uri()));
                        let repo_info = response.repo_info();
                        res.push_str(&format!("  base_uri:    {}\n", repo_info.base_uri()));
                        res.push_str(&format!("  rpki_notify: {}\n", repo_info.rpki_notify()));
                    }
                }

                res.push_str("\n");

                Ok(res)
            }
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for CurrentRepoState {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Json => Ok(serde_json::to_string_pretty(self).unwrap()),
            ReportFormat::Default | ReportFormat::Text => match &self {
                CurrentRepoState::Error(e) => Ok(format!("Error contacting repo! => {}\n", e)),
                CurrentRepoState::List(list) => {
                    let mut res = String::new();
                    res.push_str("Available and publishing objects:\n");
                    let elements = list.elements();
                    if elements.is_empty() {
                        res.push_str("  <nothing>\n");
                    } else {
                        for el in elements.iter() {
                            res.push_str(&format!("  {} {}\n", el.hash(), el.uri()));
                        }
                    }
                    Ok(res)
                }
            },
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}
