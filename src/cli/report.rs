use std::str::{from_utf8_unchecked, FromStr};

use crate::commons::api::{
    CertAuthHistory, CertAuthInfo, CertAuthList, CurrentObjects, ParentCaContact, PublisherDetails,
    PublisherList, RouteAuthorization,
};
use crate::commons::remote::api::ClientInfo;
use crate::commons::remote::rfc8183;

//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ApiResponse {
    Health,

    CertAuthInfo(CertAuthInfo),
    CertAuthHistory(CertAuthHistory),
    CertAuths(CertAuthList),
    RouteAuthorizations(Vec<RouteAuthorization>),

    ParentCaContact(ParentCaContact),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),

    Rfc8181ClientList(Vec<ClientInfo>),
    Rfc8183RepositoryResponse(rfc8183::RepositoryResponse),
    Rfc8183ChildRequest(rfc8183::ChildRequest),

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
                ApiResponse::PublisherList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::PublisherDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::Rfc8181ClientList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::Rfc8183ChildRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183RepositoryResponse(res) => Ok(Some(res.report(fmt)?)),
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
                    res.push_str(&format!("{}\n", ca.name()));
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

                let base_uri = self.repo_repo().base_uri();
                let rrdp_uri = self.repo_repo().rpki_notify();

                res.push_str(&format!("Name:     {}\n", self.handle()));
                res.push_str("\n");
                res.push_str(&format!("Base uri: {}\n", base_uri));
                res.push_str(&format!("RRDP uri: {}\n", rrdp_uri));

                res.push_str("\n");

                fn print_objects(res: &mut String, objects: &CurrentObjects) {
                    for object in objects.names() {
                        res.push_str(&format!("  {}\n", object));
                    }
                }

                for (name, kind) in self.parents().iter() {
                    res.push_str(&format!("Parent:  {}, Kind: {}\n", name, kind));
                }
                res.push_str("\n");

                for (name, rc) in self.resources() {
                    res.push_str(&format!("Resource Class: {}\n", name,));
                    res.push_str(&format!("Parent: {}\n", rc.parent_handle()));
                    res.push_str(&format!("{}", rc.keys()));

                    res.push_str("Current objects:\n");
                    print_objects(&mut res, rc.current_objects());
                    res.push_str("\n");
                }

                res.push_str("Children:\n");
                if !self.children().is_empty() {
                    for (name, details) in self.children() {
                        res.push_str(&format!("{}\n", name));
                        res.push_str(&format!("  resources: {}\n", details.entitled_resources()));
                        res.push_str("\n");
                    }
                } else {
                    res.push_str("<none>");
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
                    res.push_str(p.id());
                }
                Ok(res)
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
            _ => Err(ReportError::UnsupportedFormat),
        }
    }
}

impl Report for Vec<RouteAuthorization> {
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
