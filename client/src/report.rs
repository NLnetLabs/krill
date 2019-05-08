use std::str::FromStr;
use krill_commons::api::admin::{PublisherDetails, PublisherList};
use krill_cms_proxy::api::ClientInfo;
use krill_commons::api::ca::TrustAnchorInfo;


//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ApiResponse {
    Health,
    TrustAnchorInfo(TrustAnchorInfo),
    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),
    Rfc8181ClientList(Vec<ClientInfo>),
    Empty, // Typically a successful post just gets an empty 200 response
    GenericBody(String) // For when the server echos Json to a successful post
}

impl ApiResponse {
    pub fn report(
        &self,
        fmt: ReportFormat
    ) -> Result<Option<String>, ReportError> {
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
                },
                ApiResponse::TrustAnchorInfo(ta) => {
                    Ok(Some(ta.report(fmt)?))
                }
                ApiResponse::PublisherList(list) => {
                    Ok(Some(list.report(fmt)?))
                },
                ApiResponse::PublisherDetails(details) => {
                    Ok(Some(details.report(fmt)?))
                }
                ApiResponse::Rfc8181ClientList(list) => {
                    Ok(Some(list.report(fmt)?))
                }
                ApiResponse::GenericBody(body) => {
                    Ok(Some(body.clone()))
                }
                ApiResponse::Empty => Ok(None)
            }
        }
    }
}

//------------ ReportFormat --------------------------------------------------

/// This type defines the format to use when representing the api response
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Default, // the normal format for this data type
    None,
    Json,
    Text,
    Xml
}

impl FromStr for ReportFormat {
    type Err = ReportError;

    fn from_str(s: &str) -> Result<Self, ReportError> {
        match s {
            "none" => Ok(ReportFormat::None),
            "json" => Ok(ReportFormat::Json),
            "text" => Ok(ReportFormat::Text),
            "xml"  => Ok(ReportFormat::Xml),
            _ => Err(ReportError::UnrecognisedFormat(s.to_string()))
        }
    }
}


//------------ ReportError ---------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum ReportError {
    #[display(fmt="This report format is not supported for this data")]
    UnsupportedFormat,

    #[display(fmt="This report format is not recognised: {}", _0)]
    UnrecognisedFormat(String)
}


//------------ Report --------------------------------------------------------

/// This trait should be implemented by all api responses, so that the
/// response can be formatted for users.
trait Report {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError>;
}

impl Report for TrustAnchorInfo {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();

                let resources = self.resources();

                res.push_str(&format!("ASNs: {}\n", resources.asn()));
                res.push_str(&format!("IPv4: {}\n", resources.v4()));
                res.push_str(&format!("IPv6: {}\n", resources.v6()));

                res.push_str("\n");

                res.push_str("TAL:\n");
                res.push_str(&format!("{}", self.tal()));

                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for PublisherList {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str("Publishers: ");
                let mut first = true;
                for p in self.publishers() {
                    if ! first {
                        res.push_str(", ");
                    } else {
                        first = false;
                    }
                    res.push_str(p.id());
                }
                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for PublisherDetails {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {

                let mut res = String::new();

                res.push_str("handle: ");
                res.push_str(self.handle());
                res.push_str("\n");

                res.push_str("base uri: ");
                res.push_str(self.base_uri().to_string().as_str());
                res.push_str("\n");

                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for Vec<ClientInfo> {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();

                res.push_str("Clients: ");
                for client in self.iter() {
                    let handle = client.handle();
                    let auth = client.auth();
                    let token = auth.token();
                    let ski = auth.cert().ski_hex();

                    res.push_str(
                        &format!("   Handle: {}, Token: {}, Cert (ski): {}\n", handle, token, ski)
                    );
                }
                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}