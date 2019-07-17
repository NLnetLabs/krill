use std::str::{FromStr, from_utf8_unchecked};
use krill_commons::api::admin::{PublisherDetails, PublisherList, ParentCaContact};
use krill_commons::api::ca::{TrustAnchorInfo, CertAuthList, CertAuthInfo, CaParentsInfo, CurrentObjects};
use krill_commons::remote::api::ClientInfo;
use krill_commons::remote::rfc8183::RepositoryResponse;


//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ApiResponse {
    Health,

    TrustAnchorInfo(TrustAnchorInfo),

    CertAuthInfo(CertAuthInfo),
    CertAuths(CertAuthList),

    ParentCaInfo(ParentCaContact),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),

    Rfc8181ClientList(Vec<ClientInfo>),
    Rfc8181RepositoryResponse(RepositoryResponse),

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
                },
                ApiResponse::CertAuths(list) => {
                    Ok(Some(list.report(fmt)?))
                },
                ApiResponse::CertAuthInfo(info) => {
                    Ok(Some(info.report(fmt)?))
                },
                ApiResponse::ParentCaInfo(info) => {
                    Ok(Some(info.report(fmt)?))
                },
                ApiResponse::PublisherList(list) => {
                    Ok(Some(list.report(fmt)?))
                },
                ApiResponse::PublisherDetails(details) => {
                    Ok(Some(details.report(fmt)?))
                }
                ApiResponse::Rfc8181ClientList(list) => {
                    Ok(Some(list.report(fmt)?))
                }
                ApiResponse::Rfc8181RepositoryResponse(res) => {
                    Ok(Some(res.report(fmt)?))
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Default, // the normal format for this data type, usually json
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

                res.push_str("\n");
                res.push_str("\n");

                res.push_str("Children:\n");
                if !self.children().is_empty() {
                    for (name, details) in self.children() {
                        res.push_str(&format!("{}\n", name));
                        for (class, resources) in details.resources() {
                            res.push_str(&format!("  class: {}\n", class));

                            let inrs = resources.resources();
                            res.push_str(&format!("    asn: {}\n", inrs.asn()));
                            res.push_str(&format!("    v4:  {}\n", inrs.v4()));
                            res.push_str(&format!("    v6:  {}\n", inrs.v6()));
                            res.push_str("\n");
                        }

                    }
                } else {
                    res.push_str("<none>");
                }


                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for CertAuthList {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();
                for ca in self.cas() {
                    res.push_str(&format!("{}\n", ca.name()));
                }

                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for CertAuthInfo {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();

                let base_uri = self.base_repo().base_uri();
                let rrdp_uri = self.base_repo().rpki_notify();

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

                match self.parents() {
                    CaParentsInfo::SelfSigned(key, tal) => {
                        res.push_str("This CA is a TA\n");
                        res.push_str("\n");

                        let inrs = key.resources();
                        res.push_str(&format!("ASNs: {}\n", inrs.asn()));
                        res.push_str(&format!("IPv4: {}\n", inrs.v4()));
                        res.push_str(&format!("IPv6: {}\n", inrs.v6()));


                        res.push_str("Current objects:\n");
                        print_objects(&mut res, key.current_set().objects());
                        res.push_str("\n");

                        res.push_str("Children:\n");
                        if !self.children().is_empty() {
                            for (name, details) in self.children() {
                                res.push_str(&format!("{}\n", name));
                                for (class, resources) in details.resources() {
                                    res.push_str(&format!("  class: {}\n", class));

                                    let inrs = resources.resources();
                                    res.push_str(&format!("    asn: {}\n", inrs.asn()));
                                    res.push_str(&format!("    v4:  {}\n", inrs.v4()));
                                    res.push_str(&format!("    v6:  {}\n", inrs.v6()));
                                    res.push_str("\n");
                                }

                            }
                        } else {
                            res.push_str("<none>");
                        }

                        res.push_str("TAL:\n");
                        res.push_str(&format!("{}\n", tal));
                    },
                    CaParentsInfo::Parents(map) => {
                        for info in map.values() {
                            res.push_str(&format!("Parent:  {}\n", info.contact()));

                            for (name, rc) in info.resources() {
                                res.push_str(&format!("Resource Class: {}\n", name));
                                if let Some(key) = rc.current_key() {
                                    res.push_str("  CURRENT Key:\n");
                                    res.push_str("    Resources:\n");
                                    let inrs = key.resources();
                                    res.push_str(&format!("    ASNs: {}\n", inrs.asn()));
                                    res.push_str(&format!("    IPv4: {}\n", inrs.v4()));
                                    res.push_str(&format!("    IPv6: {}\n", inrs.v6()));

                                    res.push_str("    Objects:\n");
                                    res.push_str("\n");
                                    print_objects(&mut res, key.current_set().objects());
                                }

                                if rc.pending_key().is_some() {
                                    res.push_str("  PENDING key exists!\n");
                                    res.push_str("\n");
                                }

                                if rc.new_key().is_some() {
                                    res.push_str("  NEW key exists!\n");
                                    res.push_str("\n");
                                }

                                if rc.revoke_key().is_some() {
                                    res.push_str("  OLD unrevoked key exists!\n");
                                    res.push_str("\n");
                                }

                            }
                        }
                    }
                }
                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for ParentCaContact {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string_pretty(self).unwrap())
            },
            ReportFormat::Text => {
                Ok(self.to_string())
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
                    let ski = auth.cert().ski_hex();

                    res.push_str(
                        &format!("   Handle: {}, Cert (ski): {}\n", handle, ski)
                    );
                }
                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}

impl Report for RepositoryResponse {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Text | ReportFormat::Xml | ReportFormat::Default => {
                let bytes = self.encode_vec();
                let xml = unsafe {
                    from_utf8_unchecked(&bytes)
                };

                Ok(xml.to_string())
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}