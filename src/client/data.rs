//! Data types to wrap the API responses, and support reporting on them in
//! various formats (where applicable).
use std::fmt::Write;

//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiResponse {
    Health,
    PublisherList(PublisherList),
    PostOk
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
                ApiResponse::PublisherList(list) => {
                    Ok(Some(list.report(fmt)?))
                },
                ApiResponse::PostOk => Ok(None)
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

impl ReportFormat {
    pub fn from_str(s: &str) -> Result<Self, ReportError> {
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
#[derive(Debug, Fail)]
pub enum ReportError {
    #[fail(display="This report format is not supported for this data")]
    UnsupportedFormat,

    #[fail(display="This report format is not recognised: {}", _0)]
    UnrecognisedFormat(String)
}


//------------ Report --------------------------------------------------------

/// This trait should be implemented by all api responses, so that the
/// response can be formatted for users.
trait Report {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError>;
}


//------------ Link ----------------------------------------------------------

/// This type defines a json link item, often included in json responses as
/// helpful hints for more..
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct Link {
    rel: String,
    link: String
}


//------------ PublisherList -------------------------------------------------

/// This type defines the response for:
/// /api/v1/publishers
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct PublisherList {
    publishers: Vec<PublisherSummary>
}

impl PublisherList {
    pub fn publishers(&self) -> &Vec<PublisherSummary> {
        &self.publishers
    }
}

impl Report for PublisherList {
    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::Default | ReportFormat::Json => {
                Ok(serde_json::to_string(self).unwrap())
            },
            ReportFormat::Text => {
                let mut res = String::new();

                write!(&mut res, "Publishers: ");
                let mut first = true;
                for p in &self.publishers {
                    if ! first {
                        write!(&mut res, ", ");
                    } else {
                        first = false;
                    }
                    write!(&mut res, "{}", p.id());
                }
                Ok(res)
            },
            _ => Err(ReportError::UnsupportedFormat)
        }
    }
}


//------------ PublisherSummary ----------------------------------------------

/// This type defines an individual publisher in the response for:
/// /api/v1/publishers
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct PublisherSummary {
    id: String,
    links: Vec<Link>
}

impl PublisherSummary {
    pub fn id(&self) -> &String {
        &self.id
    }
}
