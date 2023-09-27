//------------------------ Client Error -----------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    DataDirMissing,
    UnrecognizedMatch,
    HttpClientError(httpclient::Error),
    KrillError(KrillError),
    StorageError(AggregateStoreError),
    Other(String),
}

impl Error {
    fn other(msg: &str) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DataDirMissing => write!(f, "Cannot find data dir"),
            Error::UnrecognizedMatch => write!(f, "Unrecognised argument. Use 'help'"),
            Error::HttpClientError(e) => write!(f, "HTTP client error: {}", e),
            Error::KrillError(e) => write!(f, "{}", e),
            Error::StorageError(e) => write!(f, "Issue with persistence layer: {}", e),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<KrillError> for Error {
    fn from(e: KrillError) -> Self {
        Self::KrillError(e)
    }
}

impl From<report::ReportError> for Error {
    fn from(e: report::ReportError) -> Self {
        Error::Other(e.to_string())
    }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self {
        Self::StorageError(e)
    }
}
