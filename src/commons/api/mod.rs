//! Data structures for the API, shared between client and server.

mod admin;
pub use self::admin::*;

mod ca;
pub use self::ca::*;

mod provisioning;
pub use self::provisioning::*;

mod publication;
pub use self::publication::*;

mod roas;
pub use self::roas::*;

pub mod rrdp;

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::cert::Cert;
use rpki::crl::Crl;
use rpki::manifest::Manifest;
use rpki::roa::Roa;

use crate::commons::util::sha256;

//------------ Base64 --------------------------------------------------------

/// This type contains a base64 encoded structure. The publication protocol
/// deals with objects in their base64 encoded form.
///
/// Note that we store this in a Bytes to make it cheap to clone this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base64(Bytes);

impl Base64 {
    pub fn from_content(content: &[u8]) -> Self {
        Base64::from(base64::encode(content))
    }

    /// Decodes into bytes (e.g. for saving to disk for rcync)
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(base64::decode(&self.0).unwrap())
    }

    pub fn to_hex_hash(&self) -> String {
        hex::encode(sha256(&self.to_bytes()))
    }

    pub fn to_encoded_hash(&self) -> HexEncodedHash {
        HexEncodedHash::from(self.to_hex_hash())
    }
}

impl AsRef<str> for Base64 {
    fn as_ref(&self) -> &str {
        use std::str;
        str::from_utf8(&self.0).unwrap()
    }
}

impl From<String> for Base64 {
    fn from(s: String) -> Self {
        Base64(Bytes::from(s))
    }
}

impl From<&Cert> for Base64 {
    fn from(cert: &Cert) -> Self {
        Base64::from_content(&cert.to_captured().into_bytes())
    }
}

impl From<&Roa> for Base64 {
    fn from(roa: &Roa) -> Self {
        Base64::from_content(&roa.to_captured().into_bytes())
    }
}

impl From<&Manifest> for Base64 {
    fn from(mft: &Manifest) -> Self {
        Base64::from_content(&mft.to_captured().into_bytes())
    }
}

impl From<&Crl> for Base64 {
    fn from(crl: &Crl) -> Self {
        Base64::from_content(&crl.to_captured().into_bytes())
    }
}

impl ToString for Base64 {
    fn to_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.0.to_vec()) }
    }
}

impl Serialize for Base64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D>(deserializer: D) -> Result<Base64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Ok(Base64::from(string))
    }
}

//------------ HexEncodedHash ------------------------------------------------

/// This type contains a hex encoded sha256 hash.
///
/// Note that we store this in a Bytes for cheap cloning.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HexEncodedHash(Bytes);

impl HexEncodedHash {
    pub fn from_content(content: &[u8]) -> Self {
        let sha256 = sha256(content);
        let hex = hex::encode(sha256);
        HexEncodedHash::from(hex)
    }
}

impl Into<Bytes> for HexEncodedHash {
    fn into(self) -> Bytes {
        self.0
    }
}

impl AsRef<str> for HexEncodedHash {
    fn as_ref(&self) -> &str {
        use std::str;
        str::from_utf8(&self.0).unwrap()
    }
}

impl AsRef<Bytes> for HexEncodedHash {
    fn as_ref(&self) -> &Bytes {
        &self.0
    }
}

impl From<&Crl> for HexEncodedHash {
    fn from(crl: &Crl) -> Self {
        Self::from_content(crl.to_captured().as_slice())
    }
}

impl From<&Manifest> for HexEncodedHash {
    fn from(mft: &Manifest) -> Self {
        Self::from_content(mft.to_captured().as_slice())
    }
}

impl From<String> for HexEncodedHash {
    fn from(s: String) -> Self {
        HexEncodedHash(Bytes::from(s.to_lowercase()))
    }
}

impl ToString for HexEncodedHash {
    fn to_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.0.to_vec()) }
    }
}

impl Serialize for HexEncodedHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HexEncodedHash {
    fn deserialize<D>(deserializer: D) -> Result<HexEncodedHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Ok(HexEncodedHash::from(string))
    }
}

//------------ Link ----------------------------------------------------------

/// Defines a link element to include as part of a links array in a Json
/// response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Link {
    rel: String,
    link: String,
}

//------------ ErrorResponse --------------------------------------------------

/// Defines an error response. Codes are unique and documented here:
/// https://rpki.readthedocs.io/en/latest/krill/pub/api.html#error-responses
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    code: usize,
    msg: String,
}

impl ErrorResponse {
    pub fn new(code: usize, msg: String) -> Self {
        ErrorResponse { code, msg }
    }
    pub fn code(&self) -> usize {
        self.code
    }
    pub fn msg(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &serde_json::to_string(&self).unwrap())
    }
}

impl Into<ErrorCode> for ErrorResponse {
    fn into(self) -> ErrorCode {
        ErrorCode::from(self.code)
    }
}

/// This type defines externally visible errors that the API may return.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ErrorCode {
    #[display(fmt = "Submitted Json cannot be parsed")]
    InvalidJson,

    #[display(fmt = "Invalid RFC8183 Publisher Request")]
    InvalidPublisherRequest,

    #[display(fmt = "Issue with submitted publication XML")]
    InvalidPublicationXml,

    #[display(fmt = "Invalid handle name")]
    InvalidHandle,

    #[display(fmt = "Submitted protocol CMS cannot be parsed")]
    InvalidCms,

    #[display(fmt = "2001: Submitted protocol CMS does not validate")]
    CmsValidation,

    #[display(fmt = "Out of sync with server, please send requests for instances sequentially")]
    ConcurrentModification,

    #[display(fmt = "Unknown publisher")]
    UnknownPublisher,

    #[display(fmt = "Handle already in use")]
    DuplicateHandle,

    #[display(fmt = "Base URI for publisher is outside of publisher base URI")]
    InvalidBaseUri,

    #[display(fmt = "Not allowed to publish outside of publisher jail")]
    UriOutsideJail,

    #[display(fmt = "File already exists for uri (use update!)")]
    ObjectAlreadyPresent,

    #[display(fmt = "No file found for hash at uri")]
    NoObjectForHashAndOrUri,

    #[display(fmt = "Publisher has been deactivated")]
    PublisherDeactivated,

    // 2300s CA Admin Issues
    #[display(fmt = "Child with name exists")]
    DuplicateChild,

    #[display(fmt = "Child MUST have resources")]
    ChildNeedsResources,

    #[display(fmt = "Child cannot have resources not held by parent")]
    ChildOverclaims,

    #[display(fmt = "Parent with name exists")]
    DuplicateParent,

    #[display(fmt = "Child unknown")]
    UnknownChild,

    // 3000s General server errors
    #[display(fmt = "Cannot update internal state, issue with work_dir?")]
    Persistence,

    #[display(fmt = "Cannot update repository, issue with repo_dir?")]
    RepositoryUpdate,

    #[display(fmt = "Signing error, issue with openssl version or work_dir?")]
    SigningError,

    #[display(fmt = "Proxy server error.")]
    ProxyError,

    #[display(fmt = "General CA Server issue.")]
    CaServerError,

    #[display(fmt = "Publication Client Server issue.")]
    PubClientServerError,

    #[display(fmt = "Unrecognised error (this is a bug)")]
    Unknown,
}

impl From<usize> for ErrorCode {
    fn from(n: usize) -> Self {
        match n {
            // 1000s -> Parsing issues, possible bugs
            1001 => ErrorCode::InvalidJson,
            1002 => ErrorCode::InvalidPublisherRequest,
            1003 => ErrorCode::InvalidPublicationXml,
            1004 => ErrorCode::InvalidHandle,
            1005 => ErrorCode::InvalidCms,

            // 2000s -> General client issues
            2001 => ErrorCode::CmsValidation,
            2002 => ErrorCode::ConcurrentModification,

            // 2100s -> Pub Admin issues
            2101 => ErrorCode::InvalidBaseUri,
            2102 => ErrorCode::DuplicateHandle,

            // 2200s -> Pub Client issues
            2201 => ErrorCode::UnknownPublisher,
            2202 => ErrorCode::UriOutsideJail,
            2203 => ErrorCode::ObjectAlreadyPresent,
            2204 => ErrorCode::NoObjectForHashAndOrUri,
            2205 => ErrorCode::PublisherDeactivated,

            // 2300s -> CA Admin issues
            2301 => ErrorCode::DuplicateChild,
            2302 => ErrorCode::ChildNeedsResources,
            2303 => ErrorCode::ChildOverclaims,
            2304 => ErrorCode::DuplicateParent,
            2305 => ErrorCode::UnknownChild,

            // 3000s -> Server issues, bugs or operational issues
            3001 => ErrorCode::Persistence,
            3002 => ErrorCode::RepositoryUpdate,
            3003 => ErrorCode::SigningError,
            3004 => ErrorCode::ProxyError,
            3005 => ErrorCode::CaServerError,
            3006 => ErrorCode::PubClientServerError,

            _ => ErrorCode::Unknown,
        }
    }
}

impl Into<ErrorResponse> for ErrorCode {
    fn into(self) -> ErrorResponse {
        let code = match self {
            // Parsing issues (bugs?)
            ErrorCode::InvalidJson => 1001,
            ErrorCode::InvalidPublisherRequest => 1002,
            ErrorCode::InvalidPublicationXml => 1003,
            ErrorCode::InvalidHandle => 1004,
            ErrorCode::InvalidCms => 1005,

            // general errors
            ErrorCode::CmsValidation => 2001,
            ErrorCode::ConcurrentModification => 2002,

            // pub admin errors
            ErrorCode::InvalidBaseUri => 2101,
            ErrorCode::DuplicateHandle => 2102,

            // pub client errors
            ErrorCode::UnknownPublisher => 2201,
            ErrorCode::UriOutsideJail => 2202,
            ErrorCode::ObjectAlreadyPresent => 2203,
            ErrorCode::NoObjectForHashAndOrUri => 2204,
            ErrorCode::PublisherDeactivated => 2205,

            // ca admin errors
            ErrorCode::DuplicateChild => 2301,
            ErrorCode::ChildNeedsResources => 2302,
            ErrorCode::ChildOverclaims => 2303,
            ErrorCode::DuplicateParent => 2304,
            ErrorCode::UnknownChild => 2305,

            // server errors
            ErrorCode::Persistence => 3001,
            ErrorCode::RepositoryUpdate => 3002,
            ErrorCode::SigningError => 3003,
            ErrorCode::ProxyError => 3004,
            ErrorCode::CaServerError => 3005,
            ErrorCode::PubClientServerError => 3006,

            ErrorCode::Unknown => 65535,
        };
        let msg = format!("{}", self);

        ErrorResponse { code, msg }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_code_to_number_and_back() {
        fn test_code(number_to_test: usize) {
            let code = ErrorCode::from(number_to_test);
            let response: ErrorResponse = code.into();
            assert_eq!(number_to_test, response.code());
        }

        for n in 1001..1006 {
            test_code(n)
        }

        for n in 2001..2003 {
            test_code(n)
        }

        for n in 2101..2103 {
            test_code(n)
        }

        for n in 2201..2206 {
            test_code(n)
        }

        for n in 2301..2306 {
            test_code(n)
        }

        for n in 3001..3007 {
            test_code(n)
        }
    }
}
