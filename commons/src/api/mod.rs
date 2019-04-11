//! Data structures for the API, shared between client and server.
pub mod admin;
pub mod publication;
pub mod rrdp;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::util::sha256;


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

    pub fn to_encoded_hash(&self) -> EncodedHash {
        EncodedHash::from(self.to_hex_hash())
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


impl ToString for Base64 {
    fn to_string(&self) -> String {
        unsafe {
            String::from_utf8_unchecked(self.0.to_vec())
        }
    }
}

impl Serialize for Base64 {
    fn serialize<S>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> where S: Serializer {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D>(
        deserializer: D
    ) -> Result<Base64, D::Error> where D: Deserializer<'de> {
        let string = String::deserialize(deserializer)?;
        Ok(Base64::from(string))
    }
}


//------------ EncodedHash ---------------------------------------------------

/// This type contains a hex encoded sha256 hash.
///
/// Note that we store this in a Bytes for cheap cloning.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EncodedHash(Bytes);

impl EncodedHash {
    pub fn from_content(content: &[u8]) -> Self {
        let sha256 = sha256(content);
        let hex = hex::encode(sha256);
        EncodedHash::from(hex)
    }
}

impl AsRef<str> for EncodedHash {
    fn as_ref(&self) -> &str {
        use std::str;
        str::from_utf8(&self.0).unwrap()
    }
}

impl From<String> for EncodedHash {
    fn from(s: String) -> Self {
        EncodedHash(Bytes::from(s.to_lowercase()))
    }
}

impl ToString for EncodedHash {
    fn to_string(&self) -> String {
        unsafe {
            String::from_utf8_unchecked(self.0.to_vec())
        }
    }
}

impl Serialize for EncodedHash {
    fn serialize<S>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> where S: Serializer {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncodedHash {
    fn deserialize<D>(
        deserializer: D
    ) -> Result<EncodedHash, D::Error> where D: Deserializer<'de> {
        let string = String::deserialize(deserializer)?;
        Ok(EncodedHash::from(string))
    }
}



//------------ Link ----------------------------------------------------------

/// Defines a link element to include as part of a links array in a Json
/// response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Link {
    rel: String,
    link: String
}


//------------ ErrorResponse --------------------------------------------------

/// Defines an error response. Codes are unique and documented here:
/// https://rpki.readthedocs.io/en/latest/krill/pub/api.html#error-responses
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    code: usize,
    msg: String
}

impl ErrorResponse {
    pub fn new(code: usize, msg: String) -> Self { ErrorResponse { code, msg }}
    pub fn code(&self) -> usize { self.code }
    pub fn msg(&self) -> &str { &self.msg }
}

impl Into<ErrorCode> for ErrorResponse {
    fn into(self) -> ErrorCode {
        ErrorCode::from(self.code)
    }
}

/// This type defines externally visible errors that the API may return.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ErrorCode {
    // 1000s (User Input Errors)
    #[display(fmt="Submitted Json cannot be parsed")]
    InvalidJson,

    #[display(fmt="Invalid RFC8183 Publisher Request")]
    InvalidPublisherRequest,

    #[display(fmt="Issue with submitted publication XML")]
    InvalidPublicationXml,

    #[display(fmt="Invalid handle name")]
    InvalidHandle,

    #[display(fmt="Handle already in use")]
    DuplicateHandle,

    // 2000s (Authorisation and Consistency issues)
    #[display(fmt="Unknown publisher")]
    UnknownPublisher,

    #[display(fmt="Submitted protocol CMS does not validate")]
    CmsValidation,

    #[display(fmt="Base URI for publisher is outside of publisher base URI")]
    InvalidBaseUri,

    #[display(fmt="Out of sync with server, please send requests for instances sequentially")]
    ConcurrentModification,

    #[display(fmt="Publisher has been deactivated")]
    PublisherDeactivated,

    #[display(fmt="Not allowed to publish outside of publisher jail")]
    UriOutsideJail,

    #[display(fmt="File already exists for uri (use update!)")]
    ObjectAlreadyPresent,

    #[display(fmt="No file found for hash at uri")]
    NoObjectForHashAndOrUri,

    // 3000s (Server Errors)
    #[display(fmt="Cannot update internal state, issue with work_dir?")]
    Persistence,

    #[display(fmt="Cannot update repository, issue with repo_dir?")]
    RepositoryUpdate,

    #[display(fmt="Signing error, issue with openssl version or work_dir?")]
    SigningError,

    #[display(fmt="Proxy server error.")]
    ProxyError,

    #[display(fmt="Unrecognised error (this is a bug)")]
    Unknown
}

impl From<usize> for ErrorCode {
    fn from(n: usize) -> Self {
        match n {
            1001 => ErrorCode::InvalidJson,
            1002 => ErrorCode::InvalidPublisherRequest,
            1003 => ErrorCode::InvalidPublicationXml,
            1004 => ErrorCode::InvalidHandle,

            2001 => ErrorCode::UnknownPublisher,
            2002 => ErrorCode::CmsValidation,
            2003 => ErrorCode::InvalidBaseUri,
            2004 => ErrorCode::ConcurrentModification,
            2005 => ErrorCode::PublisherDeactivated,
            2006 => ErrorCode::UriOutsideJail,
            2007 => ErrorCode::ObjectAlreadyPresent,
            2008 => ErrorCode::NoObjectForHashAndOrUri,
            2009 => ErrorCode::DuplicateHandle,

            3001 => ErrorCode::Persistence,
            3002 => ErrorCode::RepositoryUpdate,
            3003 => ErrorCode::SigningError,
            3004 => ErrorCode::ProxyError,

            _ => ErrorCode::Unknown
        }
    }
}

impl Into<ErrorResponse> for ErrorCode {
    fn into(self) -> ErrorResponse {
        let code = match self {
            ErrorCode::InvalidJson => 1001,
            ErrorCode::InvalidPublisherRequest => 1002,
            ErrorCode::InvalidPublicationXml => 1003,
            ErrorCode::InvalidHandle => 1004,

            ErrorCode::UnknownPublisher => 2001,
            ErrorCode::CmsValidation => 2002,
            ErrorCode::InvalidBaseUri => 2003,
            ErrorCode::ConcurrentModification => 2004,
            ErrorCode::PublisherDeactivated => 2005,
            ErrorCode::UriOutsideJail => 2006,
            ErrorCode::ObjectAlreadyPresent => 2007,
            ErrorCode::NoObjectForHashAndOrUri => 2008,
            ErrorCode::DuplicateHandle => 2009,

            ErrorCode::Persistence => 3001,
            ErrorCode::RepositoryUpdate => 3002,
            ErrorCode::SigningError => 3003,
            ErrorCode::ProxyError => 3004,

            ErrorCode::Unknown => 65535
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

        for n in 1001..1005 {
            test_code(n)
        }

        for n in 2001..2010 {
            test_code(n)
        }

        for n in 3001..3005 {
            test_code(n)
        }


    }
}

