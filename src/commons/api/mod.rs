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

    pub fn size(&self) -> usize {
        self.0.len()
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

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", unsafe {
            std::str::from_utf8_unchecked(self.0.as_ref())
        })
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

impl From<&Cert> for HexEncodedHash {
    fn from(cert: &Cert) -> Self {
        Self::from_content(cert.to_captured().as_slice())
    }
}

impl From<String> for HexEncodedHash {
    fn from(s: String) -> Self {
        HexEncodedHash(Bytes::from(s.to_lowercase()))
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

impl fmt::Display for HexEncodedHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = unsafe { String::from_utf8_unchecked(self.0.to_vec()) };
        write!(f, "{}", string)
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorResponse {
    code: usize,
    msg: String,
    args: Vec<String>,
}

impl ErrorResponse {
    pub fn with_args(code: usize, msg: String, args: Vec<String>) -> Self {
        ErrorResponse { code, msg, args }
    }

    pub fn no_args(code: usize, msg: impl fmt::Display) -> Self {
        ErrorResponse {
            code,
            msg: msg.to_string(),
            args: vec![],
        }
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
