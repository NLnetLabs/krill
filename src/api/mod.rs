//! Data structures for the API, shared between client and server.
pub mod publisher_data;
pub mod publication_data;
pub mod repo_data;

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
#[derive(Clone, Debug, Serialize)]
pub struct Link {
    rel: String,
    link: String
}
