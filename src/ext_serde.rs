//! Defines helper methods for Serializing and Deserializing external types.

use base64;
use bytes::Bytes;
use rpki::uri;
use rpki::remote::idcert::IdCert;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;

pub fn de_rsync_uri<'de, D>(d: D) -> Result<uri::Rsync, D::Error>
    where D: Deserializer<'de> {
    match String::deserialize(d) {
        Ok(some) => uri::Rsync::from_string(some).map_err(de::Error::custom),
        Err(err) => Err(err)
    }
}

pub fn ser_rsync_uri<S>(uri: &uri::Rsync, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
    uri.to_string().serialize(s)
}

pub fn de_http_uri<'de, D>(d: D) -> Result<uri::Http, D::Error>
    where D: Deserializer<'de> {
    match String::deserialize(d) {
        Ok(some) => uri::Http::from_string(some).map_err(de::Error::custom),
        Err(err) => Err(err)
    }
}

pub fn ser_http_uri<S>(uri: &uri::Http, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
    uri.to_string().serialize(s)
}

pub fn de_id_cert<'de, D>(d: D) -> Result<IdCert, D::Error>
    where D: Deserializer<'de> {
    match String::deserialize(d) {
        Ok(some) => {
            let dec = base64::decode(&some).map_err(de::Error::custom)?;
            let b = Bytes::from(dec);
            IdCert::decode(b).map_err(de::Error::custom)
        },
        Err(err) => Err(err)
    }
}

pub fn ser_id_cert<S>(cert: &IdCert, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
    let bytes = cert.to_bytes();
    let str = base64::encode(&bytes);
    str.serialize(s)
}
