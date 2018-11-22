//! Defines helper methods for Serializing and Deserializing external types.

use base64;
use bytes::Bytes;
use rpki::uri;
use rpki::remote::idcert::IdCert;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use rpki::signing::signer::KeyId;


pub fn de_bytes<'de, D>(d: D) -> Result<Bytes, D::Error>
where D: Deserializer<'de>
{
    let some = String::deserialize(d)?;
    let dec = base64::decode(&some).map_err(de::Error::custom)?;
    Ok(Bytes::from(dec))
}

pub fn ser_bytes<S>(b: &Bytes, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    base64::encode(b).serialize(s)
}

pub fn de_rsync_uri<'de, D>(d: D) -> Result<uri::Rsync, D::Error>
where D: Deserializer<'de>
{
    let some = String::deserialize(d)?;
    uri::Rsync::from_string(some).map_err(de::Error::custom)
}

pub fn ser_rsync_uri<S>(uri: &uri::Rsync, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    uri.to_string().serialize(s)
}

pub fn de_http_uri<'de, D>(d: D) -> Result<uri::Http, D::Error>
where D: Deserializer<'de>
{
    let some = String::deserialize(d)?;
    uri::Http::from_string(some).map_err(de::Error::custom)
}

pub fn ser_http_uri<S>(uri: &uri::Http, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    uri.to_string().serialize(s)
}

pub fn de_id_cert<'de, D>(d: D) -> Result<IdCert, D::Error>
where D: Deserializer<'de>
{
    let some = String::deserialize(d)?;
    let dec = base64::decode(&some).map_err(de::Error::custom)?;
    let b = Bytes::from(dec);
    IdCert::decode(b).map_err(de::Error::custom)
}

pub fn ser_id_cert<S>(cert: &IdCert, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    let bytes = cert.to_bytes();
    let str = base64::encode(&bytes);
    str.serialize(s)
}

pub fn de_key_id<'de, D>(d: D) -> Result<KeyId, D::Error>
where D: Deserializer<'de>
{
    let s = String::deserialize(d)?;
    Ok(KeyId::new(s))
}

pub fn ser_key_id<S>(key_id: &KeyId, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    key_id.as_str().serialize(s)
}