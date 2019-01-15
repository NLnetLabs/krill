//! Defines helper methods for Serializing and Deserializing external types.

use base64;
use bytes::Bytes;
use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use syslog::Facility;
use crate::remote::id::IdCert;
use rpki::uri;
use util::softsigner::SignerKeyId;


//------------ Bytes ---------------------------------------------------------

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


//------------ uri::Rsync ----------------------------------------------------

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


//------------ uri::Http -----------------------------------------------------

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


//------------ IdCert --------------------------------------------------------

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

//------------ KeyId ---------------------------------------------------------

pub fn de_key_id<'de, D>(d: D) -> Result<SignerKeyId, D::Error>
where D: Deserializer<'de>
{
    let s = String::deserialize(d)?;
    Ok(SignerKeyId::new(&s))
}

pub fn ser_key_id<S>(key_id: &SignerKeyId, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    key_id.as_ref().serialize(s)
}


//------------ LevelFilter ---------------------------------------------------

pub fn de_level_filter<'de, D>(d: D) -> Result<LevelFilter, D::Error>
where D: Deserializer<'de>
{
    use std::str::FromStr;
    let string = String::deserialize(d)?;
    LevelFilter::from_str(&string).map_err(de::Error::custom)
}


//------------ Facility ------------------------------------------------------

pub fn de_facility<'de, D>(d: D) -> Result<Facility, D::Error>
    where D: Deserializer<'de>
{
    use std::str::FromStr;
    let string = String::deserialize(d)?;
    Facility::from_str(&string).map_err(
        |_| { de::Error::custom(
            format!("Unsupported syslog_facility: \"{}\"", string))})
}

