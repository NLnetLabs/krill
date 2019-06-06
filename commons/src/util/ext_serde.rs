//! Defines helper methods for Serializing and Deserializing external types.
use base64;
use bytes::Bytes;
use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use syslog::Facility;


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