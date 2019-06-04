//! Defines helper methods for Serializing and Deserializing external types.
use base64;
use bytes::Bytes;
use chrono::Utc;
use log::LevelFilter;
use rpki::uri;
use rpki::x509::{
    Serial,
    Time,
};
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


//------------ Time ----------------------------------------------------------

pub fn de_time<'de, D>(d: D) -> Result<Time, D::Error> where D: Deserializer<'de> {
    use chrono::TimeZone;

    let time_stamp: i64 = i64::deserialize(d)?;
    Ok(Time::new(Utc.timestamp_millis(time_stamp)))
}

pub fn ser_time<S>(time: &Time, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
    time.timestamp_millis().serialize(s)
}

//------------ Serial ----------------------------------------------------------

pub fn de_serial<'de, D>(d: D) -> Result<Serial, D::Error> where D: Deserializer<'de> {
    let s = u128::deserialize(d)?;
    Ok(Serial::from(s))
}

pub fn ser_serial<S>(_serial: &Serial, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
    1_u64.serialize(s)
}