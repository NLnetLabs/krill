//! Defines helper methods for Serializing and Deserializing external types.
use std::{
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use log::LevelFilter;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use syslog::Facility;

use rpki::{
    crypto::PublicKey,
    repository::resources::{AsBlocks, IpBlocks},
};

//------------ Bytes ---------------------------------------------------------

pub fn de_bytes<'de, D>(d: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let some = String::deserialize(d)?;
    let dec = base64::decode(&some).map_err(de::Error::custom)?;
    Ok(Bytes::from(dec))
}

pub fn ser_bytes<S>(b: &Bytes, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64::encode(b).serialize(s)
}

//------------ AsBlocks ------------------------------------------------------

pub fn ser_as_blocks_opt<S>(blocks: &Option<AsBlocks>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match blocks {
        None => "none".serialize(s),
        Some(blocks) => blocks.to_string().serialize(s),
    }
}

pub fn de_as_blocks_opt<'de, D>(d: D) -> Result<Option<AsBlocks>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    if string.as_str() == "none" {
        return Ok(None);
    }
    let blocks = AsBlocks::from_str(string.as_str()).map_err(de::Error::custom)?;

    Ok(Some(blocks))
}

//------------ IpBlocks ------------------------------------------------------

pub fn de_ip_blocks_4<'de, D>(d: D) -> Result<IpBlocks, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    if string.contains(':') {
        return Err(de::Error::custom("Cannot deserialize IPv6 into IPv4 field"));
    }
    IpBlocks::from_str(string.as_str()).map_err(de::Error::custom)
}

pub fn ser_ip_blocks_4<S>(blocks: &IpBlocks, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    blocks.as_v4().to_string().serialize(s)
}

pub fn de_ip_blocks_4_opt<'de, D>(d: D) -> Result<Option<IpBlocks>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    if string.as_str() == "none" {
        return Ok(None);
    }
    if string.contains(':') {
        return Err(de::Error::custom("Cannot deserialize IPv6 into IPv4 field"));
    }

    let blocks = IpBlocks::from_str(string.as_str()).map_err(de::Error::custom)?;

    Ok(Some(blocks))
}

pub fn ser_ip_blocks_4_opt<S>(blocks: &Option<IpBlocks>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match blocks {
        None => "none".serialize(s),
        Some(blocks) => blocks.as_v4().to_string().serialize(s),
    }
}

pub fn de_ip_blocks_6<'de, D>(d: D) -> Result<IpBlocks, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    if string.contains('.') {
        return Err(de::Error::custom("Cannot deserialize IPv4 into IPv6 field"));
    }
    IpBlocks::from_str(string.as_str()).map_err(de::Error::custom)
}

pub fn ser_ip_blocks_6<S>(blocks: &IpBlocks, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    blocks.as_v6().to_string().serialize(s)
}

pub fn de_ip_blocks_6_opt<'de, D>(d: D) -> Result<Option<IpBlocks>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    if string.as_str() == "none" {
        return Ok(None);
    }
    if string.contains('.') {
        return Err(de::Error::custom("Cannot deserialize IPv4 into IPv6 field"));
    }

    let blocks = IpBlocks::from_str(string.as_str()).map_err(de::Error::custom)?;

    Ok(Some(blocks))
}

pub fn ser_ip_blocks_6_opt<S>(blocks: &Option<IpBlocks>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match blocks {
        None => "none".serialize(s),
        Some(blocks) => blocks.as_v6().to_string().serialize(s),
    }
}

//------------ LevelFilter ---------------------------------------------------

pub fn de_level_filter<'de, D>(d: D) -> Result<LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    LevelFilter::from_str(&string).map_err(de::Error::custom)
}

//------------ Facility ------------------------------------------------------

pub fn de_facility<'de, D>(d: D) -> Result<Facility, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    Facility::from_str(&string).map_err(|_| de::Error::custom(format!("Unsupported syslog_facility: \"{}\"", string)))
}

//------------ PublicKey ----------------------------------------------------

pub fn ser_public_key<S>(public_key: &PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64::encode(public_key.to_info_bytes()).serialize(s)
}

pub fn de_public_key<'de, D>(d: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(d)?;
    let public_key_bytes = base64::decode(string)
        .map_err(|err| de::Error::custom(format!("Invalid public key base64 encoding: {}", err)))?;
    let public_key = PublicKey::decode(&*public_key_bytes)
        .map_err(|err| de::Error::custom(format!("Invalid public key bytes: {}", err)))?;
    Ok(public_key)
}

//------------- AtomicU64 -----------------------------------------------------
// Implemented automatically by Serde derive but only for x86_64 architectures,
// for other architectures (such as armv7 for the Raspberry Pi 4b) it has to be
// implemented manually.

pub fn de_atomicu64<'de, D>(d: D) -> Result<AtomicU64, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(AtomicU64::new(u64::deserialize(d)?))
}

pub fn ser_atomicu64<S>(v: &AtomicU64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u64(v.load(Ordering::SeqCst))
}
