//! Support parsing announcements in RIS Dumps
//!
//! http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz

use std::{
    fmt,
    io::{BufRead, Read},
    num::ParseIntError,
    str::FromStr,
};

use bytes::Bytes;
use libflate::gzip::Decoder;

use crate::commons::{
    api::{AsNumber, AuthorizationFmtError, TypedPrefix},
    bgp::Announcement,
    error::KrillIoError,
};

pub struct RisDumpLoader {
    bgp_risdumps_v4_uri: String,
    bgp_risdumps_v6_uri: String,
}

impl RisDumpLoader {
    pub fn new(bgp_risdumps_v4_uri: &str, bgp_risdumps_v6_uri: &str) -> Self {
        RisDumpLoader {
            bgp_risdumps_v4_uri: bgp_risdumps_v4_uri.to_string(),
            bgp_risdumps_v6_uri: bgp_risdumps_v6_uri.to_string(),
        }
    }

    pub async fn download_updates(&self) -> Result<Vec<Announcement>, RisDumpError> {
        let v4_bytes: Bytes = reqwest::get(&self.bgp_risdumps_v4_uri).await?.bytes().await?;

        let v4_bytes = Self::gunzip(v4_bytes)?;

        let mut res = Self::parse_dump(v4_bytes.as_slice())?;

        let v6_bytes: Bytes = reqwest::get(&self.bgp_risdumps_v6_uri).await?.bytes().await?;

        let v6_bytes = Self::gunzip(v6_bytes)?;

        res.append(&mut Self::parse_dump(v6_bytes.as_slice())?);

        Ok(res)
    }

    fn gunzip(bytes: Bytes) -> Result<Vec<u8>, RisDumpError> {
        let mut gunzipped: Vec<u8> = vec![];
        let mut decoder = Decoder::new(bytes.as_ref())
            .map_err(|e| RisDumpError::UnzipError(format!("Could not unzip dump file: {}", e)))?;

        decoder
            .read_to_end(&mut gunzipped)
            .map_err(|e| RisDumpError::UnzipError(format!("Could not unzip dump file: {}", e)))?;

        Ok(gunzipped)
    }

    fn parse_dump(bytes: &[u8]) -> Result<Vec<Announcement>, RisDumpError> {
        let mut res = vec![];
        for lines_res in bytes.lines() {
            let line = lines_res.map_err(RisDumpError::parse_error)?;
            if line.is_empty() || line.starts_with('%') {
                continue;
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(RisDumpError::MissingColumn)?;
            let prefix_str = values.next().ok_or(RisDumpError::MissingColumn)?;
            let peers = values.next().ok_or(RisDumpError::MissingColumn)?;

            if u32::from_str(peers)? <= 5 {
                continue;
            }

            if asn_str.contains('{') {
                continue; // assets not supported (not important here either)
            }

            let asn = AsNumber::from_str(asn_str)?;
            let prefix = TypedPrefix::from_str(prefix_str)?;

            let ann = Announcement::new(asn, prefix);
            res.push(ann);
        }
        Ok(res)
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug)]
pub enum RisDumpError {
    ReqwestError(reqwest::Error),
    MissingColumn,
    ParseError(String),
    IoError(KrillIoError),
    UnzipError(String),
}

impl fmt::Display for RisDumpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RisDumpError::ReqwestError(e) => write!(f, "Cannot get uri: {}", e),
            RisDumpError::MissingColumn => write!(f, "Missing column in announcements input"),
            RisDumpError::ParseError(s) => write!(f, "Error parsing announcements: {}", s),
            RisDumpError::IoError(e) => write!(f, "IO error: {}", e),
            RisDumpError::UnzipError(s) => write!(f, "Error unzipping: {}", s),
        }
    }
}

impl RisDumpError {
    fn parse_error(e: impl fmt::Display) -> Self {
        RisDumpError::ParseError(format!("{}", e))
    }
}

impl From<AuthorizationFmtError> for RisDumpError {
    fn from(e: AuthorizationFmtError) -> Self {
        Self::parse_error(e)
    }
}

impl From<ParseIntError> for RisDumpError {
    fn from(e: ParseIntError) -> Self {
        RisDumpError::parse_error(e)
    }
}

impl From<reqwest::Error> for RisDumpError {
    fn from(e: reqwest::Error) -> RisDumpError {
        RisDumpError::ReqwestError(e)
    }
}

impl From<KrillIoError> for RisDumpError {
    fn from(e: KrillIoError) -> Self {
        RisDumpError::IoError(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn download_bgp_ris_dumps() {
        let bgp_ris_dump_v4_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz";
        let bgp_ris_dump_v6_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz";

        let loader = RisDumpLoader::new(bgp_ris_dump_v4_uri, bgp_ris_dump_v6_uri);
        let announcements = loader.download_updates().await.unwrap();

        assert!(!announcements.is_empty())
    }
}
