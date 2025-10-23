//! The content of a RISwhois dump.

use std::{error, fmt, io};
use std::str::FromStr;
use std::io::BufReader;
use libflate::gzip;
use crate::api::roa::{AsNumber, Ipv4Prefix, Ipv6Prefix};
use super::iptree::{RouteOrigin, RouteOriginCollection, RoutePrefix};


//------------ RisWhois ------------------------------------------------------

pub struct RisWhois {
    v4: RouteOriginCollection<Ipv4Prefix>,
    v6: RouteOriginCollection<Ipv6Prefix>,
}

impl RisWhois {
    pub async fn load(
        v4_uri: &str, v6_uri: &str
    ) -> Result<Self, RisWhoisError> {
        Ok(Self {
            v4: Self::load_tree(v4_uri).await?,
            v6: Self::load_tree(v6_uri).await?,
        })
    }

    async fn load_tree<P: FromStr + RoutePrefix>(
        uri: &str
    ) -> Result<RouteOriginCollection<P>, RisWhoisError>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        Self::parse_gz_data(
            &reqwest::get(uri).await.map_err(|err| {
                RisWhoisError::new(uri, io::Error::other(err))
            })?.bytes().await.map_err(|err| {
                RisWhoisError::new(uri, io::Error::other(err))
            })?
        ).map_err(|err| RisWhoisError::new(uri, err))
    }

    fn parse_gz_data<P: FromStr + RoutePrefix>(
        data: &[u8]
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let data = BufReader::new(
            gzip::Decoder::new(data)?
        );
        Self::parse_data(data)
    }

    fn parse_data<P: FromStr + RoutePrefix>(
        data: impl io::BufRead,
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let mut res = Vec::new();
        for line in data.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with('%') {
                continue;
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(
                io::Error::other("missing column")
            )?;
            let prefix_str = values.next().ok_or(
                io::Error::other("missing column")
            )?;
            let peers = values.next().ok_or(
                io::Error::other("missing column")
            )?;

            if u32::from_str(peers).map_err(io::Error::other)? <= 5 {
                continue;
            }

            if asn_str.contains('{') {
                continue; // assets not supported (not important here either)
            }

            let origin = AsNumber::from_str(asn_str).map_err(io::Error::other)?;
            let prefix = P::from_str(prefix_str).map_err(io::Error::other)?;

            res.push(RouteOrigin { prefix, origin });
        }

        Ok(RouteOriginCollection::new(res).unwrap())
    }
}


        /*

use std::fmt;
use std::io::{BufRead, Read};
use std::num::ParseIntError;
use std::str::FromStr;
use bytes::Bytes;
use libflate::gzip::Decoder;
use crate::api::{AsNumber, AuthorizationFmtError, TypedPrefix};
use crate::commons::error::KrillIoError;
use super::bgp::Announcement;
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

    pub async fn download_updates(&self) -> Result<Vec<Announcement>, RisWhoisError> {
        let v4_bytes: Bytes = reqwest::get(&self.bgp_risdumps_v4_uri).await?.bytes().await?;

        let v4_bytes = Self::gunzip(v4_bytes)?;

        let mut res = Self::parse_dump(v4_bytes.as_slice())?;

        let v6_bytes: Bytes = reqwest::get(&self.bgp_risdumps_v6_uri).await?.bytes().await?;

        let v6_bytes = Self::gunzip(v6_bytes)?;

        res.append(&mut Self::parse_dump(v6_bytes.as_slice())?);

        Ok(res)
    }

    fn gunzip(bytes: Bytes) -> Result<Vec<u8>, RisWhoisError> {
        let mut gunzipped: Vec<u8> = vec![];
        let mut decoder = Decoder::new(bytes.as_ref())
            .map_err(|e| RisWhoisError::UnzipError(format!("Could not unzip dump file: {}", e)))?;

        decoder
            .read_to_end(&mut gunzipped)
            .map_err(|e| )?;

        Ok(gunzipped)
    }

    fn parse_dump(bytes: &[u8]) -> Result<Vec<Announcement>, RisWhoisError> {
        let mut res = vec![];
        for lines_res in bytes.lines() {
            let line = lines_res.map_err(RisWhoisError::parse_error)?;
            if line.is_empty() || line.starts_with('%') {
                continue;
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(RisWhoisError::MissingColumn)?;
            let prefix_str = values.next().ok_or(RisWhoisError::MissingColumn)?;
            let peers = values.next().ok_or(RisWhoisError::MissingColumn)?;

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
*/

//------------ RisWhoisError ------------------------------------------------

#[derive(Debug)]
pub struct RisWhoisError {
    uri: String,
    err: io::Error,
}

impl RisWhoisError {
    fn new(uri: &str, err: io::Error) -> Self {
        Self { uri: uri.into(), err }
    }
}

impl fmt::Display for RisWhoisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Failed to download RISwhois file `{}`: {}",
            self.uri, self.err
        )
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_bgp_ris_dumps() {
        let ris = RisWhois {
            v4: RisWhois::parse_data(include_bytes!(
                "../../../test-resources/bgp/riswhoisdump.IPv4"
            ).as_ref()).unwrap(),
            v6: RisWhois::parse_data(include_bytes!(
                "../../../test-resources/bgp/riswhoisdump.IPv6"
            ).as_ref()).unwrap(),
        };

        let v4 = ris.v4.iter().collect::<Vec<_>>();
        for item in v4.windows(2) {
            assert!(item[0][0].prefix < item[1][0].prefix)
        }
        let v6 = ris.v6.iter().collect::<Vec<_>>();
        for item in v4.windows(2) {
            assert!(item[0][0].prefix < item[1][0].prefix)
        }
    }
}

