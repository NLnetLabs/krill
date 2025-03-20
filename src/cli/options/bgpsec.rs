//! Managing a CA’s router keys.

use std::{error, fmt, fs, io};
use std::convert::Infallible;
use std::str::FromStr;
use rpki::ca::csr::BgpsecCsr;
use rpki::crypto::{KeyIdentifier, SignatureVerificationError};
use rpki::dep::bcder::decode::DecodeError;
use rpki::repository::resources::Asn;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::api;
use crate::commons::httpclient;
use super::ca;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Show current BGPsec router keys
    List(List),

    /// Add a BGPsec router key
    Add(Add),

    /// Remove a BGPsec router key
    Remove(Remove),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::List(cmd) => cmd.run(client).await.into(),
            Self::Add(cmd) => cmd.run(client).await.into(),
            Self::Remove(cmd) => cmd.run(client).await.into(),
        }
    }
}


//-------- List --------------------------------------------------------------

#[derive(clap::Args)]
pub struct List {
    #[command(flatten)]
    ca: ca::Handle,
}

impl List {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::bgpsec::BgpSecCsrInfoList, httpclient::Error> {
        client.bgpsec_list(&self.ca.ca).await
    }
}


//------------ Add ----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    #[command(flatten)]
    ca: ca::Handle,

    /// The ASN to authorize the router key for
    #[arg(long, short, value_name = "ASN")]
    asn: Asn,

    /// Path to the DER-encoded certificate signing request
    #[arg(long, value_name = "path")]
    csr: BgpsecCsrFile,
}

impl Add {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.bgpsec_update(
            &self.ca.ca,
            api::bgpsec::BgpSecDefinitionUpdates {
                add: vec![
                    api::bgpsec::BgpSecDefinition {
                        asn: self.asn,
                        csr: self.csr.0,
                    }
                ],
                remove: Vec::new(),
            }
        ).await
    }
}


//------------ Remove --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Remove {
    #[command(flatten)]
    ca: ca::Handle,

    /// The ASN of router key to be removed
    #[arg(long, short, value_name = "ASN")]
    asn: Asn,

    /// The hex encoded key identifier of the router key
    #[arg(long, value_name = "key identifier")]
    key: KeyIdentifier,
}

impl Remove {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.bgpsec_update(
            &self.ca.ca,
            api::bgpsec::BgpSecDefinitionUpdates {
                add: Vec::new(),
                remove: vec![
                    api::bgpsec::BgpSecAsnKey {
                        asn: self.asn, key: self.key
                    }
                ],
            }
        ).await
    }
}


//============ Argument Parser Types =========================================

//------------ BgpsecCsrFile -------------------------------------------------

#[derive(Clone, Debug)]
struct BgpsecCsrFile(BgpsecCsr);

impl FromStr for BgpsecCsrFile {
    type Err = BgpsecCsrFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let csr = BgpsecCsr::decode(
            fs::read(path).map_err(|err| {
                BgpsecCsrFileError::Io(path.into(), err)
            })?.as_slice()
        ).map_err(|err| BgpsecCsrFileError::Decode(path.into(), err))?;
        csr.verify_signature().map_err(|err| {
            BgpsecCsrFileError::Verify(path.into(), err)
        })?;
        Ok(Self(csr))
    }
}


//============ ErrorTypes ====================================================

//------------ BgpsecCsrFileError --------------------------------------------

#[derive(Debug)]
enum BgpsecCsrFileError {
    Io(String, io::Error),
    Decode(String, DecodeError<Infallible>),
    Verify(String, SignatureVerificationError),
}

impl fmt::Display for BgpsecCsrFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(f, "Failed to read CSR file '{}': {}", path, err)
            }
            Self::Decode(path, err) => {
                write!(f, "Failed to parse CSR file '{}': {}", path, err)
            }
            Self::Verify(path, err) => {
                write!(
                    f, "Failed to verify signature in CSR file '{}': {}",
                    path, err
                )
            }
        }
    }
}

impl error::Error for BgpsecCsrFileError { }

