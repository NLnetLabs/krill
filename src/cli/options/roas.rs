//! Managing a CA’s ROAs.

use std::{error, fmt, fs, io};
use std::str::FromStr;
use rpki::repository::resources::{
    AsBlocks, Ipv4Blocks, Ipv6Blocks, ResourceSet,
};
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;
use super::ca;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// List current ROAs
    List(List),

    /// Add and remove ROAs
    Update(Update),

    /// Show current authorizations in relation to known announcements
    #[command(subcommand)]
    Bgp(BgpCommand),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::List(cmd) => cmd.run(client).await.into(),
            Self::Update(cmd) => cmd.run(client).await,
            Self::Bgp(cmd) => cmd.run(client).await,
        }
    }
}


//------------ List ---------------------------------------------------------

#[derive(clap::Args)]
pub struct List {
    #[command(flatten)]
    pub ca: ca::Handle,
}

impl List {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::roa::ConfiguredRoas, httpclient::Error> {
        client.roas_list(&self.ca.ca).await
    }
}


//------------ Update --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Update{
    #[command(flatten)]
    pub ca: ca::Handle,

    /// Path to a file with added and removed ROAs
    #[arg(long, value_name = "path")]
    pub delta: Option<RoaUpdatesFile>,

    /// One or more ROAs to add
    #[arg(long, value_name = "ROA definitions", conflicts_with = "delta")]
    pub add: Vec<api::roa::RoaConfiguration>,

    /// One or more ROAs to remove
    #[arg(long, value_name = "ROA definitions", conflicts_with = "delta")]
    pub remove: Vec<api::roa::RoaPayload>,

    /// Perform a dry run of the update, return the BGP analysis
    #[arg(long)]
    pub dryrun: bool,

    /// Try to perform the update, advice for errors or invalids
    #[arg(long = "try", conflicts_with = "dryrun")]
    pub try_update: bool,
}

impl Update{
    pub async fn run(
        self, client: &KrillClient
    ) -> Report {
        let updates = match self.delta {
            Some(updates) => updates.0,
            None => {
                api::roa::RoaConfigurationUpdates {
                    added: self.add,
                    removed: self.remove
                }
            }
        };

        if self.dryrun {
            client.roas_dryrun_update(&self.ca.ca, updates).await.into()
        }
        else if self.try_update {
            Report::from_opt_result(
                client.roas_try_update(&self.ca.ca, updates).await
            )
        }
        else {
            client.roas_update(&self.ca.ca, updates).await.into()
        }
    }
}


//------------ BgpCommand ----------------------------------------------------

#[derive(clap::Subcommand)]
pub enum BgpCommand {
    /// Show full report of ROAs vs known BGP announcements
    Analyze(Analyze),

    /// Show ROA suggestions based on known BGP announcements
    Suggest(Suggest),
}

impl BgpCommand {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Analyze(cmd) => cmd.run(client).await.into(),
            Self::Suggest(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ Analyze -------------------------------------------------------

#[derive(clap::Args)]
pub struct Analyze {
    #[command(flatten)]
    ca: ca::Handle,
}

impl Analyze {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::bgp::BgpAnalysisReport, httpclient::Error> {
        client.roas_analyze(&self.ca.ca).await
    }
}


//------------ Suggest ------------------------------------------------------

#[derive(clap::Parser)]
pub struct Suggest {
    #[command(flatten)]
    ca: ca::Handle,

    /// Scope to these IPv4 resources
    #[arg(short = '4', long, value_name = "IPv4 resources")]
    ipv4: Option<Ipv4Blocks>,

    /// Scope to these IPv6 resources
    #[arg(short = '6', long, value_name = "IPv6 resources")]
    ipv6: Option<Ipv6Blocks>,
}

impl Suggest {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::bgp::BgpAnalysisSuggestion, httpclient::Error> {
        client.roas_suggest(
            &self.ca.ca,
            if self.ipv4.is_some() || self.ipv6.is_some() {
                Some(ResourceSet::new(
                    AsBlocks::default(),
                    self.ipv4.unwrap_or_default(),
                    self.ipv6.unwrap_or_default(),
                ))
            }
            else {
                None
            }
        ).await
    }
}


//============ Argument Parser Types =========================================

//------------ RoaUpdatesFile ------------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaUpdatesFile(api::roa::RoaConfigurationUpdates);

impl FromStr for RoaUpdatesFile {
    type Err = RoaUpdatesFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            api::roa::RoaConfigurationUpdates::from_str(
                &fs::read_to_string(path).map_err(|err| {
                    RoaUpdatesFileError::Io(path.into(), err)
                })?
            ).map_err(|err| {
                RoaUpdatesFileError::Parse(path.into(), err)
            })?
        ))
    }
}


//============ ErrorTypes ====================================================

//------------ RoaUpdatesFileError -------------------------------------------

#[derive(Debug)]
pub enum RoaUpdatesFileError {
    Io(String, io::Error),
    Parse(String, api::roa::AuthorizationFmtError),
}

impl fmt::Display for RoaUpdatesFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(f, "Failed to read delta file '{}': {}", path, err)
            }
            Self::Parse(path, err) => {
                write!(f, "Failed to parse delta file '{}': {}", path, err)
            }
        }
    }
}

impl error::Error for RoaUpdatesFileError { }

