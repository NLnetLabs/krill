//! Managing a CA’s repository configuration

use std::{error, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use rpki::ca::idexchange;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::api;
use crate::commons::httpclient;
use super::ca;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Show RFC 8183 Publisher Request XML
    Request(Request),

    /// Show current repo configuration
    Show(Show),

    /// Show current repo status
    Status(Status),

    /// Configure which repository a CA uses
    Configure(Configure),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Request(cmd) => cmd.run(client).await.into(),
            Self::Show(cmd) => cmd.run(client).await.into(),
            Self::Status(cmd) => cmd.run(client).await.into(),
            Self::Configure(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ Request ------------------------------------------------------

#[derive(clap::Args)]
pub struct Request {
    #[command(flatten)]
    pub ca: ca::Handle,
}

impl Request {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::PublisherRequest, httpclient::Error> {
        client.repo_request(&self.ca.ca).await
    }
}


//------------ Show ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Show {
    #[command(flatten)]
    pub ca: ca::Handle,
}

impl Show {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::CaRepoDetails, httpclient::Error> {
        client.repo_details(&self.ca.ca).await
    }
}


//------------ Status --------------------------------------------------------

#[derive(clap::Args)]
pub struct Status {
    #[command(flatten)]
    pub ca: ca::Handle,
}

impl Status {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::RepoStatus, httpclient::Error> {
        client.repo_status(&self.ca.ca).await
    }
}


//------------ Configure -----------------------------------------------------

#[derive(clap::Parser)]
pub struct Configure {
    #[command(flatten)]
    ca: ca::Handle,

    /// Path to the RFC 8183 Publisher Response XML file
    #[arg(long, short, value_name = "path")]
    response: RepositoryResponseFile
}

impl Configure {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.repo_update(&self.ca.ca, self.response.0).await
    }
}


//============ Argument Parser Types =========================================

//------------ RepositoryResponseFile ----------------------------------------

#[derive(Clone, Debug)]
pub struct RepositoryResponseFile(idexchange::RepositoryResponse);

impl FromStr for RepositoryResponseFile {
    type Err = RepositoryResponseFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        idexchange::RepositoryResponse::parse(
            BufReader::new(
                File::open(path).map_err(|err| {
                    RepositoryResponseFileError::Io(path.into(), err)
                })?
            )
        ).map(Self).map_err(|err| {
            RepositoryResponseFileError::Parse(path.into(), err)
        })
    }
}

impl From<RepositoryResponseFile> for idexchange::RepositoryResponse {
    fn from(src: RepositoryResponseFile) -> Self {
        src.0
    }
}


//============ ErrorTypes ====================================================

//------------ RepositoryResponseFileError -----------------------------------

#[derive(Debug)]
pub enum RepositoryResponseFileError {
    Io(String, io::Error),
    Parse(String, idexchange::Error),
}

impl fmt::Display for RepositoryResponseFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(
                    f, "Failed to read repository response file '{}': {}'",
                    path, err
                )
            }
            Self::Parse(path, err) => {
                write!(
                    f, "Failed to parse repository response file '{}': {}'",
                    path, err
                )
            }
        }
    }
}

impl error::Error for RepositoryResponseFileError { }

