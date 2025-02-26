//! Managing a CA’s parent CAs.

use std::{error, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use rpki::ca::idexchange;
use rpki::ca::idexchange::ParentHandle;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;
use super::ca;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Show RFC 8183 Child Request XML
    Request(Request),

    /// Add a parent to, or update a parent of a CA
    Add(Add),

    /// Show contact information for a parent of a CA
    Contact(CaContact),

    /// Show overview of all parent statuses of a CA
    Statuses(Statuses),

    /// Remove an existing parent from a CA
    Remove(Remove),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Request(cmd) => cmd.run(client).await.into(),
            Self::Add(cmd) => cmd.run(client).await.into(),
            Self::Contact(cmd) => cmd.run(client).await.into(),
            Self::Statuses(cmd) => cmd.run(client).await.into(),
            Self::Remove(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ Handle --------------------------------------------------------

#[derive(clap::Args)]
#[group(id = "parent-handle")]
pub struct Handle {
    #[command(flatten)]
    ca: ca::Handle,

    /// The name of the parent CA you wish to control
    #[arg(long, value_name = "name")]
    parent: ParentHandle,
}


//------------ Request -------------------------------------------------------

#[derive(clap::Args)]
pub struct Request {
    #[command(flatten)]
    ca: ca::Handle,
}

impl Request {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::ChildRequest, httpclient::Error> {
        client.child_request(&self.ca.ca).await
    }
}


//------------ Add -----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    #[command(flatten)]
    handle: Handle,

    /// Path to the RFC 8183 Child Request XML file
    #[arg(long, short, value_name = "path")]
    response: ParentResponse,
}

impl Add {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.parent_add(
            &self.handle.ca.ca,
            api::admin::ParentCaReq {
                handle: self.handle.parent,
                response: self.response.0,
            }
        ).await
    }
}


//------------ CaContact -----------------------------------------------------

#[derive(clap::Args)]
pub struct CaContact {
    #[command(flatten)]
    pub handle: Handle,
}

impl CaContact {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::ParentCaContact, httpclient::Error> {
        client.parent_details(&self.handle.ca.ca, &self.handle.parent).await
    }
}


//------------ Statuses ------------------------------------------------------

#[derive(clap::Args)]
pub struct Statuses {
    #[command(flatten)]
    pub ca: ca::Handle,
}

impl Statuses {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::ParentStatuses, httpclient::Error> {
        client.parent_list(&self.ca.ca).await
    }
}


//------------ Remove --------------------------------------------------------

#[derive(clap::Args)]
pub struct Remove {
    #[command(flatten)]
    pub handle: Handle,
}

impl Remove {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.parent_delete(&self.handle.ca.ca, &self.handle.parent).await
    }
}


//============ Argument Parser Types =========================================

//------------ ParentResponse ------------------------------------------------

#[derive(Clone, Debug)]
pub struct ParentResponse(idexchange::ParentResponse);

impl FromStr for ParentResponse {
    type Err = ParentResponseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        idexchange::ParentResponse::parse(
            BufReader::new(
                File::open(src).map_err(|err| {
                    ParentResponseError::Io(src.into(), err)
                })?
            )
        ).map(Self).map_err(|err| {
            ParentResponseError::Parse(src.into(), err)
        })
    }
}


//============ ErrorTypes ====================================================

//------------ Error -----------------------------------------------

#[derive(Debug)]
pub enum ParentResponseError {
    Io(String, io::Error),
    Parse(String, idexchange::Error),
}

impl fmt::Display for ParentResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(f, "Failed to open request file '{}': {}",
                    path, err
                )
            }
            Self::Parse(path, err) => {
                write!(f, "Failed to parse request file '{}': {}",
                    path, err
                )
            }
        }
    }
}

impl error::Error for ParentResponseError { }

