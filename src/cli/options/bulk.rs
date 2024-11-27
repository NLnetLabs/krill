//! Commands triggering events for all CAs.

use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Force all CAs to ask their parents for updated certificates
    Refresh(Refresh),

    /// Force all CAs to create new objects if needed (in which case they
    /// will also sync)
    Publish(Publish),

    /// Force all CAs to sync with their repo server
    Sync(SyncRepo),
}

impl Command {
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Refresh(cmd) => cmd.run(client).into(),
            Self::Publish(cmd) => cmd.run(client).into(),
            Self::Sync(cmd) => cmd.run(client).into(),
        }
    }
}


//------------ Refresh -------------------------------------------------------

#[derive(clap::Parser)]
pub struct Refresh;

impl Refresh {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.bulk_sync_parents()
    }
}


//------------ Publish -------------------------------------------------------

#[derive(clap::Parser)]
pub struct Publish;

impl Publish {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.bulk_publish()
    }
}


//------------ SyncRepo ------------------------------------------------------

#[derive(clap::Parser)]
pub struct SyncRepo;

impl SyncRepo {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.bulk_sync_repo()
    }
}


