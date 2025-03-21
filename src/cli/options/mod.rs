//! The options for the regular Krill client.

//------------ Sub-modules ---------------------------------------------------

pub mod args;
mod aspa;
mod bgpsec;
mod bulk;
mod ca;
mod children;
mod config;
mod parents;
mod pubserver;
pub mod repo;
mod roas;
mod server;


//------------ Content -------------------------------------------------------

use rpki::ca::idexchange::ServiceUri;
use clap::Parser;
use crate::api::admin::Token;
use super::client::KrillClient;
use super::report::{Report, ReportFormat};


//------------ Options -------------------------------------------------------

/// The command line options for the Krill client.
#[derive(clap::Parser)]
#[command(
    version,
    about = "The Krill command line client.",
)]
pub struct Options {
    #[command(flatten)]
    pub general: GeneralOptions,

    #[command(subcommand)]
    pub command: Command,
}

impl Options {
    /// Creates the options from the process arguments.
    ///
    /// If the arguments won’t result in usable options, exits the process.
    pub fn from_args() -> Self {
        Self::parse()
    }
}


//------------ GeneralOptions ------------------------------------------------

/// The options common between all command line tools.
#[derive(clap::Args)]
#[command(version)]
pub struct GeneralOptions {
    /// The full URI to the Krill server.
    #[arg(
        short, long,
        env = "KRILL_CLI_SERVER",
        default_value = "https://localhost:3000/"
    )]
    pub server: ServiceUri,

    /// The secret token for the Krill server.
    #[arg(
        short, long,
        env = "KRILL_CLI_TOKEN"
   )]
    pub token: Token,

    /// Report format
    #[arg(
        short, long,
        env = "KRILL_CLI_FORMAT",
        default_value = "text",
    )]
    pub format: ReportFormat,

    /// Only show the API call and exit.
    #[arg(long)]
    pub api: bool,
}


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Creates a configuration file for Krill and prints it to stdout.
    #[command(subcommand)]
    Config(config::Command),

    /// Perform an authenticated health check.
    Health(server::Health),

    /// Show server info.
    Info(server::Info),

    /// List the current CAs
    List(ca::List),

    /// Show details of a CA
    Show(ca::Show),

    /// Show the history of a CA
    #[command(subcommand)]
    History(ca::History),

    /// Add a new CA
    Add(ca::Add),

    /// Delete a CA and let it withdraw its objects and request revocation.
    /// WARNING: Irreversible!
    Delete(ca::Delete),

    /// Show issues
    Issues(server::Issues),

    /// Manage children of a CA
    #[command(subcommand)]
    Children(children::Command),

    /// Manage parents for a CA
    #[command(subcommand)]
    Parents(parents::Command),

    /// Perform a manual key rollover for a CA
    #[command(subcommand)]
    Keyroll(ca::Keyroll),

    /// Manage the repository of a CA
    #[command(subcommand)]
    Repo(repo::Command),

    /// Manage the ROAs of a CA
    #[command(subcommand)]
    Roas(roas::Command),

    /// Manage the BGPsec router keys of a CA
    #[command(subcommand)]
    Bgpsec(bgpsec::Command),

    /// Manage the ASPAs of a CA
    #[command(subcommand)]
    Aspas(aspa::Command),

    /// Manage the Publication Server.
    #[command(subcommand)]
    Pubserver(pubserver::Command),

    /// Manually trigger refresh/republish/resync for all CAs
    #[command(subcommand)]
    Bulk(bulk::Command),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Config(cmd) => cmd.run(client).await,
            Self::Health(cmd) => cmd.run(client).await.into(),
            Self::Info(cmd) => cmd.run(client).await.into(),
            Self::List(cmd) => cmd.run(client).await.into(),
            Self::Show(cmd) => cmd.run(client).await.into(),
            Self::History(cmd) => cmd.run(client).await,
            Self::Add(cmd) => cmd.run(client).await.into(),
            Self::Delete(cmd) => cmd.run(client).await.into(),
            Self::Issues(cmd) => cmd.run(client).await,
            Self::Children(cmd) => cmd.run(client).await,
            Self::Parents(cmd) => cmd.run(client).await,
            Self::Keyroll(cmd) => cmd.run(client).await,
            Self::Repo(cmd) => cmd.run(client).await,
            Self::Roas(cmd) => cmd.run(client).await,
            Self::Bgpsec(cmd) => cmd.run(client).await,
            Self::Aspas(cmd) => cmd.run(client).await,
            Self::Pubserver(cmd) => cmd.run(client).await,
            Self::Bulk(cmd) => cmd.run(client).await,
        }
    }
}


