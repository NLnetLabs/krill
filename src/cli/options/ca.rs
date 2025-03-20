/// Commands related to managing a CA.

use rpki::ca::idexchange::CaHandle;
use rpki::repository::x509::Time;
use crate::api;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::util::httpclient;


//-------- List --------------------------------------------------------------

#[derive(clap::Parser)]
pub struct List;

impl List {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::CertAuthList, httpclient::Error> {
        client.cas_list().await
    }
}


//-------- Handle ------------------------------------------------------------

#[derive(clap::Args)]
pub struct Handle {
    /// Name of the CA to control
    #[arg(long, short, env = "KRILL_CLI_MY_CA")]
    pub ca: CaHandle,
}


//-------- Add ---------------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    #[command(flatten)]
    ca: Handle,
}

impl Add {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.ca_add(self.ca.ca).await
    }
}


//-------- Show --------------------------------------------------------------

#[derive(clap::Parser)]
pub struct Show {
    #[command(flatten)]
    ca: Handle,
}

impl Show {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::CertAuthInfo, httpclient::Error> {
        client.ca_details(&self.ca.ca).await
    }
}


//-------- Delete ------------------------------------------------------------

#[derive(clap::Parser)]
pub struct Delete {
    #[command(flatten)]
    ca: Handle,
}

impl Delete {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.ca_delete(&self.ca.ca).await
    }
}


//------------ History -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum History {
    /// Show the commands sent to a CA.
    Commands(HistoryCommands),

    /// Show details for a command in the history of a CA
    Details(HistoryDetails),
}

impl History {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Commands(cmd) => cmd.run(client).await.into(),
            Self::Details(cmd) => cmd.run(client).await.into(),
        }
    }
}


//-------- HistoryCommands ---------------------------------------------------

#[derive(clap::Parser)]
pub struct HistoryCommands {
    #[command(flatten)]
    ca: Handle,

    /// Number of rows (max 250)
    #[arg(long, value_name = "number")]
    rows: Option<u64>,

    /// Number of results to skip
    #[arg(long, value_name = "number")]
    offset: Option<u64>,

    /// Show commands issued after date/time
    #[arg(long, value_name = "RFC 3339 DateTime")]
    after: Option<Time>,

    /// Show commands issued before date/time
    #[arg(long, value_name = "RFC 3339 DateTime")]
    before: Option<Time>,
}

impl HistoryCommands {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::history::CommandHistory, httpclient::Error> {
        client.ca_history_commands(
            &self.ca.ca, self.rows, self.offset,self.after, self.before
        ).await
    }
}


//-------- HistoryDetails ----------------------------------------------------

#[derive(clap::Parser)]
pub struct HistoryDetails {
    #[command(flatten)]
    ca: Handle,

    /// The command key as shown in 'history commands'"
    #[arg(long, value_name = "command key string")]
    key: String,
}

impl HistoryDetails {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::history::CommandDetails, httpclient::Error> {
        client.ca_history_details(&self.ca.ca, &self.key).await
    }
}


//------------ Keyroll ------- -----------------------------------------------

#[derive(clap::Subcommand)]
pub enum Keyroll {
    /// Initialize roll for all keys held by a CA
    Init(InitKeyroll),

    /// Finish roll for all keys held by a CA
    Activate(ActivateKeyroll),
}

impl Keyroll {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(client).await.into(),
            Self::Activate(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ InitKeyroll ---------------------------------------------------

#[derive(clap::Parser)]
pub struct InitKeyroll {
    #[command(flatten)]
    pub handle: Handle,
}

impl InitKeyroll {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.ca_init_keyroll(&self.handle.ca).await
    }
}


//------------ ActivateKeyroll -----------------------------------------------

#[derive(clap::Parser)]
pub struct ActivateKeyroll {
    #[command(flatten)]
    pub handle: Handle,
}

impl ActivateKeyroll {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.ca_activate_keyroll(&self.handle.ca).await
    }
}

