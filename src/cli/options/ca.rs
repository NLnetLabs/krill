/// Commands related to managing a CA.

use rpki::ca::idexchange::CaHandle;
use rpki::repository::x509::Time;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;


//-------- List --------------------------------------------------------------

#[derive(clap::Parser)]
pub struct List;

impl List {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::CertAuthList, httpclient::Error> {
        client.cas_list()
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
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.ca_add(self.ca.ca)
    }
}


//-------- Show --------------------------------------------------------------

#[derive(clap::Parser)]
pub struct Show {
    #[command(flatten)]
    ca: Handle,
}

impl Show {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::CertAuthInfo, httpclient::Error> {
        client.ca_details(&self.ca.ca)
    }
}


//-------- Delete ------------------------------------------------------------

#[derive(clap::Parser)]
pub struct Delete {
    #[command(flatten)]
    ca: Handle,
}

impl Delete {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.ca_delete(&self.ca.ca)
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
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Commands(cmd) => cmd.run(client).into(),
            Self::Details(cmd) => cmd.run(client).into(),
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
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::CommandHistory, httpclient::Error> {
        client.ca_history_commands(
            &self.ca.ca, self.rows, self.offset,self.after, self.before
        )
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
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::CaCommandDetails, httpclient::Error> {
        client.ca_history_details(&self.ca.ca, &self.key)
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
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(client).into(),
            Self::Activate(cmd) => cmd.run(client).into(),
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
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.ca_init_keyroll(&self.handle.ca)
    }
}


//------------ ActivateKeyroll -----------------------------------------------

#[derive(clap::Parser)]
pub struct ActivateKeyroll {
    #[command(flatten)]
    pub handle: Handle,
}

impl ActivateKeyroll {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.ca_activate_keyroll(&self.handle.ca)
    }
}

