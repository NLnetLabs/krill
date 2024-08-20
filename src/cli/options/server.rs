//! Options relating to managing the Krill server.

use rpki::ca::idexchange::CaHandle;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;


//------------ Health --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Health;

impl Health {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.authorized().await
    }
}


//------------ Info ----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Info;

impl Info {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ServerInfo, httpclient::Error> {
        client.info().await
    }
}


//------------ Issues --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Issues {
    /// Name of the CA to check for issues
    #[arg(long, short, env = "KRILL_CLI_MY_CA")]
    ca: Option<CaHandle>,
}

impl Issues {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self.ca {
            Some(ca) => {
                client.ca_issues(&ca).await.into()
            }
            None => client.bulk_issues().await.into()
        }
    }
}

