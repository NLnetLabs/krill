//! Manage a CA’s ASPAs.

use std::{error, fmt};
use std::str::FromStr;
use rpki::repository::resources::Asn;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::api;
use crate::commons::util::httpclient;
use super::ca;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Show current ASPAs
    List(List),

    /// Add or replace an ASPA
    Add(Add),

    /// Remove the ASPA for a customer ASN
    Remove(Remove),

    /// Update an existing ASPA
    Update(Update),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::List(cmd) => cmd.run(client).await.into(),
            Self::Add(cmd) => cmd.run(client).await.into(),
            Self::Remove(cmd) => cmd.run(client).await.into(),
            Self::Update(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ List ---------------------------------------------------------

#[derive(clap::Args)]
pub struct List {
    #[command(flatten)]
    ca: ca::Handle,
}

impl List {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::aspa::AspaDefinitionList, httpclient::Error> {
        client.aspas_list(&self.ca.ca).await
    }
}


//------------ Add -----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    #[command(flatten)]
    ca: ca::Handle,

    /// The ASPA formatted like: 65000 => 65001, 65002, 65003
    #[arg(long, value_name = "ASPA definition")]
    aspa: CleanAspaDefinition,
}

impl Add {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.aspas_update(
            &self.ca.ca,
            api::aspa::AspaDefinitionUpdates {
                add_or_replace: vec![self.aspa.0],
                remove: Vec::new(),
            }
        ).await
    }
}


//------------ Remove ----------------------------------------------------

#[derive(clap::Args)]
pub struct Remove {
    #[command(flatten)]
    ca: ca::Handle,

    /// Customer ASN of the ASPA to remove
    #[arg(long, value_name = "ASN")]
    customer: Asn,
}

impl Remove {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.aspas_update(
            &self.ca.ca,
            api::aspa::AspaDefinitionUpdates {
                add_or_replace: Vec::new(),
                remove: vec![self.customer]
            },
        ).await
    }
}


//------------ Update --------------------------------------------------------

#[derive(clap::Args)]
pub struct Update {
    #[command(flatten)]
    ca: ca::Handle,

    /// Customer ASN of an existing ASPA
    #[arg(long, value_name = "ASN")]
    customer: Asn,

    /// Provider ASN to add
    #[arg(long, value_name = "ASNn")]
    add: Vec<Asn>,

    /// Provider ASN to remove.
    #[arg(long, value_name = "ASNn")]
    remove: Vec<Asn>,
}

impl Update {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, httpclient::Error> {
        client.aspas_update_single(
            &self.ca.ca, self.customer,
            api::aspa::AspaProvidersUpdate {
                added: self.add,
                removed: self.remove
            },
        ).await
    }
}


//============ Argument Parser Types =========================================

//------------ CleanAspaDefinition -------------------------------------------

#[derive(Clone, Debug)]
pub struct CleanAspaDefinition(api::aspa::AspaDefinition);

impl FromStr for CleanAspaDefinition {
    type Err = CleanAspaDefinitionError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let aspa = api::aspa::AspaDefinition::from_str(src).map_err(
            CleanAspaDefinitionError::Format
        )?;
        if aspa.customer_used_as_provider() {
            Err(CleanAspaDefinitionError::CustomerAsProvider)
        }
        else if aspa.providers.is_empty() {
            Err(CleanAspaDefinitionError::EmptyProviders)
        }
        else {
            Ok(Self(aspa))
        }
    }
}


//============ ErrorTypes ====================================================

//------------ CleanAspaDefinitionError --------------------------------------

#[derive(Debug)]
pub enum CleanAspaDefinitionError {
    Format(api::aspa::AspaDefinitionFormatError),
    CustomerAsProvider,
    EmptyProviders,
}

impl fmt::Display for CleanAspaDefinitionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Format(err) => err.fmt(f),
            Self::CustomerAsProvider => {
                f.write_str("Customer ASN may not be used as provider.")
            }
            Self::EmptyProviders => {
                f.write_str("At least one provider MUST be specified.")
            }
        }
    }
}

impl error::Error for CleanAspaDefinitionError { }

