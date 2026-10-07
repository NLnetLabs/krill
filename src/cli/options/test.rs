//! Commands performing more complex tasks useful during testing.

use std::fmt;
use rpki::ca::idexchange::CaHandle;
use crate::api;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::httpclient;
use super::children::ChildResources;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Add a CA with a local parent and local publishing.
    AddCa(AddCa),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::AddCa(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ AddCa ---------------------------------------------------------

#[derive(clap::Args)]
pub struct AddCa {
    /// Name of the CA to add.
    #[arg(long, short)]
    pub ca: CaHandle,

    /// Name of the parent CA.
    #[arg(long, short)]
    pub parent: CaHandle,

    #[command(flatten)]
    resources: ChildResources,
}

impl AddCa {
    async fn run(
        self, client: &KrillClient
    ) -> Result<api::status::Success, Error> {
        // Create the CA
        client.ca_add(self.ca.clone()).await?;

        // Add the CA as a publisher
        let request = client.repo_request(&self.ca).await?;
        client.publishers_add(request).await?;

        // Get a Repository Response for the CA.
        let response = client.publisher_response(
            &self.ca.convert()
        ).await?;

        // Update the repo for the CA.
        client.repo_update(&self.ca, response).await?;

        let request = client.child_request(&self.ca).await?;
        let id_cert = request.validate()?;
        let response = client.child_add(
            &self.parent, self.ca.convert(), self.resources.into(),
            id_cert
        ).await?;
        client.parent_add(
            &self.ca,
            api::admin::ParentCaReq {
                handle: self.parent.convert(), response
            }
        ).await?;
        Ok(api::status::Success)
    }
}


//------------ Error ---------------------------------------------------------

struct Error(Box<dyn fmt::Display>);

impl From<httpclient::Error> for Error {
    fn from(src: httpclient::Error) -> Self {
        Self(Box::new(src))
    }
}

impl From<rpki::ca::idexchange::Error> for Error {
    fn from(src: rpki::ca::idexchange::Error) -> Self {
        Self(Box::new(src))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

