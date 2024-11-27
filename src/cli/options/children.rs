//! Commands related to managing child CAs.

use std::{error, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use rpki::ca::idexchange;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ChildRequest, ParentResponse
};
use rpki::repository::resources::{
    AsBlocks, Ipv4Blocks, Ipv6Blocks, ResourceSet
};
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Add a child to a CA
    Add(Add),

    /// Update an existing child of a CA
    Update(Update),

    /// Show info for a child
    Info(Info),

    /// Remove an existing child from a CA
    Remove(Remove),

    /// Show the RFC 8183 Parent Response XML
    Response(Response),

    /// Show connections stats for children of a CA
    Connections(Connections),

    /// Suspend a child CA: un-publish certificate(s) issued to child
    Suspend(Suspend),

    /// Unsuspend a child CA: publish certificate(s) issued to child
    Unsuspend(Unsuspend),
}

impl Command {
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Add(cmd) => cmd.run(client).into(),
            Self::Update(cmd) => cmd.run(client).into(),
            Self::Info(cmd) => cmd.run(client).into(),
            Self::Remove(cmd) => cmd.run(client).into(),
            Self::Response(cmd) => cmd.run(client).into(),
            Self::Connections(cmd) => cmd.run(client).into(),
            Self::Suspend(cmd) => cmd.run(client).into(),
            Self::Unsuspend(cmd) => cmd.run(client).into(),
        }
    }
}


//------------ Handle --------------------------------------------------------

#[derive(clap::Args)]
struct Handle {
    /// Name of the CA to control
    #[arg(long, short, env = "KRILL_CLI_MY_CA")]
    ca: CaHandle,

    /// The name of the child CA you wish to control
    #[arg(long, value_name = "name")]
    child: ChildHandle,
}


//------------ Add -----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    #[command(flatten)]
    handle: Handle,

    #[command(flatten)]
    resources: ChildResources,

    /// Path to the RFC 8183 Child Request XML file
    #[arg(long, short, value_name = "path")]
    request: ChildIdCert,
}

impl Add {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<ParentResponse, httpclient::Error> {
        client.child_add(
            &self.handle.ca, self.handle.child,
            self.resources.into(), self.request.0
        )
    }
}


//------------ Info ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Info {
    #[command(flatten)]
    handle: Handle,
}

impl Info {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::ChildCaInfo, httpclient::Error> {
        client.child_details(&self.handle.ca, &self.handle.child)
    }
}


//------------ Update --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Update {
    #[command(flatten)]
    handle: Handle,

    #[command(flatten)]
    resources: ChildResources,

    /// Path to the RFC 8183 Child Request XML file
    #[arg(long, short, value_name = "path")]
    request: Option<ChildIdCert>,
}

impl Update {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.child_update(&self.handle.ca, &self.handle.child,
            api::UpdateChildRequest::new(
                self.request.map(|x| x.0), self.resources.into(), None
            )
        )
    }
}


//------------ Response -----------------------------------------------------

#[derive(clap::Args)]
pub struct Response {
    #[command(flatten)]
    handle: Handle,
}

impl Response {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::ParentResponse, httpclient::Error> {
        client.child_contact(&self.handle.ca, &self.handle.child)
    }
}


//------------ Suspend -------------------------------------------------------

#[derive(clap::Args)]
pub struct Suspend {
    #[command(flatten)]
    handle: Handle,
}

impl Suspend {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.child_update(
            &self.handle.ca, &self.handle.child,
            api::UpdateChildRequest::suspend(),
        )
    }
}


//------------ Unsuspend ----------------------------------------------------

#[derive(clap::Args)]
pub struct Unsuspend {
    #[command(flatten)]
    handle: Handle,
}

impl Unsuspend {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.child_update(
            &self.handle.ca, &self.handle.child,
            api::UpdateChildRequest::unsuspend(),
        )
    }
}


//------------ Remove --------------------------------------------------------

#[derive(clap::Args)]
pub struct Remove {
    #[command(flatten)]
    handle: Handle,
}

impl Remove {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.child_delete(&self.handle.ca, &self.handle.child)
    }
}


//------------ ChildResources ------------------------------------------------

#[derive(clap::Args)]
pub struct ChildResources {
    /// The AS resources to be included
    #[arg(short, long, value_name = "AS resources")]
    asn: Option<AsBlocks>,

    /// The IPv4 resources to be included
    #[arg(short = '4', long, value_name = "IPv4 resources")]
    ipv4: Option<Ipv4Blocks>,

    /// The IPv6 resources to be included
    #[arg(short = '6', long, value_name = "IPv6 resources")]
    ipv6: Option<Ipv6Blocks>,
}

impl From<ChildResources> for ResourceSet {
    fn from(src: ChildResources) -> Self {
        ResourceSet::new(
            src.asn.unwrap_or_default(),
            src.ipv4.unwrap_or_default(),
            src.ipv6.unwrap_or_default(),
        )
    }
}

impl From<ChildResources> for Option<ResourceSet> {
    fn from(src: ChildResources) -> Self {
        if src.asn.is_none() && src.ipv4.is_none() && src.ipv6.is_none() {
            None
        }
        else {
            Some(src.into())
        }
    }
}


//------------ Connections ---------------------------------------------------

#[derive(clap::Args)]
pub struct Connections {
    /// Name of the CA to control
    #[arg(long, short, env = "KRILL_CLI_MY_CA")]
    ca: CaHandle,
}

impl Connections {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::ChildrenConnectionStats, httpclient::Error> {
        client.child_connections(&self.ca)
    }
}


//============ Argument Parser Types =========================================

//------------ ChildIdCert ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct ChildIdCert(IdCert);

impl FromStr for ChildIdCert {
    type Err = ChildIdCertError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        ChildRequest::parse(
            BufReader::new(
                File::open(src).map_err(|err| {
                    ChildIdCertError::Io(src.into(), err)
                })?
            )
        ).and_then(|req| req.validate()).map(Self).map_err(|err| {
            ChildIdCertError::Parse(src.into(), err)
        })
    }
}


//============ ErrorTypes ====================================================

//------------ ChildIdCertError ----------------------------------------------

#[derive(Debug)]
pub enum ChildIdCertError {
    Io(String, io::Error),
    Parse(String, idexchange::Error),
}

impl fmt::Display for ChildIdCertError {
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

impl error::Error for ChildIdCertError { }

