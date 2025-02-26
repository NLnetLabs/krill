//! Managing the Trust Anchor Proxy.

use std::{error, env, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use rpki::ca::idexchange;
use rpki::ca::idcert::IdCert;
use rpki::repository::resources::{
    AsBlocks, Ipv4Blocks, Ipv6Blocks, ResourceSet,
};
use crate::{constants, ta};
use crate::cli::client::KrillClient;
use crate::cli::options::GeneralOptions;
use crate::cli::options::args::JsonFile;
use crate::cli::options::repo::RepositoryResponseFile;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::error::Error as KrillError;
use crate::commons::util::httpclient;


//------------ Command -------------------------------------------------------

#[derive(clap::Args)]
pub struct Command {
    #[command(flatten)]
    pub general: GeneralOptions,

    #[command(subcommand)]
    pub command: Subcommand,
}

impl Command {
    pub async fn run(self) -> Report {
        let client = KrillClient::new(
            self.general.server, self.general.token
        );
        if self.general.api {
            env::set_var(constants::KRILL_CLI_API_ENV, "1")
        }
        self.command.run(&client).await
    }
}


//------------ Subcommand ----------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Subcommand {
    /// Initialise the proxy
    Init(Init),

    /// Get the proxy ID certificate details
    Id(Id),

    /// Manage the repository for proxy
    #[command(subcommand)]
    Repo(Repo),

    /// Manage interactions with the associated signer
    #[command(subcommand)]
    Signer(Signer),

    /// Manage children under the TA proxy
    #[command(subcommand)]
    Children(Children),
}

impl Subcommand {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(client).await.into(),
            Self::Id(cmd) => cmd.run(client).await.into(),
            Self::Repo(cmd) => cmd.run(client).await,
            Self::Signer(cmd) => cmd.run(client).await,
            Self::Children(cmd) => cmd.run(client).await,
        }
    }
}


//------------ Init ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Init;

impl Init {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.ta_proxy_init().await
    }
}


//------------ Id ------------------------------------------------------------

#[derive(clap::Args)]
pub struct Id;

impl Id {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::ca::IdCertInfo, httpclient::Error> {
        client.ta_proxy_id().await
    }
}


//------------ Repo ----------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Repo {
    /// Get RFC 8183 publisher request
    Request(RepoRequest),

    /// Show the configured repository for the proxy
    Contact(RepoContact),

    /// Configure (add) the repository for the proxy
    Configure(RepoConfigure),
}

impl Repo {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Request(cmd) => cmd.run(client).await.into(),
            Self::Contact(cmd) => cmd.run(client).await.into(),
            Self::Configure(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ RepoRequest ---------------------------------------------------

#[derive(clap::Args)]
pub struct RepoRequest;

impl RepoRequest {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::PublisherRequest, httpclient::Error> {
        client.ta_proxy_repo_request().await
    }
}


//------------ RepoContact ---------------------------------------------------

#[derive(clap::Args)]
pub struct RepoContact;

impl RepoContact {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::RepositoryContact, httpclient::Error> {
        client.ta_proxy_repo_contact().await
    }
}


//------------ RepoConfigure -------------------------------------------------

#[derive(clap::Args)]
pub struct RepoConfigure {
    /// Path to the Publisher Response XML file
    #[arg(long, short, value_name = "path")]
    response: RepositoryResponseFile,
}

impl RepoConfigure {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.ta_proxy_repo_configure(self.response.into()).await
    }
}


//------------ Signer --------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Signer {
    /// Initialise signer association
    Init(SignerInit),

    /// Make a NEW request for the signer (fails if a request exists)
    MakeRequest(SignerMakeRequest),

    /// Show existing request for the signer (fails if there is no request)
    ShowRequest(SignerShowRequest),

    /// Process a response from the signer. Fails it not for the open request
    ProcessResponse(SignerProcessResponse),
}

impl Signer {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(client).await.into(),
            Self::MakeRequest(cmd) => cmd.run(client).await.into(),
            Self::ShowRequest(cmd) => cmd.run(client).await.into(),
            Self::ProcessResponse(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ SignerInit ----------------------------------------------------

#[derive(clap::Args)]
pub struct SignerInit {
    /// Path to the the Trust Anchor Signer info file (as 'signer show')
    #[arg(long, short, value_name="path")]
    info: JsonFile<ta::TrustAnchorSignerInfo, TasiMsg>,
}

impl SignerInit {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.ta_proxy_signer_add(self.info.content).await
    }
}

#[derive(Clone, Copy, Default, Debug)]
struct TasiMsg;

impl fmt::Display for TasiMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("signer info")
    }
}


//------------ SignerMakeRequest ---------------------------------------------

#[derive(clap::Args)]
pub struct SignerMakeRequest;

impl SignerMakeRequest {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<ta::TrustAnchorSignedRequest, httpclient::Error> {
        client.ta_proxy_signer_make_request().await
    }
}


//------------ SignerShowRequest ---------------------------------------------

#[derive(clap::Args)]
pub struct SignerShowRequest;

impl SignerShowRequest {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<ta::TrustAnchorSignedRequest, httpclient::Error> {
        client.ta_proxy_signer_show_request().await
    }
}


//------------ SignerProcessResponse -----------------------------------------

#[derive(clap::Args)]
pub struct SignerProcessResponse {
    /// Path to the the Trust Anchor Signer info file (as 'signer show')
    #[arg(long, short, value_name="path")]
    response: JsonFile<ta::TrustAnchorSignedResponse, TasrMsg>,
}

impl SignerProcessResponse {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<api::admin::Success, httpclient::Error> {
        client.ta_proxy_signer_response(self.response.content).await
    }
}

#[derive(Clone, Copy, Default, Debug)]
struct TasrMsg;

impl fmt::Display for TasrMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("response")
    }
}


//------------ Children ------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Children {
    /// Add a child
    Add(ChildrenAdd),

    /// Get parent response for child
    Response(ChildrenResponse),
}

impl Children {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Add(cmd) => cmd.run(client).await.into(),
            Self::Response(cmd) => cmd.run(client).await.into(),
        }
    }
}


//------------ ChildrenAdd ---------------------------------------------------

#[derive(clap::Args)]
pub struct ChildrenAdd {
    /// Path to the child info JSON (from krillc show).
    #[arg(long, short, value_name = "path")]
    info: CertAuthInfoFile,

    /// The ASN resources for the child
    #[arg(
        long, short,
        value_name = "ASN resources",
        default_value = "AS0-AS4294967295"
    )]
    asn: AsBlocks,

    /// The IPv4 resources for the child
    #[arg(
        long, short = '4',
        value_name = "IPv4 resources",
        default_value = "0.0.0.0/0",
    )]
    ipv4: Ipv4Blocks,

    /// The IPv6 resources for the child
    #[arg(
        long, short = '6',
        value_name = "IPv6 resources",
        default_value = "::/0"
    )]
    ipv6: Ipv6Blocks,
}

impl ChildrenAdd {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::ParentResponse, httpclient::Error> {
        client.ta_proxy_children_add(
            api::admin::AddChildRequest {
                handle: self.info.handle,
                resources: ResourceSet::new(self.asn, self.ipv4, self.ipv6),
                id_cert: self.info.id_cert,
            }
        ).await
    }
}


//------------ ChildrenResponse ----------------------------------------------

#[derive(clap::Args)]
pub struct ChildrenResponse {
    /// Name of the child CA
    #[arg(long, value_name = "name")]
    child: idexchange::ChildHandle,
}

impl ChildrenResponse {
    pub async fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::ParentResponse, httpclient::Error> {
        client.ta_proxy_child_response(&self.child).await
    }
}


//============ Argument Parser Types =========================================

//------------ CertAuthInfoFile ----------------------------------------------

#[derive(Clone, Debug)]
pub struct CertAuthInfoFile {
    handle: idexchange::ChildHandle,
    id_cert: IdCert,
}

impl FromStr for CertAuthInfoFile {
    type Err = CertAuthInfoFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let info = serde_json::from_reader::<_, api::ca::CertAuthInfo>(
            BufReader::new(
                File::open(path).map_err(|err| {
                    CertAuthInfoFileError::Io(path.into(), err)
                })?
            )
        ).map_err(|err| {
            CertAuthInfoFileError::Parse(path.into(), err)
        })?;
        Ok(Self {
            handle: info.handle.convert(),
            id_cert: (&info.id_cert).try_into().map_err(|err| {
                CertAuthInfoFileError::Cert(path.into(), err)
            })?
        })
    }
}


//============ ErrorTypes ====================================================

//------------ CertAuthInfoFileError------------------------------------------

#[derive(Debug)]
pub enum CertAuthInfoFileError {
    Io(String, io::Error),
    Parse(String, serde_json::Error),
    Cert(String, KrillError),
}

impl fmt::Display for CertAuthInfoFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(
                    f, "Failed to read child info file '{}': {}'",
                    path, err
                )
            }
            Self::Parse(path, err) => {
                write!(
                    f, "Failed to parse child info file '{}': {}'",
                    path, err
                )
            }
            Self::Cert(path, err) => {
                write!(
                    f, "Failed to parse child info file '{}': {}'",
                    path, err
                )
            }
        }
    }
}

impl error::Error for CertAuthInfoFileError { }


