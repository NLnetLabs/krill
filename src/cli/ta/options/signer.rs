//! Managing the Trust Anchor Proxy.

use std::{error, fmt, fs, io};
use std::str::FromStr;
use std::sync::Arc;
use rpki::uri;
use crate::{api, constants};
use crate::api::ta::{
    ApiTrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::cli::options::args::JsonFile;
use crate::cli::report::{Report, ReportFormat};
use crate::cli::ta::signer::{
    SignerClientError, SignerInitInfo, SignerReissueInfo, TrustAnchorSignerManager
};
use crate::tasigner::{Config, ConfigError, TrustAnchorProxySignerExchanges};


//------------ Command -------------------------------------------------------

#[derive(clap::Args)]
pub struct Command {
    /// Path to config file.
    #[arg(
        long, short,
        value_name = "path",
        default_value = constants::KRILL_DEFAULT_TA_CONFIG_FILE,
    )]
    config: ConfigFile,

    /// Report format
    #[arg(
        short, long,
        env = "KRILL_CLI_FORMAT",
        default_value = "text",
    )]
    pub format: ReportFormat,

    #[command(subcommand)]
    pub command: Subcommand,
}

impl Command {
    pub fn run(self) -> Report {
        self.command.run(&self.config.0)
    }
}


//------------ Subcommand ----------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Subcommand {
    /// Initialise the signer
    Init(Init),

    /// Reissue the TA certificate
    Reissue(Reissue),

    /// Show the signer info
    Show(Show),

    /// Process a proxy request
    Process(Process),

    /// Show last response
    Last(Last),

    /// Show full history of proxy signer exchanges
    Exchanges(Exchanges),
}


impl Subcommand {
    pub fn run(self, manager: &TrustAnchorSignerManager) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(manager).into(),
            Self::Reissue(cmd) => cmd.run(manager).into(),
            Self::Show(cmd) => cmd.run(manager).into(),
            Self::Process(cmd) => cmd.run(manager).into(),
            Self::Last(cmd) => cmd.run(manager).into(),
            Self::Exchanges(cmd) => cmd.run(manager).into(),
        }
    }
}


//------------ Init ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Init {
    /// Path to the proxy ID JSON file.
    #[arg(long, short = 'i', value_name = "path")]
    proxy_id: JsonFile<api::ca::IdCertInfo, IdiMsg>,

    /// Path to the proxy repository contact JSON file.
    #[arg(long, short = 'r', value_name = "path")]
    proxy_repository_contact: JsonFile<api::admin::RepositoryContact, RcMsg>,

    /// The rsync URI used for TA certificate on TAL and AIA
    #[arg(long, value_name = "rsync URI")]
    tal_rsync: uri::Rsync,

    /// The HTTPS URI used for the TAL.
    #[arg(long, value_name = "HTTPS URI")]
    tal_https: Vec<uri::Https>,

    /// Import an existing private key in PEM format
    #[arg(long, value_name = "path")]
    private_key_pem: Option<PrivateKeyFile>,

    /// Set the initial manifest number
    #[arg(long, value_name = "number", default_value = "1")]
    initial_manifest_number: u64,
}

impl Init {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<api::status::Success, SignerClientError> {
        manager.init(
            SignerInitInfo {
                proxy_id: self.proxy_id.content,
                repo_info: self.proxy_repository_contact.content.into(),
                tal_https: self.tal_https,
                tal_rsync: self.tal_rsync,
                private_key_pem: self.private_key_pem.map(|x| x.0),
                ta_mft_nr_override: Some(self.initial_manifest_number),
            }
        )
    }
}


#[derive(Clone, Copy, Debug, Default)]
struct IdiMsg;

impl fmt::Display for IdiMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("proxy ID")
    }
}


#[derive(Clone, Copy, Debug, Default)]
struct RcMsg;

impl fmt::Display for RcMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("repository contact")
    }
}

//------------ Reissue -------------------------------------------------------

#[derive(clap::Args)]
pub struct Reissue {
    /// Path to the proxy ID JSON file.
    #[arg(long, short = 'i', value_name = "path")]
    proxy_id: JsonFile<api::ca::IdCertInfo, IdiMsg>,

    /// Path to the proxy repository contact JSON file.
    #[arg(long, short = 'r', value_name = "path")]
    proxy_repository_contact: JsonFile<api::admin::RepositoryContact, RcMsg>,

    /// The rsync URI used for TA certificate on TAL and AIA
    #[arg(long, value_name = "rsync URI")]
    tal_rsync: uri::Rsync,

    /// The HTTPS URI used for the TAL.
    #[arg(long, value_name = "HTTPS URI")]
    tal_https: Vec<uri::Https>,
}

impl Reissue {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<api::status::Success, SignerClientError> {
        manager.reissue(
            SignerReissueInfo {
                proxy_id: self.proxy_id.content,
                repo_info: self.proxy_repository_contact.content.into(),
                tal_https: self.tal_https,
                tal_rsync: self.tal_rsync,
            }
        )
    }
}


//------------ Show ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Show;

impl Show {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<TrustAnchorSignerInfo, SignerClientError> {
        manager.show()
    }
}


//------------ Process -------------------------------------------------------

#[derive(clap::Args)]
pub struct Process {
    /// Path to TA proxy request JSON file
    #[arg(long, short, value_name = "path")]
    request: JsonFile<ApiTrustAnchorSignedRequest, TasrMsg>,

    /// Override the next manifest number.
    #[arg(long, value_name = "number")]
    ta_mft_number_override: Option<u64>,
}

impl Process {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        manager.process(
            self.request.content.into(), self.ta_mft_number_override
        )
    }
}


#[derive(Clone, Copy, Debug, Default)]
struct TasrMsg;

impl fmt::Display for TasrMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("proxy request")
    }
}


//------------ Last ----------------------------------------------------------

#[derive(clap::Args)]
pub struct Last;

impl Last {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        manager.show_last_response()
    }
}


//------------ Exchanges -----------------------------------------------------

#[derive(clap::Args)]
pub struct Exchanges;

impl Exchanges {
    pub fn run(
        self, manager: &TrustAnchorSignerManager
    ) -> Result<TrustAnchorProxySignerExchanges, SignerClientError> {
        manager.show_exchanges()
    }
}


//============ Argument Parser Types =========================================

//------------ ConfigFile ----------------------------------------------------

#[derive(Clone)]
pub struct ConfigFile(Arc<TrustAnchorSignerManager>);

impl FromStr for ConfigFile {
    type Err = ConfigFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Config::parse(path).map_err(|err| {
            ConfigFileError::Parse(path.into(), err)
        }).and_then(|config| {
            TrustAnchorSignerManager::create(config).map_err(
                ConfigFileError::Create
            )
        }).map(|manager| Self(manager.into()))
    }
}

//------------ PrivateKeyFile ------------------------------------------------

#[derive(Clone)]
struct PrivateKeyFile(String);

impl FromStr for PrivateKeyFile {
    type Err = PrivateKeyFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        fs::read_to_string(path).map(Self).map_err(|err| {
            PrivateKeyFileError { path: path.into(), err }
        })
    }
}


//============ ErrorTypes ====================================================

//------------ ConfigFileError -----------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigFileError {
    Parse(String, ConfigError),
    Create(SignerClientError),
}

impl fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Parse(path, err) => {
                write!(
                    f, "Failed to read config file '{path}': {err}"
                )
            }
            Self::Create(err) => err.fmt(f)
        }
    }
}

impl error::Error for ConfigFileError { }


//------------ PrivateKeyFileError -------------------------------------------

#[derive(Debug)]
pub struct PrivateKeyFileError {
    path: String,
    err: io::Error,
}

impl fmt::Display for PrivateKeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f, "Failed to read private key file '{}': {}'",
            self.path, self.err
        )
    }
}

impl error::Error for PrivateKeyFileError { }

