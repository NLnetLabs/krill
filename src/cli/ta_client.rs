//! Trust Anchor Client for managing the TA Proxy *and* Signer

use std::{
    env,
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

use clap::{App, Arg, ArgMatches, SubCommand};
use log::LevelFilter;
use rpki::ca::idexchange::ServiceUri;
use serde::de::DeserializeOwned;

use crate::{
    cli::report::Report,
    commons::{
        api::{IdCertInfo, Token},
        error::Error as KrillError,
        eventsourcing::AggregateStore,
        util::httpclient::{self},
    },
    constants::{KRILL_CLI_API_ENV, KRILL_TA_CLIENT_APP, KRILL_VERSION},
    daemon::{
        config::LogType,
        ta::{TrustAnchorSigner, TrustAnchorSignerCommand},
    },
};

use super::{options::GeneralArgs, report};

//------------------------ Client Constants -------------------------------------
const CONFIG_PATH: &str = "/etc/krillta.conf";

//------------------------ Client Error -----------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    DataDirMissing,
    UnrecognizedMatch,
    HttpClientError(httpclient::Error),
    KrillError(KrillError),
    Other(String),
}

impl Error {
    fn other(msg: &str) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DataDirMissing => write!(f, "Cannot find data dir"),
            Error::UnrecognizedMatch => write!(f, "Unrecognised argument. Use 'help'"),
            Error::HttpClientError(e) => write!(f, "HTTP client error: {}", e),
            Error::KrillError(e) => write!(f, "{}", e),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<KrillError> for Error {
    fn from(e: KrillError) -> Self {
        Self::KrillError(e)
    }
}

impl From<report::ReportError> for Error {
    fn from(e: report::ReportError) -> Self {
        Error::Other(e.to_string())
    }
}

//------------------------ Client Commands --------------------------------------

#[derive(Debug)]
pub enum TrustAnchorClientCommand {
    Proxy(ProxyCommand),
    Signer(SignerCommand),
}

impl TrustAnchorClientCommand {
    pub fn report_format(&self) -> report::ReportFormat {
        match self {
            TrustAnchorClientCommand::Signer(_) => report::ReportFormat::None,
            TrustAnchorClientCommand::Proxy(command) => command.general.format,
        }
    }
}

#[derive(Debug)]
pub struct ProxyCommand {
    general: GeneralArgs,
    details: ProxyCommandDetails,
}

#[derive(Debug)]
pub enum ProxyCommandDetails {
    Init,
    Id,
}

#[derive(Debug)]
pub struct SignerCommand {
    config: Config,
    details: SignerCommandDetails,
}

#[derive(Debug)]
pub enum SignerCommandDetails {
    Init,
}

impl TrustAnchorClientCommand {
    pub fn from_args() -> Result<Self, Error> {
        let matches = Self::make_matches();
        Self::parse_matches(matches)
    }
}

/// # Create matches for command line parsing
///
impl TrustAnchorClientCommand {
    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new(KRILL_TA_CLIENT_APP).version(KRILL_VERSION);

        app = Self::make_proxy_sc(app);
        app = Self::make_signer_sc(app);

        app.get_matches()
    }

    //-- Sub Commands Proxy

    fn make_proxy_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("proxy").about("Manage the Trust Anchor Proxy");

        sub = Self::make_proxy_init_sc(sub);
        sub = Self::make_proxy_id_sc(sub);

        app.subcommand(sub)
    }

    fn make_proxy_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init").about("Initialise the proxy");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_id_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("id").about("Get the proxy ID certificate details");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    //-- Sub Commands Signer

    fn make_signer_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("signer").about("Manage the Trust Anchor Signer");

        sub = Self::make_signer_init_sc(sub);

        app.subcommand(sub)
    }

    fn make_signer_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init").about("Initialise the signer");

        sub = Self::add_config_arg(sub);

        app.subcommand(sub)
    }

    //-- Arguments

    fn add_config_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("config")
                .long("config")
                .value_name("path")
                .short("c")
                .help("Path to config file. Defaults to: /etc/krillta.conf")
                .required(false),
        )
    }
}

/// # Parse command line matches
///
impl TrustAnchorClientCommand {
    fn parse_matches(matches: ArgMatches) -> Result<Self, Error> {
        if let Some(m) = matches.subcommand_matches("proxy") {
            Self::parse_matches_proxy(m)
        } else if let Some(m) = matches.subcommand_matches("signer") {
            Self::parse_matches_signer(m)
        } else {
            Err(Error::UnrecognizedMatch)
        }
    }

    //-- Parse Proxy
    fn parse_matches_proxy(matches: &ArgMatches) -> Result<Self, Error> {
        if let Some(m) = matches.subcommand_matches("id") {
            Self::parse_matches_proxy_id(m)
        } else if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_proxy_init(m)
        } else {
            Err(Error::UnrecognizedMatch)
        }
    }

    fn parse_matches_proxy_init(matches: &ArgMatches) -> Result<Self, Error> {
        let general = GeneralArgs::from_matches(matches).map_err(|e| Error::Other(e.to_string()))?;
        let details = ProxyCommandDetails::Init;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand { general, details }))
    }

    fn parse_matches_proxy_id(matches: &ArgMatches) -> Result<Self, Error> {
        let general = GeneralArgs::from_matches(matches).map_err(|e| Error::Other(e.to_string()))?;
        let details = ProxyCommandDetails::Id;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand { general, details }))
    }

    //-- Parse Signer
    fn parse_matches_signer(matches: &ArgMatches) -> Result<Self, Error> {
        if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_signer_init(m)
        } else {
            Err(Error::UnrecognizedMatch)
        }
    }

    fn parse_matches_signer_init(matches: &ArgMatches) -> Result<Self, Error> {
        let config = Self::parse_config(matches)?;
        let details = SignerCommandDetails::Init;

        Ok(TrustAnchorClientCommand::Signer(SignerCommand { config, details }))
    }

    fn parse_config(matches: &ArgMatches) -> Result<Config, Error> {
        let config_path = matches.value_of("config").unwrap_or(CONFIG_PATH);
        Config::parse(config_path)
    }
}

//------------------------ TrustAnchorClient ------------------------------------

pub struct TrustAnchorClient;

impl TrustAnchorClient {
    pub async fn process(command: TrustAnchorClientCommand) -> Result<TrustAnchorClientApiResponse, Error> {
        match command {
            TrustAnchorClientCommand::Proxy(proxy_command) => {
                let client = ProxyClient::create(proxy_command.general);

                match proxy_command.details {
                    ProxyCommandDetails::Init => client.post_empty("api/v1/ta/proxy/init").await,
                    ProxyCommandDetails::Id => {
                        let id: IdCertInfo = client.get_json("api/v1/ta/proxy/id").await?;
                        Ok(TrustAnchorClientApiResponse::IdCert(id))
                    }
                }
            }
            TrustAnchorClientCommand::Signer(signer_command) => {
                let signer_client = SignerClient::create(signer_command.config)?;

                match signer_command.details {
                    SignerCommandDetails::Init => signer_client.init()?,
                }

                Ok(TrustAnchorClientApiResponse::Empty)
            }
        }
    }
}

pub enum TrustAnchorClientApiResponse {
    IdCert(IdCertInfo),
    Empty,
}

impl TrustAnchorClientApiResponse {
    pub fn report(&self, fmt: report::ReportFormat) -> Result<Option<String>, report::ReportError> {
        if fmt == report::ReportFormat::None {
            Ok(None)
        } else {
            match self {
                TrustAnchorClientApiResponse::IdCert(id_cert) => id_cert.report(fmt).map(Some),
                TrustAnchorClientApiResponse::Empty => Ok(None),
            }
        }
    }
}

//------------------------ ProxyClient ------------------------------------------

pub struct ProxyClient {
    server: ServiceUri,
    token: Token,
}

impl ProxyClient {
    fn create(general: GeneralArgs) -> Self {
        let client = ProxyClient {
            server: general.server,
            token: general.token,
        };

        if general.api {
            // passing the api option in the env, so that the call
            // to the back-end will just print and exit.
            env::set_var(KRILL_CLI_API_ENV, "1")
        }

        client
    }
    async fn post_empty(&self, path: &str) -> Result<TrustAnchorClientApiResponse, Error> {
        let uri = self.resolve_uri(path);
        httpclient::post_empty(&uri, Some(&self.token))
            .await
            .map(|_| TrustAnchorClientApiResponse::Empty)
            .map_err(Error::HttpClientError)
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let uri = self.resolve_uri(path);
        httpclient::get_json(&uri, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    fn resolve_uri(&self, path: &str) -> String {
        format!("{}{}", self.server, path)
    }
}

//------------------------ SignerClient -----------------------------------------

struct SignerClient {
    config: Config,
    store: AggregateStore<TrustAnchorSigner>,
}

impl SignerClient {
    fn create(config: Config) -> Result<Self, Error> {
        let store = AggregateStore::disk(&config.data_dir, "signer").map_err(KrillError::AggregateStoreError)?;
        Ok(SignerClient { config, store })
    }

    fn init(&self) -> Result<(), Error> {
        // let cmd = TrustAnchorSignerCommand::self.store.command(cmd)?;
        todo!("init signer")
    }
}

//------------------------ Config -----------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    data_dir: PathBuf,

    #[serde(default = "crate::daemon::config::ConfigDefaults::log_type")]
    log_type: LogType,

    #[serde(
        default = "crate::daemon::config::ConfigDefaults::log_level",
        deserialize_with = "crate::commons::util::ext_serde::de_level_filter"
    )]
    pub log_level: LevelFilter,
}

impl Config {
    fn parse(file_path: &str) -> Result<Self, Error> {
        let mut v = Vec::new();

        let mut file = File::open(file_path)
            .map_err(|e| Error::Other(format!("Could not read config file '{}': {}", file_path, e)))?;

        file.read_to_end(&mut v)
            .map_err(|e| Error::Other(format!("Could not read config file '{}': {}", file_path, e)))?;

        let config: Config = toml::from_slice(v.as_slice())
            .map_err(|e| Error::Other(format!("Error parsing config file: '{}': {}", file_path, e)))?;

        config.init_logging()?;

        Ok(config)
    }

    fn init_logging(&self) -> Result<(), Error> {
        match self.log_type {
            LogType::File => self.file_logger(),
            LogType::Stderr => self.stderr_logger(),
            LogType::Syslog => Err(Error::other("syslog is not support for the TA client")),
        }
    }

    fn file_logger(&self) -> Result<(), Error> {
        let path = self.data_dir.join("krillta.log");
        let log_file = fern::log_file(&path)
            .map_err(|e| Error::Other(format!("Failed to open log file '{}': {}", path.display(), e)))?;

        self.fern_logger()
            .chain(log_file)
            .apply()
            .map_err(|e| Error::Other(format!("Failed to init file logging: {}", e)))
    }

    /// Creates a stderr logger.
    fn stderr_logger(&self) -> Result<(), Error> {
        self.fern_logger()
            .chain(io::stderr())
            .apply()
            .map_err(|e| Error::Other(format!("Failed to init stderr logging: {}", e)))
    }

    /// Creates and returns a fern logger with log level tweaks
    fn fern_logger(&self) -> fern::Dispatch {
        // suppress overly noisy logging
        let framework_level = self.log_level.min(LevelFilter::Warn);
        let krill_framework_level = self.log_level.min(LevelFilter::Debug);

        let show_target = self.log_level == LevelFilter::Trace || self.log_level == LevelFilter::Debug;

        fern::Dispatch::new()
            .format(move |out, message, record| {
                if show_target {
                    out.finish(format_args!(
                        "{} [{}] [{}] {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        record.level(),
                        record.target(),
                        message
                    ))
                } else {
                    out.finish(format_args!(
                        "{} [{}] {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        record.level(),
                        message
                    ))
                }
            })
            .level(self.log_level)
            .level_for("rustls", framework_level)
            .level_for("hyper", framework_level)
            .level_for("mio", framework_level)
            .level_for("reqwest", framework_level)
            .level_for("tokio_reactor", framework_level)
            .level_for("tokio_util::codec::framed_read", framework_level)
            .level_for("want", framework_level)
            .level_for("tracing::span", framework_level)
            .level_for("krill::commons::eventsourcing", krill_framework_level)
            .level_for("krill::commons::util::file", krill_framework_level)
    }
}
