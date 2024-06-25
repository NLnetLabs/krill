//! Trust Anchor Client for managing the TA Proxy *and* Signer

use std::{env, path::PathBuf, str::FromStr, sync::Arc};

use bytes::Bytes;
use clap::{App, Arg, ArgMatches, SubCommand};

use rpki::{
    ca::idexchange::{self, ChildHandle, RepoInfo, ServiceUri},
    repository::resources::ResourceSet,
    uri,
};
use serde::de::DeserializeOwned;

use crate::{
    cli::report::Report,
    commons::{
        actor::Actor,
        api::{
            AddChildRequest, ApiRepositoryContact, CertAuthInfo, IdCertInfo,
            RepositoryContact, Token,
        },
        crypto::KrillSigner,
        error::Error as KrillError,
        eventsourcing::{
            namespace, AggregateStore, AggregateStoreError, Namespace,
        },
        util::{file, httpclient},
    },
    constants::{
        KRILL_CLI_API_ENV, KRILL_CLI_FORMAT_ENV, KRILL_TA_CLIENT_APP,
        KRILL_VERSION,
    },
    ta::{
        self, Config, TrustAnchorHandle, TrustAnchorProxySignerExchanges,
        TrustAnchorSignedRequest, TrustAnchorSignedResponse,
        TrustAnchorSigner, TrustAnchorSignerCommand, TrustAnchorSignerInfo,
        TrustAnchorSignerInitCommand, TrustAnchorSignerInitCommandDetails,
    },
};

use super::{
    options::GeneralArgs,
    report::{self, ReportFormat},
};

//------------------------ Client Constants
//------------------------ -------------------------------------
const CONFIG_PATH: &str = "/etc/krillta.conf";

//------------------------ Client Error
//------------------------ -----------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TaClientError {
    DataDirMissing,
    UnrecognizedMatch,
    HttpClientError(httpclient::Error),
    KrillError(KrillError),
    StorageError(AggregateStoreError),
    ConfigError(ta::ConfigError),
    Other(String),
}

impl TaClientError {
    fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for TaClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TaClientError::DataDirMissing => {
                write!(f, "Cannot find data dir")
            }
            TaClientError::UnrecognizedMatch => {
                write!(f, "Unrecognised argument. Use 'help'")
            }
            TaClientError::HttpClientError(e) => {
                write!(f, "HTTP client error: {}", e)
            }
            TaClientError::KrillError(e) => write!(f, "{}", e),
            TaClientError::StorageError(e) => {
                write!(f, "Issue with persistence layer: {}", e)
            }
            TaClientError::ConfigError(e) => {
                write!(f, "Issue with configuration file: {}", e)
            }
            TaClientError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<ta::ConfigError> for TaClientError {
    fn from(e: ta::ConfigError) -> Self {
        Self::ConfigError(e)
    }
}

impl From<KrillError> for TaClientError {
    fn from(e: KrillError) -> Self {
        Self::KrillError(e)
    }
}

impl From<report::ReportError> for TaClientError {
    fn from(e: report::ReportError) -> Self {
        TaClientError::Other(e.to_string())
    }
}

impl From<AggregateStoreError> for TaClientError {
    fn from(e: AggregateStoreError) -> Self {
        Self::StorageError(e)
    }
}

//------------------------ Client Commands
//------------------------ --------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorClientCommand {
    Proxy(ProxyCommand),
    Signer(SignerCommand),
}

impl TrustAnchorClientCommand {
    pub fn report_format(&self) -> report::ReportFormat {
        match self {
            TrustAnchorClientCommand::Signer(command) => command.format,
            TrustAnchorClientCommand::Proxy(command) => {
                command.general.format
            }
        }
    }
}

#[derive(Debug)]
pub struct ProxyCommand {
    general: GeneralArgs,
    details: ProxyCommandDetails,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProxyCommandDetails {
    Init,
    Id,
    RepoRequest,
    RepoContact,
    RepoConfigure(ApiRepositoryContact),
    SignerAdd(TrustAnchorSignerInfo),
    SignerMakeRequest,
    SignerShowRequest,
    SignerProcessResponse(TrustAnchorSignedResponse),
    ChildAdd(AddChildRequest),
    ChildResponse(ChildHandle),
}

#[derive(Debug)]
pub struct SignerCommand {
    config: Config,
    format: ReportFormat,
    details: SignerCommandDetails,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SignerCommandDetails {
    Init(SignerInitInfo),
    ShowInfo,
    ProcessRequest {
        signed_request: TrustAnchorSignedRequest,
        ta_mft_number_override: Option<u64>,
    },
    ShowLastResponse,
    ShowExchanges,
}

#[derive(Debug)]
pub struct SignerInitInfo {
    proxy_id: IdCertInfo,
    repo_info: RepoInfo,
    tal_https: Vec<uri::Https>,
    tal_rsync: uri::Rsync,
    private_key_pem: Option<String>,
    ta_mft_nr_override: Option<u64>,
}

impl TrustAnchorClientCommand {
    pub fn from_args() -> Result<Self, TaClientError> {
        let matches = Self::make_matches();
        Self::parse_matches(matches)
    }
}

/// # Create matches for command line parsing
impl TrustAnchorClientCommand {
    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new(KRILL_TA_CLIENT_APP).version(KRILL_VERSION);

        app = Self::make_proxy_sc(app);
        app = Self::make_signer_sc(app);

        app.get_matches()
    }

    //-- Sub Commands Proxy

    fn make_proxy_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("proxy")
            .about("Manage the Trust Anchor Proxy");

        sub = Self::make_proxy_init_sc(sub);
        sub = Self::make_proxy_id_sc(sub);
        sub = Self::make_proxy_repo_sc(sub);
        sub = Self::make_proxy_signer_sc(sub);
        sub = Self::make_proxy_children_sc(sub);

        app.subcommand(sub)
    }

    fn make_proxy_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("init").about("Initialise the proxy");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_id_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("id")
            .about("Get the proxy ID certificate details");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_repo_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("repo")
            .about("Manage the repository for proxy");
        sub = Self::make_proxy_repo_request_sc(sub);
        sub = Self::make_proxy_repo_contact_sc(sub);
        sub = Self::make_proxy_repo_configure_sc(sub);
        app.subcommand(sub)
    }

    fn make_proxy_repo_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request")
            .about("Get RFC 8183 publisher request");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_repo_contact_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("contact")
            .about("Show the configured repository for the proxy");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_repo_configure_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("configure")
            .about("Configure (add) the repository for the proxy");
        sub = GeneralArgs::add_args(sub);

        sub = sub.arg(
            Arg::with_name("response")
                .value_name("file")
                .long("response")
                .short("r")
                .help("The location of the RFC 8183 Publisher Response XML file")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_proxy_signer_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("signer")
            .about("Manage interactions with the associated signer");
        sub = Self::make_proxy_signer_init_sc(sub);
        sub = Self::make_proxy_signer_make_request_sc(sub);
        sub = Self::make_proxy_signer_show_request_sc(sub);
        sub = Self::make_proxy_signer_process_response_sc(sub);
        app.subcommand(sub)
    }

    fn make_proxy_signer_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init")
            .about("Initialise signer association");

        sub = GeneralArgs::add_args(sub);
        sub = sub.arg(
            Arg::with_name("info")
                .value_name("info")
                .long("info")
                .short("i")
                .help("The Trust Anchor Signer info JSON (as 'signer show')")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_proxy_signer_make_request_sc<'a, 'b>(
        app: App<'a, 'b>,
    ) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("make-request").about(
            "Make a NEW request for the signer (fails if a request exists).",
        );
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_signer_show_request_sc<'a, 'b>(
        app: App<'a, 'b>,
    ) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show-request")
            .about("Show the existing request for the signer (fails if there is no request).");
        sub = GeneralArgs::add_args(sub);
        app.subcommand(sub)
    }

    fn make_proxy_signer_process_response_sc<'a, 'b>(
        app: App<'a, 'b>,
    ) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("process-response")
            .about("Process a response from the signer. Fails it did not match the open request.");

        sub = GeneralArgs::add_args(sub);
        sub = sub.arg(
            Arg::with_name("response")
                .long("response")
                .short("r")
                .value_name("file")
                .help("Path to signer response (JSON)")
                .required(true),
        );
        app.subcommand(sub)
    }

    fn make_proxy_children_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("children")
            .about("Manage children under the TA proxy");
        sub = Self::make_proxy_children_add_sc(sub);
        sub = Self::make_proxy_children_response_sc(sub);
        app.subcommand(sub)
    }

    fn make_proxy_children_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a child. Recommended: add 1 child with all resources and use that as a parent to other CAs. This way the resources for those children can be updated without the need to have the offline signer sign a new certificate to them.");

        sub = GeneralArgs::add_args(sub);
        sub = sub
            .arg(
                Arg::with_name("info")
                    .value_name("info")
                    .long("info")
                    .short("i")
                    .help("The Child info JSON (as 'krillc show --ca <ca_name>')")
                    .required(true),
            )
            .arg(
                Arg::with_name("asn")
                    .value_name("asn resources")
                    .long("asn")
                    .help("The ASN resources for the child. Default: all")
                    .required(false),
            )
            .arg(
                Arg::with_name("ipv4")
                    .value_name("IPv4 resources")
                    .long("ipv4")
                    .help("The IPv4 resources for the child. Default: all")
                    .required(false),
            )
            .arg(
                Arg::with_name("ipv6")
                    .value_name("IPv6 resources")
                    .long("ipv6")
                    .help("The IPv6 resources for the child. Default: all")
                    .required(false),
            );

        app.subcommand(sub)
    }

    fn make_proxy_children_response_sc<'a, 'b>(
        app: App<'a, 'b>,
    ) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("response")
            .about("Get parent response for child.");
        sub = GeneralArgs::add_args(sub);
        sub = Self::add_child_arg(sub);
        app.subcommand(sub)
    }

    //-- Sub Commands Signer

    fn make_signer_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("signer")
            .about("Manage the Trust Anchor Signer");

        sub = Self::make_signer_init_sc(sub);
        sub = Self::make_signer_show_sc(sub);
        sub = Self::make_signer_process_sc(sub);
        sub = Self::make_signer_last_sc(sub);
        sub = Self::make_signer_exchanges_sc(sub);

        app.subcommand(sub)
    }

    fn make_signer_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("init").about("Initialise the signer");

        sub = Self::add_config_arg(sub)
            .arg(
                Arg::with_name("proxy_id")
                    .long("proxy_id")
                    .short("i")
                    .value_name("path")
                    .help("Path to Proxy ID JSON")
                    .required(true),
            )
            .arg(
                Arg::with_name("proxy_repository_contact")
                    .long("proxy_repository_contact")
                    .short("r")
                    .value_name("path")
                    .help("Path to Proxy ID JSON")
                    .required(true),
            )
            .arg(
                Arg::with_name("tal_rsync")
                    .long("tal_rsync")
                    .value_name("Rsync URI")
                    .help("Used for TA certificate on TAL and AIA")
                    .required(true),
            )
            .arg(
                Arg::with_name("tal_https")
                    .long("tal_https")
                    .value_name("HTTPS URI")
                    .help("Used for TAL. Multiple allowed.")
                    .multiple(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("private_key_pem")
                    .long("private_key_pem")
                    .value_name("path")
                    .help("[OPTIONAL] Import an existing private key in PEM format")
                    .required(false),
            )
            .arg(
                Arg::with_name("initial_manifest_number")
                    .long("initial_manifest_number")
                    .value_name("number")
                    .help("[OPTIONAL] Override the initial manifest number (defaults to 1)")
                    .required(false),
            );

        app.subcommand(sub)
    }

    fn make_signer_show_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("show").about("Show the signer info");
        sub = Self::add_config_arg(sub);
        sub = Self::add_format_arg(sub);
        app.subcommand(sub)
    }

    fn make_signer_process_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("process").about("Process a proxy request");
        sub = Self::add_config_arg(sub);
        sub = Self::add_format_arg(sub);

        sub = sub
            .arg(
                Arg::with_name("request")
                    .long("request")
                    .short("r")
                    .value_name("file")
                    .help("Path to TA Proxy request file (JSON)")
                    .required(true),
            )
            .arg(
                Arg::with_name("ta_mft_number_override")
                    .long("ta_mft_number_override")
                    .value_name("number")
                    .help("[OPTIONAL] Override the next manifest number (defaults to last + 1)")
                    .required(false),
            );
        app.subcommand(sub)
    }

    fn make_signer_last_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("last").about("Show last response");
        sub = Self::add_config_arg(sub);
        sub = Self::add_format_arg(sub);
        app.subcommand(sub)
    }

    fn make_signer_exchanges_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("exchanges")
            .about("Show full history of proxy signer exchanges. Text output shows summary.");
        sub = Self::add_config_arg(sub);
        sub = Self::add_format_arg(sub);
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

    fn add_format_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("format")
                .long("format")
                .value_name("type")
                .short("f")
                .help("Report format: none|json (default)|text. Or set env: KRILL_CLI_FORMAT")
                .required(false),
        )
    }

    fn add_child_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("child")
                .long("child")
                .value_name("name")
                .help("Name of the child CA")
                .required(true),
        )
    }
}

/// # Parse command line matches
impl TrustAnchorClientCommand {
    fn parse_matches(matches: ArgMatches) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("proxy") {
            Self::parse_matches_proxy(m)
        } else if let Some(m) = matches.subcommand_matches("signer") {
            Self::parse_matches_signer(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    //-- Parse Proxy
    fn parse_matches_proxy(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("id") {
            Self::parse_matches_proxy_id(m)
        } else if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_proxy_init(m)
        } else if let Some(m) = matches.subcommand_matches("repo") {
            Self::parse_matches_proxy_repo(m)
        } else if let Some(m) = matches.subcommand_matches("signer") {
            Self::parse_matches_proxy_signer(m)
        } else if let Some(m) = matches.subcommand_matches("children") {
            Self::parse_matches_proxy_children(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    fn parse_matches_proxy_init(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let details = ProxyCommandDetails::Init;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details,
        }))
    }

    fn parse_matches_proxy_id(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let details = ProxyCommandDetails::Id;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details,
        }))
    }

    fn parse_matches_proxy_repo(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_proxy_repo_request(m)
        } else if let Some(m) = matches.subcommand_matches("contact") {
            Self::parse_matches_proxy_repo_contact(m)
        } else if let Some(m) = matches.subcommand_matches("configure") {
            Self::parse_matches_proxy_repo_configure(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    fn parse_matches_proxy_repo_request(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let details = ProxyCommandDetails::RepoRequest;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details,
        }))
    }

    fn parse_matches_proxy_repo_contact(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let details = ProxyCommandDetails::RepoContact;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details,
        }))
    }

    fn parse_matches_proxy_repo_configure(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;

        let path = matches.value_of("response").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let response = idexchange::RepositoryResponse::parse(bytes.as_ref())
            .map_err(|e| {
                TaClientError::Other(format!(
                    "Cannot parse repository response: {}",
                    e
                ))
            })?;

        let details = ProxyCommandDetails::RepoConfigure(
            ApiRepositoryContact::new(response),
        );

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details,
        }))
    }

    fn parse_matches_proxy_signer(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_proxy_signer_init(m)
        } else if let Some(m) = matches.subcommand_matches("make-request") {
            Self::parse_matches_proxy_signer_make_request(m)
        } else if let Some(m) = matches.subcommand_matches("show-request") {
            Self::parse_matches_proxy_signer_show_request(m)
        } else if let Some(m) = matches.subcommand_matches("process-response")
        {
            Self::parse_matches_proxy_signer_process_response(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    fn parse_matches_proxy_signer_init(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;

        let info = Self::read_json(matches.value_of("info").unwrap())?;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::SignerAdd(info),
        }))
    }

    fn parse_matches_proxy_signer_make_request(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::SignerMakeRequest,
        }))
    }

    fn parse_matches_proxy_signer_show_request(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::SignerShowRequest,
        }))
    }

    fn parse_matches_proxy_signer_process_response(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let response =
            Self::read_json(matches.value_of("response").unwrap())?;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::SignerProcessResponse(response),
        }))
    }

    fn parse_matches_proxy_children(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_proxy_children_add(m)
        } else if let Some(m) = matches.subcommand_matches("response") {
            Self::parse_matches_proxy_children_response(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    fn parse_matches_proxy_children_add(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;

        let info: CertAuthInfo =
            Self::read_json(matches.value_of("info").unwrap())?;
        let resources: ResourceSet = {
            let asn = matches.value_of("asn").unwrap_or("AS0-AS4294967295");
            let ipv4 = matches.value_of("ipv4").unwrap_or("0.0.0.0/0");
            let ipv6 = matches.value_of("ipv6").unwrap_or("::/0");
            ResourceSet::from_strs(asn, ipv4, ipv6).map_err(|e| {
                TaClientError::Other(format!("Cannot parse resources: {}", e))
            })?
        };

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::ChildAdd(AddChildRequest::new(
                info.handle().convert(),
                resources,
                info.id_cert().try_into()?,
            )),
        }))
    }

    fn parse_matches_proxy_children_response(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let general = GeneralArgs::from_matches(matches)
            .map_err(|e| TaClientError::Other(e.to_string()))?;
        let child = Self::parse_child_arg(matches)?;

        Ok(TrustAnchorClientCommand::Proxy(ProxyCommand {
            general,
            details: ProxyCommandDetails::ChildResponse(child),
        }))
    }

    fn parse_child_arg(
        matches: &ArgMatches,
    ) -> Result<ChildHandle, TaClientError> {
        let child_str = matches.value_of("child").unwrap();
        ChildHandle::from_str(child_str).map_err(|e| {
            TaClientError::Other(format!("Invalid child name: {}", e))
        })
    }

    fn read_file_arg(path_str: &str) -> Result<Bytes, TaClientError> {
        let path = PathBuf::from(path_str);
        file::read(&path).map_err(|e| {
            TaClientError::Other(format!(
                "Can't read: {}. Error: {}",
                path_str, e
            ))
        })
    }

    // Read json from a path argument
    fn read_json<T: DeserializeOwned>(
        path: &str,
    ) -> Result<T, TaClientError> {
        let bytes = Self::read_file_arg(path)?;

        serde_json::from_slice(&bytes).map_err(|e| {
            TaClientError::Other(format!(
                "Cannot deserialize file {}: {}",
                path, e
            ))
        })
    }

    //-- Parse Signer
    fn parse_matches_signer(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_signer_init(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_signer_show(m)
        } else if let Some(m) = matches.subcommand_matches("process") {
            Self::parse_matches_signer_process(m)
        } else if let Some(m) = matches.subcommand_matches("last") {
            Self::parse_matches_signer_last_response(m)
        } else if let Some(m) = matches.subcommand_matches("exchanges") {
            Self::parse_matches_signer_exchanges(m)
        } else {
            Err(TaClientError::UnrecognizedMatch)
        }
    }

    fn parse_matches_signer_init(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let config = Self::parse_config(matches)?;
        let format = ReportFormat::None;

        let proxy_id =
            Self::read_json(matches.value_of("proxy_id").unwrap())?;

        let repo_info = {
            let repo_contact: RepositoryContact = Self::read_json(
                matches.value_of("proxy_repository_contact").unwrap(),
            )?;
            repo_contact.into()
        };

        let tal_https = {
            let uri_strs = matches.values_of("tal_https").unwrap();
            let mut uris = vec![];
            for uri_str in uri_strs {
                uris.push(uri::Https::from_str(uri_str).map_err(|_| {
                    TaClientError::Other(format!(
                        "Invalid HTTPS URI: {}",
                        uri_str
                    ))
                })?);
            }
            uris
        };

        let tal_rsync = {
            let rsync_str = matches.value_of("tal_rsync").unwrap();
            uri::Rsync::from_str(rsync_str).map_err(|_| {
                TaClientError::Other(format!(
                    "Invalid rsync uri: {}",
                    rsync_str
                ))
            })?
        };

        let ta_mft_nr_override = if let Some(number) =
            matches.value_of("initial_manifest_number")
        {
            let nr = u64::from_str(number).map_err(|_| {
                TaClientError::other("Invalid manifest number, must be >1")
            })?;
            Some(nr)
        } else {
            None
        };

        let private_key_pem = if let Some(path) =
            matches.value_of("private_key_pem")
        {
            let bytes = Self::read_file_arg(path)?;
            let pem = std::str::from_utf8(&bytes).map_err(|_| {
                TaClientError::other("invalid UTF8 in private_key_pem file")
            })?;
            Some(pem.to_string())
        } else {
            None
        };

        let info = SignerInitInfo {
            proxy_id,
            repo_info,
            tal_https,
            tal_rsync,
            ta_mft_nr_override,
            private_key_pem,
        };
        let details = SignerCommandDetails::Init(info);

        Ok(TrustAnchorClientCommand::Signer(SignerCommand {
            config,
            format,
            details,
        }))
    }

    fn parse_matches_signer_show(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let config = Self::parse_config(matches)?;
        let format = Self::parse_format(matches)?;

        Ok(TrustAnchorClientCommand::Signer(SignerCommand {
            config,
            format,
            details: SignerCommandDetails::ShowInfo,
        }))
    }

    fn parse_matches_signer_process(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let config = Self::parse_config(matches)?;
        let format = Self::parse_format(matches)?;
        let signed_request =
            Self::read_json(matches.value_of("request").unwrap())?;

        let ta_mft_number_override = if let Some(nr_str) =
            matches.value_of("ta_mft_number_override")
        {
            let nr = u64::from_str(nr_str).map_err(|_| {
                TaClientError::other(
                    "Invalid number for ta_mft_number_override, must be >1",
                )
            })?;
            Some(nr)
        } else {
            None
        };

        Ok(TrustAnchorClientCommand::Signer(SignerCommand {
            config,
            format,
            details: SignerCommandDetails::ProcessRequest {
                signed_request,
                ta_mft_number_override,
            },
        }))
    }

    fn parse_matches_signer_last_response(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let config = Self::parse_config(matches)?;
        let format = Self::parse_format(matches)?;

        Ok(TrustAnchorClientCommand::Signer(SignerCommand {
            config,
            format,
            details: SignerCommandDetails::ShowLastResponse,
        }))
    }

    fn parse_matches_signer_exchanges(
        matches: &ArgMatches,
    ) -> Result<Self, TaClientError> {
        let config = Self::parse_config(matches)?;
        let format = Self::parse_format(matches)?;
        let details = SignerCommandDetails::ShowExchanges;

        Ok(TrustAnchorClientCommand::Signer(SignerCommand {
            config,
            format,
            details,
        }))
    }

    fn parse_config(matches: &ArgMatches) -> Result<Config, TaClientError> {
        let config_path = matches.value_of("config").unwrap_or(CONFIG_PATH);
        Config::parse(config_path).map_err(TaClientError::ConfigError)
    }

    fn parse_format(
        matches: &ArgMatches,
    ) -> Result<ReportFormat, TaClientError> {
        let mut format = match env::var(KRILL_CLI_FORMAT_ENV) {
            Ok(fmt_str) => Some(ReportFormat::from_str(&fmt_str)?),
            Err(_) => None,
        };

        if let Some(fmt_str) = matches.value_of("format") {
            format = Some(ReportFormat::from_str(fmt_str)?);
        }

        Ok(format.unwrap_or(ReportFormat::Json))
    }
}

//------------------------ TrustAnchorClient
//------------------------ ------------------------------------

pub struct TrustAnchorClient;

impl TrustAnchorClient {
    pub async fn process(
        command: TrustAnchorClientCommand,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        match command {
            TrustAnchorClientCommand::Proxy(proxy_command) => {
                let client = ProxyClient::create(proxy_command.general);

                match proxy_command.details {
                    ProxyCommandDetails::Init => {
                        client.post_empty("api/v1/ta/proxy/init").await
                    }
                    ProxyCommandDetails::Id => {
                        let id_cert =
                            client.get_json("api/v1/ta/proxy/id").await?;
                        Ok(TrustAnchorClientApiResponse::IdCert(id_cert))
                    }
                    ProxyCommandDetails::RepoRequest => {
                        let publisher_request = client
                            .get_json("api/v1/ta/proxy/repo/request.json")
                            .await?;
                        Ok(TrustAnchorClientApiResponse::PublisherRequest(
                            publisher_request,
                        ))
                    }
                    ProxyCommandDetails::RepoContact => {
                        let contact =
                            client.get_json("api/v1/ta/proxy/repo").await?;
                        Ok(TrustAnchorClientApiResponse::RepositoryContact(
                            contact,
                        ))
                    }
                    ProxyCommandDetails::RepoConfigure(repo_response) => {
                        client
                            .post_json("api/v1/ta/proxy/repo", repo_response)
                            .await
                    }
                    ProxyCommandDetails::SignerAdd(info) => {
                        client
                            .post_json("api/v1/ta/proxy/signer/add", info)
                            .await
                    }
                    ProxyCommandDetails::SignerMakeRequest => {
                        let request = client
                            .post_empty_with_response(
                                "api/v1/ta/proxy/signer/request",
                            )
                            .await?;
                        Ok(TrustAnchorClientApiResponse::SignerRequest(
                            request,
                        ))
                    }
                    ProxyCommandDetails::SignerShowRequest => {
                        let request = client
                            .get_json("api/v1/ta/proxy/signer/request")
                            .await?;
                        Ok(TrustAnchorClientApiResponse::SignerRequest(
                            request,
                        ))
                    }
                    ProxyCommandDetails::SignerProcessResponse(response) => {
                        client
                            .post_json(
                                "api/v1/ta/proxy/signer/response",
                                response,
                            )
                            .await
                    }
                    ProxyCommandDetails::ChildAdd(child) => {
                        let response = client
                            .post_json_with_response(
                                "api/v1/ta/proxy/children",
                                child,
                            )
                            .await?;
                        Ok(TrustAnchorClientApiResponse::ParentResponse(
                            response,
                        ))
                    }
                    ProxyCommandDetails::ChildResponse(child) => {
                        let uri_path = format!("api/v1/ta/proxy/children/{}/parent_response.json", child);
                        let response = client.get_json(&uri_path).await?;
                        Ok(TrustAnchorClientApiResponse::ParentResponse(
                            response,
                        ))
                    }
                }
            }
            TrustAnchorClientCommand::Signer(signer_command) => {
                let signer_manager =
                    TrustAnchorSignerManager::create(signer_command.config)?;

                match signer_command.details {
                    SignerCommandDetails::Init(info) => {
                        signer_manager.init(info)
                    }
                    SignerCommandDetails::ShowInfo => signer_manager.show(),
                    SignerCommandDetails::ProcessRequest {
                        signed_request,
                        ta_mft_number_override,
                    } => signer_manager
                        .process(signed_request, ta_mft_number_override),
                    SignerCommandDetails::ShowLastResponse => {
                        signer_manager.show_last_response()
                    }
                    SignerCommandDetails::ShowExchanges => {
                        signer_manager.show_exchanges()
                    }
                }
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorClientApiResponse {
    IdCert(IdCertInfo),
    PublisherRequest(idexchange::PublisherRequest),
    RepositoryContact(RepositoryContact),
    TrustAnchorProxySignerInfo(TrustAnchorSignerInfo),
    ParentResponse(idexchange::ParentResponse),
    SignerRequest(TrustAnchorSignedRequest),
    SignerResponse(TrustAnchorSignedResponse),
    ProxySignerExchanges(TrustAnchorProxySignerExchanges),
    Empty,
}

impl TrustAnchorClientApiResponse {
    pub fn report(
        &self,
        fmt: report::ReportFormat,
    ) -> Result<Option<String>, report::ReportError> {
        if fmt == report::ReportFormat::None {
            Ok(None)
        } else {
            match self {
                TrustAnchorClientApiResponse::IdCert(id_cert) => {
                    id_cert.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::PublisherRequest(pr) => {
                    pr.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::RepositoryContact(contact) => {
                    contact.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::TrustAnchorProxySignerInfo(
                    info,
                ) => info.report(fmt).map(Some),
                TrustAnchorClientApiResponse::ParentResponse(response) => {
                    response.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::SignerRequest(request) => {
                    request.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::SignerResponse(response) => {
                    response.report(fmt).map(Some)
                }
                TrustAnchorClientApiResponse::ProxySignerExchanges(
                    exchanges,
                ) => exchanges.report(fmt).map(Some),
                TrustAnchorClientApiResponse::Empty => Ok(None),
            }
        }
    }
}

//------------------------ ProxyClient
//------------------------ ------------------------------------------

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

    async fn post_empty(
        &self,
        path: &str,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        let uri = self.resolve_uri(path);
        httpclient::post_empty(&uri, Some(&self.token))
            .await
            .map(|_| TrustAnchorClientApiResponse::Empty)
            .map_err(TaClientError::HttpClientError)
    }

    async fn post_empty_with_response<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, TaClientError> {
        let uri = self.resolve_uri(path);
        httpclient::post_empty_with_response(&uri, Some(&self.token))
            .await
            .map_err(TaClientError::HttpClientError)
    }

    async fn post_json(
        &self,
        path: &str,
        data: impl serde::Serialize,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        let uri = self.resolve_uri(path);
        httpclient::post_json(&uri, data, Some(&self.token))
            .await
            .map(|_| TrustAnchorClientApiResponse::Empty)
            .map_err(TaClientError::HttpClientError)
    }

    async fn post_json_with_response<T: DeserializeOwned>(
        &self,
        path: &str,
        data: impl serde::Serialize,
    ) -> Result<T, TaClientError> {
        let uri = self.resolve_uri(path);
        httpclient::post_json_with_response(&uri, data, Some(&self.token))
            .await
            .map_err(TaClientError::HttpClientError)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, TaClientError> {
        let uri = self.resolve_uri(path);
        httpclient::get_json(&uri, Some(&self.token))
            .await
            .map_err(TaClientError::HttpClientError)
    }

    fn resolve_uri(&self, path: &str) -> String {
        format!("{}{}", self.server, path)
    }
}

//------------------------ TrustAnchorSignerManager
//------------------------ -----------------------------

struct TrustAnchorSignerManager {
    store: AggregateStore<TrustAnchorSigner>,
    ta_handle: TrustAnchorHandle,
    config: Arc<Config>,
    signer: Arc<KrillSigner>,
    actor: Actor,
}

impl TrustAnchorSignerManager {
    fn create(config: Config) -> Result<Self, TaClientError> {
        let store = AggregateStore::create(
            &config.storage_uri,
            namespace!("signer"),
            config.use_history_cache,
        )
        .map_err(KrillError::AggregateStoreError)?;
        let ta_handle = TrustAnchorHandle::new("ta".into());
        let config = Arc::new(config);
        let signer = config.signer()?;
        let actor = Actor::krillta();

        Ok(TrustAnchorSignerManager {
            store,
            ta_handle,
            config,
            signer,
            actor,
        })
    }

    fn init(
        &self,
        info: SignerInitInfo,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        if self.store.has(&self.ta_handle)? {
            Err(TaClientError::other(
                "Trust Anchor Signer was already initialised.",
            ))
        } else {
            let cmd = TrustAnchorSignerInitCommand::new(
                &self.ta_handle,
                TrustAnchorSignerInitCommandDetails {
                    proxy_id: info.proxy_id,
                    repo_info: info.repo_info,
                    tal_https: info.tal_https,
                    tal_rsync: info.tal_rsync,
                    private_key_pem: info.private_key_pem,
                    ta_mft_nr_override: info.ta_mft_nr_override,
                    timing: self.config.timing_config,
                    signer: self.signer.clone(),
                },
                &self.actor,
            );

            self.store.add(cmd)?;

            Ok(TrustAnchorClientApiResponse::Empty)
        }
    }

    fn show(&self) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        let ta_signer = self.get_signer()?;
        let info = ta_signer.get_signer_info();
        Ok(TrustAnchorClientApiResponse::TrustAnchorProxySignerInfo(
            info,
        ))
    }

    fn process(
        &self,
        signed_request: TrustAnchorSignedRequest,
        ta_mft_number_override: Option<u64>,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        let cmd = TrustAnchorSignerCommand::make_process_request_command(
            &self.ta_handle,
            signed_request,
            self.config.timing_config,
            ta_mft_number_override,
            self.signer.clone(),
            &self.actor,
        );
        self.store.command(cmd)?;

        self.show_last_response()
    }

    fn show_last_response(
        &self,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        self.get_signer()?
            .get_latest_exchange()
            .map(|exchange| {
                TrustAnchorClientApiResponse::SignerResponse(
                    exchange.response.clone(),
                )
            })
            .ok_or_else(|| TaClientError::other("No response found."))
    }

    fn show_exchanges(
        &self,
    ) -> Result<TrustAnchorClientApiResponse, TaClientError> {
        let signer = self.get_signer()?;
        // In this context it's okay to clone the exchanges.
        // If we are afraid that this would become too expensive, then we will
        // need to rethink the model where we return data in the enum that we
        // use. We can't have references and lifetimes because the signer will
        // be gone..
        //
        // But, again, in this context this should never be huge with
        // exchanges happening every couple of months. So, it should
        // all be fine.
        let exchanges = signer.get_exchanges().clone();
        Ok(TrustAnchorClientApiResponse::ProxySignerExchanges(
            exchanges,
        ))
    }

    fn get_signer(&self) -> Result<Arc<TrustAnchorSigner>, TaClientError> {
        if self.store.has(&self.ta_handle)? {
            self.store
                .get_latest(&self.ta_handle)
                .map_err(TaClientError::KrillError)
        } else {
            Err(TaClientError::other(
                "Trust Anchor Signer is not initialised.",
            ))
        }
    }
}
