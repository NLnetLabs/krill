use std::convert::TryFrom;
use std::env;
use std::io;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};

use clap::{App, Arg, ArgMatches, SubCommand};

use rpki::uri;

use crate::cli::report::{ReportError, ReportFormat};
use crate::commons::api::{
    AddChildRequest, AddParentRequest, AuthorizationFmtError, CertAuthInit, CertAuthPubMode,
    ChildAuthRequest, Handle, ParentCaContact, ResSetErr, ResourceSet, RouteAuthorizationUpdates,
    Token, UpdateChildRequest,
};
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;

const KRILL_CLI_SERVER_ARG: &str = "server";
const KRILL_CLI_SERVER_ENV: &str = "KRILL_CLI_SERVER";

const KRILL_CLI_TOKEN_ARG: &str = "admintoken";
const KRILL_CLI_TOKEN_ENV: &str = "KRILL_CLI_ADMIN_TOKEN";

const KRILL_CLI_FORMAT_ARG: &str = "format";
const KRILL_CLI_FORMAT_ENV: &str = "KRILL_CLI_FORMAT";

const KRILL_CLI_API_ARG: &str = "api";
pub const KRILL_CLI_API_ENV: &str = "KRILL_CLI_API";

const KRILL_CLI_MY_CA_ARG: &str = "ca";
const KRILL_CLI_MY_CA_ENV: &str = "KRILL_CLI_MY_CA";

const KRILL_CLI_MY_CA_TOKEN_ARG: &str = "catoken";
const KRILL_CLI_MY_CA_TOKEN_ENV: &str = "KRILL_CLI_MY_CA_TOKEN";

struct GeneralArgs {
    server: uri::Https,
    token: Token,
    format: ReportFormat,
    api: bool,
}

impl GeneralArgs {
    fn from_matches(matches: &ArgMatches) -> Result<Self, Error> {
        let server = {
            let mut server = match env::var(KRILL_CLI_SERVER_ENV) {
                Ok(server_str) => Some(uri::Https::try_from(server_str)?),
                Err(_) => None,
            };

            if let Some(server_str) = matches.value_of(KRILL_CLI_SERVER_ARG) {
                server = Some(uri::Https::from_str(server_str)?);
            }

            server.ok_or_else(|| {
                Error::missing_arg_with_env(KRILL_CLI_SERVER_ARG, KRILL_CLI_SERVER_ENV)
            })?
        };

        let token = {
            let mut token = env::var(KRILL_CLI_TOKEN_ENV).ok().map(Token::from);

            if let Some(token_str) = matches.value_of(KRILL_CLI_TOKEN_ARG) {
                token = Some(Token::from(token_str));
            }

            token.ok_or_else(|| {
                Error::missing_arg_with_env(KRILL_CLI_TOKEN_ARG, KRILL_CLI_TOKEN_ENV)
            })?
        };

        let format = {
            let mut format = match env::var(KRILL_CLI_FORMAT_ENV) {
                Ok(fmt_str) => Some(ReportFormat::from_str(&fmt_str)?),
                Err(_) => None,
            };

            if let Some(fmt_str) = matches.value_of(KRILL_CLI_FORMAT_ARG) {
                format = Some(ReportFormat::from_str(fmt_str)?);
            }

            format.unwrap_or_else(|| ReportFormat::Text)
        };

        let api = env::var(KRILL_CLI_API_ENV).is_ok() || matches.is_present(KRILL_CLI_API_ARG);

        Ok(GeneralArgs {
            server,
            token,
            format,
            api,
        })
    }
}

/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action. Note that this is extracted
/// from the bin/krillc.rs, so that we can use this in integration testing
/// more easily.
pub struct Options {
    pub server: uri::Https,
    pub token: Token,
    pub format: ReportFormat,
    pub api: bool,
    pub command: Command,
}

impl Options {
    fn make(general: GeneralArgs, command: Command) -> Self {
        Options {
            server: general.server,
            token: general.token,
            format: general.format,
            api: general.api,
            command,
        }
    }

    pub fn format(&self) -> ReportFormat {
        self.format
    }

    /// Creates a new Options explicitly (useful for testing)
    pub fn new(server: uri::Https, token: &str, format: ReportFormat, command: Command) -> Self {
        Options {
            server,
            token: Token::from(token),
            format,
            api: false,
            command,
        }
    }

    fn add_general_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("URI")
                .help("The full URI to the krill server. Or set env: KRILL_CLI_SERVER")
                .required(false),
        )
        .arg(
            Arg::with_name("admintoken")
                .short("t")
                .long("admintoken")
                .value_name("token-string")
                .help("The admin token. Or set env: KRILL_CLI_ADMIN_TOKEN")
                .required(false),
        )
        .arg(
            Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("type")
                .help("Report format: none|json|text (default) |xml. Or set env: KRILL_CLI_FORMAT")
                .required(false),
        )
        .arg(
            Arg::with_name("api")
                .long("api")
                .help("Only show the API call and exit. Or set env: KRILL_CLI_API=1")
                .required(false),
        )
    }

    fn add_my_ca_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("ca")
                .value_name("name")
                .short("c")
                .long("ca")
                .help("The name of the CA you wish to control. Or set env: KRILL_CLI_MY_CA")
                .required(false),
        )
    }

    fn add_child_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("child")
                .value_name("name")
                .long("child")
                .help("The name of the child CA you wish to control.")
                .required(true),
        )
    }

    fn add_child_resource_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("asn")
                .short("a")
                .long("asn")
                .value_name("AS resources")
                .help("The delegated AS resources: e.g. AS1, AS3-4")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv4")
                .short("4")
                .long("ipv4")
                .value_name("IPv4 resources")
                .help("The delegated IPv4 resources: e.g. 192.168.0.0/16")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv6")
                .short("6")
                .long("ipv6")
                .value_name("IPv6 resources")
                .help("The delegated IPv6 resources: e.g. 2001:db8::/32")
                .required(false),
        )
    }

    fn add_child_embedded_rfc6492_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("embedded")
                .long("embedded")
                .help("Add a child that exists in this Krill instance. Note that an id cert can \
                still be added later to allow this child to connect remotely. It's really how the \
                child configures its parent that determines how it will connect")
                .required(false)
        )
        .arg(
            Arg::with_name("rfc8183")
                .long("rfc8183")
                .help("Add a child using an RFC8183 Child Request XML file. This will return \
                an RFC8183 Parent Response XML (on stdout)")
                .value_name("<XML file>")
                .required(false)
        )
    }

    fn add_parent_embedded_rfc6492_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("parent")
                .long("parent")
                .short("p")
                .value_name("name")
                .help("The local by which your ca refers to this parent.")
                .required(true),
        )
        .arg(
            Arg::with_name("embedded")
                .long("embedded")
                .help("Add a parent that exists in this Krill instance.")
                .required(false),
        )
        .arg(
            Arg::with_name("rfc8183")
                .long("rfc8183")
                .help("Add a parent using an RFC8183 Parent Response XML file.")
                .value_name("<XML file>")
                .required(false),
        )
    }

    fn make_cas_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let sub = SubCommand::with_name("list").about("List the current CAs.");

        let sub = Self::add_general_args(sub);

        app.subcommand(sub)
    }

    fn make_cas_show_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show details of a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_show_history_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("history").about("Show full history of a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_add_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a new CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("catoken")
                .help("The token for your CA. Or set: KRILL_MY_CA_TOKEN")
                .value_name("token-string")
                .long("catoken")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_children_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a child to a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);
        sub = Self::add_child_resource_args(sub);
        sub = Self::add_child_embedded_rfc6492_args(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update an existing child of a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);
        sub = Self::add_child_resource_args(sub);
        sub = sub.arg(
            Arg::with_name("idcert")
                .long("idcert")
                .help("The child's updated ID certificate")
                .value_name("DER encoded certificate")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_children_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("children").about("Manage children for a CA in Krill.");

        sub = Self::make_cas_children_add_sc(sub);
        sub = Self::make_cas_children_update_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_myid_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("myid").about("Show this CA's RFC8183 Request XML");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a parent to this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_embedded_rfc6492_args(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("parents").about("Manage parents for a CA.");

        sub = Self::make_cas_parents_myid_sc(sub);
        sub = Self::make_cas_parents_add_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("init").about("Initialise roll for all keys held by this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_activate_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("activate").about("Finish roll for all keys held by this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("keyroll").about("Perform a manual key-roll in Krill.");

        sub = Self::make_cas_keyroll_init_sc(sub);
        sub = Self::make_cas_keyroll_activate_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("Show current authorizations.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update authorizations.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("delta")
                .long("delta")
                .help(concat!(
                    "Provide a delta file using the following format:\n",
                    "# Some comment\n",
                    "  # Indented comment\n",
                    "\n", // empty line
                    "A: 192.168.0.0/16 => 64496 # inline comment\n",
                    "A: 192.168.1.0/24 => 64496\n",
                    "R: 192.168.3.0/24 => 64496\n",
                ))
                .value_name("<file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_routes_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("roas").about("Manage ROAs for your CA.");

        sub = Self::make_cas_routes_list_sc(sub);
        sub = Self::make_cas_routes_update_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("cas").about("Manage Certification Authorities");

        sub = Self::make_cas_list_sc(sub);
        sub = Self::make_cas_show_ca_sc(sub);
        sub = Self::make_cas_show_history_sc(sub);
        sub = Self::make_cas_add_ca_sc(sub);
        sub = Self::make_cas_children_sc(sub);
        sub = Self::make_cas_parents_sc(sub);
        sub = Self::make_cas_keyroll_sc(sub);
        sub = Self::make_cas_routes_sc(sub);

        app.subcommand(sub)
    }

    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new("Krill Client").version("0.1.1");

        app = Self::make_cas_sc(app);

        app.get_matches()
    }

    //---------------------- Parsing

    fn parse_my_ca(matches: &ArgMatches) -> Result<Handle, Error> {
        let my_ca = {
            let mut my_ca = None;

            if let Ok(my_ca_env) = env::var(KRILL_CLI_MY_CA_ENV) {
                my_ca = Some(Handle::from_str(&my_ca_env).map_err(|_| Error::InvalidHandle)?);
            }

            if let Some(my_ca_str) = matches.value_of(KRILL_CLI_MY_CA_ARG) {
                my_ca = Some(Handle::from_str(my_ca_str).map_err(|_| Error::InvalidHandle)?);
            }

            my_ca.ok_or_else(|| {
                Error::missing_arg_with_env(KRILL_CLI_MY_CA_ARG, KRILL_CLI_MY_CA_ENV)
            })?
        };

        Ok(my_ca)
    }

    fn parse_my_ca_token(matches: &ArgMatches) -> Result<Token, Error> {
        let my_ca_token = {
            let mut my_ca_token = env::var(KRILL_CLI_MY_CA_TOKEN_ENV).ok().map(Token::from);

            if let Some(my_ca_token_str) = matches.value_of(KRILL_CLI_MY_CA_TOKEN_ARG) {
                my_ca_token = Some(Token::from(my_ca_token_str));
            }

            my_ca_token.ok_or_else(|| {
                Error::missing_arg_with_env(KRILL_CLI_MY_CA_TOKEN_ARG, KRILL_CLI_MY_CA_TOKEN_ENV)
            })?
        };

        Ok(my_ca_token)
    }

    fn parse_resource_args(matches: &ArgMatches) -> Result<Option<ResourceSet>, Error> {
        let asn = matches.value_of("asn");
        let v4 = matches.value_of("ipv4");
        let v6 = matches.value_of("ipv6");

        if asn.is_some() || v4.is_some() || v6.is_some() {
            let asn = asn.unwrap_or_else(|| "");
            let v4 = v4.unwrap_or_else(|| "");
            let v6 = v6.unwrap_or_else(|| "");

            Ok(Some(ResourceSet::from_strs(asn, v4, v6)?))
        } else {
            Ok(None)
        }
    }

    fn parse_matches_cas_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::CertAuth(CaCommand::List);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let token = Self::parse_my_ca_token(matches)?;

        let init = CertAuthInit::new(my_ca, token, CertAuthPubMode::Embedded);

        let command = Command::CertAuth(CaCommand::Init(init));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_show(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::Show(my_ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_history(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ShowHistory(my_ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let resources =
            Self::parse_resource_args(matches)?.ok_or_else(|| Error::MissingResources)?;

        let auth_request = {
            if matches.is_present("embedded") {
                ChildAuthRequest::Embedded
            } else if let Some(path) = matches.value_of("rfc8183") {
                let xml = PathBuf::from(path);
                let bytes = file::read(&xml)?;
                let cr = rfc8183::ChildRequest::validate(bytes.as_ref())?;
                ChildAuthRequest::Rfc8183(cr)
            } else {
                return Err(Error::MissingChildAuth);
            }
        };

        let child_request = AddChildRequest::new(child, resources, auth_request);

        let command = Command::CertAuth(CaCommand::AddChild(my_ca, child_request));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let id_cert = {
            if let Some(path) = matches.value_of("idcert") {
                let bytes = file::read(&PathBuf::from(path))?;
                let id_cert = IdCert::decode(bytes).map_err(|_| Error::InvalidChildIdCert)?;
                Some(id_cert)
            } else {
                None
            }
        };
        let resources = Self::parse_resource_args(matches)?;

        let update = UpdateChildRequest::force(id_cert, resources);

        let command = Command::CertAuth(CaCommand::UpdateChild(my_ca, child, update));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_children_add(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_children_update(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_parents_myid(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ChildRequest(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let parent_req = {
            if matches.is_present("embedded") {
                AddParentRequest::new(parent, ParentCaContact::Embedded)
            } else if let Some(path) = matches.value_of("rfc8183") {
                let xml = PathBuf::from(path);
                let bytes = file::read(&xml)?;
                let res = rfc8183::ParentResponse::validate(bytes.as_ref())?;

                AddParentRequest::new(parent, ParentCaContact::for_rfc6492(res))
            } else {
                return Err(Error::MissingChildAuth);
            }
        };

        let command = Command::CertAuth(CaCommand::AddParent(my_ca, parent_req));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("myid") {
            Self::parse_matches_cas_parents_myid(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_parents_add(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_keyroll_init(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::KeyRollInit(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_keyroll_activate(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::KeyRollActivate(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_keyroll(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_cas_keyroll_init(m)
        } else if let Some(m) = matches.subcommand_matches("activate") {
            Self::parse_matches_cas_keyroll_activate(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_routes_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::RouteAuthorizationsList(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_routes_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let updates = {
            let path = matches.value_of("delta").map(PathBuf::from).unwrap();
            let bytes = file::read(&path)?;
            let updates_str = unsafe { from_utf8_unchecked(&bytes) };
            RouteAuthorizationUpdates::from_str(updates_str)?
        };

        let command = Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(my_ca, updates));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_routes(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_routes_list(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_routes_update(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_list(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_add(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_show(m)
        } else if let Some(m) = matches.subcommand_matches("history") {
            Self::parse_matches_cas_history(m)
        } else if let Some(m) = matches.subcommand_matches("children") {
            Self::parse_matches_cas_children(m)
        } else if let Some(m) = matches.subcommand_matches("parents") {
            Self::parse_matches_cas_parents(m)
        } else if let Some(m) = matches.subcommand_matches("keyroll") {
            Self::parse_matches_cas_keyroll(m)
        } else if let Some(m) = matches.subcommand_matches("roas") {
            Self::parse_matches_cas_routes(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches(matches: ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("cas") {
            Self::parse_matches_cas(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    pub fn from_args() -> Result<Options, Error> {
        let matches = Self::make_matches();
        Self::parse_matches(matches)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    NotSet,
    Health,
    CertAuth(CaCommand),
    Publishers(PublishersCommand),
    Rfc8181(Rfc8181Command),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommand {
    // Initialise a CA
    Init(CertAuthInit),

    // Get the RFC8183 child request
    ChildRequest(Handle),

    // Add a parent to this CA
    AddParent(Handle, AddParentRequest),

    // Children
    AddChild(Handle, AddChildRequest),
    UpdateChild(Handle, Handle, UpdateChildRequest),

    // Initialise a manual key-roll now
    KeyRollInit(Handle),

    // Activate all new keys now (finish keyroll, provided new key was certified)
    KeyRollActivate(Handle),

    // List the current RouteAuthorizations
    RouteAuthorizationsList(Handle),

    // Update the Route Authorizations for this CA
    RouteAuthorizationsUpdate(Handle, RouteAuthorizationUpdates),

    // Show details for this CA
    Show(Handle),

    // Show the history for this CA
    ShowHistory(Handle),

    // List all CAs
    List,

    // Refresh all CAs: let them update from parents, and shrink children if needed
    RefreshAll,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishersCommand {
    Add(AddPublisher),
    Details(Handle),
    Deactivate(Handle),
    List,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddPublisher {
    pub handle: Handle,
    pub base_uri: uri::Rsync,
    pub token: Token,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rfc8181Command {
    List,
    Add(AddRfc8181Client),
    RepoRes(Handle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRfc8181Client {
    pub xml: PathBuf,
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    UriError(uri::Error),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    ReportError(ReportError),

    #[display(fmt = "Invalid RFC8183 XML: {}", _0)]
    Rfc8183(rfc8183::Error),

    #[display(fmt = "Invalid resources requested: {}", _0)]
    ResSetErr(ResSetErr),

    #[display(fmt = "{}", _0)]
    InvalidRouteDelta(AuthorizationFmtError),

    #[display(fmt = "The publisher handle may only contain -_A-Za-z0-9, (\\ /) see issue #83")]
    InvalidHandle,

    #[display(
        fmt = "Missing argument: --{}, alternatively you may use env var: {}",
        _0,
        _1
    )]
    MissingArgWithEnv(String, String),

    #[display(fmt = "You must specify resources when adding a CA (--asn, --ipv4, --ipv6)")]
    MissingResources,

    #[display(fmt = "You must specify either --embedded or --rfc8183 when adding a child")]
    MissingChildAuth,

    #[display(fmt = "Invalid ID cert for child.")]
    InvalidChildIdCert,

    #[display(fmt = "Unrecognised sub-command. Use 'help'.")]
    UnrecognisedSubCommand,
}

impl Error {
    fn missing_arg_with_env(arg: &str, env_var: &str) -> Self {
        Error::MissingArgWithEnv(arg.to_string(), env_var.to_string())
    }
}

impl From<rfc8183::Error> for Error {
    fn from(e: rfc8183::Error) -> Self {
        Error::Rfc8183(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ReportError> for Error {
    fn from(e: ReportError) -> Self {
        Error::ReportError(e)
    }
}

impl From<ResSetErr> for Error {
    fn from(e: ResSetErr) -> Self {
        Error::ResSetErr(e)
    }
}

impl From<AuthorizationFmtError> for Error {
    fn from(e: AuthorizationFmtError) -> Self {
        Error::InvalidRouteDelta(e)
    }
}
