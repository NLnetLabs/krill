use std::collections::HashSet;
use std::convert::TryFrom;
use std::io;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};
use std::{env, fmt};

use bytes::Bytes;
use clap::{App, Arg, ArgMatches, SubCommand};

use rpki::uri;
use rpki::x509::Time;

use crate::cli::report::{ReportError, ReportFormat};
use crate::commons::api::{
    AddChildRequest, AuthorizationFmtError, CertAuthInit, ChildAuthRequest, ChildHandle, Handle, ParentCaContact,
    ParentCaReq, ParentHandle, PublisherHandle, ResourceSet, ResourceSetError, RoaDefinitionUpdates, Token,
    UpdateChildRequest,
};
use crate::commons::api::{RepositoryUpdate, RoaDefinition};
use crate::commons::crypto::{IdCert, SignSupport};
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::constants::*;
use crate::daemon::ca::RtaRequest;

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

            server.unwrap_or_else(|| uri::Https::from_str(KRILL_CLI_SERVER_DFLT).unwrap())
        };

        let token = {
            let mut token = env::var(KRILL_CLI_TOKEN_ENV).ok().map(Token::from);

            if let Some(token_str) = matches.value_of(KRILL_CLI_TOKEN_ARG) {
                token = Some(Token::from(token_str));
            }

            token.ok_or_else(|| Error::missing_arg_with_env(KRILL_CLI_TOKEN_ARG, KRILL_CLI_TOKEN_ENV))?
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
            Arg::with_name(KRILL_CLI_SERVER_ARG)
                .short("s")
                .long(KRILL_CLI_SERVER_ARG)
                .value_name("URI")
                .help("The full URI to the krill server. Or set env: KRILL_CLI_SERVER")
                .required(false),
        )
        .arg(
            Arg::with_name(KRILL_CLI_TOKEN_ARG)
                .short("t")
                .long(KRILL_CLI_TOKEN_ARG)
                .value_name("string")
                .help("The secret token for the krill server. Or set env: KRILL_CLI_TOKEN")
                .required(false),
        )
        .arg(
            Arg::with_name(KRILL_CLI_FORMAT_ARG)
                .short("f")
                .long(KRILL_CLI_FORMAT_ARG)
                .value_name("type")
                .help("Report format: none|json|text (default). Or set env: KRILL_CLI_FORMAT")
                .required(false),
        )
        .arg(
            Arg::with_name(KRILL_CLI_API_ARG)
                .long(KRILL_CLI_API_ARG)
                .help("Only show the API call and exit. Or set env: KRILL_CLI_API=1")
                .required(false),
        )
    }

    fn add_my_ca_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name(KRILL_CLI_MY_CA_ARG)
                .value_name("name")
                .short("c")
                .long(KRILL_CLI_MY_CA_ARG)
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

    fn add_resource_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("asn")
                .short("a")
                .long("asn")
                .value_name("AS resources")
                .help("The AS resources: e.g. AS1, AS3-4")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv4")
                .short("4")
                .long("ipv4")
                .value_name("IPv4 resources")
                .help("The IPv4 resources: e.g. 192.168.0.0/16")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv6")
                .short("6")
                .long("ipv6")
                .value_name("IPv6 resources")
                .help("The IPv6 resources: e.g. 2001:db8::/32")
                .required(false),
        )
    }

    fn add_parent_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("parent")
                .long("parent")
                .short("p")
                .value_name("name")
                .help("The local name by which your ca refers to this parent.")
                .required(true),
        )
    }

    fn make_config_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut config_sub =
            SubCommand::with_name("config").about("Creates a configuration file for krill and prints it to STDOUT.");

        fn add_data_dir_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("data")
                    .long("data")
                    .short("d")
                    .value_name("path")
                    .help("Override the default path (./data/) for the data directory (must end with '/').")
                    .required(false),
            )
        }

        fn add_log_file_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("logfile")
                    .long("logfile")
                    .short("l")
                    .value_name("path")
                    .help("Override the default path (./krill.log) for the log file.")
                    .required(false),
            )
        }

        fn add_rsync_base_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("rsync")
                    .long("rsync")
                    .value_name("uri")
                    .help("Specify the base rsync URI for your repository, must end with '/'.")
                    .required(true),
            )
        }

        fn add_rrdp_service_uri_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("rrdp")
                    .long("rrdp")
                    .value_name("uri")
                    .help(
                        "Specify the base https URI for your RRDP (excluding notification.xml), \
                    must \
                    end with '/'",
                    )
                    .required(true),
            )
        }

        let mut with_repo = SubCommand::with_name("repo").about("Use a self-hosted repository (not recommended)");

        with_repo = Self::add_general_args(with_repo);
        with_repo = add_data_dir_arg(with_repo);
        with_repo = add_log_file_arg(with_repo);
        with_repo = add_rsync_base_arg(with_repo);
        with_repo = add_rrdp_service_uri_arg(with_repo);

        let mut with_3rd = SubCommand::with_name("simple").about("Use a 3rd party repository for publishing");

        with_3rd = Self::add_general_args(with_3rd);
        with_3rd = add_data_dir_arg(with_3rd);
        with_3rd = add_log_file_arg(with_3rd);

        config_sub = config_sub.subcommand(with_3rd);
        config_sub = config_sub.subcommand(with_repo);

        app.subcommand(config_sub)
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

        sub = sub.arg(
            Arg::with_name("full")
                .long("full")
                .help("Show history including publication.")
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("rows")
                .long("rows")
                .help("Number of rows (max 250)")
                .value_name("<number>")
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("offset")
                .long("offset")
                .help("Number of results to skip")
                .value_name("<number>")
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("after")
                .long("after")
                .help("Show commands issued after date/time in RFC 3339 format, e.g. 2020-04-09T19:37:02Z")
                .value_name("<RFC 3339 DateTime>")
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("before")
                .long("before")
                .help("Show commands issued after date/time in RFC 3339 format, e.g. 2020-04-09T19:37:02Z")
                .value_name("<RFC 3339 DateTime>")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_show_action_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("action").about("Show details for a specific CA action.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("key")
                .long("key")
                .value_name("action key string")
                .help("The action key (as shown in the history).")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_add_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a new CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a child to a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);
        sub = Self::add_resource_args(sub);
        let sub = sub.arg(
            Arg::with_name("request")
                .long("request")
                .short("r")
                .help("The location of the RFC8183 Child Request XML file.")
                .value_name("<XML file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_children_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update an existing child of a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);
        sub = Self::add_resource_args(sub);
        sub = sub.arg(
            Arg::with_name("idcert")
                .long("idcert")
                .help("The child's updated ID certificate")
                .value_name("DER encoded certificate")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_children_response_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("response").about("Show the RFC8183 Parent Response XML.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_info_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("info").about("Show info for a child (id and resources).");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove an existing child from a CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("children").about("Manage children for a CA in Krill.");

        sub = Self::make_cas_children_add_sc(sub);
        sub = Self::make_cas_children_update_sc(sub);
        sub = Self::make_cas_children_info_sc(sub);
        sub = Self::make_cas_children_remove_sc(sub);
        sub = Self::make_cas_children_response_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request").about("Show RFC8183 Child Request XML.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a parent to this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);
        sub = sub.arg(
            Arg::with_name("response")
                .long("response")
                .short("r")
                .help("The location of the RFC8183 Parent Response XML file.")
                .value_name("<XML file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_parents_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update an existing parent of this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);
        sub = sub.arg(
            Arg::with_name("response")
                .long("response")
                .short("r")
                .help("The location of the RFC8183 Parent Response XML file.")
                .value_name("<XML file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_parents_statuses_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("statuses").about("Show overview of all parent statuses of this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_contact_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("contact").about("Show contact information for a parent of this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove an existing parent from this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("parents").about("Manage parents for this CA.");

        sub = Self::make_cas_parents_request_sc(sub);
        sub = Self::make_cas_parents_add_sc(sub);
        sub = Self::make_cas_parents_update_sc(sub);
        sub = Self::make_cas_parents_contact_sc(sub);
        sub = Self::make_cas_parents_statuses_sc(sub);
        sub = Self::make_cas_parents_remove_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init").about("Initialise roll for all keys held by this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_activate_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("activate").about("Finish roll for all keys held by this CA.");

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
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("add")
                .long("add")
                .help("One or more ROAs to add, e.g.: 192.168.0.0/16 => 64496")
                .value_name("<roa definition>")
                .multiple(true)
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("remove")
                .long("remove")
                .help("One or more ROAs to remove, e.g.: 192.168.0.0/16 => 64496")
                .value_name("<roa definition>")
                .multiple(true)
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("dryrun")
                .long("dryrun")
                .help("Perform a dry run of the update and return the BGP analysis for the scoped to the update")
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("try")
                .long("try")
                .help("Try to perform the update, advice in case it would result in errors or invalids.")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_routes_bgp_full_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("analyze").about("Show full report of ROAs vs known BGP announcements.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        app.subcommand(sub)
    }

    fn make_cas_routes_bgp_suggestions_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("suggest").about("Show ROA suggestions based on known BGP announcements.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub
            .arg(
                Arg::with_name("ipv4")
                    .short("4")
                    .long("ipv4")
                    .value_name("IPv4 resources")
                    .help("Scope to these IPv4 resources")
                    .required(false),
            )
            .arg(
                Arg::with_name("ipv6")
                    .short("6")
                    .long("ipv6")
                    .value_name("IPv6 resources")
                    .help("Scope to these IPv6 resources")
                    .required(false),
            );

        app.subcommand(sub)
    }

    fn make_cas_routes_bgp_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("bgp").about("Show current authorizations in relation to known announcements.");

        sub = Self::make_cas_routes_bgp_full_sc(sub);
        sub = Self::make_cas_routes_bgp_suggestions_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("roas").about("Manage ROAs for your CA.");

        sub = Self::make_cas_routes_list_sc(sub);
        sub = Self::make_cas_routes_update_sc(sub);
        sub = Self::make_cas_routes_bgp_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request").about("Show RFC8183 Publisher Request XML.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_show_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show current repo config.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_status_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("status").about("Show current repo status.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Change which repository this CA uses.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = sub.arg(
            Arg::with_name("response")
                .value_name("file")
                .long("response")
                .short("r")
                .help("The location of the RFC8183 Publisher Response XML file. Defaults to reading from STDIN")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_repo_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("repo").about("Manage the repository for your CA.");

        sub = Self::make_cas_repo_request_sc(sub);
        sub = Self::make_cas_repo_show_sc(sub);
        sub = Self::make_cas_repo_status_sc(sub);
        sub = Self::make_cas_repo_update_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_issues_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("issues").about("Show issues for CAs.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_rta_oneoff_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("oneoff").about("Create one-off RTA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = Self::add_resource_args(sub);

        sub = sub.arg(
            Arg::with_name("days")
                .long("days")
                .short("d")
                .value_name("number of days")
                .help("Validity time of the RTA in days")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("in")
                .long("in")
                .short("i")
                .value_name("path")
                .help("Content which needs to be signed")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("out")
                .long("out")
                .short("o")
                .value_name("path")
                .help("Path where the RTA signature should be written to")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_rta_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("rta").about("Manage Resource Tagged Attestations");
        sub = Self::make_cas_rta_oneoff_sc(sub);
        app.subcommand(sub)
    }

    fn make_publishers_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("List all publishers.");
        sub = Self::add_general_args(sub);
        app.subcommand(sub)
    }

    fn make_publishers_stale_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("stale").about("List all publishers which have not published in a while.");
        sub = Self::add_general_args(sub);
        sub = sub.arg(
            Arg::with_name("seconds")
                .value_name("seconds")
                .long("seconds")
                .help("The number of seconds since last publication.")
                .required(true),
        );
        app.subcommand(sub)
    }

    fn make_publishers_stats_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("stats").about("Show publication server stats.");
        sub = Self::add_general_args(sub);
        app.subcommand(sub)
    }

    fn add_publisher_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("publisher")
                .value_name("handle")
                .short("p")
                .long("publisher")
                .help("The handle (name) of the publisher.")
                .required(true),
        )
    }

    fn make_publishers_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a publisher.");
        sub = Self::add_general_args(sub);

        sub = sub
            .arg(
                Arg::with_name("request")
                    .value_name("file")
                    .long("request")
                    .short("r")
                    .help("The location of the RFC8183 Publisher Request XML file.")
                    .required(true),
            )
            .arg(
                Arg::with_name("publisher")
                    .value_name("handle")
                    .short("p")
                    .long("publisher")
                    .help("Override the publisher handle in the XML.")
                    .required(false),
            );

        app.subcommand(sub)
    }

    fn make_publishers_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove a publisher.");
        sub = Self::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publishers_show_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show details for a publisher.");
        sub = Self::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publishers_response_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("response").about("Show RFC8183 Repository Response XML.");
        sub = Self::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publishers_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("publishers").about("Manage publishers in Krill.");

        sub = Self::make_publishers_list_sc(sub);
        sub = Self::make_publishers_stale_sc(sub);
        sub = Self::make_publishers_stats_sc(sub);
        sub = Self::make_publishers_add_sc(sub);
        sub = Self::make_publishers_remove_sc(sub);
        sub = Self::make_publishers_show_sc(sub);
        sub = Self::make_publishers_response_sc(sub);

        app.subcommand(sub)
    }

    fn make_bulk_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("bulk").about("Manually trigger refresh/republish/resync for all CAs.");

        let mut refresh =
            SubCommand::with_name("refresh").about("Force that all CAs ask their parents for updated certificates");
        refresh = Self::add_general_args(refresh);

        let mut republish = SubCommand::with_name("publish")
            .about("Force that all CAs create new objects if needed (in which case they will also sync)");
        republish = Self::add_general_args(republish);

        let mut resync = SubCommand::with_name("sync").about("Force that all CAs sync with their repo server");
        resync = Self::add_general_args(resync);

        sub = sub.subcommand(refresh).subcommand(republish).subcommand(resync);

        app.subcommand(sub)
    }

    fn make_health_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let health = SubCommand::with_name("health").about("Perform an authenticated health check.");
        let health = Self::add_general_args(health);
        app.subcommand(health)
    }

    fn make_info_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let info = SubCommand::with_name("info").about("Show server info");
        let info = Self::add_general_args(info);
        app.subcommand(info)
    }

    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new(KRILL_CLIENT_APP).version(KRILL_VERSION);

        app = Self::make_config_sc(app);
        app = Self::make_cas_list_sc(app);
        app = Self::make_cas_show_ca_sc(app);
        app = Self::make_cas_show_history_sc(app);
        app = Self::make_cas_show_action_sc(app);
        app = Self::make_cas_add_ca_sc(app);
        app = Self::make_cas_children_sc(app);
        app = Self::make_cas_parents_sc(app);
        app = Self::make_cas_keyroll_sc(app);
        app = Self::make_cas_routes_sc(app);
        app = Self::make_cas_repo_sc(app);
        app = Self::make_cas_issues_sc(app);
        app = Self::make_cas_rta_sc(app);

        app = Self::make_publishers_sc(app);

        app = Self::make_health_sc(app);

        app = Self::make_info_sc(app);

        app = Self::make_bulk_sc(app);

        app.get_matches()
    }

    //---------------------- Parsing

    fn read_file_arg(path: &str) -> Result<Bytes, Error> {
        let path = PathBuf::from(path);
        file::read(&path).map_err(Error::IoError)
    }

    fn parse_my_ca(matches: &ArgMatches) -> Result<Handle, Error> {
        let my_ca = {
            let mut my_ca = None;

            if let Ok(my_ca_env) = env::var(KRILL_CLI_MY_CA_ENV) {
                my_ca = Some(Handle::from_str(&my_ca_env).map_err(|_| Error::InvalidHandle)?);
            }

            if let Some(my_ca_str) = matches.value_of(KRILL_CLI_MY_CA_ARG) {
                my_ca = Some(Handle::from_str(my_ca_str).map_err(|_| Error::InvalidHandle)?);
            }

            my_ca.ok_or_else(|| Error::missing_arg_with_env(KRILL_CLI_MY_CA_ARG, KRILL_CLI_MY_CA_ENV))?
        };

        Ok(my_ca)
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

    fn parse_matches_repo_config(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let rrdp_base: uri::Https = matches.value_of("rrdp").map(uri::Https::from_str).unwrap()?;

        if !rrdp_base.as_str().ends_with('/') {
            return Err(Error::general("URI for --rrdp MUST end with a '/'"));
        }

        let rsync_base = matches.value_of("rsync").map(uri::Rsync::from_str).unwrap()?;

        if !rsync_base.to_string().ends_with('/') {
            return Err(Error::general("URI for --rsync MUST end with a '/'"));
        }

        let mut details = KrillInitDetails::default();
        details.with_rsync_base(rsync_base);
        details.with_rrdp_service_uri(rrdp_base);

        if let Some(data) = matches.value_of("data") {
            if !data.ends_with('/') {
                return Err(Error::general("Path for --data MUST end with a '/'"));
            }
            details.with_data_dir(data);
        }

        if let Some(log_file) = matches.value_of("logfile") {
            details.with_log_file(log_file);
        }

        let command = Command::Init(details);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_simple_config(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let mut details = KrillInitDetails::default();
        if let Some(data) = matches.value_of("data") {
            if !data.ends_with('/') {
                return Err(Error::general("Path for --data MUST end with a '/'"));
            }
            details.with_data_dir(data);
        }
        if let Some(log_file) = matches.value_of("logfile") {
            details.with_log_file(log_file);
        }

        let command = Command::Init(details);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_config(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("repo") {
            Self::parse_matches_repo_config(m)
        } else if let Some(m) = matches.subcommand_matches("simple") {
            Self::parse_matches_simple_config(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
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

        let init = CertAuthInit::new(my_ca);

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

        let mut options = HistoryOptions::default();
        if matches.is_present("full") {
            options.short = false;
        }

        if let Some(offset) = matches.value_of("offset") {
            let offset =
                u64::from_str(offset).map_err(|e| Error::general(&format!("invalid number: {}", e.to_string())))?;
            options.offset = offset
        }

        if let Some(rows) = matches.value_of("rows") {
            let rows =
                u64::from_str(rows).map_err(|e| Error::general(&format!("invalid number: {}", e.to_string())))?;
            if rows > 250 {
                return Err(Error::general("No more than 250 rows allowed in history"));
            }
            options.rows = rows
        }

        if let Some(after) = matches.value_of("after") {
            let time = Time::from_str(after)
                .map_err(|e| Error::general(&format!("invalid date format: {}", e.to_string())))?;
            options.after = Some(time);
        }

        if let Some(after) = matches.value_of("before") {
            let time = Time::from_str(after)
                .map_err(|e| Error::general(&format!("invalid date format: {}", e.to_string())))?;
            options.before = Some(time);
        }

        let command = Command::CertAuth(CaCommand::ShowHistory(my_ca, options));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_action(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let key = matches.value_of("key").unwrap();

        let command = Command::CertAuth(CaCommand::ShowAction(my_ca, key.to_string()));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_add(matches: &ArgMatches) -> Result<Options, Error> {
        let path = matches.value_of("request").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let request = rfc8183::ChildRequest::validate(bytes.as_ref())?;
        let auth_request = ChildAuthRequest::Rfc8183(request);

        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let resources = Self::parse_resource_args(matches)?.ok_or_else(|| Error::MissingResources)?;

        let child_request = AddChildRequest::new(child, resources, auth_request);
        let command = Command::CertAuth(CaCommand::ChildAdd(my_ca, child_request));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let id_cert = {
            if let Some(path) = matches.value_of("idcert") {
                let bytes = Self::read_file_arg(path)?;
                let id_cert = IdCert::decode(bytes).map_err(|_| Error::InvalidChildIdCert)?;
                Some(id_cert)
            } else {
                None
            }
        };
        let resources = Self::parse_resource_args(matches)?;

        let update = UpdateChildRequest::new(id_cert, resources);

        let command = Command::CertAuth(CaCommand::ChildUpdate(my_ca, child, update));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ChildInfo(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_response(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ParentResponse(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = Handle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ChildDelete(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_children_add(m)
        } else if let Some(m) = matches.subcommand_matches("response") {
            Self::parse_matches_cas_children_response(m)
        } else if let Some(m) = matches.subcommand_matches("info") {
            Self::parse_matches_cas_children_info(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_children_update(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_cas_children_remove(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_parents_request(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ChildRequest(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_add(matches: &ArgMatches) -> Result<Options, Error> {
        let path = matches.value_of("response").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let response = rfc8183::ParentResponse::validate(bytes.as_ref())?;

        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;
        let contact = ParentCaContact::for_rfc6492(response);
        let parent_req = ParentCaReq::new(parent, contact);

        let command = Command::CertAuth(CaCommand::AddParent(my_ca, parent_req));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let path = matches.value_of("response").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let response = rfc8183::ParentResponse::validate(bytes.as_ref())?;

        let contact = ParentCaContact::for_rfc6492(response);

        let command = Command::CertAuth(CaCommand::UpdateParentContact(my_ca, parent, contact));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::MyParentCaContact(my_ca, parent));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_statuses(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ParentStatuses(my_ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::RemoveParent(my_ca, parent));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_cas_parents_request(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_parents_add(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_parents_update(m)
        } else if let Some(m) = matches.subcommand_matches("contact") {
            Self::parse_matches_cas_parents_info(m)
        } else if let Some(m) = matches.subcommand_matches("statuses") {
            Self::parse_matches_cas_parents_statuses(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_cas_parents_remove(m)
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

        let updates = if let Some(path) = matches.value_of("delta") {
            if matches.is_present("add") || matches.is_present("remove") {
                return Err(Error::general("Cannot use --add or --remove if --delta is specified"));
            }

            let bytes = Self::read_file_arg(path)?;
            let updates_str = unsafe { from_utf8_unchecked(&bytes) };
            RoaDefinitionUpdates::from_str(updates_str)?
        } else {
            let mut added = HashSet::new();
            let mut removed = HashSet::new();

            if let Some(add) = matches.values_of("add") {
                for roa_str in add {
                    let roa: RoaDefinition = RoaDefinition::from_str(roa_str)?;
                    added.insert(roa);
                }
            }

            if let Some(remove) = matches.values_of("remove") {
                for roa_str in remove {
                    let roa: RoaDefinition = RoaDefinition::from_str(roa_str)?;
                    removed.insert(roa);
                }
            }

            if added.is_empty() && removed.is_empty() {
                return Err(Error::general(
                    "You MUST specify either --delta, or --add and/or --remove",
                ));
            }

            RoaDefinitionUpdates::new(added, removed)
        };

        if matches.is_present("dryrun") && matches.is_present("try") {
            return Err(Error::general("You cannot use both --dryrun and --try"));
        }

        let command = if matches.is_present("dryrun") {
            Command::CertAuth(CaCommand::RouteAuthorizationsDryRunUpdate(my_ca, updates))
        } else if matches.is_present("try") {
            Command::CertAuth(CaCommand::RouteAuthorizationsTryUpdate(my_ca, updates))
        } else {
            Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(my_ca, updates))
        };

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_routes_bgp_full(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        Ok(Options::make(
            general_args,
            Command::CertAuth(CaCommand::BgpAnalysisFull(my_ca)),
        ))
    }

    fn parse_matches_cas_routes_bgp_suggest(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let v4 = matches.value_of("ipv4").unwrap_or("");
        let v6 = matches.value_of("ipv6").unwrap_or("");

        let resources = ResourceSet::from_strs("", v4, v6)
            .map_err(|e| Error::GeneralArgumentError(format!("Could not parse IP resources: {}", e)))?;

        let resources = if resources.is_empty() { None } else { Some(resources) };

        Ok(Options::make(
            general_args,
            Command::CertAuth(CaCommand::BgpAnalysisSuggest(my_ca, resources)),
        ))
    }

    fn parse_matches_cas_routes_bgp(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("analyze") {
            Self::parse_matches_cas_routes_bgp_full(m)
        } else if let Some(m) = matches.subcommand_matches("suggest") {
            Self::parse_matches_cas_routes_bgp_suggest(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_routes(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_routes_list(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_routes_update(m)
        } else if let Some(m) = matches.subcommand_matches("bgp") {
            Self::parse_matches_cas_routes_bgp(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_repo_request(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::RepoPublisherRequest(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_repo_details(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::RepoDetails(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_repo_status(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::RepoStatus(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_repo_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let path = matches.value_of("response").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let response = rfc8183::RepositoryResponse::validate(bytes.as_ref())?;

        let update = RepositoryUpdate::rfc8181(response);
        let command = Command::CertAuth(CaCommand::RepoUpdate(my_ca, update));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_repo(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_cas_repo_request(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_repo_details(m)
        } else if let Some(m) = matches.subcommand_matches("status") {
            Self::parse_matches_cas_repo_status(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_repo_update(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_issues(matches: &ArgMatches) -> Result<Options, Error> {
        let general = GeneralArgs::from_matches(matches)?;
        let command = if let Ok(ca) = Self::parse_my_ca(matches) {
            Command::CertAuth(CaCommand::Issues(Some(ca)))
        } else {
            Command::CertAuth(CaCommand::Issues(None))
        };
        Ok(Options::make(general, command))
    }

    fn parse_matches_cas_rta_oneoff(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;

        let days = matches.value_of("days").unwrap();
        let days =
            i64::from_str(days).map_err(|e| Error::GeneralArgumentError(format!("Invalid number of days: {}", e)))?;

        let in_file = matches.value_of("in").unwrap();
        let in_file = PathBuf::from_str(in_file)
            .map_err(|_| Error::GeneralArgumentError(format!("Invalid filename: {}", in_file)))?;

        let content = file::read(&in_file).map_err(|e| {
            Error::GeneralArgumentError(format!(
                "Can't read file '{}', error: {}",
                in_file.to_string_lossy().to_string(),
                e,
            ))
        })?;

        let out_file = matches.value_of("out").unwrap();
        let out_file = PathBuf::from_str(out_file)
            .map_err(|_| Error::GeneralArgumentError(format!("Invalid filename: {}", out_file)))?;

        file::save(&[], &out_file).map_err(|e| {
            Error::GeneralArgumentError(format!(
                "Cannot save to file: {}, error: {}",
                out_file.to_string_lossy(),
                e
            ))
        })?;

        let validity = SignSupport::sign_validity_days(days);

        let resources = Self::parse_resource_args(matches)?
            .ok_or_else(|| Error::general("You must specify at least one of --ipv4, --ipv6 or --asn."))?;

        let request = RtaRequest::new(resources, validity, vec![], content);
        let command = Command::CertAuth(CaCommand::RtaOneOff(ca, request, Some(out_file)));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("oneoff") {
            Self::parse_matches_cas_rta_oneoff(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_publisher_arg(matches: &ArgMatches) -> Result<PublisherHandle, Error> {
        let publisher_str = matches.value_of("publisher").unwrap();
        PublisherHandle::from_str(publisher_str).map_err(|_| Error::InvalidHandle)
    }

    fn parse_matches_publishers_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::Publishers(PublishersCommand::PublisherList);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_stale(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let seconds = i64::from_str(matches.value_of("seconds").unwrap()).map_err(|_| Error::InvalidSeconds)?;
        let command = Command::Publishers(PublishersCommand::StalePublishers(seconds));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_stats(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::Publishers(PublishersCommand::Stats);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;

        let path = matches.value_of("request").unwrap();
        let path = PathBuf::from(path);
        let bytes = file::read(&path)?;
        let mut req = rfc8183::PublisherRequest::validate(bytes.as_ref())?;

        if let Some(publisher_str) = matches.value_of("publisher") {
            let publisher = PublisherHandle::from_str(publisher_str).map_err(|_| Error::InvalidHandle)?;
            let (tag, _, cert) = req.unpack();
            req = rfc8183::PublisherRequest::new(tag, publisher, cert);
        }

        let command = Command::Publishers(PublishersCommand::AddPublisher(req));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::Publishers(PublishersCommand::RemovePublisher(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_show(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::Publishers(PublishersCommand::ShowPublisher(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_repo_response(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::Publishers(PublishersCommand::RepositoryResponse(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_publishers_list(m)
        } else if let Some(m) = matches.subcommand_matches("stale") {
            Self::parse_matches_publishers_stale(m)
        } else if let Some(m) = matches.subcommand_matches("stats") {
            Self::parse_matches_publishers_stats(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_publishers_add(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_publishers_remove(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_publishers_show(m)
        } else if let Some(m) = matches.subcommand_matches("response") {
            Self::parse_matches_publishers_repo_response(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_bulk(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("publish") {
            let general_args = GeneralArgs::from_matches(m)?;
            let command = Command::Bulk(BulkCaCommand::Publish);
            Ok(Options::make(general_args, command))
        } else if let Some(m) = matches.subcommand_matches("refresh") {
            let general_args = GeneralArgs::from_matches(m)?;
            let command = Command::Bulk(BulkCaCommand::Refresh);
            Ok(Options::make(general_args, command))
        } else if let Some(m) = matches.subcommand_matches("sync") {
            let general_args = GeneralArgs::from_matches(m)?;
            let command = Command::Bulk(BulkCaCommand::Sync);
            Ok(Options::make(general_args, command))
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_health(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::Health;
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::Info;
        Ok(Options::make(general_args, command))
    }

    fn parse_matches(matches: ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("config") {
            Self::parse_matches_config(m)
        } else if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_list(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_add(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_show(m)
        } else if let Some(m) = matches.subcommand_matches("history") {
            Self::parse_matches_cas_history(m)
        } else if let Some(m) = matches.subcommand_matches("action") {
            Self::parse_matches_cas_action(m)
        } else if let Some(m) = matches.subcommand_matches("children") {
            Self::parse_matches_cas_children(m)
        } else if let Some(m) = matches.subcommand_matches("parents") {
            Self::parse_matches_cas_parents(m)
        } else if let Some(m) = matches.subcommand_matches("keyroll") {
            Self::parse_matches_cas_keyroll(m)
        } else if let Some(m) = matches.subcommand_matches("roas") {
            Self::parse_matches_cas_routes(m)
        } else if let Some(m) = matches.subcommand_matches("repo") {
            Self::parse_matches_cas_repo(m)
        } else if let Some(m) = matches.subcommand_matches("issues") {
            Self::parse_matches_cas_issues(m)
        } else if let Some(m) = matches.subcommand_matches("rta") {
            Self::parse_matches_cas_rta(m)
        } else if let Some(m) = matches.subcommand_matches("publishers") {
            Self::parse_matches_publishers(m)
        } else if let Some(m) = matches.subcommand_matches("bulk") {
            Self::parse_matches_bulk(m)
        } else if let Some(m) = matches.subcommand_matches("health") {
            Self::parse_matches_health(m)
        } else if let Some(m) = matches.subcommand_matches("info") {
            Self::parse_matches_info(m)
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    pub fn from_args() -> Result<Options, Error> {
        let matches = Self::make_matches();
        Self::parse_matches(matches)
    }
}

#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    #[display(fmt = "not set")]
    NotSet,

    #[display(fmt = "health")]
    Health,

    #[display(fmt = "info")]
    Info,

    #[display(fmt = "bulk: {}", _0)]
    Bulk(BulkCaCommand),

    #[display(fmt = "ca: {}", _0)]
    CertAuth(CaCommand),

    #[display(fmt = "publishers: {}", _0)]
    Publishers(PublishersCommand),

    #[display(fmt = "init")]
    Init(KrillInitDetails),
}

#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommand {
    // Initialise a CA
    #[display(fmt = "init ca: '{}'", _0)]
    Init(CertAuthInit),

    // Update CA id
    #[display(fmt = "update id for ca: '{}'", _0)]
    UpdateId(Handle),

    // Get an RFC8183 parent response for a child
    #[display(fmt = "parent response from ca: '{}' for child '{}'", _0, _1)]
    ParentResponse(Handle, ChildHandle),

    // Get the RFC8183 child request
    #[display(fmt = "get child request for ca: '{}'", _0)]
    ChildRequest(Handle),

    // Get the RFC8183 publisher request
    #[display(fmt = "get repo request for ca: '{}'", _0)]
    RepoPublisherRequest(Handle),

    #[display(fmt = "get repo details for ca: '{}'", _0)]
    RepoDetails(Handle),

    #[display(fmt = "update repo details for ca: '{}'", _0)]
    RepoUpdate(Handle, RepositoryUpdate),

    #[display(fmt = "get repo status for ca: '{}'", _0)]
    RepoStatus(Handle),

    #[display(fmt = "add parent '{}' to ca: '{}'", _0, _1)]
    AddParent(Handle, ParentCaReq),

    #[display(fmt = "add parent to ca: '{}'", _0)]
    MyParentCaContact(Handle, ParentHandle),

    #[display(fmt = "show parents status overview for ca: '{}'", _0)]
    ParentStatuses(Handle),

    #[display(fmt = "update contact for parent {} of ca: '{}' to: {}", _1, _0, _2)]
    UpdateParentContact(Handle, ParentHandle, ParentCaContact),

    #[display(fmt = "remove parent {} of ca: '{}'", _1, _0)]
    RemoveParent(Handle, ParentHandle),

    // Children
    #[display(fmt = "show child {} of ca: '{}'", _1, _0)]
    ChildInfo(Handle, ChildHandle),

    #[display(fmt = "add child {} to ca: '{}'", _1, _0)]
    ChildAdd(Handle, AddChildRequest),

    #[display(fmt = "update child {} of ca: '{}'", _1, _0)]
    ChildUpdate(Handle, ChildHandle, UpdateChildRequest),

    #[display(fmt = "delete child {} of ca: '{}'", _1, _0)]
    ChildDelete(Handle, ChildHandle),

    #[display(fmt = "initialise key roll for ca: '{}'", _0)]
    KeyRollInit(Handle),

    #[display(fmt = "activate key roll for ca: '{}'", _0)]
    KeyRollActivate(Handle),

    // Authorizations
    #[display(fmt = "list ROAS for ca: '{}'", _0)]
    RouteAuthorizationsList(Handle),

    #[display(fmt = "Update ROAS for ca: '{}' -> {}", _0, _1)]
    RouteAuthorizationsUpdate(Handle, RoaDefinitionUpdates),

    #[display(fmt = "Try to update ROAS for ca: '{}' -> {}", _0, _1)]
    RouteAuthorizationsTryUpdate(Handle, RoaDefinitionUpdates),

    #[display(fmt = "Perform a dry-run update of ROAS for ca: '{}' -> {}", _0, _1)]
    RouteAuthorizationsDryRunUpdate(Handle, RoaDefinitionUpdates),

    #[display(fmt = "Show detailed ROA vs BGP analysis for ca: '{}'", _0)]
    BgpAnalysisFull(Handle),

    #[display(fmt = "Show ROA suggestions based on BGP analysis for ca: '{}'", _0)]
    BgpAnalysisSuggest(Handle, Option<ResourceSet>),

    // Show details for this CA
    #[display(fmt = "Show details for ca: '{}'", _0)]
    Show(Handle),

    #[display(fmt = "Show history for ca: '{}', mode: {}", _0, _1)]
    ShowHistory(Handle, HistoryOptions),

    #[display(fmt = "Show action details for ca: '{}', action key: {}", _0, _1)]
    ShowAction(Handle, String),

    #[display(fmt = "Show issues for ca: '{:?}'", _0)]
    Issues(Option<Handle>),

    #[display(fmt = "One-off RTA request for CA: '{}'", _0)]
    RtaOneOff(Handle, RtaRequest, Option<PathBuf>),

    // List all CAs
    #[display(fmt = "List all cas")]
    List,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryOptions {
    pub short: bool,
    pub offset: u64,
    pub rows: u64,
    pub after: Option<Time>,
    pub before: Option<Time>,
}

impl Default for HistoryOptions {
    fn default() -> Self {
        HistoryOptions {
            short: true,
            offset: 0,
            rows: 100,
            after: None,
            before: None,
        }
    }
}

impl fmt::Display for HistoryOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = if self.short { "short" } else { "full" }.to_string();

        if let Some(before) = self.before {
            let after = self.after.map(|t| t.timestamp()).unwrap_or_else(|| 0);
            s.push_str(&format!(
                "/{}/{}/{}/{}",
                self.rows,
                self.offset,
                after,
                before.timestamp()
            ));
        } else if let Some(after) = self.after {
            s.push_str(&format!("/{}/{}/{}", self.rows, self.offset, after.timestamp()));
        } else if self.offset != 0 {
            s.push_str(&format!("/{}/{}", self.rows, self.offset));
        } else if self.rows != 100 {
            s.push_str(&format!("/{}", self.rows));
        }

        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum BulkCaCommand {
    #[display(fmt = "refresh")]
    Refresh,

    #[display(fmt = "publish")]
    Publish,

    #[display(fmt = "sync")]
    Sync,
}

#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PublishersCommand {
    #[display(fmt = "Add publisher")]
    AddPublisher(rfc8183::PublisherRequest),

    #[display(fmt = "Show publisher '{}", _0)]
    ShowPublisher(PublisherHandle),

    #[display(fmt = "Remove publisher '{}", _0)]
    RemovePublisher(PublisherHandle),

    #[display(fmt = "reposisitory response for publisher '{}'", _0)]
    RepositoryResponse(PublisherHandle),

    #[display(fmt = "Show publishers which last published longer than '{}' seconds ago", _0)]
    StalePublishers(i64),

    #[display(fmt = "Show server stats")]
    Stats,

    #[display(fmt = "Show publisher list")]
    PublisherList,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KrillInitDetails {
    rsync_base: Option<uri::Rsync>,
    rrdp_service_uri: Option<uri::Https>,
    data_dir: Option<String>,
    log_file: Option<String>,
}

impl KrillInitDetails {
    pub fn with_rsync_base(&mut self, rsync_base: uri::Rsync) {
        self.rsync_base = Some(rsync_base);
    }

    pub fn with_rrdp_service_uri(&mut self, rrdp_service_uri: uri::Https) {
        self.rrdp_service_uri = Some(rrdp_service_uri);
    }

    pub fn with_data_dir(&mut self, data_dir: &str) {
        self.data_dir = Some(data_dir.to_string())
    }

    pub fn with_log_file(&mut self, log_file: &str) {
        self.log_file = Some(log_file.to_string())
    }

    pub fn rsync_base(&self) -> Option<&uri::Rsync> {
        self.rsync_base.as_ref()
    }

    pub fn rrdp_service_uri(&self) -> Option<&uri::Https> {
        self.rrdp_service_uri.as_ref()
    }

    pub fn data_dir(&self) -> Option<&String> {
        self.data_dir.as_ref()
    }

    pub fn log_file(&self) -> Option<&String> {
        self.log_file.as_ref()
    }
}

impl Default for KrillInitDetails {
    fn default() -> Self {
        KrillInitDetails {
            rsync_base: None,
            rrdp_service_uri: None,
            data_dir: None,
            log_file: None,
        }
    }
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
    ResSetErr(ResourceSetError),

    #[display(fmt = "{}", _0)]
    InvalidRouteDelta(AuthorizationFmtError),

    #[display(fmt = "The publisher handle may only contain -_A-Za-z0-9, (\\ /) see issue #83")]
    InvalidHandle,

    #[display(fmt = "Use a number of 0 or more seconds.")]
    InvalidSeconds,

    #[display(fmt = "Missing argument: --{}, alternatively you may use env var: {}", _0, _1)]
    MissingArgWithEnv(String, String),

    #[display(fmt = "You must specify resources when adding a CA (--asn, --ipv4, --ipv6)")]
    MissingResources,

    #[display(fmt = "Invalid ID cert for child.")]
    InvalidChildIdCert,

    #[display(fmt = "Unrecognised sub-command. Use 'help'.")]
    UnrecognisedSubCommand,

    #[display(fmt = "{}", _0)]
    GeneralArgumentError(String),
}

impl Error {
    fn missing_arg_with_env(arg: &str, env_var: &str) -> Self {
        Error::MissingArgWithEnv(arg.to_string(), env_var.to_string())
    }

    fn general(msg: &str) -> Self {
        Error::GeneralArgumentError(msg.to_string())
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

impl From<ResourceSetError> for Error {
    fn from(e: ResourceSetError) -> Self {
        Error::ResSetErr(e)
    }
}

impl From<AuthorizationFmtError> for Error {
    fn from(e: AuthorizationFmtError) -> Self {
        Error::InvalidRouteDelta(e)
    }
}
