#[cfg(feature = "multi-user")]
use std::collections::HashMap;

use std::{
    convert::TryFrom,
    path::PathBuf,
    str::{from_utf8_unchecked, FromStr},
    {env, fmt},
};

use bytes::Bytes;
use clap::{App, Arg, ArgMatches, SubCommand};

use rpki::{
    ca::{
        csr::BgpsecCsr,
        idcert::IdCert,
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    },
    crypto::KeyIdentifier,
    repository::{
        aspa::{DuplicateProviderAs, ProviderAs},
        resources::{Asn, ResourceSet},
        x509::Time,
    },
    uri,
};

use crate::{
    cli::report::{ReportError, ReportFormat},
    commons::{
        api::{
            AddChildRequest, AspaCustomer, AspaDefinition, AspaDefinitionFormatError, AspaProvidersUpdate,
            AuthorizationFmtError, BgpSecAsnKey, BgpSecDefinition, CertAuthInit, ParentCaContact, ParentCaReq,
            PublicationServerUris, RepositoryContact, RoaConfiguration, RoaConfigurationUpdates, RoaPayload, RtaName,
            Token, UpdateChildRequest,
        },
        crypto::SignSupport,
        error::KrillIoError,
        util::file,
    },
    constants::*,
    daemon::ca::{ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest},
};

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

            if let Some(token_str) = matches.value_of(KRILL_CLI_ADMIN_TOKEN_ARG) {
                token = Some(Token::from(token_str));
            }

            token.ok_or_else(|| Error::missing_arg_with_env(KRILL_CLI_ADMIN_TOKEN_ARG, KRILL_CLI_TOKEN_ENV))?
        };

        let format = {
            let mut format = match env::var(KRILL_CLI_FORMAT_ENV) {
                Ok(fmt_str) => Some(ReportFormat::from_str(&fmt_str)?),
                Err(_) => None,
            };

            if let Some(fmt_str) = matches.value_of(KRILL_CLI_FORMAT_ARG) {
                format = Some(ReportFormat::from_str(fmt_str)?);
            }

            format.unwrap_or(ReportFormat::Text)
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

impl Default for GeneralArgs {
    fn default() -> Self {
        GeneralArgs {
            server: uri::Https::from_str(KRILL_CLI_SERVER_DFLT).unwrap(),
            token: Token::from(""),
            format: ReportFormat::Text,
            api: false,
        }
    }
}

/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action.
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
                .help("The full URI to the Krill server. Or set env: KRILL_CLI_SERVER")
                .required(false),
        )
        .arg(
            Arg::with_name(KRILL_CLI_ADMIN_TOKEN_ARG)
                .short("t")
                .long(KRILL_CLI_ADMIN_TOKEN_ARG)
                .value_name("string")
                .help("The secret token for the Krill server. Or set env: KRILL_CLI_TOKEN")
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
                .help("The name of the child CA you wish to control")
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
                .help("The local name by which the CA refers to this parent")
                .required(true),
        )
    }

    fn make_config_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut config_sub =
            SubCommand::with_name("config").about("Creates a configuration file for Krill and prints it to STDOUT");

        fn add_data_dir_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("data")
                    .long("data")
                    .short("d")
                    .value_name("path")
                    .help("Override the default path (./data/) for the data directory (must end with '/')")
                    .required(false),
            )
        }

        fn add_log_file_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("logfile")
                    .long("logfile")
                    .short("l")
                    .value_name("path")
                    .help("Override the default path (./krill.log) for the log file")
                    .required(false),
            )
        }

        #[cfg(feature = "multi-user")]
        fn add_id_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("id")
                    .long("id")
                    .value_name("id")
                    .help("Specify the id (e.g. username, email) to generate configuration for")
                    .required(true),
            )
        }

        #[cfg(feature = "multi-user")]
        fn add_attr_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("attr")
                    .short("a")
                    .long("attribute")
                    .value_name("attr")
                    .help("Specify key=value pair attributes to give the user")
                    .required(false)
                    .multiple(true),
            )
        }

        let mut simple = SubCommand::with_name("simple").about("Use a 3rd party repository for publishing");

        simple = Self::add_general_args(simple);
        simple = add_data_dir_arg(simple);
        simple = add_log_file_arg(simple);

        config_sub = config_sub.subcommand(simple);

        #[cfg(feature = "multi-user")]
        {
            let mut with_user =
                SubCommand::with_name("user").about("Generate a user authentication configuration file fragment");

            with_user = Self::add_general_args(with_user);
            with_user = add_id_arg(with_user);
            with_user = add_attr_arg(with_user);

            config_sub = config_sub.subcommand(with_user);
        }

        app.subcommand(config_sub)
    }

    fn make_cas_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let sub = SubCommand::with_name("list").about("List the current CAs");

        let sub = Self::add_general_args(sub);

        app.subcommand(sub)
    }

    fn make_cas_show_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show details of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_show_history_details_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("details").about("Show details for a command in the history of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("key")
                .long("key")
                .value_name("command key string")
                .help("The command key as shown in 'history commands'")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_show_history_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("commands").about("Show the commands sent to a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

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

    fn make_cas_show_history_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("history").about("Show the history of a CA");

        sub = Self::make_cas_show_history_list_sc(sub);
        sub = Self::make_cas_show_history_details_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_add_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a new CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_delete_ca_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("delete")
            .about("Delete a CA and let it withdraw its objects and request revocation. WARNING: Irreversible!");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a child to a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);
        sub = Self::add_resource_args(sub);
        let sub = sub.arg(
            Arg::with_name("request")
                .long("request")
                .short("r")
                .help("The location of the RFC 8183 Child Request XML file")
                .value_name("<XML file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_children_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update an existing child of a CA");

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
        let mut sub = SubCommand::with_name("response").about("Show the RFC 8183 Parent Response XML");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_info_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("info").about("Show info for a child (id and resources)");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove an existing child from a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_connections_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("connections").about("Show connections stats for children of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_suspend_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("suspend").about("Suspend a child CA: hide certificate(s) issued to child");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_unsuspend_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("unsuspend").about("Suspend a child CA: republish certificate(s) issued to child");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("children").about("Manage children for a CA");

        sub = Self::make_cas_children_add_sc(sub);
        sub = Self::make_cas_children_update_sc(sub);
        sub = Self::make_cas_children_info_sc(sub);
        sub = Self::make_cas_children_remove_sc(sub);
        sub = Self::make_cas_children_response_sc(sub);
        sub = Self::make_cas_children_connections_sc(sub);
        sub = Self::make_cas_children_suspend_sc(sub);
        sub = Self::make_cas_children_unsuspend_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request").about("Show RFC 8183 Child Request XML");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a parent to, or update a parent of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);
        sub = sub.arg(
            Arg::with_name("response")
                .long("response")
                .short("r")
                .help("The location of the RFC 8183 Parent Response XML file")
                .value_name("<XML file>")
                .required(true),
        );

        app.subcommand(sub)
    }

    fn make_cas_parents_statuses_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("statuses").about("Show overview of all parent statuses of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_contact_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("contact").about("Show contact information for a parent of a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove an existing parent from a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("parents").about("Manage parents for a CA");

        sub = Self::make_cas_parents_request_sc(sub);
        sub = Self::make_cas_parents_add_sc(sub);
        sub = Self::make_cas_parents_contact_sc(sub);
        sub = Self::make_cas_parents_statuses_sc(sub);
        sub = Self::make_cas_parents_remove_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init").about("Initialize roll for all keys held by a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_activate_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("activate").about("Finish roll for all keys held by a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_keyroll_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("keyroll").about("Perform a manual key rollover for a CA");

        sub = Self::make_cas_keyroll_init_sc(sub);
        sub = Self::make_cas_keyroll_activate_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("Show current authorizations");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update authorizations");

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
                .help("Try to perform the update, advice in case it would result in errors or invalids")
                .required(false),
        );

        app.subcommand(sub)
    }

    fn make_cas_routes_bgp_full_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("analyze").about("Show full report of ROAs vs known BGP announcements");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        app.subcommand(sub)
    }

    fn make_cas_routes_bgp_suggestions_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("suggest").about("Show ROA suggestions based on known BGP announcements");

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
            SubCommand::with_name("bgp").about("Show current authorizations in relation to known announcements");

        sub = Self::make_cas_routes_bgp_full_sc(sub);
        sub = Self::make_cas_routes_bgp_suggestions_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_routes_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("roas").about("Manage ROAs for a CA");

        sub = Self::make_cas_routes_list_sc(sub);
        sub = Self::make_cas_routes_update_sc(sub);
        sub = Self::make_cas_routes_bgp_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_bgpsec_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("Show current BGPSec configurations");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_bgpsec_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add BGPSec configurations");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub
            .arg(
                Arg::with_name("asn")
                    .short("a")
                    .long("asn")
                    .value_name("ASN")
                    .help("The ASN of the router for the key used in the CSR. E.g. AS65000")
                    .required(true),
            )
            .arg(
                Arg::with_name("csr")
                    .long("csr")
                    .value_name("CSR")
                    .help("The file containing the DER encoded Certificate Sign Request")
                    .required(true),
            );

        app.subcommand(sub)
    }

    fn make_cas_bgpsec_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove a BGPSec definition");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub
            .arg(
                Arg::with_name("asn")
                    .short("a")
                    .long("asn")
                    .value_name("ASN")
                    .help("The ASN used in the BGPSec definition. E.g. AS65000")
                    .required(true),
            )
            .arg(
                Arg::with_name("key")
                    .long("key")
                    .value_name("key")
                    .help("The hex encoded key identifier used in the BGPSec definition")
                    .required(true),
            );

        app.subcommand(sub)
    }

    fn make_cas_bgpsec_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("bgpsec").about("Manage BGPSec certificates");

        sub = Self::make_cas_bgpsec_list_sc(sub);
        sub = Self::make_cas_bgpsec_add_sc(sub);
        sub = Self::make_cas_bgpsec_remove_sc(sub);

        app.subcommand(sub)
    }

    #[cfg(feature = "aspa")]
    fn make_cas_aspas_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add or replace an ASPA configuration");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("aspa")
                .long("aspa")
                .help("ASPA formatted like: 65000 => 65001, 65002(v4), 65003(v6)")
                .value_name("definition")
                .required(true),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "aspa")]
    fn make_cas_aspas_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove the ASPA for a customer ASN");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("customer")
                .long("customer")
                .help("Customer ASN for an existing ASPA definition")
                .value_name("ASN")
                .required(true),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "aspa")]
    fn make_cas_aspas_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("update").about("Update an existing ASPA configuration");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("customer")
                .long("customer")
                .help("Customer ASN for an existing ASPA definition")
                .value_name("ASN")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("add")
                .long("add")
                .help("Provider ASNs to add (multiple allowed)")
                .value_name("<Provider AS>")
                .multiple(true)
                .required(false),
        );

        sub = sub.arg(
            Arg::with_name("remove")
                .long("remove")
                .help("Provider ASNs to remove (multiple allowed)")
                .value_name("<Provider AS>")
                .multiple(true)
                .required(false),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "aspa")]
    fn make_cas_aspas_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("Show current ASPA configurations");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    #[cfg(feature = "aspa")]
    fn make_cas_aspas_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("aspas").about("Manage ASPAs for a CA (experimental)");

        sub = Self::make_cas_aspas_add_sc(sub);
        sub = Self::make_cas_aspas_remove_sc(sub);
        sub = Self::make_cas_aspas_update_sc(sub);
        sub = Self::make_cas_aspas_list_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request").about("Show RFC 8183 Publisher Request XML");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_show_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show current repo config");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_status_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("status").about("Show current repo status");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_configure_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("configure").about("Configure which repository a CA uses");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
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

    fn make_cas_repo_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("repo").about("Manage the repository for a CA");

        sub = Self::make_cas_repo_request_sc(sub);
        sub = Self::make_cas_repo_show_sc(sub);
        sub = Self::make_cas_repo_status_sc(sub);
        sub = Self::make_cas_repo_configure_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_issues_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("issues").about("Show issues for a CA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_list<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("List RTAs");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_show<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show RTA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("name")
                .long("name")
                .short("n")
                .value_name("string")
                .help("Your local name for this RTA")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("out")
                .long("out")
                .short("o")
                .value_name("path")
                .help("File to write RTA to")
                .required(true),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_sign_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("sign").about("Create an RTA signed by a CA");

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
            Arg::with_name("name")
                .long("name")
                .short("n")
                .value_name("string")
                .help("Your local name for this RTA")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("keys")
                .long("keys")
                .short("k")
                .value_name("hex encoded key identifiers")
                .multiple(true)
                .help("Optional additional keys to include in this RTA")
                .required(false),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_multi_prep_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("prep").about("Prepare keys for multi-signed RTA");

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
            Arg::with_name("name")
                .long("name")
                .short("n")
                .value_name("string")
                .help("Your local name for this RTA")
                .required(true),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_multi_sign_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("cosign").about("Co-sign an existing (prepared) RTA");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        sub = sub.arg(
            Arg::with_name("name")
                .long("name")
                .short("n")
                .value_name("string")
                .help("Your local name for this RTA")
                .required(true),
        );

        sub = sub.arg(
            Arg::with_name("in")
                .long("in")
                .short("i")
                .value_name("path")
                .help("RTA which needs to be co-signed")
                .required(true),
        );

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_multi_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("multi").about("Manage RTA signed by multiple parties");

        sub = Self::make_cas_rta_multi_prep_sc(sub);
        sub = Self::make_cas_rta_multi_sign_sc(sub);

        app.subcommand(sub)
    }

    #[cfg(feature = "rta")]
    fn make_cas_rta_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("rta").about("Manage Resource Tagged Attestations");
        sub = Self::make_cas_rta_list(sub);
        sub = Self::make_cas_rta_show(sub);
        sub = Self::make_cas_rta_sign_sc(sub);
        sub = Self::make_cas_rta_multi_sc(sub);
        app.subcommand(sub)
    }

    fn make_bulk_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("bulk").about("Manually trigger refresh/republish/resync for all CAs");

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
        let health = SubCommand::with_name("health").about("Perform an authenticated health check");
        let health = Self::add_general_args(health);
        app.subcommand(health)
    }

    fn make_info_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let info = SubCommand::with_name("info").about("Show server info");
        let info = Self::add_general_args(info);
        app.subcommand(info)
    }

    fn make_publishers_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("List all publishers");
        sub = Options::add_general_args(sub);
        app.subcommand(sub)
    }

    fn make_publishers_stale_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("stale").about("List all publishers which have not published in a while");
        sub = Options::add_general_args(sub);
        sub = sub.arg(
            Arg::with_name("seconds")
                .value_name("seconds")
                .long("seconds")
                .help("The number of seconds since last publication")
                .required(true),
        );
        app.subcommand(sub)
    }

    fn add_publisher_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("publisher")
                .value_name("handle")
                .short("p")
                .long("publisher")
                .help("The handle (name) of the publisher")
                .required(true),
        )
    }

    fn add_rsync_base_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("rsync")
                .long("rsync")
                .value_name("uri")
                .help("Specify the base rsync URI for the repository, must end with '/'")
                .required(true),
        )
    }

    fn add_rrdp_base_uri_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("rrdp")
                .long("rrdp")
                .value_name("uri")
                .help(
                    "Specify the base https URI for the RRDP (excluding notification.xml), \
                    must \
                    end with '/'",
                )
                .required(true),
        )
    }

    fn make_publishers_add_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("add").about("Add a publisher");
        sub = Options::add_general_args(sub);

        sub = sub
            .arg(
                Arg::with_name("request")
                    .value_name("file")
                    .long("request")
                    .short("r")
                    .help("The location of the RFC 8183 Publisher Request XML file")
                    .required(true),
            )
            .arg(
                Arg::with_name("publisher")
                    .value_name("handle")
                    .short("p")
                    .long("publisher")
                    .help("Override the publisher handle in the XML")
                    .required(false),
            );

        app.subcommand(sub)
    }

    fn make_publishers_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("remove").about("Remove a publisher");
        sub = Options::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publishers_show_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("show").about("Show details for a publisher");
        sub = Options::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publishers_response_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("response").about("Show RFC 8183 Repository Response XML");
        sub = Options::add_general_args(sub);
        sub = Self::add_publisher_arg(sub);
        app.subcommand(sub)
    }

    fn make_publication_server_stats_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("stats").about("Show publication server stats");
        sub = Options::add_general_args(sub);
        app.subcommand(sub)
    }

    fn make_publication_server_init_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("init").about("Initialize publication server");
        sub = Options::add_general_args(sub);

        sub = Self::add_rsync_base_arg(sub);
        sub = Self::add_rrdp_base_uri_arg(sub);

        app.subcommand(sub)
    }

    fn make_publication_server_clear_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("clear").about("Clear the publication server so it can re-initialized");
        sub = Options::add_general_args(sub);
        app.subcommand(sub)
    }

    fn make_publication_server_session_reset_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("session-reset").about("Reset the RRDP session");
        sub = Options::add_general_args(sub);

        app.subcommand(sub)
    }

    fn make_publication_server_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("server").about("Manage the Publication Server (init/stats)");
        sub = Self::make_publication_server_stats_sc(sub);
        sub = Self::make_publication_server_init_sc(sub);
        sub = Self::make_publication_server_clear_sc(sub);
        sub = Self::make_publication_server_session_reset_sc(sub);
        app.subcommand(sub)
    }

    fn make_publishers_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("publishers").about("Manage the publishers in your Publication Server");

        sub = Self::make_publishers_list_sc(sub);
        sub = Self::make_publishers_stale_sc(sub);
        sub = Self::make_publishers_add_sc(sub);
        sub = Self::make_publishers_remove_sc(sub);
        sub = Self::make_publishers_show_sc(sub);
        sub = Self::make_publishers_response_sc(sub);

        app.subcommand(sub)
    }

    fn make_pubserver_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("pubserver")
            .about("Manage your Publication Server (only needed if you run your own)");

        sub = Self::make_publishers_sc(sub);
        sub = Self::make_publication_server_sc(sub);

        app.subcommand(sub)
    }

    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new(KRILL_CLIENT_APP).version(KRILL_VERSION);

        app = Self::make_config_sc(app);
        app = Self::make_cas_list_sc(app);
        app = Self::make_cas_show_ca_sc(app);
        app = Self::make_cas_show_history_sc(app);
        app = Self::make_cas_add_ca_sc(app);
        app = Self::make_cas_delete_ca_sc(app);
        app = Self::make_cas_children_sc(app);
        app = Self::make_cas_parents_sc(app);
        app = Self::make_cas_keyroll_sc(app);
        app = Self::make_cas_routes_sc(app);
        app = Self::make_cas_bgpsec_sc(app);
        app = Self::make_cas_repo_sc(app);
        app = Self::make_cas_issues_sc(app);
        app = Self::make_pubserver_sc(app);

        #[cfg(feature = "aspa")]
        {
            app = Self::make_cas_aspas_sc(app);
        }

        #[cfg(feature = "rta")]
        {
            app = Self::make_cas_rta_sc(app);
        }

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

    fn parse_my_ca(matches: &ArgMatches) -> Result<CaHandle, Error> {
        let my_ca = {
            let mut my_ca = None;

            if let Ok(my_ca_env) = env::var(KRILL_CLI_MY_CA_ENV) {
                my_ca = Some(CaHandle::from_str(&my_ca_env).map_err(|_| Error::InvalidHandle)?);
            }

            if let Some(my_ca_str) = matches.value_of(KRILL_CLI_MY_CA_ARG) {
                my_ca = Some(CaHandle::from_str(my_ca_str).map_err(|_| Error::InvalidHandle)?);
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
            let asn = asn.unwrap_or("");
            let v4 = v4.unwrap_or("");
            let v6 = v6.unwrap_or("");

            ResourceSet::from_strs(asn, v4, v6)
                .map(Some)
                .map_err(|e| Error::ResourceSetError(e.to_string()))
        } else {
            Ok(None)
        }
    }

    fn parse_matches_simple_config(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;

        #[cfg(not(feature = "multi-user"))]
        let mut details = KrillInitDetails::default();

        #[cfg(feature = "multi-user")]
        let mut details = KrillInitDetails::multi_user_dflt();

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

    #[cfg(feature = "multi-user")]
    fn parse_matches_user_config(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::default();
        let mut details = KrillUserDetails::default();
        if let Some(id) = matches.value_of("id") {
            details.with_id(id.to_string());
        }
        if let Some(attr_iter) = matches.values_of("attr") {
            for attr in attr_iter {
                let mut iter = attr.split('=');
                let k = iter
                    .next()
                    .ok_or_else(|| Error::general(&format!("attribute '{}' must be of the form key=value", attr)))?;
                let v = iter
                    .next()
                    .ok_or_else(|| Error::general(&format!("attribute '{}' must be of the form key=value", attr)))?;
                details.with_attr(k.to_string(), v.to_string());
            }
        }
        let command = Command::User(details);
        Ok(Options::make(general_args, command))
    }

    #[cfg(not(feature = "multi-user"))]
    fn parse_matches_user_config(_: &ArgMatches) -> Result<Options, Error> {
        Err(Error::UnrecognizedSubCommand)
    }

    fn parse_matches_config(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("simple") {
            Self::parse_matches_simple_config(m)
        } else if let Some(m) = matches.subcommand_matches("user") {
            Self::parse_matches_user_config(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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

    fn parse_matches_cas_delete(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::Delete(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_show(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::Show(my_ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_history_details(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let key = matches.value_of("key").unwrap();

        let command = Command::CertAuth(CaCommand::ShowHistoryDetails(my_ca, key.to_string()));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_history_commands(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let mut options = HistoryOptions::default();

        if let Some(offset) = matches.value_of("offset") {
            let offset = u64::from_str(offset).map_err(|e| Error::general(&format!("invalid number: {}", e)))?;
            options.offset = offset
        }

        if let Some(rows) = matches.value_of("rows") {
            let rows = u64::from_str(rows).map_err(|e| Error::general(&format!("invalid number: {}", e)))?;
            if rows > 250 {
                return Err(Error::general("No more than 250 rows allowed in history"));
            }
            options.rows = rows
        }

        if let Some(after) = matches.value_of("after") {
            let time = Time::from_str(after).map_err(|e| Error::general(&format!("invalid date format: {}", e)))?;
            options.after = Some(time);
        }

        if let Some(after) = matches.value_of("before") {
            let time = Time::from_str(after).map_err(|e| Error::general(&format!("invalid date format: {}", e)))?;
            options.before = Some(time);
        }

        let command = Command::CertAuth(CaCommand::ShowHistoryCommands(my_ca, options));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_history(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("commands") {
            Self::parse_matches_cas_history_commands(m)
        } else if let Some(m) = matches.subcommand_matches("details") {
            Self::parse_matches_cas_history_details(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_cas_children_add(matches: &ArgMatches) -> Result<Options, Error> {
        let path = matches.value_of("request").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let child_request = idexchange::ChildRequest::parse(bytes.as_ref())?;

        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let resources = Self::parse_resource_args(matches)?.ok_or(Error::MissingResources)?;

        let id_cert = child_request.validate()?;
        let add_child_request = AddChildRequest::new(child, resources, id_cert);
        let command = Command::CertAuth(CaCommand::ChildAdd(my_ca, add_child_request));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let id_cert = {
            if let Some(path) = matches.value_of("idcert") {
                let bytes = Self::read_file_arg(path)?;
                let id_cert = IdCert::decode(bytes.as_ref()).map_err(|_| Error::InvalidChildIdCert)?;
                Some(id_cert)
            } else {
                None
            }
        };
        let resources = Self::parse_resource_args(matches)?;

        let update = UpdateChildRequest::new(id_cert, resources, None);

        let command = Command::CertAuth(CaCommand::ChildUpdate(my_ca, child, update));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ChildInfo(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_response(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ParentResponse(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::ChildDelete(my_ca, child));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_connections(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ChildConnections(my_ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_suspend(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let update = UpdateChildRequest::suspend();

        let command = Command::CertAuth(CaCommand::ChildUpdate(my_ca, child, update));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_children_unsuspend(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let child = matches.value_of("child").unwrap();
        let child = ChildHandle::from_str(child).map_err(|_| Error::InvalidHandle)?;

        let update = UpdateChildRequest::unsuspend();

        let command = Command::CertAuth(CaCommand::ChildUpdate(my_ca, child, update));
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
        } else if let Some(m) = matches.subcommand_matches("connections") {
            Self::parse_matches_cas_children_connections(m)
        } else if let Some(m) = matches.subcommand_matches("suspend") {
            Self::parse_matches_cas_children_suspend(m)
        } else if let Some(m) = matches.subcommand_matches("unsuspend") {
            Self::parse_matches_cas_children_unsuspend(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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
        let response = idexchange::ParentResponse::parse(bytes.as_ref())?;

        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let parent = matches.value_of("parent").unwrap();
        let parent = ParentHandle::from_str(parent).map_err(|_| Error::InvalidHandle)?;
        let contact = ParentCaContact::for_rfc8183_parent_response(response)?;
        let parent_req = ParentCaReq::new(parent, contact);

        let command = Command::CertAuth(CaCommand::AddParent(my_ca, parent_req));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent = matches.value_of("parent").unwrap();
        let parent = ParentHandle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

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
        let parent = ParentHandle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::RemoveParent(my_ca, parent));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_cas_parents_request(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_parents_add(m)
        } else if let Some(m) = matches.subcommand_matches("contact") {
            Self::parse_matches_cas_parents_info(m)
        } else if let Some(m) = matches.subcommand_matches("statuses") {
            Self::parse_matches_cas_parents_statuses(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_cas_parents_remove(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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
            Err(Error::UnrecognizedSubCommand)
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
            RoaConfigurationUpdates::from_str(updates_str)?
        } else {
            let mut added = vec![];
            let mut removed = vec![];

            if let Some(add) = matches.values_of("add") {
                for roa_str in add {
                    let roa = RoaConfiguration::from_str(roa_str)?;
                    added.push(roa);
                }
            }

            if let Some(remove) = matches.values_of("remove") {
                for roa_str in remove {
                    let roa = RoaPayload::from_str(roa_str)?;
                    removed.push(roa);
                }
            }

            if added.is_empty() && removed.is_empty() {
                return Err(Error::general(
                    "You MUST specify either --delta, or --add and/or --remove",
                ));
            }

            RoaConfigurationUpdates::new(added, removed)
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
            Err(Error::UnrecognizedSubCommand)
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
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_cas_bgpsec_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::BgpSecList(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_bgpsec_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let asn_str = matches.value_of("asn").unwrap();
        let asn = Asn::from_str(asn_str).map_err(|_| Error::invalid_asn(asn_str))?;

        let csr_file = matches.value_of("csr").unwrap();
        let csr_file_path = PathBuf::from(csr_file);

        let bytes = file::read(&csr_file_path)
            .map_err(|e| Error::GeneralArgumentError(format!("Cannot read file '{}', error: {}", csr_file, e,)))?;
        let csr = BgpsecCsr::decode(bytes.as_ref())
            .map_err(|e| Error::GeneralArgumentError(format!("Cannot parse CSR file '{}', error: {}", csr_file, e)))?;

        csr.verify_signature().map_err(|e| {
            Error::GeneralArgumentError(format!("CSR in file '{}' is not valid. Error: {}", csr_file, e))
        })?;

        let definition = BgpSecDefinition::new(asn, csr);

        let command = Command::CertAuth(CaCommand::BgpSecAdd(my_ca, definition));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_bgpsec_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let asn_str = matches.value_of("asn").unwrap();
        let asn = Asn::from_str(asn_str).map_err(|_| Error::invalid_asn(asn_str))?;

        let key_str = matches.value_of("key").unwrap();
        let key = KeyIdentifier::from_str(key_str).map_err(|_| Error::general("Cannot parse key identifier"))?;

        let definition = BgpSecAsnKey::new(asn, key);

        let command = Command::CertAuth(CaCommand::BgpSecRemove(my_ca, definition));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_bgpsec(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_bgpsec_list(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_bgpsec_add(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_cas_bgpsec_remove(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_cas_aspas_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let aspa_config_str = matches.value_of("aspa").unwrap(); // required argument
        let aspa = AspaDefinition::from_str(aspa_config_str)?;

        let command = Command::CertAuth(CaCommand::AspasAddOrReplace(my_ca, aspa));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_aspas_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let customer_str = matches.value_of("customer").unwrap();
        let customer = AspaCustomer::from_str(customer_str).map_err(|_| Error::invalid_asn(customer_str))?;

        let command = Command::CertAuth(CaCommand::AspasRemove(my_ca, customer));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_aspas_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let mut added = vec![];
        let mut removed = vec![];

        let customer_str = matches.value_of("customer").unwrap();
        let customer = AspaCustomer::from_str(customer_str).map_err(|_| Error::invalid_asn(customer_str))?;

        if let Some(add) = matches.values_of("add") {
            for provider_str in add {
                let provider = ProviderAs::from_str(provider_str).map_err(|_| Error::invalid_asn(provider_str))?;
                added.push(provider);
            }
        }

        if let Some(remove) = matches.values_of("remove") {
            for provider_as_str in remove {
                let provider_as =
                    ProviderAs::from_str(provider_as_str).map_err(|_| Error::invalid_asn(provider_as_str))?;

                if added.iter().any(|added| added.provider() == provider_as.provider()) {
                    return Err(Error::general("Do not add and remove the same AS in a single update."));
                }

                removed.push(provider_as);
            }
        }

        let update = AspaProvidersUpdate::new(added, removed);
        if update.is_empty() {
            return Err(Error::general("You MUST specify at least one of --add or --remove"));
        }

        let command = Command::CertAuth(CaCommand::AspasUpdate(my_ca, customer, update));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_aspas_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::AspasList(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_aspas(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_aspas_add(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_cas_aspas_remove(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_aspas_update(m)
        } else if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_aspas_list(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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

    fn parse_matches_cas_repo_configure(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let path = matches.value_of("response").unwrap();
        let bytes = Self::read_file_arg(path)?;
        let response = idexchange::RepositoryResponse::parse(bytes.as_ref())?;

        let repo_contact = RepositoryContact::for_response(response).map_err(|e| {
            Error::GeneralArgumentError(format!(
                "Could not validate certificate in RFC 8183 Repository Response XML: {}",
                e
            ))
        })?;

        let command = Command::CertAuth(CaCommand::RepoUpdate(my_ca, repo_contact));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_repo(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_cas_repo_request(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_repo_details(m)
        } else if let Some(m) = matches.subcommand_matches("status") {
            Self::parse_matches_cas_repo_status(m)
        } else if let Some(m) = matches.subcommand_matches("configure") {
            Self::parse_matches_cas_repo_configure(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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

    fn parse_matches_cas_rta_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;
        let command = Command::CertAuth(CaCommand::RtaList(ca));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta_show(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;
        let name = matches.value_of("name").unwrap().to_string();

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

        let command = Command::CertAuth(CaCommand::RtaShow(ca, name, Some(out_file)));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta_sign(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;

        let days = matches.value_of("days").unwrap();
        let days =
            i64::from_str(days).map_err(|e| Error::GeneralArgumentError(format!("Invalid number of days: {}", e)))?;

        let in_file = matches.value_of("in").unwrap();
        let in_file = PathBuf::from_str(in_file)
            .map_err(|_| Error::GeneralArgumentError(format!("Invalid filename: {}", in_file)))?;

        let content = file::read(&in_file).map_err(|e| {
            Error::GeneralArgumentError(format!("Can't read file '{}', error: {}", in_file.to_string_lossy(), e,))
        })?;

        let name = matches.value_of("name").unwrap().to_string();

        let validity = SignSupport::sign_validity_days(days);

        let resources = Self::parse_resource_args(matches)?
            .ok_or_else(|| Error::general("You must specify at least one of --ipv4, --ipv6 or --asn"))?;

        let keys = if let Some(keys) = matches.values_of("keys") {
            let mut res = vec![];
            for key_str in keys {
                let ki = KeyIdentifier::from_str(key_str).map_err(|_| Error::general("Invalid key identifier"))?;
                res.push(ki)
            }
            res
        } else {
            vec![]
        };

        let request = RtaContentRequest::new(resources, validity, keys, content);
        let command = Command::CertAuth(CaCommand::RtaSign(ca, name, request));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta_multi_sign(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;
        let name = matches.value_of("name").unwrap().to_string();

        let in_file = matches.value_of("in").unwrap();
        let in_file = PathBuf::from_str(in_file)
            .map_err(|_| Error::GeneralArgumentError(format!("Invalid filename: {}", in_file)))?;

        let content = file::read(&in_file).map_err(|e| {
            Error::GeneralArgumentError(format!("Can't read file '{}', error: {}", in_file.to_string_lossy(), e,))
        })?;

        let rta = ResourceTaggedAttestation::new(content);

        let command = Command::CertAuth(CaCommand::RtaMultiCoSign(ca, name, rta));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta_multi_prep(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let ca = Self::parse_my_ca(matches)?;

        let name = matches.value_of("name").unwrap().to_string();
        let resources = Self::parse_resource_args(matches)?
            .ok_or_else(|| Error::general("You must specify at least one of --ipv4, --ipv6 or --asn"))?;

        let days = matches.value_of("days").unwrap();
        let days =
            i64::from_str(days).map_err(|e| Error::GeneralArgumentError(format!("Invalid number of days: {}", e)))?;
        let validity = SignSupport::sign_validity_days(days);

        let request = RtaPrepareRequest::new(resources, validity);

        let command = Command::CertAuth(CaCommand::RtaMultiPrep(ca, name, request));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_rta_multi(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("prep") {
            Self::parse_matches_cas_rta_multi_prep(m)
        } else if let Some(m) = matches.subcommand_matches("cosign") {
            Self::parse_matches_cas_rta_multi_sign(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_cas_rta(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_rta_list(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_rta_show(m)
        } else if let Some(m) = matches.subcommand_matches("sign") {
            Self::parse_matches_cas_rta_sign(m)
        } else if let Some(m) = matches.subcommand_matches("multi") {
            Self::parse_matches_cas_rta_multi(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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
            Err(Error::UnrecognizedSubCommand)
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

    fn parse_publisher_arg(matches: &ArgMatches) -> Result<PublisherHandle, Error> {
        let publisher_str = matches.value_of("publisher").unwrap();
        PublisherHandle::from_str(publisher_str).map_err(|_| Error::InvalidHandle)
    }

    fn parse_matches_publishers_list(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::PubServer(PubServerCommand::PublisherList);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_stale(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let seconds = i64::from_str(matches.value_of("seconds").unwrap()).map_err(|_| Error::InvalidSeconds)?;
        let command = Command::PubServer(PubServerCommand::StalePublishers(seconds));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;

        let path = matches.value_of("request").unwrap();
        let path = PathBuf::from(path);
        let bytes = file::read(&path)?;
        let mut req = idexchange::PublisherRequest::parse(bytes.as_ref())?;
        req.validate().map_err(|e| {
            Error::GeneralArgumentError(format!("Invalid certificate in RFC 8183 Publisher Request XML: {}", e))
        })?;

        if let Some(publisher_str) = matches.value_of("publisher") {
            let publisher_handle = PublisherHandle::from_str(publisher_str).map_err(|_| Error::InvalidHandle)?;
            let (id_cert, _handle, tag) = req.unpack();
            req = idexchange::PublisherRequest::new(id_cert, publisher_handle, tag);
        }

        let command = Command::PubServer(PubServerCommand::AddPublisher(req));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_remove(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::PubServer(PubServerCommand::RemovePublisher(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_show(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::PubServer(PubServerCommand::ShowPublisher(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publishers_repo_response(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let publisher = Self::parse_publisher_arg(matches)?;
        let command = Command::PubServer(PubServerCommand::RepositoryResponse(publisher));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publication_server_stats(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::PubServer(PubServerCommand::RepositoryStats);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publication_server_init(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;

        let rsync_str = matches.value_of("rsync").unwrap();
        let rrdp_str = matches.value_of("rrdp").unwrap();

        if !rsync_str.ends_with('/') {
            return Err(Error::general("rsync base URI must end with '/'"));
        }

        if !rrdp_str.ends_with('/') {
            return Err(Error::general("RRDP base URI must end with '/'"));
        }

        let rsync = uri::Rsync::from_str(rsync_str)
            .map_err(|e| Error::GeneralArgumentError(format!("Invalid rsync URI: {}", e)))?;

        let rrdp = uri::Https::from_str(rrdp_str)
            .map_err(|e| Error::GeneralArgumentError(format!("Invalid RRDP URI: {}", e)))?;

        let uris = PublicationServerUris::new(rrdp, rsync);

        let command = Command::PubServer(PubServerCommand::RepositoryInit(uris));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publication_server_clear(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::PubServer(PubServerCommand::RepositoryClear);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publication_server_server_reset(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let command = Command::PubServer(PubServerCommand::RepositorySessionReset);
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_publication_server(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("stats") {
            Self::parse_matches_publication_server_stats(m)
        } else if let Some(m) = matches.subcommand_matches("init") {
            Self::parse_matches_publication_server_init(m)
        } else if let Some(m) = matches.subcommand_matches("clear") {
            Self::parse_matches_publication_server_clear(m)
        } else if let Some(m) = matches.subcommand_matches("session-reset") {
            Self::parse_matches_publication_server_server_reset(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_publishers(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_publishers_list(m)
        } else if let Some(m) = matches.subcommand_matches("stale") {
            Self::parse_matches_publishers_stale(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_publishers_add(m)
        } else if let Some(m) = matches.subcommand_matches("remove") {
            Self::parse_matches_publishers_remove(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_publishers_show(m)
        } else if let Some(m) = matches.subcommand_matches("response") {
            Self::parse_matches_publishers_repo_response(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches_pubserver(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("publishers") {
            Self::parse_matches_publishers(m)
        } else if let Some(m) = matches.subcommand_matches("server") {
            Self::parse_matches_publication_server(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
        }
    }

    fn parse_matches(matches: ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("config") {
            Self::parse_matches_config(m)
        } else if let Some(m) = matches.subcommand_matches("list") {
            Self::parse_matches_cas_list(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_add(m)
        } else if let Some(m) = matches.subcommand_matches("delete") {
            Self::parse_matches_cas_delete(m)
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
        } else if let Some(m) = matches.subcommand_matches("bgpsec") {
            Self::parse_matches_cas_bgpsec(m)
        } else if let Some(m) = matches.subcommand_matches("aspas") {
            Self::parse_matches_cas_aspas(m)
        } else if let Some(m) = matches.subcommand_matches("repo") {
            Self::parse_matches_cas_repo(m)
        } else if let Some(m) = matches.subcommand_matches("issues") {
            Self::parse_matches_cas_issues(m)
        } else if let Some(m) = matches.subcommand_matches("rta") {
            Self::parse_matches_cas_rta(m)
        } else if let Some(m) = matches.subcommand_matches("bulk") {
            Self::parse_matches_bulk(m)
        } else if let Some(m) = matches.subcommand_matches("health") {
            Self::parse_matches_health(m)
        } else if let Some(m) = matches.subcommand_matches("info") {
            Self::parse_matches_info(m)
        } else if let Some(m) = matches.subcommand_matches("pubserver") {
            Self::parse_matches_pubserver(m)
        } else {
            Err(Error::UnrecognizedSubCommand)
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
    Info,
    Bulk(BulkCaCommand),
    CertAuth(CaCommand),
    PubServer(PubServerCommand),
    Init(KrillInitDetails),
    #[cfg(feature = "multi-user")]
    User(KrillUserDetails),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommand {
    Init(CertAuthInit), // Initialize a CA
    UpdateId(CaHandle), // Update CA id
    Delete(CaHandle),   // Delete the CA -> let it withdraw and request revocation as well

    // Publishing
    RepoPublisherRequest(CaHandle), // Get the RFC 8183 Publisher Request
    RepoDetails(CaHandle),
    RepoUpdate(CaHandle, RepositoryContact),
    RepoStatus(CaHandle),

    // Parents (to this CA)
    ChildRequest(CaHandle), // Get the RFC 8183 Child Request
    AddParent(CaHandle, ParentCaReq),
    MyParentCaContact(CaHandle, ParentHandle),
    ParentStatuses(CaHandle),
    RemoveParent(CaHandle, ParentHandle),
    Refresh(CaHandle), // Refresh with all parents

    // Children
    ParentResponse(CaHandle, ChildHandle), // Get an RFC 8183 Parent Response for a child
    ChildInfo(CaHandle, ChildHandle),
    ChildAdd(CaHandle, AddChildRequest),
    ChildUpdate(CaHandle, ChildHandle, UpdateChildRequest),
    ChildDelete(CaHandle, ChildHandle),
    ChildConnections(CaHandle),

    // Key Management
    KeyRollInit(CaHandle),
    KeyRollActivate(CaHandle),

    // Authorizations
    RouteAuthorizationsList(CaHandle),
    RouteAuthorizationsUpdate(CaHandle, RoaConfigurationUpdates),
    RouteAuthorizationsTryUpdate(CaHandle, RoaConfigurationUpdates),
    RouteAuthorizationsDryRunUpdate(CaHandle, RoaConfigurationUpdates),
    BgpAnalysisFull(CaHandle),
    BgpAnalysisSuggest(CaHandle, Option<ResourceSet>),

    // ASPAs
    AspasList(CaHandle),
    AspasAddOrReplace(CaHandle, AspaDefinition),
    AspasUpdate(CaHandle, AspaCustomer, AspaProvidersUpdate),
    AspasRemove(CaHandle, AspaCustomer),

    // BGPSec
    BgpSecList(CaHandle),
    BgpSecAdd(CaHandle, BgpSecDefinition),
    BgpSecRemove(CaHandle, BgpSecAsnKey),

    // Show details for this CA
    Show(CaHandle),
    ShowHistoryCommands(CaHandle, HistoryOptions),
    ShowHistoryDetails(CaHandle, String),
    Issues(Option<CaHandle>),

    // RTA
    RtaList(CaHandle),
    RtaShow(CaHandle, RtaName, Option<PathBuf>),
    RtaSign(CaHandle, RtaName, RtaContentRequest),
    RtaMultiPrep(CaHandle, RtaName, RtaPrepareRequest),
    RtaMultiCoSign(CaHandle, RtaName, ResourceTaggedAttestation),

    // List all CAs
    List,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryOptions {
    pub offset: u64,
    pub rows: u64,
    pub after: Option<Time>,
    pub before: Option<Time>,
}

impl Default for HistoryOptions {
    fn default() -> Self {
        HistoryOptions {
            offset: 0,
            rows: 100,
            after: None,
            before: None,
        }
    }
}

impl HistoryOptions {
    pub fn url_path_parameters(&self) -> String {
        if let Some(before) = self.before {
            let after = self.after.map(|t| t.timestamp()).unwrap_or_else(|| 0);
            format!("{}/{}/{}/{}", self.rows, self.offset, after, before.timestamp())
        } else if let Some(after) = self.after {
            format!("{}/{}/{}", self.rows, self.offset, after.timestamp())
        } else if self.offset != 0 {
            format!("{}/{}", self.rows, self.offset)
        } else if self.rows != 100 {
            format!("{}", self.rows)
        } else {
            "".to_string()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkCaCommand {
    Refresh,
    Publish,      // re-publish mft/crl before they would expire
    ForcePublish, // force republish all mft/crls
    Sync,
    Suspend,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KrillInitDetails {
    data_dir: Option<String>,
    log_file: Option<String>,
    multi_user: bool,
    hsm: bool,
}

impl KrillInitDetails {
    pub fn multi_user_dflt() -> Self {
        KrillInitDetails {
            data_dir: None,
            log_file: None,
            multi_user: true,
            hsm: false,
        }
    }

    pub fn with_data_dir(&mut self, data_dir: &str) {
        self.data_dir = Some(data_dir.to_string())
    }

    pub fn with_log_file(&mut self, log_file: &str) {
        self.log_file = Some(log_file.to_string())
    }

    pub fn data_dir(&self) -> Option<&String> {
        self.data_dir.as_ref()
    }

    pub fn log_file(&self) -> Option<&String> {
        self.log_file.as_ref()
    }

    pub fn multi_user(&self) -> bool {
        self.multi_user
    }

    pub fn hsm(&self) -> bool {
        self.hsm
    }
}

#[cfg(feature = "multi-user")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KrillUserDetails {
    id: String,
    attrs: HashMap<String, String>,
}

#[cfg(feature = "multi-user")]
impl KrillUserDetails {
    pub fn with_id(&mut self, id: String) {
        self.id = id;
    }
    pub fn with_attr(&mut self, attr: String, value: String) {
        self.attrs.insert(attr, value);
    }
    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn attrs(&self) -> HashMap<String, String> {
        self.attrs.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PubServerCommand {
    AddPublisher(idexchange::PublisherRequest),
    ShowPublisher(PublisherHandle),
    RemovePublisher(PublisherHandle),
    RepositoryResponse(PublisherHandle),
    StalePublishers(i64),
    PublisherList,
    RepositoryStats,
    RepositoryInit(PublicationServerUris),
    RepositoryClear,
    RepositorySessionReset,
}

//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    UriError(uri::Error),
    IoError(KrillIoError),
    ReportError(ReportError),
    Rfc8183(idexchange::Error),
    ResourceSetError(String),
    InvalidRouteDelta(AuthorizationFmtError),
    InvalidAsn(String),
    DuplicateAspaProvider(DuplicateProviderAs),
    InvalidAspaConfig(AspaDefinitionFormatError),
    InvalidHandle,
    InvalidSeconds,
    MissingArgWithEnv(String, String),
    MissingResources,
    InvalidChildIdCert,
    UnrecognizedSubCommand,
    GeneralArgumentError(String),
}

impl Error {
    fn invalid_asn(asn: &str) -> Self {
        Error::InvalidAsn(asn.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UriError(e) => e.fmt(f),
            Error::IoError(e) => e.fmt(f),
            Error::ReportError(e) => e.fmt(f),
            Error::Rfc8183(e) => write!(f, "Invalid RFC 8183 XML: {}", e),
            Error::ResourceSetError(e) => write!(f, "Invalid resources requested: {}", e),
            Error::InvalidRouteDelta(e) => e.fmt(f),
            Error::InvalidAsn(s) => write!(f, "Invalid ASN format. Expected 'AS#', got: {}", s),
            Error::DuplicateAspaProvider(e) => e.fmt(f),
            Error::InvalidAspaConfig(e) => e.fmt(f),
            Error::InvalidHandle => write!(
                f,
                "The publisher handle may only contain -_A-Za-z0-9, (\\ /) see issue #83"
            ),
            Error::InvalidSeconds => write!(f, "Use a number of 0 or more seconds"),
            Error::MissingArgWithEnv(arg, var) => write!(
                f,
                "Missing argument: --{}, alternatively you may use env var: {}",
                arg, var
            ),
            Error::MissingResources => write!(f, "You must specify resources when adding a CA (--asn, --ipv4, --ipv6)"),
            Error::InvalidChildIdCert => write!(f, "Invalid ID cert for child"),
            Error::UnrecognizedSubCommand => write!(f, "Unrecognized sub-command. Use 'help'"),
            Error::GeneralArgumentError(s) => s.fmt(f),
        }
    }
}

impl Error {
    fn missing_arg_with_env(arg: &str, env_var: &str) -> Self {
        Error::MissingArgWithEnv(arg.to_string(), env_var.to_string())
    }

    fn general(msg: &str) -> Self {
        Error::GeneralArgumentError(msg.to_string())
    }
}

impl From<idexchange::Error> for Error {
    fn from(e: idexchange::Error) -> Self {
        Error::Rfc8183(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<KrillIoError> for Error {
    fn from(e: KrillIoError) -> Self {
        Error::IoError(e)
    }
}

impl From<ReportError> for Error {
    fn from(e: ReportError) -> Self {
        Error::ReportError(e)
    }
}

impl From<AuthorizationFmtError> for Error {
    fn from(e: AuthorizationFmtError) -> Self {
        Error::InvalidRouteDelta(e)
    }
}

impl From<AspaDefinitionFormatError> for Error {
    fn from(e: AspaDefinitionFormatError) -> Self {
        Error::InvalidAspaConfig(e)
    }
}

impl From<DuplicateProviderAs> for Error {
    fn from(e: DuplicateProviderAs) -> Self {
        Error::DuplicateAspaProvider(e)
    }
}
