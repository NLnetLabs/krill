use std::convert::TryFrom;
use std::env;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::str::{from_utf8_unchecked, FromStr};

use clap::{App, Arg, ArgMatches, SubCommand};

use rpki::uri;

use crate::cli::report::{ReportError, ReportFormat};
use crate::commons::api::RepositoryUpdate;
use crate::commons::api::{
    AddChildRequest, AuthorizationFmtError, CertAuthInit, ChildAuthRequest, ChildHandle, Handle,
    ParentCaContact, ParentCaReq, ParentHandle, PublisherHandle, ResourceSet, ResourceSetError,
    RoaDefinitionUpdates, Token, UpdateChildRequest,
};
use crate::commons::remote::id::IdCert;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::constants::*;

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
                .help("Report format: none|json|text (default) |xml. Or set env: KRILL_CLI_FORMAT")
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

    fn add_parent_embedded_rfc6492_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        Self::add_parent_arg(app)
            .arg(
                Arg::with_name("embedded")
                    .long("embedded")
                    .help("Parent exists in this Krill instance.")
                    .required(false),
            )
            .arg(
                Arg::with_name("rfc8183")
                    .long("rfc8183")
                    .help("Parent is remote, uses an RFC8183 Parent Response XML file.")
                    .value_name("<XML file>")
                    .required(false),
            )
    }

    fn make_config_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut config_sub = SubCommand::with_name("config")
            .about("Creates a configuration file for krill and prints it to STDOUT.");

        fn add_data_dir_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("data")
                    .long("data")
                    .short("d")
                    .value_name("path")
                    .help("Override the default path (./data/) for the data directory (must end with slash).")
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
                    .help("Specify the base rsync URI for your repository. must end with '/'.")
                    .required(true),
            )
        }

        fn add_rrdp_service_uri_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
            app.arg(
                Arg::with_name("rrdp")
                    .long("rrdp")
                    .value_name("uri")
                    .help("Specify the base https URI for your RRDP (excluding notify.xml), must end with '/'")
                    .required(true),
            )
        }

        let mut with_repo =
            SubCommand::with_name("repo").about("Use a self-hosted repository (not recommended)");

        with_repo = Self::add_general_args(with_repo);
        with_repo = add_data_dir_arg(with_repo);
        with_repo = add_log_file_arg(with_repo);
        with_repo = add_rsync_base_arg(with_repo);
        with_repo = add_rrdp_service_uri_arg(with_repo);

        let mut with_3rd =
            SubCommand::with_name("simple").about("Use a 3rd party repository for publishing");

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

    fn make_cas_children_response_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("response").about("Get the RFC8183 response for a child.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_child_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_children_info_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("info").about("Show info for a child (id and resources).");

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

    fn make_cas_parents_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("update").about("Update an existing parent of this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_embedded_rfc6492_args(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_contact_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("contact")
            .about("Show contact information for a parent of this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_remove_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("remove").about("Remove an existing parent from this CA.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);
        sub = Self::add_parent_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_parents_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("parents").about("Manage parents for this CA.");

        sub = Self::make_cas_parents_myid_sc(sub);
        sub = Self::make_cas_parents_add_sc(sub);
        sub = Self::make_cas_parents_update_sc(sub);
        sub = Self::make_cas_parents_contact_sc(sub);
        sub = Self::make_cas_parents_remove_sc(sub);

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

    fn make_cas_repo_request_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("request").about("Show RFC8183 Publisher Request.");

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

    fn make_cas_repo_state_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("state").about("Show current repo state.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_cas_repo_update_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub =
            SubCommand::with_name("update").about("Change which repository this CA uses.");

        let mut embedded =
            SubCommand::with_name("embedded").about("Use the embedded server in krill");
        embedded = Self::add_general_args(embedded);
        embedded = Self::add_my_ca_arg(embedded);

        let mut remote = SubCommand::with_name("rfc8183").about("Use a remote server");
        remote = Self::add_general_args(remote);
        remote = Self::add_my_ca_arg(remote);
        remote = remote.arg(
            Arg::with_name("file")
                .help("File containing the RFC8183 XML. Defaults to reading from STDIN")
                .required(false),
        );

        sub = sub.subcommand(embedded);
        sub = sub.subcommand(remote);

        app.subcommand(sub)
    }

    fn make_cas_repo_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("repo").about("Manage the repository for your CA.");

        sub = Self::make_cas_repo_request_sc(sub);
        sub = Self::make_cas_repo_show_sc(sub);
        sub = Self::make_cas_repo_state_sc(sub);
        sub = Self::make_cas_repo_update_sc(sub);

        app.subcommand(sub)
    }

    fn make_cas_issues_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("issues").about("Show issues for CAs.");

        sub = Self::add_general_args(sub);
        sub = Self::add_my_ca_arg(sub);

        app.subcommand(sub)
    }

    fn make_publishers_list_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("list").about("List all publishers.");
        sub = Self::add_general_args(sub);
        app.subcommand(sub)
    }

    fn make_publishers_stale_sc<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut sub = SubCommand::with_name("stale")
            .about("List all publishers which have not published in a while.");
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

        sub = sub.arg(
            Arg::with_name("rfc8183")
                .value_name("file")
                .long("rfc8183")
                .help("RFC8183 Publisher Request XML file containing a certificate (tag is ignored)")
                .required(true)
        ).arg(
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
        let mut sub = SubCommand::with_name("response")
            .about("Show RFC8183 Repository Response for a publisher.");
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
        let mut sub = SubCommand::with_name("bulk")
            .about("Manually trigger refresh/republish/resync for all cas");

        let mut refresh = SubCommand::with_name("refresh")
            .about("Force that all CAs ask their parents for updated certificates");
        refresh = Self::add_general_args(refresh);

        let mut republish = SubCommand::with_name("publish").about(
            "Force that all CAs create new objects if needed (in which case they will also sync)",
        );
        republish = Self::add_general_args(republish);

        let mut resync =
            SubCommand::with_name("sync").about("Force that all CAs sync with their repo server");
        resync = Self::add_general_args(resync);

        sub = sub
            .subcommand(refresh)
            .subcommand(republish)
            .subcommand(resync);

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

    fn make_matches<'a>() -> ArgMatches<'a> {
        let mut app = App::new(KRILL_CLIENT_APP).version(KRILL_VERSION);

        app = Self::make_config_sc(app);
        app = Self::make_cas_list_sc(app);
        app = Self::make_cas_show_ca_sc(app);
        app = Self::make_cas_show_history_sc(app);
        app = Self::make_cas_add_ca_sc(app);
        app = Self::make_cas_children_sc(app);
        app = Self::make_cas_parents_sc(app);
        app = Self::make_cas_keyroll_sc(app);
        app = Self::make_cas_routes_sc(app);
        app = Self::make_cas_repo_sc(app);
        app = Self::make_cas_issues_sc(app);

        app = Self::make_publishers_sc(app);

        app = Self::make_health_sc(app);

        app = Self::make_info_sc(app);

        app = Self::make_bulk_sc(app);

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
        let rrdp_base = matches
            .value_of("rrdp")
            .map(uri::Https::from_str)
            .unwrap()?;
        let rsync_base = matches
            .value_of("rsync")
            .map(uri::Rsync::from_str)
            .unwrap()?;

        let mut details = KrillInitDetails::default();
        details.with_rsync_base(rsync_base);
        details.with_rrdp_service_uri(rrdp_base);

        if let Some(data) = matches.value_of("data") {
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
                let bytes = file::read(&PathBuf::from(path))?;
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

    fn parse_matches_cas_parents_myid(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::ChildRequest(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_add(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent_req = Self::parse_parent_ca_req(matches)?;

        let command = Command::CertAuth(CaCommand::AddParent(my_ca, parent_req));
        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_parents_update(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent_req = Self::parse_parent_ca_req(matches)?;
        let (parent, contact) = parent_req.unpack();

        let command = Command::CertAuth(CaCommand::UpdateParentContact(my_ca, parent, contact));
        Ok(Options::make(general_args, command))
    }

    fn parse_parent_ca_req(matches: &ArgMatches) -> Result<ParentCaReq, Error> {
        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        if matches.is_present("embedded") {
            Ok(ParentCaReq::new(parent, ParentCaContact::Embedded))
        } else if let Some(path) = matches.value_of("rfc8183") {
            let xml = PathBuf::from(path);
            let bytes = file::read(&xml)?;
            let res = rfc8183::ParentResponse::validate(bytes.as_ref())?;

            Ok(ParentCaReq::new(parent, ParentCaContact::for_rfc6492(res)))
        } else {
            Err(Error::MissingChildAuth)
        }
    }

    fn parse_matches_cas_parents_info(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;
        let parent = matches.value_of("parent").unwrap();
        let parent = Handle::from_str(parent).map_err(|_| Error::InvalidHandle)?;

        let command = Command::CertAuth(CaCommand::MyParentCaContact(my_ca, parent));
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
        if let Some(m) = matches.subcommand_matches("myid") {
            Self::parse_matches_cas_parents_myid(m)
        } else if let Some(m) = matches.subcommand_matches("add") {
            Self::parse_matches_cas_parents_add(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_parents_update(m)
        } else if let Some(m) = matches.subcommand_matches("contact") {
            Self::parse_matches_cas_parents_info(m)
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

        let updates = {
            let path = matches.value_of("delta").map(PathBuf::from).unwrap();
            let bytes = file::read(&path)?;
            let updates_str = unsafe { from_utf8_unchecked(&bytes) };
            RoaDefinitionUpdates::from_str(updates_str)?
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

    fn parse_matches_cas_repo_state(matches: &ArgMatches) -> Result<Options, Error> {
        let general_args = GeneralArgs::from_matches(matches)?;
        let my_ca = Self::parse_my_ca(matches)?;

        let command = Command::CertAuth(CaCommand::RepoState(my_ca));

        Ok(Options::make(general_args, command))
    }

    fn parse_matches_cas_update(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(matches) = matches.subcommand_matches("embedded") {
            let general_args = GeneralArgs::from_matches(matches)?;
            let my_ca = Self::parse_my_ca(matches)?;
            let update = RepositoryUpdate::embedded();
            let command = Command::CertAuth(CaCommand::RepoUpdate(my_ca, update));
            Ok(Options::make(general_args, command))
        } else if let Some(matches) = matches.subcommand_matches("rfc8183") {
            let general_args = GeneralArgs::from_matches(matches)?;
            let my_ca = Self::parse_my_ca(matches)?;

            let response = if let Some(path) = matches.value_of("file") {
                let path = PathBuf::from(path);
                let bytes = file::read(&path)?;

                rfc8183::RepositoryResponse::validate(bytes.as_ref())
            } else {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer)?;

                rfc8183::RepositoryResponse::validate(buffer.as_bytes())
            }?;

            let update = RepositoryUpdate::rfc8181(response);
            let command = Command::CertAuth(CaCommand::RepoUpdate(my_ca, update));
            Ok(Options::make(general_args, command))
        } else {
            Err(Error::UnrecognisedSubCommand)
        }
    }

    fn parse_matches_cas_repo(matches: &ArgMatches) -> Result<Options, Error> {
        if let Some(m) = matches.subcommand_matches("request") {
            Self::parse_matches_cas_repo_request(m)
        } else if let Some(m) = matches.subcommand_matches("show") {
            Self::parse_matches_cas_repo_details(m)
        } else if let Some(m) = matches.subcommand_matches("state") {
            Self::parse_matches_cas_repo_state(m)
        } else if let Some(m) = matches.subcommand_matches("update") {
            Self::parse_matches_cas_update(m)
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
        let seconds = i64::from_str(matches.value_of("seconds").unwrap())
            .map_err(|_| Error::InvalidSeconds)?;
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

        let path = matches.value_of("rfc8183").unwrap();
        let path = PathBuf::from(path);
        let bytes = file::read(&path)?;
        let mut req = rfc8183::PublisherRequest::validate(bytes.as_ref())?;

        if let Some(publisher_str) = matches.value_of("publisher") {
            let publisher =
                PublisherHandle::from_str(publisher_str).map_err(|_| Error::InvalidHandle)?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    NotSet,
    Health,
    Info,
    Bulk(BulkCaCommand),
    CertAuth(CaCommand),
    Publishers(PublishersCommand),
    Init(KrillInitDetails),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommand {
    // Initialise a CA
    Init(CertAuthInit),

    // Update CA id
    UpdateId(Handle),

    // Get an RFC8183 parent response for a child
    ParentResponse(Handle, ChildHandle),

    // Get the RFC8183 child request
    ChildRequest(Handle),

    // Get the RFC8183 publisher request
    RepoPublisherRequest(Handle),
    RepoDetails(Handle),
    RepoUpdate(Handle, RepositoryUpdate),
    RepoState(Handle),

    // Add a parent to this CA
    AddParent(Handle, ParentCaReq),
    // Show my parent's contact
    MyParentCaContact(Handle, ParentHandle),

    // Update parent contact
    UpdateParentContact(Handle, ParentHandle, ParentCaContact),

    // Remove a parent
    RemoveParent(Handle, ParentHandle),

    // Children
    ChildInfo(Handle, ChildHandle),
    ChildAdd(Handle, AddChildRequest),
    ChildUpdate(Handle, ChildHandle, UpdateChildRequest),
    ChildDelete(Handle, ChildHandle),

    // Initialise a manual key-roll now
    KeyRollInit(Handle),

    // Activate all new keys now (finish key roll, provided new key was certified)
    KeyRollActivate(Handle),

    // List the current RouteAuthorizations
    RouteAuthorizationsList(Handle),

    // Update the Route Authorizations for this CA
    RouteAuthorizationsUpdate(Handle, RoaDefinitionUpdates),

    // Show details for this CA
    Show(Handle),

    // Show the history for this CA
    ShowHistory(Handle),

    // Show issues for all, or a specific, CA
    Issues(Option<Handle>),

    // List all CAs
    List,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkCaCommand {
    Refresh,
    Publish,
    Sync,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PublishersCommand {
    AddPublisher(rfc8183::PublisherRequest),
    ShowPublisher(PublisherHandle),
    RemovePublisher(PublisherHandle),
    RepositoryResponse(PublisherHandle),
    StalePublishers(i64),
    Stats,
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
