use std::path::PathBuf;
use std::str::FromStr;
use clap::{App, Arg, SubCommand};
use rpki::uri;
use crate::report::{
    ReportFormat,
    ReportError
};

/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action. Note that this is extracted
/// from the bin/krillc.rs, so that we can use this in integration testing
/// more easily.
pub struct Options {
    pub server: uri::Https,
    pub token: String,
    pub format: ReportFormat,
    pub command: Command
}

impl Options {
    pub fn format(&self) -> &ReportFormat {
        &self.format
    }

    /// Creates a new Options explicitly (useful for testing)
    pub fn new(
        server: uri::Https,
        token: &str,
        format: ReportFormat,
        command: Command
    ) -> Self {
        Options { server, token: token.to_string(), format, command }
    }

    /// Creates a new Options from command line args (useful for cli)
    pub fn from_args() -> Result<Options, Error> {
        let matches = App::new("Krill admin client")
            .version("0.2.0")
            .arg(Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("URI")
                .help("Specify the full URI to the krill server.")
                .required(true))
            .arg(Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("token-string")
                .help("Specify the value of an admin token.")
                .required(true))
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("type")
                .help(
                    "Specify the report format (none|json|text|xml). If \
                    left unspecified the format will match the \
                    corresponding server api response type.")
                .required(false)
            )
            .subcommand(SubCommand::with_name("health")
                .about("Perform a health check. Exits with exit code 0 if \
                all is well, exit code 1 in case of any issues")
            )

            .subcommand(SubCommand::with_name("trustanchor")
                .about("Manage embedded Trust Anchor (used for testing)")
                .subcommand(SubCommand::with_name("show")
                    .about("Show embedded TA details.")
                )
                .subcommand(SubCommand::with_name("init")
                    .about("Initialise embedded TA.")
                )
            )

            .subcommand(SubCommand::with_name("publishers")
                .about("Manage publishers")
                .subcommand(SubCommand::with_name("list")
                    .about("List all current publishers")
                )
                .subcommand(SubCommand::with_name("add")
                    .about("Add an API using publisher.")
                    .arg(Arg::with_name("token")
                        .short("t")
                        .long("token")
                        .value_name("text")
                        .help("Specify a token string.")
                        .required(true)
                    )
                    .arg(Arg::with_name("uri")
                        .short("u")
                        .long("uri")
                        .value_name("rsync uri")
                        .help("Rsync base uri for publisher. Must be covered by server, and not overlap with existing publishers.")
                        .required(true)
                    )
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("name")
                        .help("A unique name for this publisher. Must be a-Z0-9 without spaces.")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("details")
                    .about("Show details for a publisher.")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("deactivate")
                    .about("Removes a known publisher")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                )
            )
            .subcommand(SubCommand::with_name("rfc8181")
                .about("Manage RFC8181 clients")
                .subcommand(SubCommand::with_name("list")
                    .about("List all current clients with details")
                )
                .subcommand(SubCommand::with_name("add")
                    .about("Add TFC8181 client")
                    .arg(Arg::with_name("token")
                        .short("t")
                        .long("token")
                        .value_name("text")
                        .help("Specify a token string.")
                        .required(true)
                    )
                    .arg(Arg::with_name("xml")
                        .short("x")
                        .long("xml")
                        .value_name("FILE")
                        .help("Specify a file containing an RFC8183 \
                        publisher request. (See: https://tools.ietf.org/html/rfc8183#section-5.2.3)")
                        .required(true)
                    )
                )
            )
            .get_matches();

        let mut command = Command::NotSet;

        if let Some(_m) = matches.subcommand_matches("health") {
            command = Command::Health;
        }

        if let Some(m) = matches.subcommand_matches("trustanchor") {
            if let Some(_m) = m.subcommand_matches("show") {
                command = Command::TrustAnchor(TrustAnchorCommand::Show)
            }
            if let Some(_m) = m.subcommand_matches("init") {
                command = Command::TrustAnchor(TrustAnchorCommand::Init)
            }
        }

        if let Some(m) = matches.subcommand_matches("publishers") {
            if let Some(_m) = m.subcommand_matches("list") {
                command = Command::Publishers(PublishersCommand::List)
            }
            if let Some(m) = m.subcommand_matches("add") {
                let handle = m.value_of("handle").unwrap().to_string();
                let base_uri = uri::Rsync::from_str(m.value_of("uri").unwrap())?;
                let token = m.value_of("token").unwrap().to_string();

                let add = AddPublisher { handle, base_uri, token };
                command = Command::Publishers(
                    PublishersCommand::Add(add)
                );
            }
            if let Some(m) = m.subcommand_matches("details") {
                let handle = m.value_of("handle").unwrap();
                let details = PublishersCommand::Details(handle.to_string());
                command = Command::Publishers(details);
            }
            if let Some(m) = m.subcommand_matches("deactivate") {
                let handle = m.value_of("handle").unwrap().to_string();
                command = Command::Publishers(PublishersCommand::Deactivate(handle))
            }
        }

        if let Some(m) = matches.subcommand_matches("rfc8181") {
            if let Some(_m) = m.subcommand_matches("list") {
                command = Command::Rfc8181(Rfc8181Command::List)
            }
            if let Some(m) = m.subcommand_matches("add") {
                let token = m.value_of("token").unwrap().to_string();
                let xml_path = m.value_of("xml").unwrap();
                let xml = PathBuf::from(xml_path);

                command = Command::Rfc8181(Rfc8181Command::Add(AddRfc8181Client{ token, xml }))
            }

        }

        let server = matches.value_of("server").unwrap(); // required
        let server = uri::Https::from_str(server).map_err(|_| Error::UriError)?;

        let token = matches.value_of("token").unwrap().to_string(); // req.

        let mut format = ReportFormat::Default;
        if let Some(fmt) = matches.value_of("format") {
            format = ReportFormat::from_str(fmt)?;
        }

        Ok(Options { server, token, format, command })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    NotSet,
    Health,
    TrustAnchor(TrustAnchorCommand),
    Publishers(PublishersCommand),
    Rfc8181(Rfc8181Command)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorCommand {
    Show,
    Init
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishersCommand {
    Add(AddPublisher),
    Details(String),
    Deactivate(String),
    List
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddPublisher {
    pub handle: String,
    pub base_uri: uri::Rsync,
    pub token:  String
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rfc8181Command {
    List,
    Add(AddRfc8181Client),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRfc8181Client {
    pub token: String,
    pub xml: PathBuf
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="Cannot parse URI.")]
    UriError,

    #[display(fmt="{}", _0)]
    ReportError(ReportError),
}

impl From<uri::Error> for Error {
    fn from(_e: uri::Error) -> Self {
        Error::UriError
    }
}

impl From<ReportError> for Error {
    fn from(e: ReportError) -> Self {
        Error::ReportError(e)
    }
}