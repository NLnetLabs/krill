use std::str::FromStr;
use clap::{App, Arg, SubCommand};
use rpki::uri;
use krill_commons::api::publishers::{
    ReportFormat,
    ReportError
};

/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action. Note that this is extracted
/// from the bin/krillc.rs, so that we can use this in integration testing
/// more easily.
pub struct Options {
    pub server: uri::Http,
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
        server: uri::Http,
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
                .subcommand(SubCommand::with_name("addcms")
                    .about("Add an RFC8181 publisher.")
                    .arg(Arg::with_name("xml")
                        .short("x")
                        .long("xml")
                        .value_name("FILE")
                        .help("Specify a file containing an RFC8183 \
                        publisher request. (See: https://tools.ietf.org/html/rfc8183#section-5.2.3)")
                        .required(true)
                    )
                    .arg(Arg::with_name("uri")
                        .short("u")
                        .long("uri")
                        .value_name("rsync uri")
                        .help("Rsync base uri for publisher. Must be covered by server, and not overlap with existing publishers.")
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
                .subcommand(SubCommand::with_name("response")
                    .about("Get the RFC8181 repository response xml")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                    .arg(Arg::with_name("out")
                        .short("o")
                        .long("out")
                        .value_name("FILE")
                        .help("Optional file to save to (default stdout).")
                        .required(false)
                    )
                )
                .subcommand(SubCommand::with_name("idcert")
                    .about("Get identity certificate known for publisher.")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                    .arg(Arg::with_name("out")
                        .short("o")
                        .long("out")
                        .value_name("FILE")
                        .help("File to save to.")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("remove")
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
            .get_matches();

        let mut command = Command::NotSet;

        if let Some(_m) = matches.subcommand_matches("health") {
            command = Command::Health;
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
            if let Some(m) = m.subcommand_matches("remove") {
                let handle = m.value_of("handle").unwrap().to_string();
                command = Command::Publishers(PublishersCommand::Deactivate(handle))
            }
        }

        let server = matches.value_of("server").unwrap(); // required
        let server = uri::Http::from_str(server)
            .map_err(|_| Error::UriError)?;

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
    Publishers(PublishersCommand)
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