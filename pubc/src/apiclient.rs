//! Publication Client that uses the JSON/Rest API
use std::path::PathBuf;
use std::str::FromStr;

use clap::{App, Arg, SubCommand};
use rpki::uri;

use krill_commons::api::{ListReply, Token};
use krill_commons::util::{file, httpclient};

use crate::{create_delta, ApiResponse, Format};

//------------ Command -------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    List,
    Sync(PathBuf, uri::Rsync),
}

impl Command {
    pub fn list() -> Self {
        Command::List
    }
    pub fn sync(dir: &str, base_uri: &str) -> Result<Self, Error> {
        let dir = PathBuf::from(dir);
        if !base_uri.ends_with('/') {
            Err(Error::InvalidBaseUri)
        } else {
            let uri = uri::Rsync::from_str(base_uri)?;
            Ok(Command::Sync(dir, uri))
        }
    }
}

//------------ Connection ---------------------------------------------------

pub struct Connection {
    // The base URI for the server. Will figure out the path from there.
    server_uri: uri::Https,

    // The handle by which this client is known to the server.
    handle: String,

    // The token for this particular client handle.
    token: Token,
}

impl Connection {
    pub fn build(server_uri: &str, handle: &str, token: &str) -> Result<Self, Error> {
        let server_uri = uri::Https::from_str(server_uri)?;
        let handle = handle.to_string();
        let token = Token::from(token);
        Ok(Connection {
            server_uri,
            handle,
            token,
        })
    }
}

//------------ Options ------------------------------------------------------

pub struct Options {
    connection: Connection,
    cmd: Command,
    format: Format,
}

impl Options {
    fn parts(self) -> (Connection, Command) {
        (self.connection, self.cmd)
    }
}

impl Options {
    pub fn new(connection: Connection, cmd: Command, format: Format) -> Self {
        Options {
            connection,
            cmd,
            format,
        }
    }

    pub fn format(&self) -> &Format {
        &self.format
    }
}

impl Options {
    pub fn create() -> Result<Self, Error> {
        let m = App::new("NLnet Labs RRDP client (API)")
            .version("0.1b")
            .arg(
                Arg::with_name("server")
                    .short("s")
                    .long("server")
                    .value_name("uri")
                    .help("Base server uri.")
                    .required(true),
            )
            .arg(
                Arg::with_name("handle")
                    .short("h")
                    .long("handle")
                    .value_name("name")
                    .help("Handle by which this client is known to the server.")
                    .required(true),
            )
            .arg(
                Arg::with_name("token")
                    .short("t")
                    .long("token")
                    .value_name("passphrase")
                    .help("Token for this particular client handle at the server")
                    .required(true),
            )
            .arg(
                Arg::with_name("format")
                    .short("f")
                    .long("format")
                    .value_name("text|json|none")
                    .help("Specify the output format. Defaults to 'text'.")
                    .required(false),
            )
            .subcommand(SubCommand::with_name("list"))
            .subcommand(
                SubCommand::with_name("sync")
                    .arg(
                        Arg::with_name("dir")
                            .short("d")
                            .long("dir")
                            .value_name("directory")
                            .help("Directory to synchronise.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("rsync_base")
                            .short("r")
                            .long("rsync_base")
                            .value_name("uri")
                            .help("Base rsync URI (name space) for this dir.")
                            .required(true),
                    ),
            )
            .get_matches();

        let connection = {
            let server_uri = m.value_of("server").unwrap();
            let handle = m.value_of("handle").unwrap();
            let token = m.value_of("token").unwrap();
            Connection::build(server_uri, handle, token)?
        };

        let command = {
            if let Some(_m) = m.subcommand_matches("list") {
                Command::list()
            } else if let Some(m) = m.subcommand_matches("sync") {
                let dir = m.value_of("dir").unwrap();
                let rsync_uri = m.value_of("rsync_base").unwrap();
                Command::sync(dir, rsync_uri)?
            } else {
                return Err(Error::NoCommand);
            }
        };

        let format = Format::from(m.value_of("format").unwrap_or("text"))
            .map_err(|_| Error::UnsupportedOutputFormat)?;

        Ok(Options::new(connection, command, format))
    }
}

///--- functions

pub fn execute(options: Options) -> Result<ApiResponse, Error> {
    let (connection, cmd) = options.parts();

    match cmd {
        Command::List => list_query(&connection).map(ApiResponse::List),
        Command::Sync(dir, rsync_uri) => sync(&connection, &dir, &rsync_uri),
    }
}

fn list_query(connection: &Connection) -> Result<ListReply, Error> {
    let uri = format!(
        "{}publication/{}",
        &connection.server_uri.to_string(),
        &connection.handle
    );

    match httpclient::get_json::<ListReply>(&uri, Some(&connection.token)) {
        Err(e) => Err(Error::HttpClientError(e)),
        Ok(list) => Ok(list),
    }
}

fn sync(
    connection: &Connection,
    dir: &PathBuf,
    base_rsync: &uri::Rsync,
) -> Result<ApiResponse, Error> {
    let list_reply = list_query(connection)?;
    let delta = create_delta(&list_reply, dir, base_rsync)?;

    let uri = format!(
        "{}publication/{}",
        &connection.server_uri, &connection.handle
    );

    httpclient::post_json(&uri, delta, Some(&connection.token))?;

    Ok(ApiResponse::Success)
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Uri error: {}", _0)]
    UriError(uri::Error),

    #[display(fmt = "{} is not a directory", _0)]
    NoDir(String),

    #[display(fmt = "Specify an action: list, or sync --dir <dir>")]
    NoCommand,

    #[display(fmt = "Expected a response body, but got nothing.")]
    NoResponse,

    #[display(fmt = "HTTP client error: {}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt = "Received invalid json response: {}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "{}", _0)]
    FileError(file::Error),

    #[display(fmt = "Unsupported output format. Use text, json or none.")]
    UnsupportedOutputFormat,

    #[display(fmt = "Base URI must end with '/'.")]
    InvalidBaseUri,
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

impl From<file::Error> for Error {
    fn from(e: file::Error) -> Self {
        Error::FileError(e)
    }
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self {
        Error::HttpClientError(e)
    }
}

// -- Tested in integration tests.
