//! Publication Client that uses the JSON/Rest API
use std::path::PathBuf;
use clap::{App, Arg, SubCommand};
use rpki::uri;
use crate::api::responses;
use crate::pubc;
use crate::util::httpclient;


//------------ Command -------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    List,
    Sync(PathBuf, uri::Rsync)
}


//------------ Connection ---------------------------------------------------

struct Connection {
    // The base URI for the server. Will figure out the path from there.
    server_uri: uri::Http,

    // The handle by which this client is known to the server.
    handle: String,

    // The token for this particular client handle.
    token: String,
}


//------------ Options ------------------------------------------------------

pub struct Options {
    connection: Connection,
    cmd: Command
}

impl Options {
    fn parts(self) -> (Connection, Command) {
        (self.connection, self.cmd)
    }
}

impl Options {
    pub fn list(
        server_uri: &str,
        handle: &str,
        token: &str
    ) -> Result<Self, Error> {
        let server_uri = uri::Http::from_str(server_uri)?;

        Ok(Options {
            connection: Connection {
                server_uri,
                handle: handle.to_string(),
                token: token.to_string()
            },
            cmd: Command::List
        })
    }

    pub fn sync(
        server_uri: &str,
        handle: &str,
        token: &str,
        dir: &str,
        rsync_uri: &str
    ) -> Result<Self, Error> {
        let server_uri = uri::Http::from_str(server_uri)?;

        let dir = PathBuf::from(dir);
        if ! dir.is_dir() {
            return Err(Error::NoDir(dir.to_string_lossy().to_string()))
        }

        let rsync_uri = uri::Rsync::from_str(rsync_uri)?;

        Ok(Options {
            connection: Connection {
                server_uri,
                handle: handle.to_string(),
                token: token.to_string()
            },
            cmd: Command::Sync(dir, rsync_uri)
        })
    }
}


impl Options {
    pub fn create() -> Result<Self, Error> {
        let m = App::new("NLnet Labs RRDP client (API)")
            .version("0.1b")
            .arg(Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("uri")
                .help("Base server uri.")
                .required(true)
            )
            .arg(Arg::with_name("handle")
                .short("h")
                .long("handle")
                .value_name("name")
                .help("Handle by which this client is known to the server.")
                .required(true)
            )
            .arg(Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("passphrase")
                .help("Token for this particular client handle at the server")
                .required(true)
            )
            .subcommand(SubCommand::with_name("list"))
            .subcommand(SubCommand::with_name("sync")
                .arg(Arg::with_name("dir")
                    .short("d")
                    .long("dir")
                    .value_name("directory")
                    .help("Directory to synchronise.")
                    .required(true)
                )
                .arg(Arg::with_name("rsync_base")
                    .short("r")
                    .long("rsync_base")
                    .value_name("uri")
                    .help("Base rsync URI (name space) for this dir.")
                    .required(true)
                )
            )
            .get_matches();

        let server_uri = m.value_of("server").unwrap();
        let handle     = m.value_of("handle").unwrap();
        let token      = m.value_of("token").unwrap();

        if let Some(_m) = m.subcommand_matches("list") {
            Options::list(server_uri, handle, token)
        } else if let Some(m) = m.subcommand_matches("sync") {
            let dir = m.value_of("dir").unwrap();
            let rsync_uri = m.value_of("rsync_uri").unwrap();
            Options::sync(server_uri, handle, token, dir, rsync_uri)
        } else {
            Err(Error::NoCommand)
        }
    }
}




//------------ Output --------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Output {
    Json,
    Text,
    None
}


//------------ ApiResponse ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiResponse {
    Success,
    List(responses::ListReply),
}


///--- functions

pub fn execute(options: Options) -> Result<ApiResponse, Error> {
    let (connection, cmd) = options.parts();

    match cmd {
        Command::List => {
            list_query(&connection).map(|l| ApiResponse::List(l))
        },
        Command::Sync(dir, rsync_uri) => {
            sync(&connection, &dir, &rsync_uri)
        }
    }
}


fn list_query(connection: &Connection) -> Result<responses::ListReply, Error> {
    let uri = format!(
        "{}publication/{}",
        &connection.server_uri.to_string(),
        &connection.handle
    );

    match httpclient::get_json::<responses::ListReply>(
        &uri,
        Some(&connection.token)
    ) {
        Err(e) => Err(Error::HttpClientError(e)),
        Ok(list) => Ok(list)
    }
}

fn sync(
    connection: &Connection,
    dir: &PathBuf,
    base_rsync: &uri::Rsync
) -> Result<ApiResponse, Error> {
    let list_reply = list_query(connection)?;
    let delta = pubc::create_delta(
        list_reply,
        dir,
        base_rsync
    )?;

    let uri = format!(
        "{}publication/{}",
        &connection.server_uri,
        &connection.handle
    );

    httpclient::post_json(&uri, delta, Some(&connection.token))?;

    Ok(ApiResponse::Success)
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    UriError(uri::Error),

    #[display(fmt = "{} is not a directory", _0)]
    NoDir(String),

    #[display(fmt = "Specify an action: list, or sync --dir <dir>")]
    NoCommand,

    #[display(fmt = "Expected a response body, but got nothing.")]
    NoResponse,

    #[display(fmt="{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt="Received invalid json response: {}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt="{}", _0)]
    PubcError(pubc::Error),
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self { Error::UriError(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}

impl From<pubc::Error> for Error {
    fn from(e: pubc::Error) -> Self { Error::PubcError(e) }
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self { Error::HttpClientError(e) }
}

// -- Tested in integration tests.