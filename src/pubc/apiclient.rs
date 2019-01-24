//! Publication Client that uses the JSON/Rest API
use std::path::PathBuf;
use clap::{App, Arg, SubCommand};
use rpki::uri;
use crate::api::responses;
use crate::util::httpclient;

//------------ PubClientOptions ----------------------------------------------

pub struct PubClientOptions {
    // The base URI for the server. Will figure out the path from there.
    server_uri: uri::Http,

    // The handle by which this client is known to the server.
    handle: String,

    // The token for this particular client handle.
    token: String,

    // The intended action.
    cmd: Command
}

impl PubClientOptions {
    pub fn list(
        server_uri: &str,
        handle: &str,
        token: &str
    ) -> Result<Self, Error> {
        let server_uri = uri::Http::from_str(server_uri)?;

        Ok(PubClientOptions {
            server_uri,
            handle: handle.to_string(),
            token: token.to_string(),
            cmd: Command::List
        })
    }

    pub fn sync(
        server_uri: &str,
        handle: &str,
        token: &str,
        dir: &str
    ) -> Result<Self, Error> {
        let server_uri = uri::Http::from_str(server_uri)?;

        let dir = PathBuf::from(dir);
        if ! dir.is_dir() {
            return Err(Error::NoDir(dir.to_string_lossy().to_string()))
        }

        Ok(PubClientOptions {
            server_uri,
            handle: handle.to_string(),
            token: token.to_string(),
            cmd: Command::Sync(dir)
        })
    }
}


impl PubClientOptions {
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
            )
            .get_matches();

        let server_uri = m.value_of("server").unwrap();
        let handle     = m.value_of("handle").unwrap();
        let token      = m.value_of("token").unwrap();

        if let Some(_m) = m.subcommand_matches("list") {
            PubClientOptions::list(server_uri, handle, token)
        } else if let Some(m) = m.subcommand_matches("sync") {
            let dir = m.value_of("dir").unwrap();
            PubClientOptions::sync(server_uri, handle, token, dir)
        } else {
            Err(Error::NoCommand)
        }
    }
}


pub fn execute(options: PubClientOptions) -> Result<ApiResponse, Error> {
    match options.cmd {
        Command::List => {
            let uri = format!(
                "{}publication/{}",
                &options.server_uri.to_string(),
                &options.handle
            );

            match httpclient::get_json::<responses::ListReply>(
                &uri,
                Some(&options.token)
            ) {
                Err(e) => Err(Error::HttpClientError(e)),
                Ok(list) => Ok(ApiResponse::List(list))
            }
        },
        Command::Sync(_dir) => {
            unimplemented!()
        },
    }
}


//------------ Command -------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    List,
    Sync(PathBuf)
}


//------------ Output --------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Output {
    Json,
    Text,
    None
}


pub enum ApiResponse {
    Success,
    List(responses::ListReply)
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
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self { Error::UriError(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}
