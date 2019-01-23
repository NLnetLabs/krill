//! Publication Client that uses the JSON/Rest API
use std::path::PathBuf;
use clap::{App, Arg, SubCommand};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, CONTENT_TYPE};
use reqwest::{Client, Response, StatusCode};
use rpki::uri;
use serde::Serialize;
use std::time::Duration;
use api::responses;

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

            match get_text(&uri, &options.token) {
                Err(e) => Err(e),
                Ok(None) => Err(Error::NoResponse),
                Ok(Some(text)) => {
                    let list: responses::ListReply =
                        serde_json::from_str(&text)?;

                    Ok(ApiResponse::List(list))
                }
            }
        },
        Command::Sync(_dir) => {
            unimplemented!()
        },
    }
}


fn client() -> Result<Client, Error> {
    Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::RequestError(e))
}


fn headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str("krill-pubc").unwrap()
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/json").unwrap()
    );
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
    );
    headers
}

fn process_response(mut res: Response) -> Result<Option<String>, Error> {
    match res.status() {
        StatusCode::OK => {
            Ok(res.text().ok())
        },
        status => {
            match res.text() {
                Ok(body) => {
                    if body.is_empty() {
                        Err(Error::BadStatus(status))
                    } else {
                        Err(Error::ErrorWithBody(body))
                    }
                },
                _ => Err(Error::BadStatus(status))
            }
        }
    }
}

fn get_text(
    uri: &str,
    token: &str
) -> Result<Option<String>, Error> {
    let headers = headers(token);
    let res = client()?.get(uri).headers(headers).send()?;
    process_response(res)
}

#[allow(dead_code)]
fn post_json(
    uri: &str,
    data: impl Serialize,
    token: &str
) -> Result<Option<String>, Error> {
    let headers = headers(token);
    let body = serde_json::to_string(&data)?;
    let client = client()?;

    let res = client.post(uri).headers(headers).body(body).send()?;
    process_response(res)
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

    #[display(fmt="Request Error: {}", _0)]
    RequestError(reqwest::Error),

    #[display(fmt="Received bad status: {}", _0)]
    BadStatus(StatusCode),

    #[display(fmt="{}", _0)]
    ErrorWithBody(String),

    #[display(fmt = "Expected a response body, but got nothing.")]
    NoResponse,

    #[display(fmt="Received invalid json response: {}", _0)]
    JsonError(serde_json::Error),

}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self { Error::UriError(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::RequestError(e)
    }
}
