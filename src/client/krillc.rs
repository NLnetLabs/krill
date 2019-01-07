use std::time::Duration;
use clap::{App, Arg, SubCommand};
use rpki::uri;
use reqwest::{Client, StatusCode};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

/// Command line tool for Krill admin tasks
pub struct KrillClient;

impl KrillClient {
    pub fn run(options: Options) -> Result<(), Error> {
        match options.mode {
            RunMode::Health => {
                Self::get(&options.server, &options.token, "api/v1/health")
            },
            RunMode::NotSet => {
                Err(Error::MissingSubcommand)
            }
        }
    }


    /// Performs a get request at the server, including the token for
    /// authorization. Note that the server uri ends with a '/', so leave
    /// out the '/' from the start of the rel_path.
    fn get(
        server: &uri::Http,
        token: &String,
        rel_path: &str
    ) -> Result<(), Error> {

        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str("krillc").unwrap()
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
        );

        let client = Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        let uri = format!("{}{}", server.to_string(), rel_path);
        let res = client.get(&uri).headers(headers).send()?;

        match res.status() {
            StatusCode::OK => {
                Ok(())
            },
            bad => {
                Err(Error::BadStatus(bad))
            }
        }

    }

}


/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action. Note that this is extracted
/// from the bin/krillc.rs, so that we can use this in integration testing
/// more easily.
pub struct Options {
    server: uri::Http,
    token: String,
    mode: RunMode
}

impl Options {
    pub fn new(server: uri::Http, token: &str, mode: RunMode) -> Self {
        Options { server, token: token.to_string(), mode }
    }

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

            .subcommand(SubCommand::with_name("health")
                .about("Perform a health check. Exits with exit code 0 if \
                all is well, exit code 1 in case of any issues")
            )

            .get_matches();

        let mut mode = RunMode::NotSet;

        if let Some(_m) = matches.subcommand_matches("health") {
            mode = RunMode::Health;
        }

        let server = matches.value_of("server").unwrap(); // required
        let server = uri::Http::from_str(server)
            .map_err(|_| Error::ServerUriError)?;

        let token = matches.value_of("token").unwrap().to_string(); // req.

        Ok(Options { server, token, mode })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunMode {
    NotSet,
    Health
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="No sub-command given, see --help")]
    MissingSubcommand,

    #[fail(display ="Server is not available.")]
    ServerDown,

    #[fail(display ="Cannot parse server URI.")]
    ServerUriError,

    #[fail(display="Request Error: {}", _0)]
    RequestError(reqwest::Error),

    #[fail(display="Received bad status: {}", _0)]
    BadStatus(StatusCode),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::RequestError(e)
    }
}