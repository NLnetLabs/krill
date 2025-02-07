//! Manage the publication server.

use std::{error, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use rpki::uri;
use rpki::ca::idexchange;
use crate::pubd;
use crate::cli::client::KrillClient;
use crate::cli::report::Report;
use crate::commons::api;
use crate::commons::util::httpclient;


//------------ PubserverCommand ----------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Manage the publishers of the publication server
    #[command(subcommand)]
    Publishers(Publishers),

    /// Delete specific files from the publication server
    Delete(DeleteFiles),

    /// Manage the publication server
    #[command(subcommand)]
    Server(ServerCommand),
}

impl Command {
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Publishers(cmd) => cmd.run(client),
            Self::Delete(cmd) => cmd.run(client).into(),
            Self::Server(cmd) => cmd.run(client),
        }
    }
}


//------------ Publishers ----------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Publishers {
    /// List all publishers
    List(List),

    /// List all publishers which have not published in a while
    Stale(Stale),

    /// Add a publisher
    Add(Add),

    /// Show RFC 8183 Repository Response XML
    Response(Response),

    /// Show details for a publisher
    Show(Show),

    /// Remove a publisher
    Remove(Remove),
}

impl Publishers {
    fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::List(cmd) => cmd.run(client).into(),
            Self::Stale(cmd) => cmd.run(client).into(),
            Self::Add(cmd) => cmd.run(client).into(),
            Self::Response(cmd) => cmd.run(client).into(),
            Self::Show(cmd) => cmd.run(client).into(),
            Self::Remove(cmd) => cmd.run(client).into(),
        }
    }
}


//------------ List ----------------------------------------------------------

#[derive(clap::Parser)]
pub struct List;

impl List {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::PublisherList, httpclient::Error> {
        client.publishers_list()
    }
}


//------------ Stale --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Stale {
    /// Number of seconds since last publication
    #[arg(long)]
    seconds: u64,
}

impl Stale {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::PublisherList, httpclient::Error> {
        client.publishers_stale(self.seconds)
    }
}


//------------ Add -----------------------------------------------------------

#[derive(clap::Parser)]
pub struct Add {
    /// Path to the RFC 8183 Publisher Request XML file
    #[arg(long, value_name = "path")]
    request: PublisherRequestFile,

    /// Override the publisher handle in the XML
    #[arg(long, short, value_name = "handle")]
    publisher: Option<idexchange::PublisherHandle>,
}

impl Add {
    fn run(
        mut self, client: &KrillClient
    ) -> Result<idexchange::RepositoryResponse, httpclient::Error> {
        if let Some(handle) = self.publisher {
            self.request.0.set_publisher_handle(handle)
        }
        client.publishers_add(self.request.0)
    }
}


//------------ PublisherHandle -----------------------------------------------

#[derive(clap::Args)]
pub struct PublisherHandle {
    /// Name of the publisher
    #[arg(long, short, value_name = "handle")]
    publisher: idexchange::PublisherHandle,
}


//------------ Response ------------------------------------------------------

#[derive(clap::Parser)]
pub struct Response {
    #[command(flatten)]
    handle: PublisherHandle,
}

impl Response {
    fn run(
        self, client: &KrillClient
    ) -> Result<idexchange::RepositoryResponse, httpclient::Error> {
        client.publisher_response(&self.handle.publisher)
    }
}


//------------ Show ------------------------------------------------------

#[derive(clap::Parser)]
pub struct Show {
    #[command(flatten)]
    handle: PublisherHandle,
}

impl Show {
    fn run(
        self, client: &KrillClient
    ) -> Result<api::PublisherDetails, httpclient::Error> {
        client.publisher_details(&self.handle.publisher)
    }
}


//------------ Remove ----------------------------------------------------

#[derive(clap::Parser)]
pub struct Remove {
    #[command(flatten)]
    handle: PublisherHandle,
}

impl Remove {
    fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.publisher_delete(&self.handle.publisher)
    }
}


//-------- pubserver::DeleteFiles ----------------------------------------

#[derive(clap::Parser)]
pub struct DeleteFiles {
    base_uri: uri::Rsync,
}

impl DeleteFiles {
    fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.pubserver_delete_files(self.base_uri)
    }
}


//------------ ServerCommand ------------------------------------------------

#[derive(clap::Subcommand)]
pub enum ServerCommand {
    /// Initialize the publication server
    Init(Init),

    /// Show publication server statistics
    Stats(Stats),

    /// Reset the RRDP session
    #[command(name = "session-reset")]
    SessionReset(SessionReset),

    /// Clear the publication server so it can re-initialized
    Clear(Clear),
}

impl ServerCommand {
    pub fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Init(cmd) => cmd.run(client).into(),
            Self::Stats(cmd) => cmd.run(client).into(),
            Self::SessionReset(cmd) => cmd.run(client).into(),
            Self::Clear(cmd) => cmd.run(client).into(),
        }
    }
}


//------------ Init ------------------------------------------------------

#[derive(clap::Parser)]
pub struct Init {
    /// The RRDP base URI for the repository (excluding notification.xml)
    #[arg(long, value_name = "https URI")]
    rrdp: uri::Https,

    /// The rsync base URI for the repository
    #[arg(long, value_name = "rsync URI")]
    rsync: uri::Rsync,
}

impl Init {
    pub fn run(
        mut self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        // Ensure URIs end in a slash.
        self.rrdp.path_into_dir();
        self.rsync.path_into_dir();

        client.pubserver_init(self.rrdp, self.rsync)
    }
}


//------------ Stats ---------------------------------------------------------

#[derive(clap::Parser)]
pub struct Stats;

impl Stats {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<pubd::RepoStats, httpclient::Error> {
        client.pubserver_stats()
    }
}


//------------ SessionReset --------------------------------------------------

#[derive(clap::Parser)]
pub struct SessionReset;

impl SessionReset {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.pubserver_session_reset()
    }
}


//------------ Clear ---------------------------------------------------------

#[derive(clap::Parser)]
pub struct Clear;

impl Clear {
    pub fn run(
        self, client: &KrillClient
    ) -> Result<api::Success, httpclient::Error> {
        client.pubserver_clear()
    }
}



//============ Argument Parser Types =========================================

//------------ PublisherRequestFile ------------------------------------------

#[derive(Clone, Debug)]
pub struct PublisherRequestFile(idexchange::PublisherRequest);

impl FromStr for PublisherRequestFile {
    type Err = PublisherRequestFileError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let req = idexchange::PublisherRequest::parse(
            BufReader::new(
                File::open(path).map_err(|err| {
                    PublisherRequestFileError::Io(path.into(), err)
                })?
            )
        ).map_err(|err| {
            PublisherRequestFileError::Parse(path.into(), err)
        })?;
        req.validate().map_err(|err| {
            PublisherRequestFileError::Parse(path.into(), err)
        })?;
        Ok(Self(req))
    }
}



//============ ErrorTypes ====================================================

//------------ PublisherResponseFileError ------------------------------------

#[derive(Debug)]
pub enum PublisherRequestFileError {
    Io(String, io::Error),
    Parse(String, idexchange::Error),
}

impl fmt::Display for PublisherRequestFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, err) => {
                write!(
                    f, "Failed to read publisher request file '{}': {}'",
                    path, err
                )
            }
            Self::Parse(path, err) => {
                write!(
                    f, "Failed to parse publisher request file '{}': {}'",
                    path, err
                )
            }
        }
    }
}

impl error::Error for PublisherRequestFileError { }

