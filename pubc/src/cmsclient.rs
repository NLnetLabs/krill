use std::io;
use std::path::PathBuf;
use clap::{App, Arg, SubCommand};
use rpki::crypto::PublicKeyFormat;
use rpki::crypto::Signer;
use krill_commons::api::publication::ListReply;
use krill_commons::util::{softsigner, file};
use krill_commons::util::softsigner::OpenSslSigner;
use krill_cms_proxy::builder::IdCertBuilder;
use krill_cms_proxy::rfc8183;
use krill_cms_proxy::rfc8183::RepositoryResponse;
use krill_cms_proxy::id::{MyIdentity, ParentInfo, MyRepoInfo};
use krill_cms_proxy::proxy::{ClientProxy, ClientError};
use crate::{create_delta, ApiResponse, Format};

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum Command {
    Init(String),
    PublisherRequest(PathBuf),
    RepoResponse(PathBuf),
    List,
    Sync(PathBuf)
}

impl Command {
    pub fn init(name: &str) -> Command {
        Command::Init(name.to_string())
    }

    pub fn publisher_request(path: PathBuf) -> Command {
        Command::PublisherRequest(path)
    }

    pub fn repository_response(path: PathBuf) -> Command {
        Command::RepoResponse(path)
    }

    pub fn list() -> Command {
        Command::List
    }

    pub fn sync(dir: PathBuf) -> Command {
        Command::Sync(dir)
    }
}


pub struct PubClient {
    state_dir: PathBuf
}

impl PubClient {
    pub fn execute(options: Options) -> Result<ApiResponse, Error> {
        let mut client = Self::build(options.state_dir())?;

        match options.command {
            Command::PublisherRequest(path) => {
                let request = client.publisher_request()?;
                request.save(&path)?;
                Ok(ApiResponse::Success)
            },
            Command::RepoResponse(path) => {
                let xml = file::read(&path)?;
                let response = RepositoryResponse::decode(xml.as_ref())?;
                client.process_repo_response(&response)?;
                Ok(ApiResponse::Success)
            },
            Command::Init(name) => {
                client.init(&name)?;
                Ok(ApiResponse::Success)
            },
            Command::List => {
                let reply = client.list()?;
                Ok(ApiResponse::List(reply))
            },
            Command::Sync(dir) => {
                client.sync(&dir)?;
                Ok(ApiResponse::Success)
            }
        }
    }

    fn build(state_dir: &PathBuf) -> Result<Self, Error> {
        Ok(PubClient { state_dir: state_dir.clone() })
    }

    /// Initialises a new publication client, using a new key pair, and
    /// returns a publisher request that can be sent to the server.
    fn init(&mut self, name: &str) -> Result<(), Error> {
        let mut signer = OpenSslSigner::build(&self.state_dir)?;

        let key_id = signer.create_key(PublicKeyFormat::default())?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &signer)?;
        let my_id = MyIdentity::new(name, id_cert, key_id);

        file::save_json(&my_id, &self.path_my_id())?;
        Ok(())
    }

    /// Makes a publisher request, which can presented as an RFC8183 xml.
    fn publisher_request(
        &mut self
    ) -> Result<rfc8183::PublisherRequest, Error> {
        let id = self.my_identity()?;
        Ok(
            rfc8183::PublisherRequest::new(
                None,
                id.name(),
                id.id_cert().clone()
            )
        )
    }

    /// Process the publication server parent response.
    fn process_repo_response(
        &mut self,
        response: &rfc8183::RepositoryResponse
    ) -> Result<(), Error> {

        // Store parent info
        {
            let parent_info = ParentInfo::new(
                response.publisher_handle().clone(),
                response.id_cert().clone(),
                response.service_uri().clone()
            );

            file::save_json(&parent_info, &self.path_my_parent())?;
        }

        // Store repo info
        {
            let repo_info = MyRepoInfo::new(
                response.sia_base().clone(),
                response.rrdp_notification_uri().clone()
            );

            file::save_json(&repo_info, &self.path_my_repo())?;
        }

        Ok(())
    }

    /// Sends a list request
    fn list(&self) -> Result<ListReply, Error> {
        let proxy = self.client_proxy()?;
        proxy.list().map_err(Error::ClientError)
    }

    /// Synchronises
    fn sync(&self, dir: &PathBuf) -> Result<(), Error> {
        let proxy = self.client_proxy()?;
        let repo = self.my_repo()?;

        let list_reply = self.list()?;
        let delta = create_delta(
            &list_reply,
            dir,
            repo.sia_base()
        )?;

        proxy.delta(delta).map_err(Error::ClientError)
    }

    fn path_my_id(&self) -> PathBuf {
        let mut res = self.state_dir.clone();
        res.push("id.json");
        res
    }

    fn path_my_parent(&self) -> PathBuf {
        let mut res = self.state_dir.clone();
        res.push("parent.json");
        res
    }

    fn path_my_repo(&self) -> PathBuf {
        let mut res = self.state_dir.clone();
        res.push("repo.json");
        res
    }

    fn my_identity(&self) -> Result<MyIdentity, Error> {
        file::load_json(&self.path_my_id()).map_err(|_| Error::Uninitialised)
    }

    fn my_parent(&self) -> Result<ParentInfo, Error> {
        file::load_json(&self.path_my_parent()).map_err(|_| Error::Uninitialised)
    }

    fn my_repo(&self) -> Result<MyRepoInfo, Error> {
        file::load_json(&self.path_my_repo()).map_err(|_| Error::Uninitialised)
    }

    fn client_proxy(&self) -> Result<ClientProxy, Error> {
        let id = self.my_identity()?;
        let parent = self.my_parent()?;

        Ok(ClientProxy::new(id, parent, self.state_dir.clone()))
    }
}


//------------ Options --------------------------------------------------------

#[derive(Debug)]
pub struct Options {
    state_dir: PathBuf,
    command: Command,
    format: Format
}

/// # Accessors
impl Options {
    pub fn new(state_dir: PathBuf, command: Command, format: Format) -> Self {
        Options { state_dir, command, format }
    }
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn format(&self) -> &Format { &self.format }
}

/// # Create
impl Options {
    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, OptionsError> {
        let m = App::new("NLnet Labs RRDP Client (RFC8181)")
            .version("0.1b")

            .arg(Arg::with_name("state")
                .short("s")
                .long("state")
                .value_name("FILE")
                .help("Specify the directory where this publication client \
                       maintains its state.")
                .required(true))

            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("text|json|none")
                .help("Specify the output format. Defaults to 'none'.")
                .required(false)
            )

            .subcommand(SubCommand::with_name("init")
                .about("(Re-)Initialise the identity certificate and key \
                        pair.")
                .arg(Arg::with_name("name")
                    .short("n")
                    .long("name")
                    .value_name("NAME")
                    .help("Specify the name for this publication client.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("request")
                .about("Generate the publisher request XML")
                .arg(Arg::with_name("xml")
                    .short("x")
                    .long("xml")
                    .value_name("FILE")
                    .help("The name of the file to write the request to.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("response")
                .about("Process the repository response XML")
                .arg(Arg::with_name("xml")
                    .short("x")
                    .long("xml")
                    .value_name("FILE")
                    .help("The name of the file containing the response.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("list"))

            .subcommand(SubCommand::with_name("sync")
                .about("Synchronise the directory specified by '-d'.")
                .arg(Arg::with_name("dir")
                    .short("d")
                    .long("dir")
                    .value_name("FILE")
                    .help("The directory that should be synced to the
                           server. Note that entries here will be relative to
                           the base rsync directory specified in the
                           repository response.")
                    .required(true))
            )

            .get_matches();

        let state_dir = {
            let state = m.value_of("state").unwrap(); // safe (required)
            PathBuf::from(state)
        };

        let command = {
            if let Some(m) = m.subcommand_matches("init") {
                let name = m.value_of("name").unwrap();
                Command::Init(name.to_string())
            } else if let Some(m) = m.subcommand_matches("request") {
                let xml = m.value_of("xml").unwrap();
                let xml = PathBuf::from(xml);
                Command::PublisherRequest(xml)
            } else if let Some(m) = m.subcommand_matches("response") {
                let xml = m.value_of("xml").unwrap();
                let xml = PathBuf::from(xml);
                Command::RepoResponse(xml)
            } else if let Some(_m) = m.subcommand_matches("list") {
                Command::List
            } else if let Some(m) = m.subcommand_matches("sync") {
                let dir = m.value_of("dir").unwrap();
                let dir = PathBuf::from(dir);
                Command::Sync(dir)
            } else {
                return Err(OptionsError::NoCommand)
            }
        };

        let format = Format::from(m.value_of("format").unwrap_or("none"))
            .map_err(|_| OptionsError::UnsupportedOutputFormat)?;

        Ok(Options { state_dir, command, format })
    }
}



#[derive(Debug, Display)]
pub enum OptionsError {

    #[display(fmt="Specify a sub-command. See --help")]
    NoCommand,

    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="Unsupported output format. Use text, json or none.")]
    UnsupportedOutputFormat,
}

impl From<io::Error> for OptionsError {
    fn from(e: io::Error) -> Self {
        OptionsError::IoError(e)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {

    #[display(fmt="This client is uninitialised.")]
    Uninitialised,

    #[display(fmt="{}", _0)]
    SignerError(softsigner::SignerError),

    #[display(fmt="{}", _0)]
    BuilderError(krill_cms_proxy::builder::Error<softsigner::SignerError>),

    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    Rfc8183(rfc8183::Error),

    #[display(fmt="{}", _0)]
    ClientError(ClientError),

    #[display(fmt="{}", _0)]
    FileError(file::Error),
}

impl From<softsigner::SignerError> for Error {
    fn from(e: softsigner::SignerError) -> Self {
        Error::SignerError(e)
    }
}

impl From<krill_cms_proxy::builder::Error<softsigner::SignerError>> for Error {
    fn from(e: krill_cms_proxy::builder::Error<softsigner::SignerError>) -> Self {
        Error::BuilderError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<rfc8183::Error> for Error {
    fn from(e: rfc8183::Error) -> Self {
        Error::Rfc8183(e)
    }
}

impl From<ClientError> for Error {
    fn from(e: ClientError) -> Self {
        Error::ClientError(e)
    }
}

impl From<file::Error> for Error {
    fn from(e: file::Error) -> Self { Error::FileError(e) }
}

// For tests see main 'tests' folder
