use krill_commons::util::softsigner::OpenSslSigner;
use std::path::PathBuf;
use krill_commons::util::{softsigner, file};
use std::io;
use clap::{App, Arg, SubCommand};
use krill_cms_proxy::builder::IdCertBuilder;
use krill_cms_proxy::id::{MyIdentity, ParentInfo, MyRepoInfo};
use rpki::crypto::PublicKeyFormat;
use rpki::crypto::Signer;
use krill_cms_proxy::rfc8183;

pub struct PubClient {
    // keys
    //   -> keys by id
    signer: OpenSslSigner,

    // key value store
    work_dir: PathBuf
    //   id_key     -> MyIdentity
    //   parent_key -> ParentInfo
    //   repo_key   -> MyRepoInfo

    //   -> my directory of interest
    //      (note: we do not keep this state in client, truth is on disk)
    // archive / log
    //   -> my exchanges with the server
}

impl PubClient {
    pub fn build(work_dir: &PathBuf) -> Result<Self, Error> {
        let signer = OpenSslSigner::build(work_dir)?;
        Ok(PubClient { signer, work_dir: work_dir.clone() })
    }

    /// Initialises a new publication client, using a new key pair, and
    /// returns a publisher request that can be sent to the server.
    pub fn init(&mut self, name: &str) -> Result<(), Error> {
        let key_id = self.signer.create_key(PublicKeyFormat)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(name, id_cert, key_id);

        file::save_json(&my_id, &self.path_my_id())?;
        Ok(())
    }

    /// Makes a publisher request, which can presented as an RFC8183 xml.
    pub fn publisher_request(
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
    pub fn process_repo_response(
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

    fn path_my_id(&self) -> PathBuf {
        let mut res = self.work_dir.clone();
        res.push("id.json");
        res
    }

    fn path_my_parent(&self) -> PathBuf {
        let mut res = self.work_dir.clone();
        res.push("parent.json");
        res
    }

    fn path_my_repo(&self) -> PathBuf {
        let mut res = self.work_dir.clone();
        res.push("repo.json");
        res
    }

    fn my_identity(&self) -> Result<MyIdentity, Error> {
        file::load_json(&self.path_my_id()).map_err(|_| Error::Uninitialised)
    }

//    fn my_parent(&self) -> Result<ParentInfo, Error> {
//        file::load_json(&self.path_my_parent()).map_err(|_| Error::Uninitialised)
//    }
//
//    fn my_repo(&self) -> Result<MyRepoInfo, Error> {
//        file::load_json(&self.path_my_repo()).map_err(|_| Error::Uninitialised)
//    }
}


//------------ Config --------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    state_dir: PathBuf,
    mode: RunMode
}

/// # Accessors
impl Config {
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    pub fn mode(&self) -> &RunMode {
        &self.mode
    }
}

/// # Create
impl Config {
    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let m = App::new("NLnet Labs RRDP Client (RFC8181)")
            .version("0.1b")

            .arg(Arg::with_name("state")
                .short("s")
                .long("state")
                .value_name("FILE")
                .help("Specify the directory where this publication client \
                       maintains its state.")
                .required(true))

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

        let mut mode = RunMode::Unset;

        if let Some(m) = m.subcommand_matches("init") {
            if let Some(name) = m.value_of("name") {
                mode = RunMode::Init(name.to_string())
            }
        }

        if let Some(m) = m.subcommand_matches("request") {
            if let Some(xml) = m.value_of("xml") {
                let xml = PathBuf::from(xml);
                mode = RunMode::PublisherRequest(xml)
            }
        }
        if let Some(m) = m.subcommand_matches("response") {
            if let Some(xml) = m.value_of("xml") {
                let xml = PathBuf::from(xml);
                mode = RunMode::RepoResponse(xml)
            }
        }
        if let Some(m) = m.subcommand_matches("sync") {
            if let Some(dir) = m.value_of("dir") {
                let dir = PathBuf::from(dir);
                mode = RunMode::Sync(dir)
            }
        }

        let state = m.value_of("state").unwrap(); // safe (required)
        let state_dir = PathBuf::from(state);
        Ok(Config { state_dir, mode})
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum RunMode {
    Unset,
    Init(String),
    PublisherRequest(PathBuf),
    RepoResponse(PathBuf),
    Sync(PathBuf)
}

#[derive(Debug, Display)]
pub enum ConfigError {

    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    TomlError(toml::de::Error),
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::TomlError(e)
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

// For tests see main 'tests' folder
