use std::io;
use std::path::PathBuf;
use clap::{App, Arg, SubCommand};
use toml;


//------------ Config --------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    name: String,
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
        let m = App::new("NLnet Labs RRDP Client")
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
        let name = m.value_of("name").unwrap().to_string(); // safe (required)
        Ok(Config {name, state_dir, mode})
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

#[derive(Debug, Fail)]
pub enum ConfigError {

    #[fail(display ="{}", _0)]
    IoError(io::Error),

    #[fail(display ="{}", _0)]
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

