use std::io;
use std::path::PathBuf;
use clap::{App, Arg};
use toml;
use clap::SubCommand;


/// Global configuration for the RRDP Server.
///
/// This will parse a default config file ('./defaults/server.toml') unless
/// another file is explicitly specified. Command line arguments may be used
/// to override any of the settings in the config file.
#[derive(Debug, Deserialize)]
pub struct Config {
    name: String,
    state_dir: PathBuf,
    mode: RunMode
}

/// # Accessors
impl Config {
    pub fn name(&self) -> &String {
        &self.name
    }

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

            .arg(Arg::with_name("name")
                .short("n")
                .long("name")
                .value_name("NAME")
                .help("Specify the name for this publication client.")
                .required(true))

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
                .arg(Arg::with_name("data")
                    .short("d")
                    .long("data")
                    .value_name("FILE")
                    .help("The directory that should be synced to the
                           server. Note that entries here will be relative to
                           the base rsync directory specified in the
                           repository response.")
                    .required(true))
            )

            .get_matches();

        let mode = match m.subcommand_name() {
            Some("init") => {
                RunMode::Init
            },
            Some("request") => {
                if let Some(m) = m.subcommand_matches("request") {
                    if let Some(xml) = m.value_of("xml") {
                        let xml = PathBuf::from(xml);
                        RunMode::PublisherRequest(xml)
                    } else {
                        Self::die(m.usage());
                        unreachable!()
                    }
                } else {
                    Self::die(m.usage());
                    unreachable!()
                }
            },
            Some("response") => {
                if let Some(m) = m.subcommand_matches("response") {
                    if let Some(xml) = m.value_of("xml") {
                        let xml = PathBuf::from(xml);
                        RunMode::RepoResponse(xml)
                    } else {
                        Self::die(m.usage());
                        unreachable!()
                    }
                } else {
                    Self::die(m.usage());
                    unreachable!()
                }
            },
            Some("sync") => {
                if let Some(m) = m.subcommand_matches("sync") {
                    if let Some(dir) = m.value_of("dir") {
                        let dir = PathBuf::from(dir);
                        RunMode::Sync(dir)
                    } else {
                        Self::die(m.usage());
                        unreachable!()
                    }
                } else {
                    Self::die(m.usage());
                    unreachable!()
                }
            },
            _ => {
                Self::die(
                    "Expected subcommand (init, response, request, sync)"
                );
                unreachable!()
            }
        };

        let state = m.value_of("state").unwrap(); // safe (required)
        let state_dir = PathBuf::from(state);
        let name = m.value_of("name").unwrap().to_string(); // safe (required)
        Ok(Config {name, state_dir, mode})
    }

    fn die(message: &str) {
        eprintln!("{}", message);
        ::std::process::exit(1);
    }
}

#[derive(Debug, Deserialize)]
pub enum RunMode {
    Init,
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

