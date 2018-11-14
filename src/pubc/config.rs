use std::fs::File;
use std::io;
use std::io::Read;
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
    state_dir: PathBuf,
    data_dir: PathBuf,
}

/// # Accessors
impl Config {
    pub fn data_dir(&self) -> String {
        self.data_dir.to_string_lossy().to_string()
    }
    pub fn state_dir(&self) -> String {
        self.state_dir.to_string_lossy().to_string()
    }
}

/// # Create
impl Config {
    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let matches = App::new("NLnet Labs RRDP Client")
            .version("0.1b")
            .arg(Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Specify non-default config file. If no file is \
                specified './defaults/client.toml' will be used to \
                determine default values for all settings. Note that you \
                can use any of the following options to override any of \
                these values..")
                .required(false))


            .subcommand(SubCommand::with_name("init")
                .about("Initialise keypair and print client.xml.")
            )

            .subcommand(SubCommand::with_name("parent")
                .about("Process parent response")
                .arg(Arg::with_name("xml")
                    .short("x")
                    .long("xml")
                    .value_name("FILE")
                    .help("The server's parent.xml response.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("sync")
                .about("Synchronise the configured directory. Use the '-d' \
                option to override the value set in the config file.")
                .arg(Arg::with_name("dir")
                    .short("d")
                    .long("directory")
                    .value_name("FILE")
                    .help("Override the directory to synchronise.")
                    .required(false))
            )

            .get_matches();

        let config_file = matches.value_of("config")
            .unwrap_or("./defaults/client.toml");

        let mut c = Self::read_config(config_file.as_ref())?;

        if let Some(matches) = matches.subcommand_matches("sync") {
            if let Some(data_dir) = matches.value_of("dir") {
                c.data_dir = PathBuf::from(data_dir)
            }
        }

        Ok(c)
    }

    fn read_config(file: &str) -> Result<Self, ConfigError> {
        let mut v = Vec::new();
        let mut f = File::open(file)?;
        f.read_to_end(&mut v)?;

        let c: Config = toml::from_slice(v.as_slice())?;
        Ok(c)
    }
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


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_default_config_file() {
        let c = Config::read_config("./defaults/client.toml").unwrap();
        assert_eq!(c.state_dir(), "./client_state".to_string());
        assert_eq!(c.data_dir(), "./client_data".to_string());
    }

}
