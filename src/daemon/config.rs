use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use clap::{App, Arg};
use log::LevelFilter;
use serde::de;
use serde::{Deserialize, Deserializer};
use toml;

use rpki::uri;

use crate::commons::api::Token;
use crate::commons::util::ext_serde;
use crate::constants::*;
use crate::daemon::http::ssl;

//------------ ConfigDefaults ------------------------------------------------

pub struct ConfigDefaults;

impl ConfigDefaults {
    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }
    fn port() -> u16 {
        3000
    }
    fn use_ta() -> bool {
        env::var("KRILL_USE_TA").is_ok()
    }
    fn use_ssl() -> SslChoice {
        SslChoice::Test
    }
    fn data_dir() -> PathBuf {
        PathBuf::from("./data")
    }
    fn rsync_base() -> uri::Rsync {
        uri::Rsync::from_str("rsync://localhost/repo/").unwrap()
    }
    fn service_uri() -> String {
        "https://localhost:3000/".to_string()
    }
    fn log_level() -> LevelFilter {
        match env::var("KRILL_LOG_LEVEL") {
            Ok(level) => LevelFilter::from_str(&level).unwrap(),
            _ => LevelFilter::Info,
        }
    }
    fn log_type() -> LogType {
        LogType::File
    }
    fn log_file() -> PathBuf {
        PathBuf::from("./krill.log")
    }
    fn auth_token() -> Token {
        match env::var("KRILL_AUTH_TOKEN") {
            Ok(token) => Token::from(token),
            Err(_) => {
                eprintln!("You MUST provide a value for the master API key, either by setting \"auth_token\" in the config file, or by setting the KRILL_AUTH_TOKEN environment variable.");
                ::std::process::exit(1);
            }
        }
    }
    fn ca_refresh() -> u32 {
        600
    }
}

//------------ Config --------------------------------------------------------

/// Global configuration for the Krill Server.
///
/// This will parse a default config file ('./defaults/krill.conf') unless
/// another file is explicitly specified. Command line arguments may be used
/// to override any of the settings in the config file.
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "ConfigDefaults::ip")]
    ip: IpAddr,

    #[serde(default = "ConfigDefaults::port")]
    port: u16,

    #[serde(default = "ConfigDefaults::use_ta")]
    use_ta: bool,

    #[serde(default = "ConfigDefaults::use_ssl")]
    use_ssl: SslChoice,

    #[serde(default = "ConfigDefaults::data_dir")]
    pub data_dir: PathBuf,

    #[serde(default = "ConfigDefaults::rsync_base")]
    pub rsync_base: uri::Rsync,

    #[serde(default = "ConfigDefaults::service_uri")]
    service_uri: String,

    rrdp_service_uri: Option<String>,

    #[serde(
        default = "ConfigDefaults::log_level",
        deserialize_with = "ext_serde::de_level_filter"
    )]
    log_level: LevelFilter,

    #[serde(default = "ConfigDefaults::log_type")]
    log_type: LogType,

    #[serde(default = "ConfigDefaults::log_file")]
    log_file: PathBuf,

    #[serde(default = "ConfigDefaults::auth_token")]
    pub auth_token: Token,

    #[serde(default = "ConfigDefaults::ca_refresh")]
    pub ca_refresh: u32,
}

/// # Accessors
impl Config {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    pub fn test_ssl(&self) -> bool {
        self.use_ssl == SslChoice::Test
    }

    pub fn https_cert_file(&self) -> PathBuf {
        let mut path = self.data_dir.clone();
        path.push(ssl::HTTPS_SUB_DIR);
        path.push(ssl::CERT_FILE);
        path
    }

    pub fn https_key_file(&self) -> PathBuf {
        let mut path = self.data_dir.clone();
        path.push(ssl::HTTPS_SUB_DIR);
        path.push(ssl::KEY_FILE);
        path
    }

    pub fn service_uri(&self) -> uri::Https {
        uri::Https::from_str(&self.service_uri).unwrap()
    }

    pub fn rrdp_base_uri(&self) -> uri::Https {
        match &self.rrdp_service_uri {
            None => uri::Https::from_string(format!("{}rrdp/", &self.service_uri)).unwrap(),
            Some(uri) => uri::Https::from_str(uri).unwrap(),
        }
    }

    pub fn ta_cert_uri(&self) -> uri::Https {
        uri::Https::from_string(format!("{}ta/ta.cer", &self.service_uri)).unwrap()
    }

    pub fn use_ta(&self) -> bool {
        self.use_ta
    }
}

/// # Create
impl Config {
    fn test_config(data_dir: &PathBuf) -> Self {
        let ip = ConfigDefaults::ip();
        let port = ConfigDefaults::port();
        let use_ta = true;
        let use_ssl = SslChoice::Test;
        let data_dir = data_dir.clone();
        let rsync_base = ConfigDefaults::rsync_base();
        let service_uri = ConfigDefaults::service_uri();
        let rrdp_service_uri = Some("https://localhost:3000/test-rrdp/".to_string());
        let log_level = LevelFilter::Trace;
        let log_type = LogType::Stderr;
        let mut log_file = data_dir.clone();
        log_file.push("krill.log");
        let auth_token = Token::from("secret");
        let ca_refresh = 3600;

        Config {
            ip,
            port,
            use_ta,
            use_ssl,
            data_dir,
            rsync_base,
            service_uri,
            rrdp_service_uri,
            log_level,
            log_type,
            log_file,
            auth_token,
            ca_refresh,
        }
    }

    pub fn test(data_dir: &PathBuf) -> Self {
        let config = Self::test_config(data_dir);
        config.init_logging().unwrap();
        config
    }

    pub fn pubd_test(data_dir: &PathBuf) -> Self {
        let mut config = Self::test_config(data_dir);
        config.port = 3001;
        config.use_ta = false;
        config.service_uri = "https://localhost:3001/".to_string();
        config
    }

    pub fn get_config_filename() -> String {
        let matches = App::new(KRILL_SERVER_APP)
            .version(KRILL_VERSION)
            .arg(
                Arg::with_name("config")
                    .short("c")
                    .long("config")
                    .value_name("FILE")
                    .help(
                        "Specify non-default config file. If no file is \
                         specified './daemon/defaults/krill.conf' will be used to \
                         determine default values for all settings. Note that you \
                         can use any of the following options to override any of \
                         these values..",
                    )
                    .required(false),
            )
            .get_matches();

        let config_file = matches
            .value_of("config")
            .unwrap_or("./defaults/krill.conf");

        config_file.to_string()
    }

    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let config_file = Self::get_config_filename();

        info!(
            "{} uses configuration file: {}",
            KRILL_SERVER_APP, config_file
        );

        let c = Self::read_config(&config_file)?;
        c.init_logging()?;
        Ok(c)
    }

    fn read_config(file: &str) -> Result<Self, ConfigError> {
        let mut v = Vec::new();
        let mut f = File::open(file)?;
        f.read_to_end(&mut v)?;

        let c: Config = toml::from_slice(v.as_slice())?;

        if c.port < 1024 {
            return Err(ConfigError::other("Port number must be >1024"));
        }

        Ok(c)
    }

    pub fn init_logging(&self) -> Result<(), ConfigError> {
        match self.log_type {
            LogType::File => self.file_logger(&self.log_file),
            LogType::Stderr => self.stderr_logger(),
        }
    }

    /// Creates a stderr logger.
    fn stderr_logger(&self) -> Result<(), ConfigError> {
        self.fern_logger()
            .chain(io::stderr())
            .apply()
            .map_err(|e| ConfigError::Other(format!("Failed to init stderr logging: {}", e)))
    }

    /// Creates a file logger using the file provided by `path`.
    fn file_logger(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let file = match fern::log_file(path) {
            Ok(file) => file,
            Err(err) => {
                let error_string = format!("Failed to open log file '{}': {}", path.display(), err);
                error!("{}", error_string.as_str());
                return Err(ConfigError::Other(error_string));
            }
        };
        self.fern_logger()
            .chain(file)
            .apply()
            .map_err(|e| ConfigError::Other(format!("Failed to init file logging: {}", e)))
    }

    /// Creates and returns a fern logger
    fn fern_logger(&self) -> fern::Dispatch {
        let framework_level = match self.log_level {
            LevelFilter::Off => LevelFilter::Off,
            LevelFilter::Error => LevelFilter::Error,
            _ => LevelFilter::Warn, // more becomes too noisy
        };

        let krill_framework_level = match self.log_level {
            LevelFilter::Off => LevelFilter::Off,
            LevelFilter::Error => LevelFilter::Error,
            LevelFilter::Warn => LevelFilter::Warn,
            _ => LevelFilter::Debug, // more becomes too noisy
        };

        let show_target =
            self.log_level == LevelFilter::Trace || self.log_level == LevelFilter::Debug;
        fern::Dispatch::new()
            .format(move |out, message, record| {
                if show_target {
                    out.finish(format_args!(
                        "{} [{}] [{}] {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        record.level(),
                        record.target(),
                        message
                    ))
                } else {
                    out.finish(format_args!(
                        "{} [{}] {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        record.level(),
                        message
                    ))
                }
            })
            .level(self.log_level)
            .level_for("actix_web", framework_level)
            .level_for("actix_server", framework_level)
            .level_for("actix_http", framework_level)
            .level_for("hyper", framework_level)
            .level_for("mio", framework_level)
            .level_for("reqwest", framework_level)
            .level_for("tokio_reactor", framework_level)
            .level_for("want", framework_level)
            .level_for("krill::commons::eventsourcing", krill_framework_level)
            .level_for("krill::commons::util::file", krill_framework_level)
    }
}

#[derive(Debug, Display)]
pub enum ConfigError {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    TomlError(toml::de::Error),

    #[display(fmt = "{}", _0)]
    RpkiUriError(uri::Error),

    #[display(fmt = "{}", _0)]
    Other(String),
}

impl ConfigError {
    pub fn other(s: &str) -> ConfigError {
        ConfigError::Other(s.to_string())
    }
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

impl From<uri::Error> for ConfigError {
    fn from(e: uri::Error) -> Self {
        ConfigError::RpkiUriError(e)
    }
}

//------------ LogType -------------------------------------------------------

/// The target to log to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogType {
    Stderr,
    File,
}

impl<'de> Deserialize<'de> for LogType {
    fn deserialize<D>(d: D) -> Result<LogType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "stderr" => Ok(LogType::Stderr),
            "file" => Ok(LogType::File),
            _ => Err(de::Error::custom(format!(
                "expected \"stderr\" or \"file\", found : \"{}\"",
                string
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SslChoice {
    Yes,
    Test,
}

impl<'de> Deserialize<'de> for SslChoice {
    fn deserialize<D>(d: D) -> Result<SslChoice, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "yes" => Ok(SslChoice::Yes),
            "test" => Ok(SslChoice::Test),
            _ => Err(de::Error::custom(format!(
                "expected \"yes\", or \"test\", \
                 found: \"{}\"",
                string
            ))),
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_default_config_file() {
        // Config for auth token is required! If there is nothing in the conf
        // file, then an environment variable must be set.
        use std::env;
        env::set_var("KRILL_AUTH_TOKEN", "secret");

        let c = Config::read_config("./defaults/krill.conf").unwrap();
        let expected_socket_addr = ([127, 0, 0, 1], 3000).into();
        assert_eq!(c.socket_addr(), expected_socket_addr);
    }

}
