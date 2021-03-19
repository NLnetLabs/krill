use std::fs::File;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, fmt};

use clap::{App, Arg};
use log::{error, LevelFilter};
use serde::de;
use serde::{Deserialize, Deserializer};
#[cfg(unix)]
use syslog::Facility;

use rpki::uri;

use crate::commons::api::Token;
use crate::commons::util::ext_serde;
use crate::constants::*;
use crate::daemon::http::tls_keys;

#[cfg(feature = "multi-user")]
use crate::daemon::auth::providers::config_file::config::ConfigAuthUsers;
#[cfg(feature = "multi-user")]
use crate::daemon::auth::providers::openid_connect::ConfigAuthOpenIDConnect;

//------------ ConfigDefaults ------------------------------------------------

pub struct ConfigDefaults;

impl ConfigDefaults {
    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }
    fn port() -> u16 {
        3000
    }

    fn https_mode() -> HttpsMode {
        HttpsMode::Generate
    }
    fn data_dir() -> PathBuf {
        PathBuf::from("./data")
    }
    fn archive_threshold_days() -> Option<i64> {
        None
    }
    fn always_recover_data() -> bool {
        env::var(KRILL_ENV_FORCE_RECOVER).is_ok()
    }

    fn service_uri() -> String {
        "https://localhost:3000/".to_string()
    }
    fn log_level() -> LevelFilter {
        match env::var(KRILL_ENV_LOG_LEVEL) {
            Ok(level) => match LevelFilter::from_str(&level) {
                Ok(level) => level,
                Err(_) => {
                    eprintln!("Unrecognised value for log level in env var {}", KRILL_ENV_LOG_LEVEL);
                    ::std::process::exit(1);
                }
            },
            _ => LevelFilter::Info,
        }
    }
    fn log_type() -> LogType {
        LogType::File
    }
    fn log_file() -> PathBuf {
        PathBuf::from("./krill.log")
    }
    fn syslog_facility() -> String {
        "daemon".to_string()
    }
    fn auth_type() -> AuthType {
        AuthType::MasterToken
    }
    fn auth_token() -> Token {
        match env::var(KRILL_ENV_AUTH_TOKEN) {
            Ok(token) => Token::from(token),
            Err(_) => {
                eprintln!("You MUST provide a value for the master API key, either by setting \"auth_token\" in the config file, or by setting the KRILL_AUTH_TOKEN environment variable.");
                ::std::process::exit(1);
            }
        }
    }
    #[cfg(feature = "multi-user")]
    fn auth_policies() -> Vec<PathBuf> {
        vec![]
    }
    #[cfg(feature = "multi-user")]
    fn auth_private_attributes() -> Vec<String> {
        vec![]
    }
    fn ca_refresh() -> u32 {
        600
    }

    fn post_limit_api() -> u64 {
        256 * 1024 // 256kB
    }

    fn post_limit_rfc8181() -> u64 {
        32 * 1024 * 1024 // 32MB (roughly 8000 issued certificates, so a key roll for nicbr and 100% uptake should be okay)
    }

    fn rfc8181_log_dir() -> Option<PathBuf> {
        None
    }

    fn post_limit_rfc6492() -> u64 {
        1024 * 1024 // 1MB (for ref. the NIC br cert is about 200kB)
    }

    fn rfc6492_log_dir() -> Option<PathBuf> {
        None
    }

    fn bgp_risdumps_enabled() -> bool {
        true
    }

    fn bgp_risdumps_v4_uri() -> String {
        "http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz".to_string()
    }

    fn bgp_risdumps_v6_uri() -> String {
        "http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz".to_string()
    }

    fn roa_aggregate_threshold() -> usize {
        if let Ok(from_env) = env::var("KRILL_ROA_AGGREGATE_THRESHOLD") {
            if let Ok(nr) = usize::from_str(&from_env) {
                return nr;
            }
        }
        100
    }

    fn roa_deaggregate_threshold() -> usize {
        if let Ok(from_env) = env::var("KRILL_ROA_DEAGGREGATE_THRESHOLD") {
            if let Ok(nr) = usize::from_str(&from_env) {
                return nr;
            }
        }
        90
    }

    fn timing_publish_valid_days() -> i64 {
        7
    }

    fn timing_publish_next_hours() -> i64 {
        24
    }

    fn timing_publish_hours_before_next() -> i64 {
        8
    }

    fn timing_child_certificate_valid_weeks() -> i64 {
        52
    }

    fn timing_child_certificate_reissue_weeks_before() -> i64 {
        4
    }

    fn timing_roa_valid_weeks() -> i64 {
        52
    }

    fn timing_roa_reissue_weeks_before() -> i64 {
        4
    }
}

//------------ Config --------------------------------------------------------

/// Global configuration for the Krill Server.
///
/// This will parse a default config file ('./defaults/krill.conf') unless
/// another file is explicitly specified. Command line arguments may be used
/// to override any of the settings in the config file.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "ConfigDefaults::ip")]
    ip: IpAddr,

    #[serde(default = "ConfigDefaults::port")]
    pub port: u16,

    #[serde(default = "ConfigDefaults::https_mode")]
    https_mode: HttpsMode,

    #[serde(default = "ConfigDefaults::data_dir")]
    pub data_dir: PathBuf,

    #[serde(default = "ConfigDefaults::archive_threshold_days")]
    pub archive_threshold_days: Option<i64>,

    #[serde(default = "ConfigDefaults::always_recover_data")]
    pub always_recover_data: bool,

    pub pid_file: Option<PathBuf>,

    #[serde(default = "ConfigDefaults::service_uri")]
    pub service_uri: String,

    #[serde(
        default = "ConfigDefaults::log_level",
        deserialize_with = "ext_serde::de_level_filter"
    )]
    log_level: LevelFilter,

    #[serde(default = "ConfigDefaults::log_type")]
    log_type: LogType,

    #[serde(default = "ConfigDefaults::log_file")]
    log_file: PathBuf,

    #[serde(default = "ConfigDefaults::syslog_facility")]
    syslog_facility: String,

    #[serde(default = "ConfigDefaults::auth_token")]
    pub auth_token: Token,

    #[serde(default = "ConfigDefaults::auth_type")]
    pub auth_type: AuthType,

    #[cfg(feature = "multi-user")]
    #[serde(default = "ConfigDefaults::auth_policies")]
    pub auth_policies: Vec<PathBuf>,

    #[cfg(feature = "multi-user")]
    #[serde(default = "ConfigDefaults::auth_private_attributes")]
    pub auth_private_attributes: Vec<String>,

    #[cfg(feature = "multi-user")]
    pub auth_users: Option<ConfigAuthUsers>,

    #[cfg(feature = "multi-user")]
    pub auth_openidconnect: Option<ConfigAuthOpenIDConnect>,

    #[serde(default = "ConfigDefaults::ca_refresh")]
    pub ca_refresh: u32,

    #[serde(default = "ConfigDefaults::post_limit_api")]
    pub post_limit_api: u64,

    #[serde(default = "ConfigDefaults::post_limit_rfc8181")]
    pub post_limit_rfc8181: u64,

    #[serde(default = "ConfigDefaults::rfc8181_log_dir")]
    pub rfc8181_log_dir: Option<PathBuf>,

    #[serde(default = "ConfigDefaults::post_limit_rfc6492")]
    pub post_limit_rfc6492: u64,

    #[serde(default = "ConfigDefaults::rfc6492_log_dir")]
    pub rfc6492_log_dir: Option<PathBuf>,

    // RIS BGP
    #[serde(default = "ConfigDefaults::bgp_risdumps_enabled")]
    pub bgp_risdumps_enabled: bool,
    #[serde(default = "ConfigDefaults::bgp_risdumps_v4_uri")]
    pub bgp_risdumps_v4_uri: String,
    #[serde(default = "ConfigDefaults::bgp_risdumps_v6_uri")]
    pub bgp_risdumps_v6_uri: String,

    // ROA Aggregation per ASN
    #[serde(default = "ConfigDefaults::roa_aggregate_threshold")]
    pub roa_aggregate_threshold: usize,

    #[serde(default = "ConfigDefaults::roa_deaggregate_threshold")]
    pub roa_deaggregate_threshold: usize,

    #[serde(flatten)]
    pub issuance_timing: IssuanceTimingConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssuanceTimingConfig {
    #[serde(default = "ConfigDefaults::timing_publish_valid_days")]
    pub timing_publish_valid_days: i64,
    #[serde(default = "ConfigDefaults::timing_publish_next_hours")]
    pub timing_publish_next_hours: i64,
    #[serde(default = "ConfigDefaults::timing_publish_hours_before_next")]
    pub timing_publish_hours_before_next: i64,
    #[serde(default = "ConfigDefaults::timing_child_certificate_valid_weeks")]
    pub timing_child_certificate_valid_weeks: i64,
    #[serde(default = "ConfigDefaults::timing_child_certificate_reissue_weeks_before")]
    pub timing_child_certificate_reissue_weeks_before: i64,
    #[serde(default = "ConfigDefaults::timing_roa_valid_weeks")]
    pub timing_roa_valid_weeks: i64,
    #[serde(default = "ConfigDefaults::timing_roa_reissue_weeks_before")]
    pub timing_roa_reissue_weeks_before: i64,
}

/// # Accessors
impl Config {
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    pub fn test_ssl(&self) -> bool {
        self.https_mode == HttpsMode::Generate
    }

    pub fn https_cert_file(&self) -> PathBuf {
        let mut path = self.data_dir.clone();
        path.push(tls_keys::HTTPS_SUB_DIR);
        path.push(tls_keys::CERT_FILE);
        path
    }

    pub fn https_key_file(&self) -> PathBuf {
        let mut path = self.data_dir.clone();
        path.push(tls_keys::HTTPS_SUB_DIR);
        path.push(tls_keys::KEY_FILE);
        path
    }

    pub fn service_uri(&self) -> uri::Https {
        uri::Https::from_str(&self.service_uri).unwrap()
    }

    pub fn pid_file(&self) -> PathBuf {
        match &self.pid_file {
            None => {
                let mut path = self.data_dir.clone();
                path.push("krill.pid");
                path
            }
            Some(file) => file.clone(),
        }
    }

    pub fn republish_hours(&self) -> i64 {
        if self.issuance_timing.timing_publish_hours_before_next < self.issuance_timing.timing_publish_next_hours {
            self.issuance_timing.timing_publish_next_hours - self.issuance_timing.timing_publish_hours_before_next
        } else {
            0
        }
    }
}

/// # Create
impl Config {
    fn test_config(data_dir: &PathBuf) -> Self {
        let ip = ConfigDefaults::ip();
        let port = ConfigDefaults::port();
        let pid_file = None;
        let https_mode = HttpsMode::Generate;
        let data_dir = data_dir.clone();
        let archive_threshold_days = Some(0);
        let always_recover_data = false;
        let service_uri = ConfigDefaults::service_uri();

        let log_level = LevelFilter::Debug;
        let log_type = LogType::Stderr;
        let mut log_file = data_dir.clone();
        log_file.push("krill.log");
        let syslog_facility = ConfigDefaults::syslog_facility();
        let auth_type = AuthType::MasterToken;
        let auth_token = Token::from("secret");
        #[cfg(feature = "multi-user")]
        let auth_policies = vec![];
        #[cfg(feature = "multi-user")]
        let auth_private_attributes = vec![];
        #[cfg(feature = "multi-user")]
        let auth_users = None;
        #[cfg(feature = "multi-user")]
        let auth_openidconnect = None;
        let ca_refresh = 1;
        let post_limit_api = ConfigDefaults::post_limit_api();
        let post_limit_rfc8181 = ConfigDefaults::post_limit_rfc8181();
        let rfc8181_log_dir = {
            let mut dir = data_dir.clone();
            dir.push("rfc8181");
            Some(dir)
        };
        let post_limit_rfc6492 = ConfigDefaults::post_limit_rfc6492();
        let rfc6492_log_dir = {
            let mut dir = data_dir.clone();
            dir.push("rfc6492");
            Some(dir)
        };

        let bgp_risdumps_enabled = false;
        let bgp_risdumps_v4_uri = ConfigDefaults::bgp_risdumps_v4_uri();
        let bgp_risdumps_v6_uri = ConfigDefaults::bgp_risdumps_v6_uri();

        let roa_aggregate_threshold = 3;
        let roa_deaggregate_threshold = 2;

        let timing_publish_valid_days = ConfigDefaults::timing_publish_valid_days();
        let timing_publish_next_hours = ConfigDefaults::timing_publish_next_hours();
        let timing_publish_hours_before_next = ConfigDefaults::timing_publish_hours_before_next();
        let timing_child_certificate_valid_weeks = ConfigDefaults::timing_child_certificate_valid_weeks();
        let timing_child_certificate_reissue_weeks_before =
            ConfigDefaults::timing_child_certificate_reissue_weeks_before();
        let timing_roa_valid_weeks = ConfigDefaults::timing_roa_valid_weeks();
        let timing_roa_reissue_weeks_before = ConfigDefaults::timing_roa_reissue_weeks_before();

        let issuance_timing = IssuanceTimingConfig {
            timing_publish_valid_days,
            timing_publish_next_hours,
            timing_publish_hours_before_next,
            timing_child_certificate_valid_weeks,
            timing_child_certificate_reissue_weeks_before,
            timing_roa_valid_weeks,
            timing_roa_reissue_weeks_before,
        };

        Config {
            ip,
            port,
            pid_file,
            https_mode,
            data_dir,
            archive_threshold_days,
            always_recover_data,
            service_uri,
            log_level,
            log_type,
            log_file,
            syslog_facility,
            auth_type,
            auth_token,
            #[cfg(feature = "multi-user")]
            auth_policies,
            #[cfg(feature = "multi-user")]
            auth_private_attributes,
            #[cfg(feature = "multi-user")]
            auth_users,
            #[cfg(feature = "multi-user")]
            auth_openidconnect,
            ca_refresh,
            post_limit_api,
            post_limit_rfc8181,
            rfc8181_log_dir,
            post_limit_rfc6492,
            rfc6492_log_dir,
            bgp_risdumps_enabled,
            bgp_risdumps_v4_uri,
            bgp_risdumps_v6_uri,
            roa_aggregate_threshold,
            roa_deaggregate_threshold,
            issuance_timing,
        }
    }

    pub fn test(data_dir: &PathBuf) -> Self {
        Self::test_config(data_dir)
    }

    pub fn pubd_test(data_dir: &PathBuf) -> Self {
        let mut config = Self::test_config(data_dir);
        config.port = 3001;
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
                    .help("Override the path to the config file (default: './defaults/krill.conf')")
                    .required(false),
            )
            .get_matches();

        let config_file = matches.value_of("config").unwrap_or(KRILL_DEFAULT_CONFIG_FILE);

        config_file.to_string()
    }

    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let config_file = Self::get_config_filename();

        let config = match Self::read_config(&config_file) {
            Err(e) => {
                if config_file == KRILL_DEFAULT_CONFIG_FILE {
                    Err(ConfigError::other(
                        "Cannot find config file. Please use --config to specify its location.",
                    ))
                } else {
                    Err(ConfigError::Other(format!(
                        "Error parsing config file: {}, error: {}",
                        config_file, e
                    )))
                }
            }
            Ok(config) => {
                config.init_logging()?;
                info!("{} uses configuration file: {}", KRILL_SERVER_APP, config_file);
                Ok(config)
            }
        }?;
        config
            .verify()
            .map_err(|e| ConfigError::Other(format!("Error parsing config file: {}, error: {}", config_file, e)))?;
        Ok(config)
    }

    pub fn verify(&self) -> Result<(), ConfigError> {
        if self.port < 1024 {
            return Err(ConfigError::other("Port number must be >1024"));
        }

        if !self.service_uri.ends_with('/') {
            return Err(ConfigError::other("service URI must end with '/'"));
        } else {
            uri::Https::from_str(&self.service_uri)
                .map_err(|_| ConfigError::Other(format!("Invalid service uri: {}", self.service_uri)))?;

            if self.service_uri.as_str().matches('/').count() != 3 {
                return Err(ConfigError::other(
                    "Service URI MUST specify a host name only, e.g. https://rpki.example.com:3000/",
                ));
            }
        }

        if self.issuance_timing.timing_publish_next_hours < 2 {
            return Err(ConfigError::other("timing_publish_next_hours must be at least 2"));
        }

        if self.issuance_timing.timing_publish_hours_before_next < 1 {
            return Err(ConfigError::other(
                "timing_publish_hours_before_next must be at least 1",
            ));
        }

        if self.issuance_timing.timing_publish_hours_before_next >= self.issuance_timing.timing_publish_next_hours {
            return Err(ConfigError::other(
                "timing_publish_hours_before_next must be smaller than timing_publish_hours",
            ));
        }

        if self.issuance_timing.timing_publish_valid_days < 1
            || self.issuance_timing.timing_publish_valid_days < (self.issuance_timing.timing_publish_next_hours / 24)
        {
            return Err(ConfigError::other("timing_publish_valid_days must be 1 or bigger, and must be at least as long as timing_publish_next_hours"));
        }

        if self.issuance_timing.timing_child_certificate_valid_weeks < 2 {
            return Err(ConfigError::other(
                "timing_child_certificate_valid_weeks must be at least 2",
            ));
        }

        if self.issuance_timing.timing_child_certificate_reissue_weeks_before < 1 {
            return Err(ConfigError::other(
                "timing_child_certificate_reissue_weeks_before must be at least 1",
            ));
        }

        if self.issuance_timing.timing_child_certificate_reissue_weeks_before
            >= self.issuance_timing.timing_child_certificate_valid_weeks
        {
            return Err(ConfigError::other("timing_child_certificate_reissue_weeks_before must be smaller than timing_child_certificate_valid_weeks"));
        }

        if self.issuance_timing.timing_roa_valid_weeks < 2 {
            return Err(ConfigError::other("timing_roa_valid_weeks must be at least 2"));
        }

        if self.issuance_timing.timing_roa_reissue_weeks_before < 1 {
            return Err(ConfigError::other("timing_roa_reissue_weeks_before must be at least 1"));
        }

        if self.issuance_timing.timing_roa_reissue_weeks_before >= self.issuance_timing.timing_roa_valid_weeks {
            return Err(ConfigError::other(
                "timing_roa_reissue_weeks_before must be smaller than timing_roa_valid_week",
            ));
        }

        Ok(())
    }

    pub fn read_config(file: &str) -> Result<Self, ConfigError> {
        let mut v = Vec::new();
        let mut f = File::open(file)?;
        f.read_to_end(&mut v)?;

        let c: Config = toml::from_slice(v.as_slice())?;
        Ok(c)
    }

    pub fn init_logging(&self) -> Result<(), ConfigError> {
        match self.log_type {
            LogType::File => self.file_logger(&self.log_file),
            LogType::Stderr => self.stderr_logger(),
            LogType::Syslog => {
                let facility = Facility::from_str(&self.syslog_facility)
                    .map_err(|_| ConfigError::other("Invalid syslog_facility"))?;
                self.syslog_logger(facility)
            }
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

    /// Creates a syslog logger and configures correctly.
    #[cfg(unix)]
    fn syslog_logger(&self, facility: syslog::Facility) -> Result<(), ConfigError> {
        let process = env::current_exe()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| String::from("krill"));
        let pid = unsafe { libc::getpid() };
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            process,
            pid,
        };
        let logger = syslog::unix(formatter.clone())
            .or_else(|_| syslog::tcp(formatter.clone(), ("127.0.0.1", 601)))
            .or_else(|_| syslog::udp(formatter, ("127.0.0.1", 0), ("127.0.0.1", 514)));
        match logger {
            Ok(logger) => self
                .fern_logger()
                .chain(logger)
                .apply()
                .map_err(|e| ConfigError::Other(format!("Failed to init syslog: {}", e))),
            Err(err) => {
                let msg = format!("Cannot connect to syslog: {}", err);
                Err(ConfigError::Other(msg))
            }
        }
    }

    /// Creates and returns a fern logger with log level tweaks
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

        // disable Oso logging unless the Oso specific POLAR_LOG environment
        // variable is set, it's too noisy otherwise
        let oso_framework_level = if env::var("POLAR_LOG").is_ok() {
            match self.log_level {
                LevelFilter::Trace => LevelFilter::Trace,
                _ => LevelFilter::Debug, // at least debug
            }
        } else {
            match self.log_level {
                LevelFilter::Off => LevelFilter::Off,
                LevelFilter::Error => LevelFilter::Error,
                LevelFilter::Warn => LevelFilter::Warn,
                _ => LevelFilter::Info, // more becomes too noisy
            }
        };

        let show_target = self.log_level == LevelFilter::Trace || self.log_level == LevelFilter::Debug;
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
            .level_for("rustls", framework_level)
            .level_for("hyper", framework_level)
            .level_for("mio", framework_level)
            .level_for("reqwest", framework_level)
            .level_for("tokio_reactor", framework_level)
            .level_for("tokio_util::codec::framed_read", framework_level)
            .level_for("want", framework_level)
            .level_for("tracing::span", framework_level)
            .level_for("h2", framework_level)
            .level_for("oso", oso_framework_level)
            .level_for("krill::commons::eventsourcing", krill_framework_level)
            .level_for("krill::commons::util::file", krill_framework_level)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(io::Error),
    TomlError(toml::de::Error),
    RpkiUriError(uri::Error),
    Other(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::IoError(e) => e.fmt(f),
            ConfigError::TomlError(e) => e.fmt(f),
            ConfigError::RpkiUriError(e) => e.fmt(f),
            ConfigError::Other(s) => s.fmt(f),
        }
    }
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
    Syslog,
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
            "syslog" => Ok(LogType::Syslog),
            _ => Err(de::Error::custom(format!(
                "expected \"stderr\" or \"file\", found : \"{}\"",
                string
            ))),
        }
    }
}

//------------ HttpsMode -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpsMode {
    Existing,
    Generate,
}

impl<'de> Deserialize<'de> for HttpsMode {
    fn deserialize<D>(d: D) -> Result<HttpsMode, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "existing" => Ok(HttpsMode::Existing),
            "generate" => Ok(HttpsMode::Generate),
            _ => Err(de::Error::custom(format!(
                "expected \"existing\", or \"generate\", \
                 found: \"{}\"",
                string
            ))),
        }
    }
}

//------------ AuthType -----------------------------------------------------

/// The target to log to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthType {
    MasterToken,
    #[cfg(feature = "multi-user")]
    ConfigFile,
    #[cfg(feature = "multi-user")]
    OpenIDConnect,
}

impl<'de> Deserialize<'de> for AuthType {
    fn deserialize<D>(d: D) -> Result<AuthType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "master-token" => Ok(AuthType::MasterToken),
            #[cfg(feature = "multi-user")]
            "config-file" => Ok(AuthType::ConfigFile),
            #[cfg(feature = "multi-user")]
            "openid-connect" => Ok(AuthType::OpenIDConnect),
            _ => {
                #[cfg(not(feature = "multi-user"))]
                let msg = format!("expected \"master-token\", found: \"{}\"", string);
                #[cfg(feature = "multi-user")]
                let msg = format!(
                    "expected \"config-file\", \"master-token\", or \"openid-connect\", found: \"{}\"",
                    string
                );
                Err(de::Error::custom(msg))
            }
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
        env::set_var(KRILL_ENV_AUTH_TOKEN, "secret");

        let c = Config::read_config("./defaults/krill.conf").unwrap();
        let expected_socket_addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
        assert_eq!(c.socket_addr(), expected_socket_addr);
    }
}
