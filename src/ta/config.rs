use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};

use log::LevelFilter;
use url::Url;

use crate::{
    commons::crypto::{KrillSigner, KrillSignerBuilder, OpenSslSignerConfig},
    constants::OPENSSL_ONE_OFF_SIGNER_NAME,
    daemon::config::{LogType, SignerConfig, SignerReference, SignerType},
};

// TA timing defaults
const DFLT_TA_CERTIFICATE_VALIDITY_YEARS: i32 = 100;
const DFLT_TA_ISSUED_CERTIFICATE_VALIDITY_WEEKS: i64 = 52;
const DFLT_TA_ISSUED_CERTIFICATE_REISSUE_WEEKS_BEFORE: i64 = 26;
const DFLT_TA_MFT_NEXT_UPDATE_WEEKS: i64 = 12;
const DFLT_TA_SIGNED_MESSAGE_VALIDITY_DAYS: i64 = 14;

//------------------------ TaTimingConfig
//------------------------ ---------------------------------------

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct TaTimingConfig {
    #[serde(default = "TaTimingConfig::dflt_ta_certificate_validity_years")]
    pub certificate_validity_years: i32,

    #[serde(
        default = "TaTimingConfig::dflt_ta_issued_certificate_validity_weeks"
    )]
    pub issued_certificate_validity_weeks: i64,

    #[serde(
        default = "TaTimingConfig::dflt_ta_issued_certificate_reissue_weeks_before"
    )]
    pub issued_certificate_reissue_weeks_before: i64,

    #[serde(default = "TaTimingConfig::dflt_ta_mft_next_update_weeks")]
    pub mft_next_update_weeks: i64,

    #[serde(
        default = "TaTimingConfig::dflt_ta_signed_message_validity_days"
    )]
    pub signed_message_validity_days: i64,
}

impl Default for TaTimingConfig {
    fn default() -> Self {
        Self {
            certificate_validity_years: DFLT_TA_CERTIFICATE_VALIDITY_YEARS,
            issued_certificate_validity_weeks:
                DFLT_TA_ISSUED_CERTIFICATE_VALIDITY_WEEKS,
            issued_certificate_reissue_weeks_before:
                DFLT_TA_ISSUED_CERTIFICATE_REISSUE_WEEKS_BEFORE,
            mft_next_update_weeks: DFLT_TA_MFT_NEXT_UPDATE_WEEKS,
            signed_message_validity_days:
                DFLT_TA_SIGNED_MESSAGE_VALIDITY_DAYS,
        }
    }
}

impl TaTimingConfig {
    fn dflt_ta_certificate_validity_years() -> i32 {
        DFLT_TA_CERTIFICATE_VALIDITY_YEARS
    }

    fn dflt_ta_issued_certificate_validity_weeks() -> i64 {
        DFLT_TA_ISSUED_CERTIFICATE_VALIDITY_WEEKS
    }

    fn dflt_ta_issued_certificate_reissue_weeks_before() -> i64 {
        DFLT_TA_ISSUED_CERTIFICATE_REISSUE_WEEKS_BEFORE
    }

    fn dflt_ta_mft_next_update_weeks() -> i64 {
        DFLT_TA_MFT_NEXT_UPDATE_WEEKS
    }

    fn dflt_ta_signed_message_validity_days() -> i64 {
        DFLT_TA_SIGNED_MESSAGE_VALIDITY_DAYS
    }
}

//------------------------ Config -----------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(
        alias = "data_dir",
        deserialize_with = "crate::daemon::config::deserialize_storage_uri"
    )]
    pub storage_uri: Url,

    #[serde(default)]
    pub use_history_cache: bool,

    #[serde(default = "crate::daemon::config::ConfigDefaults::log_type")]
    log_type: LogType,

    log_file: Option<PathBuf>,

    #[serde(
        default = "crate::daemon::config::ConfigDefaults::log_level",
        deserialize_with = "crate::commons::util::ext_serde::de_level_filter"
    )]
    pub log_level: LevelFilter,

    // Signer support. Ported from main Krill.
    #[serde(
        default,
        deserialize_with = "crate::daemon::config::deserialize_signer_ref"
    )]
    pub default_signer: SignerReference,

    #[serde(
        default,
        deserialize_with = "crate::daemon::config::deserialize_signer_ref"
    )]
    pub one_off_signer: SignerReference,

    #[serde(
        default = "crate::daemon::config::ConfigDefaults::signer_probe_retry_seconds"
    )]
    pub signer_probe_retry_seconds: u64,

    #[serde(default = "crate::daemon::config::ConfigDefaults::signers")]
    pub signers: Vec<SignerConfig>,

    #[serde(default)]
    pub timing_config: TaTimingConfig,
}

impl Config {
    pub fn parse(file_path: &str) -> Result<Self, ConfigError> {
        let mut v = String::new();

        let mut file = File::open(file_path).map_err(|e| {
            ConfigError::Other(format!(
                "Could not read config file '{}': {}",
                file_path, e
            ))
        })?;

        file.read_to_string(&mut v).map_err(|e| {
            ConfigError::Other(format!(
                "Could not read config file '{}': {}",
                file_path, e
            ))
        })?;

        Self::parse_str(&v)
    }

    fn parse_str(s: &str) -> Result<Self, ConfigError> {
        let mut config: Config = toml::from_str(s).map_err(|err| {
            ConfigError::Other(format!("Error parsing config file: {err}"))
        })?;

        config.resolve_signers();
        // ignore init errors
        // they are normally due to double initialising logging
        let _ = config.init_logging();

        Ok(config)
    }

    fn resolve_signers(&mut self) {
        if self.signers.len() == 1 && !self.default_signer.is_named() {
            self.default_signer = SignerReference::new(&self.signers[0].name);
        }

        let default_signer_idx =
            self.find_signer_reference(&self.default_signer).unwrap();
        self.default_signer = SignerReference::Index(default_signer_idx);

        let openssl_signer_idx = self.find_openssl_signer();
        let one_off_signer_idx =
            self.find_signer_reference(&self.one_off_signer);

        // Use the specified one-off signer, if set, else:
        //   - Use an existing OpenSSL signer config,
        //   - Or create a new OpenSSL signer config.
        let one_off_signer_idx =
            match (one_off_signer_idx, openssl_signer_idx) {
                (Some(one_off_signer_idx), _) => one_off_signer_idx,
                (None, Some(openssl_signer_idx)) => openssl_signer_idx,
                (None, None) => {
                    self.add_openssl_signer(OPENSSL_ONE_OFF_SIGNER_NAME)
                }
            };

        self.one_off_signer = SignerReference::Index(one_off_signer_idx);
    }

    fn add_openssl_signer(&mut self, name: &str) -> usize {
        let signer_config = SignerConfig::new(
            name.to_string(),
            SignerType::OpenSsl(OpenSslSignerConfig::default()),
        );
        self.signers.push(signer_config);
        self.signers.len() - 1
    }

    fn find_signer_reference(
        &self,
        signer_ref: &SignerReference,
    ) -> Option<usize> {
        match signer_ref {
            SignerReference::Name(None) => None,
            SignerReference::Name(Some(name)) => {
                self.signers.iter().position(|s| &s.name == name)
            }
            SignerReference::Index(idx) => Some(*idx),
        }
    }

    fn find_openssl_signer(&self) -> Option<usize> {
        self.signers
            .iter()
            .position(|s| matches!(s.signer_type, SignerType::OpenSsl(_)))
    }

    // Signer support
    pub fn signer(&self) -> Result<Arc<KrillSigner>, ConfigError> {
        // Assumes that Config::verify() has already ensured that the signer
        // configuration is valid and that Config::resolve() has been
        // used to update signer name references to resolve to the
        // corresponding signer configurations.
        let probe_interval =
            std::time::Duration::from_secs(self.signer_probe_retry_seconds);
        let signer = KrillSignerBuilder::new(
            &self.storage_uri,
            probe_interval,
            &self.signers,
        )
        .with_default_signer(self.default_signer())
        .with_one_off_signer(self.one_off_signer())
        .build()
        .map_err(|e| {
            ConfigError::Other(format!("Could not create KrillSigner: {}", e))
        })?;

        Ok(Arc::new(signer))
    }

    /// Returns a reference to the default signer configuration.
    ///
    /// Assumes that the configuration is valid. Will panic otherwise.
    fn default_signer(&self) -> &SignerConfig {
        &self.signers[self.default_signer.idx()]
    }

    /// Returns a reference to the one off signer configuration.
    ///
    /// Assumes that the configuration is valid. Will panic otherwise.
    fn one_off_signer(&self) -> &SignerConfig {
        &self.signers[self.one_off_signer.idx()]
    }

    fn init_logging(&self) -> Result<(), ConfigError> {
        match self.log_type {
            LogType::File => self.file_logger(),
            LogType::Stderr => self.stderr_logger(),
            LogType::Syslog => Err(ConfigError::other(
                "syslog is not supported for the TA client",
            )),
        }
    }

    fn file_logger(&self) -> Result<(), ConfigError> {
        let path = self.log_file.as_ref().ok_or(ConfigError::Other(
            "log_file not configured with log_type = \"file\"".to_owned(),
        ))?;
        let log_file = fern::log_file(path).map_err(|e| {
            ConfigError::Other(format!(
                "Failed to open log file '{}': {}",
                path.display(),
                e
            ))
        })?;

        self.fern_logger().chain(log_file).apply().map_err(|e| {
            ConfigError::Other(format!("Failed to init file logging: {}", e))
        })
    }

    /// Creates a stderr logger.
    fn stderr_logger(&self) -> Result<(), ConfigError> {
        self.fern_logger().chain(io::stderr()).apply().map_err(|e| {
            ConfigError::Other(format!(
                "Failed to init stderr logging: {}",
                e
            ))
        })
    }

    /// Creates and returns a fern logger with log level tweaks
    fn fern_logger(&self) -> fern::Dispatch {
        // suppress overly noisy logging
        let framework_level = self.log_level.min(LevelFilter::Warn);
        let krill_framework_level = self.log_level.min(LevelFilter::Debug);

        let show_target = self.log_level == LevelFilter::Trace
            || self.log_level == LevelFilter::Debug;

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
            .level_for("krill::commons::eventsourcing", krill_framework_level)
            .level_for("krill::commons::util::file", krill_framework_level)
    }
}

//------------------------ ConfigError
//------------------------ ------------------------------------------

#[derive(Clone, Debug)]
pub enum ConfigError {
    Other(String),
}

impl ConfigError {
    fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::Other(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use crate::test;

    #[test]
    fn initialise_default_signers() {
        test::test_in_memory(|_storage_uri| {
            let config_string =
                include_str!("../../test-resources/ta/ta.conf");
            let config = Config::parse_str(config_string).unwrap();
            config.signer().unwrap();
        })
    }
}
