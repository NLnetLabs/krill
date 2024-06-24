use std::{
    env, fmt,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use chrono::Duration;
use kvx::Namespace;
use log::{error, LevelFilter};
use rpki::{
    ca::idexchange::PublisherHandle,
    repository::x509::{Time, Validity},
    uri,
};
use serde::{de, Deserialize, Deserializer};
use url::Url;

#[cfg(unix)]
use syslog::Facility;

use crate::{
    commons::{
        api::{PublicationServerUris, Token},
        crypto::{OpenSslSignerConfig, SignSupport},
        error::{Error, KrillIoError},
        eventsourcing::KeyValueStore,
        util::ext_serde,
        KrillResult,
    },
    constants::*,
    daemon::{
        http::tls_keys::{self, HTTPS_SUB_DIR},
        mq::{in_seconds, Priority},
    },
    ta::TaTimingConfig,
};

#[cfg(feature = "multi-user")]
use crate::daemon::auth::providers::{config_file::config::ConfigAuthUsers, openid_connect::ConfigAuthOpenIDConnect};

#[cfg(feature = "hsm")]
use crate::commons::crypto::{KmipSignerConfig, Pkcs11SignerConfig};

//------------ ConfigDefaults ------------------------------------------------

pub struct ConfigDefaults;

impl ConfigDefaults {
    fn dflt_true() -> bool {
        true
    }

    fn ip() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
    }

    fn port() -> u16 {
        3000
    }

    fn https_mode() -> HttpsMode {
        HttpsMode::Generate
    }

    fn storage_uri() -> Url {
        env::var(KRILL_ENV_STORAGE_URI)
            .ok()
            .and_then(|s| Url::parse(&s).ok())
            .unwrap_or_else(|| Url::parse("local://./data").unwrap())
    }

    pub fn log_level() -> LevelFilter {
        match env::var(KRILL_ENV_LOG_LEVEL) {
            Ok(level) => match LevelFilter::from_str(&level) {
                Ok(level) => level,
                Err(_) => {
                    eprintln!("Unrecognized value for log level in env var {}", KRILL_ENV_LOG_LEVEL);
                    ::std::process::exit(1);
                }
            },
            _ => LevelFilter::Info,
        }
    }

    pub fn log_type() -> LogType {
        match env::var(KRILL_ENV_LOG_TYPE) {
            Ok(log_type) => match LogType::from_str(&log_type) {
                Ok(log_type) => log_type,
                Err(e) => {
                    eprintln!(
                        "Unrecognized value for log type in env var {}, {}",
                        KRILL_ENV_LOG_TYPE, e
                    );
                    ::std::process::exit(1);
                }
            },
            _ => LogType::File,
        }
    }

    fn log_file() -> Option<PathBuf> {
        Some(PathBuf::from("./krill.log"))
    }

    fn syslog_facility() -> String {
        "daemon".to_string()
    }

    fn auth_type() -> AuthType {
        AuthType::AdminToken
    }

    pub fn admin_token() -> Token {
        match env::var(KRILL_ENV_ADMIN_TOKEN) {
            Ok(token) => Token::from(token),
            Err(_) => match env::var(KRILL_ENV_ADMIN_TOKEN_DEPRECATED) {
                Ok(token) => Token::from(token),
                Err(_) => {
                    eprintln!("You MUST provide a value for the \"admin token\", either by setting \"admin_token\" in the config file, or by setting the KRILL_ADMIN_TOKEN environment variable.");
                    ::std::process::exit(1);
                }
            },
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

    fn ca_refresh_seconds() -> u32 {
        24 * 3600 // 24 hours
    }

    fn ca_refresh_jitter_seconds() -> u32 {
        12 * 3600 // 12 hours
    }

    fn ca_refresh_parents_batch_size() -> usize {
        25
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

    fn post_protocol_msg_timeout_seconds() -> u64 {
        240 // 4 minutes by default should be plenty in most cases
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

    fn timing_publish_next_hours() -> u32 {
        24
    }

    fn timing_publish_next_jitter_hours() -> u32 {
        4
    }

    fn timing_publish_hours_before_next() -> u32 {
        8
    }

    fn timing_child_certificate_valid_weeks() -> u32 {
        52
    }

    fn timing_child_certificate_reissue_weeks_before() -> u32 {
        4
    }

    fn timing_roa_valid_weeks() -> u32 {
        52
    }

    fn timing_roa_reissue_weeks_before() -> u32 {
        4
    }

    fn timing_aspa_valid_weeks() -> u32 {
        52
    }

    fn timing_aspa_reissue_weeks_before() -> u32 {
        4
    }

    fn timing_bgpsec_valid_weeks() -> u32 {
        52
    }

    fn timing_bgpsec_reissue_weeks_before() -> u32 {
        4
    }

    pub fn openssl_signer_only() -> Vec<SignerConfig> {
        let signer_config = OpenSslSignerConfig { keys_storage_uri: None };
        vec![SignerConfig::new(
            DEFAULT_SIGNER_NAME.to_string(),
            SignerType::OpenSsl(signer_config),
        )]
    }

    pub fn signers() -> Vec<SignerConfig> {
        #[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
        {
            Self::openssl_signer_only()
        }

        #[cfg(all(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))]
        {
            // If we have both enables then just go with openssl.
            // This is because we are using rust features here to drive testing
            // which is not ideal.. should be changes when we remove the feature
            // flags for this.
            Self::openssl_signer_only()
        }

        #[cfg(all(feature = "hsm-tests-kmip", not(feature = "hsm-tests-pkcs11")))]
        {
            let signer_config = KmipSignerConfig {
                host: "127.0.0.1".to_string(),
                port: 5696,
                username: None,
                password: None,
                insecure: true,
                force: true,
                client_cert_path: Some(PathBuf::from_str("test-resources/pykmip/server.crt").unwrap()),
                client_cert_private_key_path: Some(PathBuf::from_str("test-resources/pykmip/server.key").unwrap()),
                server_cert_path: Some(PathBuf::from_str("test-resources/pykmip/server.crt").unwrap()),
                server_ca_cert_path: Some(PathBuf::from_str("test-resources/pykmip/ca.crt").unwrap()),
                retry_seconds: KmipSignerConfig::default_retry_seconds(),
                backoff_multiplier: KmipSignerConfig::default_backoff_multiplier(),
                max_retry_seconds: KmipSignerConfig::default_max_retry_seconds(),
                connect_timeout_seconds: KmipSignerConfig::default_connect_timeout_seconds(),
                read_timeout_seconds: KmipSignerConfig::default_read_timeout_seconds(),
                write_timeout_seconds: KmipSignerConfig::default_write_timeout_seconds(),
                max_lifetime_seconds: KmipSignerConfig::default_max_lifetime_seconds(),
                max_idle_seconds: KmipSignerConfig::default_max_idle_seconds(),
                max_connections: KmipSignerConfig::default_max_connections(),
                max_response_bytes: KmipSignerConfig::default_max_response_bytes(),
            };
            return vec![SignerConfig::new(
                DEFAULT_SIGNER_NAME.to_string(),
                SignerType::Kmip(signer_config),
            )];
        }

        #[cfg(all(feature = "hsm-tests-pkcs11", not(feature = "hsm-tests-kmip")))]
        {
            use crate::commons::crypto::{
                Pkcs11ConfigurablePrivateKeyAttributes,
                Pkcs11ConfigurablePublicKeyAttributes,
                Pkcs11ConfigurableSecrets,
                SlotIdOrLabel,
            };

            let signer_config = Pkcs11SignerConfig {
                lib_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
                secrets: Pkcs11ConfigurableSecrets {
                    user_pin: Some("1234".to_string().into())
                },
                slot: SlotIdOrLabel::Label("My token 1".to_string()),
                login: true,
                retry_seconds: Pkcs11SignerConfig::default_retry_seconds(),
                backoff_multiplier: Pkcs11SignerConfig::default_backoff_multiplier(),
                max_retry_seconds: Pkcs11SignerConfig::default_max_retry_seconds(),
                public_key_attributes: Pkcs11ConfigurablePublicKeyAttributes::default(),
                private_key_attributes: Pkcs11ConfigurablePrivateKeyAttributes::default(),
            };
            vec![SignerConfig::new(
                DEFAULT_SIGNER_NAME.to_string(),
                SignerType::Pkcs11(signer_config),
            )]
        }
    }

    pub fn signer_probe_retry_seconds() -> u64 {
        30
    }
}

//------------ Config --------------------------------------------------------

#[derive(Clone, Debug)]
pub enum SignerReference {
    /// The name of the [[signers]] block being referred to. If supplied it
    /// must match the name field of one of the [[signers]] blocks defined in
    /// the configuration.
    Name(Option<String>),

    /// The index into Config.signers vector that the name was resolved to.
    /// Populated based on the value of 'name' and the contents of
    /// Config.signers after the config file has been parsed.
    Index(usize),
}

pub fn deserialize_signer_ref<'de, D>(deserializer: D) -> Result<SignerReference, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(SignerReference::new(&String::deserialize(deserializer)?))
}

impl Default for SignerReference {
    fn default() -> Self {
        Self::Name(None)
    }
}

impl SignerReference {
    pub fn new(name: &str) -> SignerReference {
        SignerReference::Name(Some(name.to_string()))
    }

    pub fn name(&self) -> &String {
        match self {
            SignerReference::Name(Some(name)) => name,
            _ => panic!("Signer reference is not named"),
        }
    }

    pub fn idx(&self) -> usize {
        match self {
            SignerReference::Index(idx) => *idx,
            _ => panic!("Signer reference is not resolved"),
        }
    }

    pub fn is_named(&self) -> bool {
        matches!(self, SignerReference::Name(Some(_)))
    }

    pub fn is_set(&self) -> bool {
        match self {
            SignerReference::Name(None) => false,
            SignerReference::Name(Some(_)) => true,
            SignerReference::Index(_) => true,
        }
    }
}

/// Inspired by the serde_with crate. But, given that we don't need all
/// its features - just implementing the one thing we need here.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<'a, T> {
    One(T),
    Many(Vec<T>),
    #[serde(skip)]
    _LifeTimeMarker(std::marker::PhantomData<&'a u32>),
}

impl<'a, T> From<OneOrMany<'a, T>> for Vec<T> {
    fn from(one_or_many: OneOrMany<T>) -> Self {
        match one_or_many {
            OneOrMany::One(t) => vec![t],
            OneOrMany::Many(vec_of_t) => vec_of_t,
            OneOrMany::_LifeTimeMarker(_) => unreachable!("variant is never created"),
        }
    }
}

fn deserialize_config_ips<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    OneOrMany::<IpAddr>::deserialize(deserializer).map(|oom| oom.into())
}

pub fn deserialize_storage_uri<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let url = String::deserialize(deserializer)?;
    match Url::parse(&url) {
        Ok(url) => Ok(url),
        Err(_) => Url::parse(&format!("local://{url}/")).map_err(de::Error::custom),
    }
}

/// Global configuration for the Krill Server.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "ConfigDefaults::ip", deserialize_with = "deserialize_config_ips")]
    ip: Vec<IpAddr>,

    #[serde(default = "ConfigDefaults::port")]
    pub port: u16,

    #[serde(default = "ConfigDefaults::https_mode")]
    https_mode: HttpsMode,

    // Deserialize this field from data_dir or storage_uri
    #[serde(
        alias = "data_dir",
        default = "ConfigDefaults::storage_uri",
        deserialize_with = "deserialize_storage_uri"
    )]
    pub storage_uri: Url,

    #[serde(default = "ConfigDefaults::dflt_true")]
    pub use_history_cache: bool,

    tls_keys_dir: Option<PathBuf>,

    repo_dir: Option<PathBuf>,

    // default is false
    // implicitly enabled in case of testbed
    // for that reason.. not pub, but fn provided
    #[serde(default)]
    pub ta_support_enabled: bool,

    // default is false
    // implicitly enabled in case of testbed
    // MUST be enabled for ca imports to work,
    // but can be disabled later and signer can
    // be migrated.
    //
    // for that reason.. not pub, but fn provided
    #[serde(default)]
    pub ta_signer_enabled: bool,

    pid_file: Option<PathBuf>,

    service_uri: Option<uri::Https>,

    #[serde(
        default = "ConfigDefaults::log_level",
        deserialize_with = "ext_serde::de_level_filter"
    )]
    pub log_level: LevelFilter,

    #[serde(default = "ConfigDefaults::log_type")]
    pub log_type: LogType,

    #[serde(default = "ConfigDefaults::log_file")]
    log_file: Option<PathBuf>,

    #[serde(default = "ConfigDefaults::syslog_facility")]
    syslog_facility: String,

    #[serde(default = "ConfigDefaults::admin_token", alias = "auth_token")]
    pub admin_token: Token,

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

    #[serde(default, deserialize_with = "deserialize_signer_ref")]
    pub default_signer: SignerReference,

    #[serde(default, deserialize_with = "deserialize_signer_ref")]
    pub one_off_signer: SignerReference,

    #[serde(default = "ConfigDefaults::signer_probe_retry_seconds")]
    pub signer_probe_retry_seconds: u64,

    #[serde(default = "ConfigDefaults::signers")]
    pub signers: Vec<SignerConfig>,

    #[serde(default = "ConfigDefaults::ca_refresh_seconds", alias = "ca_refresh")]
    ca_refresh_seconds: u32,

    #[serde(default = "ConfigDefaults::ca_refresh_jitter_seconds")]
    ca_refresh_jitter_seconds: u32,

    #[serde(default = "ConfigDefaults::ca_refresh_parents_batch_size")]
    pub ca_refresh_parents_batch_size: usize,

    #[serde(skip)]
    suspend_child_after_inactive_seconds: Option<u32>,
    suspend_child_after_inactive_hours: Option<u32>,

    #[serde(default = "ConfigDefaults::post_limit_api")]
    pub post_limit_api: u64,

    #[serde(default = "ConfigDefaults::post_limit_rfc8181")]
    pub post_limit_rfc8181: u64,

    #[serde(default = "ConfigDefaults::rfc8181_log_dir")]
    pub rfc8181_log_dir: Option<PathBuf>,

    #[serde(default = "ConfigDefaults::post_limit_rfc6492")]
    pub post_limit_rfc6492: u64,

    #[serde(default = "ConfigDefaults::post_protocol_msg_timeout_seconds")]
    pub post_protocol_msg_timeout_seconds: u64,

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

    #[serde(flatten)]
    pub rrdp_updates_config: RrdpUpdatesConfig,

    #[serde(flatten)]
    pub metrics: MetricsConfig,

    pub testbed: Option<TestBed>,

    pub benchmark: Option<Benchmark>,

    #[serde(default)]
    pub ta_timing: TaTimingConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssuanceTimingConfig {
    #[serde(default = "ConfigDefaults::timing_publish_next_hours")]
    timing_publish_next_hours: u32,
    #[serde(default = "ConfigDefaults::timing_publish_next_jitter_hours")]
    timing_publish_next_jitter_hours: u32,
    #[serde(default = "ConfigDefaults::timing_publish_hours_before_next")]
    timing_publish_hours_before_next: u32,
    #[serde(default = "ConfigDefaults::timing_child_certificate_valid_weeks")]
    timing_child_certificate_valid_weeks: u32,
    #[serde(default = "ConfigDefaults::timing_child_certificate_reissue_weeks_before")]
    timing_child_certificate_reissue_weeks_before: u32,
    #[serde(default = "ConfigDefaults::timing_roa_valid_weeks")]
    timing_roa_valid_weeks: u32,
    #[serde(default = "ConfigDefaults::timing_roa_reissue_weeks_before")]
    timing_roa_reissue_weeks_before: u32,
    #[serde(default = "ConfigDefaults::timing_aspa_valid_weeks")]
    timing_aspa_valid_weeks: u32,
    #[serde(default = "ConfigDefaults::timing_aspa_reissue_weeks_before")]
    timing_aspa_reissue_weeks_before: u32,
    #[serde(default = "ConfigDefaults::timing_bgpsec_valid_weeks")]
    timing_bgpsec_valid_weeks: u32,
    #[serde(default = "ConfigDefaults::timing_bgpsec_reissue_weeks_before")]
    timing_bgpsec_reissue_weeks_before: u32,
}

impl IssuanceTimingConfig {
    //-- Publishing Manifests and CRLs

    /// Returns the next update time based on configuration:
    ///
    /// now + timing_publish_next_hours + random(0..timing_publish_next_jitter_hours)
    /// defaults: now + 24 hours + 0 to 4 hours
    pub fn publish_next(&self) -> Time {
        let regular_mins = self.timing_publish_next_hours as i64 * 60;
        let random_mins = if self.timing_publish_next_jitter_hours == 0 {
            0
        } else {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen_range(0..(60 * self.timing_publish_next_jitter_hours))
        } as i64;
        Time::now() + Duration::minutes(regular_mins + random_mins)
    }

    /// Returns the number of hours before expiry that should trigger that
    /// Manifests and CRLs are re-issued.
    pub fn publish_hours_before_next(&self) -> i64 {
        self.timing_publish_hours_before_next.into()
    }

    //-- Child Cert

    /// Validity period for newly issued child certificates
    pub fn new_child_cert_validity(&self) -> Validity {
        SignSupport::sign_validity_weeks(self.timing_child_certificate_valid_weeks.into())
    }

    /// Not after time for newly issued child certificates
    pub fn new_child_cert_not_after(&self) -> Time {
        Time::now() + Duration::weeks(self.timing_child_certificate_valid_weeks.into())
    }

    /// Threshold time for issuing new child certificates
    ///
    /// i.e. certificates with a not after time *before* this moment should be re-issued.
    pub fn new_child_cert_issuance_threshold(&self) -> Time {
        Time::now() + Duration::weeks(self.timing_child_certificate_reissue_weeks_before.into())
    }

    //-- ROAs

    /// Validity period for new ROA objects
    pub fn new_roa_validity(&self) -> Validity {
        SignSupport::sign_validity_weeks(self.timing_roa_valid_weeks.into())
    }

    /// Threshold time for issuing new ROA objects
    ///
    /// i.e. ROA objects with a not after time *before* this moment should be re-issued.
    pub fn new_roa_issuance_threshold(&self) -> Time {
        Time::now() + Duration::weeks(self.timing_roa_reissue_weeks_before.into())
    }

    //-- ASPA

    /// Validity period for new ASPA objects
    pub fn new_aspa_validity(&self) -> Validity {
        SignSupport::sign_validity_weeks(self.timing_aspa_valid_weeks.into())
    }

    /// Threshold time for issuing new ASPA objects
    ///
    /// i.e. ASPA objects with a not after time *before* this moment should be re-issued.
    pub fn new_aspa_issuance_threshold(&self) -> Time {
        Time::now() + Duration::weeks(self.timing_aspa_reissue_weeks_before.into())
    }

    //-- BGPSec

    /// Validity period for new BGPSec router certificates
    pub fn new_bgpsec_validity(&self) -> Validity {
        SignSupport::sign_validity_weeks(self.timing_bgpsec_valid_weeks.into())
    }

    /// Threshold time for issuing new BGPSec router certificates
    ///
    /// i.e. certs with a not after time *before* this moment should be re-issued.
    pub fn new_bgpsec_issuance_threshold(&self) -> Time {
        Time::now() + Duration::weeks(self.timing_bgpsec_reissue_weeks_before.into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RrdpUpdatesConfig {
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_delta_files_min_nr")]
    pub rrdp_delta_files_min_nr: usize,
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_delta_files_min_seconds")]
    pub rrdp_delta_files_min_seconds: u32,
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_delta_files_max_nr")]
    pub rrdp_delta_files_max_nr: usize,
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_delta_files_max_seconds")]
    pub rrdp_delta_files_max_seconds: u32,
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_delta_min_interval_seconds")]
    pub rrdp_delta_interval_min_seconds: u32,
    #[serde(default = "RrdpUpdatesConfig::dflt_rrdp_files_archive")]
    pub rrdp_files_archive: bool,
}

impl RrdpUpdatesConfig {
    // Keep at least X (default 5) delta files in the notification
    // file, even if they would be too old. Their impact on the notification
    // file size is not too bad.
    fn dflt_rrdp_delta_files_min_nr() -> usize {
        5
    }

    // Minimum time to keep deltas. Defaults to 20 minutes, which
    // is double a commonly used update interval, allowing the vast
    // majority of RPs to update using deltas.
    fn dflt_rrdp_delta_files_min_seconds() -> u32 {
        1200 // 20 minutes
    }

    // Maximum time to keep deltas. Defaults to two hours meaning,
    // which is double to slowest normal update interval seen used
    // by a minority of RPs.
    fn dflt_rrdp_delta_files_max_seconds() -> u32 {
        7200 // 2 hours
    }

    // For files older than the min seconds specified (default 20 mins),
    // and younger than max seconds (2 hours), keep at most up to a total
    // nr of files X (default 50).
    fn dflt_rrdp_delta_files_max_nr() -> usize {
        50
    }

    // The minimum interval between RRDP deltas. A value of 0 (default)
    // means that there will be no delays, and every change gets its
    // own delta.
    fn dflt_rrdp_delta_min_interval_seconds() -> u32 {
        0
    }

    // If set to true, we will archive - rather than delete - old
    // snapshot and delta files. The can then be backed up and/deleted
    // at the repository operator's discretion.
    fn dflt_rrdp_files_archive() -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)] // false
    pub metrics_hide_ca_details: bool,
    #[serde(default)] // false
    pub metrics_hide_child_details: bool,
    #[serde(default)] // false
    pub metrics_hide_publisher_details: bool,
    #[serde(default)] // false
    pub metrics_hide_roa_details: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TestBed {
    ta_aia: uri::Rsync,
    ta_uri: uri::Https,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl TestBed {
    pub fn new(ta_aia: uri::Rsync, ta_uri: uri::Https, rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync) -> Self {
        TestBed {
            ta_aia,
            ta_uri,
            rrdp_base_uri,
            rsync_jail,
        }
    }

    pub fn ta_aia(&self) -> &uri::Rsync {
        &self.ta_aia
    }

    pub fn ta_uri(&self) -> &uri::Https {
        &self.ta_uri
    }

    pub fn publication_server_uris(&self) -> PublicationServerUris {
        PublicationServerUris::new(self.rrdp_base_uri.clone(), self.rsync_jail.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Benchmark {
    pub cas: usize,
    pub ca_roas: usize,
}

/// # Accessors
impl Config {
    /// General purpose KV store, can be used to track server settings
    /// etc not specific to any Aggregate or WalSupport type
    pub fn general_key_value_store(&self) -> KrillResult<KeyValueStore> {
        KeyValueStore::create(&self.storage_uri, PROPERTIES_NS).map_err(Error::KeyValueError)
    }

    pub fn key_value_store(&self, name_space: &Namespace) -> KrillResult<KeyValueStore> {
        KeyValueStore::create(&self.storage_uri, name_space).map_err(Error::KeyValueError)
    }

    /// Returns the data directory if disk was used for storage.
    /// This will always be true for upgrades of pre 0.14.0 versions
    fn data_dir(&self) -> Option<PathBuf> {
        if self.storage_uri.scheme() != "local" {
            None
        } else {
            Some(
                Path::new(&format!(
                    "{}{}",
                    self.storage_uri.host_str().unwrap_or(""),
                    self.storage_uri.path()
                ))
                .to_path_buf(),
            )
        }
    }

    pub fn tls_keys_dir(&self) -> &PathBuf {
        self.tls_keys_dir.as_ref().unwrap() // should not panic, as it is always set
    }

    pub fn repo_dir(&self) -> &PathBuf {
        self.repo_dir.as_ref().unwrap() // should not panic, as it is always set
    }

    fn ips(&self) -> &Vec<IpAddr> {
        &self.ip
    }

    pub fn socket_addresses(&self) -> Vec<SocketAddr> {
        self.ips().iter().map(|ip| SocketAddr::new(*ip, self.port)).collect()
    }

    pub fn https_mode(&self) -> HttpsMode {
        self.https_mode
    }

    pub fn https_cert_file(&self) -> PathBuf {
        let mut path = self.tls_keys_dir().to_path_buf();
        path.push(tls_keys::CERT_FILE);
        path
    }

    pub fn https_key_file(&self) -> PathBuf {
        let mut path = self.tls_keys_dir().to_path_buf();
        path.push(tls_keys::KEY_FILE);
        path
    }

    pub fn service_uri(&self) -> uri::Https {
        match &self.service_uri {
            None => {
                if self.ip == ConfigDefaults::ip() {
                    uri::Https::from_string(format!("https://localhost:{}/", self.port)).unwrap()
                } else {
                    uri::Https::from_string(format!("https://{}:{}/", self.ips()[0], self.port)).unwrap()
                }
            }
            Some(uri) => uri.clone(),
        }
    }

    pub fn rfc8181_uri(&self, publisher: &PublisherHandle) -> uri::Https {
        uri::Https::from_string(format!("{}rfc8181/{}/", self.service_uri(), publisher)).unwrap()
    }

    pub fn pid_file(&self) -> &PathBuf {
        self.pid_file.as_ref().unwrap() // should not panic, as it is always set
    }

    /// Returns whether TA support is explicitly enabled in the config, or
    /// implicitly enabled in case testbed (or benchmark) mode is used.
    pub fn ta_proxy_enabled(&self) -> bool {
        self.ta_support_enabled || self.testbed.is_some()
    }

    /// Returns whether TA signer is enabled.
    pub fn ta_signer_enabled(&self) -> bool {
        self.ta_signer_enabled || self.testbed.is_some()
    }

    pub fn suspend_child_after_inactive_seconds(&self) -> Option<i64> {
        match self.suspend_child_after_inactive_seconds {
            Some(seconds) => Some(seconds.into()),
            None => self.suspend_child_after_inactive_hours.map(|hours| hours as i64 * 3600),
        }
    }

    pub fn requeue_remote_failed(&self) -> Priority {
        if test_mode_enabled() {
            in_seconds(5)
        } else {
            in_seconds(SCHEDULER_REQUEUE_DELAY_SECONDS)
        }
    }

    /// Get the priority for the next CA refresh based on the configured
    /// ca_refresh_seconds (1 day), and jitter (12 hours)
    pub fn ca_refresh_next(&self) -> Priority {
        Self::ca_refresh_next_from(self.ca_refresh_seconds, self.ca_refresh_jitter_seconds)
    }

    pub fn ca_refresh_start_up(&self, use_jitter: bool) -> Priority {
        let jitter_seconds = if use_jitter { self.ca_refresh_jitter_seconds } else { 0 };

        Self::ca_refresh_next_from(0, jitter_seconds)
    }

    fn ca_refresh_next_from(regular_seconds: u32, jitter_seconds: u32) -> Priority {
        let random_seconds = if jitter_seconds == 0 {
            0
        } else {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen_range(0..jitter_seconds)
        };

        in_seconds((regular_seconds + random_seconds).into())
    }

    pub fn testbed(&self) -> Option<&TestBed> {
        self.testbed.as_ref()
    }

    /// Returns a reference to the default signer configuration.
    ///
    /// Assumes that the configuration is valid. Will panic otherwise.
    pub fn default_signer(&self) -> &SignerConfig {
        &self.signers[self.default_signer.idx()]
    }

    /// Returns a reference to the one off signer configuration.
    ///
    /// Assumes that the configuration is valid. Will panic otherwise.
    pub fn one_off_signer(&self) -> &SignerConfig {
        &self.signers[self.one_off_signer.idx()]
    }
}

/// # Create
impl Config {
    fn test_config(
        storage_uri: &Url,
        data_dir: Option<&Path>,
        enable_testbed: bool,
        enable_ca_refresh: bool,
        enable_suspend: bool,
        #[allow(unused_variables)] second_signer: bool,
    ) -> Self {
        use crate::test;

        let ip = ConfigDefaults::ip();
        let port = ConfigDefaults::port();

        let https_mode = HttpsMode::Generate;

        let log_level = LevelFilter::Debug;
        let log_type = LogType::Stderr;
        let syslog_facility = ConfigDefaults::syslog_facility();
        let auth_type = AuthType::AdminToken;
        let admin_token = Token::from("secret");
        #[cfg(feature = "multi-user")]
        let auth_policies = vec![];
        #[cfg(feature = "multi-user")]
        let auth_private_attributes = vec![];
        #[cfg(feature = "multi-user")]
        let auth_users = None;
        #[cfg(feature = "multi-user")]
        let auth_openidconnect = None;

        let default_signer = SignerReference::default();
        let one_off_signer = SignerReference::default();
        let signer_probe_retry_seconds = ConfigDefaults::signer_probe_retry_seconds();

        // Multiple signers are only needed and can only be configured when the "hsm" feature is enabled.
        #[cfg(not(feature = "hsm"))]
        let second_signer = false;

        let signers = match second_signer {
            false => ConfigDefaults::signers(),
            true => vec![SignerConfig::new(
                "Second Test Signer".to_string(),
                SignerType::OpenSsl(OpenSslSignerConfig::default()),
            )],
        };

        let ca_refresh_seconds = if enable_ca_refresh { 1 } else { 86400 };
        let ca_refresh_jitter_seconds = if enable_ca_refresh { 0 } else { 86400 }; // no jitter in testing
        let ca_refresh_parents_batch_size = 10;
        let post_limit_api = ConfigDefaults::post_limit_api();
        let post_limit_rfc8181 = ConfigDefaults::post_limit_rfc8181();
        let post_limit_rfc6492 = ConfigDefaults::post_limit_rfc6492();
        let post_protocol_msg_timeout_seconds = ConfigDefaults::post_protocol_msg_timeout_seconds();

        let bgp_risdumps_enabled = false;
        let bgp_risdumps_v4_uri = ConfigDefaults::bgp_risdumps_v4_uri();
        let bgp_risdumps_v6_uri = ConfigDefaults::bgp_risdumps_v6_uri();

        let roa_aggregate_threshold = 3;
        let roa_deaggregate_threshold = 2;

        let timing_publish_next_hours = ConfigDefaults::timing_publish_next_hours();
        let timing_publish_next_jitter_hours = ConfigDefaults::timing_publish_next_jitter_hours();
        let timing_publish_hours_before_next = ConfigDefaults::timing_publish_hours_before_next();
        let timing_child_certificate_valid_weeks = ConfigDefaults::timing_child_certificate_valid_weeks();
        let timing_child_certificate_reissue_weeks_before =
            ConfigDefaults::timing_child_certificate_reissue_weeks_before();
        let timing_roa_valid_weeks = ConfigDefaults::timing_roa_valid_weeks();
        let timing_roa_reissue_weeks_before = ConfigDefaults::timing_roa_reissue_weeks_before();
        let timing_aspa_valid_weeks = ConfigDefaults::timing_aspa_valid_weeks();
        let timing_aspa_reissue_weeks_before = ConfigDefaults::timing_aspa_reissue_weeks_before();
        let timing_bgpsec_valid_weeks = ConfigDefaults::timing_bgpsec_valid_weeks();
        let timing_bgpsec_reissue_weeks_before = ConfigDefaults::timing_bgpsec_reissue_weeks_before();

        let issuance_timing = IssuanceTimingConfig {
            timing_publish_next_hours,
            timing_publish_next_jitter_hours,
            timing_publish_hours_before_next,
            timing_child_certificate_valid_weeks,
            timing_child_certificate_reissue_weeks_before,
            timing_roa_valid_weeks,
            timing_roa_reissue_weeks_before,
            timing_aspa_valid_weeks,
            timing_aspa_reissue_weeks_before,
            timing_bgpsec_valid_weeks,
            timing_bgpsec_reissue_weeks_before,
        };

        let rrdp_updates_config = RrdpUpdatesConfig {
            rrdp_delta_files_min_seconds: 0,
            rrdp_delta_files_min_nr: 5,
            rrdp_delta_files_max_seconds: 1,
            rrdp_delta_files_max_nr: 50,
            rrdp_delta_interval_min_seconds: 0,
            rrdp_files_archive: false,
        };

        let metrics = MetricsConfig {
            metrics_hide_ca_details: false,
            metrics_hide_child_details: false,
            metrics_hide_publisher_details: false,
            metrics_hide_roa_details: false,
        };

        let testbed = if enable_testbed {
            Some(TestBed::new(
                test::rsync("rsync://localhost/ta/ta.cer"),
                test::https(&format!("https://localhost:{}/ta/ta.cer", port)),
                test::https(&format!("https://localhost:{}/rrdp/", port)),
                test::rsync("rsync://localhost/repo/"),
            ))
        } else {
            None
        };

        let suspend_child_after_inactive_seconds = if enable_suspend { Some(3) } else { None };

        Config {
            ip,
            port,
            https_mode,
            storage_uri: storage_uri.clone(),
            use_history_cache: false,
            tls_keys_dir: data_dir.map(|d| d.join(HTTPS_SUB_DIR)),
            repo_dir: data_dir.map(|d| d.join(REPOSITORY_DIR)),
            ta_support_enabled: false, // but, enabled by testbed where applicable
            ta_signer_enabled: false,  // same as above
            pid_file: data_dir.map(|d| d.join("krill.pid")),
            service_uri: None,
            log_level,
            log_type,
            log_file: None,
            syslog_facility,
            admin_token,
            auth_type,
            #[cfg(feature = "multi-user")]
            auth_policies,
            #[cfg(feature = "multi-user")]
            auth_private_attributes,
            #[cfg(feature = "multi-user")]
            auth_users,
            #[cfg(feature = "multi-user")]
            auth_openidconnect,
            default_signer,
            one_off_signer,
            signers,
            signer_probe_retry_seconds,
            ca_refresh_seconds,
            ca_refresh_jitter_seconds,
            ca_refresh_parents_batch_size,
            suspend_child_after_inactive_seconds,
            suspend_child_after_inactive_hours: None,
            post_limit_api,
            post_limit_rfc8181,
            rfc8181_log_dir: None,
            post_limit_rfc6492,
            rfc6492_log_dir: None,
            post_protocol_msg_timeout_seconds,
            bgp_risdumps_enabled,
            bgp_risdumps_v4_uri,
            bgp_risdumps_v6_uri,
            roa_aggregate_threshold,
            roa_deaggregate_threshold,
            issuance_timing,
            rrdp_updates_config,
            metrics,
            testbed,
            benchmark: None,
            ta_timing: TaTimingConfig::default(),
        }
    }

    pub fn test(
        test_storage: &Url,
        test_dir: Option<&Path>,
        enable_testbed: bool,
        enable_ca_refresh: bool,
        enable_suspend: bool,
        second_signer: bool,
    ) -> Self {
        let mut cfg = Self::test_config(
            test_storage,
            test_dir,
            enable_testbed,
            enable_ca_refresh,
            enable_suspend,
            second_signer,
        );
        cfg.process().unwrap();
        cfg
    }

    #[cfg(test)]
    pub fn pubd_test(storage_uri: &Url, data_dir: Option<&Path>) -> Self {
        let mut config = Self::test_config(storage_uri, data_dir, false, false, false, false);
        config.port = 3001;
        config
    }

    /// Creates the config (at startup).
    pub fn create(config_file: &str, upgrade_only: bool) -> Result<Self, ConfigError> {
        let mut config = Self::read_config(config_file)?;

        if upgrade_only {
            config.log_type = LogType::Stderr;
        }

        config.init_logging()?;

        if upgrade_only {
            info!("Prepare upgrade using configuration file: {}", config_file);
            info!("Processing data from: {}", config.storage_uri);
        } else {
            info!("{} uses configuration file: {}", KRILL_SERVER_APP, config_file);
        }

        config
            .process()
            .map_err(|e| ConfigError::Other(format!("Error parsing config file: {}, error: {}", config_file, e)))?;

        Ok(config)
    }

    pub fn process(&mut self) -> Result<(), ConfigError> {
        self.fix()?;
        self.verify()?;
        self.resolve();
        Ok(())
    }

    fn fix(&mut self) -> Result<(), ConfigError> {
        if self.ca_refresh_seconds < CA_REFRESH_SECONDS_MIN {
            warn!(
                "The value for 'ca_refresh_seconds' was below the minimum value, changing it to {} seconds",
                CA_REFRESH_SECONDS_MIN
            );
            self.ca_refresh_seconds = CA_REFRESH_SECONDS_MIN;
        }

        if self.ca_refresh_seconds > CA_REFRESH_SECONDS_MAX {
            warn!(
                "The value for 'ca_refresh_seconds' was above the maximum value, changing it to {} seconds",
                CA_REFRESH_SECONDS_MAX
            );
            self.ca_refresh_seconds = CA_REFRESH_SECONDS_MAX;
        }

        if self.tls_keys_dir.is_none() {
            if let Some(mut data_dir) = self.data_dir() {
                data_dir.push(HTTPS_SUB_DIR);
                self.tls_keys_dir = Some(data_dir);
            } else {
                return Err(ConfigError::other("'tls_keys_dir' is not configured, but 'storage_uri' is not a local directory, please configure an 'tls_keys_dir'"));
            }
        }

        if self.repo_dir.is_none() {
            if let Some(mut data_dir) = self.data_dir() {
                data_dir.push(REPOSITORY_DIR);
                self.repo_dir = Some(data_dir);
            } else {
                return Err(ConfigError::other("'repo_dir' is not configured, but 'storage_uri' is not a local directory, please configure an 'repo_dir'"));
            }
        }

        if self.pid_file.is_none() {
            if let Some(mut data_dir) = self.data_dir() {
                data_dir.push("krill.pid");
                self.pid_file = Some(data_dir);
            } else {
                return Err(ConfigError::other("'pid_file' is not configured, but 'storage_uri' is not a local directory, please configure an 'pid_file'"));
            }
        }

        let half_refresh = self.ca_refresh_seconds / 2;

        if self.ca_refresh_jitter_seconds > half_refresh {
            warn!("The value for 'ca_refresh_jitter_seconds' exceeded 50% of 'ca_refresh_seconds'. Changing it to {} seconds", half_refresh);
            self.ca_refresh_jitter_seconds = half_refresh;
        }

        Ok(())
    }

    fn resolve(&mut self) {
        if self.signers.len() == 1 && !self.default_signer.is_named() {
            self.default_signer = SignerReference::new(&self.signers[0].name);
        }

        let default_signer_idx = self.find_signer_reference(&self.default_signer).unwrap();
        self.default_signer = SignerReference::Index(default_signer_idx);

        let openssl_signer_idx = self.find_openssl_signer();
        let one_off_signer_idx = self.find_signer_reference(&self.one_off_signer);

        // Use the specified one-off signer, if set, else:
        //   - Use an existing OpenSSL signer config,
        //   - Or create a new OpenSSL signer config.
        let one_off_signer_idx = match (one_off_signer_idx, openssl_signer_idx) {
            (Some(one_off_signer_idx), _) => one_off_signer_idx,
            (None, Some(openssl_signer_idx)) => openssl_signer_idx,
            (None, None) => self.add_openssl_signer(OPENSSL_ONE_OFF_SIGNER_NAME),
        };

        self.one_off_signer = SignerReference::Index(one_off_signer_idx);
    }

    fn add_openssl_signer(&mut self, name: &str) -> usize {
        let signer_config = SignerConfig::new(name.to_string(), SignerType::OpenSsl(OpenSslSignerConfig::default()));
        self.signers.push(signer_config);
        self.signers.len() - 1
    }

    fn find_signer_reference(&self, signer_ref: &SignerReference) -> Option<usize> {
        match signer_ref {
            SignerReference::Name(None) => None,
            SignerReference::Name(Some(name)) => self.signers.iter().position(|s| &s.name == name),
            SignerReference::Index(idx) => Some(*idx),
        }
    }

    fn find_openssl_signer(&self) -> Option<usize> {
        self.signers
            .iter()
            .position(|s| matches!(s.signer_type, SignerType::OpenSsl(_)))
    }

    fn verify(&self) -> Result<(), ConfigError> {
        if env::var(KRILL_ENV_ADMIN_TOKEN_DEPRECATED).is_ok() {
            warn!("The environment variable for setting the admin token has been updated from '{}' to '{}', please update as the old value may not be supported in future releases", KRILL_ENV_ADMIN_TOKEN_DEPRECATED, KRILL_ENV_ADMIN_TOKEN)
        }

        if self.port < 1024 {
            return Err(ConfigError::other("Port number must be >1024"));
        }

        if let Some(service_uri) = &self.service_uri {
            if !service_uri.as_str().ends_with('/') {
                return Err(ConfigError::other("service URI must end with '/'"));
            } else if service_uri.as_str().matches('/').count() != 3 {
                return Err(ConfigError::other(
                    "Service URI MUST specify a host name only, e.g. https://rpki.example.com:3000/",
                ));
            }
        }

        if self.issuance_timing.timing_publish_next_hours < 2 {
            return Err(ConfigError::other("timing_publish_next_hours must be at least 2"));
        }

        if self.issuance_timing.timing_publish_next_jitter_hours > (self.issuance_timing.timing_publish_next_hours / 2)
        {
            return Err(ConfigError::other(
                "timing_publish_next_jitter_hours must be at most timing_publish_next_hours divided by 2",
            ));
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

        if let Some(threshold) = self.suspend_child_after_inactive_hours {
            if threshold < CA_SUSPEND_MIN_HOURS {
                return Err(ConfigError::Other(format!(
                    "suspend_child_after_inactive_hours must be {} or higher (or not set at all)",
                    CA_SUSPEND_MIN_HOURS
                )));
            }
        }

        if let Some(benchmark) = &self.benchmark {
            if self.testbed.is_none() {
                return Err(ConfigError::other("[benchmark] section requires [testbed] config"));
            }
            if benchmark.cas > 65535 {
                return Err(ConfigError::other("[benchmark] allows only up to 65536 CAs"));
            }
            if benchmark.ca_roas > 100 {
                return Err(ConfigError::other("[benchmark] allows only up to 100 ROAs per CA"));
            }
        }

        if self.signers.is_empty() {
            // Since Config.signers defaults via Serde to ConfigDefaults::signers() which creates a vector with a
            // single signer, this can only happen if we were invoked on a config object created or modified by test
            // code.
            return Err(ConfigError::Other("No signers configured".to_string()));
        }

        #[cfg(not(feature = "hsm"))]
        {
            fn mk_err_msg(setting_name: &str) -> String {
                format!("This build of Krill lacks support for the '{}' config file setting. Please use a version of Krill that has the 'hsm' feature enabled.", setting_name)
            }

            if self.default_signer.is_named() {
                return Err(ConfigError::other(&mk_err_msg("default_signer")));
            }
            if self.one_off_signer.is_named() {
                return Err(ConfigError::other(&mk_err_msg("one_off_signer")));
            }
            if self.signers != ConfigDefaults::signers() {
                return Err(ConfigError::other(&mk_err_msg("[[signers]]")));
            }
        }

        for n in &self.signers {
            if self.signers.iter().filter(|m| m.name == n.name).count() > 1 {
                return Err(ConfigError::other(&format!("Signer name '{}' is not unique", n.name)));
            }
        }

        if self.signers.len() > 1 && !self.default_signer.is_set() {
            return Err(ConfigError::other(
                "'default_signer' must be set when more than one [[signers]] configuration is defined",
            ));
        }

        if self.default_signer.is_named() && self.find_signer_reference(&self.default_signer).is_none() {
            return Err(ConfigError::other(&format!(
                "'{}' cannot be used as the 'default_signer' as no signer with that name is defined",
                self.default_signer.name()
            )));
        }

        if self.one_off_signer.is_named() && self.find_signer_reference(&self.one_off_signer).is_none() {
            return Err(ConfigError::other(&format!(
                "'{}' cannot be used as the 'one_off_signer' as no signer with that name is defined",
                self.one_off_signer.name()
            )));
        }

        Ok(())
    }

    pub fn read_config(file: &str) -> Result<Self, ConfigError> {
        let mut v = String::new();
        let mut f = File::open(file).map_err(|e| {
            KrillIoError::new(
                format!(
                    "Could not read config file '{}'. Note: you may want to override the default location using --config <path>",
                    file
                ),
                e,
            )
        })?;
        f.read_to_string(&mut v)
            .map_err(|e| KrillIoError::new(format!("Could not read config file '{}'", file), e))?;

        toml::from_str(&v)
            .map_err(|e| ConfigError::Other(format!("Error parsing config file: {}, error: {}", file, e)))
    }

    pub fn init_logging(&self) -> Result<(), ConfigError> {
        match self.log_type {
            LogType::File => self.file_logger(),
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
    fn file_logger(&self) -> Result<(), ConfigError> {
        let path = self.log_file.as_ref().ok_or(ConfigError::Other(
            "log_file not configured with log_type = \"file\"".to_owned(),
        ))?;

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
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            process,
            pid: std::process::id(),
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
        // suppress overly noisy logging
        let framework_level = self.log_level.min(LevelFilter::Warn);
        let krill_framework_level = self.log_level.min(LevelFilter::Debug);

        // disable Oso logging unless the Oso specific POLAR_LOG environment
        // variable is set, it's too noisy otherwise
        let oso_framework_level = if env::var("POLAR_LOG").is_ok() {
            self.log_level.min(LevelFilter::Trace)
        } else {
            self.log_level.min(LevelFilter::Info)
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
    IoError(KrillIoError),
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

impl From<KrillIoError> for ConfigError {
    fn from(e: KrillIoError) -> Self {
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

impl FromStr for LogType {
    type Err = String;

    fn from_str(log_type: &str) -> Result<LogType, Self::Err> {
        match log_type {
            "stderr" => Ok(LogType::Stderr),
            "file" => Ok(LogType::File),
            "syslog" => Ok(LogType::Syslog),
            _ => Err(format!(
                "expected \"stderr\", \"file\" or \"syslog\", found : \"{}\"",
                log_type
            )),
        }
    }
}

impl<'de> Deserialize<'de> for LogType {
    fn deserialize<D>(d: D) -> Result<LogType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        LogType::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

//------------ HttpsMode -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsMode {
    Existing,
    Generate,
    Disable,
}

impl HttpsMode {
    pub fn is_generate_https_cert(&self) -> bool {
        *self == HttpsMode::Generate
    }

    pub fn is_disable_https(&self) -> bool {
        *self == HttpsMode::Disable
    }
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
            "disable" => Ok(HttpsMode::Disable),
            _ => Err(de::Error::custom(format!(
                "expected \"existing\", \"generate\", or \"disable\" found: \"{}\"",
                string
            ))),
        }
    }
}

//------------ AuthType -----------------------------------------------------

/// The target to log to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthType {
    AdminToken,
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
            "admin-token" => Ok(AuthType::AdminToken),
            #[cfg(feature = "multi-user")]
            "config-file" => Ok(AuthType::ConfigFile),
            #[cfg(feature = "multi-user")]
            "openid-connect" => Ok(AuthType::OpenIDConnect),
            _ => {
                #[cfg(not(feature = "multi-user"))]
                let msg = format!("expected \"admin-token\", found: \"{}\"", string);
                #[cfg(feature = "multi-user")]
                let msg = format!(
                    "expected \"config-file\", \"admin-token\", or \"openid-connect\", found: \"{}\"",
                    string
                );
                Err(de::Error::custom(msg))
            }
        }
    }
}

//------------ Signers -----------------------------------------------------

// Supports TOML such as:
//
//   default_signer = "<signer name>"   # optional
//   one_off_signer = "<signer name>"   # optional
//
//   [[signers]]
//   name = "My PKCS#11 signer"
//   type = "PKCS#11"
//   lib_path = "/path/to/pkcs11.so"
//   ...
//
//   [[signers]]
//   name = "My OpenSSL Signer"
//   type = "OpenSSL"
//
//   [[signers]]
//   name = "My KMIP Signer"
//   type = "KMIP"
//   host = "example.com"
//   ...
//
//   # Multiple signers of the same type are supported
//   [[signers]]
//   name = "My Other KMIP Signer"
//   type = "KMIP"
//   ...

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SignerConfig {
    /// A friendly name for the signer. Used to identify the signer with the `default_signer` and `one_off_signer`
    /// settings.
    pub name: String,

    /// Signer specific configuration settings.
    #[serde(flatten)]
    pub signer_type: SignerType,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum SignerType {
    #[serde(alias = "OpenSSL")]
    OpenSsl(OpenSslSignerConfig),

    #[cfg(feature = "hsm")]
    #[serde(alias = "PKCS#11")]
    Pkcs11(Pkcs11SignerConfig),

    #[cfg(feature = "hsm")]
    #[serde(alias = "KMIP")]
    Kmip(KmipSignerConfig),
}

impl std::fmt::Display for SignerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerType::OpenSsl(_) => f.write_str("OpenSSL"),

            #[cfg(feature = "hsm")]
            SignerType::Pkcs11(_) => f.write_str("PKCS#11"),

            #[cfg(feature = "hsm")]
            SignerType::Kmip(_) => f.write_str("KMIP"),
        }
    }
}

impl SignerConfig {
    pub fn new(name: String, signer_type: SignerType) -> SignerConfig {
        Self { name, signer_type }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::test;
    use std::env;

    use super::*;

    fn assert_err_msg(res: Result<Config, ConfigError>, expected_err_msg: &str) {
        if let Err(ConfigError::Other(msg)) = res {
            assert_eq!(msg, expected_err_msg);
        } else {
            panic!("Expected error '{}' but got: {:?}", expected_err_msg, res);
        }
    }

    #[test]
    fn should_parse_default_config_file() {
        // Config for auth token is required! If there is nothing in the conf
        // file, then an environment variable must be set.
        env::set_var(KRILL_ENV_ADMIN_TOKEN, "secret");

        let c = Config::read_config("./defaults/krill.conf").unwrap();
        let expected_socket_addresses: Vec<SocketAddr> = vec![([127, 0, 0, 1], 3000).into()];
        assert_eq!(c.socket_addresses(), expected_socket_addresses);
        assert!(c.testbed().is_none());
    }

    #[test]
    fn should_parse_testbed_config_file() {
        // Config for auth token is required! If there is nothing in the conf
        // file, then an environment variable must be set.
        env::set_var(KRILL_ENV_ADMIN_TOKEN, "secret");

        let c = Config::read_config("./defaults/krill-testbed.conf").unwrap();

        let testbed = c.testbed().unwrap();
        assert_eq!(testbed.ta_aia(), &test::rsync("rsync://testbed.example.com/ta/ta.cer"));
        assert_eq!(testbed.ta_uri(), &test::https("https://testbed.example.com/ta/ta.cer"));

        let uris = testbed.publication_server_uris();
        assert_eq!(uris.rrdp_base_uri(), &test::https("https://testbed.example.com/rrdp/"));
        assert_eq!(uris.rsync_jail(), &test::rsync("rsync://testbed.example.com/repo/"));
    }

    #[test]
    fn should_set_correct_log_levels() {
        use log::Level as LL;

        fn void_logger_from_krill_config(config: &str) -> Box<dyn log::Log> {
            let c: Config = toml::from_str(config).unwrap();
            let void_output = fern::Output::writer(Box::new(io::sink()), "");
            let (_, void_logger) = c.fern_logger().chain(void_output).into_log();
            void_logger
        }

        fn for_target_at_level(target: &str, level: LL) -> log::Metadata {
            log::Metadata::builder().target(target).level(level).build()
        }

        fn should_logging_be_enabled_at_this_krill_config_log_level(log_level: &LL, config_level: &str) -> bool {
            let log_level_from_krill_config_level = LL::from_str(config_level).unwrap();
            log_level <= &log_level_from_krill_config_level
        }

        // Krill requires an auth token to be defined, give it one in the environment
        env::set_var(KRILL_ENV_ADMIN_TOKEN, "secret");

        // Define sets of log targets aka components of Krill that we want to test log settings for, based on the
        // rules & exceptions that the actual code under test is supposed to configure the logger with
        let krill_components = vec!["krill"];
        let krill_framework_components = vec!["krill::commons::eventsourcing", "krill::commons::util::file"];
        let other_key_components = vec!["hyper", "reqwest", "oso"];

        let krill_key_components = vec![krill_components, krill_framework_components.clone()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let all_key_components = vec![krill_key_components.clone(), other_key_components]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        //
        // Test that important log levels are enabled for all key components
        //

        // for each important Krill config log level
        for config_level in &["error", "warn"] {
            // build a logger for that config
            let log = void_logger_from_krill_config(
                &format!(r#"log_level = "{config_level}""#)
            );

            // for all log levels
            for log_msg_level in &[LL::Error, LL::Warn, LL::Info, LL::Debug, LL::Trace] {
                // determine if logging should be enabled or not
                let should_be_enabled =
                    should_logging_be_enabled_at_this_krill_config_log_level(log_msg_level, config_level);

                // for each Krill component we want to pretend to log as
                for component in &all_key_components {
                    // verify that logging is enabled or not as expected
                    assert_eq!(
                        should_be_enabled,
                        log.enabled(&for_target_at_level(component, *log_msg_level)),
                        // output an easy to understand test failure description
                        "Logging at level {} with log_level={} should be {} for component {}",
                        log_msg_level,
                        config_level,
                        if should_be_enabled { "enabled" } else { "disabled" },
                        component
                    );
                }
            }
        }

        //
        // Test that info level and below are only enabled for Krill at the right log levels
        //

        // for each Krill config log level we want to test
        for config_level in &["info", "debug", "trace"] {
            // build a logger for that config
            let log = void_logger_from_krill_config(
                &format!(r#"log_level = "{config_level}""#)
            );

            // for each level of interest that messages could be logged at
            for log_msg_level in &[LL::Info, LL::Debug, LL::Trace] {
                // determine if logging should be enabled or not
                let should_be_enabled =
                    should_logging_be_enabled_at_this_krill_config_log_level(log_msg_level, config_level);

                // for each Krill component we want to pretend to log as
                for component in &krill_key_components {
                    // framework components shouldn't log at Trace level
                    let should_be_enabled = should_be_enabled
                        && (*log_msg_level < LL::Trace || !krill_framework_components.contains(component));

                    // verify that logging is enabled or not as expected
                    assert_eq!(
                        should_be_enabled,
                        log.enabled(&for_target_at_level(component, *log_msg_level)),
                        // output an easy to understand test failure description
                        "Logging at level {} with log_level={} should be {} for component {}",
                        log_msg_level,
                        config_level,
                        if should_be_enabled { "enabled" } else { "disabled" },
                        component
                    );
                }
            }
        }

        //
        // Test that Oso logging at levels below Info is only enabled if the Oso POLAR_LOG=1
        // environment variable is set
        //
        let component = "oso";
        for set_polar_log_env_var in &[true, false] {
            // setup env vars
            if *set_polar_log_env_var {
                env::set_var("POLAR_LOG", "1");
            } else {
                env::remove_var("POLAR_LOG");
            }

            // for each Krill config log level we want to test
            for config_level in &["debug", "trace"] {
                // build a logger for that config
                let log = void_logger_from_krill_config(
                    &format!(r#"log_level = "{config_level}""#)
                );

                // for each level of interest that messages could be logged at
                for log_msg_level in &[LL::Debug, LL::Trace] {
                    // determine if logging should be enabled or not
                    let should_be_enabled =
                        should_logging_be_enabled_at_this_krill_config_log_level(log_msg_level, config_level)
                            && *set_polar_log_env_var;

                    // verify that logging is enabled or not as expected
                    assert_eq!(
                        should_be_enabled,
                        log.enabled(&for_target_at_level(component, *log_msg_level)),
                        // output an easy to understand test failure description
                        r#"Logging at level {} with log_level={} should be {} for component {} and env var POLAR_LOG is {}"#,
                        log_msg_level,
                        config_level,
                        if should_be_enabled { "enabled" } else { "disabled" },
                        component,
                        if *set_polar_log_env_var { "set" } else { "not set" }
                    );
                }
            }
        }
    }

    fn parse_and_process_config_str(config_str: &str) -> Result<Config, ConfigError> {
        let mut c: Config = toml::from_str(config_str).unwrap();
        c.process()?;
        Ok(c)
    }

    #[test]
    fn config_should_accept_and_warn_about_auth_token() {
        let old_config = r#"auth_token = "secret""#;
        let c = parse_and_process_config_str(old_config).unwrap();
        assert_eq!(c.admin_token.as_ref(), "secret");
    }

    #[test]
    fn parse_single_ip() {
        let config_str = r#"
            auth_token = "secret"
            ip         = "127.0.0.1"
        "#;

        parse_and_process_config_str(config_str).unwrap();
    }

    #[test]
    fn parse_multiple_ips() {
        let config_str = r#"
            auth_token = "secret"
            ip         =  [ "127.0.0.1", "::1" ]
        "#;

        parse_and_process_config_str(config_str).unwrap();
    }

    #[cfg(not(feature = "hsm"))]
    #[test]
    fn should_fail_when_config_defines_signers_but_hsm_support_is_not_enabled() {
        fn assert_unexpected_setting_err(res: Result<Config, ConfigError>, setting_name: &str) {
            let expected_err_msg = format!("This build of Krill lacks support for the '{}' config file setting. Please use a version of Krill that has the 'hsm' feature enabled.", setting_name);
            assert_err_msg(res, &expected_err_msg);
        }

        let config_str = r#"
            auth_token = "secret"

            [[signers]]
            type = "OpenSSL"
            name = "Signer 1"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_unexpected_setting_err(res, "[[signers]]");

        // ---

        let config_str = r#"
            auth_token = "secret"
            default_signer = "Signer 1"

            [[signers]]
            type = "OpenSSL"
            name = "Signer 1"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_unexpected_setting_err(res, "default_signer");

        // ---

        let config_str = r#"
            auth_token = "secret"
            one_off_signer = "Signer 1"

            [[signers]]
            type = "OpenSSL"
            name = "Signer 1"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_unexpected_setting_err(res, "one_off_signer");
    }

    #[cfg(feature = "hsm")]
    #[test]
    fn should_fail_with_multiple_signers_and_no_default_signer() {
        let config_str = r#"
            auth_token = "secret"

            [[signers]]
            type = "OpenSSL"
            name = "Signer 1"

            [[signers]]
            type = "OpenSSL"
            name = "Signer 2"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_err_msg(
            res,
            "'default_signer' must be set when more than one [[signers]] configuration is defined",
        );
    }

    #[cfg(feature = "hsm")]
    #[test]
    fn should_fail_if_referenced_signer_is_not_defined() {
        let config_str = r#"
            auth_token = "secret"
            default_signer = "Unknown Signer"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_err_msg(
            res,
            "'Unknown Signer' cannot be used as the 'default_signer' as no signer with that name is defined",
        );

        // ---

        let config_str = r#"
            auth_token = "secret"
            one_off_signer = "Unknown Signer"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_err_msg(
            res,
            "'Unknown Signer' cannot be used as the 'one_off_signer' as no signer with that name is defined",
        );
    }

    #[test]
    #[ignore = "see issue #821"]
    fn should_use_the_expected_default_signer() {
        let config_str = r#"
            auth_token = "secret"
        "#;

        let c = parse_and_process_config_str(config_str).unwrap();

        #[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
        {
            assert_eq!(c.signers.len(), 1);
            assert_eq!(c.signers[0].name, "Default OpenSSL signer");
            assert!(matches!(c.signers[0].signer_type, SignerType::OpenSsl(_)));
        }

        #[cfg(feature = "hsm-tests-kmip")]
        {
            assert_eq!(c.signers.len(), 2);
            assert_eq!(c.signers[0].name, "(test mode) Default KMIP signer");
            assert!(matches!(c.signers[0].signer_type, SignerType::Kmip(_)));
            assert_eq!(c.signers[1].name, "OpenSSL one-off signer");
            assert!(matches!(c.signers[1].signer_type, SignerType::OpenSsl(_)));
        }

        #[cfg(feature = "hsm-tests-pkcs11")]
        {
            assert_eq!(c.signers.len(), 2);
            assert_eq!(c.signers[0].name, "(test mode) Default PKCS#11 signer");
            assert!(matches!(c.signers[0].signer_type, SignerType::Pkcs11(_)));
            assert_eq!(c.signers[1].name, "OpenSSL one-off signer");
            assert!(matches!(c.signers[1].signer_type, SignerType::OpenSsl(_)));
        }
    }

    #[cfg(feature = "hsm")]
    #[test]
    fn should_fail_if_signer_name_is_not_unique() {
        let config_str = r#"
            auth_token = "secret"
            
            [[signers]]
            type = "OpenSSL"
            name = "Blah"

            [[signers]]
            type = "OpenSSL"
            name = "Blah"
        "#;

        let res = parse_and_process_config_str(config_str);
        assert_err_msg(res, "Signer name 'Blah' is not unique");
    }

    #[test]
    fn data_dir_for_storage() {
        fn test_uri(uri: &str, expected_path: &str) {
            let storage_uri = Url::parse(uri).unwrap();
            let config = Config::test_config(&storage_uri, None, false, false, false, false);

            let expected_path = PathBuf::from(expected_path);
            assert_eq!(config.data_dir().unwrap(), expected_path);
        }

        test_uri("local:///tmp/test", "/tmp/test");
        test_uri("local://./data", "./data");
        test_uri("local://data", "data");
        test_uri("local://data/test", "data/test");
        test_uri("local:///tmp/test", "/tmp/test");
    }
}
