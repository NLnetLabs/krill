use crate::{commons::actor::ActorDef, daemon::auth::common::NoResourceType};

pub const KRILL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const KRILL_VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
pub const KRILL_VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
pub const KRILL_VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");
pub const KRILL_SERVER_APP: &str = "Krill";
pub const KRILL_UP_APP: &str = "Krill Upgrade Helper";
pub const KRILL_CLIENT_APP: &str = "Krill Client";

pub const KRILL_DEFAULT_CONFIG_FILE: &str = "./defaults/krill.conf";

const KRILL_ENV_TEST: &str = "KRILL_TEST";
const KRILL_ENV_TEST_ANN: &str = "KRILL_TEST_ANN";
pub const KRILL_ENV_UPGRADE_ONLY: &str = "KRILL_UPGRADE_ONLY";
pub const KRILL_ENV_FORCE_RECOVER: &str = "KRILL_FORCE_RECOVER";
pub const KRILL_ENV_LOG_LEVEL: &str = "KRILL_LOG_LEVEL";
pub const KRILL_ENV_ADMIN_TOKEN: &str = "KRILL_ADMIN_TOKEN";
pub const KRILL_ENV_ADMIN_TOKEN_DEPRECATED: &str = "KRILL_AUTH_TOKEN";
pub const KRILL_ENV_SERVER_PORT: &str = "KRILL_SERVER_PORT";
pub const KRILL_ENV_HTTP_LOG_INFO: &str = "KRILL_HTTP_LOG_INFO";

pub fn enable_test_mode() {
    std::env::set_var(KRILL_ENV_TEST, "1");
}

pub fn test_mode_enabled() -> bool {
    std::env::var(KRILL_ENV_TEST).is_ok()
}

pub fn enable_test_announcements() {
    std::env::set_var(KRILL_ENV_TEST_ANN, "1");
}

pub fn test_announcements_enabled() -> bool {
    std::env::var(KRILL_ENV_TEST_ANN).is_ok()
}

pub const KEYS_DIR: &str = "keys";
pub const SIGNERS_DIR: &str = "signers";

pub const CASERVER_DIR: &str = "cas";
pub const TA_PROXY_SERVER_DIR: &str = "ta_proxy";
pub const TA_SIGNER_SERVER_DIR: &str = "ta_signer";
pub const CA_OBJECTS_DIR: &str = "ca_objects";

pub const PUBSERVER_DFLT: &str = "0";
pub const PUBSERVER_DIR: &str = "pubd";
pub const PUBSERVER_CONTENT_DIR: &str = "pubd_objects";
pub const PUBSERVER_BACKUP_DIR: &str = "pubd_bk";

pub const REPOSITORY_DIR: &str = "repo";
pub const REPOSITORY_RRDP_DIR: &str = "rrdp";
pub const REPOSITORY_RRDP_ARCHIVE_DIR: &str = "archive";
pub const RRDP_FIRST_SERIAL: u64 = 1; // RFC 8182 says we MUST use 1 as the first serial
pub const REPOSITORY_RSYNC_DIR: &str = "rsync";

pub const STATUS_DIR: &str = "status";

pub const KRILL_CLI_SERVER_ARG: &str = "server";
pub const KRILL_CLI_SERVER_ENV: &str = "KRILL_CLI_SERVER";
pub const KRILL_CLI_SERVER_DFLT: &str = "https://localhost:3000/";

pub const KRILL_CLI_ADMIN_TOKEN_ARG: &str = "token";
pub const KRILL_CLI_TOKEN_ENV: &str = "KRILL_CLI_TOKEN";
pub const KRILL_CLI_FORMAT_ARG: &str = "format";
pub const KRILL_CLI_FORMAT_ENV: &str = "KRILL_CLI_FORMAT";
pub const KRILL_CLI_API_ARG: &str = "api";
pub const KRILL_CLI_API_ENV: &str = "KRILL_CLI_API";
pub const KRILL_CLI_MY_CA_ARG: &str = "ca";
pub const KRILL_CLI_MY_CA_ENV: &str = "KRILL_CLI_MY_CA";

pub const CA_REFRESH_SECONDS_MIN: u32 = 3600;
pub const CA_REFRESH_SECONDS_MAX: u32 = 3 * 24 * 3600; // 3 days
pub const CA_SUSPEND_MIN_HOURS: u32 = 48; // at least 2 days
pub const SCHEDULER_REQUEUE_DELAY_SECONDS: i64 = 300;
pub const SCHEDULER_RESYNC_REPO_CAS_THRESHOLD: usize = 5;
pub const SCHEDULER_USE_JITTER_CAS_THRESHOLD: usize = 50;
pub const SCHEDULER_USE_JITTER_CAS_PARENTS_THRESHOLD: usize = 5;
pub const SCHEDULER_INTERVAL_REPUBLISH_MINS: i64 = 5;
pub const SCHEDULER_INTERVAL_RENEW_MINS: i64 = 60;

pub const KRILL_HTTPS_ROOT_CERTS_ENV: &str = "KRILL_HTTPS_ROOT_CERTS";

pub const ID_CERTIFICATE_VALIDITY_YEARS: i32 = 15;

pub const BGP_RIS_REFRESH_MINUTES: i64 = 60;

pub const HTTP_CLIENT_TIMEOUT_SECS: u64 = 120;
pub const HTTP_USER_AGENT_TRUNCATE: usize = 256; // Will truncate received user-agent values at this size.
pub const OPENID_CONNECT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;

pub const NO_RESOURCE: NoResourceType = NoResourceType;

pub const ACTOR_DEF_KRILL: ActorDef = ActorDef::system("krill", "admin");
pub const ACTOR_DEF_ANON: ActorDef = ActorDef::anonymous();
pub const ACTOR_DEF_ADMIN_TOKEN: ActorDef = ActorDef::system("admin-token", "admin");
pub const ACTOR_DEF_TESTBED: ActorDef = ActorDef::system("testbed", "testbed");

// If we have more than 50 do not re-issue all ROAs. See issue #772
pub const UPGRADE_REISSUE_ROAS_CAS_LIMIT: usize = 50;

#[cfg(test)]
pub const ACTOR_DEF_TEST: ActorDef = ActorDef::system("test", "admin");

// Note: These must match the values used by Lagosta.
#[cfg(feature = "multi-user")]
pub const PW_HASH_LOG_N: u8 = 13;
#[cfg(feature = "multi-user")]
pub const PW_HASH_R: u32 = 8;
#[cfg(feature = "multi-user")]
pub const PW_HASH_P: u32 = 1;

#[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
pub const DEFAULT_SIGNER_NAME: &str = "Default OpenSSL signer";
#[cfg(all(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))]
pub const DEFAULT_SIGNER_NAME: &str = "Default OpenSSL signer";
#[cfg(all(feature = "hsm-tests-kmip", not(feature = "hsm-tests-pkcs11")))]
pub const DEFAULT_KMIP_SIGNER_NAME: &str = "(test mode) Default KMIP signer";
#[cfg(all(feature = "hsm-tests-pkcs11", not(feature = "hsm-tests-kmip")))]
pub const DEFAULT_PKCS11_SIGNER_NAME: &str = "(test mode) Default PKCS#11 signer";

pub const OPENSSL_ONE_OFF_SIGNER_NAME: &str = "OpenSSL one-off signer";
