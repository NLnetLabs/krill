use kvx::Namespace;
use crate::commons::actor::Actor;
use crate::commons::eventsourcing::namespace;

pub const KRILL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const KRILL_VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
pub const KRILL_VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
pub const KRILL_VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");
pub const KRILL_SERVER_APP: &str = "Krill";
pub const KRILL_UP_APP: &str = "Krill Upgrade Helper";
pub const KRILL_CLIENT_APP: &str = "Krill Client";
pub const KRILL_TA_CLIENT_APP: &str = "Krill Trust Anchor Client";

pub const KRILL_DEFAULT_CONFIG_FILE: &str = "/etc/krill.conf";
pub const KRILL_DEFAULT_TA_CONFIG_FILE: &str = "/etc/krillta.conf";

const KRILL_ENV_TEST: &str = "KRILL_TEST";
const KRILL_ENV_TEST_ANN: &str = "KRILL_TEST_ANN";
pub const KRILL_ENV_UPGRADE_ONLY: &str = "KRILL_UPGRADE_ONLY";
pub const KRILL_ENV_LOG_LEVEL: &str = "KRILL_LOG_LEVEL";
pub const KRILL_ENV_LOG_TYPE: &str = "KRILL_LOG_TYPE";
pub const KRILL_ENV_ADMIN_TOKEN: &str = "KRILL_ADMIN_TOKEN";
pub const KRILL_ENV_ADMIN_TOKEN_DEPRECATED: &str = "KRILL_AUTH_TOKEN";
pub const KRILL_ENV_SERVER_PORT: &str = "KRILL_SERVER_PORT";
pub const KRILL_ENV_HTTP_LOG_INFO: &str = "KRILL_HTTP_LOG_INFO";
pub const KRILL_ENV_STORAGE_URI: &str = "KRILL_STORAGE_URI";

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

// until const fn's are more versatile for str's, we need to use lazy_static
// to be able to expand the segment macro at compile time, while running the
// expanded code, which actually makes it a Segment, at runtime
pub const TASK_QUEUE_NS: &Namespace = namespace!("tasks");
pub const CASERVER_NS: &Namespace = namespace!("cas");
pub const CA_OBJECTS_NS: &Namespace = namespace!("ca_objects");
pub const KEYS_NS: &Namespace = namespace!("keys");
pub const PUBSERVER_CONTENT_NS: &Namespace = namespace!("pubd_objects");
pub const PUBSERVER_NS: &Namespace = namespace!("pubd");
pub const PROPERTIES_NS: &Namespace = namespace!("properties");
pub const SIGNERS_NS: &Namespace = namespace!("signers");
pub const STATUS_NS: &Namespace = namespace!("status");
pub const TA_PROXY_SERVER_NS: &Namespace = namespace!("ta_proxy");
pub const TA_SIGNER_SERVER_NS: &Namespace = namespace!("ta_signer");

pub const PROPERTIES_DFLT_NAME: &str = "main";

pub const PUBSERVER_DFLT: &str = "0";
pub const PUBSERVER_BACKUP_DIR: &str = "pubd_bk";

pub const REPOSITORY_DIR: &str = "repo";
pub const REPOSITORY_RRDP_DIR: &str = "rrdp";
pub const REPOSITORY_RRDP_ARCHIVE_DIR: &str = "archive";
pub const RRDP_FIRST_SERIAL: u64 = 1; // RFC 8182 says we MUST use 1 as the first serial
pub const REPOSITORY_RSYNC_DIR: &str = "rsync";

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

pub const ACTOR_DEF_KRILL: Actor = Actor::system("krill");
pub const ACTOR_DEF_KRILLTA: Actor = Actor::system("krillta");
pub const ACTOR_DEF_ANON: Actor = Actor::anonymous();
pub const ACTOR_DEF_ADMIN_TOKEN: Actor = Actor::system("admin-token");
pub const ACTOR_DEF_TESTBED: Actor = Actor::system("testbed");

#[cfg(test)]
pub const ACTOR_DEF_TEST: Actor = Actor::system("test");

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
pub const DEFAULT_SIGNER_NAME: &str = "(test mode) Default KMIP signer";
#[cfg(all(feature = "hsm-tests-pkcs11", not(feature = "hsm-tests-kmip")))]
pub const DEFAULT_SIGNER_NAME: &str = "(test mode) Default PKCS#11 signer";

pub const OPENSSL_ONE_OFF_SIGNER_NAME: &str = "OpenSSL one-off signer";
