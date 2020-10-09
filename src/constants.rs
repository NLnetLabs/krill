pub const KRILL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const KRILL_VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
pub const KRILL_VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
pub const KRILL_VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");
pub const KRILL_SERVER_APP: &str = "Krill";
pub const KRILL_CLIENT_APP: &str = "Krill Client";

pub const KRILL_DEFAULT_CONFIG_FILE: &str = "./defaults/krill.conf";

pub const KRILL_ENV_TEST: &str = "KRILL_TEST";
pub const KRILL_ENV_TEST_ANN: &str = "KRILL_TEST_ANN";
pub const KRILL_ENV_TEST_UNIT_DATA: &str = "KRILL_TEST_UNIT_DATA";
pub const KRILL_ENV_UPGRADE_ONLY: &str = "KRILL_UPGRADE_ONLY";
pub const KRILL_ENV_REPO_ENABLED: &str = "KRILL_REPO_ENABLED";
pub const KRILL_ENV_TESTBED_ENABLED: &str = "KRILL_TESTBED_ENABLED";
pub const KRILL_ENV_USE_TA: &str = "KRILL_USE_TA";
pub const KRILL_ENV_LOG_LEVEL: &str = "KRILL_LOG_LEVEL";
pub const KRILL_ENV_AUTH_TOKEN: &str = "KRILL_AUTH_TOKEN";

pub const CASERVER_DIR: &str = "cas";

pub const PUBSERVER_DFLT: &str = "0";
pub const PUBSERVER_DIR: &str = "pubd";

pub const REPOSITORY_DIR: &str = "repo";
pub const REPOSITORY_RRDP_DIR: &str = "rrdp";
pub const REPOSITORY_RSYNC_DIR: &str = "rsync";

pub const STATUS_DIR: &str = "status";

pub const KRILL_CLI_SERVER_ARG: &str = "server";
pub const KRILL_CLI_SERVER_ENV: &str = "KRILL_CLI_SERVER";
pub const KRILL_CLI_SERVER_DFLT: &str = "https://localhost:3000/";

pub const KRILL_CLI_TOKEN_ARG: &str = "token";
pub const KRILL_CLI_TOKEN_ENV: &str = "KRILL_CLI_TOKEN";
pub const KRILL_CLI_FORMAT_ARG: &str = "format";
pub const KRILL_CLI_FORMAT_ENV: &str = "KRILL_CLI_FORMAT";
pub const KRILL_CLI_API_ARG: &str = "api";
pub const KRILL_CLI_API_ENV: &str = "KRILL_CLI_API";
pub const KRILL_CLI_MY_CA_ARG: &str = "ca";
pub const KRILL_CLI_MY_CA_ENV: &str = "KRILL_CLI_MY_CA";

pub const KRILL_HTTPS_ROOT_CERTS_ENV: &str = "KRILL_HTTPS_ROOT_CERTS";

pub const ID_CERTIFICATE_VALIDITY_YEARS: i32 = 15;

pub const BGP_RIS_REFRESH_MINUTES: i64 = 60;

pub const HTTTP_CLIENT_TIMEOUT_SECS: u64 = 120;
