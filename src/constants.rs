pub const KRILL_VERSION: &str = "0.6.0-plus";
pub const KRILL_SERVER_APP: &str = "Krill";
pub const KRILL_CLIENT_APP: &str = "Krill Client";

pub const KRILL_DEFAULT_CONFIG_FILE: &str = "./defaults/krill.conf";

pub const CASERVER_DIR: &str = "cas";

pub const PUBSERVER_DFLT: &str = "0";
pub const PUBSERVER_DIR: &str = "pubd";

pub const PUBLISH_VALID_DAYS: i64 = 7; // mft is valid for 7 days
pub const PUBLISH_NEXT_HOURS: i64 = 24; // next update in 24 hours (otherwise mft and crl will become stale)
pub const PUBLISH_THRESHOLD_HOURS: i64 = 8; // republish 8 hours before stale

pub const REPOSITORY_DIR: &str = "repo";
pub const REPOSITORY_RRDP_DIR: &str = "rrdp";
pub const REPOSITORY_RSYNC_DIR: &str = "rsync";
pub const REPOSITORY_RRDP_SNAPSHOT_RETAIN_MINS: u64 = 10;

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

pub const CHILD_CERTIFICATE_VALIDITY_YEARS: i32 = 1;
pub const CHILD_CERTIFICATE_REISSUE_WEEKS: i64 = 4;
pub const ROA_CERTIFICATE_VALIDITY_YEARS: i32 = 1;
pub const ROA_CERTIFICATE_REISSUE_WEEKS: i64 = 4;
pub const ID_CERTIFICATE_VALIDITY_YEARS: i32 = 15;

pub const BGP_RIS_REFRESH_MINUTES: i64 = 60;

pub const HTTTP_CLIENT_TIMEOUT_SECS: u64 = 120;
