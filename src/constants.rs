//! Various Krill-wide constants.

use rpki::ca::idexchange::CaHandle;
use crate::commons::storage::Ident;
use crate::commons::actor::Actor;


//------------ Binary Names -------------------------------------------------

/// The friendly name of the `krill` binary.
pub const KRILL_SERVER_APP: &str = "Krill";

/// The friendly name of the `krillup` binary.
pub const KRILL_UP_APP: &str = "Krill Upgrade Helper";

/// The friendly name of the `krillc` binary.
pub const KRILL_CLIENT_APP: &str = "Krill Client";

/// The friendly name of the `krillta` binary.
pub const KRILL_TA_CLIENT_APP: &str = "Krill Trust Anchor Client";


//------------ Config Files Paths -------------------------------------------

/// The default path to the Krill config file.
pub const KRILL_DEFAULT_CONFIG_FILE: &str = "/etc/krill.conf";

/// The default path to the `krillta` config file.
pub const KRILL_DEFAULT_TA_CONFIG_FILE: &str = "/etc/krillta.conf";


//------------ Environment Variables ----------------------------------------

/// The environment variable signalling test mode.
///
/// Test mode is enabled when this variable is set to any value.
const KRILL_ENV_TEST: &str = "KRILL_TEST";

/// The environment variable signalling test announcements.
///
/// Test announcements are enabled if this variable is set to any value.
const KRILL_ENV_TEST_ANN: &str = "KRILL_TEST_ANN";

/// The environment variable signalling to only upgrade data.
///
/// If this variable is set, the Krill server will exit after upgrading the
/// data.
pub const KRILL_ENV_UPGRADE_ONLY: &str = "KRILL_UPGRADE_ONLY";

/// The environment variable with the log level.
///
/// The variable should contain the name of a [`log::LevelFilter`]. It will
/// be overwritten by the config file. The default is “info.”
pub const KRILL_ENV_LOG_LEVEL: &str = "KRILL_LOG_LEVEL";

/// The environment variable with the log target.
///
/// The variable should contain the name of a
/// [`LogType`][crate::daemon::config::LogType]. It will be overwritten by
/// the config file. The default is “file.”
pub const KRILL_ENV_LOG_TYPE: &str = "KRILL_LOG_TYPE";

/// The environment variable with the Krill admin token.
///
/// This is primarily used to safely signal the admin token to `krillc`.
pub const KRILL_ENV_ADMIN_TOKEN: &str = "KRILL_ADMIN_TOKEN";

/// The deprecated environment variable with the Krill admin token.
///
/// The name in [`KRILL_ENV_ADMIN_TOKEN`] should be used instead.
pub const KRILL_ENV_ADMIN_TOKEN_DEPRECATED: &str = "KRILL_AUTH_TOKEN";

/// The environment variable indicating to log HTTP requests.
///
/// If this variable is set, the HTTP server will log all requests at log
/// level “info.”
pub const KRILL_ENV_HTTP_LOG_INFO: &str = "KRILL_HTTP_LOG_INFO";

/// The environment variable indicating the default storage URI.
///
/// The value will be overwritten with that in the config file. Defaults to
/// `local://./data` if not set or not a valid URI.
pub const KRILL_ENV_STORAGE_URI: &str = "KRILL_STORAGE_URI";

/// The environment variable directing `krill` to print the request and exit.
///
/// If this variable is set, `krillc` will not execute the requested function
/// but just print out the HTTP request it would need to perform and exit.
pub const KRILL_CLI_API_ENV: &str = "KRILL_CLI_API";

/// The environment variable with the path to HTTPS root certificates.
///
/// This is used when Krill needs to make HTTP requests.
pub const KRILL_HTTPS_ROOT_CERTS_ENV: &str = "KRILL_HTTPS_ROOT_CERTS";


// XXX The following functions should probably live somewhere else. But
//     where?
//
//     The use of environment variables here is very unsafe and we should
//     probably replace this with something else.

/// Sets the environment variable to enable test mode.
pub fn enable_test_mode() {
    // Safety: See note above.
    unsafe { std::env::set_var(KRILL_ENV_TEST, "1") };
}

/// Returns whether the environment variable to enable test mode is set.
pub fn test_mode_enabled() -> bool {
    std::env::var(KRILL_ENV_TEST).is_ok()
}

/// Sets the environment variable to enable test announcements.
pub fn enable_test_announcements() {
    // Safety: See note above.
    unsafe { std::env::set_var(KRILL_ENV_TEST_ANN, "1"); }
}

/// Returns whether the environment variable for test announcements is set.
pub fn test_announcements_enabled() -> bool {
    std::env::var(KRILL_ENV_TEST_ANN).is_ok()
}


//------------ Storage Namespaces -------------------------------------------

/// The namespace for the CA manager.
///
pub const CASERVER_NS: &Ident = Ident::make("cas");

/// The namespace for CA objects store.
pub const CA_OBJECTS_NS: &Ident = Ident::make("ca_objects");

/// The namespace for the keys of the signer.
pub const KEYS_NS: &Ident = Ident::make("keys");

/// The namespace for the property manager.
pub const PROPERTIES_NS: &Ident = Ident::make("properties");

/// The namespace for the publication server content.
pub const PUBSERVER_CONTENT_NS: &Ident = Ident::make("pubd_objects");

/// The namespace for the publication server.
pub const PUBSERVER_NS: &Ident = Ident::make("pubd");

/// The namespace for the signer.
pub const SIGNERS_NS: &Ident = Ident::make("signers");

/// The namespace for the status manager.
pub const STATUS_NS: &Ident = Ident::make("status");

/// The namespace for the trust anchor proxy.
pub const TA_PROXY_SERVER_NS: &Ident = Ident::make("ta_proxy");

/// The namespace for the trust anchor signer.
pub const TA_SIGNER_SERVER_NS: &Ident = Ident::make("ta_signer");

/// The namespace for the task queue.
pub const TASK_QUEUE_NS: &Ident = Ident::make("tasks");


//------------ Property Manager Defaults ------------------------------------

/// The name of the single instance stored by the property manager.
pub const PROPERTIES_DFLT_NAME: &str = "main";


//------------ Publication Server Defaults ----------------------------------

/// The name of the single instance used by the publication server.
///
/// This is will be the scope of the object in the [`PUBSERVER_NS`]
/// namespace.
pub const PUBSERVER_DFLT: &str = "0";


//------------ Repository Defaults ------------------------------------------

/// The default sub-directory for the repository.
///
/// This is used if `repo_dir` is not given explicitly in the config file and
/// is appended to the data directory.
pub const REPOSITORY_DIR: &str = "repo";

/// The name of the subdirectory for RRDP data.
pub const REPOSITORY_RRDP_DIR: &str = "rrdp";

/// The name of the subdirectory for RRDP archive data.
pub const REPOSITORY_RRDP_ARCHIVE_DIR: &str = "archive";

/// The first RRDP serial number.
///
/// RFC 8182 says we MUST use 1 as the first serial.
pub const RRDP_FIRST_SERIAL: u64 = 1;

/// The name of the subdirectory for rsync data.
pub const REPOSITORY_RSYNC_DIR: &str = "rsync";


//------------ CA Manager Defaults -------------------------------------------

/// The minimum value for the `ca_refresh_seconds` config value.
pub const CA_REFRESH_SECONDS_MIN: u32 = 3600;

/// The maximum value for the `ca_refresh_seconds` config value.
pub const CA_REFRESH_SECONDS_MAX: u32 = 3 * 24 * 3600; // 3 days

/// The minimum value of `suspend_child_after_inactive_hours` config value.
pub const CA_SUSPEND_MIN_HOURS: u32 = 48; // 2 days


//------------ Scheduler Defaults --------------------------------------------

/// The delay before retrying a failed remote command.
pub const SCHEDULER_REQUEUE_DELAY_SECONDS: i64 = 300;

/// The number of CAs configured that stop Krill from resyncing repo at start.
pub const SCHEDULER_RESYNC_REPO_CAS_THRESHOLD: usize = 5;

/// The number of CAs configured before jitter is used when syncing at start.
pub const SCHEDULER_USE_JITTER_CAS_THRESHOLD: usize = 50;

/// The interval between re-publishing MFT/CRL if needed.
pub const SCHEDULER_INTERVAL_REPUBLISH_MINS: i64 = 5;

/// The interval between renewing objects if needed.
pub const SCHEDULER_INTERVAL_RENEW_MINS: i64 = 60;


//------------ HTTP Client Defaults ------------------------------------------

/// The HTTP client request timeout.
pub const HTTP_CLIENT_TIMEOUT_SECS: u64 = 120;

/// The maximum length of a user agent string taken from HTTP requests.
///
/// If the user agent value in an incoming request is longer than this value,
/// it will be truncated before being stored or otherwise processed.
pub const HTTP_USER_AGENT_TRUNCATE: usize = 256; 

/// The HTTP client request timeout used by the OpenID Connect auth provider.
pub const OPENID_CONNECT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;


//------------ Built-in Actors -----------------------------------------------

/// The actor used by the Krill server.
pub const ACTOR_DEF_KRILL: Actor = Actor::system("krill");

/// The actor used by the Krill TA.
pub const ACTOR_DEF_KRILLTA: Actor = Actor::system("krillta");

/// The anonymous actor.
pub const ACTOR_DEF_ANON: Actor = Actor::anonymous();

/// The actor represented by the admin token.
pub const ACTOR_DEF_ADMIN_TOKEN: Actor = Actor::system("admin-token");

/// The actor used by the Krill test bed.
pub const ACTOR_DEF_TESTBED: Actor = Actor::system("testbed");

/// The actor used by tests.
#[cfg(test)]
pub const ACTOR_DEF_TEST: Actor = Actor::system("test");


//------------ Trust Anchor --------------------------------------------------

/// The name of the handle to be used for the TA.
pub const TA_NAME: &str = "ta";

/// Returns a CA handle for the trust anchor CA.
pub fn ta_handle() -> CaHandle {
    use std::str::FromStr;
    CaHandle::from_str(TA_NAME).unwrap()
}

/// The resource class name to be used by the trust anchor.
pub fn ta_resource_class_name() -> rpki::ca::provisioning::ResourceClassName {
    "default".into()
}


//------------ Testbed -------------------------------------------------------

/// The handle of the CA used by the testbed.
pub const TESTBED_CA_NAME: &str = "testbed";

/// Returns the CA handle for the testbed.
pub fn testbed_ca_handle() -> CaHandle {
    use std::str::FromStr;
    CaHandle::from_str(TESTBED_CA_NAME).unwrap()
}


//------------ Config File Auth Provider Defaults ----------------------------
//
// Note: These must match the values used by Lagosta.

/// The log₂ of the Scrypt parameter `N` used by the UI to submit a password.
#[cfg(feature = "multi-user")]
pub const PW_HASH_LOG_N: u8 = 13;

/// The Scrypt parameter `r` used by the UI to submit a password.
#[cfg(feature = "multi-user")]
pub const PW_HASH_R: u32 = 8;

/// The Scrypt parameter `p` used by the UI to submit a password.
#[cfg(feature = "multi-user")]
pub const PW_HASH_P: u32 = 1;


//------------ Signer Defaults -----------------------------------------------

/// The validity of a newly created ID certificate. 
pub const ID_CERTIFICATE_VALIDITY_YEARS: i32 = 15;

/// The name of the default signer.
#[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
pub const DEFAULT_SIGNER_NAME: &str = "Default OpenSSL signer";

/// The name of the default signer.
#[cfg(all(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))]
pub const DEFAULT_SIGNER_NAME: &str = "Default OpenSSL signer";

/// The name of the default signer.
#[cfg(all(feature = "hsm-tests-kmip", not(feature = "hsm-tests-pkcs11")))]
pub const DEFAULT_SIGNER_NAME: &str = "(test mode) Default KMIP signer";

/// The name of the default signer.
#[cfg(all(feature = "hsm-tests-pkcs11", not(feature = "hsm-tests-kmip")))]
pub const DEFAULT_SIGNER_NAME: &str = "(test mode) Default PKCS#11 signer";

/// The name of the one-off signer.
pub const OPENSSL_ONE_OFF_SIGNER_NAME: &str = "OpenSSL one-off signer";

