#![allow(dead_code)] // Different tests use different parts.

use std::env;
use std::str::FromStr;
use std::time::Duration;
use url::Url;
use log::LevelFilter;
use log::{debug, error};
use reqwest::StatusCode;
use rpki::uri;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ChildRequest, ParentResponse, ServiceUri
};
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::{Asn, ResourceSet};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use krill::commons::api;
use krill::commons::api::Token;
use krill::commons::crypto::OpenSslSignerConfig;
use krill::commons::util::httpclient;
use krill::cli::client::KrillClient;
use krill::constants::REPOSITORY_DIR;
use krill::daemon::config::{
    AuthType, Config, ConfigDefaults, HttpsMode, IssuanceTimingConfig,
    LogType, MetricsConfig, RrdpUpdatesConfig, SignerConfig,
    SignerReference, SignerType, TestBed,
};
use krill::daemon::http::tls_keys::HTTPS_SUB_DIR;
use krill::daemon::http::server;
use krill::ta::TaTimingConfig;


//------------ TestConfig ----------------------------------------------------

/// A test config builder.
pub struct TestConfig {
    storage_uri: Url,
    data_dir: TempDir,
    port: u16,
    enable_testbed: bool,
    enable_ca_refresh: bool,
    enable_suspend: bool,
    second_signer: bool,
}

impl TestConfig {
    pub fn mem_storage() -> Self {
        let data_dir = TempDir::new().unwrap();
        Self::new(
            Url::parse(
                &format!(
                    "memory://{}", hex::encode(rand::random::<[u8; 8]>())
                )
            ).unwrap(),
            data_dir,
        )
    }

    pub fn file_storage() -> Self {
        let data_dir = TempDir::new().unwrap();
        Self::new(
            Url::parse(
                &format!("local://{}/data/", data_dir.path().display())
            ).unwrap() ,
            data_dir,
        )
    }

    fn new(storage_uri: Url, data_dir: TempDir) -> Self {
        Self {
            storage_uri,
            data_dir,
            port: ConfigDefaults::port(),
            enable_testbed: false,
            enable_ca_refresh: false,
            enable_suspend: false,
            second_signer: false,
        }
    }

    pub fn alternative_port(mut self) -> Self {
        self.port += 1;
        self
    }

    pub fn enable_testbed(mut self) -> Self {
        self.enable_testbed = true;
        self
    }

    pub fn enable_ca_refresh(mut self) -> Self {
        self.enable_ca_refresh = true;
        self
    }

    pub fn enable_suspend (mut self) -> Self {
        self.enable_suspend = true;
        self
    }

    pub fn enable_second_signer(mut self) -> Self {
        self.second_signer = true;
        self
    }

    #[allow(unused_mut)] // for mut self if feature = "hsm"
    pub fn finalize(mut self) -> (Config, TempDir) {
        let ip = ConfigDefaults::ip();
        let port = self.port;

        let https_mode = HttpsMode::Generate;

        let log_level = if env::var("KRILLTEST_DEBUG").is_ok() {
            LevelFilter::Debug
        }
        else {
            eprintln!(
                "Limiting Krill log output. \
                 Set KRILLTEST_DEBUG=1 to enable debug log to stderr."
            );
            LevelFilter::Error
        };
        let log_type = LogType::Stderr;
        let syslog_facility = ConfigDefaults::syslog_facility();
        let auth_type = AuthType::AdminToken;
        let admin_token = Token::from("secret");
        #[cfg(feature = "multi-user")]
        let auth_users = None;
        #[cfg(feature = "multi-user")]
        let auth_openidconnect = None;
        let auth_roles = ConfigDefaults::auth_roles();

        let default_signer = SignerReference::default();
        let one_off_signer = SignerReference::default();
        let signer_probe_retry_seconds =
            ConfigDefaults::signer_probe_retry_seconds();

        // Multiple signers are only needed and can only be configured when
        // the "hsm" feature is enabled.
        #[cfg(not(feature = "hsm"))]
        {
            self.second_signer = false;
        }

        let signers = match self.second_signer {
            false => ConfigDefaults::signers(),
            true => vec![SignerConfig::new(
                "Second Test Signer".to_string(),
                SignerType::OpenSsl(OpenSslSignerConfig::default()),
            )],
        };

        let ca_refresh_seconds =
            if self.enable_ca_refresh { 1 } else { 86400 };
        let ca_refresh_jitter_seconds =
            if self.enable_ca_refresh { 0 } else { 86400 };
        let ca_refresh_parents_batch_size = 10;
        let post_limit_api = ConfigDefaults::post_limit_api();
        let post_limit_rfc8181 = ConfigDefaults::post_limit_rfc8181();
        let post_limit_rfc6492 = ConfigDefaults::post_limit_rfc6492();
        let post_protocol_msg_timeout_seconds =
            ConfigDefaults::post_protocol_msg_timeout_seconds();

        let bgp_risdumps_enabled = false;
        let bgp_risdumps_v4_uri = ConfigDefaults::bgp_risdumps_v4_uri();
        let bgp_risdumps_v6_uri = ConfigDefaults::bgp_risdumps_v6_uri();

        let roa_aggregate_threshold = 3;
        let roa_deaggregate_threshold = 2;

        let timing_publish_next_hours =
            ConfigDefaults::timing_publish_next_hours();
        let timing_publish_next_jitter_hours =
            ConfigDefaults::timing_publish_next_jitter_hours();
        let timing_publish_hours_before_next =
            ConfigDefaults::timing_publish_hours_before_next();
        let timing_child_certificate_valid_weeks =
            ConfigDefaults::timing_child_certificate_valid_weeks();
        let timing_child_certificate_reissue_weeks_before =
            ConfigDefaults::timing_child_certificate_reissue_weeks_before();
        let timing_roa_valid_weeks = ConfigDefaults::timing_roa_valid_weeks();
        let timing_roa_reissue_weeks_before =
            ConfigDefaults::timing_roa_reissue_weeks_before();
        let timing_aspa_valid_weeks =
            ConfigDefaults::timing_aspa_valid_weeks();
        let timing_aspa_reissue_weeks_before =
            ConfigDefaults::timing_aspa_reissue_weeks_before();
        let timing_bgpsec_valid_weeks =
            ConfigDefaults::timing_bgpsec_valid_weeks();
        let timing_bgpsec_reissue_weeks_before =
            ConfigDefaults::timing_bgpsec_reissue_weeks_before();

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

        let testbed = if self.enable_testbed {
            krill::constants::enable_test_mode();
            krill::constants::enable_test_announcements();
            Some(TestBed::new(
                uri::Rsync::from_str("rsync://localhost/ta/ta.cer").unwrap(),
                uri::Https::from_string(
                    format!("https://localhost:{}/ta/ta.cer", port)
                ).unwrap(),
                uri::Https::from_string(
                    format!("https://localhost:{}/rrdp/", port)
                ).unwrap(),
                uri::Rsync::from_str("rsync://localhost/repo/").unwrap(),
            ))
        } else {
            None
        };

        let suspend_child_after_inactive_seconds =
            if self.enable_suspend { Some(3) } else { None };

        let mut res = Config {
            ip,
            port,
            https_mode,
            storage_uri: self.storage_uri,
            use_history_cache: false,
            tls_keys_dir: Some(self.data_dir.path().join(HTTPS_SUB_DIR)),
            repo_dir: Some(self.data_dir.path().join(REPOSITORY_DIR)),
            ta_support_enabled: false, /* but, enabled by testbed where
                                        * applicable */
            ta_signer_enabled: false, // same as above
            pid_file: Some(self.data_dir.path().join("krill.pid")),
            service_uri: None,
            log_level,
            log_type,
            log_file: None,
            syslog_facility,
            admin_token,
            auth_type,
            #[cfg(feature = "multi-user")]
            auth_users,
            #[cfg(feature = "multi-user")]
            auth_openidconnect,
            auth_roles,
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
        };
        let _ = res.init_logging(); // Allow failing on repeast attempts.
        res.process().unwrap();
        (res, self.data_dir)
    }
}


//------------ KrillServer ---------------------------------------------------

/// A test Krill server.
pub struct KrillServer {
    join: JoinHandle<()>,
    running: Option<oneshot::Receiver<()>>,
    client: KrillClient,
}

impl KrillServer {
    /// Starts a default test server.
    ///
    /// The server will use memory storage. The function will start the
    /// server and wait for it to become ready.
    pub async fn start() -> (Self, TempDir) {
        let (config, data_dir) = TestConfig::mem_storage().finalize();
        (Self::start_with_config(config).await, data_dir)
    }

    /// Starts a test server with testbed enabled.
    ///
    /// The server will use memory storage. The function will start the
    /// server and wait for it to become ready.
    pub async fn start_with_testbed() -> (Self, TempDir) {
        let (config, data_dir)
            = TestConfig::mem_storage().enable_testbed().finalize();
        (Self::start_with_config(config).await, data_dir)
    }

    /// Starts a test server with testbed enabled and a modified config.
    pub async fn start_with_config_testbed(
        op: impl FnOnce(&mut Config)
    ) -> (Self, TempDir) {
        let (mut config, data_dir)
            = TestConfig::mem_storage().enable_testbed().finalize();
        op(&mut config);
        (Self::start_with_config(config).await, data_dir)
    }

    /// Starts a test server with file storage with testbed enabled.
    ///
    /// The server will use memory storage. The function will start the
    /// server and wait for it to become ready.
    pub async fn start_with_file_storage_and_testbed() -> (Self, TempDir) {
        let (config, data_dir)
            = TestConfig::file_storage().enable_testbed().finalize();
        (Self::start_with_config(config).await, data_dir)
    }

    /// Starts a second test server with testbed enabled.
    ///
    /// The server will use memory storage. The function will start the
    /// server and wait for it to become ready.
    pub async fn start_second_with_testbed() -> (Self, TempDir) {
        let (config, data_dir) = TestConfig::mem_storage()
            .alternative_port().enable_testbed().enable_second_signer()
            .finalize();
        (Self::start_with_config(config).await, data_dir)
    }

    /// Starts a publication daemon.
    ///
    /// The server will use the given interval in seconds for its RRDP
    /// udpates.
    pub async fn start_pubd(
        rrdp_delta_min_interval_seconds: u32
    ) -> (Self, TempDir) {
        let (mut config, data_dir) = TestConfig::mem_storage()
            .alternative_port()
            .enable_second_signer() // XXX Not sure why?
            .finalize();
        config.rrdp_updates_config.rrdp_delta_interval_min_seconds =
            rrdp_delta_min_interval_seconds;
        let port = config.port;
        let server = Self::start_with_config(config).await;
        server.pubserver_init(port).await;
        (server, data_dir)
    }

    /// Starts a test server with the given config.
    ///
    /// This will start the server and wait for it to become ready.
    pub async fn start_with_config(config: Config) -> Self {
        let uri = ServiceUri::from_str(
            &format!(
                "https://{}:{}/",
                config.ip.first().unwrap(), config.port
            )
        ).unwrap();
        let client = KrillClient::new(uri, config.admin_token.clone());
        let (tx, running) = oneshot::channel();
        let mut res = Self {
            join: tokio::spawn(async {
                if let Err(err) = server::start_krill_daemon(
                    config.into(), Some(tx)
                ).await {
                    error!("Krill failed to start: {}", err);
                }
            }),
            running: Some(running),
            client,
        };
        res.ready().await;
        res
    }

    async fn ready(&mut self) {
        let running = match self.running.take() {
            Some(running) => running,
            None => return
        };
        assert!(running.await.is_ok());
        match timeout(
            Duration::from_secs(1),
            self.client.authorized(),
        ).await {
            Ok(Ok(_)) => { debug!("health check succeded") },
            err => panic!("health check failed: {:?}", err),
        }
    }

    pub async fn pubserver_init(&self, port: u16) {
        self.client().pubserver_init(
            uri::Https::from_str(
                &format!("https://localhost:{}/test-rrdp/", port)
            ).unwrap(),
            uri::Rsync::from_str(
                "rsync://localhost/dedicated-repo/"
            ).unwrap(),
        ).await.unwrap();
    }

    /// Aborts the server and waits for it to conclude cleanup.
    pub async fn abort(self) {
        self.join.abort();
        let _ = self.join.await;
    }

    /// Returns a Krill client for this server.
    pub fn client(&self) -> &KrillClient {
        &self.client
    }

    /// Returns an expected files check object.
    pub fn expected_objects<'s>(
        &'s self, ca: &'s CaHandle
    ) -> ExpectedObjects<'s> {
        ExpectedObjects::new(self, ca)
    }
}


impl KrillServer {
    /// Creates a CA publishing in the built-in publisher.
    pub async fn create_ca_with_repo(&self, ca: &CaHandle) {
        // Create the CA
        self.client.ca_add(ca.clone()).await.unwrap();

        // Add the CA as a publisher
        let request = self.client().repo_request(ca).await.unwrap();
        self.client().publishers_add(request).await.unwrap();

        // Get a Repository Response for the CA.
        let response = self.client().publisher_response(
            &ca.convert()
        ).await.unwrap();

        // Update the repo for the CA.
        self.client().repo_update(ca, response).await.unwrap();
    }

    /// Registers a CA with a parent managed by the same server.
    pub async fn register_ca_with_parent(
        &self, ca: &CaHandle, parent: &CaHandle, resources: &ResourceSet
    ) {
        let request = self.client().child_request(ca).await.unwrap();
        let response = self.add_child(
            parent, ca.convert(), request, resources.clone()
        ).await;
        self.client.parent_add(
            ca, api::ParentCaReq::new(parent.convert(), response)
        ).await.unwrap();
        assert!(self.wait_for_ca_resources(ca, resources).await);
    }

    /// Add a child to the CA.
    pub async fn add_child(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        child_request: ChildRequest,
        resources: ResourceSet,
    ) -> ParentResponse {
        let id_cert = child_request.validate().unwrap();
        self.client.child_add(ca, child, resources, id_cert).await.unwrap()
    }

    pub async fn ca_key_for_rcn(
        &self, ca: &CaHandle, rcn: &ResourceClassName
    ) -> api::CertifiedKeyInfo {
        self.client.ca_details(ca).await.unwrap()
            .resource_classes().get(rcn).unwrap()
            .current_key().unwrap().clone()
    }

    pub async fn ca_new_key_for_rcn(
        &self, ca: &CaHandle, rcn: &ResourceClassName,
    ) -> api::CertifiedKeyInfo {
        self.client.ca_details(ca).await.unwrap()
            .resource_classes().get(rcn).unwrap()
            .new_key().unwrap().clone()
    }

    pub async fn current_ca_resources(&self, ca: &CaHandle) -> ResourceSet {
        let details = self.client().ca_details(ca).await.unwrap();

        let mut res = ResourceSet::default();
        for rc in details.resource_classes().values() {
            if let Some(resources) = rc.current_resources() {
                res = res.union(resources)
            }
        }
        res
    }

    pub async fn check_configured_roas(
        &self, ca: &CaHandle, expected: &[api::RoaConfiguration]
    ) -> bool {
        let roas = self.client().roas_list(ca).await.unwrap().unpack();
        assert_eq!(roas.len(), expected.len());

        // Copy the expected configs, but convert them to an explicit max-len
        // because Krill always stores configs that way to avoid duplicate
        // equivalent entries.
        let expected = expected.iter().map(|entry| {
            entry.clone().into_explicit_max_length()
        }).collect::<Vec<_>>();

        for roa in roas.iter().map(|item| item.roa_configuration())
        {
            if !expected.contains(roa) {
                let expected_strs: Vec<_> = expected.into_iter().map(|e| {
                    e.to_string()
                }).collect();
                eprintln!(
                    "Actual configuration: '{}' not in expected: {}",
                    roa, expected_strs.join(", ")
                );
                return false
            }
        }
        true
    }

    pub async fn wait_for_ca_resources(
        &self, ca: &CaHandle, resources: &ResourceSet
    ) -> bool {
        for _ in 0..300 {
            sleep_millis(100).await;
            if self.current_ca_resources(ca).await.contains(resources) {
                return true
            }
        }
        false
    }

    pub async fn wait_for_state_new_key(&self, ca: &CaHandle) -> bool {
        for _ in 0..300 {
            let ca = self.client().ca_details(ca).await.unwrap();

            // wait for ALL RCs to become state new key
            let rc_map = ca.resource_classes();

            let expected = rc_map.len();
            let mut found = 0;

            for rc in rc_map.values() {
                if let api::ResourceClassKeysInfo::RollNew(_) = rc.keys() {
                    found += 1;
                }
            }

            if found == expected {
                return true;
            }

            sleep_millis(100).await
        }
        false
    }

    pub async fn wait_for_state_active(&self, ca: &CaHandle) -> bool {
        for _ in 0..300 {
            let ca = self.client().ca_details(ca).await.unwrap();

            // wait for ALL RCs to become state active key
            let rc_map = ca.resource_classes();

            let expected = rc_map.len();
            let mut found = 0;

            for rc in rc_map.values() {
                if let api::ResourceClassKeysInfo::Active(_) = rc.keys() {
                    found += 1;
                }
            }

            if found == expected {
                return true;
            }

            sleep_millis(100).await
        }
        false
    }

    pub async fn http_get(
        &self, rel_url: &str
    ) -> Result<String, httpclient::Error> {
        httpclient::get_text(
            &format!("{}{}", self.client().base_uri(), rel_url),
            None
        ).await
    }

    pub async fn http_get_404(
        &self, rel_url: &str
    ) -> bool {
        match httpclient::get_text(
            &format!("{}{}", self.client().base_uri(), rel_url),
            None
        ).await {
            Ok(_) => false,
            Err(err) if err.status_code() == Some(StatusCode::NOT_FOUND) => {
                true
            }
            Err(err) => panic!("{}", err),
        }
    }
}


//------------ ExpectedObjects -----------------------------------------------

pub struct ExpectedObjects<'a> {
    pub server: &'a KrillServer,
    pub ca: &'a CaHandle,
    pub files: Vec<String>,
}

impl<'a> ExpectedObjects<'a> {
    pub fn new(
        server: &'a KrillServer,
        ca: &'a CaHandle,
    ) -> Self {
        Self { server, ca, files: Vec::new() }
    }

    pub fn push(&mut self, file: String) {
        self.files.push(file);
    }

    pub async fn push_mft_and_crl(&mut self, rcn: &ResourceClassName) {
        let rc_key = self.server.ca_key_for_rcn(self.ca, rcn).await;
        self.push(rc_key.incoming_cert().mft_name().to_string());
        self.push(rc_key.incoming_cert().crl_name().to_string());
    }

    pub async fn push_new_key_mft_and_crl(&mut self, rcn: &ResourceClassName) {
        let rc_key = self.server.ca_new_key_for_rcn(self.ca, rcn).await;
        self.push(rc_key.incoming_cert().mft_name().to_string());
        self.push(rc_key.incoming_cert().crl_name().to_string());
    }

    pub async fn push_cer(&mut self, ca: &CaHandle, rcn: &ResourceClassName) {
        let rc_key = self.server.ca_key_for_rcn(ca, rcn).await;
        self.push(api::ObjectName::new(rc_key.key_id(), "cer").to_string())
    }

    pub fn push_roas<'b>(
        &mut self, roas: impl IntoIterator<Item = &'b api::RoaConfiguration>
    ) {
        self.extend(roas.into_iter().map(|roa| {
            api::ObjectName::from(
                &roa.payload().into_explicit_max_length()
            ).to_string()
        }))
    }

    pub async fn wait_for_published(&self) -> bool {
        self.wait_for_published_at(self.server).await
    }

    pub async fn wait_for_published_at(&self, server: &KrillServer) -> bool {
        let publisher = self.ca.convert();

        for _ in 0..600 {
            sleep_millis(100).await;
            let details = server.client.publisher_details(
                &publisher
            ).await.unwrap();
            let current_files = details.current_files();
            if current_files.len() == self.files.len() {
                let current_files: Vec<_> =
                    current_files.iter().map(|p| p.uri()).collect();
                let mut all_matched = true;
                for o in &self.files {
                    if !current_files.iter().any(|uri| uri.ends_with(o)) {
                        all_matched = false;
                    }
                }
                if all_matched {
                    return true;
                }
            }
        }

        let details = server.client.publisher_details(
            &publisher
        ).await.unwrap();

        eprintln!("Published files didn’t match for {}", self.ca);
        eprintln!("Found:");
        for file in details.current_files() {
            eprintln!("  {}", file.uri());
        }
        eprintln!("Expected:");
        for file in &self.files {
            eprintln!("  {}", file);
        }

        false
    }
}

impl std::iter::Extend<String> for ExpectedObjects<'_> {
    fn extend<T: IntoIterator<Item = String>>(&mut self, iter: T) {
        self.files.extend(iter)
    }
}


//------------ Misc Helpers --------------------------------------------------

pub fn ca_handle(s: &str) -> CaHandle {
    CaHandle::from_str(s).unwrap()
}

pub fn rcn(nr: u32) -> ResourceClassName {
    ResourceClassName::from(nr)
}

pub fn resources(asn: &str, v4: &str, v6: &str) -> ResourceSet {
    ResourceSet::from_strs(asn, v4, v6).unwrap()
}

pub fn asn(asn: &str) -> Asn {
    Asn::from_str(asn).unwrap()
}

pub fn ipv4_resources(v4: &str) -> ResourceSet {
    resources("", v4, "")
}

pub fn roa_conf(s: &str) -> api::RoaConfiguration {
    api::RoaConfiguration::from_str(s).unwrap()
}

pub fn roa_payload(s: &str) -> api::RoaPayload {
    api::RoaPayload::from_str(s).unwrap()
}

pub fn aspa_def(s: &str) -> api::AspaDefinition {
    api::AspaDefinition::from_str(s).unwrap()
}

pub async fn sleep_seconds(secs: u64) {
    sleep(Duration::from_secs(secs)).await
}

pub async fn sleep_millis(secs: u64) {
    sleep(Duration::from_millis(secs)).await
}

/// Checks if a result has certain non-200 HTTP status code.
///
/// Returns `true` if it does, returns `false` if the result is `Ok(_)`
/// and panics in all other cases.
pub fn check_status<T>(
    res: Result<T, httpclient::Error>,
    code: StatusCode,
) -> bool {
    match res {
        Ok(_) => false,
        Err(err) => {
            match err.status_code() {
                Some(some) => some == code,
                None => {
                    panic!("{}", err);
                }
            }
        }
    }
}

/// Checks if a result has bad request status.
///
/// Returns `true` if it does, returns `false` if the result is `Ok(_)`
/// and panics in all other cases.
pub fn check_bad_request<T>(res: Result<T, httpclient::Error>) -> bool {
    check_status(res, StatusCode::BAD_REQUEST)
}

/// Checks if a result has bad request status.
///
/// Returns `true` if it does, returns `false` if the result is `Ok(_)`
/// and panics in all other cases.
pub fn check_not_found<T>(res: Result<T, httpclient::Error>) -> bool {
    check_status(res, StatusCode::NOT_FOUND)
}

