#[cfg(feature = "multi-user")]
mod openid_connect_mock;

use OpenIDConnectMockMode::NotStarted;
use tokio::task;

use std::{env, process::ExitStatus};
use std::process::Command;

use krill::daemon::config::Config;
use krill::test::*;

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum OpenIDConnectMockMode {
    NotStarted,
    WithRPInitiatedLogout,
    WithOAuth2Revocation,
    WithNoLogoutEndpoints,
}

pub struct OpenIDConnectMockConfig {
    mode: OpenIDConnectMockMode,
    enabled_on_startup: bool,
}

#[allow(dead_code)]
impl OpenIDConnectMockConfig {
    /// Don't start the OpenID Connect mock.
    pub fn do_not_start() -> OpenIDConnectMockConfig {
        Self { mode: NotStarted, enabled_on_startup: false }
    }

    /// Start the OpenID Mock and enable it ready for use.
    pub fn enabled(mode: OpenIDConnectMockMode) -> OpenIDConnectMockConfig {
        Self { mode, enabled_on_startup: true }
    }

    /// Start the OpenID Mock initially disabled. This can be useful to prevent initial OpenID Connect Discovery
    /// succeeding before the first test runs.
    pub fn disabled(mode: OpenIDConnectMockMode) -> OpenIDConnectMockConfig {
        Self { mode, enabled_on_startup: false }
    }

    pub fn mode(&self) -> OpenIDConnectMockMode {
        self.mode
    }

    pub fn enabled_on_startup(&self) -> bool {
        self.enabled_on_startup
    }
}

#[cfg(not(feature = "multi-user"))]
pub async fn run_krill_ui_test(
    test_name: &str,
    _: OpenIDConnectMockConfig,
) {
    assert!(do_run_krill_ui_test(test_name).await);
}

#[cfg(feature = "multi-user")]
pub async fn run_krill_ui_test(
    test_name: &str,
    openid_connect_mock_config: OpenIDConnectMockConfig,
) {
    let op_handle = match openid_connect_mock_config.mode() {
        NotStarted => None,
        _ => Some(openid_connect_mock::start(openid_connect_mock_config, 1).await),
    };

    let test_result = do_run_krill_ui_test(test_name).await;

    if let Some(handle) = op_handle {
        openid_connect_mock::stop(handle).await;
    }

    assert!(test_result);
}

struct CypressRunner {
    status: ExitStatus
}
impl CypressRunner {
    pub async fn run(test_name: &str) -> Self {
        let test_name = test_name.to_string();

        ctrlc::set_handler(move || {
            // If `cargo test` is stopped with CTRL-C the background Cypress Docker container continues to run. This
            // prevents the next run of `cargo test` from working as the container unexpectedly already exists. Tell
            // Docker to kill it to avoid leaving it lying around.
            Command::new("docker").arg("kill").arg("cypress").spawn().expect("Failed to kill Cypress Docker container");    
        }).expect("Error setting Ctrl-C handler");

        let task = task::spawn_blocking(move || {
            // NOTE: the directory mentioned here must be the same as the directory
            // mentioned in the tests/ui/cypress/plugins/index.js file in the
            // "integrationFolder" property otherwise Cypress mysteriously complains
            // that it cannot find the spec file.
            let cypress_spec_path = format!("tests/ui/cypress/specs/{}.js", test_name);

            let mut cmd = Command::new("docker");

            cmd
                .arg("run")
                .arg("--name").arg("cypress")
                .arg("--rm")
                .arg("--net=host")
                .arg("--ipc=host")
                .arg("-v").arg(format!("{}:/e2e", env::current_dir().unwrap().display()))
                .arg("-w").arg("/e2e");

            if let Ok(debug_level) = std::env::var("CYPRESS_DEBUG") {
                // Example values:
                //   - To get LOTS of Cypress logging:           CYPRESS_DEBUG=cypress:*
                //   - To get logging relating to HTTP requests: CYPRESS_DEBUG=cypress:proxy:http:*
                cmd
                    .arg("-e").arg(format!("DEBUG={}", debug_level));
            }

            if std::env::var("CYPRESS_INTERACTIVE").is_ok() {
                // After running `cargo test` a Chrome browser should open from the Cypress Docker container on your local
                // X server. For this to work you might need to run this command in your shell prior to `cargo test`:
                //   xhost +
                cmd
                    .arg("-v").arg(format!("/tmp/.X11-unix:/tmp/.X11-unix"))
                    .arg("-e").arg("DISPLAY")
                    .arg("--entrypoint").arg("cypress");
            }

            cmd.arg("cypress/included:6.8.0");

            if std::env::var("CYPRESS_INTERACTIVE").is_ok() {
                cmd
                    .arg("open")
                    .arg("--project").arg(".");
            } else {
                cmd
                    .arg("--spec").arg(cypress_spec_path);
            }

            cmd
                .arg("--browser").arg("chrome")
                .status()
                .expect("Failed to run Cypress Docker UI test suite")
        }).await;

        Self {
            status: task.unwrap()
        }
    }

    pub fn success(self) -> bool {
        self.status.success()
    }
}

async fn do_run_krill_ui_test(test_name: &str) -> bool {
    krill::constants::enable_test_mode();
    let config_path = &format!("test-resources/ui/{}.conf", test_name);
    let config = Config::read_config(&config_path).unwrap();

    // Start Krill as a Tokio task in the background and wait just until we can tell that it has started.
    start_krill_with_custom_config(config).await;

    // Run the specified Cypress UI test suite and wait for it to finish
    CypressRunner::run(test_name).await.success()
}
