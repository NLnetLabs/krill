#[cfg(feature = "multi-user")]
mod openid_connect_mock;

use tokio::task;

use std::env;
use std::process::Command;

use krill::daemon::config::Config;
use krill::test::*;

#[allow(dead_code)]
pub enum TestAuthProviderConfig {
    None,
    OIDCProviderWithRPInitiatedLogout,
    OIDCProviderWithOAuth2Revocation,
}

pub async fn run_krill_ui_test(test_name: &str, openid_connect_mock_config: TestAuthProviderConfig, testbed_enabled: bool) {
    #[cfg(feature = "multi-user")]
    let op_handle = match openid_connect_mock_config {
        TestAuthProviderConfig::OIDCProviderWithRPInitiatedLogout |
        TestAuthProviderConfig::OIDCProviderWithOAuth2Revocation => {
            Some(openid_connect_mock::start(openid_connect_mock_config).await)
        }
        _ => None
    };

    do_run_krill_ui_test(test_name, testbed_enabled).await;

    #[cfg(feature = "multi-user")]
    if let Some(handle) = op_handle {
        openid_connect_mock::stop(handle).await;
    }
}

async fn do_run_krill_ui_test(test_name: &str, testbed_enabled: bool) {
    krill::constants::enable_test_mode();
    let config_path = &format!("test-resources/ui/{}.conf", test_name);
    let config = Config::read_config(&config_path).unwrap();
    start_krill(Some(config), testbed_enabled).await;

    let test_name = test_name.to_string();

    let cypress_task = task::spawn_blocking(move || {
        // NOTE: the directory mentioned here must be the same as the directory
        // mentioned in the tests/ui/cypress/plugins/index.js file in the
        // "integrationFolder" property otherwise Cypress mysteriously complains
        // that it cannot find the spec file.
        let cypress_spec_path = format!("tests/ui/cypress/specs/{}.js", test_name);

        Command::new("docker")
            .arg("run")
            .arg("--name")
            .arg("cypress")
            .arg("--rm")
            .arg("--net=host")
            .arg("--ipc=host")
            .arg("-v")
            .arg(format!("{}:/e2e", env::current_dir().unwrap().display()))
            .arg("-w")
            .arg("/e2e")

            // Uncomment the next line to enable LOTS of Cypress logging.
            // .arg("-e").arg("DEBUG=cypress:*")

            // Uncomment the next line to enable a subset of Cypress logging
            // that is useful for investigating .get() and .intercept()
            // behaviour.
            // .arg("-e").arg("DEBUG=cypress:proxy:http:*")

            .arg("cypress/included:6.2.0")
            .arg("--browser")
            .arg("chrome")
            .arg("--spec")
            .arg(cypress_spec_path)
            .status()
            .expect("Failed to run Cypress Docker UI test suite")
    });

    let cypress_exit_status = cypress_task.await.unwrap();

    assert!(cypress_exit_status.success());
}
