#[cfg(feature = "multi-user")]
mod openid_connect_mock;

use tokio::task;

use std::env;
use std::process::Command;

use krill::daemon::config::Config;
use krill::test::*;

pub async fn run_krill_ui_test(test_name: &str, _with_openid_server: bool, testbed_enabled: bool) {
    #[cfg(feature = "multi-user")]
    let mock_server_join_handle = if _with_openid_server {
        openid_connect_mock::start(1).await
    } else {
        None
    };

    do_run_krill_ui_test(test_name, testbed_enabled).await;

    #[cfg(feature = "multi-user")]
    if _with_openid_server {
        openid_connect_mock::stop(mock_server_join_handle).await;
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
    });

    let cypress_exit_status = cypress_task.await.unwrap();

    assert!(cypress_exit_status.success());
}
