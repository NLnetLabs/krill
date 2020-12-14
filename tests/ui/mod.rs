#[cfg(feature = "multi-user")]
mod openid_connect_mock;

use tokio::task;

use std::env;
use std::process::Command;

use krill::daemon::config::Config;
use krill::test::*;

pub async fn run_krill_ui_test(test_name: &str, _with_openid_server: bool) {
    #[cfg(feature = "multi-user")]
    let mock_server_join_handle = if _with_openid_server {
        openid_connect_mock::start().await
    } else {
        None
    };

    do_run_krill_ui_test(test_name).await;

    #[cfg(feature = "multi-user")]
    if _with_openid_server {
        openid_connect_mock::stop(mock_server_join_handle).await;
    }
}

async fn do_run_krill_ui_test(test_name: &str) {
    let config_path = &format!("test-resources/ui/{}.conf", test_name);
    let config = Config::read_config(&config_path).unwrap();
    start_krill(Some(config)).await;

    let test_name = test_name.to_string();

    let cypress_task = task::spawn_blocking(move || {
        // NOTE: the directory mentioned here must be the same as the directory
        // mentioned in the tests/ui/cypress_plugins/index.js file in the
        // "integrationFolder" property otherwise Cypress mysteriously complains
        // that it cannot find the spec file.
        let cypress_spec_path = format!("tests/ui/cypress_specs/{}.js", test_name);

        Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--net=host")
            .arg("--ipc=host")
            .arg("-v")
            .arg(format!("{}:/e2e", env::current_dir().unwrap().display()))
            .arg("-w")
            .arg("/e2e")
            .arg("cypress/included:5.5.0")
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
