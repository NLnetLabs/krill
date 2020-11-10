use assert_cmd::prelude::*;
use std::process::Command;
use std::env;

pub fn run_krill_ui_test(test_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Remove the Krill data directory. Assumes that the .conf file passed to
    // Krill sets data_dir to /tmp/krill... touching the host filesystem like
    // this isn't nice...
    Command::new("rm").arg("-R").arg("/tmp/krill").status()?;

    let mut krill_process = Command::cargo_bin("krill")?
        .arg("-c")
        .arg(format!("test-resources/ui/{}.conf", test_name))
        .spawn()?;

    // NOTE: the directory mentioned here must be the same as the directory
    // mentioned in the tests/ui/cypress_plugins/index.js file in the
    // "integrationFolder" property otherwise Cypress mysteriously complains
    // that it cannot find the spec file.
    let cypress_spec_path = format!("tests/ui/cypress_specs/{}.js", test_name);

    let assert = Command::new("docker")
        .arg("run")
        .arg("--net=host")
        .arg("--ipc=host")
        .arg("-v")
        .arg(format!("{}:/e2e", env::current_dir()?.display()))
        .arg("-w")
        .arg("/e2e")
        .arg("cypress/included:5.5.0")
        .arg("--browser")
        .arg("chrome")
        .arg("--spec")
        .arg(cypress_spec_path)
        .assert();

    krill_process.kill()?;

    assert.success();

    Ok(())
}