use assert_cmd::prelude::*; // Add methods on commands
use std::{process::Command, env}; // Run programs

#[test]
#[cfg_attr(not(feature = "web-ui-tests"), ignore)]
fn experimental_web_ui_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut krill_process = Command::cargo_bin("krill")?
        .arg("-c")
        .arg("test-resources/multi-user-master-token.conf")
        .spawn()?;

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
        .assert();
        
    krill_process.kill()?;

    assert.success();

    Ok(())
}