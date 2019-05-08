extern crate krill_daemon;
extern crate krill_client;

use krill_daemon::test::{ test_with_krill_server, execute_krillc_command };
use krill_client::options::{Command, TrustAnchorCommand};

#[test]
fn embedded_trust_anchor() {
    test_with_krill_server(|_d|{

        let command = Command::TrustAnchor(TrustAnchorCommand::Init);
        execute_krillc_command(command);

        let command = Command::TrustAnchor(TrustAnchorCommand::Show);
        let _res = execute_krillc_command(command);
    });
}