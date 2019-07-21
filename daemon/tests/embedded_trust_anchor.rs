extern crate krill_daemon;
extern crate krill_client;
extern crate krill_commons;

use krill_daemon::test::{test_with_krill_server, krill_admin};
use krill_client::options::{Command, TrustAnchorCommand};

#[test]
fn embedded_trust_anchor() {
    test_with_krill_server(|_d|{

        let command = Command::TrustAnchor(TrustAnchorCommand::Init);
        krill_admin(command);

        let command = Command::TrustAnchor(TrustAnchorCommand::Show);
        krill_admin(command);

//        let command = Command::TrustAnchor(TrustAnchorCommand::Publish);
//        let _res = execute_krillc_command(command);
    });
}