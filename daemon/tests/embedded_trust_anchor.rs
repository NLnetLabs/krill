extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;

use krill_client::options::{Command, TrustAnchorCommand};
use krill_daemon::test::{krill_admin, test_with_krill_server};

#[test]
fn embedded_trust_anchor() {
    test_with_krill_server(|_d| {
        let command = Command::TrustAnchor(TrustAnchorCommand::Init);
        krill_admin(command);

        let command = Command::TrustAnchor(TrustAnchorCommand::Show);
        krill_admin(command);

        //        let command = Command::TrustAnchor(TrustAnchorCommand::Publish);
        //        let _res = execute_krillc_command(command);
    });
}
