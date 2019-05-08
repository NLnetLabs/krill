extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;

use krill_client::KrillClient;
use krill_client::options::{
    Command,
    Options
};
use krill_client::report::{
    ApiResponse,
    ReportFormat
};
use krill_commons::util::test;

/// Tests that the server can be started and a health check can be done
/// through the CLI
#[test]
fn health_check() {
    krill_daemon::test::test_with_krill_server(|_d| {

        let krillc_opts = Options::new(
            test::https_uri("https://localhost:3000/"),
            "secret",
            ReportFormat::Default,
            Command::Health
        );

        let res = KrillClient::test(krillc_opts);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res, ApiResponse::Health)
    });
}

