//! Rust integration test to verify that invoking the restricted create CA REST API requires a valid bearer token.
use std::str::FromStr;

use rpki::ca::idexchange::Handle;

use krill::{
    commons::api::Token,
    test::{init_ca, start_krill_with_custom_config, test_config, tmp_storage},
};

extern crate krill;

#[tokio::test]
#[should_panic]
async fn auth_check() {
    // Use a copy of the default test Krill config but change the server admin token thereby hopefully causing the
    // bearer token sent by the test suite support functions not to match and thus be rejected which in turn should
    // cause a Rust panic.
    let storage_uri = tmp_storage();
    let mut config = test_config(&storage_uri, None, false, false, false, false);
    config.admin_token = Token::from("wrong secret");

    // Start Krill with the customized config
    start_krill_with_custom_config(config).await;

    // Try and create a CA. The test suite support function `init_ca()` will invoke the create CA REST API passing the
    // bearer token that is hard-coded into the test support suite functions ('secret').
    let ca_handle = Handle::from_str("dummy_ca").unwrap();
    init_ca(&ca_handle).await;

    // A Rust panic should have occurred. If not, this test will fail due to the use of the #[should_panic] attribute.
}
