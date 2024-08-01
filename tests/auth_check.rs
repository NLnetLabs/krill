//! Rust integration test to verify that invoking the restricted create CA
//! REST API requires a valid bearer token.

use hyper::StatusCode;
use krill::commons::util::httpclient;

mod common;


#[tokio::test]
async fn auth_check() {
    let (server, _tempdir) = common::KrillServer::start().await;

    // Get a client and change its auth token.
    let mut client = server.client().clone();
    client.set_token("different token".into());

    // Now try and create a CA. This should fail with a “Forbidden” error.
    let res = client.ca_add(common::ca_handle("dummy_ca")).await;
    dbg!(&res);
    assert!(
        matches!(
            res,
            Err(
                httpclient::Error::ErrorResponseWithJson(
                    _, StatusCode::UNAUTHORIZED, _
                )
                | httpclient::Error::Forbidden(_)
            )
        )
    );
}
