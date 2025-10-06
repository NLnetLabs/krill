//! Rust integration test to verify that invoking the restricted create CA
//! REST API requires a valid bearer token.

use hyper::StatusCode;
use krill::cli::client::KrillClient;
use krill::commons::httpclient;

mod common;


#[tokio::test]
async fn auth_check() {
    let (server, _tempdir) = common::KrillServer::start().await;

    // Get a client with a changed auth token.
    let client = KrillClient::new(
        server.server_uri().clone(), 
        Some("wrong secret".into())
    ).unwrap();

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
