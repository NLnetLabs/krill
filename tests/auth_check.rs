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

#[tokio::test]
#[cfg(unix)]
async fn auth_check_unix() {
    use std::collections::HashMap;

    use krill::cli::client::ServerUri;

    let (mut config, _tempdir) = common::TestConfig::mem_storage()
        .enable_testbed().enable_ca_refresh().finalize();

    // The user that is executing the test gets read access to everything
    let uid = nix::unistd::Uid::current();
    let user = nix::unistd::User::from_uid(uid).unwrap().unwrap();
    let file_sock = tempfile::NamedTempFile::new().unwrap();
    config.unix_socket_enabled = true;
    config.unix_socket = Some(file_sock.path().into());
    config.unix_users = HashMap::from([(user.name, "readonly".to_string())]);

    let _server = common::KrillServer::start_with_config_unix(config).await;

    let client = KrillClient::new(
        ServerUri::try_from(
            format!("unix://{}", file_sock.path().display())
        ).unwrap(), 
        None
    ).unwrap();
    
    // Now try and create a CA. This should fail with a “Forbidden” error.
    let res = client.ca_add(common::ca_handle("dummy_ca")).await;
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