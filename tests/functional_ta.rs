//! Test setting up Krill as a trust anchor.

use std::{fs, process::Command};
use std::borrow::Cow;
use std::str::FromStr;
use std::time::Duration;
use rpki::uri;
use rpki::repository::resources::ResourceSet;
use krill::api;
use krill::api::ta::TrustAnchorSignedReissue;
#[cfg(unix)]
use krill::cli::client::KrillClient;
use krill::commons::httpclient;
use krill::cli::ta::signer::{
    SignerInitInfo, 
    SignerReissueInfo, 
    TrustAnchorSignerManager
};

mod common;


//------------ Test Function -------------------------------------------------

/// Tests setting up Krill as a trust anchor.
///
/// This tests performs the steps described in the [Krill as a Trust Anchor]
/// section of the manual.
///
/// [Krill as a Trust Anchor]: https://krill.docs.nlnetlabs.nl/en/stable/trust-anchor.html
#[tokio::test]
async fn functional_ta() {
    let (mut config, tempdir) = common::TestConfig::file_storage()
        .enable_second_signer().finalize();
    let port = config.port;
    config.ta_support_enabled = true;
    #[cfg(unix)]
    let scoped_client = {
        use std::sync::Arc;
        use krill::daemon::http::auth::{PermissionSet, Role};

        let uid = nix::unistd::Uid::current();
        let user = nix::unistd::User::from_uid(uid).unwrap().unwrap();
        let socket = tempdir.path().join("krill.sock");
        config.unix_socket_enabled = true;
        config.unix_socket = Some(socket.clone());
        Arc::make_mut(&mut config.auth_roles).add(
            "child-admin",
            Role::with_resources(
                PermissionSet::ANY, [common::ca_handle("online").convert()],
            ),
        );
        config.unix_users.insert(user.name, "child-admin".into());
        KrillClient::new(
            format!("unix://{}", socket.display()).parse().unwrap(), None,
        ).unwrap()
    };
    let server = common::KrillServer::start_with_config(
        config.clone(), None,
    ).await;

    eprintln!(">>>> Initialise TA proxy.");
    server.client().ta_proxy_init().await.unwrap();

    eprintln!(">>>> Initialise publication server.");
    server.pubserver_init(port).await;

    eprintln!(">>>> Get TA proxy publisher request.");
    let request = server.client().ta_proxy_repo_request().await.unwrap();

    eprintln!(">>>> Add TA Proxy as Publisher.");
    let response = server.client().publishers_add(request).await.unwrap();

    eprintln!(">>>> Configure repository for TA proxy.");
    server.client().ta_proxy_repo_configure(response).await.unwrap();

    eprintln!(">>>> Configure the TA signer.");
    let signer_config = tempdir.path().join("ta.conf");
    let signer_dir = tempdir.path().join("signer");
    let signer_config_contents = include_str!("../test-resources/ta/ta.conf")
        .replace("memory://", signer_dir.to_str().unwrap());
    fs::write(&signer_config, &signer_config_contents).unwrap();
    let signer = TrustAnchorSignerManager::create(
        krill::tasigner::Config::parse_str(&signer_config_contents).unwrap(),
    ).unwrap();

    eprintln!(">>>> Initialise the TA signer.");
    signer.init(
        SignerInitInfo {
            proxy_id: server.client().ta_proxy_id().await.unwrap(),
            repo_info: {
                server.client().ta_proxy_repo_contact().await.unwrap().into()
            },
            tal_https: vec![
                uri::Https::from_string(
                    format!("https://localhost:{port}/ta/ta.cer")
                ).unwrap()
            ],
            tal_rsync: uri::Rsync::from_str(
                "rsync://localhost/ta/ta.cer"
            ).unwrap(),
            private_key_pem: None,
            ta_mft_nr_override: None
        }
    ).unwrap();

    eprintln!(">>>> Associate the TA signer with the proxy.");
    let signer_info = signer.show().unwrap();
    server.client().ta_proxy_signer_add(signer_info.clone()).await.unwrap();

    let initial_cert = current_ta_certificate(port).await;
    let initial_tal = server.client().testbed_tal().await.unwrap();
    assert!(!initial_tal.is_empty());

    eprintln!(">>>> Create child CA under TA.");

    // Create the “online” CA.
    let ca = common::ca_handle("online");
    let ta = common::ca_handle("ta");
    server.client().ca_add(ca.clone()).await.unwrap();

    // Add “online” as a child of “ta”
    let details = server.client().ca_details(&ca).await.unwrap();
    server.client().ta_proxy_children_add(
        api::admin::AddChildRequest {
            handle: details.handle.convert(),
            resources: ResourceSet::all(),
            id_cert: (&details.id_cert).try_into().unwrap(),
        }
    ).await.unwrap();

    // Add “ta” as a parent of “online”
    let response = server.client().ta_proxy_child_response(
        &ca.convert()
    ).await.unwrap();
    server.client().parent_add(
        &ca, api::admin::ParentCaReq { handle: ta.convert(), response }
    ).await.unwrap();

    // Add “online” as a Publisher
    let request = server.client().repo_request(&ca).await.unwrap();
    let response = server.client().publishers_add(request).await.unwrap();
    server.client().repo_update(&ca, response).await.unwrap();

    eprintln!(">>>> Prepare a signer response and a TA certificate reissue.");
    server.client().ta_proxy_signer_make_request().await.unwrap();
    let request = server.client().ta_proxy_signer_show_request().await.unwrap();
    let nonce = request.request.nonce.clone();
    let response = signer.process(request.into(), None).unwrap();

    signer.reissue(SignerReissueInfo {
        proxy_id: server.client().ta_proxy_id().await.unwrap(),
        repo_info: server.client().ta_proxy_repo_contact().await.unwrap().into(),
        tal_https: vec![
            uri::Https::from_string(
                format!("https://localhost:{port}/ta/ta.cer"),
            ).unwrap()
        ],
        tal_rsync: uri::Rsync::from_str(
            "rsync://localhost/resignedta/ta.cer",
        ).unwrap(),
    }).unwrap();
    let new_info = signer.show().unwrap();
    assert_eq!(new_info.id, signer_info.id);
    assert_eq!(
        new_info.ta_cert_details.cert.key_identifier(),
        signer_info.ta_cert_details.cert.key_identifier(),
    );

    let previous_certificate = tempdir.path().join("ta-current.cer");
    fs::write(&previous_certificate, &initial_cert).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_krillta"))
        .args(["signer", "--config"])
        .arg(&signer_config)
        .args(["--format", "json", "show-reissue", "--previous-certificate"])
        .arg(&previous_certificate)
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let reissue: TrustAnchorSignedReissue =
        serde_json::from_slice(&output.stdout).unwrap();

    #[cfg(unix)]
    assert!(matches!(
        scoped_client.ta_proxy_signer_update(reissue.clone()).await,
        Err(httpclient::Error::Forbidden(_)),
    ));
    assert!(
        server.client().ta_proxy_signer_update(reissue.clone()).await.is_err()
    );
    assert_eq!(server.client().testbed_tal().await.unwrap(), initial_tal);
    assert_eq!(current_ta_certificate(port).await, initial_cert);
    server.abort().await;

    eprintln!(">>>> Finish the pending exchange after restarting the proxy.");
    let server = common::KrillServer::start_with_config(
        config.clone(), None,
    ).await;
    assert_eq!(server.client().testbed_tal().await.unwrap(), initial_tal);
    assert_eq!(
        server.client().ta_proxy_signer_show_request().await.unwrap().request.nonce,
        nonce,
    );
    server.client().ta_proxy_signer_response(response).await.unwrap();

    eprintln!(">>>> Verify that only an authenticated reissue can be applied.");
    let update_path = [Cow::Borrowed("api/v1/ta/proxy/signer/update")];
    let updated_cert = new_info.ta_cert_details.cert.to_bytes();
    assert!(
        server.client().post_json(update_path.clone(), new_info).await.is_err()
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    invalid["signed"]["message"] = serde_json::Value::String("AAAA".into());
    assert!(server.client().post_json(update_path, invalid).await.is_err());
    assert_eq!(server.client().testbed_tal().await.unwrap(), initial_tal);

    let reissue_path = tempdir.path().join("reissue.json");
    fs::write(&reissue_path, &output.stdout).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_krillta"))
        .args(["proxy", "--server"])
        .arg(format!("https://localhost:{port}/"))
        .args(["--token", "secret", "signer", "update", "--info"])
        .arg(&reissue_path)
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let updated_tal = server.client().testbed_tal().await.unwrap();
    assert!(updated_tal.contains("resignedta"));
    assert_eq!(current_ta_certificate(port).await, updated_cert);
    server.abort().await;

    let server = common::KrillServer::start_with_config(config, None).await;
    assert_eq!(server.client().testbed_tal().await.unwrap(), updated_tal);
    assert!(server.client().ta_proxy_signer_update(reissue).await.is_err());
    assert_eq!(current_ta_certificate(port).await, updated_cert);

    eprintln!(">>>> Verify that provisioning still works after the reissue.");
    let request = server.client().ta_proxy_signer_make_request().await.unwrap();
    let response = signer.process(request.into(), None).unwrap();
    server.client().ta_proxy_signer_response(response).await.unwrap();
    assert!(server.wait_for_ca_resources(&ca, &ResourceSet::all()).await);
    server.abort().await;
}


async fn current_ta_certificate(port: u16) -> bytes::Bytes {
    let uri = format!("https://localhost:{port}/ta/ta.cer");
    httpclient::client_with_tweaks(&uri, Duration::from_secs(5), false)
        .unwrap().get(uri).send().await.unwrap().error_for_status().unwrap()
        .bytes().await.unwrap()
}
