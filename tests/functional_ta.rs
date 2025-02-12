//! Test setting up Krill as a trust anchor.

use std::str::FromStr;
use krill::commons::crypto::dispatch::signerprovider::SignerProvider;
use rpki::uri;
use rpki::repository::resources::ResourceSet;
use krill::cli::ta::signer::{SignerInitInfo, TrustAnchorSignerManager};
use krill::commons::api;

mod common;


//------------ Test Function -------------------------------------------------

/// Tests setting up Krill as a trust anchor.
///
/// This tests performs the steps described in the [Krill as a Trust Anchor]
/// section of the manual.
///
/// [Krill as a Trust Anchor]: https://krill.docs.nlnetlabs.nl/en/stable/trust-anchor.html
#[tokio::test]
async fn functional_at() {
    let (mut config, _tempdir) = common::TestConfig::mem_storage()
        .enable_second_signer().finalize();
    let port = config.port;
    config.ta_support_enabled = true;
    let server = common::KrillServer::start_with_config(config).await;

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
    let signer = TrustAnchorSignerManager::create(
        krill::ta::Config::parse_str(
            include_str!("../test-resources/ta/ta.conf")
        ).unwrap()
    ).unwrap();

    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let private_key = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let mut pem = Some(String::from_utf8(
        private_key.private_key_to_pem_pkcs8().unwrap()).unwrap());

    #[cfg(feature = "hsm")]
    if signer
        .get_krill_signer()
        .get_active_signers()
        .into_values()
        .any(|x| !matches!(*x, SignerProvider::OpenSsl(_, _))) {
            // The other signer types do not allow a PEM input causing this test to fail.
            pem = None;  
    }

    eprintln!(">>>> Initialise the TA signer.");
    signer.init(
        SignerInitInfo {
            proxy_id: server.client().ta_proxy_id().await.unwrap(),
            repo_info: {
                server.client().ta_proxy_repo_contact().await.unwrap().into()
            },
            tal_https: vec![
                uri::Https::from_string(
                    format!("https://localhost:{}/ta/ta.cer", port)
                ).unwrap()
            ],
            tal_rsync: uri::Rsync::from_str(
                "rsync://localhost/ta/ta.cer"
            ).unwrap(),
            private_key_pem: pem.clone(),
            ta_mft_nr_override: None,
            force: true
        }
    ).unwrap();

    eprintln!(">>>> Associate the TA signer with the proxy.");
    let signer_info = signer.show().unwrap();
    server.client().ta_proxy_signer_add(signer_info).await.unwrap();

    eprintln!(">>>> Fetch TAL and check it isn’t empty.");
    assert!(!server.client().testbed_tal().await.unwrap().is_empty());

    eprintln!(">>>> Create child CA under TA.");

    // Create the “online” CA.
    let ca = common::ca_handle("online");
    let ta = common::ca_handle("ta");
    server.client().ca_add(ca.clone()).await.unwrap();

    // Add “online” as a child of “ta”
    let details = server.client().ca_details(&ca).await.unwrap();
    server.client().ta_proxy_children_add(
        api::AddChildRequest::new(
            details.handle().convert(),
            ResourceSet::all(),
            details.id_cert().try_into().unwrap(),
        )
    ).await.unwrap();

    // Add “ta” as a parent of “online”
    let response = server.client().ta_proxy_child_response(
        &ca.convert()
    ).await.unwrap();
    server.client().parent_add(
        &ca, api::ParentCaReq::new(ta.convert(), response)
    ).await.unwrap();

    // Add “online” as a Publisher
    let request = server.client().repo_request(&ca).await.unwrap();
    let response = server.client().publishers_add(request).await.unwrap();
    server.client().repo_update(&ca, response).await.unwrap();

    eprintln!(">>>> Process proxy signer exchange.");
    server.client().ta_proxy_signer_make_request().await.unwrap();
    let req = server.client().ta_proxy_signer_show_request().await.unwrap();
    signer.process(req, None).unwrap();
    let response = signer.show_last_response().unwrap();
    server.client().ta_proxy_signer_response(response).await.unwrap();

    if pem.is_some() {
        eprintln!(">>>> Reinitialise the TA signer.");
        signer.init(
            SignerInitInfo {
                proxy_id: server.client().ta_proxy_id().await.unwrap(),
                repo_info: {
                    server.client().ta_proxy_repo_contact().await.unwrap().into()
                },
                tal_https: vec![
                    uri::Https::from_string(
                        format!("https://localhost:{}/ta/ta.cer", port)
                    ).unwrap()
                ],
                tal_rsync: uri::Rsync::from_str(
                    "rsync://localhost/resignedta/ta.cer"
                ).unwrap(),
                private_key_pem: pem.clone(),
                ta_mft_nr_override: None,
                force: true
            }
        ).unwrap();

        eprintln!(">>>> Reassociate the TA signer with the proxy.");
        let signer_info = signer.show().unwrap();
        server.client().ta_proxy_signer_add(signer_info).await.unwrap();

        eprintln!(">>>> Refetch TAL and check it isn’t empty.");
        assert!(!server.client().testbed_tal().await.unwrap().is_empty());

        eprintln!(">>>> Refetch TAL and check it was resigned.");
        assert!(server.client().testbed_tal().await.unwrap().contains("resigned"));
    }

    // XXX This should probably test that everything is in order but I don’t
    //     know how just yet.
}

