//! Test setting up Krill as a trust anchor.

use std::str::FromStr;
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
#[test]
fn functional_at() {
    let (mut config, _tempdir) = common::TestConfig::mem_storage()
        .enable_second_signer().finalize();
    let port = config.port;
    config.ta_support_enabled = true;
    let server = common::KrillServer::start_with_config(config);

    eprintln!(">>>> Initialise TA proxy.");
    server.client().ta_proxy_init().unwrap();

    eprintln!(">>>> Initialise publication server.");
    server.pubserver_init(port);

    eprintln!(">>>> Get TA proxy publisher request.");
    let request = server.client().ta_proxy_repo_request().unwrap();

    eprintln!(">>>> Add TA Proxy as Publisher.");
    let response = server.client().publishers_add(request).unwrap();

    eprintln!(">>>> Configure repository for TA proxy.");
    server.client().ta_proxy_repo_configure(response).unwrap();

    eprintln!(">>>> Configure the TA signer.");
    let signer = TrustAnchorSignerManager::create(
        krill::ta::Config::parse_str(
            include_str!("../test-resources/ta/ta.conf")
        ).unwrap()
    ).unwrap();

    eprintln!(">>>> Initialise the TA signer.");
    signer.init(
        SignerInitInfo {
            proxy_id: server.client().ta_proxy_id().unwrap(),
            repo_info: {
                server.client().ta_proxy_repo_contact().unwrap().into()
            },
            tal_https: vec![
                uri::Https::from_string(
                    format!("https://localhost:{}/ta/ta.cer", port)
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
    server.client().ta_proxy_signer_add(signer_info).unwrap();

    eprintln!(">>>> Fetch TAL and check it isn’t empty.");
    assert!(!server.client().testbed_tal().unwrap().is_empty());

    eprintln!(">>>> Create child CA under TA.");

    // Create the “online” CA.
    let ca = common::ca_handle("online");
    let ta = common::ca_handle("ta");
    server.client().ca_add(ca.clone()).unwrap();

    // Add “online” as a child of “ta”
    let details = server.client().ca_details(&ca).unwrap();
    server.client().ta_proxy_children_add(
        api::AddChildRequest::new(
            details.handle().convert(),
            ResourceSet::all(),
            details.id_cert().try_into().unwrap(),
        )
    ).unwrap();

    // Add “ta” as a parent of “online”
    let response = server.client().ta_proxy_child_response(
        &ca.convert()
    ).unwrap();
    server.client().parent_add(
        &ca, api::ParentCaReq::new(ta.convert(), response)
    ).unwrap();

    // Add “online” as a Publisher
    let request = server.client().repo_request(&ca).unwrap();
    let response = server.client().publishers_add(request).unwrap();
    server.client().repo_update(&ca, response).unwrap();

    eprintln!(">>>> Process proxy signer exchange.");
    server.client().ta_proxy_signer_make_request().unwrap();
    let req = server.client().ta_proxy_signer_show_request().unwrap();
    signer.process(req, None).unwrap();
    let response = signer.show_last_response().unwrap();
    server.client().ta_proxy_signer_response(response).unwrap();

    // XXX This should probably test that everything is in order but I don’t
    //     know how just yet.
}

