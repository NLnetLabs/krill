//! Test setting up Krill as with data from the previous version.

use std::{fs, path};
use chrono::Datelike;
use krill::cli::ta::signer::TrustAnchorSignerManager;

mod common;


fn untar_file(tar_path: &str, dst: impl AsRef<path::Path>) {
    let mut archive = tar::Archive::new(
        std::io::BufReader::new(
            fs::File::open(tar_path).unwrap()
        )
    );
    archive.unpack(dst).unwrap();
}

/// This function tests whether Krill in its current state still works with data
/// from v0.14.5, even as a TA. If it does not, then we might have a problem.
/// 
/// The test data contains ROA, ASPA, BGPsec, and child objects.
#[cfg(unix)]
#[tokio::test]
async fn functional_old_data() {
    let (mut config, tempdir) = common::TestConfig::file_storage()
        .enable_second_signer().finalize();

    fs::create_dir(tempdir.path().join("ta")).unwrap();
    untar_file(
        "test-resources/migrations/v0_14_5.tar", 
        tempdir.path().join("data")
    );
    untar_file(
        "test-resources/migrations/v0_14_5_signer.tar", 
        tempdir.path().join("ta")
    );
    config.ta_support_enabled = true;

    eprintln!(">>>> Check whether Krill still starts.");
    let server = common::KrillServer::start_with_config(config).await;

    let signer_config = 
        include_str!("../test-resources/migrations/v0_14_5_signer/ta.conf");
    let signer_config = signer_config.replace("%TEMPDIR%", 
        tempdir.path().join("ta").to_str().unwrap());

    eprintln!(">>>> Configure the TA signer.");
    let signer = TrustAnchorSignerManager::create(
        krill::tasigner::Config::parse_str(
            &signer_config
        ).unwrap()
    ).unwrap();

    eprintln!(">>>> Make TA proxy signer request.");
    let request = 
        server.client().ta_proxy_signer_make_request().await.unwrap();
    assert_eq!(request.ta_renew_time.unwrap().year(), 2026);
    assert_eq!(request.renew_times[0].1.year(), 2039);

    eprintln!(">>>> Sign TA proxy signer request.");
    let response = signer.process(request.into(), None).unwrap();
    assert_eq!(response.content().child_responses.len(), 1);

    eprintln!(">>>> Process TA proxy signer response.");
    server.client().ta_proxy_signer_response(response).await.unwrap();

    eprintln!(">>>> Fetch TAL and check it isn't empty.");
    assert!(!server.client().testbed_tal().await.unwrap().is_empty());
}

