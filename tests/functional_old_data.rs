//! Test setting up Krill as with data from the previous version.

use std::{fs, path};
use chrono::Datelike;
use krill::cli::ta::signer::TrustAnchorSignerManager;

mod common;


fn copy_folder(src: impl AsRef<path::Path>, dst: impl AsRef<path::Path>) {
    fs::create_dir_all(&dst).unwrap();
    for item in fs::read_dir(src).unwrap() {
        let item = item.unwrap();
        let ft = item.file_type().unwrap();
        if ft.is_dir() {
            copy_folder(item.path(), dst.as_ref().join(item.file_name()));
        } 
        else if ft.is_file() {
            fs::copy(
                item.path(), 
                dst.as_ref().join(item.file_name())
            ).unwrap();
        }
    }
}

/// This function tests whether Krill in its current state still works with data
/// from v0.14.5, even as a TA. If it does not, then we might have a problem.
/// 
/// 
#[tokio::test]
async fn functional_old_data() {
    let (mut config, tempdir) = common::TestConfig::file_storage()
        .enable_second_signer().finalize();

    fs::create_dir(&tempdir.path().join("ta")).unwrap();
    copy_folder(
        "test-resources/migrations/v0_14_5", 
        &tempdir.path().join("data")
    );
    copy_folder(
        "test-resources/migrations/v0_14_5_signer", 
        &tempdir.path().join("ta")
    );
    config.ta_support_enabled = true;

    eprintln!(">>>> Check whether Krill still starts.");
    let server = common::KrillServer::start_with_config(config).await;

    let signer_config = 
        include_str!("../test-resources/migrations/v0_14_5_signer/ta.conf");
    let signer_config = signer_config.replace("%TEMPDIR%", 
        &tempdir.path().join("ta").to_str().unwrap());

    eprintln!(">>>> Configure the TA signer.");
    let signer = TrustAnchorSignerManager::create(
        krill::tasigner::Config::parse_str(
            &signer_config
        ).unwrap()
    ).unwrap();

    eprintln!(">>>> Make TA proxy signer request.");
    let request = 
        server.client().ta_proxy_signer_make_request().await.unwrap();
    assert_eq!(request.renew_time.unwrap().year(), 2039);

    eprintln!(">>>> Sign TA proxy signer request.");
    let response = signer.process(request.into(), None).unwrap();
    assert_eq!(response.content().child_responses.len(), 1);

    eprintln!(">>>> Process TA proxy signer response.");
    server.client().ta_proxy_signer_response(response).await.unwrap();

    eprintln!(">>>> Fetch TAL and check it isn't empty.");
    assert!(!server.client().testbed_tal().await.unwrap().is_empty());
}

