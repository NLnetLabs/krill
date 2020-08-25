extern crate krill;

use std::fs;

use krill::commons::api::ResourceSet;
use krill::daemon::ca::testbed_ca_handle;
use krill::test::*;

#[tokio::test]
async fn embedded_testbed_is_created_on_startup() {
    let dir = start_krill().await;

    let asns = "0-4294967295";
    let v4 = "0.0.0.0/0";
    let v6 = "::0/0";
    let expected_resources = ResourceSet::from_strs(asns, v4, v6).unwrap();

    let testbed_ca_handle = testbed_ca_handle();
    assert!(ca_gets_resources(&testbed_ca_handle, &expected_resources).await);

    let _ = fs::remove_dir_all(dir);
}

