//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;

use krill::{commons::api, test::*};

#[tokio::test]
async fn functional_ca_import() {
    // Start an empty Krill instance.
    let krill_dir = tmp_dir();
    let config = test_config(&krill_dir, false, false, false, false);
    start_krill(config).await;

    // Import CA structure. We expect:
    //
    //        TA
    //        |
    //      parent
    //      /    \
    //   child1  child2
    //
    let ca_imports_json = include_str!("../test-resources/bulk-ca-import/cas-only.json");
    let ca_imports: api::import::Structure = serde_json::from_str(ca_imports_json).unwrap();
    import_cas(ca_imports).await;

    let parent = ca_handle("parent");
    let parent_resources = resources("AS65000-AS65535", "10.0.0.0/8, 192.168.0.0/16", "fc00::/7");
    assert!(ca_contains_resources(&parent, &parent_resources).await);

    let child1 = ca_handle("child1");
    let child1_resources = resources("AS65000", "192.168.0.0/16", "");
    assert!(ca_contains_resources(&child1, &child1_resources).await);

    let child2 = ca_handle("child2");
    let child2_resources = resources("AS65001", "10.0.0.0/16", "");
    assert!(ca_contains_resources(&child2, &child2_resources).await);

    let _ = fs::remove_dir_all(krill_dir);
}
