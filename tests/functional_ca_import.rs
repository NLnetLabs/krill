//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;

use krill::{
    commons::api::{self, ObjectName},
    test::*,
};

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
    //      \    /
    //     grandchild (two parents)
    //
    let rcn_0 = rcn(0);
    let rcn_1 = rcn(1);

    let ca_imports_json = include_str!("../test-resources/bulk-ca-import/structure.json");
    let ca_imports: api::import::Structure = serde_json::from_str(ca_imports_json).unwrap();

    let parent = ca_handle("parent");
    let parent_resources = resources("AS65000-AS65535", "10.0.0.0/8, 192.168.0.0/16", "fc00::/7");

    let child1 = ca_handle("child1");
    let child1_resources = resources("AS65000", "192.168.0.0/16", "fc00::/56");
    let child1_roas = vec![
        roa_configuration("192.168.0.0/23-24 => 65000 # my precious route"),
        roa_configuration("192.168.2.0/23 => 65001"),
        roa_configuration("fc00::/56 => 65000"),
    ];

    let child2 = ca_handle("child2");
    let child2_resources = resources("AS65001", "10.0.0.0/16", "");

    let grandchild = ca_handle("grandchild");
    let grandchild_resources = resources("AS65001", "10.0.0.0/24, 192.168.0.0/24", "");
    let grandchild_roas = [
        roa_configuration("192.168.0.0/24 => 65000"),
        roa_configuration("10.0.0.0/24 => 65001"),
    ];

    import_cas(ca_imports).await;

    {
        // check parent exists and has resources
        assert!(ca_contains_resources(&parent, &parent_resources).await);
    }

    {
        // check child1
        // - resources
        // - configured roas
        // - published roas and cert for grandchild
        assert!(ca_contains_resources(&child1, &child1_resources).await);
        expect_configured_roas(&child1, &child1_roas).await;

        let mut expected_files_child1_rc0 = expected_mft_and_crl(&child1, &rcn_0).await;
        expected_files_child1_rc0.push(expected_issued_cer(&grandchild, &rcn_0).await);
        for roa in &child1_roas {
            expected_files_child1_rc0.push(ObjectName::from(&roa.payload().into_explicit_max_length()).to_string());
        }
        assert!(
            will_publish_embedded(
                "child1 should publish certificate for grandchild and 3 roas",
                &child1,
                &expected_files_child1_rc0
            )
            .await
        );
    }

    {
        // check child2
        // - resources
        // - no roas
        // - published cert for grandchild
        assert!(ca_contains_resources(&child2, &child2_resources).await);

        let mut expected_files_child2_rc0 = expected_mft_and_crl(&child2, &rcn_0).await;
        // the certificate is issued under rc0 of child2, but from the grandchild's perspective this is in its rc1
        expected_files_child2_rc0.push(expected_issued_cer(&grandchild, &rcn_1).await);

        assert!(
            will_publish_embedded(
                "child2 should publish certificate for grandchild and no roas",
                &child2,
                &expected_files_child2_rc0
            )
            .await
        );
    }

    {
        // check grandchild
        // - resources under both parents
        // - configured roas
        // - publish a ROA in rc0 under parent child1
        // - publish a ROA in rc1 under parent child2
        assert!(ca_contains_resources(&grandchild, &grandchild_resources).await);
        expect_configured_roas(&grandchild, &grandchild_roas).await;

        let mut expected_files_grandchild = expected_mft_and_crl(&grandchild, &rcn_0).await;
        expected_files_grandchild.append(&mut expected_mft_and_crl(&grandchild, &rcn_1).await);

        for roa in &grandchild_roas {
            expected_files_grandchild.push(ObjectName::from(&roa.payload().into_explicit_max_length()).to_string());
        }

        assert!(
            will_publish_embedded(
                "grandchild should publish certificate for grandchild and 2 roas",
                &grandchild,
                &expected_files_grandchild
            )
            .await
        );
    }

    let _ = fs::remove_dir_all(krill_dir);
}
