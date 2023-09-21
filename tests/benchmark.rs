//! Perform functional tests on a Krill instance, using the API
//!
use krill::{daemon::config::Benchmark, test::*};
use log::LevelFilter;

#[tokio::test(flavor = "multi_thread")]
async fn benchmark() {
    let (data_dir, cleanup) = tmp_dir();
    let storage_uri = mem_storage();

    let cas = 10;
    let ca_roas = 10;

    let mut config = test_config(&storage_uri, Some(&data_dir), true, false, false, true);
    config.benchmark = Some(Benchmark { cas, ca_roas });
    config.log_level = LevelFilter::Info;
    start_krill(config).await;

    assert!(wait_for_nr_cas_under_testbed(cas).await);
    // We expect all CAs, plus the testbed and the ta as publishers
    wait_for_nr_cas_under_publication_server(cas + 2).await;

    cleanup()
}
