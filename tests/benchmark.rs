//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;

use krill::{daemon::config::Benchmark, test::*};
use log::LevelFilter;

#[tokio::test(flavor = "multi_thread")]
async fn benchmark() {
    let dir = tmp_dir();

    let cas = 10;
    let ca_roas = 10;

    let mut config = test_config(&dir, true, false, false, true);
    config.benchmark = Some(Benchmark { cas, ca_roas });
    config.log_level = LevelFilter::Info;
    start_krill(config).await;

    assert!(wait_for_nr_cas_under_testbed(cas).await);

    let _ = fs::remove_dir_all(dir);
}
