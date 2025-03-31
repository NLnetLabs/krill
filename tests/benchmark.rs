//! Perform functional tests on a Krill instance, using the API

use krill::cli::client::KrillClient;
use krill::server::config::Benchmark;
use log::LevelFilter;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn benchmark() {
    let (mut config, _dir) = common::TestConfig::mem_storage()
        .enable_testbed()
        .enable_second_signer()
        .finalize();

    let cas = 10;
    let ca_roas = 10;
    config.benchmark = Some(Benchmark { cas, ca_roas });
    config.log_level = LevelFilter::Info;
    let server = common::KrillServer::start_with_config(config).await;

    wait_for_nr_cas_under_testbed(server.client(), cas).await;
    // We expect all CAs, plus the testbed and the ta as publishers
    wait_for_nr_cas_under_publication_server(server.client(), cas + 2).await;

    server.abort().await;
}

async fn wait_for_nr_cas_under_testbed(
    client: &KrillClient,
    nr: usize
) {
    let handle = common::ca_handle("testbed");
    for _ in 0..300 {
        if client.ca_details(&handle).await.unwrap().children.len() == nr {
            return;
        }
        common::sleep_seconds(1).await
    }
    panic!("not all CAs appeared in time");
}


async fn wait_for_nr_cas_under_publication_server(
    client: &KrillClient,
    publishers_expected: usize,
) {
    let mut publishers_found = client.publishers_list().await.unwrap()
        .publishers.len();
    for _ in 0..300 {
        if publishers_found == publishers_expected {
            return;
        }
        common::sleep_seconds(1).await;
        publishers_found = client.publishers_list().await.unwrap()
            .publishers.len();
    }

    panic!(
        "Expected {} publishers, but found {}",
        publishers_expected, publishers_found
    );
}

