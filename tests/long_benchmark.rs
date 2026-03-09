//! Performs a test with lots of CAs including re-signing all of them.
//!
//! This test is disabled by default because it tries to change the system
//! time. Do only run this on a dedicated VM or similar.

use std::net::Ipv6Addr;
use std::time::SystemTime;
use futures_util::future::join_all;
use rpki::repository::resources::{
    AsBlocksBuilder, IpBlocksBuilder, Ipv4Blocks, Prefix, ResourceSet,
};
use rpki::resources::Asn;

mod common;

#[tokio::test]
#[ignore]
async fn long_benchmark() {
    let (config, data_dir) = common::TestConfig::file_storage()
        .enable_testbed()
        .finalize();
    let server = common::KrillServer::start_with_config(
        config, Some(data_dir)
    ).await;
    let server = &server;

    eprintln!(
        ">>>>> Storage directory: {}",
        server.data_dir().unwrap().path().display()
    );

    let t0 = SystemTime::now();

    eprintln!(">>>>> Creating CAs ...");

    join_all((0..0x30u16).map(|i| async move {
        let i = i << 8;
        for j in 0..0xffu16 {
            create_ca(&server, i | j).await;
        }
    })).await;

    let t1 = SystemTime::now();
    eprintln!(
        ">>>> CAs created in {:03} seconds.",
        t1.duration_since(t0).unwrap().as_secs_f32()
    );

}


/// Creates a CA based on a number.
///
///
async fn create_ca(server: &common::KrillServer, idx: u16) {
    server.create_testbed_ca(
        &common::ca_handle(&format!("ca_{idx}")),
        &make_resources(idx),
    ).await;
}

/// Creates the resources based on a number.
fn make_resources(idx: u16) -> ResourceSet {
    let mut asns = AsBlocksBuilder::new();
    asns.push(Asn::from_u32(idx.into()));
    let asns = asns.finalize();
    let mut v6 = IpBlocksBuilder::new();
    v6.push(Prefix::new(Ipv6Addr::new(idx, 0, 0, 0, 0, 0, 0, 0), 48));
    let v6 = v6.finalize();
    ResourceSet::new(asns, Ipv4Blocks::empty(), v6.into())
}
