//! End-to-end tests for Krill.
//!
//! This binary drives complext scenarios to test Krill. In general, these
//! scenarios involve setting up one or more Krill instances, issue commands
//! to them, and then verifying the results by checking the data set output
//! by a Routinator validation run.

// TODO: Prefix logging output by name of instance/service/binary producing
// the log output, e.g. Krill server 1, Krill server 2, Routinator, etc.
use krilltest::environment::Environment;

use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use clap::Parser;
use clap::crate_version;
use krill::api::admin::ParentCaReq;
use krill::api::admin::ResourceClassNameMapping;
use krill::api::admin::UpdateChildRequest;
use krill::api::ca::ObjectName;
use krill::api::roa::RoaConfiguration;
use krill::api::roa::RoaConfigurationUpdates;
use krill::api::status::Success;
use krill::cli::client::KrillClient;
use krill::commons::httpclient::Error;
use nix::libc::time_t;
use nix::sys::time::TimeSpec;
use nix::time::ClockId;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::ResourceSet;
use rpki::resources::Asn;
use rpki::resources::Prefix;
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use tempfile::TempDir;
use tokio::time::sleep;

const KRILL_TAL_NAME: &str = "Krill";

static CLOCK_CHANGES_ALLOWED: Mutex<bool> = Mutex::new(false);

//------------ main ----------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let (base_path, _tempdir) = match args.working_dir {
        Some(working_dir) => (working_dir, None),
        None => {
            let tempdir = TempDir::new().unwrap();
            (tempdir.path().to_path_buf(), Some(tempdir))
        }
    };

    // TODO: Allow specific tests to be selected, e.g. via --test?

    if args.allow_system_clock_changes {
        eprintln!("ALLOWING SYSTEM CLOCK CHANGES");
        *CLOCK_CHANGES_ALLOWED.lock().unwrap() = true;
    }

    // About TCP port allocation:
    //
    // We can't use systemd socket activation to acquire sockets here and
    // pass them to the applications that we spawn because (a) Krill doesn't
    // support socket activation, and (b) nginx doesn't officially support it
    // (though there is a "hack" to set the NGINX environment variable to <fd
    // number>[:<fd number>].. which could be used but cannot be relied upon
    // to continue working in the future).
    //
    // Instead we require the operator to tell us a port range to use and hope
    // that the operator is correct that none of those ports are currently
    // being listened on.
    let tcp_port_max = args.tcp_port_max.unwrap_or(u16::MAX);

    let mut env = Environment::new(
        base_path,
        args.krill,
        args.nginx,
        args.routinator,
        (args.listen_addr, (args.tcp_port_min..=tcp_port_max)),
    );

    set_clock(946684800);

    test_functional_delegated_ca_import_plus_some_roas(&mut env)
        .await
        .unwrap();

    test_many_embedded_cas(&mut env, 1000).await.unwrap();

    test_many_delegated_cas_in_one_krill_instance(&mut env, 1000)
        .await
        .unwrap();

    test_many_delegated_cas_in_own_krill_instances(&mut env, 500)
        .await
        .unwrap();
}

fn set_clock(seconds_since_epoch: time_t) {
    if *CLOCK_CHANGES_ALLOWED.lock().unwrap() {
        nix::time::clock_settime(
            ClockId::CLOCK_REALTIME,
            TimeSpec::new(seconds_since_epoch, 0),
        )
        .unwrap();
        println!(
            "NOTE: Changed system clock to {seconds_since_epoch}. System time after: {:?}",
            SystemTime::now()
        );
    }
}

async fn test_functional_delegated_ca_import_plus_some_roas(
    env: &mut Environment,
) -> Result<Success, Error> {
    // Define some CA names to work with.
    let testbed = CaHandle::from_str("testbed").unwrap();
    let parent_1 = CaHandle::from_str("parent_1").unwrap();
    let parent_2 = CaHandle::from_str("parent_2").unwrap();
    let child = CaHandle::from_str("child").unwrap();

    // Define some resource sets to work with.
    let parent_res = ResourceSet::all();
    let child_res =
        ResourceSet::from_strs("AS65000", "10.0.0.0/16", "").unwrap();
    let child_res2 = ResourceSet::from_strs(
        "AS65000-AS65010",
        "10.0.0.0/8",
        "2001:db8::/32",
    )
    .unwrap();
    let child_rcn = ResourceClassName::from("custom");

    // Define some ROAs to work with.
    let route_resource_set_10_0_0_0_def_1 =
        RoaConfiguration::from_str("10.0.0.0/16-16 => 64496").unwrap();
    let route_resource_set_10_0_0_0_def_2 =
        RoaConfiguration::from_str("10.0.0.0/16-16 => 64497").unwrap();
    let route_resource_set_10_1_0_0_def_1 = RoaConfiguration::from_str(
        "10.1.0.0/24-24 => 64496 # will be shrunk",
    )
    .unwrap();

    // Spawn two Krill servers.
    env.add_krill("server1").await;
    env.add_krill("server2").await;

    // Connect clients to the servers.
    let server1 = env.krill("server1").make_client();
    let server2 = env.krill("server2").make_client();

    //
    // Start of test operations against the Krill servers.
    //

    eprintln!(">>>> Add parent_1 under testbed in server 1.");
    add_ca_under_parent(&server1, &testbed, &parent_1, &parent_res, None)
        .await?;

    eprintln!(">>>> Add child under parent_1 in server 1.");
    add_ca_under_parent(
        &server1,
        &parent_1,
        &child,
        &child_res,
        Some(&child_rcn),
    )
    .await?;

    eprintln!(">>>> Export the child.");
    let exported = server1.child_export(&parent_1, &child.convert()).await?;

    eprintln!(">>>> Add parent_2 under testbed in server 2.");
    add_ca_under_parent(&server2, &testbed, &parent_2, &parent_res, None)
        .await?;

    eprintln!(">>>> Import child under parent_2 in server 2.");
    server2.child_import(&parent_2, exported).await?;

    eprintln!(">>>> Add parent_2 as the parent of child.");
    let response = server2.child_contact(&parent_2, &child.convert()).await?;
    server1
        .parent_add(
            &child,
            ParentCaReq {
                handle: parent_2.convert(),
                response,
            },
        )
        .await?;

    set_clock(1724101695);

    eprintln!(">>>> Remove the child from the original parent.");
    server1
        .child_delete(&parent_1, &child.convert())
        .await
        .unwrap();

    eprintln!(">>>> Update the resources for the child in parent_2.");
    server2
        .child_update(
            &parent_2,
            &child.convert(),
            UpdateChildRequest::resources(child_res2.clone()),
        )
        .await
        .unwrap();

    eprintln!(">>>> Verify that the resources are received.");
    assert!(wait_for_ca_resources(&server1, &child, &child_res2).await?);

    eprintln!(">>>> Add ROAs to parent_1.");
    server1
        .roas_update(
            &parent_1,
            RoaConfigurationUpdates {
                added: vec![
                    route_resource_set_10_0_0_0_def_1.clone(),
                    route_resource_set_10_0_0_0_def_2.clone(),
                    route_resource_set_10_1_0_0_def_1.clone(),
                ],
                removed: vec![],
            },
        )
        .await
        .unwrap();

    assert!(
        wait_for_objects(
            &server1,
            &parent_1,
            &[
                &route_resource_set_10_0_0_0_def_1,
                &route_resource_set_10_0_0_0_def_2,
                &route_resource_set_10_1_0_0_def_1,
            ]
        )
        .await?
    );

    //
    // End of test operations against Krill servers.
    //

    set_clock(1787175275);

    // Fetch the Krill TAL and install it in the Routinator extra tals
    // directory.
    let tls_cert = load_tls_cert(&env.nginx().tls_cert_path());
    let tal_bytes =
        fetch_url(env.krill("server1").tal_url(), tls_cert, 5).await;

    // Configure Routinator to use the Krill TAL
    env.routinator().install_tal(KRILL_TAL_NAME, &tal_bytes);

    // Do a Routinator validation run and fetch the available VRPs.
    //
    // We expect something like this:
    // {
    //   "metadata": {
    //     "generated": 1787123416,
    //     "generatedTime": "2026-08-19T07:10:16Z"
    //   },
    //   "roas": [
    //     { "asn": "AS64496", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
    //     { "asn": "AS64497", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
    //     { "asn": "AS64496", "prefix": "10.1.0.0/24", "maxLength": 24, "ta": "Krill" }
    //   ]
    // }
    let report: RoutinatorJsonVrpReport =
        serde_json::from_slice(&env.routinator().vrps()).unwrap();

    assert_eq!(
        report.roas,
        [
            route_resource_set_10_0_0_0_def_1.into(),
            route_resource_set_10_0_0_0_def_2.into(),
            route_resource_set_10_1_0_0_def_1.into(),
        ]
    );

    //
    // Cleanup
    //
    env.remove_krill("server2");
    env.remove_krill("server1");

    Ok(Success)
}

/// Create num_cas embeddded CAs in a single Krill instance.
async fn test_many_embedded_cas(
    env: &mut Environment,
    num_cas: usize,
) -> Result<Success, Error> {
    // Define some CA names to work with.
    let testbed = CaHandle::from_str("testbed").unwrap();

    // Spawn a Krill server.
    env.add_krill("krill").await;

    // Determine the URI to use to connect a client to the server.
    let krill_server_uri = env.krill("krill").server_api_uri();

    //
    // Start of test operations against the Krill servers.
    //

    // Why not use Rayon?
    // ==================
    // Rayon only supports running sync operations, not async operations.
    //
    // Why use threads rather than async tasks?
    // ========================================
    // KrillClient internally passes around an `impl IntoIterator` for all API
    // paths, and it is `!Send` meaning it can't be used across an `.await`
    // point when using a multi-threaded Tokio runtime.
    let num_threads = std::thread::available_parallelism().unwrap().get() / 2;
    let num_cas_per_thread = num_cas / num_threads;
    let mut remaining = num_cas % num_threads;

    println!(
        "Distributing CA creation over {num_threads} threads with {num_cas_per_thread} per thread and one additional CA each for {remaining} of the threads."
    );

    let mut first = 0;
    let mut thread_handles = vec![];
    for _ in 0..num_threads {
        // If there are more CAs to do than can be spread evenly over the
        // available threads, give as many threads as possible one extra CA
        // to do.
        let mut last = first + num_cas_per_thread;
        if remaining > 0 {
            last += 1;
            remaining -= 1;
        }

        let testbed = testbed.clone();
        let krill_server_uri = krill_server_uri.clone();
        let thread_handle = std::thread::spawn(move || {
            // Use a single threaded runtime as then we can construct
            // KrillClient once and use it across await points. We use threads
            // to achieve concurrency instead of a multi-threaded async
            // executor. See comment above about KrillClient for more info.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let krill =
                        KrillClient::new(krill_server_uri, None).unwrap();
                    for i in first..last {
                        create_ca(testbed.clone(), &krill, i).await;
                    }
                    // Wait for the ROAs to be published
                    eprintln!("Waiting for ROAs to be published...");
                    for i in first..last {
                        wait_for_roas(&krill, i).await;
                    }
                })
        });

        first = last;
        thread_handles.push(thread_handle);
    }

    // Wait for threads to complete.
    for handle in thread_handles {
        handle.join().unwrap();
    }

    //
    // End of test operations against Krill servers.
    //

    // Fetch the Krill TAL and install it in the Routinator extra tals
    // directory.
    let tls_cert = load_tls_cert(&env.nginx().tls_cert_path());
    let tal_bytes =
        fetch_url(env.krill("krill").tal_url(), tls_cert, 5).await;

    // Configure Routinator to use the Krill TAL
    env.routinator().install_tal(KRILL_TAL_NAME, &tal_bytes);

    // Do a Routinator validation run and fetch the available VRPs.
    //
    // We expect something like this:
    // {
    //   "metadata": {
    //     "generated": 1787123416,
    //     "generatedTime": "2026-08-19T07:10:16Z"
    //   },
    //   "roas": [
    //     { "asn": "AS64496", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
    //     { "asn": "AS64497", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
    //     { "asn": "AS64496", "prefix": "10.1.0.0/24", "maxLength": 24, "ta": "Krill" }
    //   ]
    // }
    std::io::stdout()
        .write_all(&env.routinator().vrps())
        .unwrap();

    // TODO
    // assert_eq!(
    //     report.roas,
    //     [
    //         route_resource_set_10_0_0_0_def_1.into(),
    //         route_resource_set_10_0_0_0_def_2.into(),
    //         route_resource_set_10_1_0_0_def_1.into(),
    //     ]
    // );

    //
    // Cleanup
    //
    env.remove_krill("krill");

    Ok(Success)
}

async fn wait_for_roas(krill: &KrillClient, i: usize) {
    let child = CaHandle::from_str(&format!("child{i}")).unwrap();
    let major = i / 256;
    let minor = i % 256;
    let ipv4 = format!("{major}.{minor}.0.0/16");
    // Define some ROAs to work with.
    let route_resource_set_10_0_0_0_def_1 =
        RoaConfiguration::from_str(&format!("{ipv4}-16 => 64496")).unwrap();
    let route_resource_set_10_0_0_0_def_2 =
        RoaConfiguration::from_str(&format!("{ipv4}-16 => 64497")).unwrap();
    assert!(
        wait_for_objects(
            &krill,
            &child,
            &[
                &route_resource_set_10_0_0_0_def_1,
                &route_resource_set_10_0_0_0_def_2,
            ]
        )
        .await
        .unwrap()
    );
}

async fn test_many_delegated_cas_in_own_krill_instances(
    env: &mut Environment,
    num_cas: usize,
) -> Result<Success, Error> {
    // Define some CA names to work with.
    let testbed = CaHandle::from_str("testbed").unwrap();
    let parent = CaHandle::from_str("parent").unwrap();

    // Define some resource sets to work with.
    let parent_res = ResourceSet::all();

    // Spawn many Krill servers, one running as a parent that offers a
    // publication service, like an RIR, and the rest as operator instance
    // that will register with the parent and publish into it.
    env.add_krill("rir").await;

    // Connect a client to the RIR Krill server.
    let rir_server_uri = {
        let rir_krill = env.krill("rir").make_client();

        add_ca_under_parent(&rir_krill, &testbed, &parent, &parent_res, None)
            .await?;

        // Determine the URI to use to connect a client to the server.
        env.krill("rir").server_api_uri()
    };

    eprintln!("Waiting for Krill instances to start..");
    let mut operator_server_uris = vec![];
    for i in 0..num_cas {
        let name = format!("operator{i}");
        env.add_krill_ext(name.clone(), false).await;
        let krill = env.krill(&name);
        operator_server_uris.push(krill.server_api_uri());
    }

    eprintln!("Reconfigure nginx");
    env.nginx_mut().reconfigure();

    eprintln!("Wait until the Krill instances are healthy..");

    for i in 0..num_cas {
        let name = format!("operator{i}");
        let krillc = env.krill(&name).make_client();
        let mut tries_left = 100;
        while tries_left > 0 && !krillc.health().await.is_ok() {
            println!(
                "Waiting for Krill instance '{name}' to finish starting up..."
            );
            sleep(Duration::from_millis(100)).await;
            tries_left -= 1;
        }
    }

    eprintln!("Krill instances are ready.");

    //
    // Start of test operations against the Krill servers.
    //

    let num_threads = std::thread::available_parallelism().unwrap().get() / 2;
    let num_cas_per_thread = num_cas / num_threads;
    let mut remaining = num_cas % num_threads;

    println!(
        "Distributing CA creation over {num_threads} threads with {num_cas_per_thread} per thread and one additional CA each for {remaining} of the threads."
    );

    let mut first = 0;
    let mut thread_handles = vec![];
    for _ in 0..num_threads {
        // If there are more CAs to do than can be spread evenly over the
        // available threads, give as many threads as possible one extra CA
        // to do.
        let mut last = first + num_cas_per_thread;
        if remaining > 0 {
            last += 1;
            remaining -= 1;
        }

        let rir_server_uri = rir_server_uri.clone();
        let operator_server_uris = operator_server_uris.clone();
        let parent = parent.clone();
        let thread_handle = std::thread::spawn(move || {
            // Use a single threaded runtime as then we can construct
            // KrillClient once and use it across await points. We use threads
            // to achieve concurrency instead of a multi-threaded async
            // executor. See comment above about KrillClient for more info.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let rir_krill =
                        KrillClient::new(rir_server_uri, None).unwrap();

                    eprintln!(">>>> Add parent under testbed in server 1.");
                    for i in first..last {
                        let major = i / 256;
                        let minor = i % 256;
                        let asn = format!("AS{i}");
                        let ipv4 = format!("{major}.{minor}.0.0/16");
                        let child_res = ResourceSet::from_strs(&asn, &ipv4, "").unwrap();
                        let route_resource_set_10_0_0_0_def_1 =
                            RoaConfiguration::from_str(&format!("{ipv4}-16 => 64496")).unwrap();
                        let route_resource_set_10_0_0_0_def_2 =
                            RoaConfiguration::from_str(&format!("{ipv4}-16 => 64497")).unwrap();

                        let operator_server_uri = operator_server_uris[i].clone();
                        let operator_krill =
                            KrillClient::new(operator_server_uri, None).unwrap();

                        eprintln!(">>>> Add child{i} in server 2");
                        let child = CaHandle::from_str(&format!("child{i}")).unwrap();
                        // krillc repo request
                        operator_krill.ca_add(child.clone()).await.unwrap();
                        eprintln!(">>>> Configure the server 2 child{i} to publish to server 1");
                        let request = operator_krill.repo_request(&child).await.unwrap();
                        // "supply it to your Publication Server". "Your publication server
                        // provider will give you a repository response XML".
                        let response = rir_krill.publishers_add(request).await.unwrap();
                        // krillc repo configure
                        let mut tries_left = 100;
                        let mut last_res = None;
                        while tries_left > 0 {
                            let res = operator_krill.repo_update(&child, response.clone()).await;
                            if res.is_ok() {
                                break;
                            }
                            last_res = Some(res);
                            tries_left -= 1;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        if tries_left <= 0 {
                            panic!("repo_update() failed: {}", last_res.unwrap().unwrap_err());
                        }

                        eprintln!(">>>> Configure a server 1 parent for our server 2 child{i}");
                        // krillc parents request
                        let child_request = operator_krill.child_request(&child).await.unwrap();
                        // "present your CA's RFC 8183 Child Request XML file to you parent"
                        // "Your RIR or NIR will provide you with a parent response XML"
                        let id_cert = child_request.validate().unwrap();
                        let response = rir_krill
                            .child_add(&parent, child.convert(), child_res.clone(), id_cert)
                            .await.unwrap();
                        // Supply the parent response to the child CA
                        operator_krill
                            .parent_add(
                                &child,
                                ParentCaReq {
                                    handle: parent.convert(),
                                    response,
                                },
                            )
                            .await.unwrap();

                        assert!(
                            wait_for_ca_resources(&operator_krill, &child, &child_res)
                                .await.unwrap()
                        );

                        eprintln!(">>>> Add ROAs to child{i}");
                        operator_krill
                            .roas_update(
                                &child,
                                RoaConfigurationUpdates {
                                    added: vec![
                                        route_resource_set_10_0_0_0_def_1.clone(),
                                        route_resource_set_10_0_0_0_def_2.clone(),
                                    ],
                                    removed: vec![],
                                },
                            )
                            .await
                            .unwrap();
                    }
                })
        });

        first = last;
        thread_handles.push(thread_handle);
    }

    // Wait for threads to complete.
    for handle in thread_handles {
        handle.join().unwrap();
    }

    // Wait till the RIR publication server reports that it has all of the
    // children as publishers.
    let rir_krill = env.krill("rir").make_client();
    let mut tries_left = 30;
    while tries_left > 0 {
        let publishers =
            &rir_krill.pubserver_stats().await.unwrap().publishers;
        let mut ok_count = 0;
        for i in 0..num_cas {
            let pub_handle =
                CaHandle::from_str(&format!("child{i}")).unwrap();
            let Some(p) = publishers.get(&pub_handle.convert()) else {
                break;
            };
            if p.objects < 2 {
                break;
            }
            ok_count += 1;
        }

        if ok_count == num_cas {
            println!(
                "All {num_cas} children have published at least 2 objects in the parent server"
            );
            // Fetch the Krill TAL and install it in the Routinator extra tals
            // directory.
            let tls_cert = load_tls_cert(&env.nginx().tls_cert_path());
            let tal_bytes =
                fetch_url(env.krill("rir").tal_url(), tls_cert, 5).await;

            // Configure Routinator to use the Krill TAL
            env.routinator().install_tal(KRILL_TAL_NAME, &tal_bytes);

            // Do a Routinator validation run and fetch the available VRPs.
            //
            // We expect something like this:
            // {
            //   "metadata": {
            //     "generated": 1787123416,
            //     "generatedTime": "2026-08-19T07:10:16Z"
            //   },
            //   "roas": [
            //     { "asn": "AS64496", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
            //     { "asn": "AS64497", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
            //     { "asn": "AS64496", "prefix": "10.1.0.0/24", "maxLength": 24, "ta": "Krill" }
            //   ]
            // }
            std::io::stdout()
                .write_all(&env.routinator().vrps())
                .unwrap();
            return Ok(Success);
        }

        eprintln!(
            "{ok_count} / {num_cas} publishers ready, waiting for the rest.."
        );
        sleep(Duration::from_millis(100)).await;
        tries_left -= 1;
    }

    Ok(Success)
}

async fn test_many_delegated_cas_in_one_krill_instance(
    env: &mut Environment,
    num_cas: usize,
) -> Result<Success, Error> {
    // Define some CA names to work with.
    let testbed = CaHandle::from_str("testbed").unwrap();
    let parent = CaHandle::from_str("parent").unwrap();

    // Define some resource sets to work with.
    let parent_res = ResourceSet::all();

    // Spawn two Krill servers, one running as a parent that offers a
    // publication service, like an RIR, and another as a placeholder for many
    // operator instances each with their own, but instead we put all of those
    // CAs in one child instance of Krill, all of which will be registered
    // with the parent and publish into it.
    env.add_krill("rir").await;
    env.add_krill("operators").await;

    // Connect clients to the Krill servers.
    let rir_krill = env.krill("rir").make_client();

    // Determine the URIs to use to connect clients to the servers.
    let rir_server_uri = env.krill("rir").server_api_uri();
    let operators_server_uri = env.krill("operators").server_api_uri();

    //
    // Start of test operations against the Krill servers.
    //

    // Add a parent CA to RIR testbed.
    add_ca_under_parent(&rir_krill, &testbed, &parent, &parent_res, None)
        .await?;

    let num_threads = std::thread::available_parallelism().unwrap().get() / 2;
    let num_cas_per_thread = num_cas / num_threads;
    let mut remaining = num_cas % num_threads;

    println!(
        "Distributing CA creation over {num_threads} threads with {num_cas_per_thread} per thread and one additional CA each for {remaining} of the threads."
    );

    let mut first = 0;
    let mut thread_handles = vec![];
    for _ in 0..num_threads {
        // If there are more CAs to do than can be spread evenly over the
        // available threads, give as many threads as possible one extra CA
        // to do.
        let mut last = first + num_cas_per_thread;
        if remaining > 0 {
            last += 1;
            remaining -= 1;
        }

        let rir_server_uri = rir_server_uri.clone();
        let operators_server_uri = operators_server_uri.clone();
        let parent = parent.clone();
        let thread_handle = std::thread::spawn(move || {
            // Use a single threaded runtime as then we can construct
            // KrillClient once and use it across await points. We use threads
            // to achieve concurrency instead of a multi-threaded async
            // executor. See comment above about KrillClient for more info.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let rir_krill =
                        KrillClient::new(rir_server_uri, None).unwrap();

                    let operators_krill =
                        KrillClient::new(operators_server_uri, None).unwrap();

                    eprintln!(">>>> Add parent under testbed in server 1.");
                    for i in first..last {
                        let major = i / 256;
                        let minor = i % 256;
                        let asn = format!("AS{i}");
                        let ipv4 = format!("{major}.{minor}.0.0/16");
                        let child_res = ResourceSet::from_strs(&asn, &ipv4, "").unwrap();
                        let route_resource_set_10_0_0_0_def_1 =
                            RoaConfiguration::from_str(&format!("{ipv4}-16 => 64496")).unwrap();
                        let route_resource_set_10_0_0_0_def_2 =
                            RoaConfiguration::from_str(&format!("{ipv4}-16 => 64497")).unwrap();

                        eprintln!(">>>> Add a child{i} in server 2");
                        let child = CaHandle::from_str(&format!("child{i}")).unwrap();
                        // krillc repo request
                        operators_krill.ca_add(child.clone()).await.unwrap();
                        eprintln!(">>>> Configure the server 2 child{i} to publish to server 1");
                        let request = operators_krill.repo_request(&child).await.unwrap();
                        // "supply it to your Publication Server". "Your publication server
                        // provider will give you a repository response XML".
                        let response = rir_krill.publishers_add(request).await.unwrap();
                        // krillc repo configure
                        let mut tries_left = 100;
                        let mut last_res = None;
                        while tries_left > 0 {
                            let res = operators_krill.repo_update(&child, response.clone()).await;
                            if res.is_ok() {
                                break;
                            }
                            last_res = Some(res);
                            tries_left -= 1;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        if tries_left <= 0 {
                            panic!("repo_update() failed: {}", last_res.unwrap().unwrap_err());
                        }

                        eprintln!(">>>> Configure a server 1 parent for our server 2 child{i}");
                        // krillc parents request
                        let child_request = operators_krill.child_request(&child).await.unwrap();
                        // "present your CA's RFC 8183 Child Request XML file to you parent"
                        // "Your RIR or NIR will provide you with a parent response XML"
                        let id_cert = child_request.validate().unwrap();
                        let response = rir_krill
                            .child_add(&parent, child.convert(), child_res.clone(), id_cert)
                            .await.unwrap();
                        // Supply the parent response to the child CA
                        operators_krill
                            .parent_add(
                                &child,
                                ParentCaReq {
                                    handle: parent.convert(),
                                    response,
                                },
                            )
                            .await.unwrap();

                        assert!(
                            wait_for_ca_resources(&operators_krill, &child, &child_res)
                                .await.unwrap()
                        );

                        eprintln!(">>>> Add ROAs to child{i}");
                        operators_krill
                            .roas_update(
                                &child,
                                RoaConfigurationUpdates {
                                    added: vec![
                                        route_resource_set_10_0_0_0_def_1.clone(),
                                        route_resource_set_10_0_0_0_def_2.clone(),
                                    ],
                                    removed: vec![],
                                },
                            )
                            .await
                            .unwrap();
                    }
                })
        });

        first = last;
        thread_handles.push(thread_handle);
    }

    // Wait for threads to complete.
    for handle in thread_handles {
        handle.join().unwrap();
    }

    // Wait till the RIR publication server reports that it has all of the
    // children as publishers.
    let rir_krill = env.krill("rir").make_client();
    let mut tries_left = 30;
    while tries_left > 0 {
        let publishers =
            &rir_krill.pubserver_stats().await.unwrap().publishers;
        let mut ok_count = 0;
        for i in 0..num_cas {
            let pub_handle =
                CaHandle::from_str(&format!("child{i}")).unwrap();
            let Some(p) = publishers.get(&pub_handle.convert()) else {
                break;
            };
            if p.objects < 2 {
                break;
            }
            ok_count += 1;
        }

        if ok_count == num_cas {
            println!(
                "All {num_cas} children have published at least 2 objects in the parent server"
            );
            // Fetch the Krill TAL and install it in the Routinator extra tals
            // directory.
            let tls_cert = load_tls_cert(&env.nginx().tls_cert_path());
            let tal_bytes =
                fetch_url(env.krill("rir").tal_url(), tls_cert, 5).await;

            // Configure Routinator to use the Krill TAL
            env.routinator().install_tal(KRILL_TAL_NAME, &tal_bytes);

            // Do a Routinator validation run and fetch the available VRPs.
            //
            // We expect something like this:
            // {
            //   "metadata": {
            //     "generated": 1787123416,
            //     "generatedTime": "2026-08-19T07:10:16Z"
            //   },
            //   "roas": [
            //     { "asn": "AS64496", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
            //     { "asn": "AS64497", "prefix": "10.0.0.0/16", "maxLength": 16, "ta": "Krill" },
            //     { "asn": "AS64496", "prefix": "10.1.0.0/24", "maxLength": 24, "ta": "Krill" }
            //   ]
            // }
            std::io::stdout()
                .write_all(&env.routinator().vrps())
                .unwrap();
            return Ok(Success);
        }

        eprintln!(
            "{ok_count} / {num_cas} publishers ready, waiting for the rest.."
        );
        sleep(Duration::from_millis(100)).await;
        tries_left -= 1;
    }

    Ok(Success)
}

async fn create_ca(testbed: CaHandle, krill: &KrillClient, i: usize) {
    let child = CaHandle::from_str(&format!("child{i}")).unwrap();
    let major = i / 256;
    let minor = i % 256;
    let asn = format!("AS{i}");
    let ipv4 = format!("{major}.{minor}.0.0/16");
    let child_res = ResourceSet::from_strs(&asn, &ipv4, "").unwrap();

    eprintln!(">>>> Add child{i} under testbed.");
    add_ca_under_parent(&krill, &testbed, &child, &child_res, None)
        .await
        .unwrap();

    // eprintln!(">>>> Verify that the resources are received.");
    // assert!(
    //     wait_for_ca_resources(&krill, &child, &child_res)
    //         .await
    //         .unwrap()
    // );

    // Define some ROAs to work with.
    let route_resource_set_10_0_0_0_def_1 =
        RoaConfiguration::from_str(&format!("{ipv4}-16 => 64496")).unwrap();
    let route_resource_set_10_0_0_0_def_2 =
        RoaConfiguration::from_str(&format!("{ipv4}-16 => 64497")).unwrap();

    eprintln!(">>>> Add ROAs to child{i}.");
    krill
        .roas_update(
            &child,
            RoaConfigurationUpdates {
                added: vec![
                    route_resource_set_10_0_0_0_def_1.clone(),
                    route_resource_set_10_0_0_0_def_2.clone(),
                ],
                removed: vec![],
            },
        )
        .await
        .unwrap();

    // assert!(
    //     wait_for_objects(
    //         &krill,
    //         &child,
    //         &[
    //             &route_resource_set_10_0_0_0_def_1,
    //             &route_resource_set_10_0_0_0_def_2,
    //         ]
    //     )
    //     .await
    //     .unwrap()
    // );
}

//---- Helpers

#[derive(Debug, Deserialize, PartialEq)]
struct RoutinatorJsonVrpReport {
    roas: Vec<RoutinatorJsonVrpReportRoa>,
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq)]
struct RoutinatorJsonVrpReportRoa {
    #[serde_as(as = "DisplayFromStr")]
    asn: Asn,
    prefix: Prefix,
    #[serde(rename = "maxLength")]
    max_length: u8,
    ta: String,
}

/// Convert with the assumption that the expected TAL is our Krill TAL.
impl From<RoaConfiguration> for RoutinatorJsonVrpReportRoa {
    fn from(config: RoaConfiguration) -> Self {
        let payload = config.payload.into_explicit_max_length();
        Self {
            asn: payload.asn.into(),
            prefix: Prefix::new(
                payload.prefix.ip_addr(),
                payload.prefix.addr_len(),
            )
            .unwrap(),
            max_length: payload.max_length.unwrap(),
            ta: KRILL_TAL_NAME.into(),
        }
    }
}

async fn add_ca_under_parent(
    client: &KrillClient,
    parent: &CaHandle,
    child: &CaHandle,
    child_res: &ResourceSet,
    child_rcn: Option<&ResourceClassName>,
) -> Result<bool, Error> {
    client.ca_add(child.clone()).await?;
    let request = client.repo_request(child).await?;
    client.publishers_add(request).await?;
    let response = client.publisher_response(&child.convert()).await?;
    client.repo_update(child, response).await?;
    let child_request = client.child_request(child).await?;
    let id_cert = child_request.validate().unwrap();
    let response = client
        .child_add(&parent, child.convert(), child_res.clone(), id_cert)
        .await?;
    if let Some(rcn) = child_rcn {
        client
            .child_update(
                &parent.convert(),
                &child.convert(),
                UpdateChildRequest::resource_class_name_mapping(
                    ResourceClassNameMapping {
                        name_in_parent: ResourceClassName::from(0),
                        name_for_child: rcn.clone(),
                    },
                ),
            )
            .await?;
    }
    client
        .parent_add(
            child,
            ParentCaReq {
                handle: parent.convert(),
                response,
            },
        )
        .await?;

    wait_for_ca_resources(client, child, child_res).await
}

async fn wait_for_ca_resources(
    client: &KrillClient,
    ca: &CaHandle,
    resources: &ResourceSet,
) -> Result<bool, Error> {
    for _ in 0..100 {
        if let Ok(details) = client.ca_details(ca).await {
            let mut res = ResourceSet::default();
            for rc in details.resource_classes.values() {
                if let Some(resources) = rc.keys.current_resources() {
                    res = res.union(resources);
                }
            }
            if res.contains(&resources) {
                return Ok(true);
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(false)
}

async fn wait_for_objects(
    client: &KrillClient,
    ca: &CaHandle,
    roas: &[&RoaConfiguration],
) -> Result<bool, Error> {
    let mut files = vec![];
    let ca_key_info = client
        .ca_details(ca)
        .await
        .unwrap()
        .resource_classes
        .get(&ResourceClassName::from(0))
        .unwrap()
        .keys
        .current_key()
        .unwrap()
        .clone();
    files.push(ca_key_info.incoming_cert.mft_name().to_string());
    files.push(ca_key_info.incoming_cert.crl_name().to_string());
    for roa in roas {
        files.push(ObjectName::from(roa.payload).to_string());
    }

    for _ in 0..100 {
        let details = client.publisher_details(&ca.convert()).await?;
        if details.current_files.len() == files.len() {
            let current_files: Vec<_> =
                details.current_files.iter().map(|p| &p.uri).collect();
            let mut all_matched = true;
            for o in &files {
                if !current_files.iter().any(|uri| uri.ends_with(o)) {
                    all_matched = false;
                }
            }
            if all_matched {
                return Ok(true);
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    let details = client.publisher_details(&ca.convert()).await.unwrap();

    eprintln!("Published files didn’t match for {ca}");
    eprintln!("Found:");
    for file in &details.current_files {
        eprintln!("  {}", file.uri);
    }
    eprintln!("Expected:");
    for file in &files {
        eprintln!("  {file}");
    }

    Ok(false)
}

fn load_tls_cert(tls_cert_path: &Path) -> reqwest::Certificate {
    let mut f = std::fs::File::open(tls_cert_path).unwrap();
    let mut tls_ca_cert_pem_bytes = vec![];
    f.read_to_end(&mut tls_ca_cert_pem_bytes).unwrap();
    drop(f);
    let tls_ca_cert =
        reqwest::Certificate::from_pem(&tls_ca_cert_pem_bytes).unwrap();
    tls_ca_cert
}

async fn fetch_url(
    url: String,
    tls_cert: reqwest::Certificate,
    max_tries: u8,
) -> bytes::Bytes {
    let trusting_client = reqwest::Client::builder()
        .tls_certs_only([tls_cert])
        .build()
        .unwrap();
    let mut tries_left = max_tries;
    while tries_left > 0 {
        match trusting_client.get(&url).send().await {
            Ok(bytes) => {
                return bytes.bytes().await.unwrap();
            }
            Err(err) => {
                eprintln!(
                    "{url} not yet available, will retry in 1 second: {err}"
                );
                sleep(Duration::from_secs(1)).await;
            }
        }
        tries_left -= 1;
    }
    unreachable!();
}

//------------ Args ----------------------------------------------------------

#[derive(clap::Parser)]
#[command(
    version = crate_version!(), name = "krilltest",
    about, long_about = None,
)]
struct Args {
    /// The path of the krill binary.
    #[arg(long, default_value = "target/release/krill")]
    krill: PathBuf,

    /// The path of the routinator binary.
    #[arg(long, default_value = "routinator")]
    routinator: PathBuf,

    /// The path of the nginx binary.
    #[arg(long, default_value = "/usr/sbin/nginx")]
    nginx: PathBuf,

    /// The working directory for all test data.
    ///
    /// A temporary directory in '/tmp' is used if not given.
    #[arg(long)]
    working_dir: Option<PathBuf>,

    /// The IP address all the servers should listen on.
    #[arg(long, default_value = "127.0.0.1")]
    listen_addr: IpAddr,

    /// The lowest TCP port number to use for services that we spawn.
    ///
    /// Default: 3000
    #[arg(long, default_value = "3000")]
    tcp_port_min: u16,

    /// The highest TCP port number to use for services that we spawn.
    ///
    /// Default: No upper limit.
    #[arg(long)]
    tcp_port_max: Option<u16>,

    /// Allow tests to change the system clock.
    ///
    /// WARNING: Do not do this on your own host, only inside a VM.
    #[arg(long, default_value_t = false)]
    allow_system_clock_changes: bool,
}
