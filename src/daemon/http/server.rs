//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::convert::Infallible;
use std::sync::Arc;

use tokio::sync::RwLock;

use futures::TryFutureExt;

use hyper;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};

use crate::commons::error::Error;
use crate::daemon::config::Config;
use crate::daemon::endpoints::*;
use crate::daemon::http::{tls, tls_keys, Request};
use crate::daemon::krillserver::KrillServer;

//------------ AppServer -----------------------------------------------------

pub type State = Arc<RwLock<KrillServer>>;

pub async fn start(config: Config) -> Result<(), Error> {
    let state = {
        let krill = KrillServer::build(&config)?;
        Arc::new(RwLock::new(krill))
    };

    let service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                let state = state.clone();
                map_requests(req, state)
            }))
        }
    });

    tls_keys::create_key_cert_if_needed(&config.data_dir)
        .map_err(|e| Error::HttpsSetup(format!("{}", e)))?;

    let server_config_builder = tls::TlsConfigBuilder::new()
        .cert_path(tls_keys::cert_file_path(&config.data_dir))
        .key_path(tls_keys::key_file_path(&config.data_dir));
    let server_config = server_config_builder.build().unwrap();

    let acceptor = tls::TlsAcceptor::new(
        server_config,
        AddrIncoming::bind(&config.socket_addr()).unwrap(),
    );

    let server = hyper::Server::builder(acceptor)
        .serve(service)
        .map_err(|e| eprintln!("Server error: {}", e));

    if server.await.is_err() {
        eprintln!("Krill failed to start");
        ::std::process::exit(1);
    }

    Ok(())
}

async fn map_requests(
    req: hyper::Request<hyper::Body>,
    state: State,
) -> Result<hyper::Response<hyper::Body>, Error> {
    let req = Request::new(req, state);

    let log_req = format!("{} {}", req.method(), req.path.full());

    let res = api(req)
        .or_else(health)
        .or_else(metrics)
        .or_else(stats)
        .or_else(rfc8181)
        .or_else(rfc6492)
        .or_else(render_not_found)
        .map_err(|_| Error::custom("should have received not found response"))
        .await;

    match res {
        Ok(routing_result) => {
            let response = routing_result.response();
            info!("{} {}", log_req, response.status(),);
            trace!("Response body: {:?}", response.body());
            Ok(response)
        }
        Err(e) => {
            error!("{} Error: {}", log_req, e);
            Err(e)
        }
    }

    //
    // let post_limit_api = config.post_limit_api;
    // let post_limit_rfc8181 = config.post_limit_rfc8181;
    // let post_limit_rfc6492 = config.post_limit_rfc6492;

    // HttpServer::new(move || {
    //         .wrap(middleware::Logger::default())

    //         // Public TA related methods
    //         .route("/ta/ta.tal", get().to(tal))
    //         .route("/ta/ta.cer", get().to(ta_cer))

    //         .add_statics()
    //         // Catch all (not found or not allowed)
    //         .default_service(
    //             // 404 for GET request
    //             web::resource("")
    //                 .route(web::get().to(not_found))
    //                 // all requests that are not `GET`
    //                 .route(
    //                     web::route()
    //                         .guard(guard::Not(guard::Get()))
    //                         .to(HttpResponse::MethodNotAllowed),
    //                 ),
    //         )
    // })
}

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::commons::util::test;

    use super::*;

    #[tokio::test]
    async fn hello_world() {
        let dir = test::sub_dir(&PathBuf::from("work"));

        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::sub_dir(&dir);
            Config::test(&data_dir)
        };

        tokio::spawn(super::start(server_conf));

        assert!(crate::daemon::test::primary_server_ready().await);
    }
}
