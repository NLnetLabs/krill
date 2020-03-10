//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::convert::Infallible;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

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

#[derive(Clone)]
pub struct State(Arc<RwLock<KrillServer>>);

impl State {
    pub fn read(&self) -> RwLockReadGuard<KrillServer> {
        self.0.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<KrillServer> {
        self.0.write().unwrap()
    }
}

pub async fn start(config: Config) -> Result<(), Error> {
    let state = {
        let krill = KrillServer::build(&config)?;
        State(Arc::new(RwLock::new(krill)))
    };

    let service = make_service_fn(move |_| {
        let mut state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                let mut state = state.clone();
                map_requests(req, state)
            }))
        }
    });

    tls_keys::create_key_cert_if_needed(&config.data_dir)
        .map_err(|e| Error::HttpsSetup(format!("{}", e)))?;

    let mut server_config_builder = tls::TlsConfigBuilder::new()
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

    if let Err(_) = server.await {
        eprintln!("Krill failed to start");
        ::std::process::exit(1);
    }

    Ok(())
}

async fn map_requests(
    req: hyper::Request<hyper::Body>,
    mut state: State,
) -> Result<hyper::Response<hyper::Body>, Error> {
    let req = Request::new(req, state);

    debug!("Got request for: {}", req.path.full());

    health(req)
        .or_else(metrics)
        .or_else(stats)
        .or_else(api)
        .or_else(render_not_found)
        .map_err(|_| Error::custom("should have received not found response"))
        .await?
        .res()
    //
    // let post_limit_api = config.post_limit_api;
    // let post_limit_rfc8181 = config.post_limit_rfc8181;
    // let post_limit_rfc6492 = config.post_limit_rfc6492;

    // HttpServer::new(move || {
    //         .wrap(middleware::Logger::default())
    //         // API end-points
    //         .service(
    //             scope("/api/v1")
    //                 // Let the UI check if it's authorized
    //                 // Repositories and their publishers (both embedded and remote)
    //                 // CAs (both embedded and remote)
    //                 .route("/cas", post().to(ca_init))
    //                 .route("/cas", get().to(cas))
    //                 .route("/cas/issues", get().to(endpoints::all_ca_issues))
    //                 .route("/cas/issues/{ca}", get().to(endpoints::ca_issues))
    //                 .route("/cas/{ca}", get().to(ca_info))
    //                 .route("/cas/{ca}/id", post().to(ca_regenerate_id))
    //                 .route("/cas/{ca}/history", get().to(ca_history))
    //                 .route("/cas/{ca}/child_request.xml", get().to(ca_child_req_xml))
    //                 .route("/cas/{ca}/child_request.json", get().to(ca_child_req_json))
    //                 .route("/cas/{ca}/repo", get().to(ca_repo_details))
    //                 .route("/cas/{ca}/repo/state", get().to(ca_repo_state))
    //                 .route(
    //                     "/cas/{ca}/repo/request.json",
    //                     get().to(ca_publisher_req_json),
    //                 )
    //                 .route("/cas/{ca}/repo/request.xml", get().to(ca_publisher_req_xml))
    //                 .route("/cas/{ca}/repo", post().to(ca_repo_update))
    //                 .route("/cas/{ca}/parents", post().to(ca_add_parent))
    //                 .route(
    //                     "/cas/{ca}/parents-xml/{parent}",
    //                     post().to(ca_add_parent_xml),
    //                 )
    //                 .route("/cas/{ca}/parents/{parent}", get().to(ca_my_parent_contact))
    //                 .route("/cas/{ca}/parents/{parent}", post().to(ca_update_parent))
    //                 .route("/cas/{ca}/parents/{parent}", delete().to(ca_remove_parent))
    //                 .route("/cas/{ca}/children", post().to(ca_add_child))
    //                 .route(
    //                     "/cas/{ca}/children/{child}/contact",
    //                     get().to(ca_parent_contact),
    //                 )
    //                 .route(
    //                     "/cas/{ca}/children/{child}/parent_response.json",
    //                     get().to(ca_parent_res_json),
    //                 )
    //                 .route(
    //                     "/cas/{ca}/children/{child}/parent_response.xml",
    //                     get().to(ca_parent_res_xml),
    //                 )
    //                 .route("/cas/{ca}/children/{child}", get().to(ca_show_child))
    //                 .route("/cas/{ca}/children/{child}", post().to(ca_child_update))
    //                 .route("/cas/{ca}/children/{child}", delete().to(ca_child_remove))
    //                 .route("/cas/{ca}/keys/roll_init", post().to(ca_kr_init))
    //                 .route("/cas/{ca}/keys/roll_activate", post().to(ca_kr_activate))
    //                 .route("/cas/{ca}/routes", post().to(ca_routes_update))
    //                 .route("/cas/{ca}/routes", get().to(ca_routes_show))
    //                 // Republish ALL CAs
    //                 .route("/cas/republish_all", post().to(republish_all))
    //                 // Force resyncing of all CAs at repo servers
    //                 .route("/cas/resync_all", post().to(resync_all))
    //                 // Force refresh of ALL CA certificates
    //                 .route("/cas/refresh_all", post().to(refresh_all))
    //                 // Methods that are not found should return a bad request and some explanation
    //                 .default_service(web::route().to(api_bad_request)),
    //         )
    //         // Publication Protocol (RFC 8181)
    //         .service(
    //             Resource::new("/rfc8181/{handle}")
    //                 .data(web::PayloadConfig::default().limit(post_limit_rfc8181))
    //                 .route(post().to(rfc8181)),
    //         )
    //         // Uo-Down Protocol (RFC 6492)
    //         .service(
    //             Resource::new("/rfc6492/{handle}")
    //                 .data(web::PayloadConfig::default().limit(post_limit_rfc6492))
    //                 .route(post().to(rfc6492)),
    //         )
    //         // Public TA related methods
    //         .route("/ta/ta.tal", get().to(tal))
    //         .route("/ta/ta.cer", get().to(ta_cer))
    //         // RRDP repository
    //         .route("/rrdp/{path:.*}", get().to(serve_rrdp_files))
    //         // UI
    //         .route(
    //             "/",
    //             get().to(|| {
    //                 HttpResponse::Found()
    //                     .header("location", "/index.html")
    //                     .finish()
    //             }),
    //         )
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
    use std::time::Duration;

    use tokio::time::{delay_for, timeout};

    use crate::commons::util::{httpclient, test};

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

        assert!(crate::daemon::test::server_ready().await);
    }
}
