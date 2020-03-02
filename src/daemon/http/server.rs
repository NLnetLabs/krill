//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::io;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use futures::future::ok;
use futures::Future;
use futures::TryFutureExt;

use hyper::server::conn::{AddrIncoming, Http};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Server};

use tokio::net::TcpListener;
use tokio_proto::TcpServer;
use tokio_tls::TlsAcceptor;

use crate::commons::error::Error;
use crate::daemon::config::Config;
use crate::daemon::endpoints;
use crate::daemon::endpoints::*;
use crate::daemon::http::ssl;
use crate::daemon::http::ssl::TlsAddrIncoming;
use crate::daemon::http::HttpResponse;
use crate::daemon::krillserver::KrillServer;

//------------ AppServer -----------------------------------------------------

#[derive(Clone)]
pub struct AppServer(Arc<RwLock<KrillServer>>);

impl AppServer {
    pub fn read(&self) -> RwLockReadGuard<KrillServer> {
        self.0.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<KrillServer> {
        self.0.write().unwrap()
    }
}

pub fn start(config: &Config) -> Result<(), Error> {
    let krill_app = {
        let krill = KrillServer::build(config)?;
        AppServer(Arc::new(RwLock::new(krill)))
    };

    //
    // let post_limit_api = config.post_limit_api;
    // let post_limit_rfc8181 = config.post_limit_rfc8181;
    // let post_limit_rfc6492 = config.post_limit_rfc6492;

    // HttpServer::new(move || {
    //     App::new()
    //         .data(server.clone())
    //         .wrap(middleware::Logger::default())
    //         .route("/health", get().to(endpoints::health))
    //         .route("/metrics", get().to(metrics))
    //         .route("/stats/info", get().to(server_info))
    //         .route("/stats/repo", get().to(repo_stats))
    //         .route("/stats/cas", get().to(cas_stats))
    //         // API end-points
    //         .service(
    //             scope("/api/v1")
    //                 .data(web::JsonConfig::default().limit(post_limit_api))
    //                 // Let the UI check if it's authorized
    //                 .route("/authorized", get().to(api_authorized))
    //                 // Repositories and their publishers (both embedded and remote)
    //                 .route("/publishers", get().to(list_pbl))
    //                 .route("/publishers", post().to(add_pbl))
    //                 .route("/publishers/{handle}", get().to(show_pbl))
    //                 .route("/publishers/{handle}", delete().to(remove_pbl))
    //                 .route(
    //                     "/publishers/{handle}/response.xml",
    //                     get().to(repository_response_xml),
    //                 )
    //                 .route(
    //                     "/publishers/{handle}/response.json",
    //                     get().to(repository_response_json),
    //                 )
    //                 .route("/publishers/stale/{seconds}", get().to(stale_publishers))
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
    // .bind_ssl(config.socket_addr(), https_builder)?
    // .run()?;

    //
    let new_service = service_fn(|_req: Request<Body>| async move {
        HttpResponse::text("hello world".to_string().into_bytes()).res()
    });
    let make_service = make_service_fn(|_| async move { Ok::<_, Error>(new_service) });

    // let ai = TlsAddrIncoming::new(&config.socket_addr())?;
    let ai =
        AddrIncoming::bind(&config.socket_addr()).map_err(|e| Error::HttpsSetup(e.to_string()))?;

    let server = Server::builder(ai)
        .serve(make_service)
        .map_err(|e| eprintln!("Server error: {}", e));

    async {
        if let Err(_) = server.await {
            eprintln!("Server oops")
        }
    };

    // TcpServer::new(
    //     tokio_proto::Server::new(Http::new(), tls_cx),
    //     config.socket_addr(),
    // )
    // .serve(new_service);

    //
    // async {
    //     let listener = TcpListener::bind(&config.socket_addr()).await.unwrap();
    //     //
    //     let http = Http::new();
    //     let conn = http.serve_connection(
    //         listener.incoming().and_then(move |socket| {
    //             tls_cx
    //                 .accept(socket)
    //                 .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    //         }),
    //         new_service,
    //     );
    // }?;
    //
    // async {
    //     if let Err(e) = conn.await {
    //         eprintln!("server connection error: {}", e);
    //     }
    // };

    Ok(())
}

/// Used to set up HTTPS. Creates keypair and self signed certificate
/// if config has 'use_ssl=test'.
fn tls_acceptor(config: &Config) -> Result<TlsAcceptor, Error> {
    if config.test_ssl() {
        ssl::create_key_cert_if_needed(&config.data_dir)
            .map_err(|e| Error::HttpsSetup(format!("{}", e)))?;
    }

    let id = ssl::load_identity(&config.data_dir).map_err(|e| Error::HttpsSetup(e.to_string()))?;

    let tls_cx = native_tls::TlsAcceptor::builder(id)
        .build()
        .map_err(|e| Error::HttpsSetup(e.to_string()))?;

    Ok(TlsAcceptor::from(tls_cx))
}

// XXX TODO: use a better handler that does not load everything into
// memory first, and set the correct headers for caching.
// See also:
// https://github.com/actix/actix-website/blob/master/content/docs/static-files.md
// https://www.keycdn.com/blog/http-cache-headers
// fn serve_rrdp_files(server: web::Data<AppServer>, path: Path<String>) -> HttpResponse {
//     let mut full_path = server.read().rrdp_base_path();
//     full_path.push(path.into_inner());
//     match File::open(full_path) {
//         Ok(mut file) => {
//             use std::io::Read;
//             let mut buffer = Vec::new();
//             file.read_to_end(&mut buffer).unwrap();
//
//             HttpResponse::build(StatusCode::OK).body(buffer)
//         }
//         _ => HttpResponse::build(StatusCode::NOT_FOUND).finish(),
//     }
// }

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs
