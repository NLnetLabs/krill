//! Actix-web based HTTP server for the publication server.

use std::fs::File;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use actix_web::{pred, server};
use actix_web::{App, FromRequest, HttpResponse, ResponseError};
use actix_web::dev::MessageBody;
use actix_web::middleware;
use actix_web::http::{Method, StatusCode };
use bcder::decode;
use bytes::Bytes;
use futures::Future;
use serde::Serialize;
use crate::provisioning::publisher_store;
use crate::pubd::config::Config;
use crate::pubd::pubserver;
use crate::pubd::pubserver::PubServer;
use crate::remote::sigmsg::SignedMessage;

const NOT_FOUND: &'static [u8] = include_bytes!("../../static/html/404.html");

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<PubServer>>>);

impl PubServerApp {
    pub fn new(server: Arc<RwLock<PubServer>>) -> Self {
        let app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .resource("/publishers", |r| {
                r.f(Self::publishers)
            })
            .resource("/publishers/{handle}", |r| {
                r.f(Self::repository_response)
            })
            .resource("/rfc8181/{handle}", |r| {
                r.method(Method::POST).with(
                    Self::process_publish_request
                )
            })
            .resource("/rrdp/{path:.*}", |r| {
                r.f(Self::serve_rrdp_files)
            })
            .resource("/health", |r| {
                r.f(Self::service_ok)
            })
            .default_resource(|r| {
                // 404 for GET request
                r.method(Method::GET).f(Self::p404);

                // all requests that are not `GET`
                r.route().filter(pred::Not(pred::Get())).f(
                    |_req| HttpResponse::MethodNotAllowed());
            });

        PubServerApp(with_statics(app))
    }

    pub fn create_server(config: &Config) -> Arc<RwLock<PubServer>> {
        let pub_server = match PubServer::new(
            config.data_dir(),
            config.pub_xml_dir(),
            config.rsync_base(),
            config.service_uri(),
            config.rrdp_base_uri()
        ) {
            Err(e) => {
                error!("{}", e);
                ::std::process::exit(1);
            },
            Ok(server) => server
        };
        Arc::new(RwLock::new(pub_server))
    }

    /// Used to start the server with an existing executor (e.g. in tests)
    pub fn start(config: &Config) {
        let ps = PubServerApp::create_server(config);

        server::new(move || PubServerApp::new(ps.clone()))
            .bind(config.socket_addr())
            .expect(&format!("Cannot bind to: {}", config.socket_addr()))
            .shutdown_timeout(0)
            .start();
    }

    /// Used to run the server in blocking mode, from the main method.
    pub fn run(config: &Config) {
        let ps = PubServerApp::create_server(config);

        server::new(move || PubServerApp::new(ps.clone()))
            .bind(config.socket_addr())
            .expect(&format!("Cannot bind to: {}", config.socket_addr()))
            .shutdown_timeout(0)
            .run();
    }

    /// 404 handler
    fn p404(_req: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::NOT_FOUND)
            .body(NOT_FOUND)
    }

    fn publishers(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match server.publishers() {
            Err(e) => Self::server_error(Error::ServerError(e)),
            Ok(publishers) => Self::render_json(publishers)
        }
    }

    fn render_json<O: Serialize>(object: O) -> HttpResponse {
        match serde_json::to_string(&object){
            Ok(enc) => {
                HttpResponse::Ok().body(enc)
            },
            Err(e) => Self::server_error(Error::JsonError(e))
        }
    }

    fn repository_response(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match req.match_info().get("handle") {
            None => Self::p404(req),
            Some(handle) => {
                match server.repository_response(handle) {
                    Ok(res) => {
                        HttpResponse::Ok().body(res.encode_vec())
                    },
                    Err(pubserver::Error::PublisherStoreError
                        (publisher_store::Error::UnknownPublisher(_))) => {
                        Self::p404(req)
                    },
                    Err(e) => {
                        Self::server_error(Error::ServerError(e))
                    }
                }
            }
        }
    }

    fn process_publish_request(
        req: HttpRequest,
        pr: PublishRequest
    ) -> HttpResponse {
        debug!("Processing publish request");
        match SignedMessage::decode(pr.body, true) {
            Err(e)  => {
                Self::server_error(Error::DecodeError(e))
            },
            Ok(msg) => {
                Self::handle_signed_request(
                    req.state().write().unwrap(),
                    msg,
                    pr.handle.as_str()
                )
            }
        }
    }

    fn handle_signed_request(
        mut server: RwLockWriteGuard<PubServer>,
        msg: SignedMessage,
        handle: &str
    ) -> HttpResponse {
        match server.handle_request(msg, handle) {
            Ok(captured) => {
                HttpResponse::build(StatusCode::OK)
                    .content_type("application/rpki-publication")
                    .body(captured.into_bytes())
            }
            Err(e) => {
                Self::server_error(Error::ServerError(e))
            }
        }
    }

    // XXX TODO: use a better handler that does not load everything into
    // memory first, and set the correct headers for caching.
    // See also:
    // https://github.com/actix/actix-website/blob/master/content/docs/static-files.md
    // https://www.keycdn.com/blog/http-cache-headers
    fn serve_rrdp_files(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();

        match req.match_info().get("path") {
            Some(path) => {
                let mut full_path = server.rrdp_base_path();
                full_path.push(path);
                match File::open(full_path) {
                    Ok(mut file) => {
                        use std::io::Read;
                        let mut buffer = Vec::new();
                        file.read_to_end(&mut buffer).unwrap();

                        HttpResponse::build(StatusCode::OK).body(buffer)
                    },
                    _ => {
                        Self::p404(req)
                    }
                }
            },
            None => Self::p404(req)
        }
    }

    fn service_ok(_r: &HttpRequest) -> HttpResponse {
        // XXX TODO: do a real check
        HttpResponse::Ok().body("I am completely operational, and all my circuits are functioning perfectly.")
    }

    fn server_error(error: Error) -> HttpResponse {
        error!("{}", error);
        error.error_response()
    }

}


struct PublishRequest {
    handle: String,
    body: Bytes
}

impl<S: 'static> FromRequest<S> for PublishRequest {

    type Config = PublishRequestConfig;
    type Result = Result<
        Box<Future<Item = Self, Error = actix_web::Error>>,
        actix_web::Error
    >;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        cfg: &Self::Config
    ) -> Self::Result {
        if let Some(handle) = req.match_info().get("handle") {
            let handle = handle.to_string();
            Ok(Box::new(MessageBody::new(req).limit(cfg.limit())
                .from_err()
                .map(|bytes| {
                    PublishRequest {
                        handle,
                        body: bytes
                    }
                }))
            )
        } else {
            Err(Error::WrongPath.into())
        }
    }
}

pub struct PublishRequestConfig;
impl PublishRequestConfig {
    fn limit(&self) -> usize {
        255 * 1024 * 1024 // 256 MB
    }
}

impl Default for PublishRequestConfig {
    fn default() -> Self {
        PublishRequestConfig
    }
}




//------------ IntoHttpHandler -----------------------------------------------

impl server::IntoHttpHandler for PubServerApp {
    type Handler = <App<Arc<RwLock<PubServer>>> as server::IntoHttpHandler>::Handler;

    fn into_handler(self) -> Self::Handler {
        self.0.into_handler()
    }
}

//------------ Definition of Statics -----------------------------------------

static CSS: &[u8] = b"text/css";
static PNG: &[u8] = b"image/png";

fn with_statics<S: 'static>(app: App<S>) -> App<S> {
    statics!(app,
        "css/custom.css" => CSS,
        "images/404.png" => PNG,
    )
}

//------------ HttpRequest ---------------------------------------------------

pub type HttpRequest = actix_web::HttpRequest<Arc<RwLock<PubServer>>>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    ServerError(pubserver::Error),

    #[fail(display = "{}", _0)]
    JsonError(serde_json::Error),

    #[fail(display = "Cannot decode request: {}", _0)]
    DecodeError(decode::Error),

    #[fail(display = "Wrong path")]
    WrongPath,
}


impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("I'm afraid I can't do that: {}", self))
    }
}

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs
