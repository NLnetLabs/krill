//! Actix-web based HTTP server for the publication server.

use std::sync::{
    Arc,
    RwLock,
    RwLockReadGuard,
    RwLockWriteGuard
};
use actix_web::{
    pred,
    server,
    App,
    HttpResponse,
};
use actix_web::http::{
    Method,
    StatusCode
};
use bcder::decode;
use bytes::Bytes;
use provisioning::publisher_store;
use pubd::config::Config;
use pubd::pubserver;
use pubd::pubserver::PubServer;
use rpki::remote::sigmsg::SignedMessage;
use serde::Serialize;

const NOT_FOUND: &'static [u8] = include_bytes!("../../static/html/404.html");

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<PubServer>>>);

impl PubServerApp {
    pub fn new(server: Arc<RwLock<PubServer>>) -> Self {
        let app = App::with_state(server)
            .resource("/publishers", |r| {
                r.f(Self::publishers)
            })
            .resource("/publishers/{handle}", |r| {
                r.f(Self::repository_response)
            })
            .resource("/rfc8181/{handle}", |r| {
                r.method(Method::POST).with(Self::process_publish_request)
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
            config.notify_sia()
        ) {
            Err(e) => {
                eprintln!("{}", e);
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
        body: Bytes
    ) -> HttpResponse {
        match SignedMessage::decode(body, true) {
            Err(e)  => Self::server_error(Error::DecodeError(e)),
            Ok(msg) => {
                match req.match_info().get("handle") {
                    None => Self::server_error(Error::WrongPath),
                    Some(handle) => {
                        Self::handle_signed_request(
                            req.state().write().unwrap(),
                            msg,
                            handle
                        )
                    }
                }
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

    fn service_ok(_r: &HttpRequest) -> HttpResponse {
        // XXX TODO: do a real check
        HttpResponse::Ok().body("I am completely operational, and all my circuits are functioning perfectly.")
    }

    fn server_error(error: Error) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("I'm afraid I can't do that: {}", error))
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

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs