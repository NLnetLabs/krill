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
use openssl::ssl::{SslMethod, SslAcceptor, SslAcceptorBuilder, SslFiletype};
use serde::Serialize;
use crate::provisioning::publisher_store;
use crate::pubd::config::Config;
use crate::pubd::https;
use crate::pubd::pubserver;
use crate::pubd::pubserver::PubServer;
use crate::remote::sigmsg::SignedMessage;
use api::PublisherList;
use api::PublisherDetails;

const NOT_FOUND: &'static [u8] = include_bytes!("../../static/html/404.html");

const PATH_PUBLISHERS: &'static str = "/api/v1/publishers";

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<PubServer>>>);

/// # Set up methods
///
impl PubServerApp {
    pub fn new(server: Arc<RwLock<PubServer>>) -> Self {
        let app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .resource(PATH_PUBLISHERS, |r| {
                r.f(Self::publishers)
            })
            .resource("/api/v1/publishers/{handle}", |r| {
                r.f(Self::publisher_details)
            })
            .resource("/api/v1/publishers/{handle}/id.cer", |r| {
                r.f(Self::id_cert)
            })
            .resource("/api/v1/publishers/{handle}/response.xml", |r| {
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
    ///
    /// Note https is not supported in tests.
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

        let server = server::new(move || PubServerApp::new(ps.clone()));

        if config.use_https() {
            match Self::https_builder(config) {
                Ok(https_builder) => {
                    server.bind_ssl(config.socket_addr(), https_builder)
                        .expect(&format!("Cannot bind to: {}", config.socket_addr()))
                        .shutdown_timeout(0)
                        .run();
                },
                Err(e) => {
                    eprintln!("{}", e);
                    ::std::process::exit(1);
                }
            }

        } else {
            server.bind(config.socket_addr())
                .expect(&format!("Cannot bind to: {}", config.socket_addr()))
                .shutdown_timeout(0)
                .run();
        }
    }

    fn https_builder(config: &Config) -> Result<SslAcceptorBuilder, Error> {
        https::create_key_cert_if_needed(config.data_dir())
            .map_err(|e| Error::Other(format!("{}", e)))?;

        let mut https_builder = SslAcceptor::mozilla_intermediate(
            SslMethod::tls()
        ).map_err(|e| Error::Other(format!("{}", e)))?;

        https_builder.set_private_key_file(
            config.https_key_file(),
            SslFiletype::PEM
        ).map_err(|e| Error::Other(format!("{}", e)))?;

        https_builder.set_certificate_chain_file(
            config.https_cert_file()
        ).map_err(|e| Error::Other(format!("{}", e)))?;

        Ok(https_builder)
    }

}


/// # Handle requests
///
impl PubServerApp {

    /// 404 handler
    fn p404(_req: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::NOT_FOUND)
            .body(NOT_FOUND)
    }

    /// Returns a json structure with all publishers in it.
    fn publishers(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match server.publishers() {
            Err(e) => Self::server_error(Error::ServerError(e)),
            Ok(publishers) => {
                Self::render_json(
                    PublisherList::from(&publishers, PATH_PUBLISHERS)
                )
            }
        }
    }

    /// Returns a json structure with publisher details
    fn publisher_details(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match req.match_info().get("handle") {
            None => Self::p404(req),
            Some(handle) => {
                match server.publisher(handle) {
                    Ok(None) => Self::p404(req),
                    Ok(Some(publisher)) => {
                        Self::render_json(
                            PublisherDetails::from(&publisher,
                                                   PATH_PUBLISHERS)
                        )
                    },
                    Err(e) => Self::server_error(Error::ServerError(e))
                }
            }
        }
    }

    /// Returns the id.cer for a publisher
    fn id_cert(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match req.match_info().get("handle") {
            None => Self::p404(req),
            Some(handle) => {
                match server.publisher(handle) {
                    Ok(None) => Self::p404(req),
                    Ok(Some(publisher)) => {
                        let bytes = publisher.id_cert().to_bytes();
                        HttpResponse::Ok()
                            .content_type("application/pkix-cert")
                            .body(bytes)
                    },
                    Err(e) => Self::server_error(Error::ServerError(e))
                }
            }
        }
    }

    /// Shows the server's RFC8183 section 5.2.4 Repository Response XML
    /// file for a known publisher.
    fn repository_response(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();
        match req.match_info().get("handle") {
            None => Self::p404(req),
            Some(handle) => {
                match server.repository_response(handle) {
                    Ok(res) => {
                        HttpResponse::Ok()
                            .content_type("application/xml")
                            .body(res.encode_vec())
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

    /// Processes an RFC8181 query and returns the appropriate response.
    ///
    /// Note this method checks whether the request can be decoded only, and
    /// if successful delegates to [`handle_signed_request`] for further
    /// processing.
    ///
    /// [`handle_signed_request`]: #method.handle_signed_request
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

    /// Handles a decoded RFC8181 query.
    ///
    /// This delegates to `PubServer` to do the actual hard work.
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

    /// Helper function to render json output.
    fn render_json<O: Serialize>(object: O) -> HttpResponse {
        match serde_json::to_string(&object){
            Ok(enc) => {
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(enc)
            },
            Err(e) => Self::server_error(Error::JsonError(e))
        }
    }

    /// Simple server status response page.
    fn service_ok(_r: &HttpRequest) -> HttpResponse {
        // XXX TODO: do a real check
        HttpResponse::Ok().body("I am completely operational, and all my circuits are functioning perfectly.")
    }

    /// Helper function to render server side errors. Also responsible for
    /// logging the errors.
    fn server_error(error: Error) -> HttpResponse {
        error!("{}", error);
        error.error_response()
    }
}


//------------ PublishRequest ------------------------------------------------

/// This type was introduced so that both the handle for the publisher, and
/// the body of an RFC8181 request to the publication server, can be derived
/// from the request by actix.
///
/// Furthermore it allows to use a higher limit to the size of these requests,
/// in this case 256MB (comparison the entire RIPE NCC repository in December
/// 2018 amounted to roughly 100MB).
///
/// We may want to lower this and/or make it configurable, or make it
/// depend on which publisher is sending data.
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
        "css/custom.css" => CSS => "39e0abcc41c3653600f6d8eadb57b17246f1aca7",
        "images/404.png" => PNG => "d48f938ae7a05a033d38f55cfa12a08fb3f3f8db",
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

    #[fail(display = "{}", _0)]
    Other(String),
}


impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("I'm afraid I can't do that: {}", self))
    }
}

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs
