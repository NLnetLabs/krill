//! Actix-web based HTTP server for the publication server.
use std::error;
use std::fs::File;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use actix_web::{pred, server};
use actix_web::{App, FromRequest, HttpResponse, ResponseError};
use actix_web::dev::MessageBody;
use actix_web::middleware;
use actix_web::http::{Method, StatusCode };
use bcder::decode;
use futures::Future;
use openssl::ssl::{SslMethod, SslAcceptor, SslAcceptorBuilder, SslFiletype};
use crate::daemon::api::admin;
use crate::daemon::api::auth::{Authorizer, CheckAuthorisation};
use crate::daemon::config::Config;
use crate::daemon::http::ssl;
use crate::daemon::krillserver;
use crate::daemon::krillserver::KrillServer;
use crate::remote::rfc8183::{PublisherRequest, PublisherRequestError};
use crate::remote::sigmsg::SignedMessage;

const NOT_FOUND: &'static [u8] = include_bytes!("../../../ui/public/404.html");

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<KrillServer>>>);

/// # Set up methods
///
impl PubServerApp {
    pub fn new(server: Arc<RwLock<KrillServer>>) -> Self {
        let app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .middleware(CheckAuthorisation)
            .resource("/api/v1/publishers", |r| {
                r.method(Method::GET).f(admin::publishers);
                r.method(Method::POST).with(admin::add_publisher);
            })
            .resource("/api/v1/publishers/{handle}", |r| {
                r.method(Method::GET).with(admin::publisher_details);
                r.method(Method::POST).with(admin::add_named_publisher);
                r.method(Method::DELETE).with(admin::remove_publisher);
            })
            // For clients that cannot handle http methods
            .resource("/api/v1/publishers/{handle}/del", |r| {
                r.method(Method::POST).with(admin::remove_publisher);
            })
            .resource("/api/v1/publishers/{handle}/response.xml", |r| {
                r.method(Method::GET).with(admin::repository_response)
            })
            .resource("/api/v1/health", |r| {
                r.method(Method::GET).f(Self::api_ok)
            })
            .resource("/rfc8181/{handle}", |r| {
                r.method(Method::POST).with(Self::process_publish_request)
            })
            .resource("/rrdp/{path:.*}", |r| {
                r.method(Method::GET).f(Self::serve_rrdp_files)
            })
            .resource("/health", |r| {
                r.method(Method::GET).f(Self::service_ok)
            })
            .default_resource(|r| {
                // 404 for GET request
                r.method(Method::GET).f(Self::p404);

                // all requests that are not `GET`
                r.route().filter(pred::Not(pred::Get())).f(
                    |_req| HttpResponse::MethodNotAllowed());
            });

        PubServerApp(app)
    }

    pub fn create_server(config: &Config) -> Arc<RwLock<KrillServer>> {
        let authorizer = Authorizer::new(&config.auth_token);
        let pub_server = match KrillServer::new(
            &config.data_dir,
            &config.rsync_base,
            &config.service_uri,
            &config.rrdp_base_uri,
            authorizer
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

        if config.use_ssl() {
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
        if config.test_ssl() {
            ssl::create_key_cert_if_needed(&config.data_dir)
                .map_err(|e| Error::Other(format!("{}", e)))?;
        }

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
            .map_err(|e| Error::Other(format!("{}", e)))?;

        builder.set_private_key_file(
            config.https_key_file(),
            SslFiletype::PEM
        ).map_err(|e| Error::Other(format!("{}", e)))?;

        builder.set_certificate_chain_file(
            config.https_cert_file()
        ).map_err(|e| Error::Other(format!("{}", e)))?;

        Ok(builder)
    }
}


/// # Handle requests
///
impl PubServerApp {

    /// 404 handler
    fn p404(req: &HttpRequest) -> HttpResponse {
        if req.path().starts_with("/api") {
            HttpResponse::build(StatusCode::NOT_FOUND).finish()
        } else {
            HttpResponse::build(StatusCode::NOT_FOUND).body(NOT_FOUND)
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
        handle: PublisherHandle,
        msg: SignedMessage
    ) -> HttpResponse {
        debug!("Processing publish request");
        Self::handle_signed_request(
            req.state().write().unwrap(),
            &msg,
            handle.0.as_str()
        )
    }

    /// Handles a decoded RFC8181 query.
    ///
    /// This delegates to `PubServer` to do the actual hard work.
    fn handle_signed_request(
        mut server: RwLockWriteGuard<KrillServer>,
        msg: &SignedMessage,
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
        let server: RwLockReadGuard<KrillServer> = req.state().read().unwrap();

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

    /// API health check, expect that caller authenticates.
    fn api_ok(_r: &HttpRequest) -> HttpResponse {
        HttpResponse::Ok().body("")
    }

    /// Simple human server status response page.
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


//------------ SignedMessage -------------------------------------------------

/// Support converting requests into SignedMessage.
///
/// Also allows to use a higher limit to the size of these requests, in this
/// case 256MB (comparison the entire RIPE NCC repository in December 2018
/// amounted to roughly 100MB).
///
/// We may want to lower this and/or make it configurable, or make it
/// depend on which publisher is sending data.
/// struct PublishRequest {
impl<S: 'static> FromRequest<S> for SignedMessage {

    type Config = SignedMessageConvertConfig;
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(cfg.limit())
            .from_err()
            .and_then(|bytes| {
                match SignedMessage::decode(bytes, true) {
                    Ok(message) => Ok(message),
                    Err(e) => Err(Error::DecodeError(e).into())
                }
            }))
    }
}

pub struct SignedMessageConvertConfig;
impl SignedMessageConvertConfig {
    fn limit(&self) -> usize {
        255 * 1024 * 1024 // 256 MB
    }
}

impl Default for SignedMessageConvertConfig {
    fn default() -> Self {
        SignedMessageConvertConfig
    }
}

//------------ PublisherRequest ----------------------------------------------

/// Support converting requests into PublisherRequest
impl<S: 'static> FromRequest<S> for PublisherRequest {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                match PublisherRequest::decode(bytes.as_ref()) {
                    Ok(req) => Ok(req),
                    Err(e) => Err(Error::PublisherRequestError(e).into())
                }
            })

        )
    }
}


//------------ PublisherHandle -----------------------------------------------

/// Defines a publisher_handle in a path, then can be built with FromRequest,
/// so that we can easily use this as a parameter on server methods.
pub struct PublisherHandle(pub String);

impl<S> FromRequest<S> for PublisherHandle {
    type Config = ();
    type Result = Result<Self, actix_web::Error>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        if let Some(handle) = req.match_info().get("handle") {
            let handle = handle.to_string();
            Ok(PublisherHandle(handle))
        } else {
            Err(Error::WrongPath.into())
        }
    }
}

impl AsRef<str> for PublisherHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}


//------------ IntoHttpHandler -----------------------------------------------

impl server::IntoHttpHandler for PubServerApp {
    type Handler = <App<Arc<RwLock<KrillServer>>> as server::IntoHttpHandler>::Handler;

    fn into_handler(self) -> Self::Handler {
        self.0.into_handler()
    }
}


//------------ HttpRequest ---------------------------------------------------

pub type HttpRequest = actix_web::HttpRequest<Arc<RwLock<KrillServer>>>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    ServerError(krillserver::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Cannot decode request: {}", _0)]
    DecodeError(decode::Error),

    #[display(fmt = "Cannot decode request: {}", _0)]
    PublisherRequestError(PublisherRequestError),

    #[display(fmt = "Wrong path")]
    WrongPath,

    #[display(fmt = "{}", _0)]
    Other(String),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "An error happened"
    }
}

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("{}", self))
    }
}

//------------ Tests ---------------------------------------------------------

// Tested in tests/integration_test.rs
