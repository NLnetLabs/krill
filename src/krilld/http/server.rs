//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::error;
use std::fs::File;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{pred, fs, server};
use actix_web::{App, FromRequest, HttpResponse};
use actix_web::dev::MessageBody;
use actix_web::middleware;
use actix_web::http::{Method, StatusCode};
use bcder::decode;
use futures::Future;
use openssl::ssl::{SslMethod, SslAcceptor, SslAcceptorBuilder, SslFiletype};
use crate::api::publication;
use crate::api::publishers;
use crate::krilld::auth::{Authorizer, CheckAuthorisation};
use crate::krilld::config::Config;
use crate::krilld::endpoints;
use crate::krilld::http::ssl;
use crate::krilld::krillserver;
use crate::krilld::krillserver::KrillServer;
use crate::remote::rfc8183;
use crate::remote::sigmsg::SignedMessage;

const NOT_FOUND: &'static [u8] = include_bytes!("../../../ui/dev/html/404.html");

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<KrillServer>>>);


/// # Set up methods
///
impl PubServerApp {
    pub fn new(server: Arc<RwLock<KrillServer>>) -> Self {
        let mut app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .middleware(CheckAuthorisation)
            .resource("/api/v1/publishers", |r| {
                r.method(Method::GET).f(endpoints::publishers);
                r.method(Method::POST).with(endpoints::add_publisher);
            })
            .resource("/api/v1/publishers/{handle}", |r| {
                r.method(Method::GET).with(endpoints::publisher_details);
                r.method(Method::DELETE).with(endpoints::remove_publisher);
            })
            // For clients that cannot handle http methods
            .resource("/api/v1/publishers/{handle}/del", |r| {
                r.method(Method::POST).with(endpoints::remove_publisher);
            })
            .resource("/api/v1/publishers/{handle}/response.xml", |r| {
                r.method(Method::GET).with(endpoints::repository_response)
            })
            .resource("/rfc8181/{handle}", |r| {
                r.method(Method::POST).with(endpoints::handle_rfc8181_request)
            })
            .resource("/publication/{handle}", |r| {
                r.method(Method::GET).with(endpoints::handle_list);
                r.method(Method::POST).with(endpoints::handle_delta);
            })
            .resource("/rrdp/{path:.*}", |r| {
                r.method(Method::GET).f(Self::serve_rrdp_files)
            })
            .resource("/health", |r| { // No authentication required
                r.method(Method::GET).f(endpoints::health)
            })
            .resource("/api/v1/health", |r| { // health with authentication
                r.method(Method::GET).f(endpoints::health)
            })
            .default_resource(|r| {
                // 404 for GET request
                r.method(Method::GET).f(Self::p404);

                // all requests that are not `GET`
                r.route().filter(pred::Not(pred::Get())).f(
                    |_req| HttpResponse::MethodNotAllowed());
            });

        use std::env;
        match env::var("KRILL_DEV_MODE") {
            Ok(_) => {
                app = app.handler(
                    "/ui/dev",
                    fs::StaticFiles::new("./ui/dev")
                        .unwrap()
                        .show_files_listing()
                );
            },
            _ => {}
        }

        PubServerApp(with_statics(app))
    }

    pub fn create_server(config: &Config) -> Arc<RwLock<KrillServer>> {
        let authorizer = Authorizer::new(&config.auth_token);
        let pub_server = match KrillServer::new(
            &config.data_dir,
            &config.rsync_base,
            config.service_uri(),
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

    /// Used to start the server with an existing executor (for tests)
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

    /// Used to set up HTTPS. Creates keypair and self signed certificate
    /// if config has 'use_ssl=test'.
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

    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(255 * 1024 * 1024) // 256 MB
            .from_err()
            .and_then(|bytes| {
                match SignedMessage::decode(bytes, true) {
                    Ok(message) => Ok(message),
                    Err(e) => Err(Error::DecodeError(e).into())
                }
            }))
    }
}


//------------ Publisher ----------------------------------------------------

/// Converts the body sent to 'add publisher' end-points to a
/// PublisherRequestChoice, which contains either an
/// rfc8183::PublisherRequest, or an API publisher request (no ID certs and
/// CMS etc).
impl<S: 'static> FromRequest<S> for publishers::Publisher {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                let p: publishers::Publisher =
                    serde_json::from_reader(bytes.as_ref())
                    .map_err(|e| Error::JsonError(e))?;
                Ok(p)
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


//------------ PublishDelta --------------------------------------------------
/// Support converting request body into PublishDelta
impl<S: 'static> FromRequest<S> for publication::PublishDelta {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(255 * 1024 * 1024) // up to 256MB
            .from_err()
            .and_then(|bytes| {
                let delta: publication::PublishDelta =
                    serde_json::from_reader(bytes.as_ref())
                    .map_err(|e| Error::JsonError(e))?;
                Ok(delta)
            })
        )
    }
}


//------------ IntoHttpHandler -----------------------------------------------

impl server::IntoHttpHandler for PubServerApp {
    type Handler = <App<Arc<RwLock<KrillServer>>> as server::IntoHttpHandler>::Handler;

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
    Wrong8183Xml(rfc8183::PublisherRequestError),

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
