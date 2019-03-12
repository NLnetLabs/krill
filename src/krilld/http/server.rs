//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::io;
use std::fs::File;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{pred, fs, server};
use actix_web::{App, FromRequest, HttpResponse};
use actix_web::dev::MessageBody;
use actix_web::middleware;
use actix_web::middleware::identity::CookieIdentityPolicy;
use actix_web::middleware::identity::IdentityService;
use actix_web::http::{Method, StatusCode};
use bcder::decode;
use futures::Future;
use openssl::ssl::{SslMethod, SslAcceptor, SslAcceptorBuilder, SslFiletype};
use crate::api::publication_data;
use crate::api::publisher_data;
use crate::api::publisher_data::PublisherHandle;
use crate::eventsourcing::DiskKeyStore;
use crate::krilld::auth;
use crate::krilld::auth::{Authorizer, CheckAuthorisation};
use crate::krilld::config::Config;
use crate::krilld::endpoints;
use crate::krilld::http::ssl;
use crate::krilld::krillserver;
use crate::krilld::krillserver::KrillServer;

const NOT_FOUND: &[u8] = include_bytes!("../../../ui/dev/html/404.html");
const LOGIN: &[u8] = include_bytes!("../../../ui/dev/html/login.html");


//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<KrillServer<DiskKeyStore>>>>);


/// # Set up methods
///
impl PubServerApp {
    pub fn new(server: Arc<RwLock<KrillServer<DiskKeyStore>>>) -> Self {
        let mut app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .middleware(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("krilld_login")
                    .secure(false)
                )
            )
            .middleware(CheckAuthorisation)
            .resource("/login", |r| {
                r.method(Method::GET).f(Self::login_page);
                r.method(Method::POST).with(auth::login_page);
            })
            .resource("/api/v1/publishers", |r| {
                r.method(Method::GET).f(endpoints::publishers);
                r.method(Method::POST).with(endpoints::add_publisher);
            })
            .resource("/api/v1/publishers/{handle}", |r| {
                r.method(Method::GET).with(endpoints::publisher_details);
                r.method(Method::DELETE).with(endpoints::deactivate_publisher);
            })
            // For clients that cannot handle http methods
            .resource("/api/v1/publishers/{handle}/del", |r| {
                r.method(Method::POST).with(endpoints::deactivate_publisher);
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
        if env::var("KRILL_DEV_MODE").is_ok() {
            app = app.handler(
                "/ui/dev",
                fs::StaticFiles::new("./ui/dev")
                    .unwrap()
                    .show_files_listing()
            );
        }

        PubServerApp(with_statics(app))
    }

    pub fn create_server(
        config: &Config
    ) -> Result<Arc<RwLock<KrillServer<DiskKeyStore>>>, Error> {
        let authorizer = Authorizer::new(&config.auth_token);

        let pubserver_store = DiskKeyStore::under_work_dir(&config.data_dir, "pubsrv")?;

        let pub_server = KrillServer::build(
            &config.data_dir,
            &config.rsync_base,
            config.service_uri(),
            &config.rrdp_base_uri,
            authorizer,
            pubserver_store
        )?;

        Ok(Arc::new(RwLock::new(pub_server)))
    }

    /// Used to start the server with an existing executor (for tests)
    ///
    /// Note https is not supported in tests.
    pub fn start(config: &Config) {
        let ps = match PubServerApp::create_server(config) {
            Ok(server) => server,
            Err(e) => {
                eprintln!("{}", e);
                ::std::process::exit(1);
            }
        };

        server::new(move || PubServerApp::new(ps.clone()))
            .bind(config.socket_addr())
            .unwrap_or_else(|_| panic!("Cannot bind to: {}", config.socket_addr()))
            .shutdown_timeout(0)
            .start();
    }

    /// Used to run the server in blocking mode, from the main method.
    pub fn run(config: &Config) {
        let ps = match PubServerApp::create_server(config) {
            Ok(server) => server,
            Err(e) => {
                eprintln!("{}", e);
                ::std::process::exit(1);
            }
        };

        let server = server::new(move || PubServerApp::new(ps.clone()));

        if config.use_ssl() {
            match Self::https_builder(config) {
                Ok(https_builder) => {
                    server.bind_ssl(config.socket_addr(), https_builder)
                        .unwrap_or_else(|_| panic!("Cannot bind to: {}", config.socket_addr()))
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
                .unwrap_or_else(|_| panic!("Cannot bind to: {}", config.socket_addr()))
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

    /// Login page
    fn login_page(_r: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::NOT_FOUND).body(LOGIN)
    }

    // XXX TODO: use a better handler that does not load everything into
    // memory first, and set the correct headers for caching.
    // See also:
    // https://github.com/actix/actix-website/blob/master/content/docs/static-files.md
    // https://www.keycdn.com/blog/http-cache-headers
    fn serve_rrdp_files(req: &HttpRequest) -> HttpResponse {
        let server: RwLockReadGuard<KrillServer<DiskKeyStore>> = req.state().read()
            .unwrap();

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


//------------ Publisher ----------------------------------------------------

/// Converts the body sent to 'add publisher' end-points to a
/// PublisherRequestChoice, which contains either an
/// rfc8183::PublisherRequest, or an API publisher request (no ID certs and
/// CMS etc).
impl<S: 'static> FromRequest<S> for publisher_data::PublisherRequest {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                let p: publisher_data::PublisherRequest =
                    serde_json::from_reader(bytes.as_ref())
                    .map_err(Error::JsonError)?;
                Ok(p)
            })
        )
    }
}


//------------ PublisherHandle -----------------------------------------------

impl<S> FromRequest<S> for PublisherHandle {
    type Config = ();
    type Result = Result<Self, actix_web::Error>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        if let Some(handle) = req.match_info().get("handle") {
            Ok(PublisherHandle::from(handle))
        } else {
            Err(Error::WrongPath.into())
        }
    }
}


//------------ PublishDelta --------------------------------------------------
/// Support converting request body into PublishDelta
impl<S: 'static> FromRequest<S> for publication_data::PublishDelta {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(255 * 1024 * 1024) // up to 256MB
            .from_err()
            .and_then(|bytes| {
                let delta: publication_data::PublishDelta =
                    serde_json::from_reader(bytes.as_ref())?;
                Ok(delta)
            })
        )
    }
}


//------------ IntoHttpHandler -----------------------------------------------

impl server::IntoHttpHandler for PubServerApp {
    type Handler = <App<Arc<RwLock<KrillServer<DiskKeyStore>>>> as server::IntoHttpHandler>::Handler;

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

pub type HttpRequest = actix_web::HttpRequest<Arc<RwLock<KrillServer<DiskKeyStore>>>>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    ServerError(krillserver::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Cannot decode request: {}", _0)]
    DecodeError(decode::Error),

    #[display(fmt = "Wrong path")]
    WrongPath,

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    Other(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<krillserver::Error> for Error {
    fn from(e: krillserver::Error) -> Self { Error::ServerError(e) }
}

impl std::error::Error for Error {
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
