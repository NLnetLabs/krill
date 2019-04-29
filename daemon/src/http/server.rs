//! Actix-web based HTTP server for the publication server.
//!
//! Here we deal with booting and setup, and once active deal with parsing
//! arguments and routing of requests, typically handing off to the
//! daemon::api::endpoints functions for processing and responding.
use std::io;
use std::fs::File;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{pred, server};
use actix_web::{App, FromRequest, HttpResponse };
use actix_web::dev::MessageBody;
use actix_web::middleware;
use actix_web::middleware::identity::CookieIdentityPolicy;
use actix_web::middleware::identity::IdentityService;
use actix_web::http::{Method, StatusCode};
use bcder::decode;
use futures::Future;
use openssl::ssl::{SslMethod, SslAcceptor, SslAcceptorBuilder, SslFiletype};
use crate::auth::{self, Authorizer, CheckAuthorisation, Credentials};
use crate::config::Config;
use crate::endpoints;
use crate::http::ssl;
use crate::krillserver;
use crate::krillserver::KrillServer;

const NOT_FOUND: &[u8] = include_bytes!("../../ui/dist/404.html");

//------------ PubServerApp --------------------------------------------------

pub struct PubServerApp(App<Arc<RwLock<KrillServer>>>);


/// # Set up methods
///
impl PubServerApp {
    pub fn new(server: Arc<RwLock<KrillServer>>) -> Self {
        let app = App::with_state(server)
            .middleware(middleware::Logger::default())
            .middleware(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("krilld_login")
                    .secure(false)
                )
            )
            .middleware(CheckAuthorisation)
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

            .resource("/api/v1/rfc8181/clients", |r| {
                r.method(Method::GET).f(endpoints::rfc8181_clients);
                r.method(Method::POST).with(endpoints::add_rfc8181_client)
            })

            .resource("/api/v1/rfc8181/{handle}/response.xml", |r| {
                r.method(Method::GET).with(endpoints::repository_response)
            })

            .resource("/publication/{handle}", |r| {
                r.method(Method::GET).with(endpoints::handle_list);
                r.method(Method::POST).with_config(endpoints::handle_delta, |cfg| {
                    cfg.1.limit(256 * 1024 * 1024); //up to 256MB;
                })
            })

            .resource("/rfc8181/{handle}", |r| {
                r.method(Method::POST).with(endpoints::handle_rfc8181_request)
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
            .resource("/ui/is_logged_in", |r| {
                r.method(Method::GET).f(auth::is_logged_in)
            })
            .resource("/ui/login", |r| {
                r.method(Method::POST).with(auth::post_login)
            })
            .resource("/ui/logout", |r| {
                r.method(Method::POST).f(auth::post_logout)
            })
            .resource("/", |r| {
                r.method(Method::GET).f(
                    |_r| {
                        HttpResponse::Found()
                            .header("location", "/ui/index.html")
                            .finish()
                    }
                )
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


    pub fn create_server(
        config: &Config
    ) -> Result<Arc<RwLock<KrillServer>>, Error> {
        let authorizer = Authorizer::new(&config.auth_token);

        let pub_server = KrillServer::build(
            &config.data_dir,
            &config.rsync_base,
            config.service_uri(),
            &config.rrdp_base_uri,
            authorizer,
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


//------------ Credentials --------------------------------------------------

impl<S: 'static> FromRequest<S> for Credentials {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _c: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                let credentials: Credentials =
                    serde_json::from_reader(bytes.as_ref())
                        .map_err(Error::JsonError)?;
                Ok(credentials)
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

static HTML:  &[u8] = b"text/html";
static FAV:   &[u8] = b"image/x-icon";
static JS:    &[u8] = b"application/javascript";
static CSS:   &[u8] = b"text/css";
static SVG:   &[u8] = b"image/svg+xml";
static WOFF:  &[u8] = b"font/woff";
static WOFF2: &[u8] = b"font/woff2";

fn with_statics<S: 'static>(app: App<S>) -> App<S> {
    statics!(app,
        "404.html" => HTML,
        "index.html" => HTML,

        "favicon.ico" => FAV,

        "js/app.js" => JS,
        "js/app.js.map" => JS,

        "css/app.css" => CSS,

        "img/krill_logo_white.svg" => SVG,
        "img/route_left.svg" => SVG,
        "img/route_right.svg" => SVG,

        "fonts/element-icons.woff" => WOFF,
        "fonts/lato-latin-100.woff" => WOFF,
        "fonts/lato-latin-100italic.woff" => WOFF,
        "fonts/lato-latin-300.woff" => WOFF,
        "fonts/lato-latin-300italic.woff" => WOFF,
        "fonts/lato-latin-400.woff" => WOFF,
        "fonts/lato-latin-400italic.woff" => WOFF,
        "fonts/lato-latin-700.woff" => WOFF,
        "fonts/lato-latin-700italic.woff" => WOFF,
        "fonts/lato-latin-900.woff" => WOFF,
        "fonts/lato-latin-900italic.woff" => WOFF,
        "fonts/source-code-pro-latin-200.woff" => WOFF,
        "fonts/source-code-pro-latin-300.woff" => WOFF,
        "fonts/source-code-pro-latin-400.woff" => WOFF,
        "fonts/source-code-pro-latin-500.woff" => WOFF,
        "fonts/source-code-pro-latin-600.woff" => WOFF,
        "fonts/source-code-pro-latin-700.woff" => WOFF,
        "fonts/source-code-pro-latin-900.woff" => WOFF,

        "fonts/lato-latin-100.woff2" => WOFF2,
        "fonts/lato-latin-100italic.woff2" => WOFF2,
        "fonts/lato-latin-300.woff2" => WOFF2,
        "fonts/lato-latin-300italic.woff2" => WOFF2,
        "fonts/lato-latin-400.woff2" => WOFF2,
        "fonts/lato-latin-400italic.woff2" => WOFF2,
        "fonts/lato-latin-700.woff2" => WOFF2,
        "fonts/lato-latin-700italic.woff2" => WOFF2,
        "fonts/lato-latin-900.woff2" => WOFF2,
        "fonts/lato-latin-900italic.woff2" => WOFF2,
        "fonts/source-code-pro-latin-200.woff2" => WOFF2,
        "fonts/source-code-pro-latin-300.woff2" => WOFF2,
        "fonts/source-code-pro-latin-400.woff2" => WOFF2,
        "fonts/source-code-pro-latin-500.woff2" => WOFF2,
        "fonts/source-code-pro-latin-600.woff2" => WOFF2,
        "fonts/source-code-pro-latin-700.woff2" => WOFF2,
        "fonts/source-code-pro-latin-900.woff2" => WOFF2,
    )
}


//------------ HttpRequest ---------------------------------------------------

pub type HttpRequest = actix_web::HttpRequest<Arc<RwLock<KrillServer>>>;


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
