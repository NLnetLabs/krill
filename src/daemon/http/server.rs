use std::env;
use std::sync::Arc;
use clap::crate_version;
use hyper::StatusCode;
use log::{error, info, warn, trace};
use tokio::runtime;
use crate::api::admin::ServerInfo;
use crate::api::ca::Timestamp;
use crate::commons::KrillResult;
use crate::commons::error::FatalError;
use crate::config::Config;
use crate::constants::KRILL_ENV_HTTP_LOG_INFO;
use crate::server::oldmanager::OldManager;
use super::auth::Authorizer;
use super::dispatch::{DispatchError, dispatch_request};
use super::request::{BodyLimits, HyperRequest, Request};
use super::response::{HyperResponse, HttpResponse};



//------------ HttpServer ----------------------------------------------------

/// The Krill HTTP server.
pub struct HttpServer {
    /// The Krill “business logic.”
    krill: OldManager,

    /// The component responsible for API authorization checks
    authorizer: Authorizer,

    /// A copy of the configuration.
    config: Arc<Config>,

    /// Time this server was started
    started: Timestamp,
}

impl HttpServer {
    /// Creates a new server from a Krill manager and the configuration.
    pub fn new(
        krill: OldManager,
        config: Arc<Config>,
        runtime: &runtime::Handle,
    ) -> KrillResult<Arc<Self>> {
        let authorizer = Authorizer::new(config.clone())?;
        authorizer.spawn_sweep(runtime);
        Ok(Self {
            krill,
            authorizer,
            config,
            started: Timestamp::now(),
        }.into())
    }

    /// Processes an HTTP request.
    pub async fn process_request(
        &self, request: HyperRequest
    ) -> Result<HyperResponse, FatalError> {
        let logger = RequestLogger::begin(&request);
        let (auth, new_token) = self.authorizer.authenticate_request(
            &request
        ).await;
        let request = Request::new(
            request, self, auth, BodyLimits::from_config(&self.config)
        );
        let path = match request.path() {
            Ok(path) => path,
            Err(err) => {
                return Ok(
                    HttpResponse::error(
                        StatusCode::BAD_REQUEST, err
                    ).into_hyper()
                );
            }
        };

        let mut response = match dispatch_request(
            request, path.iter(),
        ).await {
            Ok(response) => Ok(response),
            Err(DispatchError::Response(response)) => Ok(response),
            Err(DispatchError::Fatal(err)) => Err(err),
        };

        // Augment the response with any updated auth details that were
        // determined above.
        if let (Ok(response), Some(token)) = (response.as_mut(), new_token) {
            response.add_authorization_token(token);
        }

        logger.end(response.as_ref());
        response.map(HttpResponse::into_hyper)
    }
}

impl HttpServer {
    /// Returns a reference to the Krill manager.
    pub(super) fn krill(&self) -> &OldManager {
        &self.krill
    }

    /// Returns a reference to the authorizer.
    pub(super) fn authorizer(&self) -> &Authorizer {
        &self.authorizer
    }

    /// Returns a reference to the configuration.
    pub(super) fn config(&self) -> &Config {
        &self.config
    }

    pub(super) fn server_info(&self) -> ServerInfo {
        ServerInfo { version: crate_version!().into(), started: self.started }
    }
}


//------------ RequestLogger -------------------------------------------------

struct RequestLogger {
    req_method: hyper::Method,
    req_path: String,
}

impl RequestLogger {
    fn begin(req: &HyperRequest) -> Self {
        let req_method = req.method().clone();
        let req_path = req.uri().path().into();

        trace!(
            "Request: method={} path={} headers={:?}",
            &req_method,
            &req_path,
            &req.headers()
        );

        RequestLogger {
            req_method,
            req_path,
        }
    }

    fn end(&self, res: Result<&HttpResponse, &FatalError>) {
        match res {
            Ok(response) => {
                match (response.status(), response.benign(), response.cause())
                {
                    (s, false, Some(cause)) if s.is_client_error() => {
                        warn!("HTTP {}: {}", s.as_u16(), cause)
                    }
                    (s, false, Some(cause)) if s.is_server_error() => {
                        error!("HTTP {}: {}", s.as_u16(), cause)
                    }
                    _ => {}
                }

                if env::var(KRILL_ENV_HTTP_LOG_INFO).is_ok() {
                    info!(
                        "{} {} {}",
                        self.req_method,
                        self.req_path,
                        response.status()
                    );
                }

                if response.loggable() {
                    trace!(
                        "{} {} {}",
                        self.req_method,
                        self.req_path,
                        response.status()
                    );
                    trace!(
                        "Response: headers={:?} body={:?}",
                        response.headers(),
                        response.body()
                    );
                }
            }
            Err(err) => {
                error!(
                    "{} {} Fatal error: {}",
                    self.req_method, self.req_path, err
                );
            }
        }
    }
}

