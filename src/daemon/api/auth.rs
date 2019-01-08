//! Authorization for the API

use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{HttpResponse, HttpRequest, Result};
use actix_web::http::HeaderMap;
use actix_web::middleware::{Middleware, Started};
use crate::daemon::pubserver::PubServer;

pub struct CheckAuthorisation;

impl Middleware<Arc<RwLock<PubServer>>> for CheckAuthorisation {
    fn start(
        &self,
        req: &HttpRequest<Arc<RwLock<PubServer>>>
    ) -> Result<Started> {
        let server: RwLockReadGuard<PubServer> = req.state().read().unwrap();

        if server.authorizer().allowed(req.path(), req.headers()) {
            Ok(Started::Done)
        } else {
            Ok(
                Started::Response(
                    HttpResponse::Forbidden().finish()
                )
            )
        }
    }
}


//------------ Authorizer ----------------------------------------------------

/// This type is responsible for checking authorisations when the API is
/// accessed.
#[derive(Clone, Debug)]
pub struct Authorizer {
    krill_auth_token: String
}

impl Authorizer {
    pub fn new(krill_auth_token: &str) -> Self {
        Authorizer {
            krill_auth_token: krill_auth_token.to_string()
        }
    }

    pub fn allowed(&self, path: &str, headers: &HeaderMap) -> bool {
        if path.starts_with("/api/v1") {
            if let Some(header) = headers.get("Authorization") {
                if let Ok(str_header) = header.to_str() {
                    let str_header = str_header.to_lowercase();
                    if str_header.len() > 6 {
                        let (bearer, token) = str_header.split_at(6);
                        let bearer = bearer.trim();
                        let token = token.trim();

                        return "bearer" == bearer &&
                        self.krill_auth_token.as_str().to_lowercase() == token
                    }
                }
            }
            return false
        } else {
            true
        }
    }
}