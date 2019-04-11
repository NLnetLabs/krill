//! Authorization for the API
use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{Form, HttpResponse, HttpRequest, Result};
use actix_web::http::HeaderMap;
use actix_web::middleware::{Middleware, Started};
use actix_web::middleware::identity::RequestIdentity;
use crate::krillserver::KrillServer;


const ADMIN_API_PATH: &str = "/api/";
const PUBLICATION_API_PATH: &str = "/publication/";

pub struct CheckAuthorisation;

impl Middleware<Arc<RwLock<KrillServer>>> for CheckAuthorisation {
    fn start(
        &self,
        req: &HttpRequest<Arc<RwLock<KrillServer>>>
    ) -> Result<Started> {
        if req.identity() == Some("admin".to_string()) {
            return Ok(Started::Done)
        }

        let server: RwLockReadGuard<KrillServer> = req.state().read().unwrap();

        let mut allowed = true;

        let token_opt = Self::extract_token(req.headers());

        if req.path().starts_with(ADMIN_API_PATH) {
            allowed = server.is_api_allowed(token_opt)
        } else if req.path().starts_with(PUBLICATION_API_PATH) {
            let handle_opt = Self::extract_publication_handle(req.path());
            allowed = server.is_publication_api_allowed(handle_opt, token_opt);
        }

        if allowed {
            Ok(Started::Done)
        } else {
            Ok(Started::Response(HttpResponse::Forbidden().finish()))
        }
    }
}

impl CheckAuthorisation {
    fn extract_token(headers: &HeaderMap) -> Option<String> {
        if let Some(header) = headers.get("Authorization") {
            if let Ok(str_header) = header.to_str() {
                let str_header = str_header.to_lowercase();
                if str_header.len() > 6 {
                    let (bearer, token) = str_header.split_at(6);
                    let bearer = bearer.trim();
                    let token = token.trim();

                    if "bearer" == bearer {
                        return Some(token.to_string())
                    }
                }
            }
        }
        None
    }

    fn extract_publication_handle(path: &str) -> Option<String> {
        if path.starts_with(PUBLICATION_API_PATH) {
            let (_, handle) = path.split_at(PUBLICATION_API_PATH.len());
            Some(handle.to_string())
        } else {
            None
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

    pub fn is_api_allowed(&self, token_opt: Option<String>) -> bool {
        match token_opt {
            None => false,
            Some(secret) => self.krill_auth_token == secret
        }
    }
}

#[derive(Deserialize)]
pub struct Credentials {
    token: String
}

pub fn post_login(
    req: HttpRequest<Arc<RwLock<KrillServer>>>,
    cred: Credentials
) -> HttpResponse {
    let server: RwLockReadGuard<KrillServer> = req.state().read().unwrap();
    if server.is_api_allowed(Some(cred.token.clone())) {
        req.remember("admin".to_string());
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::Forbidden().finish()
    }
}

pub fn post_logout(
    req: &HttpRequest<Arc<RwLock<KrillServer>>>
) -> HttpResponse {
    req.forget();
    HttpResponse::Ok().finish()
}


#[allow(clippy::needless_pass_by_value)]
pub fn login_page(
    req: HttpRequest<Arc<RwLock<KrillServer>>>,
    form: Form<Credentials>
) -> HttpResponse {
    let server: RwLockReadGuard<KrillServer> = req.state().read().unwrap();
    if server.is_api_allowed(Some(form.token.clone())) {
        req.remember("admin".to_string());
        HttpResponse::Found().header("location", "/api/v1/publishers").finish()
    } else {
        HttpResponse::Forbidden().finish()
    }
}

pub fn is_logged_in(
    req: &HttpRequest<Arc<RwLock<KrillServer>>>
) -> HttpResponse {
    if req.identity() == Some("admin".to_string()) {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::Forbidden().finish()
    }
}

