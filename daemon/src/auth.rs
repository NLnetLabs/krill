//! Authorization for the API
use std::sync::Arc;

use actix_service::{Service, Transform};
use actix_web::{
    Error,
    FromRequest,
    HttpResponse,
    HttpRequest,
    ResponseError,
};
use actix_web::dev::{
    Payload,
    ServiceResponse,
    ServiceRequest,
};
use actix_web::middleware::identity::Identity;
use actix_web::web::{
    self,
    Json
};
use futures::future::{ok, Either, FutureResult};
use futures::Poll;

use krill_commons::api::admin::Token;

use crate::http::server::AppServer;

pub const AUTH_COOKIE_NAME: &str = "krill_auth";


//------------ Authorizer ----------------------------------------------------

/// This type is responsible for checking authorisations when the API is
/// accessed.
#[derive(Clone, Debug)]
pub struct Authorizer {
    krill_auth_token: Token
}

impl Authorizer {
    pub fn new(krill_auth_token: &Token) -> Self {
        Authorizer {
            krill_auth_token: krill_auth_token.clone()
        }
    }

    pub fn is_api_allowed(&self, token_opt: Option<Token>) -> bool {
        match token_opt {
            None => false,
            Some(secret) => self.krill_auth_token == secret
        }
    }
}

#[derive(Deserialize)]
pub struct Credentials {
    token: Token
}

pub fn login(
    server: web::Data<AppServer>,
    cred: Json<Credentials>,
    id: Identity
) -> HttpResponse {
    if server.read().is_api_allowed(Some(cred.token.clone())) {
        id.remember("admin".to_string());
        HttpResponse::Ok().finish()
    } else {
        info!("Failed login attempt {}", cred.token.as_ref());
        HttpResponse::Forbidden().finish()
    }
}

pub fn logout(
    id: Identity
) -> HttpResponse {
    id.forget();
    HttpResponse::Ok().finish()
}

pub fn is_logged_in(
    _auth: Auth
) -> HttpResponse {
    HttpResponse::Ok().finish()
}


#[derive(Clone)]
pub struct CheckAuthorisation(Arc<Token>);

impl CheckAuthorisation {
    pub fn new(token: &Token) -> Self {
        let arc = Arc::new(token.clone());
        CheckAuthorisation(arc)
    }
}

impl <S, B> Transform<S> for CheckAuthorisation
    where
        S: Service<Request = ServiceRequest, Response=ServiceResponse<B>, Error = Error>,
        S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CheckAuthorisationMiddleware<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CheckAuthorisationMiddleware { token: self.0.clone(), service })
    }
}


pub struct CheckAuthorisationMiddleware<S> {
    token: Arc<Token>,
    service: S
}

impl<S, B> Service for CheckAuthorisationMiddleware<S>
    where
        S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
        S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Either<S::Future, FutureResult<Self::Response, Self::Error>>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        self.service.poll_ready()
    }

    /// This implementation will verify a Bearer token in the HTTPS request
    /// if it is present. I.e. if a token is presented it has to be valid. If
    /// no token is presented then, just pass on. Logged in users are verified
    /// because methods include an Auth parameter, which enforces that either
    /// a user is logged in, or a token is present in its FromRequest
    /// implementation.
    fn call(&mut self, req: Self::Request) -> Self::Future {

        if let Some(header) = req.headers().get("Authorization").cloned() {
            if let Ok(str_header) = header.to_str() {
                if let Ok(token) = Auth::extract_bearer_token(str_header) {
                    if &token == self.token.as_ref() {
                        return Either::A(self.service.call(req))
                    }
                }
            }
            Either::B(ok(req.error_response(AuthError::InvalidToken.error_response())))
        } else {
            // If no Bearer token is present in the header, then just pass on.
            Either::A(self.service.call(req))
        }
    }
}

pub enum Auth {
    User(String),
    Bearer
}

impl Auth {
    /// Extracts the bearer token from header string,
    /// returns an error if parsing fails
    fn extract_bearer_token(header: &str) -> Result<Token, AuthError> {
        let header = header.to_lowercase();
        if header.len() > 6 {
            let (bearer, token) = header.split_at(6);
            let bearer = bearer.trim();
            let token = Token::from(token.trim());

            if "bearer" == bearer {
                return Ok(token)
            }
        }

        Err(AuthError::Unauthorised)
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Result<Auth, Error>;
    type Config = ();

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        if let Some(identity) = Identity::from_request(req, payload)?.identity() {
            info!("Found user: {}", &identity);
            Ok(Auth::User(identity))
        } else if let Some(header) = req.headers().get("Authorization") {
            let _token = Auth::extract_bearer_token(
                header.to_str().map_err(|_| AuthError::InvalidToken)?
            )?;
            Ok(Auth::Bearer)
        } else {
            Err(AuthError::Unauthorised.into())
        }
    }
}


#[derive(Debug, Display)]
pub enum AuthError {
    #[display(fmt = "Neither logged in user, nor bearer token found")]
    Unauthorised,

    #[display(fmt = "Invalid token")]
    InvalidToken
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().finish()
    }
}
