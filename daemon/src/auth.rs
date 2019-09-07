//! Authorization for the API
use actix_identity::Identity;
use actix_web::dev::Payload;
use actix_web::web::{self, Json};
use actix_web::{Error, FromRequest, HttpRequest, HttpResponse, ResponseError};

use krill_commons::api::Token;

use crate::http::server::AppServer;
use std::fmt;

pub const AUTH_COOKIE_NAME: &str = "krill_auth";

//------------ Authorizer ----------------------------------------------------

/// This type is responsible for checking authorisations when the API is
/// accessed.
#[derive(Clone, Debug)]
pub struct Authorizer {
    krill_auth_token: Token,
}

impl Authorizer {
    pub fn new(krill_auth_token: &Token) -> Self {
        Authorizer {
            krill_auth_token: krill_auth_token.clone(),
        }
    }

    pub fn is_api_allowed(&self, token: &Token) -> bool {
        &self.krill_auth_token == token
    }
}

//------------ Credentials ---------------------------------------------------

#[derive(Deserialize)]
pub struct Credentials {
    token: Token,
}

pub fn login(server: web::Data<AppServer>, cred: Json<Credentials>, id: Identity) -> HttpResponse {
    if server.read().login(cred.token.clone()) {
        id.remember("admin".to_string());
        HttpResponse::Ok().finish()
    } else {
        warn!("Failed login attempt {}", cred.token.as_ref());
        HttpResponse::Forbidden().finish()
    }
}

pub fn logout(id: Identity) -> HttpResponse {
    id.forget();
    HttpResponse::Ok().finish()
}

pub fn is_logged_in(_auth: Auth) -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub type UserName = String;

//------------ Auth ----------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Auth {
    User(UserName),
    Bearer(Token),
}

impl Auth {
    /// Extracts the bearer token from header string,
    /// returns an invalid token error if parsing fails
    fn extract_bearer_token(header: &str) -> Result<Token, AuthError> {
        let header = header.to_lowercase();
        if header.len() > 6 {
            let (bearer, token) = header.split_at(6);
            let bearer = bearer.trim();
            let token = Token::from(token.trim());

            if "bearer" == bearer {
                return Ok(token);
            }
        }

        Err(AuthError::InvalidToken)
    }
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Auth::User(user) => write!(f, "User: {}", user),
            Auth::Bearer(token) => write!(f, "Bearer: {}", token),
        }
    }
}

impl Into<Token> for Auth {
    fn into(self) -> Token {
        match self {
            Auth::Bearer(token) => token,
            _ => Token::from(""),
        }
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Result<Auth, Error>;
    type Config = ();

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        if let Some(identity) = Identity::from_request(req, payload)?.identity() {
            debug!("Found user: {}", &identity);
            Ok(Auth::User(identity))
        } else if let Some(header) = req.headers().get("Authorization") {
            let token =
                Auth::extract_bearer_token(header.to_str().map_err(|_| AuthError::InvalidToken)?)?;

            Ok(Auth::Bearer(token))
        } else {
            Err(AuthError::Unauthorised.into())
        }
    }
}

//------------ AuthError -----------------------------------------------------

#[derive(Debug, Display)]
pub enum AuthError {
    #[display(fmt = "Neither logged in user, nor bearer token found")]
    Unauthorised,

    #[display(fmt = "Invalid token")]
    InvalidToken,
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().finish()
    }
}
