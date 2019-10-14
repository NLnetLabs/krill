//! Authorization for the API
use std::fmt;

use actix_web::dev::Payload;
use actix_web::{Error, FromRequest, HttpRequest, HttpResponse, ResponseError};

use crate::commons::api::Token;

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

    pub fn is_api_allowed(&self, auth: &Auth) -> bool {
        &self.krill_auth_token == auth.token()
    }
}

//------------ Auth ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Auth(Token);

impl Auth {
    pub fn token(&self) -> &Token {
        &self.0
    }

    /// Extracts the bearer token from header string,
    /// returns an invalid token error if parsing fails
    fn extract_bearer_token(header: &str) -> Result<Token, AuthError> {
        if header.len() > 6 {
            let (bearer, token) = header.split_at(6);
            let bearer = bearer.trim();
            let token = Token::from(token.trim());

            if "Bearer" == bearer {
                return Ok(token);
            }
        }

        Err(AuthError::InvalidToken)
    }
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bearer: {}", self.0)
    }
}

impl Into<Token> for Auth {
    fn into(self) -> Token {
        self.0
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Result<Auth, Error>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        if let Some(header) = req.headers().get("Authorization") {
            let token =
                Auth::extract_bearer_token(header.to_str().map_err(|_| AuthError::InvalidToken)?)?;

            Ok(Auth(token))
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
