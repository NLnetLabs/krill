//! Authorization for the API

use crate::commons::api::Token;

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
        match auth {
            Auth::Bearer(token) => &self.krill_auth_token == token,
        }
    }
}

pub enum Auth {
    Bearer(Token),
}

impl Auth {
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

// impl FromRequest for Auth {
//     type Error = Error;
//     type Future = Result<Auth, Error>;
//     type Config = ();
//
//     fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
//         if let Some(header) = req.headers().get("Authorization") {
//             let token =
//                 Auth::extract_bearer_token(header.to_str().map_err(|_| AuthError::InvalidToken)?)?;
//
//             Ok(Auth::Bearer(token))
//         } else {
//             Err(AuthError::Unauthorised.into())
//         }
//     }
// }

#[derive(Debug, Display)]
pub enum AuthError {
    #[display(fmt = "No bearer token found")]
    Unauthorised,

    #[display(fmt = "Invalid token")]
    InvalidToken,
}

// impl ResponseError for AuthError {
//     fn error_response(&self) -> Response {
//         unimplemented!("#189")
//     }
// }
