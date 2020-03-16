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
    pub fn bearer(token: Token) -> Self {
        Auth::Bearer(token)
    }
}
