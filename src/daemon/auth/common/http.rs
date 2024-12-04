//! HTTP-related functions common to all auth providers.

use crate::commons::api::Token;


//------------ get_bearer_token ----------------------------------------------

/// Gets the Bearer token from the request header, if present.
pub fn get_bearer_token(
    request: &hyper::Request<hyper::body::Incoming>,
) -> Option<Token> {
    request.headers().get(hyper::header::AUTHORIZATION).and_then(|value| {
        value.to_str().ok()
    }).and_then(|header_string| {
        header_string
            .strip_prefix("Bearer ")
            .map(|s| Token::from(s.trim()))
    })
}

