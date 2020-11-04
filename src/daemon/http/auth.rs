use hyper::Method;

use crate::daemon::auth::LoggedInUser;
use crate::daemon::http::{HttpResponse, Request, RoutingResult};

pub const AUTH_CALLBACK_ENDPOINT: &str = "/auth/callback";
pub const AUTH_LOGIN_ENDPOINT: &str = "/auth/login";
pub const AUTH_LOGOUT_ENDPOINT: &str = "/auth/logout";

pub async fn auth(req: Request) -> RoutingResult {
    match req.path.full() {
        // TODO: are callback and login post responses actually one and the
        // same? Both returning an ID and a final token from a temporary token?
        // In the POST login case the temporary token is the API token, but
        // could perhaps better be a one way sha256 hash of the token? In the
        // callback case the token is an OpenID Connect temporary code.
        AUTH_CALLBACK_ENDPOINT if *req.method() == Method::GET => {
            match req.login().await {
                Ok(LoggedInUser { token, id }) => {
                    let quoted_token = urlparse::quote(token, b"").unwrap(); // TODO: remove unwrap
                    let quoted_id = urlparse::quote(id, b"").unwrap(); // TODO: remove unwrap
                    let location = format!("/index.html#/login?token={}&id={}",
                        &quoted_token, &quoted_id);
                    Ok(HttpResponse::found(&location))
                },
                Err(err) => {
                    warn!("Login failed: {}", err);
                    // TODO: render to_error_response() as JSON and set it as
                    // the HTTP 302 Found response body?
                    let location = format!("/index.html#/login?error={}",
                        err.to_error_response().label());
                    Ok(HttpResponse::found(&location))
                },
            }
        },
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::GET => {
            Ok(HttpResponse::text_no_cache(req.get_login_url().await.into_bytes()))
        },
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::POST => {
            match req.login().await {
                Ok(logged_in_user) => Ok(HttpResponse::json(&logged_in_user)),
                Err(_) => Ok(HttpResponse::unauthorized()), // todo: don't discard the error details
            }
        },
        AUTH_LOGOUT_ENDPOINT if *req.method() == Method::POST => {
            Ok(HttpResponse::text_no_cache(req.logout().await.into_bytes()))
        },
        _ => Err(req),
    }
}