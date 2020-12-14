#[cfg(feature = "multi-user")]
use std::string::FromUtf8Error;
#[cfg(feature = "multi-user")]
use crate::commons::error::Error as KrillError;
#[cfg(feature = "multi-user")]
use urlparse::quote;
#[cfg(feature = "multi-user")]
use crate::daemon::auth::LoggedInUser;

use hyper::Method;
use crate::daemon::http::{HttpResponse, Request, RoutingResult};

pub const AUTH_CALLBACK_ENDPOINT: &str = "/auth/callback";
pub const AUTH_LOGIN_ENDPOINT: &str = "/auth/login";
pub const AUTH_LOGOUT_ENDPOINT: &str = "/auth/logout";

#[cfg(feature = "multi-user")]
fn build_auth_redirect_location(user: LoggedInUser) -> Result<String, FromUtf8Error> {
    let mut location = format!("/index.html#/login?token={}&id={}",
        &quote(user.token, b"")?,
        &quote(user.id, b"")?);

    for (k, v) in &user.attributes {
        location.push_str(&format!("&{}={}", k, quote(v, b"")?));
    }

    Ok(location)
}

fn to_ok_with_err_desc(err: KrillError) -> RoutingResult {
    let location = format!("/index.html#/login?error={}",
        err.to_error_response().label());
    Ok(HttpResponse::found(&location))
}

pub async fn auth(req: Request) -> RoutingResult {
    match req.path.full() {
        #[cfg(feature = "multi-user")]
        AUTH_CALLBACK_ENDPOINT if *req.method() == Method::GET => {
            if log_enabled!(log::Level::Trace) {
                trace!("Authentication callback invoked: {:?}", &req.request);
            }

            req.login().await
                .and_then(|user| {
                    Ok(build_auth_redirect_location(user)
                        .map_err(|err: FromUtf8Error| {
                            KrillError::custom(format!(
                                "Unable to build redirect with logged in user details: {:?}", err))})?)
                })
                .map(|location| HttpResponse::found(&location))
                .or_else(to_ok_with_err_desc)
        },
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::GET => {
            req.get_login_url().await.or_else(to_ok_with_err_desc)
        },
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::POST => {
            match req.login().await {
                Ok(logged_in_user) => Ok(HttpResponse::json(&logged_in_user)),
                Err(_) => Ok(HttpResponse::unauthorized()), // todo: don't discard the error details
            }
        },
        AUTH_LOGOUT_ENDPOINT if *req.method() == Method::POST => {
            req.logout().await.or_else(to_ok_with_err_desc)
        },
        _ => Err(req),
    }
}