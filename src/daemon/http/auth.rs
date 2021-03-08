use crate::commons::error::Error;
#[cfg(feature = "multi-user")]
use crate::daemon::http::server::render_error_redirect;

#[cfg(feature = "multi-user")]
use {crate::daemon::auth::LoggedInUser, urlparse::quote};

use crate::daemon::http::{HttpResponse, Request, RoutingResult};
use hyper::Method;

pub const AUTH_CALLBACK_ENDPOINT: &str = "/auth/callback";
pub const AUTH_LOGIN_ENDPOINT: &str = "/auth/login";
pub const AUTH_LOGOUT_ENDPOINT: &str = "/auth/logout";

#[cfg(feature = "multi-user")]
pub fn url_encode<S: AsRef<str>>(s: S) -> Result<String, Error> {
    quote(s, b"").map_err(|err| Error::custom(err.to_string()))
}

#[cfg(feature = "multi-user")]
fn build_auth_redirect_location(user: LoggedInUser) -> Result<String, Error> {
    use std::collections::HashMap;

    fn b64_encode_attributes_with_mapped_error(a: &HashMap<String, String>) -> Result<String, Error> {
        Ok(base64::encode(
            serde_json::to_string(a).map_err(|err| Error::custom(err.to_string()))?,
        ))
    }

    let attributes = b64_encode_attributes_with_mapped_error(&user.attributes)?;

    Ok(format!(
        "/index.html#/login?token={}&id={}&attributes={}",
        &url_encode(user.token)?,
        &url_encode(user.id)?,
        &url_encode(attributes)?
    ))
}

fn render_error(err: Error) -> RoutingResult {
    Ok(HttpResponse::response_from_error(err))
}

pub async fn auth(req: Request) -> RoutingResult {
    match req.path.full() {
        #[cfg(feature = "multi-user")]
        AUTH_CALLBACK_ENDPOINT if *req.method() == Method::GET => {
            if log_enabled!(log::Level::Trace) {
                trace!("Authentication callback invoked: {:?}", &req.request);
            }

            req.login()
                .await
                .and_then(|user| {
                    Ok(build_auth_redirect_location(user).map_err(|err| {
                        Error::custom(format!(
                            "Unable to build redirect with logged in user details: {:?}",
                            err
                        ))
                    })?)
                })
                .map(|location| HttpResponse::found(&location))
                .or_else(render_error_redirect)
        }
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::GET => req.get_login_url().await.or_else(render_error),
        AUTH_LOGIN_ENDPOINT if *req.method() == Method::POST => match req.login().await {
            Ok(logged_in_user) => Ok(HttpResponse::json(&logged_in_user)),
            Err(err) => render_error(err),
        },
        AUTH_LOGOUT_ENDPOINT if *req.method() == Method::POST => req.logout().await.or_else(render_error),
        _ => Err(req),
    }
}
