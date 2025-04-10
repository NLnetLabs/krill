//! `/auth`

use hyper::Method;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ /auth ---------------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("login") => login(request, path).await,
        Some("logout") => logout(request, path).await,

        #[cfg(feature = "multi-user")]
        Some("callback") => multi_user::callback(request, path).await,

        _ => Ok(HttpResponse::not_found())
    }
}

async fn login(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            path.check_exhausted()?;
            let (request, _) = request.proceed_unchecked();
            let server = request.empty()?;
            Ok(server.authorizer().get_login_url().await?)
        }
        Method::POST => {
            path.check_exhausted()?;
            let (server, request) = request.proceed_raw();
            Ok(HttpResponse::json(
                &server.authorizer().login(&request).await?
            ))
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn logout(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (server, request) = request.proceed_raw();
    Ok(server.authorizer().logout(&request).await?)
}


#[cfg(feature = "multi-user")]
mod multi_user {
    use base64::engine::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
    use log::trace;
    use crate::commons::error::Error;
    use crate::daemon::http::auth::LoggedInUser;
    use crate::daemon::http::util::url_encode;
    use super::*;

    pub async fn callback(
        request: Request<'_>,
        path: PathIter<'_>,
    ) -> Result<HttpResponse, DispatchError> {
        path.check_exhausted()?;
        request.check_get()?;
        
        trace!(
            "Authentication callback invoked: {:?}", &request.hyper()
        );
        
        let (server, request) = request.proceed_raw();
        server.authorizer().login(&request).await.and_then(|user| {
            build_auth_redirect_location(user).map_err(|err| {
                Error::custom(format!(
                    "Unable to build redirect with logged in user details: \
                     {:?}",
                    err
                ))
            })
        }).map(|location| {
            HttpResponse::found(&location)
        }).or_else(|err| {
            // HTTP redirects cannot have a response body and so we cannot
            // render the error to be displayed in Lagosta as a JSON body,
            // instead we must package the JSON as a query parameter.
            let location = match serde_json::to_string(
                &err.to_error_response()
            ) {
                Ok(json) => {
                    format!("/ui/login?error={}", BASE64_ENGINE.encode(json))
                }
                Err(_) => String::from("/ui/login")
            };
            Ok(HttpResponse::found(&location))
        })
    }

    fn build_auth_redirect_location(
        user: LoggedInUser
    ) -> Result<String, Error> {
        fn b64_encode_attributes_with_mapped_error(
            a: &impl serde::Serialize,
        ) -> Result<String, Error> {
            Ok(BASE64_ENGINE.encode(
                serde_json::to_string(a)
                    .map_err(|err| Error::custom(err.to_string()))?,
            ))
        }

        let attributes = b64_encode_attributes_with_mapped_error(
            user.attributes()
        )?;

        Ok(format!(
            "/ui/login?token={}&id={}&attributes={}",
            &url_encode(user.token())?,
            &url_encode(user.id())?,
            &url_encode(attributes)?,
        ))
    }
}

