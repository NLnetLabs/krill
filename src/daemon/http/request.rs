use std::str::FromStr;
use std::str::from_utf8;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{HeaderMap, Method};
use hyper::body::Body;
use hyper::header::USER_AGENT;
use hyper::http::uri::PathAndQuery;
use log::info;
use rpki::ca::idexchange::MyHandle;
use serde::de::DeserializeOwned;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::error::{ApiAuthError, Error};
use crate::constants::HTTP_USER_AGENT_TRUNCATE;
use super::auth::{AuthInfo, LoggedInUser, Permission};
use super::response::HttpResponse;
use super::server::State;


//------------ HyperRequest --------------------------------------------------

/// A type alias for the request we receive from Hyper.
pub type HyperRequest = hyper::Request<hyper::body::Incoming>;



//------------ Request -------------------------------------------------------

pub struct Request {
    request: HyperRequest,
    path: RequestPath,
    state: State,
    auth: AuthInfo,
}

impl Request {
    pub async fn new(request: HyperRequest, state: State) -> Self {
        let path = RequestPath::from_request(&request);
        let auth = state.authenticate_request(&request).await;

        Request {
            request,
            path,
            state,
            auth,
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        self.request.headers()
    }

    pub fn user_agent(&self) -> Option<String> {
        match self.headers().get(&USER_AGENT) {
            None => None,
            Some(value) => value.to_str().ok().map(|s| {
                // Note: HeaderValue.to_str() only returns ok in case the
                // value is plain       ascii so it's safe to
                // treat bytes as characters here.
                if s.len() > HTTP_USER_AGENT_TRUNCATE {
                    s[..HTTP_USER_AGENT_TRUNCATE].to_string()
                } else {
                    s.to_string()
                }
            }),
        }
    }

    pub async fn upgrade_from_anonymous(&mut self, auth: AuthInfo) {
        if self.auth.actor().is_anonymous() {
            self.auth = auth;
            info!(
                "Permitted anonymous actor to become actor '{}' \
                 for the duration of this request",
                self.auth.actor().name()
            );
        }
    }

    pub fn check_permission(
        &self, 
        permission: Permission,
        resource: Option<&MyHandle>
    ) -> Result<(), ApiAuthError> {
        self.auth.check_permission(permission, resource)
    }

    pub fn actor(&self) -> Actor {
        self.auth.actor().clone()
    }

    pub fn auth_info(&self) -> &AuthInfo {
        &self.auth
    }

    pub fn auth_info_mut(&mut self) -> &mut AuthInfo {
        &mut self.auth
    }

    pub fn request(&self) -> &HyperRequest {
        &self.request
    }

    /// Returns the complete path.
    pub fn path(&self) -> &RequestPath {
        &self.path
    }

    /// Get the application State
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns the method of this request.
    pub fn method(&self) -> &Method {
        self.request.method()
    }

    /// Returns whether the request is a GET request.
    pub fn is_get(&self) -> bool {
        self.request.method() == Method::GET
    }

    /// Returns whether the request is a GET request.
    pub fn is_post(&self) -> bool {
        self.request.method() == Method::POST
    }

    /// Returns whether the request is a DELETE request.
    pub fn is_delete(&self) -> bool {
        self.request.method() == Method::DELETE
    }

    /// Get a json object from a post body
    pub async fn json<O: DeserializeOwned>(self) -> Result<O, Error> {
        let bytes = self.api_bytes().await?;

        let string =
            from_utf8(&bytes).map_err(|_| Error::InvalidUtf8Input)?;
        serde_json::from_str(string).map_err(Error::JsonError)
    }

    pub async fn api_bytes(self) -> Result<Bytes, Error> {
        let limit = self.state().config.post_limit_api;
        self.read_bytes(limit).await
    }

    pub async fn rfc6492_bytes(self) -> Result<Bytes, Error> {
        let limit = self.state().config.post_limit_rfc6492;
        self.read_bytes(limit).await
    }

    pub async fn rfc8181_bytes(self) -> Result<Bytes, Error> {
        let limit = self.state().config.post_limit_rfc8181;
        self.read_bytes(limit).await
    }

    pub async fn read_bytes(self, limit: u64) -> Result<Bytes, Error> {
        // We’re going to cheat a bit. If we know the body is too big from
        // the Content-Length header, we return Error::PostTooBig. But if
        // we don’t -- which means there are multiple chunks or somesuch --
        // we just use http_body_utils::Limited and return PostCannotRead
        // on any error.

        if self.request.body().size_hint().lower() > limit {
            return Err(Error::PostTooBig);
        }

        Ok(Limited::new(
            self.request.into_body(),
            limit.try_into().unwrap_or(usize::MAX),
        )
        .collect()
        .await
        .map_err(|_| Error::PostCannotRead)?
        .to_bytes())
    }

    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.state.get_login_url().await
    }

    pub async fn login(&self) -> KrillResult<LoggedInUser> {
        self.state.login(&self.request).await
    }

    pub async fn logout(&self) -> KrillResult<HttpResponse> {
        self.state.logout(&self.request).await
    }
}

//------------ RequestPath ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct RequestPath {
    path: PathAndQuery,
    segment: (usize, usize),
}

impl std::fmt::Display for RequestPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full())
    }
}

impl RequestPath {
    pub fn from_request<B>(request: &hyper::Request<B>) -> Self {
        let path = request.uri().path_and_query().unwrap().clone();
        let mut res = RequestPath {
            path,
            segment: (0, 0),
        };
        res.next_segment();
        res
    }

    pub fn full(&self) -> &str {
        self.path.path()
    }

    pub fn remaining(&self) -> &str {
        &self.full()[self.segment.1..]
    }

    pub fn segment(&self) -> &str {
        &self.full()[self.segment.0..self.segment.1]
    }

    fn next_segment(&mut self) -> bool {
        let mut start = self.segment.1;
        let path = self.full();
        // Start beyond the length of the path signals the end.
        if start >= path.len() {
            return false;
        }
        // Skip any leading slashes. There may be multiple which should be
        // folded into one (or at least that’s what we do).
        while path.split_at(start).1.starts_with('/') {
            start += 1
        }
        // Find the next slash. If we have one, that’s the end of
        // our segment, otherwise, we go all the way to the end of the path.
        let end = path[start..]
            .find('/')
            .map(|x| x + start)
            .unwrap_or_else(|| path.len());
        self.segment = (start, end);
        true
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&str> {
        if self.next_segment() {
            Some(self.segment())
        } else {
            None
        }
    }

    pub fn path_arg<T>(&mut self) -> Option<T>
    where
        T: FromStr,
    {
        self.next().and_then(|s| T::from_str(s).ok())
    }
}
