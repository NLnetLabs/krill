//! HTTP requests.

#![allow(dead_code)] // XXX

use std::{fmt, str};
use std::borrow::Cow;
use std::str::FromStr;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::Method;
use hyper::body::Body;
use hyper::header::USER_AGENT;
use hyper::http::uri::PathAndQuery;
use percent_encoding::percent_decode;
use rpki::ca::idexchange::MyHandle;
use serde::de::DeserializeOwned;
use crate::api::status::ErrorResponse;
use crate::commons::error::Error;
use crate::config::Config;
use crate::constants::HTTP_USER_AGENT_TRUNCATE;
use super::auth::{AuthInfo, Permission};
use super::response::HttpResponse;
use super::server::HttpServer;


//------------ HyperRequest --------------------------------------------------

/// A type alias for the request we receive from Hyper.
pub type HyperRequest = hyper::Request<hyper::body::Incoming>;


//------------ Request -------------------------------------------------------

/// An enriched request.
pub struct Request<'a> {
    /// The underlying raw request.
    request: HyperRequest,

    /// The server providing access to Krill itself.
    server: &'a HttpServer,

    /// Authentication information for the request.
    auth: AuthInfo,

    /// The limits for reading the body of the request.
    limits: BodyLimits,
}

impl<'a> Request<'a> {
    /// Creates a request from the various necessary information.
    pub fn new(
        request: HyperRequest,
        server: &'a HttpServer,
        auth: AuthInfo,
        limits: BodyLimits,
    ) ->Self {
        Self { request, server, auth, limits }
    }

    /// Returns whether testbed mode is enabled.
    pub fn testbed_enabled(&self) -> bool {
        self.server.krill().testbed_enabled()
    }

    /// Returns the method of this request.
    pub fn method(&self) -> &Method {
        self.request.method()
    }

    /// Checks whether the request is a GET or returns an error response.
    pub fn check_get(&self) -> Result<(), HttpResponse> {
        match *self.request.method() {
            Method::GET => Ok(()),
            _ => Err(HttpResponse::method_not_allowed()),
        }
    }

    /// Checks whether the request is a POST or returns an error response.
    pub fn check_post(&self) -> Result<(), HttpResponse> {
        match *self.request.method() {
            Method::POST => Ok(()),
            _ => Err(HttpResponse::method_not_allowed()),
        }
    }

    /// Checks whether the request is a POST or returns an error response.
    pub fn check_delete(&self) -> Result<(), HttpResponse> {
        match *self.request.method() {
            Method::DELETE => Ok(()),
            _ => Err(HttpResponse::method_not_allowed()),
        }
    }

    /*
    /// Returns the full URI of the request.
    pub fn uri(&self) -> &Uri {
        self.request.uri()
    }
    */

    /// Returns the current request path.
    pub fn path(&self) -> Result<RequestPath, InvalidPath> {
        RequestPath::from_request(self)
    }

    /// Returns a reference to the Hyper request.
    pub fn hyper(&self) -> &HyperRequest {
        &self.request
    }

    /*
    /// Returns the headers of the request.
    pub fn headers(&self) -> &HeaderMap {
        self.request.headers()
    }
    */

    /// Returns the user agent header if present.
    pub fn user_agent(&self) -> Option<String> {
        match self.request.headers().get(&USER_AGENT) {
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

    /// Checks for permissions.
    ///
    /// Returns an appropriate error response if the permissions are not met.
    pub fn check_permission(
        &self, permission: Permission, resource: Option<&MyHandle>
    ) -> Result<(), HttpResponse> {
        self.auth.check_permission(permission, resource).map_err(|err| {
            HttpResponse::response_from_error(Error::from(err))
        })
    }

    /// Checks the permissions and progresses to the next processing stage.
    ///
    /// If the authentication information for the request has the given
    /// permissions, returns an [`AuthedRequest`] and an [`Actor`] which
    /// allow further processing.
    ///
    /// Otherwise returns an appropriate error response.
    pub fn proceed_permitted(
        self, 
        permission: Permission,
        resource: Option<&MyHandle>,
    ) -> Result<(AuthedRequest<'a>, AuthInfo), HttpResponse> {
        self.check_permission(permission, resource)?;
        Ok((
            AuthedRequest {
                request: self.request,
                server: self.server,
                limits: self.limits,
            },
            self.auth
        ))
    }

    /// Permits the request to the next processing stage.
    ///
    /// Returns [`AuthedRequest`] and [`Actor`] without requiring any
    /// permissions whatsoever.
    pub fn proceed_unchecked(
        self
    ) -> (AuthedRequest<'a>, AuthInfo) {
        (
            AuthedRequest {
                request: self.request,
                server: self.server,
                limits: self.limits,
            },
            self.auth
        )
    }

    /// Splits the request into the server and raw Hyper request.
    pub fn proceed_raw(self) -> (&'a HttpServer, HyperRequest) {
        (self.server, self.request)
    }
}


//------------ AuthedRequest -------------------------------------------------

/// A request that has been checked for the correct access permissions.
///
/// This type allows access to the request’s body and, by way of reading the
/// body or forcing it to be empty, to the server.
pub struct AuthedRequest<'a> {
    /// The underlying raw request.
    request: HyperRequest,

    /// The server providing access to Krill itself.
    server: &'a HttpServer,

    /// The limits for reading the body of the request.
    limits: BodyLimits,
}

impl<'a> AuthedRequest<'a> {
    /// Ensures the body is empty.
    pub fn empty(self) -> Result<&'a HttpServer, Error> {
        if self.request.body().size_hint().upper() != Some(0) {
            return Err(Error::UnexpectedBody)
        }
        Ok(self.server)
    }

    /// Returns the raw bytes of the request body.
    pub async fn read_bytes(self) -> Result<(&'a HttpServer, Bytes), Error> {
        let limit = self.limits.post_limit_api;
        self.read_body(limit).await
    }

    /// Get a json object from a post body
    pub async fn read_json<T: DeserializeOwned>(
        self
    ) -> Result<(&'a HttpServer, T), Error> {
        let (server, bytes) = self.read_bytes().await?;
        let json = serde_json::from_slice(&bytes).map_err(Error::JsonError)?;
        Ok((server, json))
    }

    /// Returns the raw bytes of a provisioning protocol request.
    pub async fn read_rfc6492_bytes(
        self
    ) -> Result<(&'a HttpServer, Bytes), Error> {
        let limit = self.limits.post_limit_rfc6492;
        self.read_body(limit).await
    }

    pub async fn read_rfc8181_bytes(
        self
    ) -> Result<(&'a HttpServer, Bytes), Error> {
        let limit = self.limits.post_limit_rfc8181;
        self.read_body(limit).await
    }

    async fn read_body(
        self, limit: u64
    ) -> Result<(&'a HttpServer, Bytes), Error> {
        // We’re going to cheat a bit. If we know the body is too big from
        // the Content-Length header, we return Error::PostTooBig. But if
        // we don’t -- which means there are multiple chunks or somesuch --
        // we just use http_body_utils::Limited and return PostCannotRead
        // on any error.

        if self.request.body().size_hint().lower() > limit {
            return Err(Error::PostTooBig);
        }

        Ok((
            self.server,
            Limited::new(
                self.request.into_body(),
                limit.try_into().unwrap_or(usize::MAX),
            ).collect().await.map_err(|_| {
                Error::PostCannotRead
            })?.to_bytes()
        ))
    }
}


//------------ RequestPath ---------------------------------------------------

/// The path of a request’s URI.
///
/// It primarily allows iterating over the path segments. Note that because it
/// needs to be a “borrowing iterator,” it cannot implement the normal
/// `Iterator` trait.
#[derive(Debug, Clone)]
pub struct RequestPath {
    path: Result<PathAndQuery, String>,
}

impl RequestPath {
    fn from_request(request: &Request) -> Result<Self, InvalidPath> {
        let path = if let Cow::Owned(some) = percent_decode(
            request.request.uri().path().as_bytes()
        ).decode_utf8().map_err(|_| InvalidPath)? {
            Err(some)
        }
        else {
            Ok(
                request.request.uri().path_and_query()
                    .ok_or(InvalidPath)?.clone()
            )
        };
        Ok(Self { path })
    }

    pub fn as_str(&self) -> &str {
        match self.path.as_ref() {
            Ok(path) => path.path(),
            Err(path) => path.as_str()
        }
    }

    pub fn iter(&self) -> PathIter {
        PathIter::new(self.as_str())
    }
}

impl AsRef<str> for RequestPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}


//------------ PathIter -------------------------------------------------

#[derive(Debug)]
pub struct PathIter<'a> {
    full: &'a str,
    remaining: Option<&'a str>,
}

impl<'a> PathIter<'a> {
    fn new(path: &'a str) -> Self {
        Self {
            full: path,
            remaining: Some(path.strip_prefix('/').unwrap_or(path))
        }
    }

    /// Returns a copy with a possible trailing slash removed.
    pub fn strip_trailing_slash(&self) -> Self {
        // Some("") means there _was_ a trailing slash and we are now just
        // past it. So we need to transform this case into an exhausted path.
        let remaining = match self.remaining {
            Some("") | None => None,
            Some(remaining) => {
                Some(remaining.strip_suffix('/').unwrap_or(remaining))
            }
        };
        Self {
            full: self.full.strip_suffix('/').unwrap_or(self.full),
            remaining
        }
    }

    pub fn full(&self) -> &str {
        self.full
    }

    pub fn remaining(&self) -> Option<&str> {
        self.remaining
    }

    /// Checks that the path has been exhausted.
    ///
    /// Returns a 404 error response if it isn’t.
    pub fn check_exhausted(&self) -> Result<(), HttpResponse> {
        if self.remaining.is_some() {
            Err(HttpResponse::not_found())
        }
        else {
            Ok(())
        }
    }

    /// Parses the next segment as the given type or returns a Not Found.
    pub fn parse_next<T: FromStr>(&mut self) -> Result<T, HttpResponse> {
        T::from_str(
            self.next().ok_or_else(HttpResponse::not_found)?
        ).map_err(|_| {
            HttpResponse::not_found()
        })
    }

    /// Parses the next optional segment.
    ///
    /// Returns `Ok(None)` if we reached the end of the path. Returns a
    /// Not Found error response if parsing failed.
    pub fn parse_opt_next<T: FromStr>(
        &mut self
    ) -> Result<Option<T>, HttpResponse> {
        self.next().map(|s| {
            T::from_str(s).map_err(|_| HttpResponse::not_found())
        }).transpose()
    }

    /// Parses the next optional segment, allowing for a trailing slash.
    ///
    /// Returns `Ok(None)` if we reached the end of the path or if there was
    /// a trailing slash. Returns a/ Not Found error response if parsing
    /// failed.
    pub fn parse_opt_next_trailing_slash<T: FromStr>(
        &mut self
    ) -> Result<Option<T>, HttpResponse> {
        self.next().map(|s| {
            T::from_str(s).map_err(|_| HttpResponse::not_found())
        }).transpose()
    }
}

impl<'a> Iterator for PathIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remaining?;
        let slash = match remaining.find('/') {
            Some(pos) => pos,
            None => {
                let res = remaining;
                self.remaining = None; 
                return Some(res)
            }
        };
        let res = &remaining[..slash];
        self.remaining = Some(&remaining[slash + 1..]);
        Some(res)
    }
}


//------------ BodyLimits ----------------------------------------------------

/// The size limits of a request body.
#[derive(Clone, Copy, Debug)]
pub struct BodyLimits {
    /// The POST limit for API data.
    post_limit_api: u64,

    /// The POST limit for provisioning protocol data.
    post_limit_rfc6492: u64,


    /// The POST limit for publication protocol data.
    post_limit_rfc8181: u64,
}

impl BodyLimits {
    /// Creates the limits from the config.
    pub fn from_config(config: &Config) -> Self {
        Self {
            post_limit_api: config.post_limit_api,
            post_limit_rfc6492: config.post_limit_rfc6492,
            post_limit_rfc8181: config.post_limit_rfc8181,
        }
    }
}


//------------ InvalidPath ---------------------------------------------------

/// An error happened while preparing the request path.
#[derive(Clone, Copy, Debug)]
pub struct InvalidPath;

impl From<InvalidPath> for ErrorResponse {
    fn from(_: InvalidPath) -> Self {
        Self::new("invalid-path", "The request path was invalid.")
    }
}

impl fmt::Display for InvalidPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid request path")
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    impl RequestPath {
        fn test_str(s: &str) -> Self {
            Self {
                path: Err(
                    percent_decode(
                        s.as_bytes()
                    ).decode_utf8().unwrap().into_owned()
                )
            }
        }
    }

    #[test]
    fn request_path_next() {
        let path = RequestPath::test_str("/foo/bar/baz/");
        let mut path = path.iter();
        assert_eq!(path.next(), Some("foo"));
        assert_eq!(path.next(), Some("bar"));
        assert_eq!(path.next(), Some("baz"));
        assert_eq!(path.next(), Some(""));
        assert_eq!(path.next(), None);

        let path = RequestPath::test_str("/foo/bar/baz");
        let mut path = path.iter();
        assert_eq!(path.next(), Some("foo"));
        assert_eq!(path.next(), Some("bar"));
        assert_eq!(path.next(), Some("baz"));
        assert_eq!(path.next(), None);

        let path = RequestPath::test_str("/foo/b%61%72%2fbaz/");
        let mut path = path.iter();
        assert_eq!(path.next(), Some("foo"));
        assert_eq!(path.next(), Some("bar"));
        assert_eq!(path.next(), Some("baz"));
        assert_eq!(path.next(), Some(""));
        assert_eq!(path.next(), None);

        let path = RequestPath::test_str("/foö/bär/baß");
        let mut path = path.iter();
        assert_eq!(path.next(), Some("foö"));
        assert_eq!(path.next(), Some("bär"));
        assert_eq!(path.next(), Some("baß"));
        assert_eq!(path.next(), None);
    }
}

