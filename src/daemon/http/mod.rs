use hyper::header::USER_AGENT;
use serde::de::DeserializeOwned;
use std::io;
use std::str::FromStr;
use std::{convert::TryInto, str::from_utf8};

use bytes::{Buf, BufMut, Bytes};
use serde::Serialize;

use hyper::http::uri::PathAndQuery;
use hyper::{body::HttpBody, HeaderMap};
use hyper::{Body, Method, StatusCode};

use crate::commons::error::Error;
use crate::commons::remote::{rfc6492, rfc8181};
use crate::commons::{
    actor::{Actor, ActorDef},
    KrillResult,
};
use crate::constants::HTTP_USER_AGENT_TRUNCATE;
use crate::daemon::auth::LoggedInUser;
use crate::daemon::http::server::State;

pub mod auth;
pub mod server;
pub mod statics;
pub mod testbed;
pub mod tls;
pub mod tls_keys;

//------------ RoutingResult ---------------------------------------------

pub type RoutingResult = Result<HttpResponse, Request>;

//----------- ContentType ----------------------------------------------------

#[derive(Clone, Copy)]
enum ContentType {
    Cert,
    Json,
    Rfc8181,
    Rfc6492,
    Text,
    Xml,
    Html,
    Fav,
    Js,
    Css,
    Svg,
    Woff,
    Woff2,
}

impl AsRef<str> for ContentType {
    fn as_ref(&self) -> &str {
        match self {
            ContentType::Cert => "application/x-x509-ca-cert",
            ContentType::Json => "application/json",
            ContentType::Rfc8181 => rfc8181::CONTENT_TYPE,
            ContentType::Rfc6492 => rfc6492::CONTENT_TYPE,
            ContentType::Text => "text/plain",
            ContentType::Xml => "application/xml",

            ContentType::Html => "text/html",
            ContentType::Fav => "image/x-icon",
            ContentType::Js => "application/javascript",
            ContentType::Css => "text/css",
            ContentType::Svg => "image/svg+xml",
            ContentType::Woff => "font/woff",
            ContentType::Woff2 => "font/woff2",
        }
    }
}

//----------- Response -------------------------------------------------------

struct Response {
    status: StatusCode,
    content_type: ContentType,
    max_age: Option<usize>,
    body: Vec<u8>,
    cause: Option<Error>,
}

impl Response {
    fn new(status: StatusCode) -> Self {
        Response {
            status,
            content_type: ContentType::Text,
            max_age: None,
            body: Vec::new(),
            cause: None,
        }
    }

    fn finalize(self) -> HttpResponse {
        let mut builder = hyper::Response::builder()
            .status(self.status)
            .header("Content-Type", self.content_type.as_ref());

        if let Some(max_age) = self.max_age {
            builder = builder.header("Cache-Control", &format!("max-age={}", max_age));
        }

        if self.status == StatusCode::UNAUTHORIZED {
            builder = builder.header("WWW-Authenticate", "Bearer");
        }

        let response = builder.body(self.body.into()).unwrap();

        let mut r = HttpResponse::new(response);
        if let Some(cause) = self.cause {
            r.set_cause(cause);
        }
        r
    }
}

impl From<Response> for HttpResponse {
    fn from(res: Response) -> Self {
        res.finalize()
    }
}

impl io::Write for Response {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.body.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.body.flush()
    }
}

//------------ HttpResponse ---------------------------------------------------

pub struct HttpResponse {
    response: hyper::Response<Body>,
    cause: Option<Error>,
    loggable: bool,
    benign: bool,
}

impl HttpResponse {
    pub fn new(response: hyper::Response<Body>) -> Self {
        HttpResponse {
            response,
            cause: None,
            loggable: true,
            benign: false,
        }
    }

    pub fn response(self) -> hyper::Response<Body> {
        self.response
    }

    pub fn loggable(&self) -> bool {
        self.loggable
    }

    pub fn benign(&self) -> bool {
        self.benign
    }

    pub fn cause(&self) -> Option<&Error> {
        self.cause.as_ref()
    }

    /// Hint to the response handling code that, if logging responses, that this
    /// response should not be logged (perhaps it is sensitive, distracting or
    /// simply not considered helpful).
    pub fn do_not_log(&mut self) {
        self.loggable = false;
    }

    /// Hint to the response handling code that, if warning about certain
    /// responses or classes of response, that this response should be considered
    /// benign, i.e. not worth warning about.
    pub fn with_benign(mut self, benign: bool) -> Self {
        self.benign = benign;
        self
    }

    /// When logging it can be useful to have the original cause to log rather
    /// than the HTTP response body (as that might for example be JSON or XML).
    pub fn set_cause(&mut self, error: Error) {
        self.cause = Some(error);
    }

    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    pub fn body(&self) -> &Body {
        self.response.body()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    fn ok_response(content_type: ContentType, body: Vec<u8>) -> Self {
        Response {
            status: StatusCode::OK,
            content_type,
            max_age: None,
            body,
            cause: None,
        }
        .finalize()
    }

    pub fn json<O: Serialize>(object: &O) -> Self {
        match serde_json::to_string(object) {
            Ok(json) => Self::ok_response(ContentType::Json, json.into_bytes()),
            Err(e) => Self::response_from_error(Error::JsonError(e)),
        }
    }

    pub fn text(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Text, body)
    }

    pub fn text_no_cache(body: Vec<u8>) -> Self {
        HttpResponse::new(
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ContentType::Text.as_ref())
                .header("Cache-Control", "no-cache")
                .body(body.into())
                .unwrap(),
        )
    }

    pub fn xml(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Xml, body)
    }

    pub fn xml_with_cache(body: Vec<u8>, seconds: usize) -> Self {
        Response {
            status: StatusCode::OK,
            content_type: ContentType::Xml,
            max_age: Some(seconds),
            body,
            cause: None,
        }
        .finalize()
    }

    pub fn rfc8181(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Rfc8181, body)
    }

    pub fn rfc6492(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Rfc6492, body)
    }

    pub fn cert(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Cert, body)
    }

    pub fn html(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Html, content.to_vec())
    }

    pub fn fav(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Fav, content.to_vec())
    }

    pub fn js(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Js, content.to_vec())
    }

    pub fn css(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Css, content.to_vec())
    }

    pub fn svg(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Svg, content.to_vec())
    }

    pub fn woff(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Woff, content.to_vec())
    }

    pub fn woff2(content: &[u8]) -> Self {
        Self::ok_response(ContentType::Woff2, content.to_vec())
    }

    fn response_from_error(error: Error) -> Self {
        let status = error.status();
        let response = error.to_error_response();
        let body = serde_json::to_string(&response).unwrap();
        Response {
            status,
            content_type: ContentType::Json,
            max_age: None,
            body: body.into_bytes(),
            cause: Some(error),
        }
        .finalize()
    }

    pub fn ok() -> Self {
        Response::new(StatusCode::OK).finalize()
    }

    pub fn found(location: &str) -> Self {
        Self::new(
            hyper::Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", location)
                .body(hyper::Body::empty())
                .unwrap(),
        )
    }

    pub fn not_found() -> Self {
        Response::new(StatusCode::NOT_FOUND).finalize()
    }

    pub fn unauthorized(reason: String) -> Self {
        Self::response_from_error(Error::ApiInvalidCredentials(reason))
    }

    pub fn forbidden(reason: String) -> Self {
        Self::response_from_error(Error::ApiInsufficientRights(reason))
    }
}

//------------ Request -------------------------------------------------------

pub struct Request {
    request: hyper::Request<hyper::Body>,
    path: RequestPath,
    state: State,
    actor: Actor,
}

impl Request {
    pub async fn new(request: hyper::Request<hyper::Body>, state: State) -> Self {
        let path = RequestPath::from_request(&request);
        let actor = state.actor_from_request(&request);

        Request {
            request,
            path,
            state,
            actor,
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        self.request.headers()
    }

    pub fn user_agent(&self) -> Option<String> {
        match self.headers().get(&USER_AGENT) {
            None => None,
            Some(value) => value.to_str().ok().map(|s| {
                // Note: HeaderValue.to_str() only returns ok in case the value is plain
                //       ascii so it's safe to treat bytes as characters here.
                if s.len() > HTTP_USER_AGENT_TRUNCATE {
                    s[..HTTP_USER_AGENT_TRUNCATE].to_string()
                } else {
                    s.to_string()
                }
            }),
        }
    }

    pub async fn upgrade_from_anonymous(&mut self, actor_def: ActorDef) {
        if self.actor.is_anonymous() {
            self.actor = self.state.actor_from_def(actor_def);
            info!(
                "Permitted anonymous actor to become actor '{}' for the duration of this request",
                self.actor.name()
            );
        }
    }

    pub fn actor(&self) -> Actor {
        self.actor.clone()
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

        if bytes.iter().any(|c| !c.is_ascii()) {
            Err(Error::NonAsciiCharsInput)
        } else {
            let string = from_utf8(&bytes).map_err(|_| Error::InvalidUtf8Input)?;
            serde_json::from_str(string).map_err(Error::JsonError)
        }
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

    /// See hyper::body::to_bytes
    ///
    /// Here we want to limit the bytes consumed to a maximum. So, the
    /// code below is adapted from the method in the hyper crate.
    pub async fn read_bytes(self, limit: u64) -> Result<Bytes, Error> {
        let body = self.request.into_body();

        futures_util::pin_mut!(body);

        if body.size_hint().lower() > limit {
            return Err(Error::PostTooBig);
        }

        let mut size_processed = 0;

        fn assert_body_size(size_processed: u64, body_lower_hint: u64, post_limit: u64) -> Result<(), Error> {
            if size_processed + body_lower_hint > post_limit {
                Err(Error::PostTooBig)
            } else {
                Ok(())
            }
        }

        assert_body_size(size_processed, body.size_hint().lower(), limit)?;

        // If there's only 1 chunk, we can just return Buf::to_bytes()
        let first = if let Some(buf) = body.data().await {
            let buf = buf.map_err(|_| Error::PostCannotRead)?;
            let size: u64 = buf.len().try_into().map_err(|_| Error::PostTooBig)?;
            size_processed += size;
            buf
        } else {
            return Ok(Bytes::new());
        };

        assert_body_size(size_processed, body.size_hint().lower(), limit)?;
        let second = if let Some(buf) = body.data().await {
            let buf = buf.map_err(|_| Error::PostCannotRead)?;
            let size: u64 = buf.len().try_into().map_err(|_| Error::PostTooBig)?;
            size_processed += size;
            buf
        } else {
            return Ok(first);
        };

        assert_body_size(size_processed, body.size_hint().lower(), limit)?;
        // With more than 1 buf, we gotta flatten into a Vec first.
        let cap = first.remaining() + second.remaining() + body.size_hint().lower() as usize;
        let mut vec = Vec::with_capacity(cap);
        vec.put(first);
        vec.put(second);

        while let Some(buf) = body.data().await {
            let buf = buf.map_err(|_| Error::PostCannotRead)?;
            let size: u64 = buf.len().try_into().map_err(|_| Error::PostTooBig)?;
            size_processed += size;
            assert_body_size(size_processed, body.size_hint().lower(), limit)?;
            vec.put(buf);
        }

        Ok(vec.into())
    }

    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.state.get_login_url()
    }

    pub async fn login(&self) -> KrillResult<LoggedInUser> {
        self.state.login(&self.request)
    }

    pub async fn logout(&self) -> KrillResult<HttpResponse> {
        self.state.logout(&self.request)
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
        let mut res = RequestPath { path, segment: (0, 0) };
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
        let end = path[start..].find('/').map(|x| x + start).unwrap_or_else(|| path.len());
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
        self.next().map(|s| T::from_str(s).ok()).flatten()
    }
}
