use std::borrow::Cow;
use std::io;
use std::sync::RwLockReadGuard;

use serde::Serialize;

use hyper::http::uri::PathAndQuery;
use hyper::{Body, Method, StatusCode};

use crate::commons::api::Token;
use crate::commons::error::Error;
use crate::commons::remote::{rfc6492, rfc8181};
use crate::daemon::auth::Auth;
use crate::daemon::http::server::State;
use crate::daemon::krillserver::KrillServer;

pub mod server;
pub mod statics;
pub mod tls;
pub mod tls_keys;

//----------- ContentType ----------------------------------------------------

enum ContentType {
    Cert,
    Json,
    Html,
    Rfc8181,
    Rfc6492,
    Text,
    Xml,
}

impl AsRef<str> for ContentType {
    fn as_ref(&self) -> &str {
        match self {
            ContentType::Cert => "application/x-x509-ca-cert",
            ContentType::Json => "application/json",
            ContentType::Html => "text/html;charset=utf-8",
            ContentType::Rfc8181 => rfc8181::CONTENT_TYPE,
            ContentType::Rfc6492 => rfc6492::CONTENT_TYPE,
            ContentType::Text => "text/plain",
            ContentType::Xml => "application/xml",
        }
    }
}

//----------- Response -------------------------------------------------------

struct Response {
    status: StatusCode,
    content_type: ContentType,
    body: Vec<u8>,
}

impl Response {
    fn new(status: StatusCode) -> Self {
        Response {
            status,
            content_type: ContentType::Text,
            body: Vec::new(),
        }
    }

    fn finalize(self) -> HttpResponse {
        HttpResponse(
            hyper::Response::builder()
                .status(self.status)
                .header("Content-Type", self.content_type.as_ref())
                .body(self.body.into())
                .unwrap(),
        )
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

pub struct HttpResponse(hyper::Response<Body>);

impl HttpResponse {
    fn ok_response(content_type: ContentType, body: Vec<u8>) -> Self {
        Response {
            status: StatusCode::OK,
            content_type,
            body,
        }
        .finalize()
    }

    pub fn res(self) -> Result<hyper::Response<Body>, Error> {
        Ok(self.0)
    }

    pub fn json<O: Serialize>(object: &O) -> Self {
        match serde_json::to_string(object) {
            Ok(json) => Self::ok_response(ContentType::Json, json.into_bytes()),
            Err(e) => Self::error(Error::JsonError(e)),
        }
    }

    pub fn text(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Text, body)
    }

    pub fn xml(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Xml, body)
    }

    pub fn rfc8181(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Rfc8181, body)
    }

    pub fn rfc6492(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Rfc8181, body)
    }

    pub fn cert(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Cert, body)
    }

    pub fn error(error: Error) -> Self {
        error!("{}", error);
        let status = error.status();
        let response = error.to_error_response();
        let body = serde_json::to_string(&response).unwrap();
        Response {
            status,
            content_type: ContentType::Json,
            body: body.into_bytes(),
        }
        .finalize()
    }

    pub fn ok() -> Self {
        Response::new(StatusCode::OK).finalize()
    }

    pub fn not_found() -> Self {
        Response::new(StatusCode::NOT_FOUND).finalize()
    }

    pub fn forbidden() -> Self {
        Response::new(StatusCode::FORBIDDEN).finalize()
    }
}

//------------ Request -------------------------------------------------------

pub struct Request {
    request: hyper::Request<Body>,
    path: RequestPath,
    state: State,
}

impl Request {
    pub fn new(request: hyper::Request<Body>, state: State) -> Self {
        let path = RequestPath::from_request(&request);
        Request {
            request,
            path,
            state,
        }
    }

    /// Returns the complete path.
    pub fn path(&self) -> &RequestPath {
        &self.path
    }

    pub fn path_mut(&mut self) -> &mut RequestPath {
        &mut self.path
    }

    /// Get the application State
    fn state(&self) -> &State {
        &self.state
    }

    /// Get read_status
    pub fn read(&self) -> RwLockReadGuard<KrillServer> {
        self.state.read()
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

    /// Checks whether the Bearer token is set to what we expect
    pub fn is_authorized(&self) -> bool {
        if let Some(header) = self.request.headers().get("Authorization") {
            if let Ok(header) = header.to_str() {
                if header.len() > 6 {
                    let (bearer, token) = header.split_at(6);
                    let bearer = bearer.trim();
                    let token = Token::from(token.trim());

                    if "Bearer" == bearer {
                        return self.read().is_api_allowed(&Auth::bearer(token));
                    }
                }
            }
        }
        false
    }
}

//------------ RequestPath ---------------------------------------------------

pub struct RequestPath {
    path: PathAndQuery,
    segment: (usize, usize),
}

impl RequestPath {
    fn from_request<B>(request: &hyper::Request<B>) -> Self {
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
            .unwrap_or(path.len());
        self.segment = (start, end);
        true
    }

    pub fn next(&mut self) -> Option<&str> {
        if self.next_segment() {
            Some(self.segment())
        } else {
            None
        }
    }
}
