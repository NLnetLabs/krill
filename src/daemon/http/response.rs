use bytes::Bytes;
use http_body_util::{Either, Empty, Full};
use hyper::{HeaderMap, StatusCode};
use hyper::header::{HeaderName, HeaderValue};
use log::warn;
use rpki::ca::{provisioning, publication};
use serde::Serialize;
use crate::api::admin::Token;
use crate::api::status::ErrorResponse;
use crate::commons::error::Error;


//----------- ContentType ----------------------------------------------------

#[derive(Clone, Copy)]
enum ContentType {
    Cert,
    Json,
    Rfc8181,
    Rfc6492,
    Text,
    Prometheus,
    Xml,
    Html,
    Fav,
    Js,
    Css,
    Svg,
    Woff,
    Woff2,
}

impl ContentType {
    fn as_str(&self) -> &'static str {
        match self {
            ContentType::Cert => "application/x-x509-ca-cert",
            ContentType::Json => "application/json",
            ContentType::Rfc8181 => publication::CONTENT_TYPE,
            ContentType::Rfc6492 => provisioning::CONTENT_TYPE,
            ContentType::Text => "text/plain",
            ContentType::Prometheus => "text/plain; version=0.0.4",
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

//------------ HyperRequest and HyperResponse --------------------------------

pub type HyperResponseBody = Either<Empty<Bytes>, Full<Bytes>>;
pub type HyperResponse = hyper::Response<HyperResponseBody>;

//----------- Response -------------------------------------------------------

struct Response {
    status: StatusCode,
    content_type: &'static str,
    max_age: Option<usize>,
    body: Bytes,
    cause: Option<Error>,
}

impl Response {
    fn new(status: StatusCode) -> Self {
        Response {
            status,
            content_type: ContentType::Text.as_str(),
            max_age: None,
            body: Bytes::default(), 
            cause: None,
        }
    }

    fn finalize(self) -> HttpResponse {
        let mut builder = hyper::Response::builder()
            .status(self.status)
            .header("Content-Type", self.content_type);

        if let Some(max_age) = self.max_age {
            builder = builder
                .header("Cache-Control", &format!("max-age={max_age}"));
        }

        if self.status == StatusCode::UNAUTHORIZED {
            builder = builder.header("WWW-Authenticate", "Bearer");
        }

        let body = if self.body.is_empty() {
            Either::Left(Empty::new())
        } else {
            Either::Right(Full::new(self.body))
        };
        let response = builder.body(body).unwrap();

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


//------------ HttpResponse --------------------------------------------------

#[derive(Debug)]
pub struct HttpResponse {
    response: HyperResponse,
    cause: Option<Error>,
    loggable: bool,
    benign: bool,
}

impl HttpResponse {
    pub fn new(response: HyperResponse) -> Self {
        HttpResponse {
            response,
            cause: None,
            loggable: true,
            benign: false,
        }
    }

    pub fn into_response(self) -> HyperResponse {
        self.response
    }

    pub fn into_hyper(self) -> HyperResponse {
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

    /// Hint to the response handling code that, if logging responses, that
    /// this response should not be logged (perhaps it is sensitive,
    /// distracting or simply not considered helpful).
    pub fn do_not_log(&mut self) {
        self.loggable = false;
    }

    /// Hint to the response handling code that, if warning about certain
    /// responses or classes of response, that this response should be
    /// considered benign, i.e. not worth warning about.
    pub fn with_benign(mut self, benign: bool) -> Self {
        self.benign = benign;
        self
    }

    /// When logging it can be useful to have the original cause to log rather
    /// than the HTTP response body (as that might for example be JSON or
    /// XML).
    pub fn set_cause(&mut self, error: Error) {
        self.cause = Some(error);
    }

    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    pub fn body(&self) -> &HyperResponseBody {
        self.response.body()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    pub fn ok_with_body(
        content_type: &'static str,
        body: impl Into<Bytes>
    ) -> Self {
        Response {
            status: StatusCode::OK,
            content_type,
            max_age: None,
            body: body.into(),
            cause: None,
        }
        .finalize()
    }


    fn ok_response(
        content_type: ContentType,
        body: impl Into<Bytes>
    ) -> Self {
        Self::ok_with_body(content_type.as_str(), body)
    }

    pub fn json<O: Serialize>(object: &O) -> Self {
        match serde_json::to_string(object) {
            Ok(json) => {
                Self::ok_response(ContentType::Json, json)
            }
            Err(e) => Self::response_from_error(Error::JsonError(e)),
        }
    }

    pub fn text(body: impl Into<Bytes>) -> Self {
        Self::ok_response(ContentType::Text, body)
    }

    pub fn text_no_cache(body: Vec<u8>) -> Self {
        HttpResponse::new(
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ContentType::Text.as_str())
                .header("Cache-Control", "no-cache")
                .body(Either::Right(Full::new(body.into())))
                .unwrap(),
        )
    }

    pub fn prometheus(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Prometheus, body)
    }

    pub fn xml(body: Vec<u8>) -> Self {
        Self::ok_response(ContentType::Xml, body)
    }

    pub fn xml_with_cache(body: Vec<u8>, seconds: usize) -> Self {
        Response {
            status: StatusCode::OK,
            content_type: ContentType::Xml.as_str(),
            max_age: Some(seconds),
            body: body.into(),
            cause: None,
        }
        .finalize()
    }

    pub fn rfc8181(body: Bytes) -> Self {
        Self::ok_response(ContentType::Rfc8181, body)
    }

    pub fn rfc6492(body: Bytes) -> Self {
        Self::ok_response(ContentType::Rfc6492, body)
    }

    pub fn cert(body: Bytes) -> Self {
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

    pub fn error(
        status: StatusCode, error: impl Into<ErrorResponse>
    ) -> Self {
        let error = error.into();
        let body = serde_json::to_string(&error).unwrap().into();
        Response {
            status,
            content_type: ContentType::Json.as_str(),
            max_age: None,
            body,
            cause: None,
        }.finalize()
    }

    pub fn response_from_error(error: Error) -> Self {
        let status = error.status();
        let response = error.to_error_response();
        let body = serde_json::to_string(&response).unwrap().into();
        Response {
            status,
            content_type: ContentType::Json.as_str(),
            max_age: None,
            body,
            cause: Some(error),
        }.finalize()
    }

    pub fn ok() -> Self {
        Response::new(StatusCode::OK).finalize()
    }

    pub fn found(location: &str) -> Self {
        Self::new(
            hyper::Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", location)
                .body(Either::Left(Empty::new()))
                .unwrap(),
        )
    }

    pub fn not_found() -> Self {
        Response::new(StatusCode::NOT_FOUND).finalize()
    }

    pub fn unauthorized(reason: String) -> Self {
        Self::response_from_error(Error::ApiInvalidCredentials(reason))
    }

    pub fn forbidden(err: String) -> Self {
        Self::response_from_error(Error::ApiInsufficientRights(err))
    }

    pub fn method_not_allowed() -> Self {
        Response::new(StatusCode::METHOD_NOT_ALLOWED).finalize()
    }

    // Suppress any error in the unlikely event that we fail to inject the
    // Authorization header into the HTTP response as this is an internal error
    // that we should shield the user from, but log a warning as this is very
    // unexpected.
    pub fn add_authorization_token(
        &mut self, token: Token,
    ) {
        let header_name = const { HeaderName::from_static("authorization") };
        let header_value = match HeaderValue::from_maybe_shared(
            Bytes::from(format!("Bearer {}", &token))
        ) {
            Ok(value) => value,
            Err(_) => {
                warn!(
                    "Internal error: unable to add refreshed auth token \
                     '{token}' to the response."
                );
                return
            }
        };

        self.response.headers_mut().insert(header_name, header_value);
    }
}

