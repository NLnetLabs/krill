//! Some helper functions for HTTP calls
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::{env, fmt};

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue, CONTENT_TYPE, USER_AGENT};
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::commons::api::{ErrorResponse, Token};
use crate::commons::util::file;
use crate::constants::{HTTP_CLIENT_TIMEOUT_SECS, KRILL_CLI_API_ENV, KRILL_HTTPS_ROOT_CERTS_ENV, KRILL_VERSION};

const JSON_CONTENT: &str = "application/json";

fn report_get_and_exit(uri: &str, token: Option<&Token>) {
    println!("GET:\n  {}", uri);
    if let Some(token) = token {
        println!("Headers:\n  Authorization: Bearer {}", token);
    }
    std::process::exit(0);
}

fn report_post_and_exit(uri: &str, content_type: Option<&str>, token: Option<&Token>, body: &str) {
    println!("POST:\n  {}", uri);

    if content_type.is_some() || token.is_some() {
        println!("Headers:");
    }

    if let Some(content_type) = content_type {
        println!("  content-type: {}", content_type);
    }
    if let Some(token) = token {
        println!("  Authorization: Bearer {}", token);
    }
    println!("Body:\n{}", body);
    std::process::exit(0);
}

fn report_delete(uri: &str, content_type: Option<&str>, token: Option<&Token>) {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        println!("DELETE:\n  {}", uri);
        if content_type.is_some() || token.is_some() {
            println!("Headers:");
        }

        if let Some(content_type) = content_type {
            println!("  content-type: {}", content_type);
        }
        if let Some(token) = token {
            println!("  Authorization: Bearer {}", token);
        }
        std::process::exit(0);
    }
}

/// Gets the Bearer token from the request header, if present.
pub fn get_bearer_token(request: &hyper::Request<hyper::Body>) -> Option<Token> {
    request
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|header_string| {
            header_string
                .to_lowercase()
                .strip_prefix("bearer")
                .map(|str| Token::from(str.trim()))
        })
}

/// Performs a GET request that expects a json response that can be
/// deserialized into the an owned value of the expected type. Returns an error
/// if nothing is returned.
pub async fn get_json<T: DeserializeOwned>(uri: &str, token: Option<&Token>) -> Result<T, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(Some(JSON_CONTENT), token)?;

    let res = client(uri)?.get(uri).headers(headers).send().await?;
    process_json_response(res).await
}

/// Performs a get request and expects a response that can be turned
/// into a string (in particular, not a binary response).
pub async fn get_text(uri: &str, token: Option<&Token>) -> Result<String, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(None, token)?;
    let res = client(uri)?.get(uri).headers(headers).send().await?;
    match opt_text_response(res).await? {
        Some(res) => Ok(res),
        None => Err(Error::EmptyResponse),
    }
}

/// Checks that there is a 200 OK response at the given URI. Discards the
/// response body.
pub async fn get_ok(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(None, token)?;
    let res = client(uri)?.get(uri).headers(headers).send().await?;
    opt_text_response(res).await?; // Will return nice errors with possible body.
    Ok(())
}

/// Performs a POST of data that can be serialized into json, and expects
/// a 200 OK response, without a body.
pub async fn post_json(uri: &str, data: impl Serialize, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        let body = serde_json::to_string_pretty(&data)?;
        report_post_and_exit(uri, Some(JSON_CONTENT), token, &body);
    }

    let body = serde_json::to_string(&data)?;
    let headers = headers(Some(JSON_CONTENT), token)?;

    let res = client(uri)?.post(uri).headers(headers).body(body).send().await?;
    if let Some(res) = opt_text_response(res).await? {
        Err(Error::UnexpectedResponse(res))
    } else {
        Ok(())
    }
}

/// Performs a POST of data that can be serialized into json, and expects
/// a json response that can be deserialized into the an owned value of the
/// expected type.
pub async fn post_json_with_response<T: DeserializeOwned>(
    uri: &str,
    data: impl Serialize,
    token: Option<&Token>,
) -> Result<T, Error> {
    match post_json_with_opt_response(uri, data, token).await? {
        None => Err(Error::EmptyResponse),
        Some(res) => Ok(res),
    }
}

/// Performs a POST of data that can be serialized into json, and expects
/// an optional json response that can be deserialized into the an owned
/// value of the expected type.
pub async fn post_json_with_opt_response<T: DeserializeOwned>(
    uri: &str,
    data: impl Serialize,
    token: Option<&Token>,
) -> Result<Option<T>, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        let body = serde_json::to_string_pretty(&data)?;
        report_post_and_exit(uri, Some(JSON_CONTENT), token, &body);
    }

    let body = serde_json::to_string(&data)?;
    let headers = headers(Some(JSON_CONTENT), token)?;
    let res = client(uri)?.post(uri).headers(headers).body(body).send().await?;
    process_opt_json_response(res).await
}

/// Performs a POST with no data to the given URI and expects and empty 200 OK response.
pub async fn post_empty(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, None, token, "<empty>");
    }

    let headers = headers(Some(JSON_CONTENT), token)?;
    let res = client(uri)?.post(uri).headers(headers).send().await?;
    if let Some(res) = opt_text_response(res).await? {
        Err(Error::UnexpectedResponse(res))
    } else {
        Ok(())
    }
}

/// Posts binary data, and expects a binary response. Includes the full krill version
/// as the user agent. Intended for sending RFC 6492 (provisioning) and 8181 (publication)
/// to the trusted parent or publication server.
///
/// Note: Bytes may be empty if the post was successful, but the response was
/// empty.
pub async fn post_binary_with_full_ua(uri: &str, data: &Bytes, content_type: &str) -> Result<Bytes, Error> {
    let body = data.to_vec();

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_str(&format!("krill/{}", KRILL_VERSION))?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(Error::RequestError)?;

    let res = client.post(uri).headers(headers).body(body).send().await?;

    match res.status() {
        StatusCode::OK => {
            let bytes = res.bytes().await?;
            Ok(bytes)
        }
        _ => Err(Error::from_res(res).await),
    }
}

/// Sends a delete request to the specified url.
pub async fn delete(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    report_delete(uri, None, token);

    let headers = headers(None, token)?;
    let res = client(uri)?.delete(uri).headers(headers).send().await?;

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => Err(Error::from_res(res).await),
    }
}

fn load_root_cert(path: &str) -> Result<reqwest::Certificate, Error> {
    let path = PathBuf::from_str(path).map_err(Error::https_root_cert_error)?;
    let file = file::read(&path).map_err(Error::https_root_cert_error)?;
    reqwest::Certificate::from_pem(file.as_ref()).map_err(Error::https_root_cert_error)
}

/// Default client for Krill use cases.
pub fn client(uri: &str) -> Result<reqwest::Client, Error> {
    client_with_tweaks(uri, Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS), true)
}

/// Client with tweaks - in particular needed by the openid connect client
pub fn client_with_tweaks(uri: &str, timeout: Duration, allow_redirects: bool) -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::ClientBuilder::new().timeout(timeout);

    if !allow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Ok(cert_list) = env::var(KRILL_HTTPS_ROOT_CERTS_ENV) {
        for path in cert_list.split(':') {
            let cert = load_root_cert(path)?;
            builder = builder.add_root_certificate(cert);
        }
    }

    if uri.starts_with("https://localhost") || uri.starts_with("https://127.0.0.1") {
        builder.danger_accept_invalid_certs(true).build()
    } else {
        builder.build()
    }
    .map_err(Error::RequestError)
}

fn headers(content_type: Option<&str>, token: Option<&Token>) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_str("krill")?);
    if let Some(content_type) = content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);
    }
    if let Some(token) = token {
        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );
    }
    Ok(headers)
}

async fn process_json_response<T: DeserializeOwned>(res: Response) -> Result<T, Error> {
    match process_opt_json_response(res).await? {
        None => Err(Error::EmptyResponse),
        Some(res) => Ok(res),
    }
}

async fn process_opt_json_response<T: DeserializeOwned>(res: Response) -> Result<Option<T>, Error> {
    match opt_text_response(res).await {
        Err(e) => Err(e),
        Ok(None) => Ok(None),
        Ok(Some(s)) => {
            let res: T = serde_json::from_str(&s)?;
            Ok(Some(res))
        }
    }
}

async fn opt_text_response(res: Response) -> Result<Option<String>, Error> {
    match res.status() {
        StatusCode::OK => match res.text().await.ok() {
            None => Ok(None),
            Some(s) => {
                if s.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(s))
                }
            }
        },
        StatusCode::FORBIDDEN => Err(Error::Forbidden),
        _ => Err(Error::from_res(res).await),
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    RequestError(reqwest::Error),
    Forbidden,
    BadStatus(StatusCode),
    ErrorWithBody(StatusCode, String),
    ErrorWithJson(StatusCode, ErrorResponse),
    JsonError(serde_json::Error),
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidMethod(String),
    InvalidStatusCode(u16),
    EmptyResponse,
    UnexpectedResponse(String),
    HttpsRootCertError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::RequestError(e) => write!(f, "Request Error: {}", e),
            Error::Forbidden => write!(f, "Access Forbidden"),
            Error::BadStatus(code) => write!(f, "Received bad status: {}", code),
            Error::ErrorWithBody(code, e) => write!(f, "Status: {}, Error: {}", code, e),
            Error::ErrorWithJson(code, res) => write!(f, "Status: {}, ErrorResponse: {}", code, res),
            Error::JsonError(e) => e.fmt(f),
            Error::InvalidHeaderName => write!(f, "failed parse header name"),
            Error::InvalidHeaderValue => write!(f, "failed parse header value"),
            Error::InvalidMethod(m) => write!(f, "unrecognised method requested: '{}'", m),
            Error::InvalidStatusCode(code) => write!(f, "unrecognised status code in response: '{}'", code),
            Error::EmptyResponse => write!(f, "Empty response received from server"),
            Error::UnexpectedResponse(s) => write!(f, "Unexpected response: {}", s),
            Error::HttpsRootCertError(e) => write!(
                f,
                "HTTPS root cert error, check files under dir defined in KRILL_HTTPS_ROOT_CERTS: {}",
                e
            ),
        }
    }
}

impl Error {
    async fn from_res(res: Response) -> Error {
        let status = res.status();
        match res.text().await {
            Ok(body) => {
                if body.is_empty() {
                    Error::BadStatus(status)
                } else {
                    match serde_json::from_str::<ErrorResponse>(&body) {
                        Ok(res) => Error::ErrorWithJson(status, res),
                        Err(_) => Error::ErrorWithBody(status, body),
                    }
                }
            }
            _ => Error::BadStatus(status),
        }
    }

    pub fn https_root_cert_error(e: impl fmt::Display) -> Self {
        Error::HttpsRootCertError(e.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::RequestError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(_v: InvalidHeaderValue) -> Self {
        // note InvalidHeaderValue is a marker and contains no further information.
        Error::InvalidHeaderValue
    }
}
