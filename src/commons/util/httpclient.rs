//! Some helper functions for HTTP calls
use std::{env, fmt, path::PathBuf, str::FromStr, time::Duration};

use bytes::Bytes;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT},
    Response, StatusCode,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    commons::{
        api::{ErrorResponse, Token},
        util::file,
    },
    constants::{HTTP_CLIENT_TIMEOUT_SECS, KRILL_CLI_API_ENV, KRILL_HTTPS_ROOT_CERTS_ENV, KRILL_VERSION},
};

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
        .and_then(|header_string| header_string.strip_prefix("Bearer ").map(|s| Token::from(s.trim())))
}

/// Performs a GET request that expects a json response that can be
/// deserialized into the an owned value of the expected type. Returns an error
/// if nothing is returned.
pub async fn get_json<T: DeserializeOwned>(uri: &str, token: Option<&Token>) -> Result<T, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(uri, Some(JSON_CONTENT), token)?;

    let res = client(uri)?
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    process_json_response(uri, res).await
}

/// Performs a get request and expects a response that can be turned
/// into a string (in particular, not a binary response).
pub async fn get_text(uri: &str, token: Option<&Token>) -> Result<String, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(uri, None, token)?;
    let res = client(uri)?
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    text_response(uri, res).await
}

/// Checks that there is a 200 OK response at the given URI. Discards the
/// response body.
pub async fn get_ok(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(uri, None, token)?;
    let res = client(uri)?
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    opt_text_response(uri, res).await?; // Will return nice errors with possible body.
    Ok(())
}

/// Performs a POST of data that can be serialized into json, and expects
/// a 200 OK response, without a body.
pub async fn post_json(uri: &str, data: impl Serialize, token: Option<&Token>) -> Result<(), Error> {
    let body = serde_json::to_string_pretty(&data).map_err(|e| Error::request_build_json(uri, e))?;

    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, Some(JSON_CONTENT), token, &body);
    }
    let headers = headers(uri, Some(JSON_CONTENT), token)?;

    let res = client(uri)?
        .post(uri)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    empty_response(uri, res).await
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
        None => Err(Error::response(uri, "expected JSON response")),
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
    let body = serde_json::to_string_pretty(&data).map_err(|e| Error::request_build_json(uri, e))?;

    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, Some(JSON_CONTENT), token, &body);
    }

    let headers = headers(uri, Some(JSON_CONTENT), token)?;
    let res = client(uri)?
        .post(uri)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    process_opt_json_response(uri, res).await
}

/// Performs a POST with no data to the given URI and expects and empty 200 OK response.
pub async fn post_empty(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    let res = do_empty_post(uri, token).await?;
    empty_response(uri, res).await
}

/// Performs a POST with no data to the given URI and expects a response.
pub async fn post_empty_with_response<T: DeserializeOwned>(uri: &str, token: Option<&Token>) -> Result<T, Error> {
    let res = do_empty_post(uri, token).await?;
    process_json_response(uri, res).await
}

async fn do_empty_post(uri: &str, token: Option<&Token>) -> Result<Response, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, None, token, "<empty>");
    }

    let headers = headers(uri, Some(JSON_CONTENT), token)?;
    client(uri)?
        .post(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))
}

/// Posts binary data, and expects a binary response. Includes the full krill version
/// as the user agent. Intended for sending RFC 6492 (provisioning) and 8181 (publication)
/// to the trusted parent or publication server.
///
/// Note: Bytes may be empty if the post was successful, but the response was
/// empty.
pub async fn post_binary_with_full_ua(
    uri: &str,
    data: &Bytes,
    content_type: &str,
    timeout: u64,
) -> Result<Bytes, Error> {
    let body = data.to_vec();

    let mut headers = HeaderMap::new();

    let ua_string = format!("krill/{}", KRILL_VERSION);
    let user_agent_value = HeaderValue::from_str(&ua_string).map_err(|e| Error::request_build(uri, e))?;
    let content_type_value = HeaderValue::from_str(content_type).map_err(|e| Error::request_build(uri, e))?;

    headers.insert(USER_AGENT, user_agent_value);
    headers.insert(CONTENT_TYPE, content_type_value);

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| Error::request_build(uri, e))?;

    let res = client
        .post(uri)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    match res.status() {
        StatusCode::OK => {
            let bytes = res
                .bytes()
                .await
                .map_err(|e| Error::response(uri, format!("cannot get body: {}", e)))?;
            Ok(bytes)
        }
        _ => Err(Error::from_res(uri, res).await),
    }
}

/// Sends a delete request to the specified url.
pub async fn delete(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    report_delete(uri, None, token);

    let headers = headers(uri, None, token)?;
    let res = client(uri)?
        .delete(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(uri, e))?;

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => Err(Error::from_res(uri, res).await),
    }
}

#[allow(clippy::result_large_err)]
fn load_root_cert(path_str: &str) -> Result<reqwest::Certificate, Error> {
    let path = PathBuf::from_str(path_str).map_err(|e| Error::request_build_https_cert(path_str, e))?;
    let file = file::read(&path).map_err(|e| Error::request_build_https_cert(path_str, e))?;
    reqwest::Certificate::from_pem(file.as_ref()).map_err(|e| Error::request_build_https_cert(path_str, e))
}

/// Default client for Krill use cases.
#[allow(clippy::result_large_err)]
pub fn client(uri: &str) -> Result<reqwest::Client, Error> {
    client_with_tweaks(uri, Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS), true)
}

/// Client with tweaks - in particular needed by the openid connect client
#[allow(clippy::result_large_err)]
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
    .map_err(|e| Error::request_build(uri, e))
}

#[allow(clippy::result_large_err)]
fn headers(uri: &str, content_type: Option<&str>, token: Option<&Token>) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("krill"));

    if let Some(content_type) = content_type {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).map_err(|e| Error::request_build(uri, e))?,
        );
    }
    if let Some(token) = token {
        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| Error::request_build(uri, e))?,
        );
    }
    Ok(headers)
}

async fn process_json_response<T: DeserializeOwned>(uri: &str, res: Response) -> Result<T, Error> {
    match process_opt_json_response(uri, res).await? {
        None => Err(Error::response(uri, "got empty response body")),
        Some(res) => Ok(res),
    }
}

async fn process_opt_json_response<T: DeserializeOwned>(uri: &str, res: Response) -> Result<Option<T>, Error> {
    match opt_text_response(uri, res).await? {
        None => Ok(None),
        Some(s) => {
            let res: T = serde_json::from_str(&s)
                .map_err(|e| Error::response(uri, format!("could not parse JSON response: {}", e)))?;
            Ok(Some(res))
        }
    }
}

async fn empty_response(uri: &str, res: Response) -> Result<(), Error> {
    match opt_text_response(uri, res).await? {
        None => Ok(()),
        Some(_) => Err(Error::response(uri, "expected empty response")),
    }
}

async fn text_response(uri: &str, res: Response) -> Result<String, Error> {
    match opt_text_response(uri, res).await? {
        None => Err(Error::response(uri, "expected response body")),
        Some(s) => Ok(s),
    }
}

async fn opt_text_response(uri: &str, res: Response) -> Result<Option<String>, Error> {
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
        StatusCode::FORBIDDEN => Err(Error::Forbidden(uri.to_string())),
        _ => Err(Error::from_res(uri, res).await),
    }
}

//------------ Error ---------------------------------------------------------

type ErrorUri = String;
type RootCertPath = String;
type ErrorMessage = String;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::result_large_err)]
pub enum Error {
    RequestBuild(ErrorUri, ErrorMessage),
    RequestBuildHttpsCert(RootCertPath, ErrorMessage),

    RequestExecute(ErrorUri, ErrorMessage),

    Response(ErrorUri, ErrorMessage),
    Forbidden(ErrorUri),
    ErrorResponseWithBody(ErrorUri, StatusCode, String),
    ErrorResponseWithJson(ErrorUri, StatusCode, ErrorResponse),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::RequestBuild(uri, msg) => write!(f, "Issue creating request for URI: {}, error: {}", uri, msg),
            Error::RequestBuildHttpsCert(path, msg) => {
                write!(f, "Cannot use configured HTTPS root cert '{}'. Error: {}", path, msg)
            }

            Error::RequestExecute(uri, msg) => write!(f, "Issue accessing URI: {}, error: {}", uri, msg),

            Error::Response(uri, msg) => write!(f, "Issue processing response from URI: {}, error: {}", uri, msg),
            Error::Forbidden(uri) => write!(f, "Got 'Forbidden' response for URI: {}", uri),
            Error::ErrorResponseWithBody(uri, code, e) => {
                write!(f, "Error response from URI: {}, Status: {}, Error: {}", uri, code, e)
            }
            Error::ErrorResponseWithJson(uri, code, res) => write!(
                f,
                "Error response from URI: {}, Status: {}, ErrorResponse: {}",
                uri, code, res
            ),
        }
    }
}

impl Error {
    pub fn request_build(uri: &str, msg: impl fmt::Display) -> Self {
        Error::RequestBuild(uri.to_string(), msg.to_string())
    }

    pub fn request_build_json(uri: &str, e: impl fmt::Display) -> Self {
        Error::RequestBuild(uri.to_string(), format!("could not serialize type to JSON: {}", e))
    }

    pub fn request_build_https_cert(path: &str, msg: impl fmt::Display) -> Self {
        Error::RequestBuildHttpsCert(path.to_string(), msg.to_string())
    }

    pub fn execute(uri: &str, msg: impl fmt::Display) -> Self {
        Error::RequestExecute(uri.to_string(), msg.to_string())
    }

    pub fn response(uri: &str, msg: impl fmt::Display) -> Self {
        Error::Response(uri.to_string(), msg.to_string())
    }

    pub fn forbidden(uri: &str) -> Self {
        Error::Forbidden(uri.to_string())
    }

    pub fn unexpected_status(status: StatusCode) -> String {
        format!("unexpected status code {}", status)
    }

    pub fn response_unexpected_status(uri: &str, status: StatusCode) -> Self {
        Error::Response(uri.to_string(), Self::unexpected_status(status))
    }

    async fn from_res(uri: &str, res: Response) -> Error {
        let status = res.status();
        match res.text().await {
            Ok(body) => {
                if body.is_empty() {
                    Self::response_unexpected_status(uri, status)
                } else {
                    match serde_json::from_str::<ErrorResponse>(&body) {
                        Ok(res) => Error::ErrorResponseWithJson(uri.to_string(), status, res),
                        Err(_) => Error::ErrorResponseWithBody(uri.to_string(), status, body),
                    }
                }
            }
            _ => Self::response_unexpected_status(uri, status),
        }
    }
}
