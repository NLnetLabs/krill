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
use crate::constants::{HTTTP_CLIENT_TIMEOUT_SECS, KRILL_CLI_API_ENV, KRILL_HTTPS_ROOT_CERTS_ENV};

const JSON_CONTENT: &str = "application/json";

fn report_get_and_exit(uri: &str, token: Option<&Token>) {
    println!("GET:\n  {}", uri);
    if let Some(token) = token {
        println!("Headers:\n  Authorization: Bearer {}", token);
    }
    std::process::exit(0);
}

enum PostBody<'a> {
    String(&'a String),
    Bytes(&'a Vec<u8>),
}

impl<'a> fmt::Display for PostBody<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PostBody::String(string) => write!(f, "{}", string),
            PostBody::Bytes(bytes) => {
                let base64 = base64::encode(bytes);
                write!(f, "<binary content, base64 encoded for display here> {}", base64)
            }
        }
    }
}

fn report_post_and_exit(uri: &str, content_type: Option<&str>, token: Option<&Token>, body: PostBody) {
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

/// Performs a GET request that expects a json response that can be
/// deserialized into the an owned value of the expected type. Returns an error
/// if nothing is returned.
pub async fn get_json<T: DeserializeOwned>(uri: &str, token: Option<&Token>) -> Result<T, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(Some(JSON_CONTENT), token)?;

    let res = client(uri).await?.get(uri).headers(headers).send().await?;
    process_json_response(res).await
}

/// Performs a get request and expects a response that can be turned
/// into a string (in particular, not a binary response).
pub async fn get_text(uri: &str, token: Option<&Token>) -> Result<String, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri, token);
    }

    let headers = headers(None, token)?;
    let res = client(uri).await?.get(uri).headers(headers).send().await?;
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
    let res = client(uri).await?.get(uri).headers(headers).send().await?;
    opt_text_response(res).await?; // Will return nice errors with possible body.
    Ok(())
}

/// Performs a POST of data that can be serialized into json, and expects
/// a 200 OK response, without a body.
pub async fn post_json(uri: &str, data: impl Serialize, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        let body = serde_json::to_string_pretty(&data)?;
        report_post_and_exit(uri, Some(JSON_CONTENT), token, PostBody::String(&body));
    }

    let body = serde_json::to_string(&data)?;
    let headers = headers(Some(JSON_CONTENT), token)?;

    let res = client(uri).await?.post(uri).headers(headers).body(body).send().await?;
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
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        let body = serde_json::to_string_pretty(&data)?;
        report_post_and_exit(uri, Some(JSON_CONTENT), token, PostBody::String(&body));
    }

    let body = serde_json::to_string(&data)?;
    let headers = headers(Some(JSON_CONTENT), token)?;
    let res = client(uri).await?.post(uri).headers(headers).body(body).send().await?;
    process_json_response(res).await
}

/// Performs a POST with no data to the given URI and expects and empty 200 OK response.
pub async fn post_empty(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, None, token, PostBody::String(&"<empty>".to_string()));
    }

    let headers = headers(Some(JSON_CONTENT), token)?;
    let res = client(uri).await?.post(uri).headers(headers).send().await?;
    if let Some(res) = opt_text_response(res).await? {
        Err(Error::UnexpectedResponse(res))
    } else {
        Ok(())
    }
}

/// Posts binary data, and expects a binary response.
///
/// Note: Bytes may be empty if the post was successful, but the response was
/// empty.
pub async fn post_binary(uri: &str, data: &Bytes, content_type: &str) -> Result<Bytes, Error> {
    let body = data.to_vec();
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, None, None, PostBody::Bytes(&body));
    }

    let headers = headers(Some(content_type), None)?;
    let res = client(uri).await?.post(uri).headers(headers).body(body).send().await?;

    match res.status() {
        StatusCode::OK => {
            let bytes = res.bytes().await?;
            Ok(bytes)
        }
        status => match res.text().await {
            Ok(body) => {
                if body.is_empty() {
                    Err(Error::BadStatus(status))
                } else {
                    Err(Error::ErrorWithBody(status, body))
                }
            }
            _ => Err(Error::BadStatus(status)),
        },
    }
}

/// Sends a delete request to the specified url.
pub async fn delete(uri: &str, token: Option<&Token>) -> Result<(), Error> {
    report_delete(uri, None, token);

    let headers = headers(None, token)?;
    let res = client(uri).await?.delete(uri).headers(headers).send().await?;

    match res.status() {
        StatusCode::OK => Ok(()),
        status => match res.text().await {
            Ok(body) => {
                if body.is_empty() {
                    Err(Error::BadStatus(status))
                } else {
                    Err(Error::ErrorWithBody(status, body))
                }
            }
            _ => Err(Error::BadStatus(status)),
        },
    }
}

fn load_root_cert(path: &str) -> Result<reqwest::Certificate, Error> {
    let path = PathBuf::from_str(path).map_err(Error::https_root_cert_error)?;
    let file = file::read(&path).map_err(Error::https_root_cert_error)?;
    reqwest::Certificate::from_pem(file.as_ref()).map_err(Error::https_root_cert_error)
}

pub async fn client(uri: &str) -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::ClientBuilder::new().timeout(Duration::from_secs(HTTTP_CLIENT_TIMEOUT_SECS));

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
        headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token))?);
    }
    Ok(headers)
}

async fn process_json_response<T: DeserializeOwned>(res: Response) -> Result<T, Error> {
    match opt_text_response(res).await {
        Err(e) => Err(e),
        Ok(None) => Err(Error::EmptyResponse),
        Ok(Some(s)) => {
            let res: T = serde_json::from_str(&s)?;
            Ok(res)
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
        status => match res.text().await {
            Ok(body) => {
                if body.is_empty() {
                    Err(Error::BadStatus(status))
                } else {
                    Err(Error::wrap_err_res(status, body))
                }
            }
            _ => Err(Error::BadStatus(status)),
        },
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt = "Request Error: {}", _0)]
    RequestError(reqwest::Error),

    #[display(fmt = "Access Forbidden")]
    Forbidden,

    #[display(fmt = "Received bad status: {}", _0)]
    BadStatus(StatusCode),

    #[display(fmt = "Status: {}, Error: {}", _0, _1)]
    ErrorWithBody(StatusCode, String),

    #[display(fmt = "Status: {}, Error: {}", _0, _1)]
    ErrorWithJson(StatusCode, ErrorResponse),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "{}", _0)]
    InvalidHeader(InvalidHeaderValue),

    #[display(fmt = "Empty response received from server")]
    EmptyResponse,

    #[display(fmt = "Unexpected response: {}", _0)]
    UnexpectedResponse(String),

    #[display(
        fmt = "HTTPS root cert error, check files under dir defined in KRILL_HTTPS_ROOT_CERTS: {}",
        _0
    )]
    HttpsRootCertError(String),
}

impl Error {
    fn wrap_err_res(code: StatusCode, content: String) -> Error {
        match serde_json::from_str::<ErrorResponse>(&content) {
            Ok(res) => Error::ErrorWithJson(code, res),
            Err(_) => Error::ErrorWithBody(code, content),
        }
    }

    fn https_root_cert_error(e: impl fmt::Display) -> Self {
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
    fn from(v: InvalidHeaderValue) -> Self {
        Error::InvalidHeader(v)
    }
}
