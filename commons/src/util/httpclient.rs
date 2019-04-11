//! Some helper functions for HTTP calls
use std::io::Read;
use std::time::Duration;
use bytes::Bytes;
use reqwest::{Client, Response, StatusCode};
use reqwest::header::{
    HeaderMap,
    HeaderValue,
    InvalidHeaderValue,
    USER_AGENT,
    CONTENT_TYPE};
use serde::Serialize;
use serde::de::DeserializeOwned;

const JSON_CONTENT: &str = "application/json";


/// Performs a GET request that expects a json response that can be
/// deserialized into the an owned value of the expected type. Returns an error
/// if nothing is returned.
pub fn get_json<T: DeserializeOwned>(
    uri: &str,
    token: Option<&str>
) -> Result<T, Error> {
    let headers = headers(Some(JSON_CONTENT), token)?;
    let res = client()?.get(uri).headers(headers).send()?;
    process_json_response(res)
}

/// Performs a get request and expects a response that can be turned
/// into a string (in particular, not a binary response).
pub fn get_text(
    uri: &str,
    content_type: &str,
    token: Option<&str>
) -> Result<String, Error> {
    let headers = headers(Some(content_type), token)?;
    let res = client()?.get(uri).headers(headers).send()?;
    match opt_text_response(res)? {
        Some(res) => Ok(res),
        None => Err(Error::EmptyResponse)
    }
}

/// Checks that there is a 200 OK response at the given URI. Discards the
/// response body.
pub fn get_ok(uri: &str, token: Option<&str>) -> Result<(), Error> {
    let headers = headers(None, token)?;
    let res = client()?.get(uri).headers(headers).send()?;
    opt_text_response(res)?; // Will return nice errors with possible body.
    Ok(())
}


/// Performs a POST of data that can be serialized into json, and expects
/// a 200 OK response, without a body.
pub fn post_json(
    uri: &str,
    data: impl Serialize,
    token: Option<&str>
) -> Result<(), Error> {
    let headers = headers(Some(JSON_CONTENT), token)?;
    let body = serde_json::to_string(&data)?;
    let res = client()?.post(uri).headers(headers).body(body).send()?;
    if let Some(res) = opt_text_response(res)? {
        Err(Error::UnexpectedResponse(res))
    } else {
        Ok(())
    }
}


/// Performs a POST of data that can be serialized into json, and expects
/// a json response that can be deserialized into the an owned value of the
/// expected type.
pub fn post_json_with_response<T: DeserializeOwned>(
    uri: &str,
    data: impl Serialize,
    token: Option<&str>
) -> Result<T, Error> {
    let headers = headers(Some(JSON_CONTENT), token)?;
    let body = serde_json::to_string(&data)?;
    let res = client()?.post(uri).headers(headers).body(body).send()?;
    process_json_response(res)
}


/// Posts binary data, and expects a binary response.
///
/// Note: Bytes may be empty if the post was successful, but the response was
/// empty.
pub fn post_binary(
    uri: &str,
    data: &Bytes,
    content_type: &str
) -> Result<Bytes, Error> {
    let headers = headers(Some(content_type), None)?;
    let body = data.to_vec();

    let mut res = client()?.post(uri).headers(headers).body(body).send()?;

    match res.status() {
        StatusCode::OK => {
            let mut bytes: Vec<u8> = vec![];
            res.read_to_end(&mut bytes).unwrap();
            let bytes = bytes::Bytes::from(bytes);
            Ok(bytes)
        },
        status => {
            match res.text() {
                Ok(body) => {
                    if body.is_empty() {
                        Err(Error::BadStatus(status))
                    } else {
                        Err(Error::ErrorWithBody(status, body))
                    }
                },
                _ => Err(Error::BadStatus(status))
            }
        }
    }
}

/// Sends a delete request to the specified url.
pub fn delete(
    uri: &str,
    token: Option<&str>
) -> Result<(), Error> {
    let headers = headers(None, token)?;
    client()?.delete(uri).headers(headers).send()?;
    Ok(())
}


fn client() -> Result<Client, Error> {
    Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(Error::RequestError)
}

fn headers(
    content_type: Option<&str>,
    token: Option<&str>
) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str("krill")?
    );
    if let Some(content_type) = content_type {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type)?
        );
    }
    if let Some(token) = token {
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", token))?
        );
    }
    Ok(headers)
}

fn process_json_response<T: DeserializeOwned>(
    res: Response
) -> Result<T, Error> {
    match opt_text_response(res) {
        Err(e) => Err(e),
        Ok(None) => Err(Error::EmptyResponse),
        Ok(Some(s)) => {
            let res: T = serde_json::from_str(&s)?;
            Ok(res)
        }
    }
}

fn opt_text_response(mut res: Response) -> Result<Option<String>, Error> {
    match res.status() {
        StatusCode::OK => {
            match res.text().ok() {
                None => Ok(None),
                Some(s) => {
                    if s.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(s))
                    }
                }
            }
        },
        StatusCode::FORBIDDEN => Err(Error::Forbidden),
        status => {
            match res.text() {
                Ok(body) => {
                    if body.is_empty() {
                        Err(Error::BadStatus(status))
                    } else {
                        Err(Error::ErrorWithBody(status, body))
                    }
                },
                _ => Err(Error::BadStatus(status))
            }
        }
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="Request Error: {}", _0)]
    RequestError(reqwest::Error),

    #[display(fmt="Access Forbidden")]
    Forbidden,

    #[display(fmt="Received bad status: {}", _0)]
    BadStatus(StatusCode),

    #[display(fmt="Status: {}, Error: {}", _0, _1)]
    ErrorWithBody(StatusCode, String),

    #[display(fmt="{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt="{}", _0)]
    InvalidHeader(InvalidHeaderValue),

    #[display(fmt="Empty response received from server")]
    EmptyResponse,

    #[display(fmt="Unexpected response: {}", _0)]
    UnexpectedResponse(String)
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self { Error::RequestError(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}

impl From<InvalidHeaderValue> for Error {
    fn from(v: InvalidHeaderValue) -> Self { Error::InvalidHeader(v) }
}
