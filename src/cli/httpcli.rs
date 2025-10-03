//! Some helper functions for HTTP calls
use std::env;

use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT},
    Response, StatusCode,
};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::{
    commons::httpclient::Error,
    constants::KRILL_CLI_API_ENV,
};

const JSON_CONTENT: &str = "application/json";

fn report_get_and_exit(uri: &str) {
    println!("GET:\n  {uri}");
    std::process::exit(0);
}

fn report_post_and_exit(
    uri: &str,
    _content_type: Option<&str>,
    body: &str,
) {
    println!("POST:\n  {uri}");
    println!("Body:\n{body}");
    std::process::exit(0);
}

fn report_delete(
    uri: &str,
    _content_type: Option<&str>,
) {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        println!("DELETE:\n  {uri}");
        std::process::exit(0);
    }
}

/// Performs a GET request that expects a json response that can be
/// deserialized into the an owned value of the expected type. Returns an
/// error if nothing is returned.
pub async fn get_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    uri: &str,
) -> Result<T, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri);
    }

    let headers = headers(uri, Some(JSON_CONTENT))?;

    let res = client
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    process_json_response(&uri, res).await
}

/// Performs a get request and expects a response that can be turned
/// into a string (in particular, not a binary response).
pub async fn get_text(
    client: &reqwest::Client,
    uri: &str,
) -> Result<String, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri);
    }

    let headers = headers(uri, None)?;
    let res = client
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    text_response(&uri, res).await
}

/// Checks that there is a 200 OK response at the given URI. Discards the
/// response body.
pub async fn get_ok(client: &reqwest::Client, uri: &str) -> Result<(), Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_get_and_exit(uri);
    }

    let headers = headers(uri, None)?;
    let res = client
        .get(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    opt_text_response(&uri, res).await?; // Will return nice errors with possible body.
    Ok(())
}

/// Performs a POST of data that can be serialized into json, and expects
/// a 200 OK response, without a body.
pub async fn post_json(
    client: &reqwest::Client,
    uri: &str,
    data: impl Serialize,
) -> Result<(), Error> {
    let body = serde_json::to_string_pretty(&data)
        .map_err(|e| Error::request_build_json(uri, e))?;

    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, Some(JSON_CONTENT), &body);
    }
    let headers = headers(uri, Some(JSON_CONTENT))?;

    let res = client
        .post(uri)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    empty_response(&uri, res).await
}

/// Performs a POST of data that can be serialized into json, and expects
/// a json response that can be deserialized into the an owned value of the
/// expected type.
pub async fn post_json_with_response<T: DeserializeOwned>(
    client: &reqwest::Client,
    uri: &str,
    data: impl Serialize,
) -> Result<T, Error> {
    match post_json_with_opt_response(client, uri, data).await? {
        None => Err(Error::response(uri, "expected JSON response")),
        Some(res) => Ok(res),
    }
}

/// Performs a POST of data that can be serialized into json, and expects
/// an optional json response that can be deserialized into the an owned
/// value of the expected type.
pub async fn post_json_with_opt_response<T: DeserializeOwned>(
    client: &reqwest::Client,
    uri: &str,
    data: impl Serialize,
) -> Result<Option<T>, Error> {
    let body = serde_json::to_string_pretty(&data)
        .map_err(|e| Error::request_build_json(uri, e))?;

    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, Some(JSON_CONTENT), &body);
    }

    let headers = headers(uri, Some(JSON_CONTENT))?;

    let res = client
        .post(uri)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    process_opt_json_response(&uri, res).await
}

/// Performs a POST with no data to the given URI and expects and empty 200 OK
/// response.
pub async fn post_empty(
    client: &reqwest::Client,
    uri: &str,
) -> Result<(), Error> {
    let res = do_empty_post(client, uri).await?;
    empty_response(uri, res).await
}

/// Performs a POST with no data to the given URI and expects a response.
pub async fn post_empty_with_response<T: DeserializeOwned>(
    client: &reqwest::Client,
    uri: &str,
) -> Result<T, Error> {
    let res = do_empty_post(client, uri).await?;
    process_json_response(uri, res).await
}

pub async fn do_empty_post(
    client: &reqwest::Client,
    uri: &str,
) -> Result<Response, Error> {
    if env::var(KRILL_CLI_API_ENV).is_ok() {
        report_post_and_exit(uri, None, "<empty>");
    }

    let headers = headers(uri, Some(JSON_CONTENT))?;

    client
        .post(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))
}

/// Sends a delete request to the specified url.
pub async fn delete(
    client: &reqwest::Client,
    uri: &str
) -> Result<(), Error> {
    report_delete(uri, None);

    let headers = headers(uri, None)?;

    let res = client
        .delete(uri)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::execute(&uri, e))?;

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => Err(Error::from_res(&uri, res).await),
    }
}

#[allow(clippy::result_large_err)]
fn headers(
    uri: &str,
    content_type: Option<&str>,
) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("krill"));

    if let Some(content_type) = content_type {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .map_err(|e| Error::request_build(uri, e))?,
        );
    }
    Ok(headers)
}

async fn process_json_response<T: DeserializeOwned>(
    uri: &str,
    res: Response,
) -> Result<T, Error> {
    match process_opt_json_response(uri, res).await? {
        None => Err(Error::response(uri, "got empty response body")),
        Some(res) => Ok(res),
    }
}

async fn process_opt_json_response<T: DeserializeOwned>(
    uri: &str,
    res: Response,
) -> Result<Option<T>, Error> {
    match opt_text_response(uri, res).await? {
        None => Ok(None),
        Some(s) => {
            let res: T = serde_json::from_str(&s).map_err(|e| {
                Error::response(
                    uri,
                    format!("could not parse JSON response: {e}"),
                )
            })?;
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

async fn opt_text_response(
    uri: &str,
    res: Response,
) -> Result<Option<String>, Error> {
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