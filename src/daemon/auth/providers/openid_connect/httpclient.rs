use std::{str::FromStr, time::Duration};

use reqwest::Response;

use crate::{
    commons::error::Error,
    commons::util::httpclient,
    constants::{test_mode_enabled, OPENID_CONNECT_HTTP_CLIENT_TIMEOUT_SECS},
};

// Wrap the httpclient produced above with optional logging of requests to and responses from the OpenID Connect
// provider.
pub async fn logging_http_client(req: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, Error> {
    if log_enabled!(log::Level::Trace) {
        // Don't {:?} log the openidconnect::HTTPRequest req object
        // because that renders the body as an unreadable integer byte
        // array, instead try and decode it as UTF-8.
        let body = match std::str::from_utf8(&req.body) {
            Ok(text) => text.to_string(),
            Err(_) => format!("{:?}", &req.body),
        };
        debug!(
            "OpenID Connect request: url: {:?}, method: {:?}, headers: {:?}, body: {}",
            req.url, req.method, req.headers, body
        );
    }

    let res = dispatch_openid_request(req).await;

    if log_enabled!(log::Level::Trace) {
        match &res {
            Ok(res) => {
                // Don't {:?} log the openidconnect::HTTPResponse res
                // object because that renders the body as an unreadable
                // integer byte array, instead try and decode it as
                // UTF-8.
                let body = match std::str::from_utf8(&res.body) {
                    Ok(text) => text.to_string(),
                    Err(_) => format!("{:?}", &res.body),
                };
                debug!(
                    "OpenID Connect response: status_code: {:?}, headers: {:?}, body: {}",
                    res.status_code, res.headers, body
                );
            }
            Err(err) => {
                debug!("OpenID Connect response: {:?}", err)
            }
        }
    }

    res.map_err(Error::HttpClientError)
}

async fn dispatch_openid_request(
    request: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, httpclient::Error> {
    let request_uri = request.url.to_string();

    let client = {
        let timeout = openid_connect_provider_timeout();
        let allow_redirects = false; // Following redirects opens the client up to SSRF vulnerabilities.

        httpclient::client_with_tweaks(&request_uri, timeout, allow_redirects)
    }?;

    let request = convert_openid_request(request, &client)?;

    let response = client
        .execute(request)
        .await
        .map_err(|e| httpclient::Error::execute(&request_uri, e))?;

    convert_to_openid_response(&request_uri, response).await
}

fn convert_openid_request(
    request: openidconnect::HttpRequest,
    client: &reqwest::Client,
) -> Result<reqwest::Request, httpclient::Error> {
    let request_uri = request.url.to_string();

    let request_method = reqwest::Method::from_str(request.method.as_str())
        .map_err(|_| httpclient::Error::request_build(&request_uri, format!("invalid method: {}", request.method)))?;

    let mut request_builder = client.request(request_method, &request_uri).body(request.body);

    // map openid connect headers to the request builder
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    request_builder
        .build()
        .map_err(|e| httpclient::Error::request_build(&request_uri, e))
}

async fn convert_to_openid_response(
    uri: &str,
    response: Response,
) -> Result<openidconnect::HttpResponse, httpclient::Error> {
    let response_code = response.status().as_u16();

    let response_status = openidconnect::http::StatusCode::from_u16(response_code)
        .map_err(|_| httpclient::Error::response(uri, format!("invalid status code: {}", response_code)))?;

    let response_headers = {
        let mut headers = openidconnect::http::HeaderMap::new();
        for (name, value) in response.headers() {
            let name = openidconnect::http::header::HeaderName::from_str(name.as_str())
                .map_err(|_| httpclient::Error::response(uri, format!("invalid header name: {}", name.as_str())))?;

            let value = openidconnect::http::header::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| {
                httpclient::Error::response(uri, format!("invalid value for header: {}", name.as_str()))
            })?;

            headers.append(name, value);
        }

        headers
    };

    let response_body = response
        .bytes()
        .await
        .map_err(|e| httpclient::Error::response(uri, format!("could not get response body: {}", e)))?;

    Ok(openidconnect::HttpResponse {
        status_code: response_status,
        headers: response_headers,
        body: response_body.to_vec(),
    })
}

fn openid_connect_provider_timeout() -> Duration {
    if test_mode_enabled() {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(OPENID_CONNECT_HTTP_CLIENT_TIMEOUT_SECS)
    }
}
