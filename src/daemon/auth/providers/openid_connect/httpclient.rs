use std::{env, path::PathBuf, str::FromStr};

use crate::{commons::util::{file, httpclient::http_client_timeout}, constants::KRILL_HTTPS_ROOT_CERTS_ENV};

use crate::commons::error::Error;

use crate::commons::util::httpclient;

// Based on httpclient::load_root_cert(). We can't just use the original function as the invoked functions are specific
// to types in the reqwest crate version being used.
fn load_root_cert(path: &str) -> Result<reqwestblocking::Certificate, httpclient::Error> {
    let path = PathBuf::from_str(path).map_err(httpclient::Error::https_root_cert_error)?;
    let file = file::read(&path).map_err(httpclient::Error::https_root_cert_error)?;
    reqwestblocking::Certificate::from_pem(file.as_ref()).map_err(httpclient::Error::https_root_cert_error)
}

// Based on httpclient::client().  We can't just use the original function as the invoked functions are specific to
// types in the reqwest crate version being used.
fn configure_http_client_for_krill(mut builder: reqwestblocking::ClientBuilder, uri: &str) -> Result<reqwestblocking::ClientBuilder, httpclient::Error> {
    builder = builder.timeout(http_client_timeout());

    if let Ok(cert_list) = env::var(KRILL_HTTPS_ROOT_CERTS_ENV) {
        for path in cert_list.split(':') {
            let cert = load_root_cert(path)?;
            builder = builder.add_root_certificate(cert);
        }
    }

    if uri.starts_with("https://localhost") || uri.starts_with("https://127.0.0.1") {
        builder = builder.danger_accept_invalid_certs(true);
    }

    Ok(builder)
}

// This is basically a copy of oauth2::reqwest::blocking::http_client() with the addition of the same logic Krill uses
// in its main HTTP client configuration (to permit insecure TLS server certificates if the server host is "localhost",
// useful when testing with a local OpenID Connect provider with a self-signed certificate, e.g. our mock provider, and
// to support custom TLS root certificates). 
//
// NOTE: Why does this use a second aliased reqwest dependency as reqwestblocking?
// This is due to the reqwest 0.10.x blocking implementation actually using a futures runtime and that you can't use a
// futures runtime inside another futures runtime otherwise you get error:
//   "panicked at 'Cannot drop a runtime in a context where blocking is not allowed. This happens when a runtime is
//    dropped from within an asynchronous context.' reqwest blocking"
// And we can't move to using async reqwest because async Rust doesn't work with traits and AuthProvider is a trait.
// Unless we use the async_traits crate...
//
// NOTE: We don't return reqwest::Error as the oauth2-rs implementation of `fn http_client()` does because that is a
// type in the oauth2-rs crate and all of the constructors for that type are private to the crate and so we cannot use
// map_err(reqwest::Error).
fn http_client(request: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, Error> {
    let mut client_builder = reqwestblocking::Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwestblocking::RedirectPolicy::none());

    client_builder = configure_http_client_for_krill(client_builder, request.url.as_str())
        .map_err(|err| Error::custom(format!("Failed to configure HTTP client: {}", err)))?;

    let client = client_builder.build().map_err(Error::custom)?;

    let mut request_builder = client
        .request(
            reqwestblocking::Method::from_bytes(request.method.as_str().as_ref())
                .expect("failed to convert Method from http 0.2 to 0.1"),
            request.url.as_str(),
        )
        .body(request.body);

    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let request = request_builder.build().map_err(Error::custom)?;

    let mut response = client.execute(request).map_err(Error::custom)?;

    let mut body = Vec::new();
    {
        use std::io::Read;
        response.read_to_end(&mut body).map_err(Error::custom)?;
    }

    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                openidconnect::http::header::HeaderName::from_bytes(name.as_str().as_ref())
                    .expect("failed to convert HeaderName from http 0.2 to 0.1"),
                openidconnect::http::header::HeaderValue::from_bytes(value.as_bytes())
                    .expect("failed to convert HeaderValue from http 0.2 to 0.1"),
            )
        })
        .collect::<openidconnect::http::HeaderMap>();

    Ok(openidconnect::HttpResponse {
        status_code: openidconnect::http::StatusCode::from_u16(response.status().as_u16())
            .expect("failed to convert StatusCode from http 0.2 to 0.1"),
        headers,
        body,
    })
}

// Wrap the httpclient produced above with optional logging of requests to and responses from the OpenID Connect 
// provider.
pub fn logging_http_client(req: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, Error> {
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

    let res = http_client(req);

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

    res
}