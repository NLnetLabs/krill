use std::fmt::Display;

use openidconnect::{
    core::CoreErrorResponseType,
    http::{
        self,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    url::form_urlencoded,
    HttpRequest, HttpResponse, StandardErrorResponse,
};
use reqwest::Url;

///
/// OAuth 2.0 Token Revocation request
///
pub struct TokenRevocationRequest {
    pub(super) url: Url,
    pub(super) client_id: String,
    pub(super) client_secret: String,
    pub(super) token: String,
    pub(super) token_type_hint: String,
}
impl TokenRevocationRequest {
    ///
    /// Submits this request to the associated token revocation endpoint using the specified synchronous
    /// HTTP client.
    ///
    pub fn request<HC, ER>(self, http_client: HC) -> Result<(), StandardErrorResponse<CoreErrorResponseType>>
    where
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, ER>,
        ER: Display,
    {
        http_client(self.prepare_request())
            .map_err(|err| {
                StandardErrorResponse::new(
                    CoreErrorResponseType::Extension(format!("Token revocation failed with internal error: {}", err)),
                    None,
                    None,
                )
            })
            .and_then(token_response)
    }

    fn prepare_request(&self) -> HttpRequest {
        token_request(
            self.client_id.clone(),
            self.client_secret.clone(),
            self.token.clone(),
            self.token_type_hint.clone(),
            self.url.clone(),
        )
        // let (auth_header, auth_value) = auth_bearer(&self.access_token);
        // HttpRequest {
        //     url: self.url.clone(),
        //     method: Method::POST,
        //     headers: vec![
        //         (
        //             CONTENT_TYPE,
        //             HeaderValue::from_static("application/x-www-form-urlencoded"),
        //         ),
        //         // (auth_header, auth_value),
        //     ]
        //     .into_iter()
        //     .collect(),
        //     body: format!(
        //         "client_id={}&client_secret={}&token={}&token_type_hint={}",
        //         urlparse::quote_plus(self.client_id.clone(), b"").unwrap(),
        //         urlparse::quote_plus(self.client_secret.clone(), b"").unwrap(),
        //         urlparse::quote_plus(self.token.clone(), b"").unwrap(),
        //         urlparse::quote_plus(self.token_type_hint.clone(), b"").unwrap()
        //     )
        //     .into_bytes(),
        // }
    }
}

// Based on oauth2 v3.0.0
fn token_request(
    client_id: String,
    client_secret: String,
    token: String,
    token_type_hint: String,
    url: Url,
) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static("application/json"));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    // FIXME: add support for auth extensions? e.g., client_secret_jwt and private_key_jwt
    // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
    // before using them as HTTP Basic auth username and password. Note that this is
    // not standard for ordinary Basic auth, so curl won't do it for us.
    let urlencoded_id: String = form_urlencoded::byte_serialize(&client_id.as_bytes()).collect();
    let urlencoded_secret: String = form_urlencoded::byte_serialize(&client_secret.as_bytes()).collect();
    let b64_credential = base64::encode(&format!("{}:{}", &urlencoded_id, &urlencoded_secret));
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
    );

    let mut params: Vec<(&str, &str)> = Vec::new();
    params.push(("token", &token));
    params.push(("token_type_hint", &token_type_hint));
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    HttpRequest {
        url,
        method: http::method::Method::POST,
        headers,
        body,
    }
}

fn token_response(http_response: HttpResponse) -> Result<(), StandardErrorResponse<CoreErrorResponseType>> {
    match http_response.status_code {
        StatusCode::OK => Ok(()),
        _ => Err(StandardErrorResponse::new(
            CoreErrorResponseType::Extension(format!(
                "Token revocation failed with status code {}",
                http_response.status_code
            )),
            None,
            None,
        )),
    }
}

// // Copied from oauth2 v3.0.0
// fn token_response(
//     http_response: HttpResponse,
// ) -> Result<(), StandardErrorResponse<CoreErrorResponseType>> {
//     if http_response.status_code != StatusCode::OK {
//         let reason = http_response.body.as_slice();
//         if reason.is_empty() {
//             return Err(StandardErrorResponse::new(
//                 CoreErrorResponseType::Extension("Server returned empty error response".to_string()),
//                 None,
//                 None
//             ));
//         } else {
//             let error = match serde_json::from_slice::<StandardErrorResponse<CoreErrorResponseType>>(reason) {
//                 Ok(error) => RequestTokenError::ServerResponse(error),
//                 Err(error) => RequestTokenError::Parse(error, reason.to_vec()),
//             };
//             return Err(error);
//         }
//     }

//     // Validate that the response Content-Type is JSON.
//     http_response
//         .headers
//         .get(CONTENT_TYPE)
//         .map_or(Ok(()), |content_type|
//             // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
//             // may be followed by optional whitespace and/or a parameter (e.g., charset).
//             // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
//             if content_type.to_str().ok().filter(|ct| ct.to_lowercase().starts_with("application/json")).is_none() {
//                 Err(
//                     RequestTokenError::Other(
//                         format!(
//                             "Unexpected response Content-Type: {:?}, should be `{}`",
//                             content_type,
//                             "application/json"
//                         )
//                     )
//                 )
//             } else {
//                 Ok(())
//             }
//         )?;

//     if http_response.body.is_empty() {
//         Err(RequestTokenError::Other(
//             "Server returned empty response body".to_string(),
//         ))
//     } else {
//         let response_body = http_response.body.as_slice();
//         serde_json::from_slice(response_body)
//             .map_err(|e| RequestTokenError::Parse(e, response_body.to_vec()))
//     }
// }
