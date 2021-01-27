use std::fmt::Display;

use openidconnect::{
    core::CoreErrorResponseType,
    http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode},
    HttpRequest, HttpResponse, RefreshToken, StandardErrorResponse,
};
use reqwest::Url;

///
/// OAuth 2.0 Token Revocation request
///
pub struct TokenRevocationRequest {
    pub(super) url: Url,
    pub(super) refresh_token: RefreshToken,
    // pub(super) access_token: Option<AccessToken>,
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
            .and_then(|http_response| self.token_revocation_response(http_response))
    }

    fn prepare_request(&self) -> HttpRequest {
        // let (auth_header, auth_value) = auth_bearer(&self.access_token);
        HttpRequest {
            url: self.url.clone(),
            method: Method::POST,
            headers: vec![
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                ),
                // (auth_header, auth_value),
            ]
            .into_iter()
            .collect(),
            body: format!(
                "token={}",
                urlparse::quote_plus(self.refresh_token.secret(), b"").unwrap()
            )
            .into_bytes(),
        }
    }

    fn token_revocation_response(
        self,
        http_response: HttpResponse,
    ) -> Result<(), StandardErrorResponse<CoreErrorResponseType>> {
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
}