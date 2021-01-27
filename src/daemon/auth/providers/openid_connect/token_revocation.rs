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

///
/// Error revoking token
///
/// TODO: See:
///   - https://tools.ietf.org/html/rfc6749#section-5.2
///   - https://tools.ietf.org/html/rfc7009#section-2.2.1
///
#[derive(Debug)]
#[non_exhaustive]
pub enum TokenRevocationError {
    ///
    /// An unexpected error occurred.
    ///
    Other(String),
}

// #[cfg(test)]
// mod tests {
//     use crate::core::CoreGenderClaim;
//     use crate::{AdditionalClaims, UserInfoClaims};

//     use std::collections::HashMap;

//     #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
//     struct TestClaims {
//         pub tfa_method: String,
//     }
//     impl AdditionalClaims for TestClaims {}

//     #[test]
//     fn test_additional_claims() {
//         let claims = UserInfoClaims::<TestClaims, CoreGenderClaim>::from_json::<
//             crate::reqwest::HttpClientError,
//         >(
//             "{
//                 \"iss\": \"https://server.example.com\",
//                 \"sub\": \"24400320\",
//                 \"aud\": [\"s6BhdRkqt3\"],
//                 \"tfa_method\": \"u2f\"
//             }"
//             .as_bytes(),
//             None,
//         )
//         .expect("failed to deserialize");
//         assert_eq!(claims.additional_claims().tfa_method, "u2f");
//         assert_eq!(
//             serde_json::to_string(&claims).expect("failed to serialize"),
//             "{\
//              \"iss\":\"https://server.example.com\",\
//              \"aud\":[\"s6BhdRkqt3\"],\
//              \"sub\":\"24400320\",\
//              \"tfa_method\":\"u2f\"\
//              }",
//         );

//         UserInfoClaims::<TestClaims, CoreGenderClaim>::from_json::<crate::reqwest::HttpClientError>(
//             "{
//                 \"iss\": \"https://server.example.com\",
//                 \"sub\": \"24400320\",
//                 \"aud\": [\"s6BhdRkqt3\"]
//             }".as_bytes(),
//             None,
//         )
//             .expect_err("missing claim should fail to deserialize");
//     }

//     #[derive(Debug, Deserialize, Serialize)]
//     struct AllOtherClaims(HashMap<String, serde_json::Value>);
//     impl AdditionalClaims for AllOtherClaims {}

//     #[test]
//     fn test_catch_all_additional_claims() {
//         let claims = UserInfoClaims::<AllOtherClaims, CoreGenderClaim>::from_json::<
//             crate::reqwest::HttpClientError,
//         >(
//             "{
//                 \"iss\": \"https://server.example.com\",
//                 \"sub\": \"24400320\",
//                 \"aud\": [\"s6BhdRkqt3\"],
//                 \"tfa_method\": \"u2f\",
//                 \"updated_at\": 1000
//             }"
//             .as_bytes(),
//             None,
//         )
//         .expect("failed to deserialize");

//         assert_eq!(claims.additional_claims().0.len(), 1);
//         assert_eq!(claims.additional_claims().0["tfa_method"], "u2f");
//     }
// }
