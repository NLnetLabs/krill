use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreErrorResponseType,
    CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode,
    CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse, CoreSubjectIdentifierType,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, Client, ExtraTokenFields, IdTokenClaims, IdTokenFields,
    ProviderMetadata, StandardErrorResponse, StandardTokenResponse, UserInfoClaims,
};

use crate::commons::error::Error;
use crate::commons::KrillResult;

// -----------------------------------------------------------------------------
// Swap out the openidconnect crate types EmptyAdditionalClaims and
// EmptyExtraTokenFields with our own types which are flexible enough to handle
// deserialization of any possible (but known in advance) claim/token fields
// that the OpenID Connect provider might include in a response to us. Otherwise
// the default openidconnect crate implementation drops such response fields
// during deserialization preventing us from extracting them (e.g. to learn
// which Krill role the identity provider logged in user should have).
// -----------------------------------------------------------------------------

// Define additional claims that we might receive from the OpenID Connect
// provider as an arbitrary JSON hierarchy as we cannot know at compile time
// which claim name we should expect to look for from a given customers provider
// rather they must tell us that via runtime configuration. If we were instead
// to, for example, define a "role" member field of our custom additional claims
// struct, serde_json would fail to deserialize it if the the field is not
// present or not structured as expected. Using this approach we can inspect the
// structure when we receive it from the provider.
#[derive(Serialize, Deserialize, Debug)]
pub struct CustomerDefinedAdditionalClaims(serde_json::Value);
impl AdditionalClaims for CustomerDefinedAdditionalClaims {}

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomerDefinedExtraTokenFields(serde_json::Value);
impl ExtraTokenFields for CustomerDefinedExtraTokenFields {}

pub type FlexibleTokenResponse = StandardTokenResponse<
    IdTokenFields<
        CustomerDefinedAdditionalClaims,
        CustomerDefinedExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
    >,
    CoreTokenType,
>;
pub type FlexibleClient = Client<
    CustomerDefinedAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    FlexibleTokenResponse,
    CoreTokenType,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
>;
pub type FlexibleIdTokenClaims = IdTokenClaims<CustomerDefinedAdditionalClaims, CoreGenderClaim>;
pub type FlexibleUserInfoClaims = UserInfoClaims<CustomerDefinedAdditionalClaims, CoreGenderClaim>;

// Define additional metadata fields that we hope to find in the OpenID Connect
// Discovery response from the .well-known/openid-configuration provider
// endpoint. These fields are optional if we cannot be sure that the provider
// will set them in its response, otherwise response deserialization would fail.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DesiredAdditionalProviderMetadata {
    pub end_session_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
}
impl AdditionalProviderMetadata for DesiredAdditionalProviderMetadata {}

// Define a type which we can use to instruct the openidconnect Rust crate to
// expect to receive and deserialize the additional metadata fields that we just
// defined.
pub type WantedMeta = ProviderMetadata<
    DesiredAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

impl From<openidconnect::url::ParseError> for Error {
    fn from(e: openidconnect::url::ParseError) -> Self {
        Error::Custom(e.to_string())
    }
}

// -----------------------------------------------------------------------------
// Macros to assist with runtime inspection of the OpenID Connect provider
// discovery response. These allow the calling code to limiit itself to
// expressing our intent and not be cluttered by type structure handling. We
// have to use macros otherwise the need to specify different pattern matches
// would cause us to need to express lots of this boilerplate in the calling
// code.
// -----------------------------------------------------------------------------
macro_rules! is_supported {
    ($x:expr, $p:pat) => {{
        match $x.iter().any(|v| matches!(v, $p)) {
            true => Some(()),
            false => None,
        }
    }};
}

macro_rules! is_supported_opt {
    ($x:expr, $p:pat) => {{
        let empty_vec = Vec::new();
        is_supported!($x.unwrap_or_else(|| &empty_vec), $p)
    }};
}

macro_rules! is_supported_val {
    ($x:expr, $v:expr) => {{
        match $x.contains(&$v) {
            true => Some(()),
            false => None,
        }
    }};
}

macro_rules! is_supported_val_opt {
    ($x:expr, $v:expr) => {{
        let empty_vec = Vec::new();
        is_supported_val!($x.unwrap_or_else(|| &empty_vec), $v)
    }};
}

// -----------------------------------------------------------------------------
// Extend Option<> to simplify logging of the presence or absence of optional
// OpenID Connect provider discovery properties that we require to be present.
// -----------------------------------------------------------------------------
pub trait LogOrFail {
    fn log_or_fail(self, prop: &str, val: Option<&str>) -> KrillResult<()>;
}
impl<T> LogOrFail for Option<T> {
    fn log_or_fail(self, prop: &str, val: Option<&str>) -> KrillResult<()> {
        let prop_val_text = match val {
            Some(val) => format!("{}={}", prop, val),
            None => prop.to_string(),
        };

        match self {
            Some(_) => {
                debug!("OpenID Connect provider has capability {}", prop_val_text);
                Ok(())
            }
            None => {
                let err = format!("OpenID Connect provider lacks capability {}", prop_val_text);
                error!("{}", err);
                Err(Error::Custom(err))
            }
        }
    }
}
