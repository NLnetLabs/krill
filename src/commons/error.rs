//! Defines all Krill server side errors

use std::fmt::Display;
use std::{fmt, io};

use actix_web::http::StatusCode;

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::commons::api::rrdp::PublicationDeltaError;
use crate::commons::api::{
    ChildHandle, ErrorResponse, Handle, ParentHandle, PublisherHandle, ResourceSetError,
};
use crate::commons::eventsourcing::AggregateStoreError;
use crate::commons::remote::rfc6492;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8181::ReportErrorCode;
use crate::commons::util::httpclient;
use crate::commons::util::softsigner::SignerError;
use crate::daemon::ca::RouteAuthorization;

#[derive(Debug, Display)]
pub enum Error {
    //-----------------------------------------------------------------
    // System Issues (1000-1099)
    //-----------------------------------------------------------------

    // 1000, internal server error
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    // 1001, internal server error
    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),

    // 1002, internal server error
    #[display(fmt = "Signing issue: {}", _0)]
    SignerError(String),

    // not on api (fails at start up)
    #[display(fmt = "{}", _0)]
    HttpsSetup(String),

    // not on api
    #[display(fmt = "{}", _0)]
    HttpClientError(httpclient::Error),

    //-----------------------------------------------------------------
    // General API Client Issues (2000-2099)
    //-----------------------------------------------------------------

    // 2000
    #[display(fmt = "Invalid JSON: {}", _0)]
    JsonError(serde_json::Error),

    // 2001, BAD REQUEST
    #[display(fmt = "Unknown API method.")]
    ApiUnknownMethod,

    // 2002, NOT FOUND (generic API not found)
    #[display(fmt = "Unknown resource.")]
    ApiUnknownResource,

    //-----------------------------------------------------------------
    // Repository Issues (2100-2199)
    //-----------------------------------------------------------------

    // 2100
    #[display(fmt = "No repository configured.")]
    RepoNotSet,

    //-----------------------------------------------------------------
    // Publisher Issues (2200-2299)
    //-----------------------------------------------------------------

    // 2200
    #[display(fmt = "Unknown publisher '{}'", _0)]
    PublisherUnknown(PublisherHandle),

    // 2201
    #[display(fmt = "Publishing uri '{}' outside repository uri '{}'", _0, _1)]
    PublisherUriOutsideBase(String, String),

    // 2202
    #[display(fmt = "Publisher uri '{}' must have a trailing slash", _0)]
    PublisherBaseUriNoSlash(String),

    // 2203
    #[display(fmt = "Duplicate publisher '{}'", _0)]
    PublisherDuplicate(PublisherHandle),

    // 2204
    #[display(fmt = "No embedded repository configured")]
    PublisherNoEmbeddedRepo,

    //-----------------------------------------------------------------
    // RF8181 (publishing, not on json API so no error responses)
    //-----------------------------------------------------------------

    // not on api
    #[display(fmt = "Could not decode or validate RFC8181 request: {}", _0)]
    Rfc8181Validation(String),

    // not on api
    #[display(fmt = "{}", _0)]
    Rfc8181MessageError(rfc8181::MessageError),

    // not on api
    #[display(fmt = "{}", _0)]
    Rfc8181Delta(PublicationDeltaError),

    //-----------------------------------------------------------------
    // CA Issues (2300-2399)
    //-----------------------------------------------------------------

    // 2300
    #[display(fmt = "CA '{}' was already initialised", _0)]
    CaDuplicate(Handle),

    // 2301
    #[display(fmt = "CA '{}' is unknown", _0)]
    CaUnknown(Handle),

    // CA Repo Issues (2310-2319)

    // 2310
    #[display(fmt = "CA '{}' already uses this repository.", _0)]
    CaRepoInUse(Handle),

    // 2311
    #[display(fmt = "CA '{}' got error from repository: {}", _0, _1)]
    CaRepoNotResponsive(Handle, String),

    // CA Parent Issues (2320-2329)

    // 2320
    #[display(fmt = "CA '{}' already has a parent named '{}'", _0, _1)]
    CaParentDuplicate(Handle, ParentHandle),

    // 2321
    #[display(fmt = "CA '{}' does not have parent named '{}'", _0, _1)]
    CaParentUnknown(Handle, ParentHandle),

    // 2322
    #[display(fmt = "CA '{}' got error from parent '{}': {}", _0, _1, _2)]
    CaParentNotResponsive(Handle, ParentHandle, String),

    //-----------------------------------------------------------------
    // RFC6492 (requesting resources, not on JSON api)
    //-----------------------------------------------------------------
    // not on api
    #[display(fmt = "{}", _0)]
    Rfc6492(rfc6492::Error),

    // not on api
    #[display(fmt = "Invalid CSR received: {}.", _0)]
    Rfc6492InvalidCsrSent(String),

    // not on api
    #[display(fmt = "Invalidly signed RFC 6492 CMS.")]
    Rfc6492SignatureInvalid,

    // CA Child Issues (2330-2339)

    // 2330
    #[display(fmt = "CA '{}' already has child named {}.", _0, _1)]
    CaChildDuplicate(Handle, ChildHandle),

    // 2331
    #[display(fmt = "CA '{}' does not have child named {}.", _0, _1)]
    CaChildUnknown(Handle, ChildHandle),

    // 2332
    #[display(fmt = "Child '{}' for CA '{}' MUST have resources specified.", _1, _0)]
    CaChildMustHaveResources(Handle, ChildHandle),

    // 2333
    #[display(fmt = "CA '{}' does not know id certificate for child '{}'.", _0, _1)]
    CaChildUnauthorised(Handle, ChildHandle),

    // RouteAuthorizations (2340-2349)

    // 2340
    #[display(fmt = "Cannot remove unknown authorization '{}' from CA '{}'", _0, _1)]
    CaAuthorisationUnknown(Handle, RouteAuthorization),

    // 2341
    #[display(fmt = "Duplicate authorization '{}' for CA '{}'", _1, _0)]
    CaAuthorisationDuplicate(Handle, RouteAuthorization),

    // 2342
    #[display(fmt = "Invalid max length in authorization: '{}' for CA '{}", _1, _0)]
    CaAuthorisationInvalidMaxlength(Handle, RouteAuthorization),

    // 2343
    #[display(fmt = "Authorisation '{}' resource not held by CA '{}'.", _1, _0)]
    CaAuthorisationNotEntitled(Handle, RouteAuthorization),

    //-----------------------------------------------------------------
    // Key Usage Issues (2400-2499)
    //-----------------------------------------------------------------

    // not on api
    #[display(fmt = "Attempt at re-using keys.")]
    KeyUseAttemptReuse,

    // not on api
    #[display(fmt = "No new key in resource class")]
    KeyUseNoNewKey,

    // not on api
    #[display(fmt = "No current key in resource class")]
    KeyUseNoCurrentKey,

    // not on api
    #[display(fmt = "No old key in resource class")]
    KeyUseNoOldKey,

    // not on api
    #[display(fmt = "No issued cert matching pub key")]
    KeyUseNoIssuedCert,

    // not on api
    #[display(fmt = "No key found matching key identifier: {}", _0)]
    KeyUseNoMatch(KeyIdentifier),

    //-----------------------------------------------------------------
    // Resource Issues (2500-2599)
    //-----------------------------------------------------------------

    // not on api
    #[display(fmt = "Unknown resource class: {}", _0)]
    ResourceClassUnknown(String),

    // not on api
    #[display(fmt = "{}", _0)]
    ResourceSetError(ResourceSetError),

    // not on api
    #[display(fmt = "Requester is not entitled to all requested resources.")]
    MissingResources,

    //-----------------------------------------------------------------
    // Embedded (test) TA issues (2600-2699)
    //-----------------------------------------------------------------

    // 2600
    #[display(fmt = "Functionality not supported for TA.")]
    TaNotAllowed,

    // 2601
    #[display(fmt = "Name reserved for embedded TA.")]
    TaNameReserved,

    // not on api
    #[display(fmt = "TrustAnchor was already initialised")]
    TaAlreadyInitialised,

    //-----------------------------------------------------------------
    // If we really don't know any more..
    //-----------------------------------------------------------------
    // 65535  - but should not occur on API
    #[display(fmt = "{}", _0)]
    Custom(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self {
        Error::AggregateStoreError(e)
    }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self {
        Error::SignerError(e.to_string())
    }
}

impl From<rfc6492::Error> for Error {
    fn from(e: rfc6492::Error) -> Self {
        Error::Rfc6492(e)
    }
}

impl From<rfc8181::MessageError> for Error {
    fn from(e: rfc8181::MessageError) -> Self {
        Error::Rfc8181MessageError(e)
    }
}

impl From<ResourceSetError> for Error {
    fn from(e: ResourceSetError) -> Self {
        Error::ResourceSetError(e)
    }
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn invalid_csr(msg: &str) -> Self {
        Error::Rfc6492InvalidCsrSent(msg.to_string())
    }

    pub fn unknown_resource_class(class: impl Display) -> Self {
        Error::ResourceClassUnknown(class.to_string())
    }

    pub fn publishing_outside_jail(uri: &uri::Rsync, jail: &uri::Rsync) -> Self {
        Error::PublisherUriOutsideBase(uri.to_string(), jail.to_string())
    }

    pub fn custom(msg: impl fmt::Display) -> Self {
        Error::Custom(msg.to_string())
    }

    pub fn rfc8181_validation(e: impl fmt::Display) -> Self {
        Error::Rfc8181Validation(e.to_string())
    }
}

impl std::error::Error for Error {}

/// Translate an error to an HTTP Status Code
impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            // Most is bad requests by users, so just mapping the things that are not
            Error::IoError(_) | Error::SignerError(_) | Error::AggregateStoreError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Error::PublisherUnknown(_)
            | Error::CaChildUnknown(_, _)
            | Error::CaParentUnknown(_, _) => StatusCode::NOT_FOUND,

            _ => StatusCode::BAD_REQUEST,
        }
    }

    pub fn to_error_response(&self) -> ErrorResponse {
        fn not_in_api() -> ErrorResponse {
            unimplemented!("Cannot be caused by API")
        }

        match self {
            //-----------------------------------------------------------------
            // System Issues (1000-1099)
            //-----------------------------------------------------------------

            // 1000, internal server error
            Error::IoError(e) => {
                ErrorResponse::with_args(1000, self.to_string(), vec![e.to_string()])
            }

            // 1001, internal server error
            Error::AggregateStoreError(e) => {
                ErrorResponse::with_args(1001, self.to_string(), vec![e.to_string()])
            }

            // 1002, internal server error
            Error::SignerError(e) => {
                ErrorResponse::with_args(1002, self.to_string(), vec![e.to_string()])
            }

            // not on api (fails at start up)
            Error::HttpsSetup(_) => not_in_api(),

            // not on api
            Error::HttpClientError(_) => not_in_api(),

            //-----------------------------------------------------------------
            // General API Client Issues (2000-2099)
            //-----------------------------------------------------------------

            // 2000
            Error::JsonError(e) => {
                ErrorResponse::with_args(2000, self.to_string(), vec![e.to_string()])
            }

            // 2001, BAD REQUEST
            Error::ApiUnknownMethod => ErrorResponse::no_args(2001, &self),

            // 2002, NOT FOUND (generic API not found)
            Error::ApiUnknownResource => ErrorResponse::no_args(2002, &self),

            //-----------------------------------------------------------------
            // Repository Issues (2100-2199)
            //-----------------------------------------------------------------

            // 2100
            Error::RepoNotSet => ErrorResponse::no_args(2100, &self),

            //-----------------------------------------------------------------
            // Publisher Issues (2200-2299)
            //-----------------------------------------------------------------
            Error::PublisherUnknown(p) => {
                ErrorResponse::with_args(2200, self.to_string(), vec![p.to_string()])
            }

            Error::PublisherUriOutsideBase(uri, base) => ErrorResponse::with_args(
                2201,
                self.to_string(),
                vec![uri.to_string(), base.to_string()],
            ),

            Error::PublisherBaseUriNoSlash(uri) => {
                ErrorResponse::with_args(2202, self.to_string(), vec![uri.to_string()])
            }

            Error::PublisherDuplicate(p) => {
                ErrorResponse::with_args(2203, self.to_string(), vec![p.to_string()])
            }

            Error::PublisherNoEmbeddedRepo => ErrorResponse::no_args(2204, &self),

            //-----------------------------------------------------------------
            // RF8181 (publishing, not on json API so no error responses)
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(_) => not_in_api(),
            Error::Rfc8181MessageError(_) => not_in_api(),
            Error::Rfc8181Delta(_) => not_in_api(),

            //-----------------------------------------------------------------
            // CA Issues (2300-2399)
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => {
                ErrorResponse::with_args(2300, self.to_string(), vec![ca.to_string()])
            }

            Error::CaUnknown(ca) => {
                ErrorResponse::with_args(2301, self.to_string(), vec![ca.to_string()])
            }

            Error::CaRepoInUse(ca) => {
                ErrorResponse::with_args(2302, self.to_string(), vec![ca.to_string()])
            }

            Error::CaRepoNotResponsive(ca, err) => {
                ErrorResponse::with_args(2311, self.to_string(), vec![ca.to_string(), err.clone()])
            }

            Error::CaParentDuplicate(ca, parent) => ErrorResponse::with_args(
                2320,
                self.to_string(),
                vec![ca.to_string(), parent.to_string()],
            ),

            Error::CaParentUnknown(ca, parent) => ErrorResponse::with_args(
                2321,
                self.to_string(),
                vec![ca.to_string(), parent.to_string()],
            ),

            Error::CaParentNotResponsive(ca, parent, err) => ErrorResponse::with_args(
                2322,
                self.to_string(),
                vec![ca.to_string(), parent.to_string(), err.clone()],
            ),

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources, not on JSON api)
            //-----------------------------------------------------------------
            Error::Rfc6492(_) => not_in_api(),
            Error::Rfc6492InvalidCsrSent(_) => not_in_api(),
            Error::Rfc6492SignatureInvalid => not_in_api(),

            // CA Child Issues (2330-2339)
            Error::CaChildDuplicate(ca, child) => ErrorResponse::with_args(
                2330,
                self.to_string(),
                vec![ca.to_string(), child.to_string()],
            ),

            Error::CaChildUnknown(ca, child) => ErrorResponse::with_args(
                2331,
                self.to_string(),
                vec![ca.to_string(), child.to_string()],
            ),

            Error::CaChildMustHaveResources(ca, child) => ErrorResponse::with_args(
                2332,
                self.to_string(),
                vec![ca.to_string(), child.to_string()],
            ),

            Error::CaChildUnauthorised(ca, child) => ErrorResponse::with_args(
                2333,
                self.to_string(),
                vec![ca.to_string(), child.to_string()],
            ),

            // RouteAuthorizations (2340-2349)
            Error::CaAuthorisationUnknown(ca, auth) => ErrorResponse::with_args(
                2340,
                self.to_string(),
                vec![
                    ca.to_string(),
                    auth.prefix().to_string(),
                    auth.effective_max_length().to_string(),
                    auth.asn().to_string(),
                ],
            ),

            Error::CaAuthorisationDuplicate(ca, auth) => ErrorResponse::with_args(
                2341,
                self.to_string(),
                vec![
                    ca.to_string(),
                    auth.prefix().to_string(),
                    auth.effective_max_length().to_string(),
                    auth.asn().to_string(),
                ],
            ),

            Error::CaAuthorisationInvalidMaxlength(ca, auth) => ErrorResponse::with_args(
                2342,
                self.to_string(),
                vec![
                    ca.to_string(),
                    auth.prefix().to_string(),
                    auth.effective_max_length().to_string(),
                    auth.asn().to_string(),
                ],
            ),

            Error::CaAuthorisationNotEntitled(ca, auth) => ErrorResponse::with_args(
                2343,
                self.to_string(),
                vec![
                    ca.to_string(),
                    auth.prefix().to_string(),
                    auth.effective_max_length().to_string(),
                    auth.asn().to_string(),
                ],
            ),

            //-----------------------------------------------------------------
            // Key Usage Issues (2400-2499)
            //-----------------------------------------------------------------

            // not on api
            Error::KeyUseAttemptReuse => not_in_api(),
            Error::KeyUseNoNewKey => not_in_api(),
            Error::KeyUseNoCurrentKey => not_in_api(),
            Error::KeyUseNoOldKey => not_in_api(),
            Error::KeyUseNoIssuedCert => not_in_api(),
            Error::KeyUseNoMatch(_) => not_in_api(),

            //-----------------------------------------------------------------
            // Resource Issues (2500-2599)
            //-----------------------------------------------------------------
            Error::ResourceClassUnknown(_) => not_in_api(),
            Error::ResourceSetError(_) => not_in_api(),
            Error::MissingResources => not_in_api(),

            //-----------------------------------------------------------------
            // Embedded (test) TA issues (2600-2699)
            //-----------------------------------------------------------------
            Error::TaNotAllowed => ErrorResponse::no_args(2600, &self),
            Error::TaNameReserved => ErrorResponse::no_args(2601, &self),
            Error::TaAlreadyInitialised => not_in_api(),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(_msg) => ErrorResponse::no_args(65535, &self),
        }

        //        self.code().clone().into()
    }

    pub fn to_rfc8181_error_code(&self) -> ReportErrorCode {
        match self {
            Error::Rfc8181Validation(_) | Error::PublisherUnknown(_) => {
                ReportErrorCode::PermissionFailure
            }
            Error::Rfc8181MessageError(_) => ReportErrorCode::XmlError,
            Error::Rfc8181Delta(e) => match e {
                PublicationDeltaError::UriOutsideJail(_, _) => ReportErrorCode::PermissionFailure,
                PublicationDeltaError::NoObjectForHashAndOrUri(_) => {
                    ReportErrorCode::NoObjectPresent
                }
                PublicationDeltaError::ObjectAlreadyPresent(_) => {
                    ReportErrorCode::ObjectAlreadyPresent
                }
            },
            _ => ReportErrorCode::OtherError,
        }
    }
}
