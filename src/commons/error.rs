//! Defines all Krill server side errors

use std::fmt::Display;
use std::{fmt, io};

// use actix_web::http::StatusCode;
use hyper::StatusCode;

use rpki::crypto::KeyIdentifier;
use rpki::uri;
use rpki::x509::ValidationError;

use crate::commons::api::rrdp::PublicationDeltaError;
use crate::commons::api::{
    ChildHandle, ErrorResponse, Handle, ParentHandle, PublisherHandle, ResourceClassName,
    ResourceSetError,
};
use crate::commons::eventsourcing::AggregateStoreError;
use crate::commons::remote::rfc6492;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8181::ReportErrorCode;
use crate::commons::util::httpclient;
use crate::commons::util::softsigner::SignerError;
use crate::daemon::ca::RouteAuthorization;
use crate::daemon::http::tls_keys;

#[derive(Debug, Display)]
pub enum Error {
    //-----------------------------------------------------------------
    // System Issues
    //-----------------------------------------------------------------
    #[display(fmt = "I/O error: {}", _0)]
    IoError(io::Error),

    #[display(fmt = "Persistence error: {}", _0)]
    AggregateStoreError(AggregateStoreError),

    #[display(fmt = "Signing issue: {}", _0)]
    SignerError(String),

    #[display(fmt = "Cannot set up HTTPS: {}", _0)]
    HttpsSetup(String),

    #[display(fmt = "HTTP client error: {}", _0)]
    HttpClientError(httpclient::Error),

    //-----------------------------------------------------------------
    // General API Client Issues
    //-----------------------------------------------------------------
    #[display(fmt = "Invalid JSON: {}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Unknown API method")]
    ApiUnknownMethod,

    #[display(fmt = "Unknown resource")]
    ApiUnknownResource,

    #[display(fmt = "Invalid path argument for handle")]
    ApiInvalidHandle,

    #[display(fmt = "Invalid path argument for seconds")]
    ApiInvalidSeconds,

    #[display(fmt = "POST body exceeds configured limit")]
    PostTooBig,

    #[display(fmt = "POST body cannot be read")]
    PostCannotRead,

    //-----------------------------------------------------------------
    // Repository Issues
    //-----------------------------------------------------------------
    #[display(fmt = "No repository configured for CA")]
    RepoNotSet,

    //-----------------------------------------------------------------
    // Publisher Issues
    //-----------------------------------------------------------------
    #[display(fmt = "Unknown publisher '{}'", _0)]
    PublisherUnknown(PublisherHandle),

    #[display(fmt = "Publishing uri '{}' outside repository uri '{}'", _0, _1)]
    PublisherUriOutsideBase(String, String),

    #[display(fmt = "Publisher uri '{}' must have a trailing slash", _0)]
    PublisherBaseUriNoSlash(String),

    #[display(fmt = "Duplicate publisher '{}'", _0)]
    PublisherDuplicate(PublisherHandle),

    #[display(fmt = "No embedded repository configured")]
    PublisherNoEmbeddedRepo,

    //-----------------------------------------------------------------
    // RFC 8181 (publishing)
    //-----------------------------------------------------------------
    #[display(fmt = "Issue with RFC8181 request: {}", _0)]
    Rfc8181Validation(ValidationError),

    #[display(fmt = "Issue with decoding RFC8181 request: {}", _0)]
    Rfc8181Decode(String),

    #[display(fmt = "{}", _0)]
    Rfc8181MessageError(rfc8181::MessageError),

    #[display(fmt = "{}", _0)]
    Rfc8181Delta(PublicationDeltaError),

    //-----------------------------------------------------------------
    // CA Issues
    //-----------------------------------------------------------------
    #[display(fmt = "CA '{}' was already initialised", _0)]
    CaDuplicate(Handle),
    #[display(fmt = "CA '{}' is unknown", _0)]
    CaUnknown(Handle),

    // CA Repo Issues
    #[display(fmt = "CA '{}' already uses this repository", _0)]
    CaRepoInUse(Handle),

    #[display(
        fmt = "CA '{}' cannot get response from repository '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository",
        _0,
        _1
    )]
    CaRepoIssue(Handle, String),
    #[display(fmt = "CA '{}' got invalid repository response xml: {}", _0, _1)]
    CaRepoResponseInvalidXml(Handle, String),
    #[display(fmt = "CA '{}' got parent instead of repository response", _0)]
    CaRepoResponseWrongXml(Handle),

    // CA Parent Issues
    #[display(fmt = "CA '{}' already has a parent named '{}'", _0, _1)]
    CaParentDuplicate(Handle, ParentHandle),

    #[display(fmt = "CA '{}' does not have a parent named '{}'", _0, _1)]
    CaParentUnknown(Handle, ParentHandle),

    #[display(fmt = "CA '{}' got error from parent '{}': {}", _0, _1, _2)]
    CaParentIssue(Handle, ParentHandle, String),

    #[display(fmt = "CA '{}' got invalid parent response xml: {}", _0, _1)]
    CaParentResponseInvalidXml(Handle, String),

    #[display(fmt = "CA '{}' got repository response when adding parent", _0)]
    CaParentResponseWrongXml(Handle),

    #[display(
        fmt = "CA '{}' cannot get response from parent '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository",
        _0,
        _1
    )]
    CaParentAddNotResponsive(Handle, ParentHandle),

    //-----------------------------------------------------------------
    // RFC6492 (requesting resources)
    //-----------------------------------------------------------------
    #[display(fmt = "RFC 6492 Issue: {}", _0)]
    Rfc6492(rfc6492::Error),

    #[display(fmt = "Invalid CSR received: {}", _0)]
    Rfc6492InvalidCsrSent(String),

    #[display(fmt = "Invalidly signed RFC 6492 CMS")]
    Rfc6492SignatureInvalid,

    // CA Child Issues
    #[display(fmt = "CA '{}' already has a child named '{}'", _0, _1)]
    CaChildDuplicate(Handle, ChildHandle),

    #[display(fmt = "CA '{}' does not have a child named '{}'", _0, _1)]
    CaChildUnknown(Handle, ChildHandle),

    #[display(fmt = "Child '{}' for CA '{}' MUST have resources specified", _1, _0)]
    CaChildMustHaveResources(Handle, ChildHandle),

    #[display(fmt = "Child '{}' cannot have resources not held by CA '{}'", _1, _0)]
    CaChildExtraResources(Handle, ChildHandle),

    #[display(fmt = "CA '{}' does not know id certificate for child '{}'", _0, _1)]
    CaChildUnauthorized(Handle, ChildHandle),

    #[display(
        fmt = "You can only update one aspect for child '{}' of CA '{}' at a time - i.e. either resources or ID cert",
        _1,
        _0
    )]
    CaChildUpdateOneThing(Handle, ChildHandle),

    // RouteAuthorizations - ROAs
    #[display(fmt = "Cannot remove unknown ROA '{}'", _1)]
    CaAuthorizationUnknown(Handle, RouteAuthorization),

    #[display(fmt = "ROA '{}' already present", _1)]
    CaAuthorizationDuplicate(Handle, RouteAuthorization),

    #[display(fmt = "ROA '{}' was not added because it is redundant", _1)]
    CaAuthorizationRedundant(Handle, RouteAuthorization),

    #[display(
        fmt = "ROA '{}' was not added because it would make existing ROAs redundant",
        _1
    )]
    CaAuthorizationIncludes(Handle, RouteAuthorization),

    #[display(fmt = "Invalid max length in ROA: '{}'", _1)]
    CaAuthorizationInvalidMaxlength(Handle, RouteAuthorization),

    #[display(fmt = "Prefix in ROA '{}' not held by you", _1)]
    CaAuthorizationNotEntitled(Handle, RouteAuthorization),

    //-----------------------------------------------------------------
    // Key Usage Issues
    //-----------------------------------------------------------------
    #[display(fmt = "Attempt at re-using keys")]
    KeyUseAttemptReuse,

    #[display(fmt = "No new key in resource class")]
    KeyUseNoNewKey,

    #[display(fmt = "No current key in resource class")]
    KeyUseNoCurrentKey,

    #[display(fmt = "No old key in resource class")]
    KeyUseNoOldKey,

    #[display(fmt = "No issued cert matching pub key")]
    KeyUseNoIssuedCert,

    #[display(fmt = "No key found matching key identifier: '{}'", _0)]
    KeyUseNoMatch(KeyIdentifier),

    //-----------------------------------------------------------------
    // Resource Issues
    //-----------------------------------------------------------------
    #[display(fmt = "Unknown resource class: '{}'", _0)]
    ResourceClassUnknown(ResourceClassName),

    #[display(fmt = "{}", _0)]
    ResourceSetError(ResourceSetError),

    #[display(fmt = "Requester is not entitled to all requested resources")]
    MissingResources,

    //-----------------------------------------------------------------
    // Embedded (test) TA issues
    //-----------------------------------------------------------------
    #[display(fmt = "Functionality not supported for Trust Anchor")]
    TaNotAllowed,

    #[display(fmt = "Name reserved for embedded Trust Anchor")]
    TaNameReserved,

    #[display(fmt = "TrustAnchor was already initialised")]
    TaAlreadyInitialised,

    //-----------------------------------------------------------------
    // If we really don't know any more..
    //-----------------------------------------------------------------
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

impl From<tls_keys::Error> for Error {
    fn from(e: tls_keys::Error) -> Self {
        Error::HttpsSetup(e.to_string())
    }
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn invalid_csr(msg: &str) -> Self {
        Error::Rfc6492InvalidCsrSent(msg.to_string())
    }

    pub fn publishing_outside_jail(uri: &uri::Rsync, jail: &uri::Rsync) -> Self {
        Error::PublisherUriOutsideBase(uri.to_string(), jail.to_string())
    }

    pub fn custom(msg: impl fmt::Display) -> Self {
        Error::Custom(msg.to_string())
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
            | Error::CaUnknown(_)
            | Error::CaChildUnknown(_, _)
            | Error::CaParentUnknown(_, _)
            | Error::ApiUnknownResource => StatusCode::NOT_FOUND,

            _ => StatusCode::BAD_REQUEST,
        }
    }

    pub fn to_error_response(&self) -> ErrorResponse {
        match self {
            //-----------------------------------------------------------------
            // System Issues (label: sys-*)
            //-----------------------------------------------------------------

            // internal server error
            Error::IoError(e) => ErrorResponse::new("sys-io", &self).with_cause(e),

            // internal server error
            Error::AggregateStoreError(e) => ErrorResponse::new("sys-store", &self).with_cause(e),

            // internal server error
            Error::SignerError(e) => ErrorResponse::new("sys-signer", &self).with_cause(e),

            // internal server error
            Error::HttpsSetup(e) => ErrorResponse::new("sys-https", &self).with_cause(e),

            // internal server error
            Error::HttpClientError(e) => ErrorResponse::new("sys-http-client", &self).with_cause(e),

            //-----------------------------------------------------------------
            // General API Client Issues (label: api-*)
            //-----------------------------------------------------------------
            Error::JsonError(e) => ErrorResponse::new("api-json", &self).with_cause(e),

            Error::ApiUnknownMethod => ErrorResponse::new("api-unknown-method", &self),

            // NOT FOUND (generic API not found)
            Error::ApiUnknownResource => ErrorResponse::new("api-unknown-resource", &self),

            Error::ApiInvalidHandle => ErrorResponse::new("api-invalid-path-handle", &self),

            Error::ApiInvalidSeconds => ErrorResponse::new("api-invalid-path-seconds", &self),

            Error::PostTooBig => ErrorResponse::new("api-post-body-exceeds-limit", &self),

            Error::PostCannotRead => ErrorResponse::new("api-post-body-cannot-read", &self),

            //-----------------------------------------------------------------
            // Repository Issues (label: repo-*)
            //-----------------------------------------------------------------

            // 2100
            Error::RepoNotSet => ErrorResponse::new("repo-not-set", &self),

            //-----------------------------------------------------------------
            // Publisher Issues (label: pub-*)
            //-----------------------------------------------------------------
            Error::PublisherUnknown(p) => {
                ErrorResponse::new("pub-unknown", &self).with_publisher(p)
            }

            Error::PublisherDuplicate(p) => {
                ErrorResponse::new("pub-duplicate", &self).with_publisher(p)
            }

            Error::PublisherUriOutsideBase(uri, base) => {
                ErrorResponse::new("pub-outside-jail", &self)
                    .with_uri(uri)
                    .with_base_uri(base)
            }

            Error::PublisherBaseUriNoSlash(uri) => {
                ErrorResponse::new("pub-uri-no-slash", &self).with_uri(uri)
            }

            Error::PublisherNoEmbeddedRepo => ErrorResponse::new("pub-no-embedded-repo", &self),

            //-----------------------------------------------------------------
            // RFC 8181
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(e) => {
                ErrorResponse::new("rfc8181-validation", &self).with_cause(e)
            }
            Error::Rfc8181Decode(e) => ErrorResponse::new("rfc8181-decode", &self).with_cause(e),
            Error::Rfc8181MessageError(e) => {
                ErrorResponse::new("rfc8181-protocol-message", &self).with_cause(e)
            }
            Error::Rfc8181Delta(e) => ErrorResponse::new("rfc8181-delta", &self).with_cause(e),

            //-----------------------------------------------------------------
            // CA Issues (label: ca-*)
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => ErrorResponse::new("ca-duplicate", &self).with_ca(ca),

            Error::CaUnknown(ca) => ErrorResponse::new("ca-unknown", &self).with_ca(ca),

            Error::CaRepoInUse(ca) => ErrorResponse::new("ca-repo-same", &self).with_ca(ca),

            Error::CaRepoIssue(ca, err) => ErrorResponse::new("ca-repo-issue", &self)
                .with_ca(ca)
                .with_cause(err),

            Error::CaRepoResponseInvalidXml(ca, err) => {
                ErrorResponse::new("ca-repo-response-invalid-xml", &self)
                    .with_ca(ca)
                    .with_cause(err)
            }

            Error::CaRepoResponseWrongXml(ca) => {
                ErrorResponse::new("ca-repo-response-wrong-xml", &self).with_ca(ca)
            }

            Error::CaParentDuplicate(ca, parent) => {
                ErrorResponse::new("ca-parent-duplicate", &self)
                    .with_ca(ca)
                    .with_parent(parent)
            }

            Error::CaParentUnknown(ca, parent) => ErrorResponse::new("ca-parent-unknown", &self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentIssue(ca, parent, err) => ErrorResponse::new("ca-parent-issue", &self)
                .with_ca(ca)
                .with_parent(parent)
                .with_cause(err),

            Error::CaParentResponseInvalidXml(ca, err) => {
                ErrorResponse::new("ca-parent-response-invalid-xml", &self)
                    .with_ca(ca)
                    .with_cause(err)
            }

            Error::CaParentResponseWrongXml(ca) => {
                ErrorResponse::new("ca-parent-response-wrong-xml", &self).with_ca(ca)
            }

            Error::CaParentAddNotResponsive(ca, parent) => {
                ErrorResponse::new("ca-parent-add-unresponsive", &self)
                    .with_ca(ca)
                    .with_parent(parent)
            }

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources, not on JSON api)
            //-----------------------------------------------------------------
            Error::Rfc6492(e) => ErrorResponse::new("rfc6492-protocol", &self).with_cause(e),
            Error::Rfc6492InvalidCsrSent(e) => {
                ErrorResponse::new("rfc6492-invalid-csr", &self).with_cause(e)
            }
            Error::Rfc6492SignatureInvalid => {
                ErrorResponse::new("rfc6492-invalid-signature", &self)
            }

            // CA Child Issues
            Error::CaChildDuplicate(ca, child) => ErrorResponse::new("ca-child-duplicate", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildUnknown(ca, child) => ErrorResponse::new("ca-child-unknown", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildMustHaveResources(ca, child) => {
                ErrorResponse::new("ca-child-resources-required", &self)
                    .with_ca(ca)
                    .with_child(child)
            }
            Error::CaChildExtraResources(ca, child) => {
                ErrorResponse::new("ca-child-resources-extra", &self)
                    .with_ca(ca)
                    .with_child(child)
            }
            Error::CaChildUnauthorized(ca, child) => {
                ErrorResponse::new("ca-child-unauthorized", &self)
                    .with_ca(ca)
                    .with_child(child)
            }

            Error::CaChildUpdateOneThing(ca, child) => {
                ErrorResponse::new("ca-child-update-one-thing", &self)
                    .with_ca(ca)
                    .with_child(child)
            }

            // RouteAuthorizations
            Error::CaAuthorizationUnknown(ca, auth) => ErrorResponse::new("ca-roa-unknown", &self)
                .with_ca(ca)
                .with_auth(auth),

            Error::CaAuthorizationDuplicate(ca, auth) => {
                ErrorResponse::new("ca-roa-duplicate", &self)
                    .with_ca(ca)
                    .with_auth(auth)
            }

            Error::CaAuthorizationRedundant(ca, auth) => {
                ErrorResponse::new("ca-roa-redundant", &self)
                    .with_ca(ca)
                    .with_auth(auth)
            }

            Error::CaAuthorizationIncludes(ca, auth) => {
                ErrorResponse::new("ca-roa-includes", &self)
                    .with_ca(ca)
                    .with_auth(auth)
            }

            Error::CaAuthorizationInvalidMaxlength(ca, auth) => {
                ErrorResponse::new("ca-roa-invalid-max-length", &self)
                    .with_ca(ca)
                    .with_auth(auth)
            }

            Error::CaAuthorizationNotEntitled(ca, auth) => {
                ErrorResponse::new("ca-roa-not-entitled", &self)
                    .with_ca(ca)
                    .with_auth(auth)
            }

            //-----------------------------------------------------------------
            // Key Usage Issues (key-*)
            //-----------------------------------------------------------------
            Error::KeyUseAttemptReuse => ErrorResponse::new("key-re-use", &self),
            Error::KeyUseNoNewKey => ErrorResponse::new("key-no-new", &self),
            Error::KeyUseNoCurrentKey => ErrorResponse::new("key-no-current", &self),
            Error::KeyUseNoOldKey => ErrorResponse::new("key-no-old", &self),
            Error::KeyUseNoIssuedCert => ErrorResponse::new("key-no-cert", &self),
            Error::KeyUseNoMatch(ki) => {
                ErrorResponse::new("key-no-match", &self).with_key_identifier(ki)
            }

            //-----------------------------------------------------------------
            // Resource Issues (label: rc-*)
            //-----------------------------------------------------------------
            Error::ResourceClassUnknown(name) => {
                ErrorResponse::new("rc-unknown", &self).with_resource_class(name)
            }
            Error::ResourceSetError(e) => ErrorResponse::new("rc-resources", &self).with_cause(e),
            Error::MissingResources => ErrorResponse::new("rc-missing-resources", &self),

            //-----------------------------------------------------------------
            // Embedded (test) TA issues (label: ta-*)
            //-----------------------------------------------------------------
            Error::TaNotAllowed => ErrorResponse::new("ta-not-allowed", &self),
            Error::TaNameReserved => ErrorResponse::new("ta-name-reserved", &self),
            Error::TaAlreadyInitialised => ErrorResponse::new("ta-initialised", &self),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(_msg) => ErrorResponse::new("general-error", &self),
        }
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

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::commons::api::RoaDefinition;
    use crate::commons::remote::id::tests::test_id_certificate;

    use super::*;

    #[test]
    fn error_response_json_regression() {
        let ca = unsafe { Handle::from_str_unsafe("ca") };
        let parent = unsafe { ParentHandle::from_str_unsafe("parent") };
        let child = unsafe { ChildHandle::from_str_unsafe("child") };
        let publisher = unsafe { PublisherHandle::from_str_unsafe("publisher") };

        let auth =
            RouteAuthorization::new(RoaDefinition::from_str("192.168.0.0/16-24 => 64496").unwrap());

        fn verify(expected_json: &str, e: Error) {
            let actual = e.to_error_response();
            let expected: ErrorResponse = serde_json::from_str(expected_json).unwrap();
            assert_eq!(actual, expected);

            // check that serde works too
            let serialized = serde_json::to_string(&actual).unwrap();
            let des = serde_json::from_str(&serialized).unwrap();
            assert_eq!(actual, des);
        }

        //-----------------------------------------------------------------
        // System Issues
        //-----------------------------------------------------------------

        let io_err = io::Error::new(io::ErrorKind::Other, "can't read file");
        verify(
            include_str!("../../test-resources/api/regressions/errors/sys-io.json"),
            Error::IoError(io_err),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/sys-store.json"),
            Error::AggregateStoreError(AggregateStoreError::InitError),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/sys-signer.json"),
            Error::SignerError("signer issue".to_string()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/sys-https.json"),
            Error::HttpsSetup("can't find pem file".to_string()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/sys-http-client.json"),
            Error::HttpClientError(httpclient::Error::Forbidden),
        );

        //-----------------------------------------------------------------
        // General API Client Issues
        //-----------------------------------------------------------------
        let invalid_rsync_json = "\"https://host/module/folder\"";
        let json_err = serde_json::from_str::<uri::Rsync>(invalid_rsync_json)
            .err()
            .unwrap();
        verify(
            include_str!("../../test-resources/api/regressions/errors/api-json.json"),
            Error::JsonError(json_err),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/api-unknown-method.json"),
            Error::ApiUnknownMethod,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/api-unknown-resource.json"),
            Error::ApiUnknownResource,
        );

        //-----------------------------------------------------------------
        // Repository Issues
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/api/regressions/errors/repo-not-set.json"),
            Error::RepoNotSet,
        );

        //-----------------------------------------------------------------
        // Publisher Issues
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/api/regressions/errors/pub-unknown.json"),
            Error::PublisherUnknown(publisher.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/pub-duplicate.json"),
            Error::PublisherDuplicate(publisher),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/pub-outside-jail.json"),
            Error::PublisherUriOutsideBase(
                "rsync://somehost/module/folder".to_string(),
                "rsync://otherhost/module/folder".to_string(),
            ),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/pub-uri-no-slash.json"),
            Error::PublisherBaseUriNoSlash("rsync://host/module/folder".to_string()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/pub-no-embedded-repo.json"),
            Error::PublisherNoEmbeddedRepo,
        );

        //-----------------------------------------------------------------
        // RFC 8181
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/api/regressions/errors/rfc8181-validation.json"),
            Error::Rfc8181Validation(ValidationError),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/rfc8181-decode.json"),
            Error::Rfc8181Decode("could not parse CMS".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/rfc8181-protocol-message.json"
            ),
            Error::Rfc8181MessageError(rfc8181::MessageError::InvalidVersion),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/rfc8181-delta.json"),
            Error::Rfc8181Delta(PublicationDeltaError::ObjectAlreadyPresent(
                uri::Rsync::from_str("rsync://host/module/file.cer").unwrap(),
            )),
        );

        //-----------------------------------------------------------------
        // CA Issues (label: ca-*)
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-duplicate.json"),
            Error::CaDuplicate(ca.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-unknown.json"),
            Error::CaUnknown(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-repo-same.json"),
            Error::CaRepoInUse(ca.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-repo-issue.json"),
            Error::CaRepoIssue(ca.clone(), "cannot connect".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-repo-response-invalid-xml.json"
            ),
            Error::CaRepoResponseInvalidXml(ca.clone(), "expected some tag".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-repo-response-wrong-xml.json"
            ),
            Error::CaRepoResponseWrongXml(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-parent-duplicate.json"),
            Error::CaParentDuplicate(ca.clone(), parent.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-parent-unknown.json"),
            Error::CaParentUnknown(ca.clone(), parent.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-parent-issue.json"),
            Error::CaParentIssue(ca.clone(), parent, "connection refused".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-parent-response-invalid-xml.json"
            ),
            Error::CaParentResponseInvalidXml(ca.clone(), "expected something".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-parent-response-wrong-xml.json"
            ),
            Error::CaParentResponseWrongXml(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/rfc6492-protocol.json"),
            Error::Rfc6492(rfc6492::Error::InvalidVersion),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/rfc6492-invalid-csr.json"),
            Error::Rfc6492InvalidCsrSent("invalid signature".to_string()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/rfc6492-invalid-signature.json"
            ),
            Error::Rfc6492SignatureInvalid,
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-child-duplicate.json"),
            Error::CaChildDuplicate(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-child-unknown.json"),
            Error::CaChildUnknown(ca.clone(), child.clone()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-child-resources-required.json"
            ),
            Error::CaChildMustHaveResources(ca.clone(), child.clone()),
        );
        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-child-resources-extra.json"
            ),
            Error::CaChildExtraResources(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-child-unauthorized.json"),
            Error::CaChildUnauthorized(ca.clone(), child),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-unknown.json"),
            Error::CaAuthorizationUnknown(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-duplicate.json"),
            Error::CaAuthorizationDuplicate(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-redundant.json"),
            Error::CaAuthorizationRedundant(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-includes.json"),
            Error::CaAuthorizationIncludes(ca.clone(), auth),
        );

        verify(
            include_str!(
                "../../test-resources/api/regressions/errors/ca-roa-invalid-max-length.json"
            ),
            Error::CaAuthorizationInvalidMaxlength(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-not-entitled.json"),
            Error::CaAuthorizationNotEntitled(ca, auth),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/key-re-use.json"),
            Error::KeyUseAttemptReuse,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/key-no-new.json"),
            Error::KeyUseNoNewKey,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/key-no-current.json"),
            Error::KeyUseNoCurrentKey,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/key-no-old.json"),
            Error::KeyUseNoOldKey,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/key-no-cert.json"),
            Error::KeyUseNoIssuedCert,
        );
        let ki = test_id_certificate()
            .subject_public_key_info()
            .key_identifier();
        verify(
            include_str!("../../test-resources/api/regressions/errors/key-no-match.json"),
            Error::KeyUseNoMatch(ki),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/rc-unknown.json"),
            Error::ResourceClassUnknown(ResourceClassName::from("RC0")),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/rc-resources.json"),
            Error::ResourceSetError(ResourceSetError::Mix),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/rc-missing-resources.json"),
            Error::MissingResources,
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ta-not-allowed.json"),
            Error::TaNotAllowed,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ta-name-reserved.json"),
            Error::TaNameReserved,
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ta-initialised.json"),
            Error::TaAlreadyInitialised,
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/general-error.json"),
            Error::custom("some unlikely corner case"),
        );

        //        let mut res = String::new();
        //        for e in errs {
        //            let error_response = e.to_error_response();
        //
        //            let path = format!("test-resources/api/regressions/errors/{}.json", error_response.label());
        //            let path = PathBuf::from(&path);
        //
        //            file::save_json(&error_response, &path).unwrap();
        //        }
    }
}
