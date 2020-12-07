//! Defines all Krill server side errors

use std::fmt::Display;
use std::{fmt, io};

use hyper::StatusCode;

use rpki::crypto::KeyIdentifier;
use rpki::uri;
use rpki::x509::ValidationError;

use crate::commons::api::rrdp::PublicationDeltaError;
use crate::commons::api::{
    ChildHandle, ErrorResponse, Handle, ParentHandle, PublisherHandle, ResourceClassName, ResourceSetError,
    RoaDefinition,
};
use crate::commons::eventsourcing::{AggregateStoreError, KeyValueError};
use crate::commons::remote::rfc6492;
use crate::commons::remote::rfc6492::NotPerformedResponse;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8181::ReportErrorCode;
use crate::commons::util::httpclient;
use crate::commons::util::softsigner::SignerError;
use crate::daemon::ca::RouteAuthorization;
use crate::daemon::http::tls_keys;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaDeltaError {
    duplicates: Vec<RoaDefinition>,
    notheld: Vec<RoaDefinition>,
    unknowns: Vec<RoaDefinition>,
    invalid_length: Vec<RoaDefinition>,
}

impl Default for RoaDeltaError {
    fn default() -> Self {
        RoaDeltaError {
            duplicates: vec![],
            notheld: vec![],
            unknowns: vec![],
            invalid_length: vec![],
        }
    }
}

impl RoaDeltaError {
    pub fn add_duplicate(&mut self, addition: RoaDefinition) {
        self.duplicates.push(addition);
    }

    pub fn add_notheld(&mut self, addition: RoaDefinition) {
        self.notheld.push(addition);
    }

    pub fn add_unknown(&mut self, removal: RoaDefinition) {
        self.unknowns.push(removal);
    }

    pub fn add_invalid_length(&mut self, invalid: RoaDefinition) {
        self.invalid_length.push(invalid);
    }

    pub fn combine(&mut self, mut other: Self) {
        self.duplicates.append(&mut other.duplicates);
        self.notheld.append(&mut other.notheld);
        self.unknowns.append(&mut other.unknowns);
        self.invalid_length.append(&mut other.invalid_length);
    }

    pub fn is_empty(&self) -> bool {
        self.duplicates.is_empty()
            && self.notheld.is_empty()
            && self.unknowns.is_empty()
            && self.invalid_length.is_empty()
    }
}

impl fmt::Display for RoaDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.duplicates.is_empty() {
            writeln!(f, "Cannot add the following duplicate ROAs:")?;
            for dup in self.duplicates.iter() {
                writeln!(f, "  {}", dup)?;
            }
        }
        if !self.notheld.is_empty() {
            writeln!(
                f,
                "Cannot add the following ROAs with prefixes not on any of your certificates:"
            )?;
            for not in self.notheld.iter() {
                writeln!(f, "  {}", not)?;
            }
        }
        if !self.unknowns.is_empty() {
            writeln!(f, "Cannot remove the following unknown ROAs:")?;
            for unk in self.unknowns.iter() {
                writeln!(f, "  {}", unk)?;
            }
        }
        if !self.invalid_length.is_empty() {
            writeln!(
                f,
                "The following ROAs have a max length which is invalid for the prefix:"
            )?;
            for unk in self.invalid_length.iter() {
                writeln!(f, "  {}", unk)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    //-----------------------------------------------------------------
    // System Issues
    //-----------------------------------------------------------------
    IoError(io::Error),
    KeyValueError(KeyValueError),
    AggregateStoreError(AggregateStoreError),
    SignerError(String),
    HttpsSetup(String),
    HttpClientError(httpclient::Error),
    ConfigError(String),

    //-----------------------------------------------------------------
    // General API Client Issues
    //-----------------------------------------------------------------
    JsonError(serde_json::Error),
    ApiUnknownMethod,
    ApiUnknownResource,
    ApiInvalidHandle,
    ApiInvalidSeconds,
    PostTooBig,
    PostCannotRead,
    ApiMissingCredentials,
    ApiInvalidCredentials,
    ApiInsufficientRights(String),

    //-----------------------------------------------------------------
    // Repository Issues
    //-----------------------------------------------------------------
    RepoNotSet,

    //-----------------------------------------------------------------
    // Publisher Issues
    //-----------------------------------------------------------------
    PublisherUnknown(PublisherHandle),
    PublisherUriOutsideBase(String, String),
    PublisherBaseUriNoSlash(String),
    PublisherDuplicate(PublisherHandle),
    PublisherNoEmbeddedRepo,

    //-----------------------------------------------------------------
    // RFC 8181 (publishing)
    //-----------------------------------------------------------------
    Rfc8181Validation(ValidationError),
    Rfc8181Decode(String),
    Rfc8181MessageError(rfc8181::MessageError),
    Rfc8181Delta(PublicationDeltaError),

    //-----------------------------------------------------------------
    // CA Issues
    //-----------------------------------------------------------------
    CaDuplicate(Handle),
    CaUnknown(Handle),

    // CA Repo Issues
    CaRepoInUse(Handle),
    CaRepoIssue(Handle, String),
    CaRepoResponseInvalidXml(Handle, String),
    CaRepoResponseWrongXml(Handle),

    // CA Parent Issues
    CaParentDuplicateName(Handle, ParentHandle),
    CaParentDuplicateInfo(Handle, ParentHandle),
    CaParentUnknown(Handle, ParentHandle),
    CaParentIssue(Handle, ParentHandle, String),
    CaParentResponseInvalidXml(Handle, String),
    CaParentResponseWrongXml(Handle),
    CaParentAddNotResponsive(Handle, ParentHandle),

    //-----------------------------------------------------------------
    // RFC6492 (requesting resources)
    //-----------------------------------------------------------------
    Rfc6492(rfc6492::Error),
    Rfc6492NotPerformed(NotPerformedResponse),
    Rfc6492InvalidCsrSent(String),
    Rfc6492SignatureInvalid,

    //-----------------------------------------------------------------
    // CA Child Issues
    //-----------------------------------------------------------------
    CaChildDuplicate(Handle, ChildHandle),
    CaChildUnknown(Handle, ChildHandle),
    CaChildMustHaveResources(Handle, ChildHandle),
    CaChildExtraResources(Handle, ChildHandle),
    CaChildUnauthorized(Handle, ChildHandle),
    CaChildUpdateOneThing(Handle, ChildHandle),

    //-----------------------------------------------------------------
    // RouteAuthorizations - ROAs
    //-----------------------------------------------------------------
    CaAuthorizationUnknown(Handle, RouteAuthorization),
    CaAuthorizationDuplicate(Handle, RouteAuthorization),
    CaAuthorizationInvalidMaxlength(Handle, RouteAuthorization),
    CaAuthorizationNotEntitled(Handle, RouteAuthorization),
    RoaDeltaError(RoaDeltaError),

    //-----------------------------------------------------------------
    // Key Usage Issues
    //-----------------------------------------------------------------
    KeyUseAttemptReuse,
    KeyUseNoNewKey,
    KeyUseNoCurrentKey,
    KeyUseNoOldKey,
    KeyUseNoIssuedCert,
    KeyUseNoMatch(KeyIdentifier),

    //-----------------------------------------------------------------
    // Resource Issues
    //-----------------------------------------------------------------
    ResourceClassUnknown(ResourceClassName),
    ResourceSetError(ResourceSetError),
    MissingResources,

    //-----------------------------------------------------------------
    // Embedded (test) TA issues
    //-----------------------------------------------------------------
    TaNotAllowed,
    TaNameReserved,
    TaAlreadyInitialised,

    //-----------------------------------------------------------------
    // Resource Tagged Attestation issues
    //-----------------------------------------------------------------
    RtaResourcesNotHeld,

    //-----------------------------------------------------------------
    // If we really don't know any more..
    //-----------------------------------------------------------------
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            //-----------------------------------------------------------------
            // System Issues
            //-----------------------------------------------------------------
            Error::IoError(e) => write!(f, "I/O error: {}", e),
            Error::KeyValueError(e) => write!(f, "Key/Value error: {}", e),
            Error::AggregateStoreError(e) => write!(f, "Persistence error: {}", e),
            Error::SignerError(e) => write!(f, "Signing issue: {}", e),
            Error::HttpsSetup(e) => write!(f, "Cannot set up HTTPS: {}", e),
            Error::HttpClientError(e) => write!(f, "HTTP client error: {}", e),
            Error::ConfigError(e) => write!(f, "Configuration error: {}", e),

            //-----------------------------------------------------------------
            // General API Client Issues
            //-----------------------------------------------------------------
            Error::JsonError(e) => write!(f,"Invalid JSON: {}", e),
            Error::ApiUnknownMethod => write!(f,"Unknown API method"),
            Error::ApiUnknownResource => write!(f, "Unknown resource"),
            Error::ApiInvalidHandle => write!(f, "Invalid path argument for handle"),
            Error::ApiInvalidSeconds => write!(f, "Invalid path argument for seconds"),
            Error::PostTooBig => write!(f, "POST body exceeds configured limit"),
            Error::PostCannotRead => write!(f, "POST body cannot be read"),
            Error::ApiMissingCredentials => write!(f, "Missing credentials"),
            Error::ApiInvalidCredentials => write!(f, "Invalid credentials"),
            Error::ApiInsufficientRights(e) => write!(f, "Insufficient rights: {}", e),


            //-----------------------------------------------------------------
            // Repository Issues
            //-----------------------------------------------------------------
            Error::RepoNotSet=> write!(f, "No repository configured for CA"),


            //-----------------------------------------------------------------
            // Publisher Issues
            //-----------------------------------------------------------------
            Error::PublisherUnknown(pbl) => write!(f, "Unknown publisher '{}'", pbl),
            Error::PublisherUriOutsideBase(uri, jail) => write!(f, "Publishing uri '{}' outside repository uri '{}'", uri, jail),
            Error::PublisherBaseUriNoSlash(uri) => write!(f, "Publisher uri '{}' must have a trailing slash", uri),
            Error::PublisherDuplicate(pbl) => write!(f, "Duplicate publisher '{}'", pbl),
            Error::PublisherNoEmbeddedRepo => write!(f, "No embedded repository configured"),


            //-----------------------------------------------------------------
            // RFC 8181 (publishing)
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(req) => write!(f, "Issue with RFC8181 request: {}", req),
            Error::Rfc8181Decode(req) => write!(f, "Issue with decoding RFC8181 request: {}", req),
            Error::Rfc8181MessageError(e) => e.fmt(f),
            Error::Rfc8181Delta(e) => e.fmt(f),


            //-----------------------------------------------------------------
            // CA Issues
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => write!(f, "CA '{}' was already initialised", ca),
            Error::CaUnknown(ca) => write!(f, "CA '{}' is unknown", ca),

            // CA Repo Issues
            Error::CaRepoInUse(ca) => write!(f, "CA '{}' already uses this repository", ca),
            Error::CaRepoIssue(ca, e) => write!(f, "CA '{}' cannot get response from repository '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh \
            re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository", ca,        e),
            Error::CaRepoResponseInvalidXml(ca, e) => write!(f, "CA '{}' got invalid repository response xml: {}", ca, e),
            Error::CaRepoResponseWrongXml(ca) => write!(f, "CA '{}' got parent instead of repository response", ca),

            // CA Parent Issues
            Error::CaParentDuplicateName(ca, parent) => write!(f, "CA '{}' already has a parent named '{}'", ca, parent),
            Error::CaParentDuplicateInfo(ca, parent) => write!(f, "CA '{}' already has a parent named '{}' for this XML", ca, parent),
            Error::CaParentUnknown(ca, parent) => write!(f, "CA '{}' does not have a parent named '{}'", ca, parent),
            Error::CaParentIssue(ca, parent, e) => write!(f, "CA '{}' got error from parent '{}': {}", ca, parent, e),
            Error::CaParentResponseInvalidXml(ca, e) => write!(f, "CA '{}' got invalid parent response xml: {}", ca, e),
            Error::CaParentResponseWrongXml(ca) => write!(f, "CA '{}' got repository response when adding parent", ca),
            Error::CaParentAddNotResponsive(ca, parent) => write!(f, "CA '{}' cannot get response from parent '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository",        ca, parent),

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources)
            //-----------------------------------------------------------------
            Error::Rfc6492(e) => write!(f, "RFC 6492 Issue: {}", e),
            Error::Rfc6492NotPerformed(not) => write!(f, "RFC 6492 Not Performed: {}", not),
            Error::Rfc6492InvalidCsrSent(e) => write!(f, "Invalid CSR received: {}", e),
            Error::Rfc6492SignatureInvalid => write!(f, "Invalidly signed RFC 6492 CMS"),

            //-----------------------------------------------------------------
            // CA Child Issues
            //-----------------------------------------------------------------
            Error::CaChildDuplicate(ca, child) => write!(f, "CA '{}' already has a child named '{}'", ca, child),
            Error::CaChildUnknown(ca, child) => write!(f, "CA '{}' does not have a child named '{}'", ca, child),
            Error::CaChildMustHaveResources(ca, child) => write!(f, "Child '{}' for CA '{}' MUST have resources specified", child, ca),
            Error::CaChildExtraResources(ca, child) => write!(f, "Child '{}' cannot have resources not held by CA '{}'", child, ca),
            Error::CaChildUnauthorized(ca, child) => write!(f, "CA '{}' does not know id certificate for child '{}'", ca, child),
            Error::CaChildUpdateOneThing(ca, child) => write!(f, "You can only update one aspect for child '{}' of CA '{}' at a time - i.e. either resources or ID cert", child, ca),

            //-----------------------------------------------------------------
            // RouteAuthorizations - ROAs
            //-----------------------------------------------------------------
            Error::CaAuthorizationUnknown(_ca, roa) => write!(f, "Cannot remove unknown ROA '{}'", roa),
            Error::CaAuthorizationDuplicate(_ca, roa) => write!(f, "ROA '{}' already present", roa),
            Error::CaAuthorizationInvalidMaxlength(_ca, roa) => write!(f, "Invalid max length in ROA: '{}'", roa),
            Error::CaAuthorizationNotEntitled(_ca, roa) => write!(f, "Prefix in ROA '{}' not held by you", roa),
            Error::RoaDeltaError(e) => write!(f, "ROA delta rejected:\n\n'{}' ", e),

            //-----------------------------------------------------------------
            // Key Usage Issues
            //-----------------------------------------------------------------
            Error::KeyUseAttemptReuse => write!(f, "Attempt at re-using keys"),
            Error::KeyUseNoNewKey => write!(f, "No new key in resource class"),
            Error::KeyUseNoCurrentKey => write!(f, "No current key in resource class"),
            Error::KeyUseNoOldKey => write!(f, "No old key in resource class"),
            Error::KeyUseNoIssuedCert => write!(f, "No issued cert matching pub key"),
            Error::KeyUseNoMatch(ki) => write!(f, "No key found matching key identifier: '{}'", ki),

            //-----------------------------------------------------------------
            // Resource Issues
            //-----------------------------------------------------------------
            Error::ResourceClassUnknown(rcn) => write!(f, "Unknown resource class: '{}'", rcn),
            Error::ResourceSetError(e) => e.fmt(f),
            Error::MissingResources => write!(f, "Requester is not entitled to all requested resources"),


            //-----------------------------------------------------------------
            // Embedded (test) TA issues
            //-----------------------------------------------------------------
            Error::TaNotAllowed => write!(f, "Functionality not supported for Trust Anchor"),
            Error::TaNameReserved => write!(f, "Name reserved for embedded Trust Anchor"),
            Error::TaAlreadyInitialised => write!(f, "TrustAnchor was already initialised"),

            //-----------------------------------------------------------------
            // Resource Tagged Attestation issues
            //-----------------------------------------------------------------
            Error::RtaResourcesNotHeld => write!(f, "Your CA does not hold the requested resources"),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(s) => s.fmt(f)
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<KeyValueError> for Error {
    fn from(e: KeyValueError) -> Self {
        Error::KeyValueError(e)
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

impl From<crate::commons::crypto::Error> for Error {
    fn from(e: crate::commons::crypto::Error) -> Self {
        Error::signer(e)
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
            Error::ApiInvalidCredentials
            | Error::ApiInsufficientRights(_) => StatusCode::FORBIDDEN,

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
            Error::KeyValueError(e) => ErrorResponse::new("sys-kv", &self).with_cause(e),

            // internal server error
            Error::AggregateStoreError(e) => ErrorResponse::new("sys-store", &self).with_cause(e),

            // internal server error
            Error::SignerError(e) => ErrorResponse::new("sys-signer", &self).with_cause(e),

            // internal server error
            Error::HttpsSetup(e) => ErrorResponse::new("sys-https", &self).with_cause(e),

            // internal server error
            Error::HttpClientError(e) => ErrorResponse::new("sys-http-client", &self).with_cause(e),

            // internal configuration error
            Error::ConfigError(e) => ErrorResponse::new("sys-config", &self).with_cause(e),

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

            Error::ApiMissingCredentials => ErrorResponse::new("api-missing-credentials", &self),

            Error::ApiInvalidCredentials => ErrorResponse::new("api-invalid-credentials", &self),

            Error::ApiInsufficientRights(e) => ErrorResponse::new("api-insufficient-rights", &self).with_cause(e),

            //-----------------------------------------------------------------
            // Repository Issues (label: repo-*)
            //-----------------------------------------------------------------

            // 2100
            Error::RepoNotSet => ErrorResponse::new("repo-not-set", &self),

            //-----------------------------------------------------------------
            // Publisher Issues (label: pub-*)
            //-----------------------------------------------------------------
            Error::PublisherUnknown(p) => ErrorResponse::new("pub-unknown", &self).with_publisher(p),

            Error::PublisherDuplicate(p) => ErrorResponse::new("pub-duplicate", &self).with_publisher(p),

            Error::PublisherUriOutsideBase(uri, base) => ErrorResponse::new("pub-outside-jail", &self)
                .with_uri(uri)
                .with_base_uri(base),

            Error::PublisherBaseUriNoSlash(uri) => ErrorResponse::new("pub-uri-no-slash", &self).with_uri(uri),

            Error::PublisherNoEmbeddedRepo => ErrorResponse::new("pub-no-embedded-repo", &self),

            //-----------------------------------------------------------------
            // RFC 8181
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(e) => ErrorResponse::new("rfc8181-validation", &self).with_cause(e),
            Error::Rfc8181Decode(e) => ErrorResponse::new("rfc8181-decode", &self).with_cause(e),
            Error::Rfc8181MessageError(e) => ErrorResponse::new("rfc8181-protocol-message", &self).with_cause(e),
            Error::Rfc8181Delta(e) => ErrorResponse::new("rfc8181-delta", &self).with_cause(e),

            //-----------------------------------------------------------------
            // CA Issues (label: ca-*)
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => ErrorResponse::new("ca-duplicate", &self).with_ca(ca),

            Error::CaUnknown(ca) => ErrorResponse::new("ca-unknown", &self).with_ca(ca),

            Error::CaRepoInUse(ca) => ErrorResponse::new("ca-repo-same", &self).with_ca(ca),

            Error::CaRepoIssue(ca, err) => ErrorResponse::new("ca-repo-issue", &self).with_ca(ca).with_cause(err),

            Error::CaRepoResponseInvalidXml(ca, err) => ErrorResponse::new("ca-repo-response-invalid-xml", &self)
                .with_ca(ca)
                .with_cause(err),

            Error::CaRepoResponseWrongXml(ca) => ErrorResponse::new("ca-repo-response-wrong-xml", &self).with_ca(ca),

            Error::CaParentDuplicateName(ca, parent) => ErrorResponse::new("ca-parent-duplicate", &self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentDuplicateInfo(ca, parent) => ErrorResponse::new("ca-parent-xml-duplicate", &self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentUnknown(ca, parent) => ErrorResponse::new("ca-parent-unknown", &self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentIssue(ca, parent, err) => ErrorResponse::new("ca-parent-issue", &self)
                .with_ca(ca)
                .with_parent(parent)
                .with_cause(err),

            Error::CaParentResponseInvalidXml(ca, err) => ErrorResponse::new("ca-parent-response-invalid-xml", &self)
                .with_ca(ca)
                .with_cause(err),

            Error::CaParentResponseWrongXml(ca) => {
                ErrorResponse::new("ca-parent-response-wrong-xml", &self).with_ca(ca)
            }

            Error::CaParentAddNotResponsive(ca, parent) => ErrorResponse::new("ca-parent-add-unresponsive", &self)
                .with_ca(ca)
                .with_parent(parent),

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources, not on JSON api)
            //-----------------------------------------------------------------
            Error::Rfc6492(e) => ErrorResponse::new("rfc6492-protocol", &self).with_cause(e),
            Error::Rfc6492NotPerformed(e) => ErrorResponse::new("rfc6492-not-performed-response", &self).with_cause(e),
            Error::Rfc6492InvalidCsrSent(e) => ErrorResponse::new("rfc6492-invalid-csr", &self).with_cause(e),
            Error::Rfc6492SignatureInvalid => ErrorResponse::new("rfc6492-invalid-signature", &self),

            // CA Child Issues
            Error::CaChildDuplicate(ca, child) => ErrorResponse::new("ca-child-duplicate", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildUnknown(ca, child) => ErrorResponse::new("ca-child-unknown", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildMustHaveResources(ca, child) => ErrorResponse::new("ca-child-resources-required", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildExtraResources(ca, child) => ErrorResponse::new("ca-child-resources-extra", &self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildUnauthorized(ca, child) => ErrorResponse::new("ca-child-unauthorized", &self)
                .with_ca(ca)
                .with_child(child),

            Error::CaChildUpdateOneThing(ca, child) => ErrorResponse::new("ca-child-update-one-thing", &self)
                .with_ca(ca)
                .with_child(child),

            // RouteAuthorizations
            Error::CaAuthorizationUnknown(ca, auth) => {
                ErrorResponse::new("ca-roa-unknown", &self).with_ca(ca).with_auth(auth)
            }

            Error::CaAuthorizationDuplicate(ca, auth) => ErrorResponse::new("ca-roa-duplicate", &self)
                .with_ca(ca)
                .with_auth(auth),

            Error::CaAuthorizationInvalidMaxlength(ca, auth) => ErrorResponse::new("ca-roa-invalid-max-length", &self)
                .with_ca(ca)
                .with_auth(auth),

            Error::CaAuthorizationNotEntitled(ca, auth) => ErrorResponse::new("ca-roa-not-entitled", &self)
                .with_ca(ca)
                .with_auth(auth),

            Error::RoaDeltaError(roa_delta_error) => {
                ErrorResponse::new("ca-roa-delta-error", "Delta rejected, see included json")
                    .with_roa_delta_error(roa_delta_error)
            }

            //-----------------------------------------------------------------
            // Key Usage Issues (key-*)
            //-----------------------------------------------------------------
            Error::KeyUseAttemptReuse => ErrorResponse::new("key-re-use", &self),
            Error::KeyUseNoNewKey => ErrorResponse::new("key-no-new", &self),
            Error::KeyUseNoCurrentKey => ErrorResponse::new("key-no-current", &self),
            Error::KeyUseNoOldKey => ErrorResponse::new("key-no-old", &self),
            Error::KeyUseNoIssuedCert => ErrorResponse::new("key-no-cert", &self),
            Error::KeyUseNoMatch(ki) => ErrorResponse::new("key-no-match", &self).with_key_identifier(ki),

            //-----------------------------------------------------------------
            // Resource Issues (label: rc-*)
            //-----------------------------------------------------------------
            Error::ResourceClassUnknown(name) => ErrorResponse::new("rc-unknown", &self).with_resource_class(name),
            Error::ResourceSetError(e) => ErrorResponse::new("rc-resources", &self).with_cause(e),
            Error::MissingResources => ErrorResponse::new("rc-missing-resources", &self),

            //-----------------------------------------------------------------
            // Embedded (test) TA issues (label: ta-*)
            //-----------------------------------------------------------------
            Error::TaNotAllowed => ErrorResponse::new("ta-not-allowed", &self),
            Error::TaNameReserved => ErrorResponse::new("ta-name-reserved", &self),
            Error::TaAlreadyInitialised => ErrorResponse::new("ta-initialised", &self),

            //-----------------------------------------------------------------
            // Resource Tagged Attestation issues
            //-----------------------------------------------------------------
            Error::RtaResourcesNotHeld => ErrorResponse::new("rta-resources-not-held", &self),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(_msg) => ErrorResponse::new("general-error", &self),
        }
    }

    pub fn to_rfc8181_error_code(&self) -> ReportErrorCode {
        match self {
            Error::Rfc8181Validation(_) | Error::PublisherUnknown(_) => ReportErrorCode::PermissionFailure,
            Error::Rfc8181MessageError(_) => ReportErrorCode::XmlError,
            Error::Rfc8181Delta(e) => match e {
                PublicationDeltaError::UriOutsideJail(_, _) => ReportErrorCode::PermissionFailure,
                PublicationDeltaError::NoObjectForHashAndOrUri(_) => ReportErrorCode::NoObjectPresent,
                PublicationDeltaError::ObjectAlreadyPresent(_) => ReportErrorCode::ObjectAlreadyPresent,
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

    use super::*;
    use crate::test::definition;
    use crate::test::test_id_certificate;

    fn verify(expected_json: &str, e: Error) {
        let actual = e.to_error_response();
        let expected: ErrorResponse = serde_json::from_str(expected_json).unwrap();
        assert_eq!(actual, expected);

        // check that serde works too
        let serialized = serde_json::to_string(&actual).unwrap();
        let des = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, des);
    }

    #[test]
    fn error_response_json_regression() {
        let ca = Handle::from_str("ca").unwrap();
        let parent = ParentHandle::from_str("parent").unwrap();
        let child = ChildHandle::from_str("child").unwrap();
        let publisher = PublisherHandle::from_str("publisher").unwrap();

        let auth = RouteAuthorization::new(RoaDefinition::from_str("192.168.0.0/16-24 => 64496").unwrap());

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
            Error::AggregateStoreError(AggregateStoreError::InitError(ca.clone())),
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
        let json_err = serde_json::from_str::<uri::Rsync>(invalid_rsync_json).err().unwrap();
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
            include_str!("../../test-resources/api/regressions/errors/rfc8181-protocol-message.json"),
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
            include_str!("../../test-resources/api/regressions/errors/ca-repo-response-invalid-xml.json"),
            Error::CaRepoResponseInvalidXml(ca.clone(), "expected some tag".to_string()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-repo-response-wrong-xml.json"),
            Error::CaRepoResponseWrongXml(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-parent-duplicate.json"),
            Error::CaParentDuplicateName(ca.clone(), parent.clone()),
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
            include_str!("../../test-resources/api/regressions/errors/ca-parent-response-invalid-xml.json"),
            Error::CaParentResponseInvalidXml(ca.clone(), "expected something".to_string()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-parent-response-wrong-xml.json"),
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
            include_str!("../../test-resources/api/regressions/errors/rfc6492-invalid-signature.json"),
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
            include_str!("../../test-resources/api/regressions/errors/ca-child-resources-required.json"),
            Error::CaChildMustHaveResources(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-child-resources-extra.json"),
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
            include_str!("../../test-resources/api/regressions/errors/ca-roa-invalid-max-length.json"),
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
        let ki = test_id_certificate().subject_public_key_info().key_identifier();
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
    }

    #[test]
    fn roa_delta_json() {
        let mut error = RoaDeltaError::default();

        let duplicate = definition("10.0.0.0/20-24 => 1");
        let not_held = definition("10.128.0.0/9 => 1");
        let invalid_length = definition("10.0.1.0/25 => 1");
        let unknown = definition("192.168.0.0/16 => 1");

        error.add_duplicate(duplicate);
        error.add_notheld(not_held);
        error.add_invalid_length(invalid_length);
        error.add_unknown(unknown);

        // println!(
        //     "{}",
        //     serde_json::to_string_pretty(&Error::RoaDeltaError(error).to_error_response()).unwrap()
        // );

        verify(
            include_str!("../../test-resources/api/regressions/errors/ca-roa-delta-error.json"),
            Error::RoaDeltaError(error),
        );
    }
}
