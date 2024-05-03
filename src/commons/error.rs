//! Defines all Krill server side errors

use std::{fmt, fmt::Display, io};

use hyper::StatusCode;

use rpki::{
    ca::{
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
        provisioning,
        provisioning::ResourceClassName,
        publication,
    },
    crypto::KeyIdentifier,
    repository::error::ValidationError,
    uri,
};

use crate::{
    commons::{
        api::{rrdp::PublicationDeltaError, CustomerAsn, ErrorResponse, RoaPayload},
        crypto::SignerError,
        eventsourcing::{AggregateStoreError, KeyValueError},
        util::httpclient,
    },
    daemon::{ca::RoaPayloadJsonMapKey, http::tls_keys},
    ta,
    upgrades::UpgradeError,
};

use super::{
    api::{BgpSecAsnKey, BgpSecDefinition, RoaConfiguration},
    eventsourcing::WalStoreError,
};

//------------ RoaDeltaError -----------------------------------------------

/// This type contains a detailed error report for a ROA delta
/// that could not be applied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaDeltaError {
    duplicates: Vec<RoaConfiguration>,
    notheld: Vec<RoaConfiguration>,
    unknowns: Vec<RoaPayload>,
    invalid_length: Vec<RoaConfiguration>,
}

impl RoaDeltaError {
    pub fn add_duplicate(&mut self, addition: RoaConfiguration) {
        self.duplicates.push(addition);
    }

    pub fn add_notheld(&mut self, addition: RoaConfiguration) {
        self.notheld.push(addition);
    }

    pub fn add_unknown(&mut self, removal: RoaPayload) {
        self.unknowns.push(removal);
    }

    pub fn add_invalid_length(&mut self, invalid: RoaConfiguration) {
        self.invalid_length.push(invalid);
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

//------------ ApiAuthError ------------------------------------------------

// ApiAuthError is *also* implemented as a separate enum,
// so that we don't have to implement the Clone trait for
// all of the Error enum.
// Also it makes kind of sense to keep these errors separate
// container, since they all originate in interactions
// with the Auth provider (or lack thereof).
#[derive(Debug, Clone)]
pub enum ApiAuthError {
    ApiInvalidCredentials(String),
    ApiLoginError(String),
    ApiAuthPermanentError(String),
    ApiAuthTransientError(String),
    ApiAuthSessionExpired(String),
    ApiInsufficientRights(String),
}

impl Display for ApiAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ApiAuthError::ApiInvalidCredentials(err)
            | ApiAuthError::ApiLoginError(err)
            | ApiAuthError::ApiAuthPermanentError(err)
            | ApiAuthError::ApiAuthTransientError(err)
            | ApiAuthError::ApiAuthSessionExpired(err)
            | ApiAuthError::ApiInsufficientRights(err) => write!(f, "{}", &err),
        }
    }
}

impl From<Error> for ApiAuthError {
    fn from(e: Error) -> Self {
        match e {
            Error::ApiAuthPermanentError(e) => ApiAuthError::ApiAuthPermanentError(e),
            Error::ApiLoginError(e) => ApiAuthError::ApiLoginError(e),
            Error::ApiInsufficientRights(e) => ApiAuthError::ApiInsufficientRights(e),
            Error::ApiAuthTransientError(e) => ApiAuthError::ApiAuthTransientError(e),
            Error::ApiAuthSessionExpired(e) => ApiAuthError::ApiAuthSessionExpired(e),
            Error::ApiInvalidCredentials(e) => ApiAuthError::ApiInvalidCredentials(e),
            _ => ApiAuthError::ApiAuthPermanentError(e.to_string()),
        }
    }
}

//------------ FatalError --------------------------------------------------

/// Wraps an error so horrible to contemplate that it should result in
/// a server crash, as it would have lost its reason to live.
///
/// Note that we do not provide any From<Error> for this in an attempt
/// to ensure that this is only ever used explicitly and when it is
/// appropriate.
#[derive(Debug)]
pub struct FatalError(pub Error);

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//------------ Error -------------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    //-----------------------------------------------------------------
    // System Issues
    //-----------------------------------------------------------------
    IoError(KrillIoError),
    KeyValueError(KeyValueError),
    AggregateStoreError(AggregateStoreError),
    WalStoreError(WalStoreError),
    SignerError(String),
    HttpsSetup(String),
    HttpClientError(httpclient::Error),
    ConfigError(String),
    UpgradeError(UpgradeError),

    //-----------------------------------------------------------------
    // General API Client Issues
    //-----------------------------------------------------------------
    JsonError(serde_json::Error),
    InvalidUtf8Input,
    ApiUnknownMethod,
    ApiUnknownResource,
    ApiInvalidHandle,
    ApiInvalidSeconds,
    PostTooBig,
    PostCannotRead,
    ApiInvalidCredentials(String),
    ApiLoginError(String),
    ApiAuthPermanentError(String),
    ApiAuthTransientError(String),
    ApiAuthSessionExpired(String),
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

    //-----------------------------------------------------------------
    // Repository Server Issues
    //-----------------------------------------------------------------
    RepositoryServerNotInitialized,
    RepositoryServerHasPublishers,
    RepositoryServerAlreadyInitialized,

    //-----------------------------------------------------------------
    // Publishing
    //-----------------------------------------------------------------
    Rfc8181Validation(ValidationError),
    Rfc8181Decode(String),
    Rfc8181(publication::Error),
    Rfc8181Delta(PublicationDeltaError),
    PublishingObjects(String),

    //-----------------------------------------------------------------
    // CA Issues
    //-----------------------------------------------------------------
    CaDuplicate(CaHandle),
    CaUnknown(CaHandle),

    // CA Repo Issues
    CaRepoInUse(CaHandle),
    CaRepoIssue(CaHandle, String),
    CaRepoResponseInvalid(CaHandle, String),
    CaRepoResponseWrongXml(CaHandle),

    // CA Parent Issues
    CaParentDuplicateName(CaHandle, ParentHandle),
    CaParentDuplicateInfo(CaHandle, ParentHandle),
    CaParentUnknown(CaHandle, ParentHandle),
    CaParentIssue(CaHandle, ParentHandle, String),
    CaParentResponseInvalid(CaHandle, String),
    CaParentResponseWrongXml(CaHandle),
    CaParentAddNotResponsive(CaHandle, ParentHandle),
    CaParentSyncError(CaHandle, ParentHandle, ResourceClassName, String),

    //-----------------------------------------------------------------
    // RFC8183 (exchanging id XML)
    //-----------------------------------------------------------------
    Rfc8183(String),

    //-----------------------------------------------------------------
    // RFC6492 (requesting resources)
    //-----------------------------------------------------------------
    Rfc6492(provisioning::Error),
    Rfc6492NotPerformed(provisioning::NotPerformedResponse),
    Rfc6492InvalidCsrSent(String),

    //-----------------------------------------------------------------
    // CA Child Issues
    //-----------------------------------------------------------------
    CaChildDuplicate(CaHandle, ChildHandle),
    CaChildUnknown(CaHandle, ChildHandle),
    CaChildMustHaveResources(CaHandle, ChildHandle),
    CaChildExtraResources(CaHandle, ChildHandle),
    CaChildUnauthorized(CaHandle, ChildHandle),

    //-----------------------------------------------------------------
    // RouteAuthorizations - ROAs
    //-----------------------------------------------------------------
    CaAuthorizationUnknown(CaHandle, RoaPayloadJsonMapKey),
    CaAuthorizationDuplicate(CaHandle, RoaPayloadJsonMapKey),
    CaAuthorizationInvalidMaxLength(CaHandle, RoaPayloadJsonMapKey),
    CaAuthorizationNotEntitled(CaHandle, RoaPayloadJsonMapKey),
    RoaDeltaError(CaHandle, RoaDeltaError),

    //-----------------------------------------------------------------
    // Autonomous System Provider Authorization - ASPA
    //-----------------------------------------------------------------
    AspaCustomerAsNotEntitled(CaHandle, CustomerAsn),
    AspaCustomerAlreadyPresent(CaHandle, CustomerAsn),
    AspaCustomerUnknown(CaHandle, CustomerAsn),
    AspaCustomerAsProvider(CaHandle, CustomerAsn),
    AspaProvidersDuplicates(CaHandle, CustomerAsn),
    AspaProvidersEmpty(CaHandle, CustomerAsn),

    //-----------------------------------------------------------------
    // BGP Sec
    //-----------------------------------------------------------------
    BgpSecDefinitionUnknown(CaHandle, BgpSecAsnKey),
    BgpSecDefinitionInvalidlySigned(CaHandle, BgpSecDefinition, String),
    BgpSecDefinitionNotEntitled(CaHandle, BgpSecAsnKey),

    //-----------------------------------------------------------------
    // Key Usage Issues
    //-----------------------------------------------------------------
    KeyUseAttemptReuse,
    KeyUseNoNewKey,
    KeyUseNoCurrentKey,
    KeyUseNoOldKey,
    KeyUseNoIssuedCert,
    KeyUseNoMatch(KeyIdentifier),
    KeyRollInProgress,
    KeyRollActivatePendingRequests,

    //-----------------------------------------------------------------
    // Resource Issues
    //-----------------------------------------------------------------
    ResourceClassUnknown(ResourceClassName),
    ResourceSetError(String),
    MissingResources,

    //-----------------------------------------------------------------
    // TA issues
    //-----------------------------------------------------------------
    TaNotAllowed,
    TaNameReserved,
    TaNotInitialized,
    TaAlreadyInitialized,
    TaProxyAlreadyHasRepository,
    TaProxyHasNoRepository,
    TaProxyHasNoSigner,
    TaProxyAlreadyHasSigner,
    TaProxyHasNoRequest,
    TaProxyHasRequest,
    TaProxyRequestNonceMismatch(ta::Nonce, ta::Nonce),

    //-----------------------------------------------------------------
    // Resource Tagged Attestation issues
    //-----------------------------------------------------------------
    RtaResourcesNotHeld,

    //-----------------------------------------------------------------
    // If we really don't know any more..
    //-----------------------------------------------------------------
    Custom(String),
    Multiple(Vec<Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            //-----------------------------------------------------------------
            // System Issues
            //-----------------------------------------------------------------
            Error::IoError(e) => write!(f, "I/O error: {}", e),
            Error::KeyValueError(e) => write!(f, "Key/Value error: {}", e),
            Error::AggregateStoreError(e) => write!(f, "Persistence (aggregate store) error: {}", e),
            Error::WalStoreError(e) => write!(f, "Persistence (wal store) error: {}", e),
            Error::SignerError(e) => write!(f, "Signing issue: {}", e),
            Error::HttpsSetup(e) => write!(f, "Cannot set up HTTPS: {}", e),
            Error::HttpClientError(e) => write!(f, "HTTP client error: {}", e),
            Error::ConfigError(e) => write!(f, "Configuration error: {}", e),
            Error::UpgradeError(e) => write!(f, "Could not upgrade Krill: {}", e),

            //-----------------------------------------------------------------
            // General API Client Issues
            //-----------------------------------------------------------------
            Error::JsonError(e) => write!(f,"Invalid JSON: {}", e),
            Error::InvalidUtf8Input => write!(f, "Submitted bytes are invalid UTF8"),
            Error::ApiUnknownMethod => write!(f,"Unknown API method"),
            Error::ApiUnknownResource => write!(f, "Unknown resource"),
            Error::ApiInvalidHandle => write!(f, "Invalid path argument for handle"),
            Error::ApiInvalidSeconds => write!(f, "Invalid path argument for seconds"),
            Error::PostTooBig => write!(f, "POST body exceeds configured limit"),
            Error::PostCannotRead => write!(f, "POST body cannot be read"),
            Error::ApiInvalidCredentials(e) => write!(f, "Invalid credentials: {}", e),
            Error::ApiLoginError(e) => write!(f, "Login error: {}", e),
            Error::ApiAuthPermanentError(e) => write!(f, "Authentication error: {}", e),
            Error::ApiAuthTransientError(e) => write!(f, "Transient authentication error: {}", e),
            Error::ApiAuthSessionExpired(e) => write!(f, "Session expired: {}", e),
            Error::ApiInsufficientRights(e) => write!(f, "Insufficient rights: {}", e),

            //-----------------------------------------------------------------
            // Repository Issues
            //-----------------------------------------------------------------
            Error::RepoNotSet => write!(f, "No repository configured for CA"),


            //-----------------------------------------------------------------
            // Publisher Issues
            //-----------------------------------------------------------------
            Error::PublisherUnknown(pbl) => write!(f, "Unknown publisher '{}'", pbl),
            Error::PublisherUriOutsideBase(uri, jail) => write!(f, "Publishing uri '{}' outside repository uri '{}'", uri, jail),
            Error::PublisherBaseUriNoSlash(uri) => write!(f, "Publisher uri '{}' must have a trailing slash", uri),
            Error::PublisherDuplicate(pbl) => write!(f, "Duplicate publisher '{}'", pbl),

            //-----------------------------------------------------------------
            // Repository Server Issues
            //-----------------------------------------------------------------
            Error::RepositoryServerNotInitialized => write!(f, "Publication Server not initialized, see 'krillc pubserver server init --help'"),
            Error::RepositoryServerHasPublishers => write!(f, "Publication Server cannot be removed, still has publishers"),
            Error::RepositoryServerAlreadyInitialized => write!(f, "Publication Server already initialized"),

            //-----------------------------------------------------------------
            // RFC 8181 (publishing)
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(req) => write!(f, "Issue with RFC8181 request: {}", req),
            Error::Rfc8181Decode(req) => write!(f, "Issue with decoding RFC8181 request: {}", req),
            Error::Rfc8181(e) => e.fmt(f),
            Error::Rfc8181Delta(e) => e.fmt(f),
            Error::PublishingObjects(msg) => write!(f, "Issue generating repository objects: '{}'", msg),


            //-----------------------------------------------------------------
            // CA Issues
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => write!(f, "CA '{}' was already initialized", ca),
            Error::CaUnknown(ca) => write!(f, "CA '{}' is unknown", ca),

            // CA Repo Issues
            Error::CaRepoInUse(ca) => write!(f, "CA '{}' already uses this repository", ca),
            Error::CaRepoIssue(ca, e) => write!(f, "CA '{}' cannot get response from repository '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh \
            re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository", ca,        e),
            Error::CaRepoResponseInvalid(ca, e) => write!(f, "CA '{}' got invalid repository response: {}", ca, e),
            Error::CaRepoResponseWrongXml(ca) => write!(f, "CA '{}' got parent instead of repository response", ca),

            // CA Parent Issues
            Error::CaParentDuplicateName(ca, parent) => write!(f, "CA '{}' already has a parent named '{}'", ca, parent),
            Error::CaParentDuplicateInfo(ca, parent) => write!(f, "CA '{}' already has a parent named '{}' for this XML", ca, parent),
            Error::CaParentUnknown(ca, parent) => write!(f, "CA '{}' does not have a parent named '{}'", ca, parent),
            Error::CaParentIssue(ca, parent, e) => write!(f, "CA '{}' got error from parent '{}': {}", ca, parent, e),
            Error::CaParentResponseInvalid(ca, e) => write!(f, "CA '{}' got invalid parent response: {}", ca, e),
            Error::CaParentResponseWrongXml(ca) => write!(f, "CA '{}' got repository response when adding parent", ca),
            Error::CaParentAddNotResponsive(ca, parent) => write!(f, "CA '{}' cannot get response from parent '{}'. Is the 'service_uri' in the XML reachable? Note that when upgrading Krill you should re-use existing configuration and data. For a fresh re-install of Krill you will need to send XML to all other parties again: parent(s), children, and repository",        ca, parent),
            Error::CaParentSyncError(ca, parent, rcn, error_msg) => {
                write!(
                    f,
                    "CA '{}' could not sync with parent '{}', for resource class '{}', error: {}",
                    ca,
                    parent,
                    rcn,
                    error_msg
                )
            }

            //-----------------------------------------------------------------
            // RFC8183 (exchanging id XML)
            //-----------------------------------------------------------------
            Error::Rfc8183(e) => write!(f, "RFC 8183 XML issue: {}", e),

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources)
            //-----------------------------------------------------------------
            Error::Rfc6492(e) => write!(f, "RFC 6492 Issue: {}", e),
            Error::Rfc6492NotPerformed(not) => write!(f, "RFC 6492 Not Performed: {}", not),
            Error::Rfc6492InvalidCsrSent(e) => write!(f, "Invalid CSR received: {}", e),

            //-----------------------------------------------------------------
            // CA Child Issues
            //-----------------------------------------------------------------
            Error::CaChildDuplicate(ca, child) => write!(f, "CA '{}' already has a child named '{}'", ca, child),
            Error::CaChildUnknown(ca, child) => write!(f, "CA '{}' does not have a child named '{}'", ca, child),
            Error::CaChildMustHaveResources(ca, child) => write!(f, "Child '{}' for CA '{}' MUST have resources specified", child, ca),
            Error::CaChildExtraResources(ca, child) => write!(f, "Child '{}' cannot have resources not held by CA '{}'", child, ca),
            Error::CaChildUnauthorized(ca, child) => write!(f, "CA '{}' does not know id certificate for child '{}'", ca, child),

            //-----------------------------------------------------------------
            // RouteAuthorizations - ROAs
            //-----------------------------------------------------------------
            Error::CaAuthorizationUnknown(_ca, roa) => write!(f, "Cannot remove unknown ROA '{}'", roa),
            Error::CaAuthorizationDuplicate(_ca, roa) => write!(f, "ROA '{}' already present", roa),
            Error::CaAuthorizationInvalidMaxLength(_ca, roa) => write!(f, "Invalid max length in ROA: '{}'", roa),
            Error::CaAuthorizationNotEntitled(_ca, roa) => write!(f, "Prefix in ROA '{}' not held by you", roa),
            Error::RoaDeltaError(_ca, e) => write!(f, "ROA delta rejected:\n\n'{}' ", e),

            //-----------------------------------------------------------------
            // Autonomous System Provider Authorization - ASPAs
            //-----------------------------------------------------------------
            Error::AspaCustomerAsNotEntitled(_ca, asn) => write!(f, "Customer AS '{}' is not held by you", asn),
            Error::AspaCustomerAlreadyPresent(_ca, asn) => write!(f, "ASPA already exists for customer AS '{}'", asn),
            Error::AspaProvidersEmpty(_ca, asn) => write!(f, "ASPA for customer AS '{}' requires at least one provider", asn),
            Error::AspaCustomerAsProvider(_ca, asn) => write!(f, "ASPA for customer AS '{}' cannot have that AS as provider", asn),
            Error::AspaProvidersDuplicates(_ca, asn) => write!(f, "ASPA for customer AS '{}' cannot have duplicate providers", asn),
            Error::AspaCustomerUnknown(_ca, asn) => write!(f, "No current ASPA exists for customer AS '{}'", asn),

            //-----------------------------------------------------------------
            // BGPSec
            //-----------------------------------------------------------------
            Error::BgpSecDefinitionUnknown(_ca, key) => write!(f, "Cannot remove BGPSec CSR for unknown combination of ASN '{}' and key '{}'", key.asn(), key.key_identifier()),
            Error::BgpSecDefinitionInvalidlySigned(_ca, def, msg) => write!(f, "Invalidly signed BGPSec CSR remove BGPSec CSR for ASN '{}' and key '{}', error: {}", def.asn(), def.csr().public_key().key_identifier(), msg),
            Error::BgpSecDefinitionNotEntitled(_ca, key) => write!(f, "AS '{}' is not held by you", key.asn()),


            //-----------------------------------------------------------------
            // Key Usage Issues
            //-----------------------------------------------------------------
            Error::KeyUseAttemptReuse => write!(f, "Attempt at re-using keys"),
            Error::KeyUseNoNewKey => write!(f, "No new key in resource class"),
            Error::KeyUseNoCurrentKey => write!(f, "No current key in resource class"),
            Error::KeyUseNoOldKey => write!(f, "No old key in resource class"),
            Error::KeyUseNoIssuedCert => write!(f, "No issued cert matching pub key"),
            Error::KeyUseNoMatch(ki) => write!(f, "No key found matching key identifier: '{}'", ki),
            Error::KeyRollInProgress => write!(f, "Key roll in progress"),
            Error::KeyRollActivatePendingRequests => write!(f, "Cannot activate key while there are still pending requests."),

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
            Error::TaNotInitialized => write!(f, "TrustAnchor was not initialized"),
            Error::TaAlreadyInitialized => write!(f, "TrustAnchor was already initialized"),
            Error::TaProxyAlreadyHasRepository => write!(f, "Trust Anchor Proxy already has repository"),
            Error::TaProxyHasNoRepository => write!(f, "Trust Anchor Proxy has no repository"),
            Error::TaProxyHasNoSigner => write!(f, "Trust Anchor Proxy has no associated signer"),
            Error::TaProxyAlreadyHasSigner => write!(f, "Trust Anchor Proxy already has associated signer"),
            Error::TaProxyHasNoRequest => write!(f, "Trust Anchor Proxy has no signer request"),
            Error::TaProxyHasRequest => write!(f, "Trust Anchor Proxy already has signer request"),
            Error::TaProxyRequestNonceMismatch(rcvd, expected) => write!(f, "Trust Anchor Response nonce '{}' does not match open Request nonce '{}'", rcvd, expected),

            //-----------------------------------------------------------------
            // Resource Tagged Attestation issues
            //-----------------------------------------------------------------
            Error::RtaResourcesNotHeld => write!(f, "Your CA does not hold the requested resources"),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(s) => s.fmt(f),

            Error::Multiple(errors) => {
                let error_strings: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                write!(f, "Multiple errors: {}", error_strings.join(", "))
            }
        }
    }
}

impl From<KrillIoError> for Error {
    fn from(e: KrillIoError) -> Self {
        Error::IoError(e)
    }
}

impl From<KeyValueError> for Error {
    fn from(e: KeyValueError) -> Self {
        Error::KeyValueError(e)
    }
}

impl From<kvx::Error> for Error {
    fn from(e: kvx::Error) -> Self {
        Error::KeyValueError(KeyValueError::Inner(e))
    }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self {
        Error::AggregateStoreError(e)
    }
}

impl From<WalStoreError> for Error {
    fn from(e: WalStoreError) -> Self {
        Error::WalStoreError(e)
    }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self {
        Error::SignerError(e.to_string())
    }
}

impl From<provisioning::Error> for Error {
    fn from(e: provisioning::Error) -> Self {
        Error::Rfc6492(e)
    }
}

impl From<publication::Error> for Error {
    fn from(e: publication::Error) -> Self {
        Error::Rfc8181(e)
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

impl From<ApiAuthError> for Error {
    fn from(e: ApiAuthError) -> Self {
        match e {
            ApiAuthError::ApiAuthPermanentError(e) => Error::ApiAuthPermanentError(e),
            ApiAuthError::ApiLoginError(e) => Error::ApiLoginError(e),
            ApiAuthError::ApiInsufficientRights(e) => Error::ApiInsufficientRights(e),
            ApiAuthError::ApiAuthTransientError(e) => Error::ApiAuthTransientError(e),
            ApiAuthError::ApiAuthSessionExpired(e) => Error::ApiAuthSessionExpired(e),
            ApiAuthError::ApiInvalidCredentials(e) => Error::ApiInvalidCredentials(e),
        }
    }
}

impl From<PublicationDeltaError> for Error {
    fn from(e: PublicationDeltaError) -> Self {
        Error::Rfc8181Delta(e)
    }
}

impl From<UpgradeError> for Error {
    fn from(e: UpgradeError) -> Self {
        Error::UpgradeError(e)
    }
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn invalid_csr(msg: impl fmt::Display) -> Self {
        Error::Rfc6492InvalidCsrSent(msg.to_string())
    }

    pub fn publishing_outside_jail(uri: &uri::Rsync, jail: &uri::Rsync) -> Self {
        Error::PublisherUriOutsideBase(uri.to_string(), jail.to_string())
    }

    pub fn publishing(msg: impl fmt::Display) -> Self {
        Error::PublishingObjects(msg.to_string())
    }

    pub fn rfc8183(e: impl Display) -> Self {
        Error::Rfc8183(e.to_string())
    }

    pub fn custom(msg: impl fmt::Display) -> Self {
        Error::Custom(msg.to_string())
    }

    pub fn io_error_with_context(context: String, cause: io::Error) -> Self {
        Error::IoError(KrillIoError::new(context, cause))
    }
}

impl std::error::Error for Error {}

/// Translate an error to an HTTP Status Code
impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            // Most is bad requests by users, so just mapping the things that are not
            Error::IoError(_)
            | Error::SignerError(_)
            | Error::AggregateStoreError(_)
            | Error::WalStoreError(_)
            | Error::PublishingObjects(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::PublisherUnknown(_)
            | Error::CaUnknown(_)
            | Error::CaChildUnknown(_, _)
            | Error::CaParentUnknown(_, _)
            | Error::ApiUnknownResource => StatusCode::NOT_FOUND,

            Error::ApiInvalidCredentials(_)
            | Error::ApiAuthPermanentError(_)
            | Error::ApiAuthTransientError(_)
            | Error::ApiAuthSessionExpired(_)
            | Error::ApiLoginError(_) => StatusCode::UNAUTHORIZED,
            Error::ApiInsufficientRights(_) => StatusCode::FORBIDDEN,

            _ => StatusCode::BAD_REQUEST,
        }
    }

    pub fn to_error_response(&self) -> ErrorResponse {
        match self {
            //-----------------------------------------------------------------
            // System Issues (label: sys-*)
            //-----------------------------------------------------------------

            // internal server error
            Error::IoError(e) => ErrorResponse::new("sys-io", self).with_cause(e),

            // internal server error
            Error::KeyValueError(e) => ErrorResponse::new("sys-kv", self).with_cause(e),

            // internal server error
            Error::AggregateStoreError(e) => ErrorResponse::new("sys-store", self).with_cause(e),

            // internal server error
            Error::WalStoreError(e) => ErrorResponse::new("sys-wal-store", self).with_cause(e),

            // internal server error
            Error::SignerError(e) => ErrorResponse::new("sys-signer", self).with_cause(e),

            // internal server error
            Error::HttpsSetup(e) => ErrorResponse::new("sys-https", self).with_cause(e),

            // internal server error
            Error::HttpClientError(e) => ErrorResponse::new("sys-http-client", self).with_cause(e),

            // internal configuration error
            Error::ConfigError(e) => ErrorResponse::new("sys-config", self).with_cause(e),

            // upgrade error
            Error::UpgradeError(e) => ErrorResponse::new("sys-upgrade", self).with_cause(e),

            //-----------------------------------------------------------------
            // General API Client Issues (label: api-*)
            //-----------------------------------------------------------------
            Error::JsonError(e) => ErrorResponse::new("api-json", self).with_cause(e),

            Error::InvalidUtf8Input => ErrorResponse::new("api-invalid-utf8", self),

            Error::ApiUnknownMethod => ErrorResponse::new("api-unknown-method", self),

            // NOT FOUND (generic API not found)
            Error::ApiUnknownResource => ErrorResponse::new("api-unknown-resource", self),

            Error::ApiInvalidHandle => ErrorResponse::new("api-invalid-path-handle", self),

            Error::ApiInvalidSeconds => ErrorResponse::new("api-invalid-path-seconds", self),

            Error::PostTooBig => ErrorResponse::new("api-post-body-exceeds-limit", self),

            Error::PostCannotRead => ErrorResponse::new("api-post-body-cannot-read", self),

            Error::ApiInvalidCredentials(e) => ErrorResponse::new("api-invalid-credentials", self).with_cause(e),

            Error::ApiLoginError(e) => ErrorResponse::new("api-login-error", self).with_cause(e),

            Error::ApiAuthPermanentError(e) => ErrorResponse::new("api-auth-permanent-error", self).with_cause(e),

            Error::ApiAuthTransientError(e) => ErrorResponse::new("api-auth-transient-error", self).with_cause(e),

            Error::ApiAuthSessionExpired(e) => ErrorResponse::new("api-auth-session-expired", self).with_cause(e),

            Error::ApiInsufficientRights(e) => ErrorResponse::new("api-insufficient-rights", self).with_cause(e),

            //-----------------------------------------------------------------
            // Repository Issues (label: repo-*)
            //-----------------------------------------------------------------

            // 2100
            Error::RepoNotSet => ErrorResponse::new("repo-not-set", self),

            //-----------------------------------------------------------------
            // Publisher Issues (label: pub-*)
            //-----------------------------------------------------------------
            Error::PublisherUnknown(p) => ErrorResponse::new("pub-unknown", self).with_publisher(p),

            Error::PublisherDuplicate(p) => ErrorResponse::new("pub-duplicate", self).with_publisher(p),

            Error::PublisherUriOutsideBase(uri, base) => ErrorResponse::new("pub-outside-jail", self)
                .with_uri(uri)
                .with_base_uri(base),

            Error::PublisherBaseUriNoSlash(uri) => ErrorResponse::new("pub-uri-no-slash", self).with_uri(uri),

            //-----------------------------------------------------------------
            // Repository Server Issues
            //-----------------------------------------------------------------
            Error::RepositoryServerNotInitialized => ErrorResponse::new("pub-repo-not-initialized", self),
            Error::RepositoryServerHasPublishers => ErrorResponse::new("pub-repo-has-publishers", self),
            Error::RepositoryServerAlreadyInitialized => ErrorResponse::new("pub-repo-initialized", self),

            //-----------------------------------------------------------------
            // Publishing
            //-----------------------------------------------------------------
            Error::Rfc8181Validation(e) => ErrorResponse::new("rfc8181-validation", self).with_cause(e),
            Error::Rfc8181Decode(e) => ErrorResponse::new("rfc8181-decode", self).with_cause(e),
            Error::Rfc8181(e) => ErrorResponse::new("rfc8181-protocol-message", self).with_cause(e),
            Error::Rfc8181Delta(e) => ErrorResponse::new("rfc8181-delta", self).with_cause(e),
            Error::PublishingObjects(msg) => {
                ErrorResponse::new("publishing-generate-repository-objects", self).with_cause(msg)
            }

            //-----------------------------------------------------------------
            // CA Issues (label: ca-*)
            //-----------------------------------------------------------------
            Error::CaDuplicate(ca) => ErrorResponse::new("ca-duplicate", self).with_ca(ca),

            Error::CaUnknown(ca) => ErrorResponse::new("ca-unknown", self).with_ca(ca),

            Error::CaRepoInUse(ca) => ErrorResponse::new("ca-repo-same", self).with_ca(ca),

            Error::CaRepoIssue(ca, err) => ErrorResponse::new("ca-repo-issue", self).with_ca(ca).with_cause(err),

            Error::CaRepoResponseInvalid(ca, err) => ErrorResponse::new("ca-repo-response-invalid-xml", self)
                .with_ca(ca)
                .with_cause(err),

            Error::CaRepoResponseWrongXml(ca) => ErrorResponse::new("ca-repo-response-wrong-xml", self).with_ca(ca),

            Error::CaParentDuplicateName(ca, parent) => ErrorResponse::new("ca-parent-duplicate", self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentDuplicateInfo(ca, parent) => ErrorResponse::new("ca-parent-xml-duplicate", self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentUnknown(ca, parent) => ErrorResponse::new("ca-parent-unknown", self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentIssue(ca, parent, err) => ErrorResponse::new("ca-parent-issue", self)
                .with_ca(ca)
                .with_parent(parent)
                .with_cause(err),

            Error::CaParentResponseInvalid(ca, err) => ErrorResponse::new("ca-parent-response-invalid-xml", self)
                .with_ca(ca)
                .with_cause(err),

            Error::CaParentResponseWrongXml(ca) => ErrorResponse::new("ca-parent-response-wrong-xml", self).with_ca(ca),

            Error::CaParentAddNotResponsive(ca, parent) => ErrorResponse::new("ca-parent-add-unresponsive", self)
                .with_ca(ca)
                .with_parent(parent),

            Error::CaParentSyncError(ca, parent, rcn, _errors) => ErrorResponse::new("ca-parent-sync", self)
                .with_ca(ca)
                .with_parent(parent)
                .with_resource_class(rcn),

            //-----------------------------------------------------------------
            // RFC8183 (exchanging id XML)
            //-----------------------------------------------------------------
            Error::Rfc8183(e) => ErrorResponse::new("rfc-8183-xml", self).with_cause(e),

            //-----------------------------------------------------------------
            // RFC6492 (requesting resources, not on JSON api)
            //-----------------------------------------------------------------
            Error::Rfc6492(e) => ErrorResponse::new("rfc6492-protocol", self).with_cause(e),
            Error::Rfc6492NotPerformed(e) => ErrorResponse::new("rfc6492-not-performed-response", self).with_cause(e),
            Error::Rfc6492InvalidCsrSent(e) => ErrorResponse::new("rfc6492-invalid-csr", self).with_cause(e),

            // CA Child Issues
            Error::CaChildDuplicate(ca, child) => ErrorResponse::new("ca-child-duplicate", self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildUnknown(ca, child) => ErrorResponse::new("ca-child-unknown", self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildMustHaveResources(ca, child) => ErrorResponse::new("ca-child-resources-required", self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildExtraResources(ca, child) => ErrorResponse::new("ca-child-resources-extra", self)
                .with_ca(ca)
                .with_child(child),
            Error::CaChildUnauthorized(ca, child) => ErrorResponse::new("ca-child-unauthorized", self)
                .with_ca(ca)
                .with_child(child),

            // RouteAuthorizations
            Error::CaAuthorizationUnknown(ca, auth) => {
                ErrorResponse::new("ca-roa-unknown", self).with_ca(ca).with_auth(auth)
            }
            Error::CaAuthorizationDuplicate(ca, auth) => {
                ErrorResponse::new("ca-roa-duplicate", self).with_ca(ca).with_auth(auth)
            }

            Error::CaAuthorizationInvalidMaxLength(ca, auth) => ErrorResponse::new("ca-roa-invalid-max-length", self)
                .with_ca(ca)
                .with_auth(auth),

            Error::CaAuthorizationNotEntitled(ca, auth) => ErrorResponse::new("ca-roa-not-entitled", self)
                .with_ca(ca)
                .with_auth(auth),

            Error::RoaDeltaError(ca, roa_delta_error) => ErrorResponse::new("ca-roa-delta-error", self)
                .with_ca(ca)
                .with_roa_delta_error(roa_delta_error),

            //-----------------------------------------------------------------
            // Autonomous System Provider Authorization - ASPA
            //-----------------------------------------------------------------
            Error::AspaCustomerAsNotEntitled(ca, asn) => ErrorResponse::new("ca-aspa-not-entitled", self)
                .with_ca(ca)
                .with_asn(*asn),
            Error::AspaCustomerAlreadyPresent(ca, asn) => ErrorResponse::new("ca-aspa-customer-as-duplicate", self)
                .with_ca(ca)
                .with_asn(*asn),
            Error::AspaProvidersEmpty(ca, asn) => ErrorResponse::new("ca-aspa-provider-as-empty", self)
                .with_ca(ca)
                .with_asn(*asn),
            Error::AspaCustomerAsProvider(ca, asn) => ErrorResponse::new("ca-aspa-customer-as-provider", self)
                .with_ca(ca)
                .with_asn(*asn),
            Error::AspaProvidersDuplicates(ca, asn) => ErrorResponse::new("ca-aspa-provider-duplicates", self)
                .with_ca(ca)
                .with_asn(*asn),
            Error::AspaCustomerUnknown(ca, asn) => ErrorResponse::new("ca-aspa-unknown-customer-as", self)
                .with_ca(ca)
                .with_asn(*asn),

            //-----------------------------------------------------------------
            // BGP Sec
            //-----------------------------------------------------------------
            Error::BgpSecDefinitionUnknown(ca, key) => ErrorResponse::new("ca-bgpsec-unknown", self)
                .with_ca(ca)
                .with_asn(key.asn())
                .with_key_identifier(&key.key_identifier()),
            Error::BgpSecDefinitionInvalidlySigned(ca, def, msg) => {
                ErrorResponse::new("ca-bgpsec-invalidly-signed", self)
                    .with_ca(ca)
                    .with_asn(def.asn())
                    .with_key_identifier(&def.csr().public_key().key_identifier())
                    .with_bgpsec_csr(def.csr())
                    .with_cause(msg)
            }
            Error::BgpSecDefinitionNotEntitled(ca, key) => ErrorResponse::new("ca-bgpsec-not-entitled", self)
                .with_ca(ca)
                .with_asn(key.asn()),

            //-----------------------------------------------------------------
            // Key Usage Issues (key-*)
            //-----------------------------------------------------------------
            Error::KeyUseAttemptReuse => ErrorResponse::new("key-re-use", self),
            Error::KeyUseNoNewKey => ErrorResponse::new("key-no-new", self),
            Error::KeyUseNoCurrentKey => ErrorResponse::new("key-no-current", self),
            Error::KeyUseNoOldKey => ErrorResponse::new("key-no-old", self),
            Error::KeyUseNoIssuedCert => ErrorResponse::new("key-no-cert", self),
            Error::KeyUseNoMatch(ki) => ErrorResponse::new("key-no-match", self).with_key_identifier(ki),
            Error::KeyRollInProgress => ErrorResponse::new("key-roll-disallowed", self),
            Error::KeyRollActivatePendingRequests => ErrorResponse::new("key-roll-pending-requests", self),

            //-----------------------------------------------------------------
            // Resource Issues (label: rc-*)
            //-----------------------------------------------------------------
            Error::ResourceClassUnknown(name) => ErrorResponse::new("rc-unknown", self).with_resource_class(name),
            Error::ResourceSetError(e) => ErrorResponse::new("rc-resources", self).with_cause(e),
            Error::MissingResources => ErrorResponse::new("rc-missing-resources", self),

            //-----------------------------------------------------------------
            // Embedded (test) TA issues (label: ta-*)
            //-----------------------------------------------------------------
            Error::TaNotAllowed => ErrorResponse::new("ta-not-allowed", self),
            Error::TaNameReserved => ErrorResponse::new("ta-name-reserved", self),
            Error::TaNotInitialized => ErrorResponse::new("ta-not-initialized", self),
            Error::TaAlreadyInitialized => ErrorResponse::new("ta-initialized", self),
            Error::TaProxyAlreadyHasRepository => ErrorResponse::new("ta-has-repository", self),
            Error::TaProxyHasNoRepository => ErrorResponse::new("ta-has-no-repository", self),
            Error::TaProxyHasNoSigner => ErrorResponse::new("ta-has-no-signer", self),
            Error::TaProxyAlreadyHasSigner => ErrorResponse::new("ta-has-signer", self),
            Error::TaProxyHasNoRequest => ErrorResponse::new("ta-has-no-signer-req", self),
            Error::TaProxyHasRequest => ErrorResponse::new("ta-has-signer-req", self),
            Error::TaProxyRequestNonceMismatch(_rcvd, _expected) => ErrorResponse::new("ta-proxy-response-nonce", self),

            //-----------------------------------------------------------------
            // Resource Tagged Attestation issues
            //-----------------------------------------------------------------
            Error::RtaResourcesNotHeld => ErrorResponse::new("rta-resources-not-held", self),

            //-----------------------------------------------------------------
            // If we really don't know any more..
            //-----------------------------------------------------------------
            Error::Custom(_msg) => ErrorResponse::new("general-error", self),
            Error::Multiple(_errors) => ErrorResponse::new("multiple-errors", self),
        }
    }

    pub fn to_rfc8181_error_code(&self) -> publication::ReportErrorCode {
        match self {
            Error::Rfc8181Validation(_) | Error::PublisherUnknown(_) => publication::ReportErrorCode::PermissionFailure,
            Error::Rfc8181(_) => publication::ReportErrorCode::XmlError,
            Error::Rfc8181Delta(e) => match e {
                PublicationDeltaError::UriOutsideJail(_, _) => publication::ReportErrorCode::PermissionFailure,
                PublicationDeltaError::NoObjectForHashAndOrUri(_) => publication::ReportErrorCode::NoObjectPresent,
                PublicationDeltaError::ObjectAlreadyPresent(_) => publication::ReportErrorCode::ObjectAlreadyPresent,
            },
            _ => publication::ReportErrorCode::OtherError,
        }
    }
}

#[derive(Debug)]
pub struct KrillIoError {
    context: String,
    cause: io::Error,
}

impl KrillIoError {
    pub fn new(context: String, cause: io::Error) -> Self {
        KrillIoError { context, cause }
    }
}

impl fmt::Display for KrillIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "context: {}, underlying io::Error: {}", self.context, self.cause)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::commons::api::RoaPayload;
    use crate::test::roa_configuration;

    use super::*;
    use crate::test::roa_payload;
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
        let ca = CaHandle::from_str("ca").unwrap();
        let parent = ParentHandle::from_str("parent").unwrap();
        let child = ChildHandle::from_str("child").unwrap();
        let publisher = PublisherHandle::from_str("publisher").unwrap();

        let auth = RoaPayloadJsonMapKey::from(RoaPayload::from_str("192.168.0.0/16-24 => 64496").unwrap());

        //-----------------------------------------------------------------
        // System Issues
        //-----------------------------------------------------------------

        let krill_io_err = KrillIoError::new(
            "Trouble reading 'foo'".to_string(),
            io::Error::new(io::ErrorKind::Other, "can't read file"),
        );

        verify(
            include_str!("../../test-resources/errors/sys-io.json"),
            Error::IoError(krill_io_err),
        );

        verify(
            include_str!("../../test-resources/errors/sys-store.json"),
            Error::AggregateStoreError(AggregateStoreError::InitError(ca.clone())),
        );
        verify(
            include_str!("../../test-resources/errors/sys-signer.json"),
            Error::SignerError("signer issue".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/sys-https.json"),
            Error::HttpsSetup("can't find pem file".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/sys-http-client.json"),
            Error::HttpClientError(httpclient::Error::forbidden("https://example.com/")),
        );

        //-----------------------------------------------------------------
        // General API Client Issues
        //-----------------------------------------------------------------
        let invalid_rsync_json = "\"https://host/module/folder\"";
        let json_err = serde_json::from_str::<uri::Rsync>(invalid_rsync_json).err().unwrap();
        verify(
            include_str!("../../test-resources/errors/api-json.json"),
            Error::JsonError(json_err),
        );
        verify(
            include_str!("../../test-resources/errors/api-unknown-method.json"),
            Error::ApiUnknownMethod,
        );
        verify(
            include_str!("../../test-resources/errors/api-unknown-resource.json"),
            Error::ApiUnknownResource,
        );

        //-----------------------------------------------------------------
        // Repository Issues
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/errors/repo-not-set.json"),
            Error::RepoNotSet,
        );

        //-----------------------------------------------------------------
        // Publisher Issues
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/errors/pub-unknown.json"),
            Error::PublisherUnknown(publisher.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/pub-duplicate.json"),
            Error::PublisherDuplicate(publisher),
        );
        verify(
            include_str!("../../test-resources/errors/pub-outside-jail.json"),
            Error::PublisherUriOutsideBase(
                "rsync://somehost/module/folder".to_string(),
                "rsync://otherhost/module/folder".to_string(),
            ),
        );
        verify(
            include_str!("../../test-resources/errors/pub-uri-no-slash.json"),
            Error::PublisherBaseUriNoSlash("rsync://host/module/folder".to_string()),
        );

        //-----------------------------------------------------------------
        // RFC 8181
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/errors/rfc8181-decode.json"),
            Error::Rfc8181Decode("could not parse CMS".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/rfc8181-protocol-message.json"),
            Error::Rfc8181(publication::Error::InvalidVersion),
        );
        verify(
            include_str!("../../test-resources/errors/rfc8181-delta.json"),
            Error::Rfc8181Delta(PublicationDeltaError::ObjectAlreadyPresent(
                uri::Rsync::from_str("rsync://host/module/file.cer").unwrap(),
            )),
        );

        //-----------------------------------------------------------------
        // CA Issues (label: ca-*)
        //-----------------------------------------------------------------
        verify(
            include_str!("../../test-resources/errors/ca-duplicate.json"),
            Error::CaDuplicate(ca.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-unknown.json"),
            Error::CaUnknown(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/errors/ca-repo-same.json"),
            Error::CaRepoInUse(ca.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-repo-issue.json"),
            Error::CaRepoIssue(ca.clone(), "cannot connect".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-repo-response-invalid-xml.json"),
            Error::CaRepoResponseInvalid(ca.clone(), "expected some tag".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-repo-response-wrong-xml.json"),
            Error::CaRepoResponseWrongXml(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/errors/ca-parent-duplicate.json"),
            Error::CaParentDuplicateName(ca.clone(), parent.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-parent-unknown.json"),
            Error::CaParentUnknown(ca.clone(), parent.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-parent-issue.json"),
            Error::CaParentIssue(ca.clone(), parent, "connection refused".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-parent-response-invalid-xml.json"),
            Error::CaParentResponseInvalid(ca.clone(), "expected something".to_string()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-parent-response-wrong-xml.json"),
            Error::CaParentResponseWrongXml(ca.clone()),
        );

        verify(
            include_str!("../../test-resources/errors/rfc6492-protocol.json"),
            Error::Rfc6492(provisioning::Error::InvalidVersion),
        );
        verify(
            include_str!("../../test-resources/errors/rfc6492-invalid-csr.json"),
            Error::Rfc6492InvalidCsrSent("invalid signature".to_string()),
        );

        verify(
            include_str!("../../test-resources/errors/ca-child-duplicate.json"),
            Error::CaChildDuplicate(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-child-unknown.json"),
            Error::CaChildUnknown(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-child-resources-required.json"),
            Error::CaChildMustHaveResources(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-child-resources-extra.json"),
            Error::CaChildExtraResources(ca.clone(), child.clone()),
        );
        verify(
            include_str!("../../test-resources/errors/ca-child-unauthorized.json"),
            Error::CaChildUnauthorized(ca.clone(), child),
        );

        verify(
            include_str!("../../test-resources/errors/ca-roa-unknown.json"),
            Error::CaAuthorizationUnknown(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/errors/ca-roa-duplicate.json"),
            Error::CaAuthorizationDuplicate(ca.clone(), auth),
        );

        verify(
            include_str!("../../test-resources/errors/ca-roa-invalid-max-length.json"),
            Error::CaAuthorizationInvalidMaxLength(ca.clone(), auth),
        );
        verify(
            include_str!("../../test-resources/errors/ca-roa-not-entitled.json"),
            Error::CaAuthorizationNotEntitled(ca, auth),
        );

        verify(
            include_str!("../../test-resources/errors/key-re-use.json"),
            Error::KeyUseAttemptReuse,
        );
        verify(
            include_str!("../../test-resources/errors/key-no-new.json"),
            Error::KeyUseNoNewKey,
        );
        verify(
            include_str!("../../test-resources/errors/key-no-current.json"),
            Error::KeyUseNoCurrentKey,
        );
        verify(
            include_str!("../../test-resources/errors/key-no-old.json"),
            Error::KeyUseNoOldKey,
        );
        verify(
            include_str!("../../test-resources/errors/key-no-cert.json"),
            Error::KeyUseNoIssuedCert,
        );
        let ki = test_id_certificate().subject_public_key_info().key_identifier();
        verify(
            include_str!("../../test-resources/errors/key-no-match.json"),
            Error::KeyUseNoMatch(ki),
        );

        verify(
            include_str!("../../test-resources/errors/rc-unknown.json"),
            Error::ResourceClassUnknown(ResourceClassName::from("RC0")),
        );
        verify(
            include_str!("../../test-resources/errors/rc-missing-resources.json"),
            Error::MissingResources,
        );

        verify(
            include_str!("../../test-resources/errors/ta-not-allowed.json"),
            Error::TaNotAllowed,
        );
        verify(
            include_str!("../../test-resources/errors/ta-name-reserved.json"),
            Error::TaNameReserved,
        );
        verify(
            include_str!("../../test-resources/errors/ta-initialized.json"),
            Error::TaAlreadyInitialized,
        );

        verify(
            include_str!("../../test-resources/errors/general-error.json"),
            Error::custom("some unlikely corner case"),
        );
    }

    #[test]
    fn roa_delta_json() {
        let mut error = RoaDeltaError::default();

        let duplicate = roa_configuration("10.0.0.0/20-24 => 1");
        let not_held = roa_configuration("10.128.0.0/9 => 1");
        let invalid_length = roa_configuration("10.0.1.0/25 => 1");
        let unknown = roa_payload("192.168.0.0/16 => 1");

        error.add_duplicate(duplicate);
        error.add_notheld(not_held);
        error.add_invalid_length(invalid_length);
        error.add_unknown(unknown);

        let ca = CaHandle::from_str("ca").unwrap();

        let error = Error::RoaDeltaError(ca, error);

        verify(
            include_str!("../../test-resources/errors/ca-roa-delta-error.json"),
            error,
        );
    }
}
