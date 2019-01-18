use std::sync::Arc;
use std::path::PathBuf;
use bcder::Captured;
use rpki::uri;
use rpki::x509::ValidationError;
use crate::daemon::api::responses;
use crate::daemon::api::requests::PublishRequest;
use crate::daemon::publishers::Publisher;
use crate::daemon::repo;
use crate::remote::id::IdCert;
use crate::remote::responder;
use crate::remote::responder::Responder;
use crate::remote::rfc8181;
use crate::remote::rfc8183;
use crate::remote::sigmsg::SignedMessage;

/// Proxy that supports the official IETF communication protocols:
/// * RFC8183 Out-of-band Identity Exchanges
/// * RFC8181 Publication Protocol
/// * (in future) RFC6492 Provisioning Protocol
///
/// These protocols are based on having XML messages, wrapped in CMS,
/// signed by Identity Certificates.
///
/// However, things can be simpler. We prefer to use the same semantics as
/// these protocols, but in the form of a JSON REST API over HTTPS, with a
/// shared token (possibly in future something more, like signatures in json).
#[derive(Clone, Debug)]
pub struct CmsProxy {
    // The component that manages server id, and wraps responses to clients
    responder: Responder,

    // The URI that publishers need to access to publish (see config)
    service_uri: uri::Http,
}

/// # Set up
impl CmsProxy {
    pub fn new(
        work_dir: &PathBuf,
        service_uri: &uri::Http
    ) -> Result<Self, Error> {
        let responder = Responder::init(work_dir)?;
        Ok(CmsProxy { responder, service_uri: service_uri.clone() })
    }

    pub fn base_service_uri(&self) -> &uri::Http {
        &self.service_uri
    }
}

/// Handle requests
impl CmsProxy {

    /// Handles an incoming SignedMessage for a publish request, verifies it's
    /// validly signed by a known publisher and processes the QueryMessage
    /// contained. Returns the (json) equivalent request for the API, or
    /// an error if the message did not validate, or could not be decoded.
    pub fn publish_request(
        &mut self,
        msg: &SignedMessage,
        id_cert: &IdCert,
    ) -> Result<PublishRequest, Error> {
        debug!("Validating Signed Message");
        msg.validate(id_cert)?;
        let msg = rfc8181::Message::from_signed_message(&msg)?;
        let msg = msg.as_query()?;
        Ok(msg.as_publish_request())
    }

    /// Handles a PublishReply, and wraps it in an RFC8181 message
    /// in signed CMS
    pub fn wrap_publish_reply(
        &mut self,
        reply: responses::PublishReply
    ) -> Result<Captured, Error> {
        let msg = match reply {
            responses::PublishReply::Success => {
                rfc8181::SuccessReply::build_message()
            },
            responses::PublishReply::List(list) => {
                rfc8181::ListReply::build(&list)
            }
        };

        self.responder.sign_msg(msg).map_err(|e| Error::ResponderError(e))
    }

    /// Converts an error to an RFC8181 response message
    pub fn wrap_error(
        &mut self,
        error: impl ToReportErrorCode
    ) -> Result<Captured, Error> {
        let mut error_builder = rfc8181::ErrorReply::build();
        error_builder.add(
            rfc8181::ReportError::reply(
                error.to_report_error_code(),
                None // Finding the specific PDU is too much hard work.
            )
        );
        let msg = error_builder.build_message();

        self.responder.sign_msg(msg).map_err(|e| Error::ResponderError(e))
    }

    /// Returns an RFC8183 Repository Response
    pub fn repository_response(
        &self,
        publisher: Arc<Publisher>,
        rrdp_notification_uri: uri::Http
    ) -> Result<rfc8183::RepositoryResponse, Error> {
        self.responder
            .repository_response(publisher, rrdp_notification_uri)
            .map_err(|e| Error::ResponderError(e))
    }



}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    ResponderError(responder::Error),

    #[display(fmt="{}", _0)]
    ValidationError(ValidationError),

    #[display(fmt="{}", _0)]
    MessageError(rfc8181::MessageError),
}

impl From<responder::Error> for Error {
    fn from(e: responder::Error) -> Self {
        Error::ResponderError(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::ValidationError(e)
    }
}

impl From<rfc8181::MessageError> for Error {
    fn from(e: rfc8181::MessageError) -> Self {
        Error::MessageError(e)
    }
}


//------------ ToReportErrorCode ---------------------------------------------

pub trait ToReportErrorCode {
    fn to_report_error_code(&self) -> rfc8181::ReportErrorCode;
}

impl ToReportErrorCode for Error {
    fn to_report_error_code(&self) -> rfc8181::ReportErrorCode {
        match self {
            Error::MessageError(e) => e.to_report_error_code(),
            _ => rfc8181::ReportErrorCode::OtherError
        }
    }
}

impl ToReportErrorCode for rfc8181::MessageError {
    fn to_report_error_code(&self) -> rfc8181::ReportErrorCode {
        rfc8181::ReportErrorCode::XmlError
    }
}

impl ToReportErrorCode for repo::Error {
    fn to_report_error_code(&self) -> rfc8181::ReportErrorCode {
        match self {
            repo::Error::ObjectAlreadyPresent(_) =>
                rfc8181::ReportErrorCode::ObjectAlreadyPresent,
            repo::Error::NoObjectPresent(_) =>
                rfc8181::ReportErrorCode::NoObjectPresent,
            repo::Error::NoObjectMatchingHash =>
                rfc8181::ReportErrorCode::NoObjectMatchingHash,
            repo::Error::OutsideBaseUri =>
                rfc8181::ReportErrorCode::PermissionFailure,
            _ => rfc8181::ReportErrorCode::OtherError
        }
    }
}
