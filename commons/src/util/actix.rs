//! Support conversions from actix requests to data types in this crate.

use actix_web::FromRequest;
use actix_web::HttpResponse;
use actix_web::dev::MessageBody;
use actix_web::http::StatusCode;
use futures::Future;
use crate::api::admin::PublisherRequest;
use crate::api::admin::PublisherHandle;
use crate::api::publication::PublishDelta;


//------------ PublisherRequest ----------------------------------------------

/// Converts the body sent to 'add publisher' end-points to a
/// PublisherRequestChoice, which contains either an
/// rfc8183::PublisherRequest, or an API publisher request (no ID certs and
/// CMS etc).
impl<S: 'static> FromRequest<S> for PublisherRequest {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                let p: PublisherRequest =
                    serde_json::from_reader(bytes.as_ref())
                        .map_err(Error::JsonError)?;
                Ok(p)
            })
        )
    }
}


//------------ PublisherHandle -----------------------------------------------

impl<S> FromRequest<S> for PublisherHandle {
    type Config = ();
    type Result = Result<Self, actix_web::Error>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        if let Some(handle) = req.match_info().get("handle") {
            Ok(PublisherHandle::from(handle))
        } else {
            Err(Error::InvalidHandle.into())
        }
    }
}


//------------ PublishDelta --------------------------------------------------

/// Support converting request body into PublishDelta
impl<S: 'static> FromRequest<S> for PublishDelta {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(255 * 1024 * 1024) // up to 256MB
            .from_err()
            .and_then(|bytes| {
                let delta: PublishDelta =
                    serde_json::from_reader(bytes.as_ref())?;
                Ok(delta)
            })
        )
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Invalid handle")]
    InvalidHandle,
}

impl std::error::Error for Error {}

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("{}", self))
    }
}
