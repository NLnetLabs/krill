//! Support for FromRequest for actix
use actix_web::{FromRequest, HttpResponse};
use actix_web::dev::MessageBody;
use actix_web::http::StatusCode;
use bcder::decode;
use futures::Future;
use crate::sigmsg::SignedMessage;
use crate::api::ClientInfo;

impl<S: 'static> FromRequest<S> for ClientInfo {
    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {

        Box::new(MessageBody::new(req)
            .from_err()
            .and_then(|bytes| {
                let info: ClientInfo =
                    serde_json::from_reader(bytes.as_ref())
                        .map_err(FromRequestError::JsonError)?;
                Ok(info)
            })
        )

    }
}

/// Support converting requests into SignedMessage.
///
/// Also allows to use a higher limit to the size of these requests, in this
/// case 256MB (comparison the entire RIPE NCC repository in December 2018
/// amounted to roughly 100MB).
///
/// We may want to lower this and/or make it configurable, or make it
/// depend on which publisher is sending data.
/// struct PublishRequest {
impl<S: 'static> FromRequest<S> for SignedMessage {

    type Config = ();
    type Result = Box<Future<Item=Self, Error=actix_web::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest<S>,
        _cfg: &Self::Config
    ) -> Self::Result {
        Box::new(MessageBody::new(req).limit(255 * 1024 * 1024) // 256 MB
            .from_err()
            .and_then(|bytes| {
                let msg = SignedMessage::decode(bytes, true)
                    .map_err(FromRequestError::DecodeError)?;
                Ok(msg)

            })
        )
    }
}


#[derive(Debug, Display)]
pub enum FromRequestError {
    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Cannot decode request: {}", _0)]
    DecodeError(decode::Error),
}

impl std::error::Error for FromRequestError {}

impl actix_web::ResponseError for FromRequestError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("{}", self))
    }
}