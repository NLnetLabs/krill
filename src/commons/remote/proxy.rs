use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bcder::encode::Values;
use bcder::{Captured, Mode};

use rpki::crypto::{PublicKeyFormat, Signer};
use rpki::uri;
use rpki::x509::ValidationError;

use crate::commons::api::{
    ErrorCode, ErrorResponse, Handle, ListReply, PublishDelta, PublishRequest,
};
use crate::commons::eventsourcing::{
    Aggregate, AggregateStore, AggregateStoreError, DiskAggregateStore,
};
use crate::commons::util::httpclient;
use crate::commons::util::softsigner::{OpenSslSigner, SignerError};

use super::api::ClientInfo;
use super::builder::{self, IdCertBuilder, SignedMessageBuilder};
use super::clients::{self, ClientManager, ClientsCommand, ClientsCommands, ClientsEvents};
use super::id::{IdCert, MyIdentity, ParentInfo};
use super::responder::{self, Responder, ResponderEvents};
use super::rfc8181::{self, ErrorReply, Message, ReplyMessage, ReportError, ReportErrorCode};
use super::rfc8183::{RepositoryResponse, ServiceUri};
use super::sigmsg::SignedMessage;

#[derive(Clone)]
pub struct ProxyServer {
    signer: OpenSslSigner,
    clients_store: Arc<DiskAggregateStore<ClientManager>>,
    responder_store: Arc<DiskAggregateStore<Responder>>,
}

/// # Server Life Cycle
///
impl ProxyServer {
    /// Initialises the Proxy Server. This will re-use the existing clients and
    /// responder (i.e. server certificate and all), if they exist for this work_dir.
    /// If they do not exist, they will be initialised as well.
    pub fn init(work_dir: &PathBuf) -> Result<Self, Error> {
        let mut signer = OpenSslSigner::build(work_dir)?;
        let clients_store = Arc::new(DiskAggregateStore::<ClientManager>::new(work_dir, "proxy")?);
        let responder_store = Arc::new(DiskAggregateStore::<Responder>::new(work_dir, "proxy")?);

        let clients_id = clients::id();
        if !clients_store.has(&clients_id) {
            clients_store.add(ClientsEvents::init())?;
        }

        let responder_id = responder::id();
        if !responder_store.has(&responder_id) {
            let my_id = Self::new_id(&mut signer)?;
            let init = ResponderEvents::init(my_id);
            responder_store.add(init)?;
        }

        Ok(ProxyServer {
            signer,
            clients_store,
            responder_store,
        })
    }

    fn new_id(signer: &mut OpenSslSigner) -> Result<MyIdentity, Error> {
        let key_id = signer.create_key(PublicKeyFormat::default())?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, signer)?;
        let name = Handle::from_str_unsafe("krill-proxy");
        Ok(MyIdentity::new(name, id_cert, key_id))
    }
}

/// # Manage Clients
///
impl ProxyServer {
    pub fn add_client(&self, request: ClientInfo) -> Result<(), Error> {
        let (handle, client) = request.unwrap();
        let command = ClientsCommands::add(handle, client);
        self.process_clients_command(command)
    }

    pub fn update_client_cert(&self, handle: Handle, cert: IdCert) -> Result<(), Error> {
        let update = ClientsCommands::update_cert(handle, cert);
        self.process_clients_command(update)
    }

    pub fn remove_client(&self, handle: Handle) -> Result<(), Error> {
        let remove = ClientsCommands::remove(handle);
        self.process_clients_command(remove)
    }

    pub fn list_clients(&self) -> Result<Vec<ClientInfo>, Error> {
        Ok(self.clients()?.list())
    }

    pub fn response(
        &self,
        handle: &Handle,
        service_uri: uri::Https,
        sia_base: uri::Rsync,
        rrdp_notification_uri: uri::Https,
    ) -> Result<RepositoryResponse, Error> {
        let tag = None;

        let id_cert = {
            let responder = self.responder_store.get_latest(&responder::id())?;
            responder.id().id_cert().clone()
        };

        let publisher_handle = handle.clone();
        let service_uri = ServiceUri::Https(service_uri);

        Ok(RepositoryResponse::new(
            tag,
            publisher_handle,
            id_cert,
            service_uri,
            sia_base,
            rrdp_notification_uri,
        ))
    }

    fn process_clients_command(&self, command: ClientsCommand) -> Result<(), Error> {
        let clients = self.clients()?;
        let events = clients.process_command(command)?;
        self.clients_store.update(&clients::id(), clients, events)?;

        Ok(())
    }

    fn clients(&self) -> Result<Arc<ClientManager>, Error> {
        self.clients_store
            .get_latest(&clients::id())
            .map_err(Error::StoreError)
    }
}

/// # Proxy RFC8181 requests to a Krill server
///
impl ProxyServer {
    /// Takes an RFC8181 request, validates it, and then returns the
    /// request type
    pub fn convert_rfc8181_req(
        &self,
        msg: SignedMessage,
        handle: &Handle,
    ) -> Result<PublishRequest, Error> {
        self.validate_msg(&msg, handle)?;
        self.convert_to_json_request(&msg)
    }

    /// Wraps a reply in the
    pub fn sign_reply(&self, reply: ReplyMessage) -> Result<Captured, Error> {
        let msg = Message::ReplyMessage(reply);
        self.sign_msg(msg)
    }

    /// Wraps the error into a signed response, unless there is an issue with
    /// building / signing the response itself.
    pub fn wrap_error(&self, e: Error) -> Result<Captured, Error> {
        let error_code = e.to_report_error_code();
        let report_error = ReportError::reply(error_code, None);
        let mut builder = ErrorReply::build_with_capacity(1);
        builder.add(report_error);

        let msg = builder.build_message();

        self.sign_msg(msg)
    }

    fn validate_msg(&self, msg: &SignedMessage, handle: &Handle) -> Result<(), Error> {
        match self.clients()?.client_auth(handle) {
            None => {
                warn!("Received RFC8181 message for unknown client: {}", &handle);
                Err(Error::UnknownClient(handle.clone()))
            }
            Some(client) => {
                let id_cert = client.cert();
                match msg.validate(id_cert) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        warn!("Received invalid message from {}", &handle);
                        Err(Error::ValidationError(e))
                    }
                }
            }
        }
    }

    /// Retrieves the QueryMessage contained in the SignedMessage and
    /// converts into the (json) equivalent request for the API.
    fn convert_to_json_request(&self, msg: &SignedMessage) -> Result<PublishRequest, Error> {
        trace!("Convert contained message to Json equivalent");
        let msg = rfc8181::Message::from_signed_message(&msg)?;
        let msg = msg.into_query()?;
        Ok(msg.into_publish_request())
    }

    fn sign_msg(&self, msg: Message) -> Result<Captured, Error> {
        let responder = self.responder_store.get_latest(&responder::id())?;

        let builder =
            SignedMessageBuilder::create(&responder.id().key_id(), &self.signer, msg.into_bytes())?;

        let enc = builder.encode();

        Ok(enc.to_captured(Mode::Der))
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    StoreError(AggregateStoreError),

    #[display(fmt = "{}", _0)]
    SignerError(SignerError),

    #[display(fmt = "{}", _0)]
    BuilderError(builder::Error<SignerError>),

    #[display(fmt = "{}", _0)]
    ClientsError(clients::Error),

    #[display(fmt = "Unknown client: {}", _0)]
    UnknownClient(Handle),

    #[display(fmt = "No private key known for client: {}", _0)]
    NoPrivateKey(Handle),

    #[display(fmt = "{}", _0)]
    ValidationError(ValidationError),

    #[display(fmt = "{}", _0)]
    Rfc8181MessageError(rfc8181::MessageError),

    #[display(fmt = "{}", _0)]
    HttpClientError(httpclient::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self {
        Error::StoreError(e)
    }
}

impl From<clients::Error> for Error {
    fn from(e: clients::Error) -> Self {
        Error::ClientsError(e)
    }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self {
        Error::SignerError(e)
    }
}

impl From<builder::Error<SignerError>> for Error {
    fn from(e: builder::Error<SignerError>) -> Self {
        Error::BuilderError(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::ValidationError(e)
    }
}

impl From<rfc8181::MessageError> for Error {
    fn from(e: rfc8181::MessageError) -> Self {
        Error::Rfc8181MessageError(e)
    }
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self {
        Error::HttpClientError(e)
    }
}

impl Error {
    fn to_report_error_code(&self) -> ReportErrorCode {
        match self {
            Error::ValidationError(_) => ReportErrorCode::PermissionFailure,
            Error::Rfc8181MessageError(_) => ReportErrorCode::XmlError,
            Error::UnknownClient(_) => ReportErrorCode::PermissionFailure,
            Error::HttpClientError(http_error) => match http_error {
                httpclient::Error::ErrorWithBody(_code, body) => {
                    match serde_json::from_str::<ErrorResponse>(body) {
                        Ok(response) => {
                            let error_nr = response.code();
                            let error_code: ErrorCode = response.into();
                            match error_code {
                                ErrorCode::InvalidPublicationXml => ReportErrorCode::XmlError,
                                ErrorCode::ObjectAlreadyPresent => {
                                    ReportErrorCode::ObjectAlreadyPresent
                                }
                                ErrorCode::NoObjectForHashAndOrUri => {
                                    ReportErrorCode::NoObjectMatchingHash
                                }
                                _ => {
                                    if error_nr > 2000 && error_nr < 3000 {
                                        ReportErrorCode::PermissionFailure
                                    } else {
                                        ReportErrorCode::OtherError
                                    }
                                }
                            }
                        }
                        Err(_) => ReportErrorCode::OtherError,
                    }
                }
                _ => ReportErrorCode::OtherError,
            },
            _ => ReportErrorCode::OtherError,
        }
    }
}

/// This type proxies native Krill requests to a remote RFC compliant server
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientProxy {
    id: MyIdentity,
    parent: ParentInfo,
    work_dir: PathBuf,
}

impl ClientProxy {
    pub fn new(id: MyIdentity, parent: ParentInfo, work_dir: PathBuf) -> Self {
        ClientProxy {
            id,
            parent,
            work_dir,
        }
    }

    pub fn list(&self) -> Result<ListReply, ClientError> {
        let msg = rfc8181::Message::list_query();
        let res = self.proxy_msg(msg)?;
        let reply = res.into_reply()?;
        match reply {
            rfc8181::ReplyMessage::ErrorReply(e) => Err(ClientError::ErrorReply(e)),
            rfc8181::ReplyMessage::SuccessReply => Err(ClientError::UnexpectedReply),
            rfc8181::ReplyMessage::ListReply(list) => Ok(list),
        }
    }

    pub fn delta(&self, delta: PublishDelta) -> Result<(), ClientError> {
        let msg = rfc8181::Message::publish_delta_query(delta);
        let res = self.proxy_msg(msg)?;
        let reply = res.into_reply()?;
        match reply {
            rfc8181::ReplyMessage::ErrorReply(e) => Err(ClientError::ErrorReply(e)),
            rfc8181::ReplyMessage::ListReply(_) => Err(ClientError::UnexpectedReply),
            rfc8181::ReplyMessage::SuccessReply => Ok(()),
        }
    }

    fn proxy_msg(&self, msg: rfc8181::Message) -> Result<rfc8181::Message, ClientError> {
        let signed = self.sign(msg)?.into_bytes();
        let res = httpclient::post_binary(
            &self.parent.service_uri().to_string(),
            &signed,
            "application/rpki-publication",
        )?;

        let res_msg = SignedMessage::decode(res, true)?;
        res_msg.validate(self.parent.id_cert())?;

        rfc8181::Message::from_signed_message(&res_msg).map_err(ClientError::MessageError)
    }

    fn sign(&self, msg: Message) -> Result<Captured, ClientError> {
        let key_id = self.id.key_id();
        let signer = OpenSslSigner::build(&self.work_dir)?;

        let builder = SignedMessageBuilder::create(&key_id, &signer, msg.into_bytes())?;
        let enc = builder.encode();

        Ok(enc.to_captured(Mode::Der))
    }
}

//------------ ClientError ----------------------------------------------------

#[derive(Debug, Display)]
pub enum ClientError {
    #[display(fmt = "{}", _0)]
    HttpError(httpclient::Error),

    #[display(fmt = "{}", _0)]
    DecodeError(bcder::decode::Error),

    #[display(fmt = "{}", _0)]
    ValidationError(ValidationError),

    #[display(fmt = "{}", _0)]
    MessageError(rfc8181::MessageError),

    #[display(fmt = "{}", _0)]
    BuilderError(builder::Error<SignerError>),

    #[display(fmt = "Received error from server: {:?}", _0)]
    ErrorReply(rfc8181::ErrorReply),

    #[display(fmt = "Received unexpected reply (list vs success)")]
    UnexpectedReply,

    #[display(fmt = "{}", _0)]
    SignerError(SignerError),
}

impl From<httpclient::Error> for ClientError {
    fn from(e: httpclient::Error) -> Self {
        ClientError::HttpError(e)
    }
}

impl From<bcder::decode::Error> for ClientError {
    fn from(e: bcder::decode::Error) -> Self {
        ClientError::DecodeError(e)
    }
}

impl From<ValidationError> for ClientError {
    fn from(e: ValidationError) -> Self {
        ClientError::ValidationError(e)
    }
}

impl From<rfc8181::MessageError> for ClientError {
    fn from(e: rfc8181::MessageError) -> Self {
        ClientError::MessageError(e)
    }
}

impl From<builder::Error<SignerError>> for ClientError {
    fn from(e: builder::Error<SignerError>) -> Self {
        ClientError::BuilderError(e)
    }
}

impl From<SignerError> for ClientError {
    fn from(e: SignerError) -> Self {
        ClientError::SignerError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use crate::commons::util::test;

    use super::*;

    #[test]
    fn should_init() {
        test::test_under_tmp(|d| {
            let server = ProxyServer::init(&d).unwrap();

            let add_alice = clients::tests::add_client(&d, "alice");

            server.process_clients_command(add_alice).unwrap();
        });
    }

}
