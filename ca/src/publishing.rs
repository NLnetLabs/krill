//! Supports publishing signed objects.

use std::io;
use std::path::PathBuf;

use rpki::uri;

use krill_commons::api::admin::CaHandle;
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateStore,
    AggregateStoreError,
    CommandDetails,
    DiskAggregateStore,
    Event,
    EventListener,
    SentCommand,
    StoredEvent,
};

use crate::trustanchor::{
    CaSigner,
    TrustAnchor,
    TrustAnchorEvent,
    TrustAnchorEventDetails
};
use krill_commons::api::ca::{CurrentObjects, ObjectsDelta};
use krill_commons::api::publication;


//------------ PubServerInfo -------------------------------------------------

pub type Token = String;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PubServerInfo {
    KrillServer(uri::Https, Token)
}


//------------ PubClientInit -------------------------------------------------

pub type PubClientInit = StoredEvent<PubClientInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClientInitDetails(PubServerInfo);

impl PubClientInitDetails {
    pub fn init_with_krill(
        handle: &CaHandle,
        service_uri: uri::Https,
        token: Token
    ) -> PubClientInit {
        PubClientInit::new(
            handle.as_ref(),
            0,
            PubClientInitDetails(PubServerInfo::KrillServer(service_uri, token))
        )
    }
}


//------------ PubClientEvent ------------------------------------------------

pub type PubClientEvent = StoredEvent<PubClientEventDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClientEventDetails;


//------------ PubClientCommand ----------------------------------------------

pub type PubClientCommand = SentCommand<PubClientCommandDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClientCommandDetails;

impl CommandDetails for PubClientCommandDetails {
    type Event = PubClientEvent;
}



//------------ PubClient -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClient {
    id: CaHandle,
    version: u64,
    server: PubServerInfo
}

impl Aggregate for PubClient {
    type Command = PubClientCommand;
    type Event = PubClientEvent;
    type InitEvent = PubClientInit;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (id, _version, details) = event.unwrap();
        let id = CaHandle::from(id);
        let version = 1;
        let server = details.0;

        Ok (PubClient { id, version, server })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        unimplemented!() // no events to process, yet
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        unimplemented!() // no commands to process, yet
    }
}

impl PubClient {
    pub fn server_info(&self) -> &PubServerInfo {
        &self.server
    }
}


//------------ Listener ------------------------------------------------------

pub struct PublicationListener {
    client_store: DiskAggregateStore<PubClient>
}

impl PublicationListener {
    pub fn build(work_dir: &PathBuf) -> Result<Self, Error> {
        let client_store = DiskAggregateStore::<PubClient>::new(work_dir, "pub_clients")?;
        Ok(PublicationListener { client_store })
    }

    fn publish(
        &self,
        handle: &CaHandle,
        _current_objects: &CurrentObjects,
        _delta: &ObjectsDelta
    ) {
        let client = self.client_store.get_latest(handle.as_ref()).unwrap();

        match client.server_info() {
            PubServerInfo::KrillServer(service_uri, token) => {
                let uri = format!("{}publication/{}", service_uri, handle.as_str());



            }
        }



        unimplemented!()
    }
}


impl<S: CaSigner> EventListener<TrustAnchor<S>> for PublicationListener {
    fn listen(&self, ta: &TrustAnchor<S>, event: &TrustAnchorEvent) {
        let handle = CaHandle::from(event.id());
        let current_objects = ta.current_objects();

        match event.details() {
            TrustAnchorEventDetails::Published(delta) => {
                self.publish(&handle, current_objects, delta.objects());
            },
        }
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum  Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self { Error::AggregateStoreError(e) }
}


impl std::error::Error for Error {}
