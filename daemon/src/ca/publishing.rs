//! Supports publishing signed objects.

use std::io;
use std::path::PathBuf;

use krill_commons::api::admin::{
    Handle,
    PubServerContact,
    PublisherClientRequest
};
use krill_commons::api::ca::AllCurrentObjects;
use krill_commons::api::publication::PublishDelta;
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

use crate::ca::{CertAuth, CaEvt, CaEvtDet};
use crate::ca::signing::CaSigner;



//------------ PubClientInit -------------------------------------------------

pub type PubClientInit = StoredEvent<PubClientInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClientInitDetails(PubServerContact);

impl PubClientInitDetails {
    pub fn init(
        handle: &Handle,
        server_info: PubServerContact
    ) -> PubClientInit {
        PubClientInit::new(
            handle,
            0,
            PubClientInitDetails(server_info)
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
    handle: Handle,
    version: u64,
    server: PubServerContact
}

impl Aggregate for PubClient {
    type Command = PubClientCommand;
    type Event = PubClientEvent;
    type InitEvent = PubClientInit;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unwrap();
        let version = 1;
        let server = details.0;

        Ok (PubClient { handle, version, server })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, _event: Self::Event) {
        unimplemented!() // no events to process, yet
    }

    fn process_command(
        &self,
        _command: Self::Command
    ) -> Result<Vec<Self::Event>, Self::Error> {
        unimplemented!() // no commands to process, yet
    }
}

impl PubClient {
    pub fn server_info(&self) -> &PubServerContact {
        &self.server
    }
}


//------------ PubClients ----------------------------------------------------

pub struct PubClients {
    store: DiskAggregateStore<PubClient>
}

impl PubClients {
    pub fn build(work_dir: &PathBuf) -> Result<Self, Error> {
        let store = DiskAggregateStore::<PubClient>::new(work_dir, "pub_clients")?;
        Ok(PubClients { store })
    }

    fn publish(
        &self,
        handle: &Handle,
        _current_objects: AllCurrentObjects,
        _delta: PublishDelta
    ) {
        let client = self.store.get_latest(handle).unwrap();

        match client.server_info() {
            PubServerContact::KrillServer(_uri, _token) => {
                error!("Remote publication not implemented")
//                let uri = format!("{}publication/{}", service_uri, handle);
//                let token = token.clone();
//                let handle = handle.clone();
//
//                thread::spawn(move ||{
//                    match httpclient::post_json(&uri, delta, Some(&token)) {
//                        Err(httpclient::Error::ErrorWithJson(_code, err)) => {
//                            let err: ErrorCode = err.into();
//                            if err == ErrorCode::ObjectAlreadyPresent ||
//                               err == ErrorCode::NoObjectForHashAndOrUri {
//                                unimplemented!("https://github.com/NLnetLabs/krill/issues/42")
//                            } else {
//                                error!("{}", err)
//                            }
//                        },
//                        Err(e) => error!("{}", e),
//                        Ok(()) => info!("PubClients: published for {}", handle)
//                    }
//                });

            },
            PubServerContact::Embedded => {
                error!("Embedded publication not implemented")
            }
        }
    }

    pub fn add(&self, req: PublisherClientRequest) -> Result<(), Error> {
        let (handle, info) = req.unwrap();

        let init = PubClientInitDetails::init(&handle, info);
        self.store.add(init)?;

        Ok(())
    }
}


/// Implement listening for CertAuth Published events.
impl<S: CaSigner> EventListener<CertAuth<S>> for PubClients {
    fn listen(&self, ca: &CertAuth<S>, event: &CaEvt) {

        if let Some(delta) = match event.details() {
            CaEvtDet::Published(_,_,_, delta) => Some(delta),
            CaEvtDet::TaPublished(delta) => Some(delta),
            _ => None
        } {
            debug!("Pubclients: publishing for {}", event.handle());

            let current_objects = ca.current_objects();
            self.publish(
                event.handle(),
                current_objects,
                delta.objects().clone().into()
            );
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
