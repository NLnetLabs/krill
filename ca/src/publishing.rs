//! Supports publishing signed objects.

use std::io;
use std::path::PathBuf;

use krill_commons::api::admin::{CaHandle, PubServerInfo, PublisherClientRequest};
use krill_commons::api::ca::CurrentObjects;
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
use krill_commons::util::httpclient;

use crate::trustanchor::{
    CaSigner,
    TrustAnchor,
    TrustAnchorEvent,
    TrustAnchorEventDetails
};


//------------ PubClientInit -------------------------------------------------

pub type PubClientInit = StoredEvent<PubClientInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubClientInitDetails(PubServerInfo);

impl PubClientInitDetails {
    pub fn init(
        handle: &CaHandle,
        server_info: PubServerInfo
    ) -> PubClientInit {
        PubClientInit::new(
            handle.as_ref(),
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

    fn apply(&mut self, _event: Self::Event) {
        unimplemented!() // no events to process, yet
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        unimplemented!() // no commands to process, yet
    }
}

impl PubClient {
    pub fn server_info(&self) -> &PubServerInfo {
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
        handle: &CaHandle,
        _current_objects: &CurrentObjects,
        delta: PublishDelta
    ) {
        let client = self.store.get_latest(handle.as_ref()).unwrap();

        match client.server_info() {
            PubServerInfo::KrillServer(service_uri, token) => {
                let service_uri = service_uri.as_str();

                // Note, I could not think of a convenient way to pass down the test
                // context, since there are different threads involved when testing.
                // So, for now, just setting test mode whenever the publication is done
                // at localhost.
                if service_uri.starts_with("https://localhost") {
                    httpclient::TEST_MODE.with(|m| { *m.borrow_mut() = true; });
                }

                let uri = format!("{}publication/{}", service_uri, handle.as_str());

                match httpclient::post_json(&uri, delta, Some(token)) {
                    Err(httpclient::Error::ErrorWithJson(_code, err)) => {
                        if err.code() == 2007 || err.code() == 2008 {
                            // TODO, do full sync!
                            unimplemented!()
                        } else {
                            panic!("{}", err)
                        }
                    },
                    Err(e) => panic!("{}", e),
                    Ok(()) => {}
                }
            }
        }
    }

    pub fn add(&self, req: PublisherClientRequest) -> Result<(), Error> {
        let (handle, info) = req.unwrap();

        let init = PubClientInitDetails::init(&handle, info);
        self.store.add(&handle, init)?;

        Ok(())
    }
}


impl<S: CaSigner> EventListener<TrustAnchor<S>> for PubClients {
    fn listen(&self, ta: &TrustAnchor<S>, event: &TrustAnchorEvent) {
        let handle = CaHandle::from(event.id());
        let current_objects = ta.current_objects();

        match event.details() {
            TrustAnchorEventDetails::Published(delta) => {
                self.publish(&handle, current_objects, delta.objects().clone().into());
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
