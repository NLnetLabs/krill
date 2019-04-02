use rpki::uri;
use krill_commons::api::publication;
use krill_commons::api::publishers::{
    PublisherDetails,
    PublisherHandle,
    PublisherRequest,
};
use krill_commons::api::rrdp::{
    CurrentObjects,
    DeltaElements,
    VerificationError
};
use krill_commons::eventsourcing::{Aggregate, CommandDetails, StoredEvent, SentCommand};
use krill_commons::util::ext_serde;


//------------ PublisherInit -------------------------------------------------

pub type PublisherInit = StoredEvent<InitPublisherDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub struct InitPublisherDetails {
    token: String,

    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: uri::Rsync,
}

impl InitPublisherDetails {
    pub fn for_request(req: PublisherRequest) -> PublisherInit {
        let (handle, token, base_uri) = req.unwrap(); // (self
        let handle = PublisherHandle::from(handle);
        let details = InitPublisherDetails { token, base_uri };
        StoredEvent::new(handle.as_ref(), 0, details)
    }
}


//------------ PublisherEvent ------------------------------------------------

pub type PublisherEvent = StoredEvent<PublisherEventDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub enum PublisherEventDetails {
    Deactivated,
    Published(DeltaElements)
}

impl PublisherEventDetails {
    pub fn deactivated(id: &PublisherHandle, version: u64) -> PublisherEvent {
        PublisherEvent::new(id.as_ref(), version, PublisherEventDetails::Deactivated)
    }

    pub fn published(id: &PublisherHandle, version: u64, delta: DeltaElements) -> PublisherEvent {
        PublisherEvent::new(id.as_ref(), version, PublisherEventDetails::Published(delta))
    }
}


//------------ PublisherCommand ----------------------------------------------

pub type PublisherCommand = SentCommand<PublisherCommandDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub enum PublisherCommandDetails {
    Deactivate,
    Publish(publication::PublishDelta)
}

impl CommandDetails for PublisherCommandDetails {
    type Event = PublisherEvent;
}

impl PublisherCommandDetails {
    pub fn deactivate(id: &PublisherHandle) -> PublisherCommand {
        PublisherCommand::new(id.as_ref(), None, PublisherCommandDetails::Deactivate)
    }

    pub fn publish(id: &PublisherHandle, delta: publication::PublishDelta) -> PublisherCommand {
        PublisherCommand::new(id.as_ref(), None, PublisherCommandDetails::Publish(delta))
    }
}


//------------ PublisherError ------------------------------------------------

#[derive(Clone, Debug, Display)]
pub enum PublisherError {
    #[display(fmt = "Publisher is (already) de-activated")]
    Deactivated,

    #[display(fmt="{}", _0)]
    VerificationError(VerificationError),
}

impl From<VerificationError> for PublisherError {
    fn from(e: VerificationError) -> Self {
        PublisherError::VerificationError(e)
    }
}

impl std::error::Error for PublisherError {}


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publisher {
    /// Aggregate house keeping
    id:          PublisherHandle,
    version:     u64,
    deactivated: bool,

    /// Publication jail for this publisher
    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri:    uri::Rsync,

    /// The token used by the API
    token:         String,

    /// All objects currently published by this publisher, by hash
    current_objects:  CurrentObjects
}

/// # Accessors
impl Publisher {
    pub fn id(&self) -> &PublisherHandle {
        &self.id
    }

    pub fn is_deactivated(&self) -> bool { self.deactivated }

    pub fn token(&self) -> &String {
        &self.token
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }

    pub fn as_api_details(&self) -> PublisherDetails {
        PublisherDetails::new(
            self.id.name(), self.deactivated, &self.base_uri
        )
    }
}

/// # Life cycle
///
impl Publisher {

    fn create(event: PublisherInit) -> Self {
        let (id, _version, init) = event.unwrap();
        Publisher {
            id:              PublisherHandle::from(id),
            version:         1,
            deactivated:         false,
            token:           init.token,
            base_uri:        init.base_uri,
            current_objects: CurrentObjects::default()
        }
    }

    fn deactivate(&self) -> Result<Vec<PublisherEvent>, PublisherError> {
        if self.deactivated {
            Err(PublisherError::Deactivated)
        } else {
            let e = PublisherEventDetails::deactivated(&self.id, self.version);
            Ok(vec![e])
        }
    }
}


/// # Publication protocol
///
impl Publisher {
    /// Gets an owned list reply containing all objects for this publisher.
    /// Note that cloning the uris and hashes is relatively cheap because of
    /// the use of Bytes as the underlying structure. Still, it may be good
    /// to change this implementation in future to return a structure that
    /// takes references, and only lives long enough to compose a response.
    pub fn list_current(&self) -> publication::ListReply {
        self.current_objects.to_list_reply()
    }

    /// Verifies a delta command and returns an event containing the delta,
    /// provided that it's legitimate.
    fn process_delta_cmd(
        &self,
        delta: publication::PublishDelta
    ) -> Result<Vec<PublisherEvent>, PublisherError> {

        let delta = DeltaElements::from(delta);
        self.current_objects.verify_delta(&delta, &self.base_uri)?;

        Ok(vec![PublisherEventDetails::published(&self.id, self.version, delta)])
    }

    fn apply_delta(&mut self, delta: DeltaElements) {
        self.current_objects.apply_delta(delta);
    }
}


impl Aggregate for Publisher {
    type Command = PublisherCommand;
    type Event = PublisherEvent;
    type InitEvent = PublisherInit;
    type Error = PublisherError;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        Ok(Self::create(event))
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        match event.into_details() {
            PublisherEventDetails::Deactivated => self.deactivated = true,
            PublisherEventDetails::Published(delta) => self.apply_delta(delta)
        }
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        match command.into_details() {
            PublisherCommandDetails::Deactivate => self.deactivate(),
            PublisherCommandDetails::Publish(delta) => self.process_delta_cmd(delta)
        }
    }
}
