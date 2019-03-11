use rpki::uri;
use crate::api::publication_data;
use crate::api::publisher_data::{
    CmsAuthData,
    PublisherHandle,
    PublisherRequest
};
use crate::api::repo_data::{
    CurrentObjects,
    DeltaElements,
    VerificationError
};
use crate::eventsourcing::{
    Aggregate,
    CommandDetails,
    StoredEvent,
    SentCommand
};
use crate::util::ext_serde;


//------------ PublisherInit -------------------------------------------------

pub type PublisherInit = StoredEvent<InitPublisherDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub struct InitPublisherDetails {
    token: String,

    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: uri::Rsync,
    cms_auth_data: Option<CmsAuthData>
}

impl PublisherInit {
    pub fn init(
        id: &PublisherHandle,
        token: String,
        base_uri: uri::Rsync,
        cms_auth_data: Option<CmsAuthData>
    ) -> Self {
        StoredEvent::new(
            id.as_ref(),
            0,
            InitPublisherDetails { token, base_uri, cms_auth_data }
        )
    }
}

impl From<PublisherRequest> for PublisherInit {
    fn from(req: PublisherRequest) -> Self {
        let (handle, token, base_uri, cms_auth_data) = req.unwrap(); // (self
        let handle = PublisherHandle::from(handle);
        let details = InitPublisherDetails { token, base_uri, cms_auth_data };
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

impl PublisherEvent {
    pub fn deactivated(id: &PublisherHandle, version: u64) -> Self {
        PublisherEvent::new(id.as_ref(), version, PublisherEventDetails::Deactivated)
    }

    pub fn published(
        id: &PublisherHandle,
        version: u64,
        delta: DeltaElements
    ) -> Self {
        PublisherEvent::new(id.as_ref(), version, PublisherEventDetails::Published(delta))
    }
}


//------------ PublisherCommand ----------------------------------------------

pub type PublisherCommand = SentCommand<PublisherCommandDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub enum PublisherCommandDetails {
    Deactivate,
    Publish(publication_data::PublishDelta)
}

impl CommandDetails for PublisherCommandDetails {
    type Event = PublisherEvent;
}

impl PublisherCommand {
    pub fn deactivate(id: &PublisherHandle) -> Self {
        PublisherCommand::new(id.as_ref(), None, PublisherCommandDetails::Deactivate)
    }

    pub fn publish(id: &PublisherHandle, delta: publication_data::PublishDelta) -> Self {
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

    /// The optional RFC8181 identity, for the RFC8183 pub protocol.
    cms_auth_data: Option<CmsAuthData>,

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

    pub fn cms_auth_data(&self) -> &Option<CmsAuthData> {
        &self.cms_auth_data
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
            cms_auth_data:   init.cms_auth_data,
            current_objects: CurrentObjects::default()
        }
    }

    fn deactivate(&self) -> Result<Vec<PublisherEvent>, PublisherError> {
        if self.deactivated {
            Err(PublisherError::Deactivated)
        } else {
            let e = PublisherEvent::deactivated(&self.id, self.version);
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
    pub fn list_current(&self) -> publication_data::ListReply {
        self.current_objects.to_list_reply()
    }

    /// Verifies a delta command and returns an event containing the delta,
    /// provided that it's legitimate.
    fn process_delta_cmd(
        &self,
        delta: publication_data::PublishDelta
    ) -> Result<Vec<PublisherEvent>, PublisherError> {

        let delta = DeltaElements::from(delta);
        self.current_objects.verify_delta(&delta, &self.base_uri)?;

        Ok(vec![PublisherEvent::published(&self.id, self.version, delta)])
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
