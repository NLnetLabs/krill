//! Repository access management.

use std::fmt;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use log::{error, info};
use rpki::ca::publication;
use rpki::ca::idexchange::{
    MyHandle, PublisherHandle, PublisherRequest, RepositoryResponse,
    ServiceUri,
};
use rpki::ca::publication::PublicationCms;
use rpki::crypto::KeyIdentifier;
use rpki::uri;
use serde::{Deserialize, Serialize};
use crate::api::admin::PublicationServerUris;
use crate::api::ca::IdCertInfo;
use crate::api::history::CommandSummary;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use crate::commons::eventsourcing::{
    Aggregate, AggregateStore, CommandDetails, Event, InitCommandDetails,
    InitEvent, SentCommand, SentInitCommand, WithStorableDetails,
};
use crate::constants::{
    ACTOR_DEF_KRILL, PUBSERVER_DFLT, PUBSERVER_NS, TA_NAME
};
use crate::config::Config;
use crate::server::manager::KrillContext;
use super::publishers::Publisher;


//------------ RepositoryAccessProxy -----------------------------------------

/// Access to the repository access aggregate.
///
/// We can only have one (1) `RepositoryAccess`, but it is an event-sourced
/// typed which is stored in an aggregate store which could theoretically
/// serve multiple. So, we use this type as a wrapper around the single
/// aggregate so that other components don't need to worry about storage
/// details.
pub struct RepositoryAccessProxy {
    /// The aggregate store storing our repository access aggregate.
    store: AggregateStore<RepositoryAccess>,

    /// The handle for this repository.
    key: MyHandle,
}

impl RepositoryAccessProxy {
    /// Creates a new repository access proxy from the config.
    pub fn create(config: &Config) -> KrillResult<Self> {
        let store = AggregateStore::<RepositoryAccess>::create(
            &config.storage_uri,
            PUBSERVER_NS,
            config.use_history_cache,
        )?;
        let key = MyHandle::from_str(PUBSERVER_DFLT).unwrap();

        if store.has(&key)? {
            if let Err(e) = store.warm() {
                // Start to 'warm' the cache. This serves two purposes:
                // 1. this ensures that the `RepositoryAccess` struct is
                //    available in memory
                // 2. this ensures that there are no apparent data issues
                //
                // If there are issues, then we need to bail out. Krill
                // 0.14.0+ uses single files for all change
                // sets, and files are first completely written to disk,
                // and only then renamed.
                //
                // In other words, if we fail to warm the cache then this
                // points at:
                // - data corruption
                // - user started
                error!(
                    "Could not warm up cache, data seems corrupt. \
                     You may need to restore a backup. Error was: {e}"
                );
            }
        }

        Ok(RepositoryAccessProxy { store, key })
    }

    /// Returns whether repository access has been initialized.
    pub fn is_initialized(&self) -> KrillResult<bool> {
        self.store.has(&self.key).map_err(Error::AggregateStoreError)
    }

    /// Initializes repository access.
    ///
    /// If access has already been initialized, returns an error.
    pub fn init(
        &self,
        uris: PublicationServerUris,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        if self.is_initialized()? {
            return Err(Error::RepositoryServerAlreadyInitialized)
        };

        let actor = ACTOR_DEF_KRILL;

        let cmd = RepositoryAccessInitCommand::new(
            self.key.clone(),
            RepositoryAccessInitCommandDetails {
                rrdp_base_uri: uris.rrdp_base_uri,
                rsync_jail: uris.rsync_jail,
                id_cert_info: signer.create_self_signed_id_cert()?.into(),
            },
            &actor,
        );

        self.store.add(cmd)?;

        Ok(())
    }

    /// Deletes the repository access aggregate.
    ///
    /// If access hadn’t been initialized or if there are currently still
    /// publishers, returns an error.
    pub fn clear(&self) -> KrillResult<()> {
        if !self.is_initialized()? {
            Err(Error::RepositoryServerNotInitialized)
        }
        else if !self.publishers()?.is_empty() {
            Err(Error::RepositoryServerHasPublishers)
        }
        else {
            self.store.drop_aggregate(&self.key)?;
            Ok(())
        }
    }

    /// Returns the repository access aggregate.
    fn read(&self) -> KrillResult<Arc<RepositoryAccess>> {
        if !self.is_initialized()? {
            Err(Error::RepositoryServerNotInitialized)
        }
        else {
            self.store.get_latest(&self.key).map_err(|e| {
                Error::custom(format!("Publication Server data issue: {e}"))
            })
        }
    }

    /// Returns a copy of the handles of all current publishers.
    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        Ok(self.read()?.publishers())
    }

    /// Returns a copy of the information of the givem publisher.
    ///
    /// Returns an error if the publisher doesn’t exist.
    pub fn get_publisher(
        &self,
        name: &PublisherHandle,
    ) -> KrillResult<Publisher> {
        self.read()?.get_publisher(name).cloned()
    }

    /// Adds a publisher based on the given publisher request.
    ///
    /// Returns an error if ther request doesn’t validate or if the handle
    /// is already taken.
    pub fn add_publisher(
        &self,
        req: PublisherRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        // XXX Doesn’t check for initialized?
        let name = req.publisher_handle().clone();
        let id_cert = req.validate().map_err(Error::rfc8183)?;
        let base_uri = self.read()?.publisher_rsync_base(&name)?;

        let cmd = RepositoryAccessCommand::new(
            self.key.clone(),
            None,
            RepositoryAccessCommandDetails::AddPublisher {
                id_cert: id_cert.into(),
                name,
                base_uri,
            },
            actor,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    /// Removes the given publisher.
    pub fn remove_publisher(
        &self,
        name: PublisherHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        if !self.is_initialized()? {
            return Err(Error::RepositoryServerNotInitialized)
        }

        let cmd = RepositoryAccessCommand::new(
            self.key.clone(),
            None,
            RepositoryAccessCommandDetails::RemovePublisher { name },
            actor,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    /// Returns the RFC8183 Repository Response for the publisher
    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher: &PublisherHandle,
    ) -> KrillResult<RepositoryResponse> {
        self.read()?.repository_response(rfc8181_uri, publisher)
    }

    /// Parse submitted bytes by a Publisher as an RFC8181 ProtocolCms object,
    /// and validates it.
    pub fn decode_and_validate(
        &self,
        publisher: &PublisherHandle,
        bytes: &[u8],
    ) -> KrillResult<PublicationCms> {
        let publisher = self.get_publisher(publisher)?;
        let msg = PublicationCms::decode(bytes).map_err(Error::Rfc8181)?;
        msg.validate(&publisher.id_cert().public_key)
            .map_err(Error::Rfc8181)?;
        Ok(msg)
    }

    /// Creates a signed publication protocol response from a message.
    pub fn create_response(
        &self,
        message: publication::Message,
        krill: &KrillContext,
    ) -> KrillResult<PublicationCms> {
        let key_id = self.read()?.key_id();
        krill.signer().create_rfc8181_cms(
            message, &key_id
        ).map_err(Error::signer)
    }
}


//------------ RepositoryAccess ----------------------------------------------

/// A publication protocol server.
///
/// The server is capable of handling publishers (both embedded, and remote),
/// and publishing to RRDP and disk, and/ signing responses.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryAccess {
    /// The instance handle of the server.
    ///
    /// This is required by the event sourcing framework.
    handle: MyHandle,

    /// The current version of the aggregate.
    version: u64,

    /// The ID certificate this server uses to sign its messages.
    id_cert: IdCertInfo,

    /// The currently registered publishers.
    publishers: HashMap<PublisherHandle, Publisher>,

    /// The base rsync URI for all published objects.
    rsync_base: uri::Rsync,

    /// The base URI for RRDP.
    rrdp_base: uri::Https,
}

impl RepositoryAccess {
    /// Returns the key identifier of the server’s ID certificate.
    pub fn key_id(&self) -> KeyIdentifier {
        self.id_cert.public_key.key_identifier()
    }
}

/// # Event Sourcing support
impl Aggregate for RepositoryAccess {
    type Command<'a> = RepositoryAccessCommand;
    type StorableCommandDetails = StorableRepositoryCommand;
    type Event = RepositoryAccessEvent;

    type InitCommand<'a> = RepositoryAccessInitCommand;
    type InitEvent = RepositoryAccessInitEvent;
    type Error = Error;

    type Context = ();

    fn init(handle: &MyHandle, event: Self::InitEvent) -> Self {
        RepositoryAccess {
            handle: handle.clone(),
            version: 1,
            id_cert: event.id_cert,
            publishers: HashMap::new(),
            rsync_base: event.rsync_jail,
            rrdp_base: event.rrdp_base_uri,
        }
    }

    fn process_init_command<'a>(
        command: Self::InitCommand<'a>,
        _context: &Self::Context,
    ) -> Result<Self::InitEvent, Self::Error> {
        let details = command.into_details();

        Ok(RepositoryAccessInitEvent {
            id_cert: details.id_cert_info,
            rrdp_base_uri: details.rrdp_base_uri,
            rsync_jail: details.rsync_jail,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn apply(&mut self, event: Self::Event) {
        match event {
            RepositoryAccessEvent::PublisherAdded { name, publisher } => {
                self.publishers.insert(name, publisher);
            }
            RepositoryAccessEvent::PublisherRemoved { name } => {
                self.publishers.remove(&name);
            }
        }
    }

    fn process_command<'a>(
        &self,
        command: Self::Command<'a>,
        _context: &Self::Context,
    ) -> Result<Vec<Self::Event>, Self::Error> {
        info!(
            "Processing command for publisher '{}', version: {}: {}",
            self.handle, self.version, command
        );

        match command.into_details() {
            RepositoryAccessCommandDetails::AddPublisher {
                id_cert, name, base_uri,
            } => {
                self.process_add_publisher(id_cert, name, base_uri)
            }
            RepositoryAccessCommandDetails::RemovePublisher { name } => {
                self.process_remove_publisher(name)
            }
        }
    }
}

impl RepositoryAccess {
    /// Processes the “add publisher” command.
    ///
    /// Adds a publisher with access to the repository. Returns an error if
    /// a publisher with the given name is already present.
    fn process_add_publisher(
        &self,
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
    ) -> Result<Vec<RepositoryAccessEvent>, Error> {
        if self.publishers.contains_key(&name) {
            Err(Error::PublisherDuplicate(name))
        }
        else {
            let publisher = Publisher::new(id_cert, base_uri);

            Ok(vec![RepositoryAccessEvent::PublisherAdded {
                name, publisher,
            }])
        }
    }

    /// Processes the “remove publisher” command.
    ///
    /// Removes a publisher and all its content.
    fn process_remove_publisher(
        &self,
        publisher_handle: PublisherHandle,
    ) -> Result<Vec<RepositoryAccessEvent>, Error> {
        if !self.has_publisher(&publisher_handle) {
            Err(Error::PublisherUnknown(publisher_handle))
        }
        else {
            Ok(vec![RepositoryAccessEvent::PublisherRemoved {
                name: publisher_handle,
            }])
        }
    }

    /// The URL for the RRDP notification file.
    fn notification_uri(&self) -> uri::Https {
        self.rrdp_base.join(b"notification.xml").unwrap()
    }

    /// Returns the rsync base URI of objects by the given publisher.
    fn publisher_rsync_base(
        &self,
        name: &PublisherHandle,
    ) -> KrillResult<uri::Rsync> {
        if name.as_str() == TA_NAME {
            // Let the TA publish directly under the rsync base dir. This
            // will be helpful for RPs that still insist on rsync.
            Ok(self.rsync_base.clone())
        }
        else {
            uri::Rsync::from_str(
                &format!("{}{}/", self.rsync_base, name)).map_err(|_| {
                    Error::Custom(format!(
                        "Cannot derive base uri for {name}"
                    ))
                }
            )
        }
    }

    /// Returns a publication protocol response for a publisher.
    fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher_handle: &PublisherHandle,
    ) -> Result<RepositoryResponse, Error> {
        let publisher = self.get_publisher(publisher_handle)?;
        let rsync_base = publisher.base_uri();
        let service_uri = ServiceUri::Https(rfc8181_uri);

        Ok(RepositoryResponse::new(
            self.id_cert.base64.clone(),
            publisher_handle.clone(),
            service_uri,
            rsync_base.clone(),
            Some(self.notification_uri()),
            None,
        ))
    }

    /// Returns the publisher with the given handle.
    ///
    /// Returns an error if the publisher does not exist.
    fn get_publisher(
        &self,
        publisher_handle: &PublisherHandle,
    ) -> Result<&Publisher, Error> {
        self.publishers.get(publisher_handle).ok_or_else(|| {
            Error::PublisherUnknown(publisher_handle.clone())
        })
    }

    /// Returns whether the given publisher exists.
    fn has_publisher(&self, name: &PublisherHandle) -> bool {
        self.publishers.contains_key(name)
    }

    /// Returns a all the publisher handles.
    fn publishers(&self) -> Vec<PublisherHandle> {
        self.publishers.keys().cloned().collect()
    }
}


//============ Commands ======================================================

//------------ RepositoryAccessCommand ---------------------------------------

pub type RepositoryAccessInitCommand = SentInitCommand<
    RepositoryAccessInitCommandDetails
>;


//------------ RepositoryAccessInitCommandDetails ----------------------------

/// The init command for the repository access aggregate.
#[derive(Clone, Debug)]
pub struct RepositoryAccessInitCommandDetails {
    /// The base URI of the RRDP server used by the repository.
    pub rrdp_base_uri: uri::Https,

    /// The base URI of the rsync server used by the repository.
    pub rsync_jail: uri::Rsync,

    /// The ID certfificate of the repository.
    pub id_cert_info: IdCertInfo,
}

impl InitCommandDetails for RepositoryAccessInitCommandDetails {
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        StorableRepositoryCommand::make_init()
    }
}

impl fmt::Display for RepositoryAccessInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}


//------------ RepositoryAccessCommand ---------------------------------------

pub type RepositoryAccessCommand = SentCommand<
    RepositoryAccessCommandDetails
>;


//------------ RepositoryAccessCommandDetails --------------------------------

/// The command details for all commands of the repository access aggregate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryAccessCommandDetails {
    /// Add a publisher to the repository.
    AddPublisher {
        /// The ID certificate used by the publisher.
        id_cert: IdCertInfo,

        /// The handle identifying the publisher.
        name: PublisherHandle,

        /// The base URI used for identifying objects published.
        base_uri: uri::Rsync,
    },

    /// Remove a publisher.
    RemovePublisher {
        /// The handle of the publisher to be removed.
        name: PublisherHandle,
    },
}

impl CommandDetails for RepositoryAccessCommandDetails {
    type Event = RepositoryAccessEvent;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl fmt::Display for RepositoryAccessCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableRepositoryCommand::from(self.clone()).fmt(f)
    }
}

impl From<RepositoryAccessCommandDetails> for StorableRepositoryCommand {
    fn from(d: RepositoryAccessCommandDetails) -> Self {
        match d {
            RepositoryAccessCommandDetails::AddPublisher { name, .. } => {
                StorableRepositoryCommand::AddPublisher { name }
            }
            RepositoryAccessCommandDetails::RemovePublisher { name } => {
                StorableRepositoryCommand::RemovePublisher { name }
            }
        }
    }
}

//------------ StorableRepositoryCommand -----------------------------------

/// The storeable part of the repository access command.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum StorableRepositoryCommand {
    /// Initialize the access aggregate.
    Init,

    /// Add a publisher.
    AddPublisher {
        /// The handle of the added publisher.
        name: PublisherHandle
    },

    /// Remove a publisher.
    RemovePublisher {
        /// The handle of the publisher to be removed.
        name: PublisherHandle
    },
}

impl WithStorableDetails for StorableRepositoryCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableRepositoryCommand::Init => {
                CommandSummary::new("pubd-init", self)
            }
            StorableRepositoryCommand::AddPublisher { name } => {
                CommandSummary::new("pubd-publisher-add", self)
                    .publisher(name)
            }
            StorableRepositoryCommand::RemovePublisher { name } => {
                CommandSummary::new("pubd-publisher-remove", self)
                    .publisher(name)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl fmt::Display for StorableRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableRepositoryCommand::Init => {
                write!(f, "Initialise server")
            }
            StorableRepositoryCommand::AddPublisher { name } => {
                write!(f, "Added publisher '{name}'")
            }
            StorableRepositoryCommand::RemovePublisher { name } => {
                write!(f, "Removed publisher '{name}'")
            }
        }
    }
}


//============ Events ========================================================

//------------ RepositoryAccessInitEvent -------------------------------------

/// The event initializing the repository access aggregate.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAccessInitEvent {
    /// The identity certificate of the repository.
    pub id_cert: IdCertInfo,

    /// The RRDP base URI for the repository.
    pub rrdp_base_uri: uri::Https,

    /// The rsync base URI for the repository.
    pub rsync_jail: uri::Rsync,
}

impl InitEvent for RepositoryAccessInitEvent {}

impl RepositoryAccessInitEvent {
    pub fn init(
        rsync_jail: uri::Rsync,
        rrdp_base_uri: uri::Https,
        signer: &KrillSigner,
    ) -> KrillResult<RepositoryAccessInitEvent> {
        signer.create_self_signed_id_cert().map_err(Error::signer).map(|id| {
            RepositoryAccessInitEvent {
                id_cert: id.into(),
                rrdp_base_uri,
                rsync_jail,
            }
        })
    }
}

impl fmt::Display for RepositoryAccessInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized publication server. RRDP base uri: {}, \
             Rsync Jail: {}",
            self.rrdp_base_uri, self.rsync_jail
        )
    }
}


//------------ RepositoryAccessEvent -----------------------------------------

/// The events of the repository access aggregate.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryAccessEvent {
    /// A publisher was added to the repository.
    PublisherAdded {
        /// The handle identifying the publisher.
        name: PublisherHandle,

        /// Information about the publisher.
        publisher: Publisher,
    },

    /// A publisher was removed.
    PublisherRemoved {
        /// The handle of the publisher to be removed.
        name: PublisherHandle,
    },
}

impl Event for RepositoryAccessEvent {}

impl fmt::Display for RepositoryAccessEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryAccessEvent::PublisherAdded { name, .. } => {
                write!(f, "Publisher '{name}' added")
            }
            RepositoryAccessEvent::PublisherRemoved { name } => {
                write!(f, "Publisher '{name}' removed")
            }
        }
    }
}

