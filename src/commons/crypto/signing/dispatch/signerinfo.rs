//! An event sourcing aggregate store for capturing information about signer
//! backends and set of keys they possess.

use std::{collections::HashMap, fmt, str::FromStr};

use rpki::{
    ca::idexchange::MyHandle,
    crypto::{KeyIdentifier, PublicKey},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    commons::{
        crypto::SignerHandle,
        error::Error,
        eventsourcing::{
            Aggregate, AggregateStore, CommandDetails, Event,
            InitCommandDetails, InitEvent, SentCommand, SentInitCommand,
            WithStorableDetails,
        },
        KrillResult,
    },
    constants::{ACTOR_DEF_KRILL, SIGNERS_NS},
};
use crate::api::history::CommandSummary;


//------------ SignerInfoInitCommand -----------------------------------------

type SignerInfoInitCommand = SentInitCommand<SignerInfoInitCommandDetails>;


//------------ SignerInfoInitCommandDetails ----------------------------------

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerInfoInitCommandDetails {
    id: SignerHandle,
    signer_name: String,
    signer_info: String,
    public_key: PublicKey,
    private_key_internal_id: String,
}

impl SignerInfoInitCommandDetails {
    pub fn new(
        id: &SignerHandle,
        signer_name: &str,
        signer_info: &str,
        public_key: &PublicKey,
        private_key_internal_id: &str,
    ) -> Self {
        SignerInfoInitCommandDetails {
            id: id.clone(),
            signer_name: signer_name.to_string(),
            signer_info: signer_info.to_string(),
            public_key: public_key.clone(),
            private_key_internal_id: private_key_internal_id.to_string(),
        }
    }
}

impl fmt::Display for SignerInfoInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for SignerInfoInitCommandDetails {
    type StorableDetails = SignerInfoCommandDetails;

    fn store(&self) -> Self::StorableDetails {
        SignerInfoCommandDetails::make_init()
    }
}


//------------ SignerInfoInitEvent -------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerInfoInitEvent {
    pub signer_name: String,
    pub signer_info: String,
    pub signer_identity: SignerIdentity,
}

impl InitEvent for SignerInfoInitEvent {}

impl fmt::Display for SignerInfoInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Signer info initialized with name '{}'",
            self.signer_name
        )
    }
}


//------------ SignerInfoEvent -----------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignerInfoEvent {
    KeyAdded(KeyIdentifier, String),
    KeyRemoved(KeyIdentifier),
    SignerNameChanged(String),
    SignerInfoChanged(String),
}

impl Event for SignerInfoEvent {}

impl SignerInfoEvent {
    pub fn key_added(key_id: KeyIdentifier, internal_key_id: String) -> Self {
        SignerInfoEvent::KeyAdded(key_id, internal_key_id)
    }

    pub fn key_removed(key_id: KeyIdentifier) -> Self {
        SignerInfoEvent::KeyRemoved(key_id)
    }

    pub fn signer_name_changed(signer_name: String) -> Self {
        SignerInfoEvent::SignerNameChanged(signer_name)
    }

    pub fn signer_info_changed(signer_info: String) -> Self {
        SignerInfoEvent::SignerInfoChanged(signer_info)
    }
}

impl fmt::Display for SignerInfoEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerInfoEvent::KeyAdded(key_id, internal_key_id) => write!(
                f,
                "added key with key id '{key_id}' and internal key id '{internal_key_id}'"
            ),
            SignerInfoEvent::KeyRemoved(key_id) => {
                write!(f, "removed key with key id '{key_id}'")
            }
            SignerInfoEvent::SignerNameChanged(signer_name) => {
                write!(f, "signer name changed to '{signer_name}'")
            }
            SignerInfoEvent::SignerInfoChanged(signer_info) => {
                write!(f, "signer info changed to '{signer_info}'")
            }
        }
    }
}


//------------ SignerInfoCommand ---------------------------------------------

type SignerInfoCommand = SentCommand<SignerInfoCommandDetails>;


//------------ SignerInfoCommandDetails --------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignerInfoCommandDetails {
    Init,
    AddKey(KeyIdentifier, String),
    RemoveKey(KeyIdentifier),
    ChangeSignerName(String),
    ChangeSignerInfo(String),
}

impl fmt::Display for SignerInfoCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerInfoCommandDetails::Init => write!(f, "Initialise Signer"),
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => {
                write!(
                    f,
                    "Add key with key id '{key_id}' and internal key id '{internal_key_id}'"
                )
            }
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                write!(f, "Remove key with key id '{key_id}'")
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                write!(f, "Change signer name to '{signer_name}'")
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                write!(f, "Change signer info to '{signer_info}'")
            }
        }
    }
}

impl WithStorableDetails for SignerInfoCommandDetails {
    fn summary(&self) -> CommandSummary {
        match self {
            SignerInfoCommandDetails::Init => {
                CommandSummary::new("signer-init", self)
            }
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => {
                CommandSummary::new("signer-add-key", self)
                    .arg("key_id", key_id)
                    .arg("internal_key_id", internal_key_id)
            }
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                CommandSummary::new("signer-remove-key", self)
                    .arg("key_id", key_id)
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                CommandSummary::new("signer-change-name", self)
                    .arg("signer_name", signer_name)
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                CommandSummary::new("signer-change-info", self)
                    .arg("signer_info", signer_info)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl CommandDetails for SignerInfoCommandDetails {
    type Event = SignerInfoEvent;
    type StorableDetails = Self;

    fn store(&self) -> Self::StorableDetails {
        self.clone()
    }
}

impl SignerInfoCommand {
    pub fn add_key(
        id: &SignerHandle,
        version: Option<u64>,
        key_id: &KeyIdentifier,
        internal_key_id: &str,
    ) -> Self {
        let details = SignerInfoCommandDetails::AddKey(
            *key_id,
            internal_key_id.to_string(),
        );
        Self::new(id.clone(), version, details, &ACTOR_DEF_KRILL)
    }

    pub fn remove_key(
        id: &SignerHandle,
        version: Option<u64>,
        key_id: &KeyIdentifier,
    ) -> Self {
        let details = SignerInfoCommandDetails::RemoveKey(*key_id);
        Self::new(id.clone(), version, details, &ACTOR_DEF_KRILL)
    }

    pub fn change_signer_name(
        id: &SignerHandle,
        version: Option<u64>,
        signer_name: &str,
    ) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerName(
            signer_name.to_string(),
        );
        Self::new(id.clone(), version, details, &ACTOR_DEF_KRILL)
    }

    pub fn change_signer_info(
        id: &SignerHandle,
        version: Option<u64>,
        signer_info: &str,
    ) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerInfo(
            signer_info.to_string(),
        );
        Self::new(id.clone(), version, details, &ACTOR_DEF_KRILL)
    }
}


//------------ SignerIdentity ------------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerIdentity {
    /// An X.509 Subject Public Key Info public key that can be used to
    /// verify the identity of the signer.
    public_key: PublicKey,

    /// The internal signer backend specific identifier for the corresponding
    /// private key.
    private_key_internal_id: String,
}


//------------ SignerInfo ----------------------------------------------------

/// SignerInfo defines the set of keys created in a particular signer backend
/// and the identity of that backend.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Deserialize, Serialize)]
pub struct SignerInfo {
    /// The id is needed when generating events.
    id: SignerHandle,

    /// The version of for this particular SignerInfo. Versions are
    /// incremented whenever events are applied. They are used to store
    /// those and apply events in the correct sequence, as well as to detect
    /// concurrency issues when a command is sent.
    version: u64,

    /// An operator assigned human readable name for this signer.
    signer_name: String,

    /// Information about the signer backend being used.
    signer_info: String,

    /// Details needed to confirm the identity of the signer backend.
    signer_identity: SignerIdentity,

    /// The keys that the signer possesses identified by their Krill
    /// KeyIdentifier and their corresponding signer specific internal
    /// identifier.
    keys: HashMap<KeyIdentifier, String>,
}

impl Aggregate for SignerInfo {
    type Command = SignerInfoCommand;
    type StorableCommandDetails = SignerInfoCommandDetails;
    type Event = SignerInfoEvent;

    type InitCommand = SignerInfoInitCommand;
    type InitEvent = SignerInfoInitEvent;

    type Error = Error;

    fn init(handle: &MyHandle, init: SignerInfoInitEvent) -> Self {
        SignerInfo {
            version: 0,
            id: handle.clone(),
            signer_name: init.signer_name,
            signer_info: init.signer_info,
            signer_identity: init.signer_identity,
            keys: HashMap::new(),
        }
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn apply(&mut self, event: SignerInfoEvent) {
        match event {
            SignerInfoEvent::KeyAdded(key_id, internal_key_id) => {
                self.keys.insert(key_id, internal_key_id);
            }
            SignerInfoEvent::KeyRemoved(key_id) => {
                let _ = self.keys.remove(&key_id);
            }
            SignerInfoEvent::SignerNameChanged(signer_name) => {
                self.signer_name = signer_name;
            }
            SignerInfoEvent::SignerInfoChanged(signer_info) => {
                self.signer_info = signer_info;
            }
        }
    }

    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Event>, Self::Error> {
        Ok(match command.into_details() {
            SignerInfoCommandDetails::Init => {
                // This can't happen really.. we would never send this command
                // to an existing Signer.
                //
                // This could be solved more elegantly, and more verbosely, if
                // we create a separate SignerInfoStorableCommand that
                // implements 'WithStorableDetails' - like we
                // have in other cases - because
                // then our initialisation command could map to that type
                // instead of having this additional variant
                // for storing.
                return Err(Error::custom("Signer already initialised"));
            }
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => {
                vec![SignerInfoEvent::key_added(key_id, internal_key_id)]
            }
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                vec![SignerInfoEvent::key_removed(key_id)]
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                if signer_name != self.signer_name {
                    vec![SignerInfoEvent::signer_name_changed(signer_name)]
                } else {
                    vec![]
                }
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                if signer_info != self.signer_info {
                    vec![SignerInfoEvent::signer_info_changed(signer_info)]
                } else {
                    vec![]
                }
            }
        })
    }

    fn process_init_command(
        command: SignerInfoInitCommand,
    ) -> Result<SignerInfoInitEvent, Self::Error> {
        let details = command.into_details();
        Ok(SignerInfoInitEvent {
            signer_name: details.signer_name,
            signer_info: details.signer_info,
            signer_identity: SignerIdentity {
                public_key: details.public_key,
                private_key_internal_id: details.private_key_internal_id,
            },
        })
    }
}


//------------ SignerMapper --------------------------------------------------

pub struct SignerMapper {
    store: AggregateStore<SignerInfo>,
}

impl std::fmt::Debug for SignerMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerMapper").finish()
    }
}

impl SignerMapper {
    /// Build a SignerMapper that will read/write its data in a subdirectory
    /// of the given work dir.
    pub fn build(storage_uri: &Url) -> KrillResult<SignerMapper> {
        let store = AggregateStore::<SignerInfo>::create(
            storage_uri,
            SIGNERS_NS,
            true,
        )?;
        Ok(SignerMapper { store })
    }

    /// Record the existence of a new signer.
    ///
    /// A signer has several properties, some fixed, some modifiable. The
    /// handle and public key are fixed at signer creation time while the
    /// name and info strings can be changed later.
    ///
    /// - The handle is an unchanging identifier that will uniquely identify
    ///   the signer in the mapper store. Each signer in the store is required
    ///   to have a unique handle. The meaning/content of the handle is opaque
    ///   to the store. Do not use a human readable string as the handle
    ///   because you may cause confusion if the value has some meaning that
    ///   is later found to be false or misleading and can then no longer be
    ///   changed. Instead use the 'name' argument to assign human readable
    ///   identifier that may need to be changed later.
    ///
    /// - The public key is an unchanging public key that can be used to
    ///   verify that a given signer in the mapper store corresponds to a
    ///   particular signer backend. Verification is done by asking the signer
    ///   backend to sign a challenge and verifying that the produced
    ///   signature corresponds to the stored public key. If verification is
    ///   successful it means that we expect the signer backend to possess the
    ///   keys attributed to it in the signer store.
    ///
    /// - The name is an operator defined string that is expected to come from
    ///   the Krill configuration file and which is intended to be a useful
    ///   friendly human readable identifier to be displayed in the UI or in
    ///   CLI output or included in log or error messages. The name can be
    ///   changed later by calling `change_signer_name()`.
    ///
    /// - The info string is intended to contain details retrieved from the
    ///   signer backend that describe useful, interesting and/or identifying
    ///   properties of the backend. The info string can be changed later by
    ///   calling `change_signer_info()`. This could be useful for example if
    ///   the signer backend retains its content but is upgraded to a newer
    ///   version, we can then update the info string in the signer store and
    ///   the upgrade will be visible in the history of the store.
    pub fn add_signer(
        &self,
        signer_name: &str,
        signer_info: &str,
        public_key: &PublicKey,
        private_key_internal_id: &str,
    ) -> KrillResult<SignerHandle> {
        let signer_handle =
            SignerHandle::from_str(&uuid::Uuid::new_v4().to_string())
                .map_err(|err| {
                    Error::SignerError(format!(
                        "Generated UUID is not a valid signer handle: {err}"
                    ))
                })?;

        let cmd = SignerInfoInitCommand::new(
            signer_handle.clone(),
            SignerInfoInitCommandDetails {
                id: signer_handle.clone(),
                signer_name: signer_name.to_string(),
                signer_info: signer_info.to_string(),
                public_key: public_key.clone(),
                private_key_internal_id: private_key_internal_id.to_string(),
            },
            &ACTOR_DEF_KRILL,
        );

        self.store.add(cmd)?;
        Ok(signer_handle)
    }

    pub fn _remove_signer(
        &self,
        signer_handle: &SignerHandle,
    ) -> KrillResult<()> {
        self.store.drop_aggregate(signer_handle)?;
        Ok(())
    }

    pub fn get_signer_name(
        &self,
        signer_handle: &SignerHandle,
    ) -> KrillResult<String> {
        Ok(self.store.get_latest(signer_handle)?.signer_name.clone())
    }

    pub fn change_signer_name(
        &self,
        signer_handle: &SignerHandle,
        signer_name: &str,
    ) -> KrillResult<()> {
        let cmd = SignerInfoCommand::change_signer_name(
            signer_handle,
            None,
            signer_name,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn get_signer_public_key(
        &self,
        signer_handle: &SignerHandle,
    ) -> KrillResult<PublicKey> {
        Ok(self
            .store
            .get_latest(signer_handle)?
            .signer_identity
            .public_key
            .clone())
    }

    pub fn get_signer_private_key_internal_id(
        &self,
        signer_handle: &SignerHandle,
    ) -> KrillResult<String> {
        Ok(self
            .store
            .get_latest(signer_handle)?
            .signer_identity
            .private_key_internal_id
            .clone())
    }

    pub fn change_signer_info(
        &self,
        signer_handle: &SignerHandle,
        signer_info: &str,
    ) -> KrillResult<()> {
        let cmd = SignerInfoCommand::change_signer_info(
            signer_handle,
            None,
            signer_info,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    /// Record the owner of a Krill key and its corresponding signer specific
    /// internal id.
    pub fn add_key(
        &self,
        signer_handle: &SignerHandle,
        key_id: &KeyIdentifier,
        internal_key_id: &str,
    ) -> KrillResult<()> {
        let cmd = SignerInfoCommand::add_key(
            signer_handle,
            None,
            key_id,
            internal_key_id,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn remove_key(
        &self,
        signer_handle: &SignerHandle,
        key_id: &KeyIdentifier,
    ) -> KrillResult<()> {
        let cmd = SignerInfoCommand::remove_key(signer_handle, None, key_id);
        self.store.command(cmd)?;
        Ok(())
    }

    /// Retrieve the signer specific internal id corresponding to the given
    /// Krill key.
    pub fn get_key(
        &self,
        signer_handle: &SignerHandle,
        key_id: &KeyIdentifier,
    ) -> KrillResult<String> {
        self.store
            .get_latest(signer_handle)?
            .keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                Error::SignerError(format!(
                    "Key with key id '{key_id}' not found"
                ))
            })
    }

    /// Get the complete set of known signer handles.
    pub fn get_signer_handles(&self) -> KrillResult<Vec<SignerHandle>> {
        self.store.list().map_err(Error::AggregateStoreError)
    }

    /// Get the handle of the signer that possesses the given Krill key, if
    /// any.
    pub fn get_signer_for_key(
        &self,
        key_id: &KeyIdentifier,
    ) -> KrillResult<SignerHandle> {
        // Look for the key id in the key set of each set. Not very efficient
        // but can be improved upon later if needed, e.g. by creating
        // on startup and maintaining an in-memory map of KeyIdentifier to
        // signer Handles.
        for signer_handle in self.store.list()? {
            let signer_info = self.store.get_latest(&signer_handle)?;
            if signer_info.keys.contains_key(key_id) {
                return Ok(signer_handle);
            }
        }
        Err(Error::SignerError(format!(
            "No signer owns key id '{key_id}'"
        )))
    }
}

