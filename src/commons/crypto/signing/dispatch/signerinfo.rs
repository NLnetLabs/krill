//! An event sourcing aggregate store for capturing information about signer backends and set of keys they possess.

use std::{collections::HashMap, fmt, str::FromStr};

use rpki::crypto::{KeyIdentifier, PublicKey};
use url::Url;

use crate::{
    commons::{
        actor::Actor,
        api::CommandSummary,
        crypto::SignerHandle,
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, CommandDetails, SentCommand, StoredEvent, WithStorableDetails},
        KrillResult,
    },
    constants::{ACTOR_DEF_KRILL, SIGNERS_NS},
};

//------------ InitSignerInfoEvent -----------------------------------------------------------------------------
type InitSignerInfoEvent = StoredEvent<InitSignerInfoDetails>;

impl InitSignerInfoEvent {
    pub fn init(
        id: &SignerHandle,
        signer_name: &str,
        signer_info: &str,
        public_key: &PublicKey,
        private_key_internal_id: &str,
    ) -> Self {
        StoredEvent::new(
            id,
            0,
            InitSignerInfoDetails {
                signer_name: signer_name.to_string(),
                signer_info: signer_info.to_string(),
                signer_identity: SignerIdentity {
                    public_key: public_key.clone(),
                    private_key_internal_id: private_key_internal_id.to_string(),
                },
            },
        )
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct InitSignerInfoDetails {
    pub signer_name: String,
    pub signer_info: String,
    pub signer_identity: SignerIdentity,
}

impl fmt::Display for InitSignerInfoDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signer info initialized with name '{}'", self.signer_name)
    }
}

//------------ SignerInfoEvent ---------------------------------------------------------------------------------
type SignerInfoEvent = StoredEvent<SignerInfoEventDetails>;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum SignerInfoEventDetails {
    KeyAdded(KeyIdentifier, String),
    KeyRemoved(KeyIdentifier),
    SignerNameChanged(String),
    SignerInfoChanged(String),
}

impl SignerInfoEvent {
    pub fn key_added(si: &SignerInfo, key_id: KeyIdentifier, internal_key_id: String) -> Self {
        StoredEvent::new(
            si.id(),
            si.version,
            SignerInfoEventDetails::KeyAdded(key_id, internal_key_id),
        )
    }

    pub fn key_removed(si: &SignerInfo, key_id: KeyIdentifier) -> Self {
        StoredEvent::new(si.id(), si.version, SignerInfoEventDetails::KeyRemoved(key_id))
    }

    pub fn signer_name_changed(si: &SignerInfo, signer_name: String) -> Self {
        StoredEvent::new(
            si.id(),
            si.version,
            SignerInfoEventDetails::SignerNameChanged(signer_name),
        )
    }

    pub fn signer_info_changed(si: &SignerInfo, signer_info: String) -> Self {
        StoredEvent::new(
            si.id(),
            si.version,
            SignerInfoEventDetails::SignerInfoChanged(signer_info),
        )
    }
}

impl fmt::Display for SignerInfoEventDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerInfoEventDetails::KeyAdded(key_id, internal_key_id) => write!(
                f,
                "added key with key id '{}' and internal key id '{}'",
                key_id, internal_key_id
            ),
            SignerInfoEventDetails::KeyRemoved(key_id) => write!(f, "removed key with key id '{}'", key_id),
            SignerInfoEventDetails::SignerNameChanged(signer_name) => {
                write!(f, "signer name changed to '{}'", signer_name)
            }
            SignerInfoEventDetails::SignerInfoChanged(signer_info) => {
                write!(f, "signer info changed to '{}'", signer_info)
            }
        }
    }
}

//------------ SignerInfoCommand ----------------------------------------------------------------------------------

type SignerInfoCommand = SentCommand<SignerInfoCommandDetails>;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum SignerInfoCommandDetails {
    AddKey(KeyIdentifier, String),
    RemoveKey(KeyIdentifier),
    ChangeSignerName(String),
    ChangeSignerInfo(String),
}

impl fmt::Display for SignerInfoCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => write!(
                f,
                "Add key with key id '{}' and internal key id '{}'",
                key_id, internal_key_id
            ),
            SignerInfoCommandDetails::RemoveKey(key_id) => write!(f, "Remove key with key id '{}'", key_id),
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                write!(f, "Change signer name to '{}'", signer_name)
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                write!(f, "Change signer info to '{}'", signer_info)
            }
        }
    }
}

impl WithStorableDetails for SignerInfoCommandDetails {
    fn summary(&self) -> CommandSummary {
        match self {
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => CommandSummary::new("signer-add-key", self)
                .with_arg("key_id", key_id)
                .with_arg("internal_key_id", internal_key_id),
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                CommandSummary::new("signer-remove-key", self).with_arg("key_id", key_id)
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                CommandSummary::new("signer-change-name", self).with_arg("signer_name", signer_name)
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                CommandSummary::new("signer-change-info", self).with_arg("signer_info", signer_info)
            }
        }
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
    pub fn add_key(id: &SignerHandle, version: Option<u64>, key_id: &KeyIdentifier, internal_key_id: &str) -> Self {
        let details = SignerInfoCommandDetails::AddKey(*key_id, internal_key_id.to_string());
        let actor = Actor::actor_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn remove_key(id: &SignerHandle, version: Option<u64>, key_id: &KeyIdentifier) -> Self {
        let details = SignerInfoCommandDetails::RemoveKey(*key_id);
        let actor = Actor::actor_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn change_signer_name(id: &SignerHandle, version: Option<u64>, signer_name: &str) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerName(signer_name.to_string());
        let actor = Actor::actor_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn change_signer_info(id: &SignerHandle, version: Option<u64>, signer_info: &str) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerInfo(signer_info.to_string());
        let actor = Actor::actor_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }
}

//------------ SignerInfo -----------------------------------------------------------------------------------------

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct SignerIdentity {
    /// An X.509 Subject Public Key Info public key that can be used to verify the identity of the signer.
    public_key: PublicKey,

    /// The internal signer backend specific identifier for the corresponding private key.
    private_key_internal_id: String,
}

/// SignerInfo defines the set of keys created in a particular signer backend and the identity of that backend.
///
#[derive(Clone, Deserialize, Serialize)]
struct SignerInfo {
    /// The id is needed when generating events.
    id: SignerHandle,

    /// The version of for this particular SignerInfo. Versions are incremented whenever events are applied. They are
    /// used to store those and apply events in the correct sequence, as well as to detect concurrency issues when a
    /// command is sent.
    version: u64,

    /// An operator assigned human readable name for this signer.
    signer_name: String,

    /// Information about the signer backend being used.
    signer_info: String,

    /// Details needed to confirm the identity of the signer backend.
    signer_identity: SignerIdentity,

    /// The keys that the signer possesses identified by their Krill KeyIdentifier and their corresponding signer
    /// specific internal identifier.
    keys: HashMap<KeyIdentifier, String>,
}

impl SignerInfo {
    pub fn id(&self) -> &SignerHandle {
        &self.id
    }
}

impl Aggregate for SignerInfo {
    type Command = SignerInfoCommand;
    type StorableCommandDetails = SignerInfoCommandDetails;
    type Event = SignerInfoEvent;
    type InitEvent = InitSignerInfoEvent;
    type Error = Error;

    fn init(event: InitSignerInfoEvent) -> Result<Self, Self::Error> {
        let (id, _version, init) = event.unpack();
        Ok(SignerInfo {
            id,
            version: 1,
            signer_name: init.signer_name,
            signer_info: init.signer_info,
            signer_identity: init.signer_identity,
            keys: HashMap::new(),
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn apply(&mut self, event: SignerInfoEvent) {
        match event.into_details() {
            SignerInfoEventDetails::KeyAdded(key_id, internal_key_id) => {
                self.keys.insert(key_id, internal_key_id);
            }
            SignerInfoEventDetails::KeyRemoved(key_id) => {
                let _ = self.keys.remove(&key_id);
            }
            SignerInfoEventDetails::SignerNameChanged(signer_name) => {
                self.signer_name = signer_name;
            }
            SignerInfoEventDetails::SignerInfoChanged(signer_info) => {
                self.signer_info = signer_info;
            }
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        Ok(match command.into_details() {
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => {
                vec![SignerInfoEvent::key_added(self, key_id, internal_key_id)]
            }
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                vec![SignerInfoEvent::key_removed(self, key_id)]
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                if signer_name != self.signer_name {
                    vec![SignerInfoEvent::signer_name_changed(self, signer_name)]
                } else {
                    vec![]
                }
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                if signer_info != self.signer_info {
                    vec![SignerInfoEvent::signer_info_changed(self, signer_info)]
                } else {
                    vec![]
                }
            }
        })
    }
}

pub struct SignerMapper {
    store: AggregateStore<SignerInfo>,
}

impl std::fmt::Debug for SignerMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerMapper").finish()
    }
}

impl SignerMapper {
    /// Build a SignerMapper that will read/write its data in a subdirectory of the given work dir.
    pub fn build(storage_uri: &Url) -> KrillResult<SignerMapper> {
        let store = AggregateStore::<SignerInfo>::create(storage_uri, SIGNERS_NS, true)?;
        Ok(SignerMapper { store })
    }

    /// Record the existence of a new signer.
    ///
    /// A signer has several properties, some fixed, some modifiable. The handle and public key are fixed at signer
    /// creation time while the name and info strings can be changed later.
    ///
    /// - The handle is an unchanging identifier that will uniquely identify the signer in the mapper store. Each signer
    ///   in the store is required to have a unique handle. The meaning/content of the handle is opaque to the store.
    ///   Do not use a human readable string as the handle because you may cause confusion if the value has some meaning
    ///   that is later found to be false or misleading and can then no longer be changed. Instead use the 'name'
    ///   argument to assign human readable identifier that may need to be changed later.
    ///
    /// - The public key is an unchanging public key that can be used to verify that a given signer in the mapper store
    ///   corresponds to a particular signer backend. Verification is done by asking the signer backend to sign a
    ///   challenge and verifying that the produced signature corresponds to the stored public key. If verification is
    ///   successful it means that we expect the signer backend to possess the keys attributed to it in the signer
    ///   store.
    ///
    /// - The name is an operator defined string that is expected to come from the Krill configuration file and which
    ///   is intended to be a useful friendly human readable identifier to be displayed in the UI or in CLI output or
    ///   included in log or error messages. The name can be changed later by calling `change_signer_name()`.
    ///
    /// - The info string is intended to contain details retrieved from the signer backend that describe useful,
    ///   interesting and/or identifying properties of the backend. The info string can be changed later by calling
    ///   `change_signer_info()`. This could be useful for example if the signer backend retains its content but is
    ///   upgraded to a newer version, we can then update the info string in the signer store and the upgrade will be
    ///   visible in the history of the store.
    pub fn add_signer(
        &self,
        signer_name: &str,
        signer_info: &str,
        public_key: &PublicKey,
        private_key_internal_id: &str,
    ) -> KrillResult<SignerHandle> {
        let signer_handle = SignerHandle::from_str(&uuid::Uuid::new_v4().to_string())
            .map_err(|err| Error::SignerError(format!("Generated UUID is not a valid signer handle: {}", err)))?;

        let init = InitSignerInfoEvent::init(
            &signer_handle,
            signer_name,
            signer_info,
            public_key,
            private_key_internal_id,
        );
        self.store.add(init)?;
        Ok(signer_handle)
    }

    pub fn _remove_signer(&self, signer_handle: &SignerHandle) -> KrillResult<()> {
        self.store.drop_aggregate(signer_handle)?;
        Ok(())
    }

    pub fn get_signer_name(&self, signer_handle: &SignerHandle) -> KrillResult<String> {
        Ok(self.store.get_latest(signer_handle)?.signer_name.clone())
    }

    pub fn change_signer_name(&self, signer_handle: &SignerHandle, signer_name: &str) -> KrillResult<()> {
        let cmd = SignerInfoCommand::change_signer_name(signer_handle, None, signer_name);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn get_signer_public_key(&self, signer_handle: &SignerHandle) -> KrillResult<PublicKey> {
        Ok(self.store.get_latest(signer_handle)?.signer_identity.public_key.clone())
    }

    pub fn get_signer_private_key_internal_id(&self, signer_handle: &SignerHandle) -> KrillResult<String> {
        Ok(self
            .store
            .get_latest(signer_handle)?
            .signer_identity
            .private_key_internal_id
            .clone())
    }

    pub fn change_signer_info(&self, signer_handle: &SignerHandle, signer_info: &str) -> KrillResult<()> {
        let cmd = SignerInfoCommand::change_signer_info(signer_handle, None, signer_info);
        self.store.command(cmd)?;
        Ok(())
    }

    /// Record the owner of a Krill key and its corresponding signer specific internal id.
    pub fn add_key(
        &self,
        signer_handle: &SignerHandle,
        key_id: &KeyIdentifier,
        internal_key_id: &str,
    ) -> KrillResult<()> {
        let cmd = SignerInfoCommand::add_key(signer_handle, None, key_id, internal_key_id);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn remove_key(&self, signer_handle: &SignerHandle, key_id: &KeyIdentifier) -> KrillResult<()> {
        let cmd = SignerInfoCommand::remove_key(signer_handle, None, key_id);
        self.store.command(cmd)?;
        Ok(())
    }

    /// Retrieve the signer specific internal id corresponding to the given Krill key.
    pub fn get_key(&self, signer_handle: &SignerHandle, key_id: &KeyIdentifier) -> KrillResult<String> {
        self.store
            .get_latest(signer_handle)?
            .keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| Error::SignerError(format!("Key with key id '{}' not found", key_id)))
    }

    /// Get the complete set of known signer handles.
    pub fn get_signer_handles(&self) -> KrillResult<Vec<SignerHandle>> {
        self.store.list().map_err(Error::AggregateStoreError)
    }

    /// Get the handle of the signer that possesses the given Krill key, if any.
    pub fn get_signer_for_key(&self, key_id: &KeyIdentifier) -> KrillResult<SignerHandle> {
        // Look for the key id in the key set of each set. Not very efficient but can be improved upon later if
        // needed, e.g. by creating on startup and maintaining an in-memory map of KeyIdentifier to signer Handles.
        for signer_handle in self.store.list()? {
            let signer_info = self.store.get_latest(&signer_handle)?;
            if signer_info.keys.contains_key(key_id) {
                return Ok(signer_handle);
            }
        }
        Err(Error::SignerError(format!("No signer owns key id '{}'", key_id)))
    }
}
