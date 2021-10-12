use std::{collections::HashMap, fmt, path::Path};

use rpki::repository::crypto::KeyIdentifier;

use crate::{
    commons::{
        actor::Actor,
        api::{CommandSummary, Handle},
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, CommandDetails, SentCommand, StoredEvent, WithStorableDetails},
        KrillResult,
    },
    constants::{ACTOR_DEF_KRILL, SIGNERS_DIR},
};

//------------ InitSignerInfoEvent -----------------------------------------------------------------------------
type InitSignerInfoEvent = StoredEvent<InitSignerInfoDetails>;

impl InitSignerInfoEvent {
    pub fn init(id: &Handle, signer_name: &str, signer_info: &str, public_key: Option<&str>) -> Self {
        StoredEvent::new(
            id,
            0,
            InitSignerInfoDetails {
                signer_name: signer_name.to_string(),
                signer_info: signer_info.to_string(),
                public_key: public_key.map(|v| v.to_string()),
            },
        )
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct InitSignerInfoDetails {
    pub signer_name: String,
    pub signer_info: String,
    pub public_key: Option<String>,
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
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => CommandSummary::new("signer-add-key", &self)
                .with_arg("key_id", key_id)
                .with_arg("internal_key_id", internal_key_id),
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                CommandSummary::new("signer-remove-key", &self).with_arg("key_id", key_id)
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                CommandSummary::new("signer-change-name", &self).with_arg("signer_name", signer_name)
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                CommandSummary::new("signer-change-info", &self).with_arg("signer_info", signer_info)
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
    pub fn add_key(id: &Handle, version: Option<u64>, key_id: &KeyIdentifier, internal_key_id: &str) -> Self {
        let details = SignerInfoCommandDetails::AddKey(key_id.clone(), internal_key_id.to_string());
        let actor = Actor::test_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn remove_key(id: &Handle, version: Option<u64>, key_id: &KeyIdentifier) -> Self {
        let details = SignerInfoCommandDetails::RemoveKey(key_id.clone());
        let actor = Actor::test_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn change_signer_name(id: &Handle, version: Option<u64>, signer_name: &str) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerName(signer_name.to_string());
        let actor = Actor::test_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }

    pub fn change_signer_info(id: &Handle, version: Option<u64>, signer_info: &str) -> Self {
        let details = SignerInfoCommandDetails::ChangeSignerInfo(signer_info.to_string());
        let actor = Actor::test_from_def(ACTOR_DEF_KRILL);
        Self::new(id, version, details, &actor)
    }
}

//------------ SignerInfo -----------------------------------------------------------------------------------------

/// Defines a SignerInfo object. SignerInfos have a name and an age.
///
#[derive(Clone, Deserialize, Serialize)]
struct SignerInfo {
    /// The id is needed when generating events. A string
    /// representation of the signer registration internal key
    /// identifier (that can be used to do signing) combined with
    /// the string representation of the KeyIdentifier of the
    /// public half of the same key.
    id: Handle,

    /// The version of for this particular SignerInfo. Versions
    /// are incremented whenever events are applied. They are
    /// used to store those and apply events in the correct
    /// sequence, as well as to detect concurrency issues when
    /// a command is sent.
    version: u64,

    /// An operator assigned human readable name for this signer.
    signer_name: String,

    /// Information about the signer backend being used.
    signer_info: String,

    /// The hex encoded bytes of an X.509 Subject Public Key Info
    /// public key that can be used to verify the identity of the
    /// signer. Should match the KeyIdentifier used in the id.
    public_key: Option<String>,

    /// The keys that the signer possesses identified by their
    /// Krill KeyIdentifier and their corresponding signer specific
    /// internal identifier.
    keys: HashMap<KeyIdentifier, String>,
}

impl SignerInfo {
    pub fn id(&self) -> &Handle {
        &self.id
    }
    pub fn _signer_name(&self) -> &String {
        &self.signer_name
    }
    // TODO: more getters?
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
            public_key: init.public_key,
            keys: HashMap::new(),
        })
    }

    fn version(&self) -> u64 {
        self.version
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
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<SignerInfoEvent>, Self::Error> {
        match command.into_details() {
            SignerInfoCommandDetails::AddKey(key_id, internal_key_id) => {
                let event = SignerInfoEvent::key_added(self, key_id, internal_key_id);
                Ok(vec![event])
            }
            SignerInfoCommandDetails::RemoveKey(key_id) => {
                let event = SignerInfoEvent::key_removed(self, key_id);
                Ok(vec![event])
            }
            SignerInfoCommandDetails::ChangeSignerName(signer_name) => {
                if signer_name != self.signer_name {
                    let event = SignerInfoEvent::signer_name_changed(self, signer_name);
                    Ok(vec![event])
                } else {
                    Ok(vec![])
                }
            }
            SignerInfoCommandDetails::ChangeSignerInfo(signer_info) => {
                if signer_info != self.signer_info {
                    let event = SignerInfoEvent::signer_info_changed(self, signer_info);
                    Ok(vec![event])
                } else {
                    Ok(vec![])
                }
            }
        }
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
    pub fn build(work_dir: &Path) -> KrillResult<SignerMapper> {
        let store = AggregateStore::<SignerInfo>::disk(work_dir, SIGNERS_DIR)?;
        Ok(SignerMapper { store })
    }

    pub fn add_signer(
        &self,
        signer_handle: &Handle,
        signer_name: &str,
        signer_info: &str,
        public_key: Option<&str>,
    ) -> KrillResult<()> {
        let init = InitSignerInfoEvent::init(signer_handle, signer_name, signer_info, public_key);
        self.store.add(init)?;
        Ok(())
    }

    pub fn remove_signer(&self, signer_handle: &Handle) -> KrillResult<()> {
        self.store.drop_aggregate(signer_handle)?;
        Ok(())
    }

    pub fn get_signer_name(&self, signer_handle: &Handle) -> KrillResult<String> {
        Ok(self.store.get_latest(signer_handle)?.signer_name.clone())
    }

    pub fn change_signer_name(&self, signer_handle: &Handle, signer_name: &str) -> KrillResult<()> {
        // TODO: should version be something other than None here?
        let cmd = SignerInfoCommand::change_signer_name(signer_handle, None, signer_name);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn get_signer_public_key(&self, signer_handle: &Handle) -> KrillResult<Option<String>> {
        Ok(self.store.get_latest(signer_handle)?.public_key.clone())
    }

    pub fn change_signer_info(&self, signer_handle: &Handle, signer_info: &str) -> KrillResult<()> {
        // TODO: should version be something other than None here?
        let cmd = SignerInfoCommand::change_signer_info(signer_handle, None, signer_info);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn add_key(&self, signer_handle: &Handle, key_id: &KeyIdentifier, internal_key_id: &str) -> KrillResult<()> {
        // TODO: should version be something other than None here?
        let cmd = SignerInfoCommand::add_key(signer_handle, None, key_id, internal_key_id);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn remove_key(&self, signer_handle: &Handle, key_id: &KeyIdentifier) -> KrillResult<()> {
        // TODO: should version be something other than None here?
        let cmd = SignerInfoCommand::remove_key(signer_handle, None, key_id);
        self.store.command(cmd)?;
        Ok(())
    }

    pub fn get_key(&self, signer_handle: &Handle, key_id: &KeyIdentifier) -> KrillResult<String> {
        self.store
            .get_latest(signer_handle)?
            .keys
            .get(key_id)
            .cloned()
            .ok_or(Error::SignerError(format!("Key with key id '{}' not found", key_id)))
    }

    pub fn get_any_key(&self, signer_handle: &Handle) -> KrillResult<String> {
        self.store
            .get_latest(signer_handle)?
            .keys
            .values()
            .next()
            .cloned()
            .ok_or(Error::SignerError(format!("Signer does not have any keys")))
    }

    pub fn has_signer(&self, signer_handle: &Handle) -> KrillResult<bool> {
        self.store.has(signer_handle).map_err(Error::AggregateStoreError)
    }

    pub fn get_signer_handles(&self) -> KrillResult<Vec<Handle>> {
        self.store.list().map_err(Error::AggregateStoreError)
    }

    pub fn get_signer_for_key(&self, key_id: &KeyIdentifier) -> KrillResult<Handle> {
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
