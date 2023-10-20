use std::{fmt, str::FromStr};

use kvx::Namespace;
use rpki::{
    ca::{idexchange::MyHandle, publication::Base64},
    repository::{
        resources::AddressFamily,
        x509::{Serial, Time, Validity},
    },
    resources::Asn,
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        api::{AspaDefinition, CustomerAsn},
        crypto::dispatch::signerinfo::{SignerInfo, SignerInfoEvent, SignerInfoInitEvent},
        eventsourcing::{
            Aggregate, AggregateStore, KeyValueStore, Storable, StoredCommand, StoredCommandBuilder,
            WithStorableDetails,
        },
    },
    daemon::{
        ca::{CertAuthEvent, CertAuthInitEvent},
        config::Config,
        properties::Properties,
    },
    pubd::{RepositoryAccess, RepositoryAccessEvent, RepositoryAccessInitEvent},
    ta::{
        TrustAnchorProxy, TrustAnchorProxyEvent, TrustAnchorProxyInitEvent, TrustAnchorSigner, TrustAnchorSignerEvent,
        TrustAnchorSignerInitEvent,
    },
};

use super::{
    AspaMigrationConfigs, CommandMigrationEffect, UnconvertedEffect, UpgradeAggregateStorePre0_14, UpgradeMode,
    UpgradeResult,
};

// Stuff in modules
mod old_commands;
pub use self::old_commands::*;

mod old_events;
pub use self::old_events::*;

mod cas_migration;
pub use self::cas_migration::*;

//------------ Pre0_14_0AspaDefinition ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaDefinition {
    pub customer: CustomerAsn,
    pub providers: Vec<Pre0_14_0ProviderAs>,
}

impl From<Pre0_14_0AspaDefinition> for AspaDefinition {
    fn from(old: Pre0_14_0AspaDefinition) -> Self {
        AspaDefinition::new(old.customer, old.providers.into_iter().map(|o| o.provider).collect())
    }
}

//------------ Pre_0_14_0AspaInfo ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaInfo {
    pub definition: Pre0_14_0AspaDefinition,
    validity: Validity,
    serial: Serial,
    uri: uri::Rsync,
    base64: Base64,
    hash: Hash,
}

//------------ Pre_0_14_0AspaObjectsUpdates -----------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub updated: Vec<Pre0_14_0AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<CustomerAsn>,
}

//------------ OldEvent -------------------------------------------------------

pub type OldInitSignerInfoEvent = OldStoredEvent<SignerInfoInitEvent>;
pub type OldSignerInfoEvent = OldStoredEvent<SignerInfoEvent>;

pub type OldCertAuthInitEvent = OldStoredEvent<CertAuthInitEvent>;
pub type OldCertAuthEvent = OldStoredEvent<CertAuthEvent>;

pub type OldTrustAnchorProxyInitEvent = OldStoredEvent<TrustAnchorProxyInitEvent>;
pub type OldTrustAnchorProxyEvent = OldStoredEvent<TrustAnchorProxyEvent>;

pub type OldTrustAnchorSignerInitEvent = OldStoredEvent<TrustAnchorSignerInitEvent>;
pub type OldTrustAnchorSignerEvent = OldStoredEvent<TrustAnchorSignerEvent>;

pub type OldRepositoryAccessInitEvent = OldStoredEvent<RepositoryAccessInitEvent>;
pub type OldRepositoryAccessEvent = OldStoredEvent<RepositoryAccessEvent>;

pub trait OldEvent: fmt::Display + Eq + PartialEq + Storable + 'static {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &MyHandle;

    /// The version of the aggregate that this event updates. An aggregate that
    /// is currently at version x, will get version x + 1, when the event for
    /// version x is applied.
    fn version(&self) -> u64;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredEvent<E: fmt::Display + Eq + PartialEq + Storable + 'static> {
    id: MyHandle,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E,
}

impl<E: fmt::Display + Eq + PartialEq + Storable + 'static> OldStoredEvent<E> {
    pub fn new(id: &MyHandle, version: u64, event: E) -> Self {
        OldStoredEvent {
            id: id.clone(),
            version,
            details: event,
        }
    }

    pub fn details(&self) -> &E {
        &self.details
    }

    pub fn into_details(self) -> E {
        self.details
    }

    /// Return the parts of this event.
    pub fn unpack(self) -> (MyHandle, u64, E) {
        (self.id, self.version, self.details)
    }
}

impl<E: fmt::Display + Eq + PartialEq + Storable + 'static> OldEvent for OldStoredEvent<E> {
    fn handle(&self) -> &MyHandle {
        &self.id
    }

    fn version(&self) -> u64 {
        self.version
    }
}

impl<E: fmt::Display + Eq + PartialEq + Storable + 'static> fmt::Display for OldStoredEvent<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id: {} version: {} details: {}", self.id, self.version, self.details)
    }
}

//------------ OldStoredCommand ----------------------------------------------

/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStoredCommand<S: WithStorableDetails> {
    actor: String,
    time: Time,
    handle: MyHandle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    #[serde(deserialize_with = "S::deserialize")]
    details: S,
    effect: OldStoredEffect,
}

impl<S: WithStorableDetails> OldStoredCommand<S> {
    pub fn actor(&self) -> &String {
        &self.actor
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn handle(&self) -> &MyHandle {
        &self.handle
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn effect(&self) -> &OldStoredEffect {
        &self.effect
    }

    pub fn details(&self) -> &S {
        &self.details
    }
}

//------------ OldStoredEffect -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum OldStoredEffect {
    Error { msg: String },
    Success { events: Vec<u64> },
}

impl OldStoredEffect {
    pub fn events(&self) -> Option<&Vec<u64>> {
        match self {
            OldStoredEffect::Error { .. } => None,
            OldStoredEffect::Success { events } => Some(events),
        }
    }
}

//------------ OldCommandKey -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldCommandKey {
    pub sequence: u64,
    pub timestamp_secs: i64,
    pub label: Label,
}

pub type Label = String;

impl fmt::Display for OldCommandKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "command--{}--{}--{}", self.timestamp_secs, self.sequence, self.label)
    }
}

impl FromStr for OldCommandKey {
    type Err = CommandKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("--").collect();
        if parts.len() != 4 || parts[0] != "command" {
            Err(CommandKeyError(s.to_string()))
        } else {
            let timestamp_secs = i64::from_str(parts[1]).map_err(|_| CommandKeyError(s.to_string()))?;
            let sequence = u64::from_str(parts[2]).map_err(|_| CommandKeyError(s.to_string()))?;
            // strip .json if present on the label part
            let label = {
                let end = parts[3].to_string();
                let last = if end.ends_with(".json") {
                    end.len() - 5
                } else {
                    end.len()
                };
                (end[0..last]).to_string()
            };

            Ok(OldCommandKey {
                sequence,
                timestamp_secs,
                label,
            })
        }
    }
}

//------------ CommandKeyError -----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandKeyError(String);

impl fmt::Display for CommandKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid command key: {}", self.0)
    }
}

//------------ UpgradeAggrateStore impls from generic ------------------------

pub type UpgradeAggregateStoreProperties = GenericUpgradeAggregateStore<Properties>;
pub type UpgradeAggregateStoreSignerInfo = GenericUpgradeAggregateStore<SignerInfo>;
pub type UpgradeAggregateStoreTrustAnchorSigner = GenericUpgradeAggregateStore<TrustAnchorSigner>;
pub type UpgradeAggregateStoreTrustAnchorProxy = GenericUpgradeAggregateStore<TrustAnchorProxy>;
pub type UpgradeAggregateStoreRepositoryAccess = GenericUpgradeAggregateStore<RepositoryAccess>;

//------------ GenericUpgradeAggrateStore ------------------------------------

/// Upgrades a generic pre 0.14.0 AggregateStore
///
/// This works for implementations that do not need to do complex command or
/// event conversions.
pub struct GenericUpgradeAggregateStore<A: Aggregate> {
    store_name: String,
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<A>,
}

impl<A: Aggregate> GenericUpgradeAggregateStore<A> {
    pub fn upgrade(name_space: &Namespace, mode: UpgradeMode, config: &Config) -> UpgradeResult<AspaMigrationConfigs> {
        let current_kv_store = KeyValueStore::create(&config.storage_uri, name_space)?;

        if current_kv_store.scopes()?.is_empty() {
            // nothing to do here
            Ok(AspaMigrationConfigs::default())
        } else {
            let new_kv_store = KeyValueStore::create_upgrade_store(&config.storage_uri, name_space)?;
            let new_agg_store =
                AggregateStore::<A>::create_upgrade_store(&config.storage_uri, name_space, config.use_history_cache)?;

            let store_migration = GenericUpgradeAggregateStore {
                store_name: name_space.to_string(),
                current_kv_store,
                new_kv_store,
                new_agg_store,
            };

            store_migration.upgrade(mode)
        }
    }
}

impl<A: Aggregate> UpgradeAggregateStorePre0_14 for GenericUpgradeAggregateStore<A> {
    type Aggregate = A;

    type OldInitEvent = A::InitEvent;
    type OldEvent = A::Event;
    type OldStorableDetails = A::StorableCommandDetails;

    fn store_name(&self) -> &str {
        &self.store_name
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_key_value_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }

    fn preparation_aggregate_store(&self) -> &AggregateStore<Self::Aggregate> {
        &self.new_agg_store
    }

    fn convert_init_event(
        &self,
        old_init: Self::OldInitEvent,
        handle: MyHandle,
        actor: String,
        time: Time,
    ) -> UpgradeResult<StoredCommand<Self::Aggregate>> {
        let details = A::StorableCommandDetails::make_init();
        let builder = StoredCommandBuilder::<A>::new(actor, time, handle, 0, details);

        Ok(builder.finish_with_init_event(old_init))
    }

    fn convert_old_command(
        &self,
        old_command: OldStoredCommand<Self::OldStorableDetails>,
        old_effect: UnconvertedEffect<Self::OldEvent>,
        version: u64,
    ) -> UpgradeResult<CommandMigrationEffect<Self::Aggregate>> {
        let new_command_builder = StoredCommandBuilder::<A>::new(
            old_command.actor().clone(),
            old_command.time(),
            old_command.handle().clone(),
            version,
            old_command.details().clone(),
        );

        let new_command = match old_effect {
            UnconvertedEffect::Error { msg } => new_command_builder.finish_with_error(msg),
            UnconvertedEffect::Success { events } => new_command_builder.finish_with_events(events),
        };

        Ok(CommandMigrationEffect::StoredCommand(new_command))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaDefinitionUpdates {
    add_or_replace: Vec<Pre0_14_0AspaDefinition>,
    remove: Vec<CustomerAsn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pre0_14_0ProviderAs {
    pub provider: Asn,
    pub afi_limit: Option<AddressFamily>,
}

impl Pre0_14_0ProviderAs {
    pub fn new(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: None,
        }
    }

    pub fn new_v4(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: Some(AddressFamily::Ipv4),
        }
    }

    pub fn new_v6(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: Some(AddressFamily::Ipv6),
        }
    }
}

//--- FromStr

impl FromStr for Pre0_14_0ProviderAs {
    type Err = <Asn as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Possible options:
        //  AS#
        //  AS#(v4)
        //  AS#(v6)
        if let Some(as_str) = s.strip_suffix("(v4)") {
            Ok(Pre0_14_0ProviderAs::new_v4(Asn::from_str(as_str)?))
        } else if let Some(as_str) = s.strip_suffix("(v6)") {
            Ok(Pre0_14_0ProviderAs::new_v6(Asn::from_str(as_str)?))
        } else {
            Ok(Pre0_14_0ProviderAs::new(Asn::from_str(s)?))
        }
    }
}

//--- Display

impl fmt::Display for Pre0_14_0ProviderAs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.afi_limit {
            None => write!(f, "{}", self.provider),
            Some(family) => {
                let fam_str = match &family {
                    AddressFamily::Ipv4 => "v4",
                    AddressFamily::Ipv6 => "v6",
                };
                write!(f, "{}({})", self.provider, fam_str)
            }
        }
    }
}

//--- Deserialize and Serialize

impl serde::Serialize for Pre0_14_0ProviderAs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Pre0_14_0ProviderAs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        Pre0_14_0ProviderAs::from_str(&string).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaProvidersUpdate {
    added: Vec<Pre0_14_0ProviderAs>,
    removed: Vec<Pre0_14_0ProviderAs>,
}

// //------------ AspaObjectsUpdates ------------------------------------------

// #[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
// pub struct Pre0_14_0AspaObjectsUpdates {
//     #[serde(skip_serializing_if = "Vec::is_empty", default)]
//     updated: Vec<Pre0_14_0AspaInfo>,

//     #[serde(skip_serializing_if = "Vec::is_empty", default)]
//     removed: Vec<CustomerAsn>,
// }

// //------------ Pre0_14_0AspaInfo -------------------------------------------

// #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
// pub struct Pre0_14_0AspaInfo {
//     // The customer ASN and all Provider ASNs
//     definition: Pre0_14_0AspaDefinition,

//     // The validity time for this ASPA.
//     validity: Validity,

//     // The serial number (needed for revocation)
//     serial: Serial,

//     // The URI where this object is expected to be published
//     uri: uri::Rsync,

//     // The actual ASPA object in base64 format.
//     base64: Base64,

//     // The ASPA object's hash
//     hash: Hash,
// }
