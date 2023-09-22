//! Runtime configuration settings and properties
//!
//! Uses an event-sourced structure so that:
//! - These can be shared between multiple nodes
//! - An audit trail is provided
//!
//! For now this is used to track the current Krill version for
//! the stored data in one place only. This will also allow multiple
//! Krill instances to compare their own version to the shared storage.
//! This can then be used to trigger upgrades. Furthermore, we can use
//! this to stop (or refuse to start) instances that are behind the
//! the storage version.
//!
//! In future we can extend this structure to include other runtime
//! properties that need to be shared between nodes. E.g. timing
//! parameters used for issuing certificates and ROAs etc.

use std::{fmt, str::FromStr, sync::Arc};

use rpki::ca::idexchange::MyHandle;
use url::Url;

use crate::{
    commons::{
        actor::Actor,
        api::CommandSummary,
        error::Error,
        eventsourcing::{
            self, Aggregate, AggregateStore, Event, InitCommandDetails, InitEvent, SentCommand, SentInitCommand,
            WithStorableDetails,
        },
        util::KrillVersion,
        KrillResult,
    },
    constants::{PROPERTIES_DFLT_NAME, PROPERTIES_NS},
};

//------------ PropertiesInitCommand ---------------------------------------
pub type PropertiesInitCommand = SentInitCommand<PropertiesInitCommandDetails>;

//------------ PropertiesInitCommandDetails --------------------------------
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PropertiesInitCommandDetails {
    pub krill_version: KrillVersion,
}

impl fmt::Display for PropertiesInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for PropertiesInitCommandDetails {
    type StorableDetails = StorablePropertiesCommand;

    fn store(&self) -> Self::StorableDetails {
        StorablePropertiesCommand::make_init()
    }
}

//------------ PropertiesCommand -------------------------------------------
pub type PropertiesCommand = SentCommand<PropertiesCommandDetails>;

//------------ PropertiesCommandDetails ------------------------------------
#[derive(Clone, Debug)]
pub enum PropertiesCommandDetails {
    UpgradeTo { krill_version: KrillVersion },
}

impl fmt::Display for PropertiesCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorablePropertiesCommand::from(self).fmt(f)
    }
}

//------------ StorablePropertiesCommand -----------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum StorablePropertiesCommand {
    Init,
    UpgradeTo { krill_version: KrillVersion },
}

impl fmt::Display for StorablePropertiesCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Init => {
                write!(f, "initialise properties")
            }
            Self::UpgradeTo { krill_version: version } => {
                write!(f, "upgrade Krill to {version}")
            }
        }
    }
}

impl eventsourcing::CommandDetails for PropertiesCommandDetails {
    type Event = PropertiesEvent;

    type StorableDetails = StorablePropertiesCommand;

    fn store(&self) -> Self::StorableDetails {
        self.into()
    }
}

impl From<&PropertiesCommandDetails> for StorablePropertiesCommand {
    fn from(details: &PropertiesCommandDetails) -> Self {
        match details {
            PropertiesCommandDetails::UpgradeTo { krill_version } => StorablePropertiesCommand::UpgradeTo {
                krill_version: krill_version.clone(),
            },
        }
    }
}

impl eventsourcing::WithStorableDetails for StorablePropertiesCommand {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        match self {
            StorablePropertiesCommand::Init => CommandSummary::new("cmd-properties-init", self),
            StorablePropertiesCommand::UpgradeTo { krill_version } => {
                CommandSummary::new("cmd-properties-krill-upgrade", self).with_arg("version", krill_version)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

//------------ PropertiesEvent ---------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum PropertiesEvent {
    KrillVersionUpgraded { old: KrillVersion, new: KrillVersion },
}

impl Event for PropertiesEvent {}

impl fmt::Display for PropertiesEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PropertiesEvent::KrillVersionUpgraded { old, new } => {
                write!(f, "upgraded Krill from {old} to {new}")
            }
        }
    }
}

//------------ PropertiesInitEvent -----------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PropertiesInitEvent {
    krill_version: KrillVersion,
}

impl InitEvent for PropertiesInitEvent {}

impl fmt::Display for PropertiesInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "initialised Krill version {}", self.krill_version)
    }
}

//------------ Properties --------------------------------------------------

/// Runtime properties used by the server
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Properties {
    handle: MyHandle,
    version: u64,

    krill_version: KrillVersion,
}

impl Aggregate for Properties {
    type Command = PropertiesCommand;
    type StorableCommandDetails = StorablePropertiesCommand;
    type Event = PropertiesEvent;

    type InitCommand = PropertiesInitCommand;
    type InitEvent = PropertiesInitEvent;

    type Error = Error;

    fn init(handle: MyHandle, event: PropertiesInitEvent) -> Self {
        Properties {
            handle,
            version: 1, // init for 0 was applied
            krill_version: event.krill_version,
        }
    }

    fn process_init_command(command: PropertiesInitCommand) -> Result<Self::InitEvent, Self::Error> {
        Ok(PropertiesInitEvent {
            krill_version: command.into_details().krill_version,
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
            PropertiesEvent::KrillVersionUpgraded { new, .. } => self.krill_version = new,
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Sending command to Properties '{}', version: {}: {}",
                self.handle,
                self.version,
                command
            );
        }

        match command.into_details() {
            PropertiesCommandDetails::UpgradeTo { krill_version } => {
                // We can only upgrade to a newer version.
                if krill_version > self.krill_version {
                    Ok(vec![PropertiesEvent::KrillVersionUpgraded {
                        old: self.krill_version.clone(),
                        new: krill_version,
                    }])
                } else {
                    Err(Error::Custom(format!(
                        "Can only upgrade Krill to newer versions. Current version: {}, Requested version: {}",
                        self.krill_version, krill_version
                    )))
                }
            }
        }
    }
}

//------------ PropertiesManager -------------------------------------------

/// Convenience manager for the single Properties instance used by Krill
pub struct PropertiesManager {
    store: AggregateStore<Properties>,
    main_key: MyHandle,

    // System actor is used for (scheduled or triggered) system actions where
    // we have no operator actor context.
    system_actor: Actor,
}

impl PropertiesManager {
    pub fn create(storage_uri: &Url, use_history_cache: bool) -> KrillResult<Self> {
        let main_key = MyHandle::from_str(PROPERTIES_DFLT_NAME).unwrap();
        AggregateStore::create(storage_uri, PROPERTIES_NS, use_history_cache)
            .map(|store| PropertiesManager {
                store,
                main_key,
                system_actor: Actor::system_actor(),
            })
            .map_err(Error::AggregateStoreError)
    }

    pub fn is_initialized(&self) -> bool {
        self.store.has(&self.main_key).unwrap_or_default()
    }

    pub fn init(&self, krill_version: KrillVersion) -> KrillResult<Arc<Properties>> {
        let cmd = PropertiesInitCommand::new(
            &self.main_key,
            PropertiesInitCommandDetails { krill_version },
            &self.system_actor,
        );
        self.store.add(cmd)
    }

    /// Returns the current KrillVersion used for the data store
    pub fn current_krill_version(&self) -> KrillResult<KrillVersion> {
        self.properties().map(|p| p.krill_version.clone())
    }

    /// Upgrade the KrillVersion
    pub fn upgrade_krill_version(&self, krill_version: KrillVersion) -> KrillResult<()> {
        let cmd = PropertiesCommand::new(
            &self.main_key,
            None,
            PropertiesCommandDetails::UpgradeTo { krill_version },
            &self.system_actor,
        );
        self.store.command(cmd)?;
        Ok(())
    }

    fn properties(&self) -> KrillResult<Arc<Properties>> {
        self.store.get_latest(&self.main_key)
    }
}

//--------- Tests
#[cfg(test)]
mod tests {

    use super::*;

    use crate::test;

    #[test]
    fn init_properties() {
        test::test_in_memory(|storage_uri| {
            let properties_mgr = PropertiesManager::create(storage_uri, false).unwrap();

            // Should not be initialised on first use.
            assert!(!properties_mgr.is_initialized());

            // We can initialise the properties to a given krill release.
            let init_version = KrillVersion::release(0, 13, 0);
            properties_mgr.init(init_version.clone()).unwrap();
            assert_eq!(init_version, properties_mgr.current_krill_version().unwrap());

            // Then we can upgrade the release
            let updated_version = KrillVersion::release(0, 14, 0);
            properties_mgr.upgrade_krill_version(updated_version.clone()).unwrap();
            assert_eq!(updated_version, properties_mgr.current_krill_version().unwrap());

            // We cannot downgrade
            let downgrade_version = KrillVersion::release(0, 13, 99);
            assert!(downgrade_version < properties_mgr.current_krill_version().unwrap());
            assert!(properties_mgr.upgrade_krill_version(downgrade_version).is_err());
        })
    }
}
