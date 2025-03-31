use crate::server::pubd::access::{
    RepositoryAccess, RepositoryAccessEvent, RepositoryAccessInitEvent
};
use crate::upgrades::pre_0_14_0::{
    GenericUpgradeAggregateStore, OldStoredEvent,
};

pub type OldRepositoryAccessInitEvent =
    OldStoredEvent<RepositoryAccessInitEvent>;
pub type OldRepositoryAccessEvent = OldStoredEvent<RepositoryAccessEvent>;

pub type UpgradeAggregateStoreRepositoryAccess =
    GenericUpgradeAggregateStore<RepositoryAccess>;
