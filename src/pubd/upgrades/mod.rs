//! Data migration for the publication server.

pub mod pre_0_10_0;
pub mod pre_0_13_0;
pub mod pre_0_14_0;


use log::info;
use rpki::ca::idexchange::MyHandle;
use crate::commons::KrillResult;
use crate::commons::eventsourcing::WalStore;
use crate::commons::storage::{Key, KeyValueStore, Segment, Scope};
use crate::constants::PUBSERVER_CONTENT_NS;
use crate::daemon::config::Config;
use crate::pubd::content::RepositoryContent;
use self::pre_0_13_0::OldRepositoryContent;


/// Migrate v0.12.x RepositoryContent to the new 0.13.0+ format.
/// Apply any open WAL changes to the source first.
pub fn migrate_0_12_pubd_objects(config: &Config) -> KrillResult<bool> {
    let old_store: WalStore<OldRepositoryContent> =
        WalStore::create(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
    let repo_content_handle = MyHandle::new("0".into());

    if old_store.has(&repo_content_handle)? {
        let old_repo_content =
            old_store.get_latest(&repo_content_handle)?.as_ref().clone();
        let repo_content: RepositoryContent =
            old_repo_content.try_into()?;
        let new_key = Key::new_scoped(
            Scope::from_segment(const { Segment::make("0") }),
            const { Segment::make("snapshot.json") },
        );
        let upgrade_store = KeyValueStore::create_upgrade_store(
            &config.storage_uri,
            PUBSERVER_CONTENT_NS,
        )?;
        upgrade_store.store(&new_key, &repo_content)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// The format of the RepositoryContent did not change in 0.12, but
/// the location and way of storing it did. So, migrate if present.
pub fn migrate_pre_0_12_pubd_objects(config: &Config) -> KrillResult<()> {
    let old_store =
        KeyValueStore::create(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
    let old_key = Key::new_global(const { Segment::make("0.json") });
    if let Ok(Some(old_repo_content)) =
        old_store.get::<OldRepositoryContent>(&old_key)
    {
        info!("Found pre 0.12.0 RC2 publication server data. Migrating..");
        let repo_content: RepositoryContent =
            old_repo_content.try_into()?;

        let new_key = Key::new_scoped(
            Scope::from_segment(const { Segment::make("0") }),
            const { Segment::make("snapshot.json") },
        );
        let upgrade_store = KeyValueStore::create_upgrade_store(
            &config.storage_uri,
            PUBSERVER_CONTENT_NS,
        )?;
        upgrade_store.store(&new_key, &repo_content)?;
    }

    Ok(())
}

