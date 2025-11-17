//! Support data migrations from one KV storage type to another.

use std::{str::FromStr};

use log::info;
use rpki::crypto::KeyIdentifier;
use url::Url;

use crate::{
    commons::{
        crypto::{
            dispatch::signerinfo::SignerInfo,
            OpenSslSigner, OpenSslSignerConfig,
        },
        eventsourcing::{
            Aggregate, AggregateStore, WalStore, WalSupport,
        },
        storage::{Ident, StorageSystem},
    },
    constants::{
        KEYS_NS, PROPERTIES_NS, PUBSERVER_CONTENT_NS,
        PUBSERVER_NS, SIGNERS_NS, TA_PROXY_SERVER_NS, TA_SIGNER_SERVER_NS,
    },
    config::Config,
    server::{
        ca::upgrades::data_migration::check_ca_objects,
        properties::{Properties, PropertiesManager},
        pubd::{RepositoryAccess, RepositoryContent},
    },
    server::taproxy::TrustAnchorProxy,
    upgrades::{
        finalise_data_migration, prepare_upgrade_data_migrations,
        UpgradeError,
    },
    tasigner::TrustAnchorSigner,
};

use super::UpgradeResult;

pub fn migrate(
    config: Config, target_storage: &StorageSystem
) -> UpgradeResult<()> {
    // Copy the source data from config unmodified into the target_storage
    info!("-----------------------------------------------------------");
    info!("                 Krill Data Migration");
    info!("-----------------------------------------------------------");
    info!("");
    info!("-----------------------------------------------------------");
    info!("STEP 1: Copy data");
    info!("");
    info!("From: {}", &config.storage_uri);
    info!("  To:   {}", &target_storage.default_uri());
    info!("-----------------------------------------------------------");
    info!("");

    copy_data_for_migration(target_storage, &config.storage_uri)?;

    // Perform a normal data migration using the target storage - the source
    // data could be for an older version of Krill.
    let properties_manager = PropertiesManager::create(
        target_storage, false
    )?;

    info!("-----------------------------------------------------------");
    info!("STEP 2: Upgrade data to current Krill version (if needed)");
    info!("-----------------------------------------------------------");
    info!("");
    if let Some(upgrade) = prepare_upgrade_data_migrations(
        crate::upgrades::UpgradeMode::PrepareToFinalise,
        target_storage,
        &config,
        &properties_manager,
    )? {
        finalise_data_migration(
            upgrade.versions(),
            target_storage,
            &properties_manager,
        )?;
    }

    info!("-----------------------------------------------------------");
    info!("STEP 3: Verify data in target store");
    info!("");
    info!("We verify the data by warming the cache for different types");
    info!("of data managed by Krill, without actually starting Krill.");
    info!("-----------------------------------------------------------");
    info!("");
    //
    // This step should not be needed, because:
    // - upgrades (if there was one) already verify the data
    // - if there was no upgrade, the data was not changed and there is
    //   nothing we can do here.
    //
    // That said, it's a pretty easy check to perform and it kind of makes
    // sense to do it to now, even if it would be to point users at deeper
    // source data issues.
    verify_target_data(target_storage, &config)
}

fn verify_target_data(
    storage: &StorageSystem, config: &Config
) -> UpgradeResult<()> {
    check_agg_store::<Properties>(storage, PROPERTIES_NS, "Properties")?;
    check_agg_store::<SignerInfo>(storage, SIGNERS_NS, "Signer")?;

    check_ca_objects(storage, config)?;

    check_agg_store::<RepositoryAccess>(
        storage,
        PUBSERVER_NS,
        "Publication Server Access",
    )?;
    check_wal_store::<RepositoryContent>(
        storage,
        PUBSERVER_CONTENT_NS,
        "Publication Server Objects",
    )?;
    check_agg_store::<TrustAnchorProxy>(
        storage,
        TA_PROXY_SERVER_NS,
        "TA Proxy",
    )?;
    check_agg_store::<TrustAnchorSigner>(
        storage,
        TA_SIGNER_SERVER_NS,
        "TA Signer",
    )?;

    check_openssl_keys(storage)?;

    Ok(())
}

fn check_openssl_keys(storage: &StorageSystem) -> UpgradeResult<()> {
    info!("");
    info!("Verify: OpenSSL keys");
    // XXX This seems to assume that OpenSSL keys are always in the store?
    let open_ssl_signer = OpenSslSigner::build(
        storage, &OpenSslSignerConfig::default(), "test", None,
    ).map_err(|e| {
        UpgradeError::Custom(format!("Cannot create openssl signer: {e}"))
    })?;
    let keys_key_store = storage.open(KEYS_NS)?;

    for key in keys_key_store.keys(None, "")? {
        let key_id =
            KeyIdentifier::from_str(key.as_str()).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Cannot parse as key identifier: {key}. Error: {e}"
                ))
            })?;
        open_ssl_signer.get_key_info(&key_id).map_err(|e| {
            UpgradeError::Custom(format!(
                "Cannot get key with key_id {key_id} from openssl keystore. Error: {e}"
            ))
        })?;
    }
    info!("Ok");

    Ok(())
}

pub fn check_agg_store<A: Aggregate>(
    storage: &StorageSystem,
    ns: &Ident,
    name: &str,
) -> UpgradeResult<AggregateStore<A>> {
    info!("");
    info!("Verify: {name}");
    let store: AggregateStore<A> = AggregateStore::create(
        storage, ns, false
    )?;
    if !store.list()?.is_empty() {
        store.warm()?;
        info!("Ok");
    } else {
        info!("not applicable");
    }
    Ok(store)
}

fn check_wal_store<W: WalSupport>(
    storage: &StorageSystem,
    ns: &Ident,
    name: &str,
) -> UpgradeResult<()> {
    info!("");
    info!("Verify: {name}");
    let store: WalStore<W> = WalStore::create(storage, ns)?;
    if !store.list()?.is_empty() {
        store.warm()?;
        info!("Ok");
    } else {
        info!("not applicable");
    }
    Ok(())
}

fn copy_data_for_migration(
    target_storage: &StorageSystem,
    source_storage: &Url,
) -> UpgradeResult<()> {
    const NAMESPACES: &[&Ident] = &[
        Ident::make("ca_objects"),
        Ident::make("cas"),
        Ident::make("keys"),
        Ident::make("pubd"),
        Ident::make("pubd_objects"),
        Ident::make("signers"),
        Ident::make("status"),
        Ident::make("ta_proxy"),
        Ident::make("ta_signer"),
    ];
    for namespace in NAMESPACES {
        let source_kv_store = target_storage.open_uri(
            source_storage, namespace
        )?;
        if !source_kv_store.is_empty()? {
            let target_kv_store = target_storage.open(namespace)?;
            target_kv_store.import(&source_kv_store)?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;
    use log::LevelFilter;
    use crate::commons::test;
    use super::*;

    #[test]
    fn test_data_migration() {
        // Create a config file that uses test data for its storage_uri
        let test_sources_base = "test-resources/migrations/v0_9_5/";
        let test_sources_url =
            Url::parse(&format!("local://{test_sources_base}")).unwrap();

        let bogus_path = PathBuf::from("/dev/null"); // needed for tls_dir etc, but will be ignored here
        let mut config = Config::test(
            &test_sources_url,
            Some(&bogus_path),
            false,
            false,
            false,
            false,
        );
        config.log_level = LevelFilter::Info;

        let _ = config.init_logging();

        // Create an in-memory target store to migrate to
        let target_store = test::mem_storage();

        migrate(config, &target_store).unwrap();
    }
}

