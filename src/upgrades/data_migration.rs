//! Support data migrations from one KV storage type to another.

use std::{str::FromStr};

use log::info;
use rpki::crypto::KeyIdentifier;
use url::Url;

use crate::{
    commons::{
        crypto::{
            dispatch::signerinfo::SignerInfo,
            OpenSslSigner,
        },
        eventsourcing::{
            Aggregate, AggregateStore, WalStore, WalSupport,
        },
        storage::{KeyValueStore, Namespace, Scope},
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

pub fn migrate(mut config: Config, target_storage: Url) -> UpgradeResult<()> {
    // Copy the source data from config unmodified into the target_storage
    info!("-----------------------------------------------------------");
    info!("                 Krill Data Migration");
    info!("-----------------------------------------------------------");
    info!("");
    info!("-----------------------------------------------------------");
    info!("STEP 1: Copy data");
    info!("");
    info!("From: {}", &config.storage_uri);
    info!("  To:   {}", &target_storage);
    info!("-----------------------------------------------------------");
    info!("");

    copy_data_for_migration(&config, &target_storage)?;

    // Update the config file with the new target_storage
    // and perform a normal data migration - the source data
    // could be for an older version of Krill.
    config.storage_uri = target_storage;
    let properties_manager =
        PropertiesManager::create(&config.storage_uri, false)?;

    info!("-----------------------------------------------------------");
    info!("STEP 2: Upgrade data to current Krill version (if needed)");
    info!("-----------------------------------------------------------");
    info!("");
    if let Some(upgrade) = prepare_upgrade_data_migrations(
        crate::upgrades::UpgradeMode::PrepareToFinalise,
        &config,
        &properties_manager,
    )? {
        finalise_data_migration(
            upgrade.versions(),
            &config,
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
    verify_target_data(&config)
}

fn verify_target_data(config: &Config) -> UpgradeResult<()> {
    check_agg_store::<Properties>(config, PROPERTIES_NS, "Properties")?;
    check_agg_store::<SignerInfo>(config, SIGNERS_NS, "Signer")?;

    check_ca_objects(config)?;

    check_agg_store::<RepositoryAccess>(
        config,
        PUBSERVER_NS,
        "Publication Server Access",
    )?;
    check_wal_store::<RepositoryContent>(
        config,
        PUBSERVER_CONTENT_NS,
        "Publication Server Objects",
    )?;
    check_agg_store::<TrustAnchorProxy>(
        config,
        TA_PROXY_SERVER_NS,
        "TA Proxy",
    )?;
    check_agg_store::<TrustAnchorSigner>(
        config,
        TA_SIGNER_SERVER_NS,
        "TA Signer",
    )?;

    check_openssl_keys(config)?;

    Ok(())
}

fn check_openssl_keys(config: &Config) -> UpgradeResult<()> {
    info!("");
    info!("Verify: OpenSSL keys");
    let open_ssl_signer = OpenSslSigner::build(
        &config.storage_uri,
        "test",
        None,
    )
    .map_err(|e| {
        UpgradeError::Custom(format!("Cannot create openssl signer: {e}"))
    })?;
    let keys_key_store = KeyValueStore::create(&config.storage_uri, KEYS_NS)?;

    for key in keys_key_store.keys(&Scope::global(), "")? {
        let key_id =
            KeyIdentifier::from_str(key.name().as_str()).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Cannot parse as key identifier: {}. Error: {}",
                    key.name().as_str(),
                    e
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
    config: &Config,
    ns: &Namespace,
    name: &str,
) -> UpgradeResult<AggregateStore<A>> {
    info!("");
    info!("Verify: {name}");
    let store: AggregateStore<A> =
        AggregateStore::create(&config.storage_uri, ns, false)?;
    if !store.list()?.is_empty() {
        store.warm()?;
        info!("Ok");
    } else {
        info!("not applicable");
    }
    Ok(store)
}

fn check_wal_store<W: WalSupport>(
    config: &Config,
    ns: &Namespace,
    name: &str,
) -> UpgradeResult<()> {
    info!("");
    info!("Verify: {name}");
    let store: WalStore<W> = WalStore::create(&config.storage_uri, ns)?;
    if !store.list()?.is_empty() {
        store.warm()?;
        info!("Ok");
    } else {
        info!("not applicable");
    }
    Ok(())
}

fn copy_data_for_migration(
    config: &Config,
    target_storage: &Url,
) -> UpgradeResult<()> {
    for ns in &[
        "ca_objects",
        "cas",
        "keys",
        "pubd",
        "pubd_objects",
        "signers",
        "status",
        "ta_proxy",
        "ta_signer",
    ] {
        let namespace = Namespace::parse(ns).map_err(|_| {
            UpgradeError::Custom(format!(
                "Cannot parse namespace '{ns}'. This is a bug."
            ))
        })?;
        let source_kv_store =
            KeyValueStore::create(&config.storage_uri, namespace)?;
        if !source_kv_store.is_empty()? {
            let target_kv_store =
                KeyValueStore::create(target_storage, namespace)?;
            target_kv_store.import(
                &source_kv_store,
                |scope| {
                    match scope.first_segment() {
                        Some(segment) => segment.as_str() != ".locks",
                        None => true
                    }
                }
            )?;
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

        migrate(config, target_store).unwrap();
    }
}

