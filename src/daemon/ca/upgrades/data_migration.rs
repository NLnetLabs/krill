use std::sync::Arc;
use log::{debug, warn};
use crate::commons::crypto::KrillSignerBuilder;
use crate::constants::CASERVER_NS;
use crate::daemon::ca::certauth::CertAuth;
use crate::daemon::ca::publishing::CaObjectsStore;
use crate::daemon::config::Config;
use crate::upgrades::UpgradeResult;
use crate::upgrades::data_migration::check_agg_store;


pub fn check_ca_objects(config: &Config) -> UpgradeResult<()> {
    let ca_store = check_agg_store::<CertAuth>(config, CASERVER_NS, "CAs")?;

    // make a dummy Signer to use for the CaObjectsStore - it won't be used,
    // but it's needed for construction.
    let probe_interval =
        std::time::Duration::from_secs(config.signer_probe_retry_seconds);
    let signer = Arc::new(
        KrillSignerBuilder::new(
            &config.storage_uri,
            probe_interval,
            &config.signers,
        )
        .with_default_signer(config.default_signer())
        .with_one_off_signer(config.one_off_signer())
        .build()?,
    );

    let ca_objects_store = CaObjectsStore::create(
        &config.storage_uri,
        config.issuance_timing.clone(),
        signer,
    )?;

    let cas_with_objects = ca_objects_store.cas()?;

    for ca in &cas_with_objects {
        ca_objects_store.ca_objects(ca)?;
        if !ca_store.has(ca)? {
            warn!("  Objects found for CA '{}' which no longer exists.", ca);
        }
    }

    for ca in ca_store.list()? {
        if !cas_with_objects.contains(&ca) {
            debug!("  CA '{}' did not have any CA objects yet.", ca);
        }
    }

    Ok(())

}

