use log::{debug, warn};
use crate::constants::CASERVER_NS;
use crate::server::ca::certauth::CertAuth;
use crate::server::ca::publishing::CaObjectsStore;
use crate::config::Config;
use crate::upgrades::UpgradeResult;
use crate::upgrades::data_migration::check_agg_store;


pub fn check_ca_objects(config: &Config) -> UpgradeResult<()> {
    let ca_store = check_agg_store::<CertAuth>(config, CASERVER_NS, "CAs")?;
    let ca_objects_store = CaObjectsStore::create(
        &config.storage_uri,
    )?;

    let cas_with_objects = ca_objects_store.cas()?;

    for ca in &cas_with_objects {
        ca_objects_store.ca_objects(ca)?;
        if !ca_store.has(ca)? {
            warn!("  Objects found for CA '{ca}' which no longer exists.");
        }
    }

    for ca in ca_store.list()? {
        if !cas_with_objects.contains(&ca) {
            debug!("  CA '{ca}' did not have any CA objects yet.");
        }
    }

    Ok(())

}

