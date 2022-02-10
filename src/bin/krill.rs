extern crate krill;

use std::sync::Arc;

use krill::{
    daemon::http::server,
    upgrades::{prepare_upgrade_data_migrations, UpgradeMode},
};
use log::{error, info};

#[tokio::main]
async fn main() {
    match server::parse_config() {
        Ok(config) => {
            if config.prepare_upgrade_only {
                match prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, Arc::new(config)).await {
                    Err(e) => {
                        error!("{}", e);
                        ::std::process::exit(1);
                    }
                    Ok(opt) => match opt {
                        None => {
                            info!("No update needed");
                        }
                        Some(upgrade) => {
                            info!(
                                "Prepared upgrade from {} to {}. You can now restart krill to finish the migration",
                                upgrade.from(),
                                upgrade.to()
                            );
                        }
                    },
                }
            } else if let Err(e) = server::start_krill_daemon(Arc::new(config)).await {
                error!("Krill failed to start: {}", e);
                ::std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Could not parse config: {}", e);
            ::std::process::exit(1);
        }
    }
}
