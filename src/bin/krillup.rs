extern crate krill;

use std::sync::Arc;

use clap::{App, Arg};
use log::info;

use krill::{
    constants::{KRILL_DEFAULT_CONFIG_FILE, KRILL_UP_APP, KRILL_VERSION},
    daemon::config::Config,
    upgrades::{prepare_upgrade_data_migrations, UpgradeMode},
};

#[tokio::main]
async fn main() {
    let matches = App::new(KRILL_UP_APP)
        .version(KRILL_VERSION)
        .about("\nThis tool can be used to reduce the risk and time needed for Krill upgrades, by preparing and verifying any data migrations that would be needed. The data_dir setting from the provided configuration file is used to find the data to migrate, and prepared data will be saved under 'data_dir/upgrade-data'.")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help(&format!(
                    "Override the path to the config file (default: '{}')",
                    KRILL_DEFAULT_CONFIG_FILE
                ))
                .required(false),
        )
        .get_matches();

    let config_file = matches.value_of("config").unwrap_or(KRILL_DEFAULT_CONFIG_FILE);

    match Config::create(config_file, true) {
        Ok(config) => {
            let config = Arc::new(config);
            match prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, config.clone()) {
                Err(e) => {
                    eprintln!("*** Error Preparing Date Migration ***");
                    eprintln!("{}", e);
                    eprintln!();
                    eprintln!("Note that your server data has NOT been modified. Do not upgrade krill itself yet!");
                    eprintln!("If you did upgrade krill, then downgrade it to your previous installed version.");
                    ::std::process::exit(1);
                }
                Ok(opt) => match opt {
                    None => {
                        info!("No update needed");
                    }
                    Some(report) => {
                        let from = report.versions().from();
                        let to = report.versions().to();
                        if report.data_migration() {
                            info!(
                                "Prepared and verified upgrade from {} to {}. Prepared data was saved to: {}",
                                from,
                                to,
                                config.upgrade_data_dir().to_string_lossy()
                            );
                        } else {
                            info!("No preparation is needed for the upgrade from {} to {}.", from, to)
                        }
                    }
                },
            }
        }
        Err(e) => {
            eprintln!("Could not parse config: {}", e);
            ::std::process::exit(1);
        }
    }
}
