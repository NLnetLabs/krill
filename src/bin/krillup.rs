//! Krill data migration tool.

use std::process;
use std::path::PathBuf;
use clap::Parser;
use log::info;
use log::LevelFilter;
use url::Url;
use krill::constants;
use krill::commons::storage::StorageSystem;
use krill::config::{Config, LogType};
use krill::server::properties::PropertiesManager;
use krill::upgrades::{prepare_upgrade_data_migrations, UpgradeMode};
use krill::upgrades::data_migration::migrate;


//------------ main ----------------------------------------------------------

fn main() {
    let options = Options::parse();

    // Load config.
    let mut config = match Config::create(&options.config, true) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Failed to read config file '{}': {}'",
                options.config.display(), err
            );
            process::exit(1);
        }
    };
    config.log_level = LevelFilter::Info;
    config.log_type = LogType::Stderr;

    match options.command {
        Command::Prepare(_prepare) => {
            let storage = match StorageSystem::new(
                config.storage_uri.clone()
            ) {
                Ok(storage) => storage,
                Err(err) => {
                    eprintln!("*** Error Preparing Data Migration ***");
                    eprintln!("Cannot connect to storage system: {err}");
                    eprintln!();
                    eprintln!(
                        "Note that your server data has NOT been modified. \
                         Do not upgrade krill"
                    );
                    eprintln!("itself yet!");
                    eprintln!(
                        "If you did upgrade krill, then downgrade it to \
                         the previous installed version."
                    );
                    ::std::process::exit(1);
                }
            };
            let properties_manager = match PropertiesManager::create(
                &storage, config.use_history_cache,
            ) {
                Ok(mgr) => mgr,
                Err(e) => {
                    eprintln!("*** Error Preparing Data Migration ***");
                    eprintln!("{e}");
                    eprintln!();
                    eprintln!(
                        "Note that your server data has NOT been modified. \
                         Do not upgrade krill"
                    );
                    eprintln!("itself yet!");
                    eprintln!(
                        "If you did upgrade krill, then downgrade it to \
                         the previous installed version."
                    );
                    ::std::process::exit(1);
                }
            };

            match prepare_upgrade_data_migrations(
                UpgradeMode::PrepareOnly,
                &storage,
                &config,
                &properties_manager,
            ) {
                Err(e) => {
                    eprintln!("*** Error Preparing Data Migration ***");
                    eprintln!("{e}");
                    eprintln!();
                    eprintln!(
                        "Note that your server data has NOT been modified. \
                         Do not upgrade krill"
                    );
                    eprintln!("itself yet!");
                    eprintln!(
                        "If you did upgrade krill, then downgrade it to \
                         the previous installed version."
                    );
                    ::std::process::exit(1);
                }
                Ok(None) => info!("No update needed"),
                Ok(Some(report)) => {
                    let from = report.versions().from();
                    let to = report.versions().to();
                    if report.data_migration() {
                        info!(
                            "Prepared and verified upgrade from {from} to {to}."
                        );
                    } else {
                        info!(
                            "No preparation is needed for the upgrade from \
                             {from} to {to}."
                        )
                    }
                },
            }
        }
        Command::Migrate(cmd) => {
            let storage = match StorageSystem::new(cmd.target) {
                Ok(storage) => storage,
                Err(err) => {
                    eprintln!("*** Error Migrating DATA ***");
                    eprintln!("Cannot connect to storage system: {err}");
                    eprintln!(
                        "Note that your server data has NOT been modified."
                    );
                    eprintln!();
                    ::std::process::exit(1);
                }
            };

            if let Err(e) = migrate(config, &storage) {
                eprintln!("*** Error Migrating DATA ***");
                eprintln!("{e}");
                eprintln!();
                eprintln!(
                    "Note that your server data has NOT been modified."
                );
                ::std::process::exit(1);
            }
        }
    }
}


//------------ Options -------------------------------------------------------

/// The command line options for the krillup command.
#[derive(clap::Parser)]
#[command(
    version,
    about = "Krill data migration tool",
)]
pub struct Options {
    /// Path to the Krill config file
    #[arg(
        short, long,
        value_name = "path",
        default_value = constants::KRILL_DEFAULT_CONFIG_FILE,
    )]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Prepare a migration, leave current data unmodified
    Prepare(Prepare),

    /// Migrate data to different storage. Stop Krill before use!
    Migrate(Migrate),
}


//------------ Prepare -------------------------------------------------------

#[derive(clap::Args)]
pub struct Prepare;


//------------ Migrate -------------------------------------------------------

#[derive(clap::Args)]
pub struct Migrate {
    /// The storage target as a URI string.
    #[arg(short, long, value_name = "URI")]
    pub target: Url,
}

