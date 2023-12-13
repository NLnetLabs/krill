extern crate krill;

use clap::{App, Arg, ArgMatches, SubCommand};
use log::{info, LevelFilter};

use krill::{
    constants::{KRILL_DEFAULT_CONFIG_FILE, KRILL_UP_APP, KRILL_VERSION},
    daemon::{
        config::{Config, LogType},
        properties::PropertiesManager,
    },
    upgrades::{data_migration::migrate, prepare_upgrade_data_migrations, UpgradeMode},
};
use url::Url;

#[tokio::main]
async fn main() {
    let matches = make_matches();

    match parse_matches(matches) {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
        Ok(mode) => match mode {
            KrillUpMode::Prepare { config } => {
                let properties_manager = match PropertiesManager::create(&config.storage_uri, config.use_history_cache)
                {
                    Ok(mgr) => mgr,
                    Err(e) => {
                        eprintln!("*** Error Preparing Data Migration ***");
                        eprintln!("{}", e);
                        eprintln!();
                        eprintln!("Note that your server data has NOT been modified. Do not upgrade krill itself yet!");
                        eprintln!("If you did upgrade krill, then downgrade it to your previous installed version.");
                        ::std::process::exit(1);
                    }
                };

                match prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, &config, &properties_manager).await {
                    Err(e) => {
                        eprintln!("*** Error Preparing Data Migration ***");
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
                                info!("Prepared and verified upgrade from {} to {}.", from, to,);
                            } else {
                                info!("No preparation is needed for the upgrade from {} to {}.", from, to)
                            }
                        }
                    },
                }
            }
            KrillUpMode::Migrate { config, target } => {
                if let Err(e) = migrate(config, target).await {
                    eprintln!("*** Error Migrating DATA ***");
                    eprintln!("{}", e);
                    eprintln!();
                    eprintln!("Note that your server data has NOT been modified.");
                    ::std::process::exit(1);
                }
            }
        },
    }
}

fn make_matches<'a>() -> ArgMatches<'a> {
    let mut app = App::new(KRILL_UP_APP).version(KRILL_VERSION).about("\nThis tool can be used to reduce the risk and time needed for Krill upgrades, by preparing and verifying any data migrations that would be needed. The data_dir setting from the provided configuration file is used to find the data to migrate, and prepared data will be saved under 'data_dir/upgrade-data'.");

    let mut prep_sub = SubCommand::with_name("prepare")
        .about("Prepares a Krill upgrade data migration if needed by the new Krill version. This operation leaves the current data unmodified. You can run this operation while Krill is running. This tool will exit and report an error in case of any issues. To finish the migration, restart Krill. The migration process will continue to ensure it includes any changes after the preparation.");
    prep_sub = add_config_arg(prep_sub);
    app = app.subcommand(prep_sub);

    let mut migrate_sub = SubCommand::with_name("migrate")
        .about("Migrate Krill data to a different storage. Stop Krill before running this tool to ensure data does not change during migration. The original data in the storage defined in the config file is not modified. If your current data is for an older version of Krill, this tool will attempt to upgrade it. After successful migration, you can reconfigure Krill to use the new data storage and restart it.");
    migrate_sub = add_config_arg(migrate_sub);
    migrate_sub = add_new_storage_arg(migrate_sub);
    app = app.subcommand(migrate_sub);

    app.get_matches()
}

fn add_config_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Override the path to the config file (default: '/etc/krill.conf').")
            .required(false),
    )
}

fn add_new_storage_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("target")
            .short("t")
            .long("target")
            .value_name("URL")
            .help("Provide the target storage URI string. E.g. local:///var/lib/krill or postgres://postgres@localhost/postgres.")
            .required(true),
    )
}

fn parse_matches(matches: ArgMatches) -> Result<KrillUpMode, String> {
    if let Some(m) = matches.subcommand_matches("prepare") {
        let config = parse_config(m)?;
        Ok(KrillUpMode::Prepare { config })
    } else if let Some(m) = matches.subcommand_matches("migrate") {
        let target_str = m.value_of("target").ok_or("--target missing".to_string())?;
        let target = Url::parse(target_str).map_err(|e| format!("cannot parse url: {}. Error: {}", target_str, e))?;

        let config = parse_config(m)?;
        Ok(KrillUpMode::Migrate { config, target })
    } else {
        Err("Cannot parse arguments. Use --help.".to_string())
    }
}

fn parse_config(m: &ArgMatches) -> Result<Config, String> {
    let config_file = m.value_of("config").unwrap_or(KRILL_DEFAULT_CONFIG_FILE);
    let mut config = Config::create(config_file, true)
        .map_err(|e| format!("Cannot parse config file '{}'. Error: {}", config_file, e))?;

    config.log_level = LevelFilter::Info;
    config.log_type = LogType::Stderr;

    Ok(config)
}

enum KrillUpMode {
    Prepare { config: Config },
    Migrate { config: Config, target: Url },
}
