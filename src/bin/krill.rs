extern crate krill;

use std::env;
use std::sync::Arc;

use krill::commons::api::PublicationServerUris;
use krill::commons::error::Error;
use krill::constants::{KRILL_ENV_TESTBED_RRDP, KRILL_ENV_TESTBED_RSYNC};
use krill::daemon::http::server;
use krill::daemon::krillserver::KrillMode;
use rpki::uri;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    match server::parse_config() {
        Ok(config) => {
            let mut mode = KrillMode::Ca;

            if env::var(KRILL_ENV_TESTBED_RRDP).is_ok() || env::var(KRILL_ENV_TESTBED_RSYNC).is_ok() {
                match extract_testbed_uris() {
                    Ok(uris) => {
                        mode = KrillMode::Testbed(uris);
                    }
                    Err(e) => {
                        eprintln!("Incorrect URI(s) specified for testbed: {}", e);
                        ::std::process::exit(1)
                    }
                }
            }

            if let Err(e) = server::start_krill_daemon(Arc::new(config), mode).await {
                eprintln!("Krill failed to start: {}", e);
                ::std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Could not parse config: {}", e);
            ::std::process::exit(1);
        }
    }
}

fn extract_testbed_uris() -> Result<PublicationServerUris, Error> {
    let rsync_string = env::var(KRILL_ENV_TESTBED_RSYNC).map_err(|_| {
        Error::Custom(format!(
            "TESTBED requested RSYNC env variable missing, set rsync base uri in {}",
            KRILL_ENV_TESTBED_RSYNC
        ))
    })?;

    if !rsync_string.ends_with('/') {
        return Err(Error::custom("Testbed rsync base uri MUST end with '/'"));
    }

    let rsync = uri::Rsync::from_str(&rsync_string)
        .map_err(|_| Error::Custom(format!("Invalid rsync base uri: {}", rsync_string)))?;

    let rrdp_string = env::var(KRILL_ENV_TESTBED_RRDP).map_err(|_| {
        Error::Custom(format!(
            "TESTBED requested RRDP env variable missing, set uri in {}",
            KRILL_ENV_TESTBED_RRDP
        ))
    })?;

    if !rrdp_string.ends_with('/') {
        return Err(Error::custom("Testbed RRDP uri MUST end with '/'"));
    }

    let rrdp =
        uri::Https::from_str(&rrdp_string).map_err(|_| Error::Custom(format!("Invalid RRPD uri: {}", rrdp_string)))?;

    Ok(PublicationServerUris::new(rrdp, rsync))
}
