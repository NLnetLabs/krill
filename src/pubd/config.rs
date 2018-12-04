use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use clap::{App, Arg};
use ext_serde;
use toml;
use rpki::uri;


/// Global configuration for the RRDP Server.
///
/// This will parse a default config file ('./defaults/server.toml') unless
/// another file is explicitly specified. Command line arguments may be used
/// to override any of the settings in the config file.
#[derive(Debug, Deserialize)]
pub struct Config {
    ip: IpAddr,
    port: u16,
    data_dir: PathBuf,
    pub_xml_dir: PathBuf,

    #[serde(deserialize_with = "ext_serde::de_rsync_uri")]
    rsync_base: uri::Rsync,

    #[serde(deserialize_with = "ext_serde::de_http_uri")]
    notify_sia: uri::Http,

    #[serde(deserialize_with = "ext_serde::de_http_uri")]
    service_uri: uri::Http,
}

/// # Accessors
impl Config {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    pub fn pub_xml_dir(&self) -> &PathBuf {
        &self.pub_xml_dir
    }

    pub fn rsync_base(&self) -> &uri::Rsync { &self.rsync_base }

    pub fn service_uri(&self) -> uri::Http {
        self.service_uri.clone()
    }

    pub fn notify_sia(&self) -> uri::Http {
        self.notify_sia.clone()
    }
}

/// # Create
impl Config {

    /// Set up a config for use in (integration) testing.
//    #[cfg(test)]
    pub fn test(
        data_dir: &PathBuf,
        pub_xml_dir: &PathBuf,
    ) -> Self {

        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));;
        let port = 3000;
        let data_dir = data_dir.clone();
        let pub_xml_dir = pub_xml_dir.clone();
        let rsync_base = uri::Rsync::from_str("rsync://127.0.0.1/rpki/")
            .unwrap();
        let notify_sia = uri::Http::from_str(
            "http://127.0.0.1:3000/repo/notify.xml").unwrap();
        let service_uri = uri::Http::from_str(
            "http://127.0.0.1:3000/rfc8181/").unwrap();

        Config {
            ip,
            port,
            data_dir,
            pub_xml_dir,
            rsync_base,
            notify_sia,
            service_uri
        }
    }

    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let matches = App::new("NLnet Labs RRDP Server")
            .version("0.1b")
            .arg(Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Specify non-default config file. If no file is \
                specified './defaults/server.toml' will be used to \
                determine default values for all settings. Note that you \
                can use any of the following options to override any of \
                these values..")
                .required(false))
            .arg(Arg::with_name("ip")
                .short("i")
                .long("ip")
                .value_name("IP Address")
                .help("Override the IP address.")
                .required(false))
            .arg(Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("Port number")
                .help("Override the port number.")
                .required(false))
            .arg(Arg::with_name("pub_xml_dir")
                .short("x")
                .long("pub_xml_dir")
                .value_name("DIR")
                .help("Override the directory with publisher XML files.")
                .required(false))
            .arg(Arg::with_name("rsync_base")
                .short("r")
                .long("rsync_base")
                .value_name("URI")
                .help("Override rsync base URI.")
                .required(false))
            .arg(Arg::with_name("notify_sia")
                .short("n")
                .long("notify_sia")
                .value_name("URI")
                .help("Override the notify URI.")
                .required(false))
            .arg(Arg::with_name("service_uri")
                .short("u")
                .long("service_uri")
                .value_name("URI")
                .help("Override the service URI.")
                .required(false))
            .get_matches();

        let config_file = matches.value_of("config")
            .unwrap_or("./defaults/server.toml");

        let mut c = Self::read_config(config_file.as_ref())?;

        if ! fs::metadata(&c.data_dir)?.is_dir() {
            return Err(
                ConfigError::Other(
                    format!(
                        "Invalid data_dir: {}",
                        c.data_dir.to_string_lossy().as_ref()
                    )
                )
            )
        }


        if let Some(ip_arg) = matches.value_of("ip") {
            match IpAddr::from_str(ip_arg) {
                Ok(ip) => c.ip = ip,
                Err(_) => return Err(
                    ConfigError::Other(
                        format!("Invalid IP Address: {}", ip_arg)
                    ))
            }
        }

        if let Some(port_arg) = matches.value_of("port") {
            match u16::from_str(port_arg) {
                Ok(p) => {
                    if p < 1024 {
                        return Err(
                            ConfigError::Other(
                                "Port number must be between 1024 and \
                                65535".to_string()
                            )
                        )
                    }
                    c.port = p;
                }
                Err(_) => return Err(
                            ConfigError::Other(
                                format!("Invalid port: {}", port_arg)))
            }

        }

        if let Some(xml_arg) = matches.value_of("pub_xml_dir") {
            c.pub_xml_dir = PathBuf::from(xml_arg)
        }

        if let Some(rsync_base) = matches.value_of("rsync_base") {
            c.rsync_base = uri::Rsync::from_str(rsync_base)?;
        }

        if let Some(notify_sia) = matches.value_of("notify_sia") {
            c.notify_sia = uri::Http::from_str(notify_sia)?;
        }

        Ok(c)
    }

    fn read_config(file: &str) -> Result<Self, ConfigError> {
        let mut v = Vec::new();
        let mut f = File::open(file)?;
        f.read_to_end(&mut v)?;

        let c: Config = toml::from_slice(v.as_slice())?;

        if c.port < 1024 {
            Err(ConfigError::Other("Port number must be >1024".to_string()))
        } else {
            Ok(c)
        }

    }
}

#[derive(Debug, Fail)]
pub enum ConfigError {

    #[fail(display ="{}", _0)]
    IoError(io::Error),

    #[fail(display ="{}", _0)]
    TomlError(toml::de::Error),

    #[fail(display ="{}", _0)]
    RpkiUriError(uri::Error),

    #[fail(display ="{}", _0)]
    Other(String)
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::TomlError(e)
    }
}

impl From<uri::Error> for ConfigError {
    fn from(e: uri::Error) -> Self {
        ConfigError::RpkiUriError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_default_config_file() {
        let c = Config::read_config("./defaults/server.toml").unwrap();
        let expected_socket_addr = ([127, 0, 0, 1], 3000).into();
        assert_eq!(c.socket_addr(), expected_socket_addr);
    }

}
