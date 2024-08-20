//! Options for creating Krill config.

use std::fmt;
use std::borrow::Cow;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use crate::cli::client::KrillClient;
use crate::cli::report::Report;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Use a 3rd party repository for publishing
    Simple(Simple),

    /// Generate a user authentication configuration file fragment
    #[cfg(feature = "multi-user")]
    User(User),
}

impl Command {
    pub async fn run(self, client: &KrillClient) -> Report {
        match self {
            Self::Simple(cmd) => cmd.run(client).into(),
            
            #[cfg(feature = "multi-user")]
            Self::User(cmd) => cmd.run().into()
        }
    }
}

//-------- Simple --------------------------------------------------------

#[derive(clap::Parser)]
pub struct Simple {
    /// Override the default data directory of ./data
    #[arg(short, long)]
    pub data: Option<String>,

    /// Override the default log file path of ./krill.log
    #[arg(short, long)]
    pub logfile: Option<String>,

    /// Include config for multi-user feature
    pub multi_user: bool,

    /// Include config for HSM
    pub hsm: bool,
}

impl Default for Simple {
    fn default() -> Self {
        Self {
            data: None,
            logfile: None,
            multi_user: Self::MULTI_USER_DEFAULT,
            hsm: false,
        }
    }
}

impl Simple {
    #[cfg(feature = "multi-user")]
    const MULTI_USER_DEFAULT: bool = true;

    #[cfg(not(feature = "multi-user"))]
    const MULTI_USER_DEFAULT: bool = false;
}

impl Simple {
    pub fn run(self, client: &KrillClient) -> ConfigFile {
        let defaults = include_str!("../../../defaults/krill.conf");
        let multi_add_on =
            include_str!("../../../defaults/krill-multi-user.conf");
        let hsm_add_on = include_str!("../../../defaults/krill-hsm.conf");

        let mut config = defaults.to_string();
        config = config.replace(
            "### admin_token =",
            &format!("admin_token = \"{}\"", client.token()),
        );

        config = config.replace(
            "### service_uri = \"https://localhost:3000/\"",
            &format!("service_uri = \"{}\"", client.base_uri()),
        );

        if let Some(data_dir) = self.data.as_ref() {
            // XXX data_dir was previously forced to end in a slash.
            //     I don’t think this requirement is true any more?
            let data_dir = if data_dir.ends_with("/") {
                Cow::Borrowed(data_dir)
            }
            else {
                Cow::Owned(format!("{}/", data_dir))
            };
            config = config.replace(
                "### storage_uri = \"./data\"",
                &data_dir
            );
        }

        if let Some(log_file) = self.logfile {
            config = config.replace(
                "### log_file = \"./krill.log\"",
                &format!("log_file = \"{}\"", log_file),
            )
        }

        if self.multi_user {
            config.push_str("\n\n\n");
            config.push_str(multi_add_on);
        }

        if self.hsm {
            config.push_str("\n\n\n");
            config.push_str(hsm_add_on);
        }

        config.into()
    }
}


//-------- User ----------------------------------------------------------

#[cfg(feature = "multi-user")]
#[derive(clap::Parser)]
pub struct User {
    /// ID (e.g., username, email) to generate configuration for
    #[arg(long, value_name = "id")]
    pub id: String,

    /// Attributes for the user
    #[arg(long, short, value_name="key=value")]
    pub attr: Vec<KeyValuePair>,
}

#[cfg(feature = "multi-user")]
impl User {
    pub fn run(self) -> ConfigFile {
        use crate::constants;

        let (password_hash, salt) = {
            use scrypt::scrypt;

            let password = rpassword::prompt_password(
                "Enter the password to hash: "
            ).unwrap();

            // The scrypt-js NPM documentation
            // (https://www.npmjs.com/package/scrypt-js)
            // says:
            //
            //   TL;DR - either only allow ASCII characters in passwords,
            //   or use String.prototype.normalize('NFKC') on any
            //   password.
            //
            // So in Lagosta we do the NFKC normalization and thus we
            // need to do the same here.
            use unicode_normalization::UnicodeNormalization;

            let user_id = self.id.nfkc().collect::<String>();
            let password = password.trim().nfkc().collect::<String>();
            let params = scrypt::Params::new(
                constants::PW_HASH_LOG_N,
                constants::PW_HASH_R,
                constants::PW_HASH_P,
                scrypt::Params::RECOMMENDED_LEN,
            ).unwrap();

            // Hash twice with two different salts: first with a salt
            // the client browser knows how to construct based on the
            // users id and a site specific string. Then hash again using
            // a strong random salt only known to the server.
            let weak_salt = format!("krill-lagosta-{}", user_id);
            let weak_salt = weak_salt.nfkc().collect::<String>();

            let mut interim_hash = [0u8; 32];
            scrypt(
                password.as_bytes(),
                weak_salt.as_bytes(),
                &params,
                &mut interim_hash,
            ).unwrap();

            let mut strong_salt: [u8; 32] = [0; 32];
            openssl::rand::rand_bytes(&mut strong_salt).unwrap();
            let mut final_hash: [u8; 32] = [0; 32];
            scrypt(
                &interim_hash, &strong_salt, &params, &mut final_hash
            ).unwrap();

            (final_hash, strong_salt)
        };

        // Due to https://github.com/alexcrichton/toml-rs/issues/406 we
        // cannot produce inline table style TOML by serializing from
        // config structs to a string using the toml crate. Instead we
        // build it up ourselves.
        let attrs_fragment = if self.attr.is_empty() {
            String::new()
        }
        else {
            format!(
                "attributes={{ {} }}, ",
                self.attr
                    .into_iter()
                    // quote the key if needed
                    .map(|KeyValuePair(k, v)| match k.contains(' ') {
                        true => (format!(r#""{}""#, k), v),
                        false => (k, v),
                    })
                    // quote the value
                    .map(|(k, v)| format!(r#"{}="{}""#, k, v))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        };

        format!(
            r#"[auth_users]\n\
               "{id}" = {{ {attrs}password_hash="{ph}", salt="{salt}" }}"#,
            id = self.id,
            attrs = attrs_fragment,
            ph = hex::encode(password_hash),
            salt = hex::encode(salt),
        ).into()
    }
}


//-------- KeyValuePair --------------------------------------------------

/// A key-value pair parsed from a string in `key=value` format.
#[cfg(feature = "multi-user")]
#[derive(Clone, Debug)]
pub struct KeyValuePair(pub String, pub String);

#[cfg(feature = "multi-user")]
impl std::str::FromStr for KeyValuePair {
    type Err = &'static str;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        match src.split_once(src) {
            Some((key, value)) => Ok(Self(key.into(), value.into())),
            None => Err("expecting \"key=value\"")
        }
    }
}


//------------ ConfigFile ----------------------------------------------------

/// A config file as an API response.
pub struct ConfigFile(String);

impl From<String> for ConfigFile {
    fn from(src: String) -> Self {
        Self(src)
    }
}

impl From<ConfigFile> for Report {
    fn from(src: ConfigFile) -> Self {
        Self::new(src)
    }
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ConfigFile {
    fn serialize<S: Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct( "ConfigFile", 1)?;
        serializer.serialize_field("content", &self.0)?;
        serializer.end()
    }
}

