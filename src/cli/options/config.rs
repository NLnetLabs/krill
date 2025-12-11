//! Options for creating Krill config.

use std::fmt;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use crate::cli::client::KrillClient;
use crate::cli::report::Report;


//------------ Command -------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum Command {
    /// Generate a user authentication configuration file fragment
    #[cfg(feature = "multi-user")]
    User(User),
}

impl Command {
    pub async fn run(self, _client: &KrillClient) -> Report {
        match self {            
            #[cfg(feature = "multi-user")]
            Self::User(cmd) => cmd.run().into()
        }
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
            let weak_salt = format!("krill-lagosta-{user_id}");
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
                        true => (format!(r#""{k}""#), v),
                        false => (k, v),
                    })
                    // quote the value
                    .map(|(k, v)| format!(r#"{k}="{v}""#))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        };

        format!(
            "[auth_users]\n\n\"{id}\" = {{ {attrs}password_hash=\"{ph}\", salt=\"{salt}\" }}",
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

