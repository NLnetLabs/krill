use std::collections::HashMap;

pub type ConfigAuthUsers = HashMap<String, ConfigUserDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigUserDetails {
    #[serde(default)]
    pub attributes: HashMap<String, String>,

    // optional so that OpenIDConnectAuthProvider can also use config file user defined attributes
    // without requiring a dummy password hash and salt
    pub password_hash: Option<String>,

    pub salt: Option<String>,
}
