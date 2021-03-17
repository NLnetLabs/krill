use std::collections::HashMap;

pub type ConfigAuthUsers = HashMap<String, ConfigUserDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigUserDetails {
    #[serde(default)]
    pub attributes: HashMap<String, String>,

    pub password_hash: Option<String>,
}
