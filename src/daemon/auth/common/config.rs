use serde::{de, Deserialize, Deserializer};

// Implement Serialize as well for this type as we serialize it when sending it
// as part of the login session state to the client. Make sure that it
// serializes to snake_case as that is what is expeced by the custom deserialize
// implementation below.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    GuiReadOnly,
    GuiReadWrite,
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D>(d: D) -> Result<Role, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "admin" => Ok(Role::Admin),
            "gui_read_only" => Ok(Role::GuiReadOnly),
            "gui_read_write" => Ok(Role::GuiReadWrite),
            _ => Err(de::Error::custom(format!(
                "expected \"admin\", \"gui_read_only\" or \"gui_read_write\", found : \"{}\"",
                string
            ))),
        }
    }
}
