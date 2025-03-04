use std::fmt;
use std::str::FromStr;
use rpki::uri;
use rpki::ca::publication::Base64;
use rpki::repository::resources::AddressFamily;
use rpki::repository::x509::{Serial, Validity};
use rpki::resources::Asn;
use rpki::rrdp::Hash;
use serde::{Deserialize, Serialize};
use crate::commons::api::aspa::{AspaDefinition, CustomerAsn};


//------------ Pre0_14_0AspaDefinition
//------------ ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaDefinition {
    pub customer: CustomerAsn,
    pub providers: Vec<Pre0_14_0ProviderAs>,
}

impl From<Pre0_14_0AspaDefinition> for AspaDefinition {
    fn from(old: Pre0_14_0AspaDefinition) -> Self {
        AspaDefinition {
            customer: old.customer,
            providers: old.providers.into_iter().map(|o| o.provider).collect(),
        }
    }
}

//------------ Pre_0_14_0AspaInfo
//------------ ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaInfo {
    pub definition: Pre0_14_0AspaDefinition,
    validity: Validity,
    serial: Serial,
    uri: uri::Rsync,
    base64: Base64,
    hash: Hash,
}

//------------ Pre_0_14_0AspaObjectsUpdates
//------------ -----------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub updated: Vec<Pre0_14_0AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<CustomerAsn>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaProvidersUpdate {
    added: Vec<Pre0_14_0ProviderAs>,
    removed: Vec<Pre0_14_0ProviderAs>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_14_0AspaDefinitionUpdates {
    add_or_replace: Vec<Pre0_14_0AspaDefinition>,
    remove: Vec<CustomerAsn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pre0_14_0ProviderAs {
    pub provider: Asn,
    pub afi_limit: Option<AddressFamily>,
}

impl Pre0_14_0ProviderAs {
    pub fn new(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: None,
        }
    }

    pub fn new_v4(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: Some(AddressFamily::Ipv4),
        }
    }

    pub fn new_v6(provider: Asn) -> Self {
        Pre0_14_0ProviderAs {
            provider,
            afi_limit: Some(AddressFamily::Ipv6),
        }
    }
}

//--- FromStr

impl FromStr for Pre0_14_0ProviderAs {
    type Err = <Asn as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Possible options:
        //  AS#
        //  AS#(v4)
        //  AS#(v6)
        if let Some(as_str) = s.strip_suffix("(v4)") {
            Ok(Pre0_14_0ProviderAs::new_v4(Asn::from_str(as_str)?))
        } else if let Some(as_str) = s.strip_suffix("(v6)") {
            Ok(Pre0_14_0ProviderAs::new_v6(Asn::from_str(as_str)?))
        } else {
            Ok(Pre0_14_0ProviderAs::new(Asn::from_str(s)?))
        }
    }
}

//--- Display

impl fmt::Display for Pre0_14_0ProviderAs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.afi_limit {
            None => write!(f, "{}", self.provider),
            Some(family) => {
                let fam_str = match &family {
                    AddressFamily::Ipv4 => "v4",
                    AddressFamily::Ipv6 => "v6",
                };
                write!(f, "{}({})", self.provider, fam_str)
            }
        }
    }
}

//--- Deserialize and Serialize

impl serde::Serialize for Pre0_14_0ProviderAs {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Pre0_14_0ProviderAs {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        Pre0_14_0ProviderAs::from_str(&string).map_err(de::Error::custom)
    }
}

