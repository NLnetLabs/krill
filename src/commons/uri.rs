//------------ Uri ------ ----------------------------------------------------

use std::{fmt, io::Error, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The URI types for the Krill command line tool
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Uri {
    Https(String),
    Http(String),
    Unix(String),
}

impl Uri {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http(http) => http,
            Self::Https(https) => https,
            Self::Unix(unix) => unix
        }
    }
}

impl TryFrom<String> for Uri {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl FromStr for Uri {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.to_lowercase().starts_with("http://") {
            return Ok(Self::Http(value.to_string()));
        } else if value.to_lowercase().starts_with("https://") {
            return Ok(Self::Https(value.to_string()));
        } else if value.to_lowercase().starts_with("unix://") {
            return Ok(Self::Unix(value.to_string()));
        }
        Err(std::io::Error::other("Unknown type"))
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Http(string) => string.fmt(f),
            Self::Https(https) => https.fmt(f),
            Self::Unix(unix) => unix.fmt(f),
        }
    }
}

impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::try_from(string).map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for Uri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
