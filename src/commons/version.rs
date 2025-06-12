use std::{cmp::Ordering, fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use clap::crate_version;


//------------ KrillVersion --------------------------------------------------

/// Defines a Krill version.
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KrillVersion {
    major: u64,
    minor: u64,
    patch: u64,
    release_type: KrillVersionReleaseType,
}

impl KrillVersion {
    pub fn code_version() -> Self {
        // Note: we have a unit test to ensure that the KRILL_VERSION constant
        // which is derived from the Cargo.toml version can be parsed.
        Self::from_str(crate_version!()).unwrap()
    }

    /// Make a notation friendly to namespaces for upgrades.
    pub fn hyphen_notated(&self) -> String {
        format!(
            "{}-{}-{}{}",
            self.major, self.minor, self.patch, self.release_type
        )
    }

    pub fn v0_5_0_or_before() -> Self {
        Self::dev(0, 5, 0, "or-before".to_string())
    }

    pub fn release(major: u64, minor: u64, patch: u64) -> Self {
        KrillVersion {
            major,
            minor,
            patch,
            release_type: KrillVersionReleaseType::Release,
        }
    }

    pub fn candidate(
        major: u64,
        minor: u64,
        patch: u64,
        number: u64,
    ) -> Self {
        KrillVersion {
            major,
            minor,
            patch,
            release_type: KrillVersionReleaseType::Candidate(number),
        }
    }

    pub fn dev(major: u64, minor: u64, patch: u64, addition: String) -> Self {
        KrillVersion {
            major,
            minor,
            patch,
            release_type: KrillVersionReleaseType::Dev(addition),
        }
    }
}

impl FromStr for KrillVersion {
    type Err = KrillVersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // x.y.z       => major.minor.patch release
        // x.y.z-rc#   => major.minor.patch release candidate #
        // x.y.z-<str> => major.minor.patch dev 'str'
        // other       => cannot parse
        //
        // Support legacy enum based version notation as well:
        // V0_6 => 0.6.0

        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 3 {
            let major = u64::from_str(parts[0])
                .map_err(|_| KrillVersionParseError::for_str(s))?;

            let minor = u64::from_str(parts[1])
                .map_err(|_| KrillVersionParseError::for_str(s))?;

            let mut patch_parts = parts[2].split('-');

            let patch = u64::from_str(patch_parts.next().unwrap())
                .map_err(|_| KrillVersionParseError::for_str(s))?;

            match patch_parts.next() {
                None => Ok(KrillVersion::release(major, minor, patch)),
                Some(addition) => {
                    if addition.len() > 2 && addition.starts_with("rc") {
                        let number =
                            u64::from_str(&addition[2..]).map_err(|_| {
                                KrillVersionParseError::for_str(s)
                            })?;
                        Ok(KrillVersion::candidate(
                            major, minor, patch, number,
                        ))
                    } else {
                        Ok(KrillVersion::dev(
                            major,
                            minor,
                            patch,
                            addition.to_string(),
                        ))
                    }
                }
            }
        } else {
            match s {
                // Enums present in versions before 0.9.1
                "V0_6" => Ok(KrillVersion::release(0, 6, 0)),
                "V0_7" => Ok(KrillVersion::release(0, 7, 0)),
                "V0_8_0_RC1" => Ok(KrillVersion::candidate(0, 8, 0, 1)),
                "V0_8" => Ok(KrillVersion::release(0, 8, 0)),
                "V0_8_1_RC1" => Ok(KrillVersion::candidate(0, 8, 1, 1)),
                "V0_8_1" => Ok(KrillVersion::release(0, 8, 1)),
                "V0_8_2" => Ok(KrillVersion::release(0, 8, 2)),
                "V0_9_0_RC1" => Ok(KrillVersion::candidate(0, 9, 0, 1)),
                "V0_9_0" => Ok(KrillVersion::release(0, 9, 0)),
                _ => Err(KrillVersionParseError::for_str(s)),
            }
        }
    }
}

impl fmt::Display for KrillVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}{}",
            self.major, self.minor, self.patch, self.release_type
        )
    }
}

#[derive(Clone, Debug)]
pub struct KrillVersionParseError(String);

impl KrillVersionParseError {
    fn for_str(s: &str) -> Self {
        KrillVersionParseError(s.to_string())
    }
}

impl fmt::Display for KrillVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse Krill version from string: {}", self.0)
    }
}

impl Ord for KrillVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut res = self.major.cmp(&other.major);

        // use res.is_eq() when the minimum rust requirement will be 1.53 or
        // higher
        if res == Ordering::Equal {
            res = self.minor.cmp(&other.minor);
        }

        if res == Ordering::Equal {
            res = self.patch.cmp(&other.patch);
        }

        if res == Ordering::Equal {
            res = self.release_type.cmp(&other.release_type);
        }

        res
    }
}

impl PartialOrd for KrillVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for KrillVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KrillVersion {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<KrillVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        KrillVersion::from_str(string.as_str()).map_err(de::Error::custom)
    }
}


//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Eq, PartialEq)]
enum KrillVersionReleaseType {
    Release,
    Candidate(u64),
    Dev(String),
}

impl Ord for KrillVersionReleaseType {
    fn cmp(&self, other: &Self) -> Ordering {
        match &self {
            KrillVersionReleaseType::Release => match other {
                KrillVersionReleaseType::Release => Ordering::Equal,
                _ => Ordering::Greater,
            },
            KrillVersionReleaseType::Candidate(nr) => match other {
                KrillVersionReleaseType::Release => Ordering::Less,
                KrillVersionReleaseType::Candidate(nr_other) => {
                    nr.cmp(nr_other)
                }
                &KrillVersionReleaseType::Dev(_) => Ordering::Greater,
            },
            KrillVersionReleaseType::Dev(_) => match other {
                KrillVersionReleaseType::Dev(_) => Ordering::Equal,
                _ => Ordering::Less,
            },
        }
    }
}

impl PartialOrd for KrillVersionReleaseType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for KrillVersionReleaseType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KrillVersionReleaseType::Release => write!(f, ""),
            KrillVersionReleaseType::Candidate(nr) => write!(f, "-rc{}", nr),
            KrillVersionReleaseType::Dev(text) => write!(f, "-{}", text),
        }
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krill_version_from_current_cargo_version() {
        KrillVersion::code_version();
    }

    #[test]
    fn krill_version_pre_0_9_1_enums() {
        KrillVersion::from_str("V0_6").unwrap();
        KrillVersion::from_str("V0_7").unwrap();
        KrillVersion::from_str("V0_8_0_RC1").unwrap();
        KrillVersion::from_str("V0_8").unwrap();
        KrillVersion::from_str("V0_8_1_RC1").unwrap();
        KrillVersion::from_str("V0_8_1").unwrap();
        KrillVersion::from_str("V0_8_2").unwrap();
        KrillVersion::from_str("V0_9_0_RC1").unwrap();
        KrillVersion::from_str("V0_9_0").unwrap();
    }

    #[test]
    fn krill_version_from_str() {
        KrillVersion::from_str("0.9.1").unwrap();
        KrillVersion::from_str("0.9.1-rc1").unwrap();
        KrillVersion::from_str("0.9.1-bis").unwrap();

        // We do not support short, or random notations including but not
        // limited to:
        assert!(KrillVersion::from_str("v0.9.1").is_err());
        assert!(KrillVersion::from_str("0.9-bis").is_err());
        assert!(KrillVersion::from_str("some garbage").is_err());
    }

    #[test]
    fn krill_version_ordering() {
        let v0_9_1 = KrillVersion::from_str("0.9.1").unwrap();
        let v0_9_1_rc1 = KrillVersion::from_str("0.9.1-rc1").unwrap();
        let v0_9_1_rc2 = KrillVersion::from_str("0.9.1-rc2").unwrap();
        let v0_9_1_dev = KrillVersion::from_str("0.9.1-dev").unwrap();

        assert!(v0_9_1 > v0_9_1_rc1);
        assert!(v0_9_1_rc2 > v0_9_1_rc1);
        assert!(v0_9_1_rc1 > v0_9_1_dev);

        let v0_9_0 = KrillVersion::from_str("0.9.0").unwrap();
        assert!(v0_9_1 > v0_9_0);
        assert!(v0_9_1_rc2 > v0_9_0);
        assert!(v0_9_1_dev > v0_9_0);
    }
}

