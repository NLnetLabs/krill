//! General utility modules for use all over the code base
use std::cmp::Ordering;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use bytes::Bytes;
use rpki::repository::crypto::DigestAlgorithm;
use rpki::uri::{Https, Rsync};

use crate::constants::KRILL_VERSION;

pub mod ext_serde;
pub mod file;
pub mod httpclient;
pub mod softsigner;
pub mod xml;


//------------ KrillVersion --------------------------------------------------

/// Defines a Krill version. Will 

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KrillVersion {
    major: u64,
    minor: u64,
    patch: u64,
    release: KrillVersionRelease
}

impl KrillVersion {
    pub fn current() -> Self {
        // Note: we have a unit test to ensure that the KRILL_VERSION constant
        // which is derived from the Cargo.toml version can be parsed.
        Self::from_str(KRILL_VERSION).unwrap()
    }

    pub fn v0_5_0_or_before() -> Self {
        Self::dev(0, 5, 0, "or-before".to_string())
    }
    
    pub fn release(major: u64, minor: u64, patch: u64) -> Self {
        KrillVersion { major, minor, patch, release: KrillVersionRelease::Release}
    }

    pub fn candidate(major: u64, minor: u64, patch: u64, number: u64) -> Self {
        KrillVersion { major, minor, patch, release: KrillVersionRelease::Candidate(number)}
    }

    fn dev(major: u64, minor: u64, patch: u64, addition: String) -> Self {
        KrillVersion { major, minor, patch, release: KrillVersionRelease::Dev(addition)}
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
                         let number = u64::from_str(&addition[2..])
                            .map_err(|_| KrillVersionParseError::for_str(s))?;
                        Ok(KrillVersion::candidate(major, minor, patch, number))
                    } else {
                        Ok(KrillVersion::dev(major, minor, patch, addition.to_string()))
                    }
                }
            }
            
        } else {
            match s {
                // Enums present in versions before 0.9.1
                "V0_6" => Ok(KrillVersion::release(0,6,0)),
                "V0_7" => Ok(KrillVersion::release(0,7,0)),
                "V0_8_0_RC1" => Ok(KrillVersion::candidate(0,8,0, 1)),
                "V0_8" => Ok(KrillVersion::release(0,8,0)),
                "V0_8_1_RC1" => Ok(KrillVersion::candidate(0,8,1, 1)),
                "V0_8_1" => Ok(KrillVersion::release(0,8,1)),
                "V0_8_2" => Ok(KrillVersion::release(0,8,2)),
                "V0_9_0_RC1" => Ok(KrillVersion::candidate(0,9,0, 1)),
                "V0_9_0" => Ok(KrillVersion::release(0,9,0)),
                _ =>  Err(KrillVersionParseError::for_str(s))
            }
        }
    }
}

impl fmt::Display for KrillVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}{}", self.major, self.minor, self.patch, self.release)
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

        // use res.is_eq() when the minimum rust requirement will be 1.53 or higher
        if res == Ordering::Equal {
            res = self.minor.cmp(&other.minor);
        }

        if res == Ordering::Equal {
            res = self.patch.cmp(&other.patch);
        }

        if res == Ordering::Equal {
            res = self.release.cmp(&other.release);
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
    fn deserialize<D>(deserializer: D) -> std::result::Result<KrillVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        KrillVersion::from_str(string.as_str()).map_err(de::Error::custom)
    }
}




#[derive(Clone, Debug, Eq, PartialEq)]
enum KrillVersionRelease {
    Release,
    Candidate(u64),
    Dev(String)
}

impl Ord for KrillVersionRelease {
    fn cmp(&self, other: &Self) -> Ordering {
        match &self {
            KrillVersionRelease::Release => match other {
                KrillVersionRelease::Release => Ordering::Equal,
                _ => Ordering::Greater
            },
            KrillVersionRelease::Candidate(nr) => match other {
                KrillVersionRelease::Release => Ordering::Less,
                KrillVersionRelease::Candidate(nr_other) => nr.cmp(nr_other),
                &KrillVersionRelease::Dev(_) => Ordering::Greater
            },
            KrillVersionRelease::Dev(text) => match other {
                KrillVersionRelease::Dev(text_other) => text.cmp(text_other),
                _ => Ordering::Less
            }
        }
    }
}

impl PartialOrd for KrillVersionRelease {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for KrillVersionRelease {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KrillVersionRelease::Release => write!(f, ""),
            KrillVersionRelease::Candidate(nr) => write!(f, "-rc{}", nr),
            KrillVersionRelease::Dev(text) => write!(f, "-{}", text),
        }
    }
}


/// Returns the SHA256 hash for the given octets.
pub fn sha256(object: &[u8]) -> Bytes {
    let digest = DigestAlgorithm::default().digest(object);
    Bytes::copy_from_slice(digest.as_ref())
}

// TODO: check that an IP address is_global() when that stabilizes: https://github.com/rust-lang/rust/issues/27709
/// Assumes that non-ip hostnames are global (they may of course resolve to something that isn't but hey we tried to help)
fn seems_global_uri(auth: &str) -> bool {
    if auth.to_lowercase() == "localhost" || auth.starts_with('[') || IpAddr::from_str(auth).is_ok() {
        false
    } else if let Some(i) = auth.rfind(':') {
        let auth = &auth[0..i];
        IpAddr::from_str(auth).is_err()
    } else {
        // appears to be a non-ip hostname, assume it's global
        true
    }
}

pub trait AllowedUri {
    fn authority(&self) -> &str;

    fn seems_global_uri(&self) -> bool {
        seems_global_uri(self.authority())
    }
}

impl AllowedUri for Rsync {
    fn authority(&self) -> &str {
        self.authority()
    }
}

impl AllowedUri for Https {
    fn authority(&self) -> &str {
        self.authority()
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use crate::commons::util::seems_global_uri;

    use super::*;

    #[test]
    fn check_uri_seems_global() {
        // Does not seem global
        assert!(!seems_global_uri("localhost"));
        assert!(!seems_global_uri("0.0.0.0"));
        assert!(!seems_global_uri("127.0.0.1"));
        assert!(!seems_global_uri("127.0.0.1:873"));
        assert!(!seems_global_uri("1.2.3.4"));
        assert!(!seems_global_uri("::"));
        assert!(!seems_global_uri("::1"));
        assert!(!seems_global_uri("[::1]:873"));
        assert!(!seems_global_uri("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));

        // Looks ok
        assert!(seems_global_uri("localghost"));
        assert!(seems_global_uri("rpki.bla"));
    }

    #[test]
    fn krill_version_from_current_cargo_version() {
        KrillVersion::current();
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
        
        // We do not support short, or random notations including but not limited to:
        assert!(KrillVersion::from_str("v0.9.1").is_err());
        assert!(KrillVersion::from_str("0.9-bis").is_err());
        assert!(KrillVersion::from_str("some garbage").is_err());
    }
    
    #[test]
    fn krill_version_ordering() {
        let v0_9_1 = KrillVersion::from_str("0.9.1").unwrap();
        let v0_9_1_rc1 = KrillVersion::from_str("0.9.1-rc1").unwrap();
        let v0_9_1_rc2 = KrillVersion::from_str("0.9.1-rc2").unwrap();
        let v0_9_1_bis = KrillVersion::from_str("0.9.1-bis").unwrap();

        assert!(v0_9_1 > v0_9_1_rc1);
        assert!(v0_9_1_rc2 > v0_9_1_rc1);
        assert!(v0_9_1_rc1 > v0_9_1_bis);
    }
}
