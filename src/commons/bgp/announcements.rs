use std::fmt;
use std::str::FromStr;

use crate::commons::api::{AsNumber, RoaDefinition, TypedPrefix};
use crate::commons::bgp::TypedPrefixTree;

//------------ Announcement --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Announcement {
    asn: AsNumber,
    prefix: TypedPrefix,
}

impl Announcement {
    pub fn new(asn: AsNumber, prefix: TypedPrefix) -> Self {
        Announcement { asn, prefix }
    }

    pub fn asn(&self) -> &AsNumber {
        &self.asn
    }

    pub fn prefix(&self) -> &TypedPrefix {
        &self.prefix
    }
}

impl FromStr for Announcement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let as_roa =
            RoaDefinition::from_str(s).map_err(|e| format!("Can't parse: {}, Error: {}", s, e))?;
        if as_roa.max_length().is_some() {
            Err(format!(
                "Cannot parse announcement (max length not allowed): {}",
                s
            ))
        } else {
            Ok(as_roa.into())
        }
    }
}

impl fmt::Display for Announcement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} => {}", self.prefix, self.asn)
    }
}

impl From<Announcement> for RoaDefinition {
    fn from(a: Announcement) -> Self {
        RoaDefinition::new(a.asn, a.prefix, None)
    }
}

impl From<RoaDefinition> for Announcement {
    fn from(d: RoaDefinition) -> Self {
        Announcement {
            asn: d.asn(),
            prefix: d.prefix(),
        }
    }
}

impl AsRef<TypedPrefix> for Announcement {
    fn as_ref(&self) -> &TypedPrefix {
        &self.prefix
    }
}

//------------ Announcements -------------------------------------------------

pub struct Announcements {
    tree: TypedPrefixTree<Announcement>,
}

impl Announcements {
    pub fn new(tree: TypedPrefixTree<Announcement>) -> Self {
        Announcements { tree }
    }

    pub fn contained_by_prefix(&self, pfx: &TypedPrefix) -> Vec<&Announcement> {
        self.tree.matching_or_more_specific(pfx)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::commons::bgp::parse_risdumps;

    use super::*;

    #[test]
    fn should_parse_ris_dumps() {
        let v4_path = PathBuf::from("test-resources/bgp/risdumps/riswhoisdump.IPv4");
        let v6_path = PathBuf::from("test-resources/bgp/risdumps/riswhoisdump.IPv6");
        let paths = vec![v4_path, v6_path];

        let announcements = parse_risdumps(&paths).unwrap();

        let ann_v4 = Announcement::from_str("1.0.0.0/24 => 13335").unwrap();
        let ann_v6 = Announcement::from_str("2001:4:112::/48 => 112").unwrap();

        let matches = announcements.contained_by_prefix(ann_v4.prefix());
        assert_eq!(1, matches.len());
        assert!(matches.contains(&&ann_v4));

        let matches = announcements.contained_by_prefix(ann_v6.prefix());
        assert_eq!(1, matches.len());
        assert!(matches.contains(&&ann_v6));
    }
}
