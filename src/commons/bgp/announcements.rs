use std::fmt;
use std::str::FromStr;

use rpki::x509::Time;

use crate::commons::api::{AsNumber, RoaDefinition, TypedPrefix};
use crate::commons::bgp::{TypedPrefixTree, TypedPrefixTreeBuilder};

//------------ AnnouncementTree ----------------------------------------------

pub type AnnouncementTree = TypedPrefixTree<Announcement>;

//------------ RoaTree -------------------------------------------------------

pub type RoaTree = TypedPrefixTree<RoaDefinition>;

pub fn make_roa_tree(roas: &[RoaDefinition]) -> RoaTree {
    make_tree(roas)
}

pub type ValidatedAnnouncementTree = TypedPrefixTree<ValidatedAnnouncement>;

pub fn make_validated_announcement_tree(
    validated: &[ValidatedAnnouncement],
) -> ValidatedAnnouncementTree {
    make_tree(validated)
}

fn make_tree<V>(els: &[V]) -> TypedPrefixTree<V>
where
    V: AsRef<TypedPrefix> + Clone,
{
    let mut builder = TypedPrefixTreeBuilder::default();
    for el in els {
        builder.add(el.clone());
    }
    builder.build()
}

//------------ Announcement --------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

    pub fn validate(&self, roas: &RoaTree) -> ValidatedAnnouncement {
        let covering = roas.matching_or_less_specific(&self.prefix);
        if covering.is_empty() {
            ValidatedAnnouncement {
                announcement: self.clone(),
                validity: AnnouncementValidity::NotFound,
                validating: None,
                invalidating: vec![],
            }
        } else {
            let mut invalidating = vec![];
            let mut same_asn_found = false;
            for roa in covering {
                if roa.asn() == self.asn {
                    if roa.prefix().covers(&self.prefix)
                        && roa.effective_max_length() >= self.prefix.addr_len()
                    {
                        return ValidatedAnnouncement {
                            announcement: self.clone(),
                            validity: AnnouncementValidity::Valid,
                            validating: Some(roa.clone()),
                            invalidating: vec![],
                        };
                    } else {
                        same_asn_found = true;
                    }
                } else {
                    invalidating.push(roa.clone());
                }
            }

            let validity = if same_asn_found {
                AnnouncementValidity::InvalidLength
            } else {
                AnnouncementValidity::InvalidAsn
            };

            ValidatedAnnouncement {
                announcement: self.clone(),
                validity,
                validating: None,
                invalidating,
            }
        }
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
    seen: TypedPrefixTree<Announcement>,
    last_updated: Option<Time>,
}

impl Announcements {
    pub fn update(&mut self, announcements: Vec<Announcement>) {
        let mut builder = TypedPrefixTreeBuilder::default();
        for a in announcements {
            builder.add(a);
        }
        let tree = builder.build();
        self.seen = tree;
        self.last_updated = Some(Time::now());
    }

    pub fn all(&self) -> Vec<&Announcement> {
        self.seen.all()
    }

    pub fn contained_by_prefix(&self, pfx: &TypedPrefix) -> Vec<&Announcement> {
        self.seen.matching_or_more_specific(pfx)
    }

    pub fn size(&self) -> usize {
        self.seen.size()
    }

    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    pub fn last_updated(&self) -> Option<Time> {
        self.last_updated
    }
}

impl Default for Announcements {
    fn default() -> Self {
        Announcements {
            seen: TypedPrefixTreeBuilder::default().build(),
            last_updated: None,
        }
    }
}

//------------ ValidatedAnnouncement -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ValidatedAnnouncement {
    announcement: Announcement,
    validity: AnnouncementValidity,
    validating: Option<RoaDefinition>,
    invalidating: Vec<RoaDefinition>,
}

impl ValidatedAnnouncement {
    pub fn validity(&self) -> AnnouncementValidity {
        self.validity
    }

    pub fn announcement(&self) -> Announcement {
        self.announcement
    }

    pub fn unpack(
        self,
    ) -> (
        Announcement,
        AnnouncementValidity,
        Option<RoaDefinition>,
        Vec<RoaDefinition>,
    ) {
        (
            self.announcement,
            self.validity,
            self.validating,
            self.invalidating,
        )
    }
}

impl AsRef<TypedPrefix> for ValidatedAnnouncement {
    fn as_ref(&self) -> &TypedPrefix {
        &self.announcement.prefix
    }
}

//------------ AnnouncementValidity -------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AnnouncementValidity {
    Valid,
    InvalidLength,
    InvalidAsn,
    NotFound,
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::*;

    #[test]
    fn find_contained() {
        let ann_v4 = Announcement::from_str("1.0.0.0/24 => 13335").unwrap();
        let ann_v6 = Announcement::from_str("2001:4:112::/48 => 112").unwrap();

        let mut announcements = Announcements::default();
        announcements.update(vec![ann_v4.clone(), ann_v6.clone()]);

        let matches = announcements.contained_by_prefix(ann_v4.prefix());
        assert_eq!(1, matches.len());
        assert!(matches.contains(&&ann_v4));

        let matches = announcements.contained_by_prefix(ann_v6.prefix());
        assert_eq!(1, matches.len());
        assert!(matches.contains(&&ann_v6));
    }

    #[test]
    fn validate_announcement() {
        let roa_authorizing_1 = definition("10.0.0.0/23-24 => 64496");
        let roa_authorizing_2 = definition("10.0.0.0/23 => 64498");
        let roa_irrelevant = definition("10.1.0.0/23-24 => 64496");

        let ann_v1 = announcement("10.0.0.0/24 => 64496");
        let ann_v2 = announcement("10.0.1.0/24 => 64496");
        let ann_ia = announcement("10.0.0.0/24 => 64497");
        let ann_il = announcement("10.0.1.0/24 => 64498");
        let ann_nf = announcement("10.2.0.0/24 => 64497");

        let mut roas_builder = TypedPrefixTreeBuilder::default();
        roas_builder.add(roa_authorizing_1);
        roas_builder.add(roa_authorizing_2);
        roas_builder.add(roa_irrelevant);
        let roas = roas_builder.build();

        fn assert_state(ann: &Announcement, roas: &RoaTree, expected: AnnouncementValidity) {
            assert_eq!(ann.validate(roas).validity, expected);
        }

        assert_state(&ann_v1, &roas, AnnouncementValidity::Valid);
        assert_state(&ann_v2, &roas, AnnouncementValidity::Valid);
        assert_state(&ann_ia, &roas, AnnouncementValidity::InvalidAsn);
        assert_state(&ann_il, &roas, AnnouncementValidity::InvalidLength);
        assert_state(&ann_nf, &roas, AnnouncementValidity::NotFound);
    }
}
