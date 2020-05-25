use std::sync::RwLock;

use chrono::Duration;

use rpki::x509::Time;

use crate::commons::api::{ResourceSet, RoaDefinition};
use crate::commons::bgp::{
    make_roa_tree, make_validated_announcement_tree, Announcement, AnnouncementValidity,
    Announcements, IpRange, RisDumpError, RisDumpLoader, RoaTable, RoaTableEntry,
    ValidatedAnnouncement,
};
use crate::constants::BGP_RIS_REFRESH_MINUTES;

/// This type helps analyse ROAs vs BGP and vice versa.
pub struct BgpAnalyser {
    dumploader: Option<RisDumpLoader>,
    seen: RwLock<Announcements>,
}

impl BgpAnalyser {
    pub fn new(ris_enabled: bool, ris_v4_uri: &str, ris_v6_uri: &str) -> Self {
        let dumploader = if ris_enabled {
            Some(RisDumpLoader::new(ris_v4_uri, ris_v6_uri))
        } else {
            None
        };
        BgpAnalyser {
            dumploader,
            seen: RwLock::new(Announcements::default()),
        }
    }

    pub async fn update(&self) -> Result<(), BgpAnalyserError> {
        if let Some(loader) = &self.dumploader {
            let mut seen = self.seen.write().unwrap();
            if let Some(last_time) = seen.last_updated() {
                if (last_time + Duration::minutes(BGP_RIS_REFRESH_MINUTES)) > Time::now() {
                    return Ok(()); // no need to update yet
                }
            }
            let announcements = loader.download_updates().await?;
            seen.update(announcements);
        }
        Ok(())
    }

    pub fn analyse(&self, roas: &[RoaDefinition], scope: &ResourceSet) -> RoaTable {
        let seen = self.seen.read().unwrap();
        let mut entries = vec![];

        if seen.last_updated().is_none() {
            // nothing to analyse, just push all ROAs as 'no announcement info'
            for roa in roas {
                entries.push(RoaTableEntry::roa_no_announcement_info(roa.clone()));
            }
        } else {
            let roa_tree = make_roa_tree(roas);

            let (v4_scope, v6_scope) = IpRange::for_resource_set(&scope);

            let mut scoped_announcements = vec![];

            for block in v4_scope.into_iter() {
                scoped_announcements.append(&mut seen.contained_by(block));
            }

            for block in v6_scope.into_iter() {
                scoped_announcements.append(&mut seen.contained_by(block));
            }

            let validated: Vec<ValidatedAnnouncement> = scoped_announcements
                .into_iter()
                .map(|a| a.validate(&roa_tree))
                .collect();

            // Check all ROAs.. and report ROA state in relation to validated announcements
            let validated_tree = make_validated_announcement_tree(validated.as_slice());
            for roa in roas {
                let covered = validated_tree.matching_or_more_specific(&roa.prefix());
                if covered.is_empty() {
                    entries.push(RoaTableEntry::roa_stale(roa.clone()))
                } else {
                    let allows: Vec<Announcement> = covered
                        .iter()
                        .filter(|va| va.validity() == AnnouncementValidity::Valid)
                        .map(|va| va.announcement())
                        .collect();

                    let disallows: Vec<Announcement> = covered
                        .iter()
                        .filter(|va| {
                            let validity = va.validity();
                            validity == AnnouncementValidity::InvalidLength
                                || validity == AnnouncementValidity::InvalidAsn
                        })
                        .map(|va| va.announcement())
                        .collect();

                    if allows.is_empty() {
                        entries.push(RoaTableEntry::roa_disallowing(roa.clone(), disallows));
                    } else {
                        entries.push(RoaTableEntry::roa_authorizing(
                            roa.clone(),
                            allows,
                            disallows,
                        ))
                    }
                }
            }

            // Loop over all validated announcements and report
            for v in validated.into_iter() {
                let (announcement, validity, _, invalidating_roas) = v.unpack();
                match validity {
                    AnnouncementValidity::Valid => {} // will show up under ROAs
                    AnnouncementValidity::InvalidLength => {
                        entries.push(RoaTableEntry::announcement_invalid_length(
                            announcement,
                            invalidating_roas,
                        ));
                    }
                    AnnouncementValidity::InvalidAsn => {
                        entries.push(RoaTableEntry::announcement_invalid_asn(
                            announcement,
                            invalidating_roas,
                        ));
                    }
                    AnnouncementValidity::NotFound => {
                        entries.push(RoaTableEntry::announcement_not_found(announcement));
                    }
                }
            }
        }
        RoaTable::new(entries)
    }

    #[cfg(test)]
    fn with_test_announcements(test_announcements: Vec<Announcement>) -> Self {
        let mut announcements = Announcements::default();
        if !test_announcements.is_empty() {
            announcements.update(test_announcements);
        }
        BgpAnalyser {
            dumploader: None,
            seen: RwLock::new(announcements),
        }
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum BgpAnalyserError {
    #[display(fmt = "BGP RIS update error: {}", _0)]
    RisDump(RisDumpError),
}

impl From<RisDumpError> for BgpAnalyserError {
    fn from(e: RisDumpError) -> Self {
        BgpAnalyserError::RisDump(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::collections::HashSet;
    use std::iter::FromIterator;

    use crate::commons::bgp::RoaTableEntryState;
    use crate::test::*;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn download_ris_dumps() {
        let bgp_risdump_v4_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz";
        let bgp_risdump_v6_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz";

        let analyser = BgpAnalyser::new(true, bgp_risdump_v4_uri, bgp_risdump_v6_uri);

        assert!(analyser.seen.read().unwrap().is_empty());
        assert!(analyser.seen.read().unwrap().last_updated().is_none());
        analyser.update().await.unwrap();
        assert!(!analyser.seen.read().unwrap().is_empty());
        assert!(analyser.seen.read().unwrap().last_updated().is_some());
    }

    #[test]
    fn analyse_bgp() {
        let roa_authorizing = definition("10.0.0.0/23-24 => 64496");
        let ann_authz_1 = announcement("10.0.0.0/24 => 64496");
        let ann_authz_2 = announcement("10.0.1.0/24 => 64496");
        let ann_invalid_1 = announcement("10.0.0.0/24 => 64497");
        let ann_invalid_2 = announcement("10.0.1.0/24 => 64497");
        let ann_invalid_3 = announcement("10.0.4.0/24 => 64497");

        let ann_irrelevant = announcement("192.168.0.0/26 => 64497");

        let ann_not_found = announcement("10.0.2.0/24 => 64497");
        let roa_stale = definition("10.0.3.0/24 => 64497");
        let roa_disallowing = definition("10.0.4.0/24 => 0");

        let resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::with_test_announcements(vec![
            ann_authz_1,
            ann_authz_2,
            ann_invalid_1,
            ann_invalid_2,
            ann_invalid_3,
            ann_not_found,
            ann_irrelevant,
        ]);
        let table = analyser.analyse(&[roa_authorizing, roa_stale, roa_disallowing], &resources);

        let expected_table: RoaTable = serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_roa_table.json"
        ))
        .unwrap();

        let entries = table.entries();
        let entries_set: HashSet<&RoaTableEntry> = HashSet::from_iter(entries.iter());

        let expected = expected_table.entries();
        let expected_set: HashSet<&RoaTableEntry> = HashSet::from_iter(expected.iter());

        assert_eq!(entries_set, expected_set);
    }

    #[test]
    fn analyse_bgp_no_announcements() {
        let roa1 = definition("10.0.0.0/23-24 => 64496");
        let roa2 = definition("10.0.3.0/24 => 64497");
        let roa3 = definition("10.0.4.0/24 => 0");

        let resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::with_test_announcements(vec![]);
        let table = analyser.analyse(&[roa1, roa2, roa3], &resources);
        let table_entries = table.entries();
        assert_eq!(3, table_entries.len());

        let roas_no_info: Vec<&RoaDefinition> = table_entries
            .iter()
            .filter(|e| e.state() == RoaTableEntryState::RoaNoAnnouncementInfo)
            .map(|e| e.definition())
            .collect();

        assert_eq!(roas_no_info.as_slice(), &[&roa1, &roa2, &roa3]);
    }
}
