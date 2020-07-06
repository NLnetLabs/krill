use std::env;
use std::sync::RwLock;

use chrono::Duration;

use rpki::x509::Time;

use crate::commons::api::{ResourceSet, RoaDefinition};
use crate::commons::bgp::{
    make_roa_tree, make_validated_announcement_tree, Announcement, AnnouncementValidity,
    Announcements, BgpAnalysisEntry, BgpAnalysisReport, IpRange, RisDumpError, RisDumpLoader,
    ValidatedAnnouncement,
};
use crate::constants::{BGP_RIS_REFRESH_MINUTES, KRILL_ENV_TEST_ANN};

//------------ BgpAnalyser -------------------------------------------------

/// This type helps analyse ROAs vs BGP and vice versa.
pub struct BgpAnalyser {
    dumploader: Option<RisDumpLoader>,
    seen: RwLock<Announcements>,
}

impl BgpAnalyser {
    pub fn new(ris_enabled: bool, ris_v4_uri: &str, ris_v6_uri: &str) -> Self {
        if env::var(KRILL_ENV_TEST_ANN).is_ok() {
            Self::with_test_announcements()
        } else {
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
    }

    pub async fn update(&self) -> Result<bool, BgpAnalyserError> {
        if let Some(loader) = &self.dumploader {
            let mut seen = self.seen.write().unwrap();
            if let Some(last_time) = seen.last_checked() {
                if (last_time + Duration::minutes(BGP_RIS_REFRESH_MINUTES)) > Time::now() {
                    trace!("Will not check BGP Ris Dumps until the refresh interval has passed");
                    return Ok(false); // no need to update yet
                }
            }
            let announcements = loader.download_updates().await?;
            if seen.equivalent(&announcements) {
                debug!("BGP Ris Dumps unchanged");
                seen.update_checked();
                Ok(false)
            } else {
                info!(
                    "Updated announcements ({}) based on BGP Ris Dumps",
                    announcements.len()
                );
                seen.update(announcements);
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    pub fn analyse(&self, roas: &[RoaDefinition], scope: &ResourceSet) -> BgpAnalysisReport {
        let seen = self.seen.read().unwrap();
        let mut entries = vec![];

        if seen.last_checked().is_none() {
            // nothing to analyse, just push all ROAs as 'no announcement info'
            for roa in roas {
                entries.push(BgpAnalysisEntry::roa_no_announcement_info(*roa));
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
                    entries.push(BgpAnalysisEntry::roa_unseen(*roa))
                } else {
                    let allows: Vec<Announcement> = covered
                        .iter()
                        .filter(|va| {
                            // VALID announcements under THIS ROA
                            // Already covered so it's under this ROA's prefix
                            // ASN must match
                            // Prefix length must be allowed under this ROA (it could be allowed by another ROA and therefore valid)
                            va.validity() == AnnouncementValidity::Valid
                                && va.announcement().prefix().addr_len()
                                    <= roa.effective_max_length()
                                && va.announcement().asn() == &roa.asn()
                        })
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

                    entries.push(BgpAnalysisEntry::roa_seen(*roa, allows, disallows))
                }
            }

            // Loop over all validated announcements and report
            for v in validated.into_iter() {
                let (announcement, validity, allowed_by, invalidating_roas) = v.unpack();
                match validity {
                    AnnouncementValidity::Valid => {
                        entries.push(BgpAnalysisEntry::announcement_valid(
                            announcement,
                            allowed_by.unwrap(), // always set for valid announcements
                        ))
                    }
                    AnnouncementValidity::InvalidLength => {
                        entries.push(BgpAnalysisEntry::announcement_invalid_length(
                            announcement,
                            invalidating_roas,
                        ));
                    }
                    AnnouncementValidity::InvalidAsn => {
                        entries.push(BgpAnalysisEntry::announcement_invalid_asn(
                            announcement,
                            invalidating_roas,
                        ));
                    }
                    AnnouncementValidity::NotFound => {
                        entries.push(BgpAnalysisEntry::announcement_not_found(announcement));
                    }
                }
            }
        }
        BgpAnalysisReport::new(entries)
    }

    fn test_announcements() -> Vec<Announcement> {
        use crate::test::announcement;

        let mut res = vec![];

        res.push(announcement("10.0.0.0/22 => 64496"));
        res.push(announcement("10.0.2.0/23 => 64496"));
        res.push(announcement("10.0.0.0/24 => 64496"));
        res.push(announcement("10.0.0.0/22 => 64497"));
        res.push(announcement("10.0.0.0/21 => 64497"));

        res.push(announcement("192.168.0.0/26 => 64497"));
        res.push(announcement("192.168.0.0/26 => 64496"));

        res.push(announcement("2001:DB8::/32 => 64498"));

        res
    }

    fn with_test_announcements() -> Self {
        let mut announcements = Announcements::default();
        announcements.update(Self::test_announcements());
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

    use crate::commons::bgp::BgpAnalysisState;
    use crate::test::*;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn download_ris_dumps() {
        let bgp_risdump_v4_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz";
        let bgp_risdump_v6_uri = "http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz";

        let analyser = BgpAnalyser::new(true, bgp_risdump_v4_uri, bgp_risdump_v6_uri);

        assert!(analyser.seen.read().unwrap().is_empty());
        assert!(analyser.seen.read().unwrap().last_checked().is_none());
        analyser.update().await.unwrap();
        assert!(!analyser.seen.read().unwrap().is_empty());
        assert!(analyser.seen.read().unwrap().last_checked().is_some());
    }

    #[test]
    fn analyse_bgp() {
        let roa_authorizing = definition("10.0.0.0/22-23 => 64496");
        let roa_stale = definition("10.0.3.0/24 => 64497");
        let roa_disallowing = definition("10.0.4.0/24 => 0");

        let resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::with_test_announcements();

        let report = analyser.analyse(&[roa_authorizing, roa_stale, roa_disallowing], &resources);

        let expected: BgpAnalysisReport = serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_full_report.json"
        ))
        .unwrap();

        assert_eq!(report, expected);
    }

    #[test]
    fn analyse_bgp_no_announcements() {
        let roa1 = definition("10.0.0.0/23-24 => 64496");
        let roa2 = definition("10.0.3.0/24 => 64497");
        let roa3 = definition("10.0.4.0/24 => 0");

        let resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::new(false, "", "");
        let table = analyser.analyse(&[roa1, roa2, roa3], &resources);
        let table_entries = table.entries();
        assert_eq!(3, table_entries.len());

        let roas_no_info: Vec<&RoaDefinition> = table_entries
            .iter()
            .filter(|e| e.state() == BgpAnalysisState::RoaNoAnnouncementInfo)
            .map(|e| e.definition())
            .collect();

        assert_eq!(roas_no_info.as_slice(), &[&roa1, &roa2, &roa3]);
    }
}
