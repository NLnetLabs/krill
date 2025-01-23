use std::str::FromStr;

use serde_json::Value;

use rpki::repository::resources::ResourceSet;

use crate::commons::{
        api::{AsNumber, ConfiguredRoa, RoaPayload, TypedPrefix},
        bgp::{
            make_roa_tree, make_validated_announcement_tree, Announcement,
            AnnouncementValidity, BgpAnalysisEntry,
            BgpAnalysisReport, BgpAnalysisState, BgpAnalysisSuggestion,
            IpRange, ValidatedAnnouncement,
        },
    };


//------------ BgpAnalyser -------------------------------------------------

/// This type helps analyse ROAs vs BGP and vice versa.
pub struct BgpAnalyser {
    bgp_api_enabled: bool,
    bgp_api_uri: String,
}

impl BgpAnalyser {
    pub fn new(
        bgp_api_enabled: bool,
        bgp_api_uri: String,
    ) -> Self {
        BgpAnalyser {
            bgp_api_enabled,
            bgp_api_uri,
        }
    }

    pub fn format_url(&self, prefix: TypedPrefix) -> String {
        let bgp_api_uri_str = self.bgp_api_uri.as_str();
        match prefix {
            TypedPrefix::V4(p) => format!("{}/api/v1/prefix/{:?}/{}/search", 
                bgp_api_uri_str, 
                p.as_ref().addr().to_v4(), 
                p.as_ref().addr_len()
            ),
            TypedPrefix::V6(p) => format!("{}/api/v1/prefix/{:?}/{}/search", 
                bgp_api_uri_str, 
                p.as_ref().addr().to_v6(), 
                p.as_ref().addr_len()
            )
        }
    }

    fn parse_meta(
        &self, 
        meta: &Value, 
        prefix_str: &str, 
        anns: &mut Vec<Announcement>
    ) -> Option<()> {
        if meta["sourceType"].as_str()? == "bgp" {
            for asn in meta["originASNs"].as_array()? {
                // Strip off "AS" prefix
                let asn = 
                    AsNumber::from_str(asn.as_str()?.get(2..)?).ok()?;
                let prefix = 
                    TypedPrefix::from_str(prefix_str).ok()?;

                anns.push(Announcement::new(
                    asn, 
                    prefix
                ));
            }
        }
        Some(())
    }

    fn parse_member(&self, member: &Value, anns: &mut Vec<Announcement>) 
        -> Option<()> {
        let prefix_str = member["prefix"].as_str()?;
        for meta in member["meta"].as_array()? {
            self.parse_meta(meta, prefix_str, anns)?;
        }
        Some(())
    }

    // Obtain the announcements from the JSON tree.
    //
    // Every element in the tree is an Option, if an element cannot be found,
    // we return None, indicating that something about the structure was
    // malformed in some way.
    fn obtain_announcements(&self, json: Value) -> Option<Vec<Announcement>> {
        let mut anns: Vec<Announcement> = vec![];
        let prefix_str = json["result"]["prefix"].as_str()?;
        for meta in json["result"]["meta"].as_array()? {
            self.parse_meta(meta, prefix_str, &mut anns)?;
        }
        for relation in json["result"]["relations"].as_array()? {
            if relation["type"].as_str()? == "more-specific" {
                for member in relation["members"].as_array()? {
                    self.parse_member(member, &mut anns)?;
                }
            }
        }
        Some(anns)
    }

    async fn retrieve(
        &self,
        block: IpRange,
    ) -> Result<Vec<Announcement>, BgpApiError> {
        let client = reqwest::Client::new();

        let mut announcements: Vec<Announcement> = vec![];

        for prefix  in block.to_prefixes() {
            let url = self.format_url(prefix);

            let resp: Value = match url.starts_with("test") {
                true => {
                    // Use test responses predefined in the JSON
                    let json: Value = serde_json::from_str(include_str!(
                        "../../../test-resources/bgp/bgp-api.json"))?;
                    let json_resp = json.get(url.as_str()).unwrap();
                    json_resp.clone()
                },
                false => client.get(url.as_str())
                    .send()
                    .await?
                    .json::<serde_json::Value>()
                    .await?
            };
            
            let ann = self.obtain_announcements(resp);

            if ann.is_none() {
                return Err(BgpApiError::MalformedDataError)
            }
            announcements.append(ann.unwrap().as_mut());
        }

        Ok(announcements)
    }

    pub async fn analyse(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisReport {
        let mut entries = vec![];

        let roas: Vec<ConfiguredRoa> = match &limited_scope {
            None => roas.to_vec(),
            Some(limit) => roas
                .iter()
                .filter(|roa| {
                    limit.contains_roa_address(&roa.as_roa_ip_address())
                })
                .cloned()
                .collect(),
        };

        let (roas_held, roas_not_held): (Vec<ConfiguredRoa>, _) =
            roas.into_iter().partition(|roa| {
                resources_held.contains_roa_address(&roa.as_roa_ip_address())
            });

        for not_held in roas_not_held {
            entries.push(BgpAnalysisEntry::roa_not_held(not_held));
        }

        if !self.bgp_api_enabled {
            // nothing to analyse, just push all ROAs as 'no announcement
            // info'
            for roa in roas_held {
                entries.push(BgpAnalysisEntry::roa_no_announcement_info(roa));
            }
        } else {
            let scope = match &limited_scope {
                Some(limit) => limit,
                None => resources_held,
            };

            let (v4_scope, v6_scope) = IpRange::for_resource_set(scope);

            let mut scoped_announcements: Vec<Announcement> = vec![];
            
            for block in [v4_scope, v6_scope].concat().into_iter() {
                let announcements = self.retrieve(block).await;
                if let Ok(mut announcements) = announcements {
                    scoped_announcements.append(
                        announcements.as_mut());
                } else {
                    for roa in roas_held {
                        entries.push(
                            BgpAnalysisEntry::roa_no_announcement_info(roa)
                        );
                    }
                    return BgpAnalysisReport::new(entries);
                }
            }

            let roa_payloads: Vec<_> = roas_held
                .iter()
                .map(|configured| configured.payload())
                .collect();
            let roa_tree = make_roa_tree(&roa_payloads);
            let validated: Vec<ValidatedAnnouncement> = scoped_announcements
                .into_iter()
                .map(|a| a.validate(&roa_tree))
                .collect();

            // Check all ROAs.. and report ROA state in relation to validated
            // announcements
            let validated_tree =
                make_validated_announcement_tree(validated.as_slice());
            for roa in roas_held {
                let covered =
                    validated_tree.matching_or_more_specific(roa.prefix());

                let other_roas_covering_this_prefix: Vec<_> = roa_tree
                    .matching_or_less_specific(roa.prefix())
                    .into_iter()
                    .filter(|other| roa.payload() != **other)
                    .cloned()
                    .collect();

                let other_roas_including_this_definition: Vec<_> =
                    other_roas_covering_this_prefix
                        .iter()
                        .filter(|other| {
                            other.asn() == roa.asn()
                                && other.prefix().addr_len()
                                    <= roa.prefix().addr_len()
                                && other.effective_max_length()
                                    >= roa.effective_max_length()
                        })
                        .cloned()
                        .collect();

                let authorizes: Vec<Announcement> = covered
                    .iter()
                    .filter(|va| {
                        // VALID announcements under THIS ROA
                        // Already covered so it's under this ROA prefix
                        // ASN must match
                        // Prefix length must be allowed under this ROA (it
                        // could be allowed by another ROA and therefore
                        // valid)
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

                let authorizes_excess = {
                    let max_length = roa.effective_max_length();
                    let nr_of_specific_ann = authorizes
                        .iter()
                        .filter(|ann| ann.prefix().addr_len() == max_length)
                        .count()
                        as u128;

                    nr_of_specific_ann > 0
                        && nr_of_specific_ann < roa.nr_of_specific_prefixes()
                };

                if roa.asn() == AsNumber::zero() {
                    // see if this AS0 ROA is redundant, if it is mark it as
                    // such
                    if other_roas_covering_this_prefix.is_empty() {
                        // will disallow all covered announcements by
                        // definition (because AS0 announcements cannot exist)
                        let announcements = covered
                            .iter()
                            .map(|va| va.announcement())
                            .collect();
                        entries.push(BgpAnalysisEntry::roa_as0(
                            roa,
                            announcements,
                        ));
                    } else {
                        entries.push(BgpAnalysisEntry::roa_as0_redundant(
                            roa,
                            other_roas_covering_this_prefix,
                        ));
                    }
                } else if !other_roas_including_this_definition.is_empty() {
                    entries.push(BgpAnalysisEntry::roa_redundant(
                        roa,
                        authorizes,
                        disallows,
                        other_roas_including_this_definition,
                    ))
                } else if authorizes.is_empty() && disallows.is_empty() {
                    entries.push(BgpAnalysisEntry::roa_unseen(roa))
                } else if authorizes_excess {
                    entries.push(BgpAnalysisEntry::roa_too_permissive(
                        roa, authorizes, disallows,
                    ))
                } else if authorizes.is_empty() {
                    entries.push(BgpAnalysisEntry::roa_disallowing(
                        roa, disallows,
                    ))
                } else {
                    entries.push(BgpAnalysisEntry::roa_seen(
                        roa, authorizes, disallows,
                    ))
                }
            }

            // Loop over all validated announcements and report
            for v in validated.into_iter() {
                let (announcement, validity, allowed_by, invalidating_roas) =
                    v.unpack();
                match validity {
                    AnnouncementValidity::Valid => {
                        entries.push(BgpAnalysisEntry::announcement_valid(
                            announcement,
                            allowed_by.unwrap(), /* always set for valid
                                                  * announcements */
                        ))
                    }
                    AnnouncementValidity::Disallowed => {
                        entries.push(
                            BgpAnalysisEntry::announcement_disallowed(
                                announcement,
                                invalidating_roas,
                            ),
                        );
                    }
                    AnnouncementValidity::InvalidLength => {
                        entries.push(
                            BgpAnalysisEntry::announcement_invalid_length(
                                announcement,
                                invalidating_roas,
                            ),
                        );
                    }
                    AnnouncementValidity::InvalidAsn => {
                        entries.push(
                            BgpAnalysisEntry::announcement_invalid_asn(
                                announcement,
                                invalidating_roas,
                            ),
                        );
                    }
                    AnnouncementValidity::NotFound => {
                        entries.push(
                            BgpAnalysisEntry::announcement_not_found(
                                announcement,
                            ),
                        );
                    }
                }
            }
        }
        BgpAnalysisReport::new(entries)
    }

    pub async fn suggest(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisSuggestion {
        let mut suggestion = BgpAnalysisSuggestion::default();

        // perform analysis
        let entries = self
            .analyse(roas, resources_held, limited_scope)
            .await
            .into_entries();
        for entry in &entries {
            match entry.state() {
                BgpAnalysisState::RoaUnseen => {
                    suggestion.add_stale(entry.configured_roa())
                }
                BgpAnalysisState::RoaTooPermissive => {
                    let replace_with = entry
                        .authorizes()
                        .iter()
                        .filter(|ann| {
                            !entries.iter().any(|other| {
                                other != entry
                                    && other.authorizes().contains(*ann)
                            })
                        })
                        .map(|auth| RoaPayload::from(*auth))
                        .collect();

                    suggestion.add_too_permissive(
                        entry.configured_roa(),
                        replace_with,
                    );
                }
                BgpAnalysisState::RoaSeen | BgpAnalysisState::RoaAs0 => {
                    suggestion.add_keep(entry.configured_roa())
                }
                BgpAnalysisState::RoaDisallowing => {
                    suggestion.add_disallowing(entry.configured_roa())
                }
                BgpAnalysisState::RoaRedundant => {
                    suggestion.add_redundant(entry.configured_roa())
                }
                BgpAnalysisState::RoaNotHeld => {
                    suggestion.add_not_held(entry.configured_roa())
                }
                BgpAnalysisState::RoaAs0Redundant => {
                    suggestion.add_as0_redundant(entry.configured_roa())
                }
                BgpAnalysisState::AnnouncementValid => {}
                BgpAnalysisState::AnnouncementNotFound => {
                    suggestion.add_not_found(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidAsn => {
                    suggestion.add_invalid_asn(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidLength => {
                    suggestion.add_invalid_length(entry.announcement())
                }
                BgpAnalysisState::AnnouncementDisallowed => {
                    suggestion.add_keep_disallowing(entry.announcement())
                }
                BgpAnalysisState::RoaNoAnnouncementInfo => {
                    suggestion.add_keep(entry.configured_roa())
                }
            }
        }

        suggestion
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug)]
pub enum BgpApiError {
    ReqwestError(reqwest::Error),
    SerdeError(serde_json::Error),
    MalformedDataError
}

impl From<reqwest::Error> for BgpApiError {
    fn from(e: reqwest::Error) -> BgpApiError {
        BgpApiError::ReqwestError(e)
    }
}

impl From<serde_json::Error> for BgpApiError {
    fn from(e: serde_json::Error) -> BgpApiError {
        BgpApiError::SerdeError(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use rpki::repository::resources::Prefix;

    use crate::{
        commons::{api::{Ipv4Prefix, Ipv6Prefix, RoaConfigurationUpdates}, bgp::BgpAnalysisState},
        test::{announcement, configured_roa},
    };

    use super::*;

    #[tokio::test]
    async fn analyse_bgp() {
        let roa_too_permissive = configured_roa("10.0.0.0/22-23 => 64496");
        let roa_as0 = configured_roa("10.0.4.0/24 => 0");
        let roa_unseen_completely = configured_roa("10.0.3.0/24 => 64497");

        let roa_not_held = configured_roa("10.1.0.0/24 => 64497");

        let roa_authorizing_single =
            configured_roa("192.168.1.0/24 => 64497");
        let roa_unseen_redundant = configured_roa("192.168.1.0/24 => 64498");
        let roa_as0_redundant = configured_roa("192.168.1.0/24 => 0");

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/16, 192.168.0.0/16", "")
                .unwrap();
        let limit = None;

        let analyser = BgpAnalyser {
            bgp_api_enabled: true,
            bgp_api_uri: "test".to_string()
        };

        let report = analyser
            .analyse(
                &[
                    roa_too_permissive,
                    roa_as0,
                    roa_unseen_completely,
                    roa_not_held,
                    roa_authorizing_single,
                    roa_unseen_redundant,
                    roa_as0_redundant,
                ],
                &resources_held,
                limit,
            )
            .await;

        let expected: BgpAnalysisReport = serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_full_report.json"
        ))
        .unwrap();

        assert_eq!(report, expected);
    }

    #[tokio::test]
    async fn analyse_bgp_disallowed_announcements() {
        let roa = configured_roa("10.0.0.0/22 => 0");

        let roas = &[roa];
        let analyser = BgpAnalyser {
            bgp_api_enabled: true,
            bgp_api_uri: "test".to_string()
        };

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let report = analyser.analyse(roas, &resources_held, None).await;

        assert!(!report.contains_invalids());

        let mut disallowed = report
            .matching_announcements(BgpAnalysisState::AnnouncementDisallowed);
        disallowed.sort();

        let disallowed_1 = announcement("10.0.0.0/22 => 64496");
        let disallowed_2 = announcement("10.0.0.0/22 => 64497");
        let disallowed_3 = announcement("10.0.0.0/24 => 64496");
        let disallowed_4 = announcement("10.0.2.0/23 => 64496");
        let mut expected =
            vec![disallowed_1, disallowed_2, disallowed_3, disallowed_4];
        expected.sort();

        assert_eq!(disallowed, expected);

        // The suggestion should not try to add the disallowed announcements
        // because they were disallowed by an AS0 roa.
        let suggestion = analyser.suggest(roas, &resources_held, None).await;
        let updates = RoaConfigurationUpdates::from(suggestion);

        let added = updates.added();
        for announcement in disallowed {
            assert!(!added.iter().any(|added_roa| {
                let added_payload = added_roa.payload();
                let announcement_payload = RoaPayload::from(announcement);
                added_payload.includes(&announcement_payload)
            }));
        }
    }

    #[tokio::test]
    async fn analyse_bgp_no_announcements() {
        let roa1 = configured_roa("10.0.0.0/23-24 => 64496");
        let roa2 = configured_roa("10.0.3.0/24 => 64497");
        let roa3 = configured_roa("10.0.4.0/24 => 0");

        let roas = vec![roa1, roa2, roa3];

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::new(false, "".to_string());
        let table = analyser.analyse(&roas, &resources_held, None).await;
        let table_entries = table.entries();
        assert_eq!(3, table_entries.len());

        let roas_no_info: Vec<ConfiguredRoa> = table_entries
            .iter()
            .filter(|e| e.state() == BgpAnalysisState::RoaNoAnnouncementInfo)
            .map(|e| e.configured_roa().clone())
            .collect();

        assert_eq!(roas_no_info, roas);
    }

    #[tokio::test]
    async fn make_bgp_analysis_suggestion() {
        let roa_too_permissive = configured_roa("10.0.0.0/22-23 => 64496");
        let roa_redundant = configured_roa("10.0.0.0/23 => 64496");
        let roa_as0 = configured_roa("10.0.4.0/24 => 0");
        let roa_unseen_completely = configured_roa("10.0.3.0/24 => 64497");
        let roa_authorizing_single =
            configured_roa("192.168.1.0/24 => 64497");
        let roa_unseen_redundant = configured_roa("192.168.1.0/24 => 64498");
        let roa_as0_redundant = configured_roa("192.168.1.0/24 => 0");

        let roas = &[
            roa_too_permissive,
            roa_redundant,
            roa_as0,
            roa_unseen_completely,
            roa_authorizing_single,
            roa_unseen_redundant,
            roa_as0_redundant,
        ];

        let analyser = BgpAnalyser {
            bgp_api_enabled: true,
            bgp_api_uri: "test".to_string()
        };

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let limit =
            Some(ResourceSet::from_strs("", "10.0.0.0/22", "").unwrap());
        let suggestion_resource_subset =
            analyser.suggest(roas, &resources_held, limit).await;

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_suggestion_some_roas.json"
        ))
            .unwrap();
        assert_eq!(suggestion_resource_subset, expected);

        let suggestion_all_roas_in_scope =
            analyser.suggest(roas, &resources_held, None).await;

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_suggestion_all_roas.json"
        ))
            .unwrap();

        assert_eq!(suggestion_all_roas_in_scope, expected);
    }

    #[test]
    fn format_url() {
        let analyser = BgpAnalyser::new(
            true, "https://rest.bgp-api.net".to_string());
        assert_eq!("https://rest.bgp-api.net/api/v1/prefix/192.168.0.0/16/search", 
            analyser.format_url(TypedPrefix::from(Ipv4Prefix::from(
                Prefix::from_str("192.168.0.0/16").unwrap()))));
        assert_eq!("https://rest.bgp-api.net/api/v1/prefix/2001:db8::/32/search", 
            analyser.format_url(TypedPrefix::from(Ipv6Prefix::from(
                Prefix::from_str("2001:db8::/32").unwrap()))));
    }

    #[tokio::test]
    async fn retrieve_announcements() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "185.49.140.0/22";
        let ipv6s = "2a04:b900::/29";
        let set = ResourceSet::from_strs("", ipv4s, ipv6s).unwrap();

        let (v4_ranges, v6_ranges) = IpRange::for_resource_set(&set);

        for range in v6_ranges {
            assert_eq!(6, analyser.retrieve(range).await.unwrap().len());
        }

        for range in v4_ranges {
            assert_eq!(3, analyser.retrieve(range).await.unwrap().len());
        }
    }

    #[tokio::test]
    async fn retrieve_broken_announcements() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "1.1.1.1/32, 2.2.2.2/32, 3.3.3.3/32, 4.4.4.4/32";
        let set = ResourceSet::from_strs("", ipv4s, "").unwrap();
        
        let (v4_ranges, _) = IpRange::for_resource_set(&set);

        for range in v4_ranges {
            assert!(analyser.retrieve(range).await.is_err());
        }
    }

    #[tokio::test]
    async fn analyse_nlnet_labs_snapshot() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "185.49.140.0/22";
        let ipv6s = "2a04:b900::/29";
        let set = ResourceSet::from_strs("AS211321", ipv4s, ipv6s).unwrap();

        let roas = &[
            configured_roa("2a04:b906::/48-48 => 0"),
            configured_roa("2a04:b907::/48-48 => 0"),
            configured_roa("185.49.142.0/24-24 => 0"),
            configured_roa("2a04:b900::/30-32 => 8587"),
            configured_roa("185.49.140.0/23-23 => 8587"),
            configured_roa("2a04:b900::/30-30 => 8587"),
            configured_roa("2a04:b905::/48-48 => 14618"),
            configured_roa("2a04:b905::/48-48 => 16509"),
            configured_roa("2a04:b902::/32-32 => 16509"),
            configured_roa("2a04:b904::/48-48 => 211321"),
            configured_roa("2a04:b907::/47-47 => 211321"),
            configured_roa("185.49.142.0/23-23 => 211321"),
            configured_roa("2a04:b902::/48-48 => 211321"),
            configured_roa("185.49.143.0/24-24 => 211321"),
        ];

        let report = analyser.analyse(roas, &set, None).await;

        dbg!(&report);

        let entry_expect_roa = |x: &str, y| {
            let x = x.to_string();
            assert!(report.entries().iter().any(|s| 
                s.state() == y &&
                s.configured_roa().to_string() == x 
            ));
        };

        let entry_expect_ann = |x: &str, y: u32, z: BgpAnalysisState| {
            let x = x.to_string();
            assert!(report.entries().iter().any(|s|
                s.state() == z &&
                *s.announcement().asn() == AsNumber::new(y) &&
                s.announcement().prefix().to_string() == x
            ));
        };

        entry_expect_roa("2a04:b907::/48-48 => 0", BgpAnalysisState::RoaAs0Redundant);
        entry_expect_roa("185.49.142.0/24-24 => 0", BgpAnalysisState::RoaAs0Redundant);
        entry_expect_roa("2a04:b900::/30-30 => 8587", BgpAnalysisState::RoaRedundant);
        entry_expect_roa("2a04:b905::/48-48 => 14618", BgpAnalysisState::RoaUnseen);
        entry_expect_roa("2a04:b902::/32-32 => 16509", BgpAnalysisState::RoaUnseen);
        entry_expect_ann("2a04:b907::/48", 211321, BgpAnalysisState::AnnouncementInvalidLength);
        entry_expect_ann("185.49.142.0/24", 211321, BgpAnalysisState::AnnouncementInvalidLength);
        entry_expect_roa("2a04:b902::/48-48 => 211321", BgpAnalysisState::RoaUnseen);
        entry_expect_roa("185.49.143.0/24-24 => 211321", BgpAnalysisState::RoaUnseen);
    }
}
