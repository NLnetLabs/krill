//! The actual BGP analyser and its supporting, private data structures.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use arc_swap::ArcSwapOption;
use chrono::{DateTime, Duration, Utc};
use log::trace;
use rpki::repository::resources::{IpBlock, ResourceSet};
use rpki::repository::x509::Time;
use crate::api::bgp::{
    Announcement, BgpAnalysisEntry, BgpAnalysisReport, BgpAnalysisState,
    BgpAnalysisSuggestion, ReplacementRoaSuggestion,
};
use crate::api::roa::{
    AsNumber, ConfiguredRoa, Ipv4Prefix, Ipv6Prefix, RoaPayload, TypedPrefix,
};
use crate::config::Config;
use super::riswhois::{
    RisWhois, RisWhoisError, RisWhoisLoader, RouteOrigin, RouteOriginSet,
    RoutePrefix,
};


//------------ BgpAnalyser -------------------------------------------------

/// An analyser for the effects of ROAs against real-world BGP data.
///
/// The analyser is configured with the URLs of the RISwhois dumps and
/// whether to download them at all and if so, how often. It doesn’t download
/// data immediately but only when the [`update`][Self::update] method is
/// called. 
/// 
/// There are two methods that perform an analyis: [`analyse`][Self::analyse]
/// produces a report for an existing set of ROAs while
/// [`suggest`][Self::suggest] also adds suggestions what ROAs should be
/// created.
pub struct BgpAnalyser {
    /// The loader for RISwhois data.
    ///
    /// If this is `None`, loading data has been disabled.
    loader: Option<RisWhoisLoader>,

    /// How long should we wait before downloading the data again.
    refresh_duration: Duration,

    /// The last time we downloaded the data.
    ///
    /// This is the Unix timestamp in full seconds of that time. If we never
    /// downloaded the data, this will be set to `i64::MIN`.
    last_checked: AtomicI64,

    /// The current set of RISwhois data.
    ///
    /// This may be `None` if we haven’t downloaded a set (yet).
    riswhois: ArcSwapOption<RisWhois>,
}

impl BgpAnalyser {
    /// Creates a new analyser using information in the config.
    pub fn new(config: &Config) -> Self {
        Self {
            loader: config.bgp_riswhois_enabled.then(|| {
                RisWhoisLoader::new(
                    config.bgp_riswhois_v4_uri.clone(),
                    config.bgp_riswhois_v6_uri.clone(),
                )
            }),
            refresh_duration: config.bgp_riswhois_refresh_duration,
            last_checked: i64::MIN.into(),
            riswhois: ArcSwapOption::new(None),
        }
    }

    /// Updates the RISwhois dataset.
    ///
    /// This can be called at any time and will only actually download data
    /// if downloading has been enabled and if the configured refresh
    /// duration has passed since the last download.
    ///
    /// Returns `Ok(true)` if it did do a download, `Ok(false)` if no download
    /// was necessary, or an error if downloading was attempted but failed.
    pub async fn update(&self) -> Result<bool, RisWhoisError> {
        let Some(loader) = self.loader.as_ref() else {
            return Ok(false)
        };
        let last_checked = Time::new(
            DateTime::from_timestamp(
                self.last_checked.load(Ordering::Relaxed), 0
            ).unwrap_or(DateTime::<Utc>::MIN_UTC)
        );
        if last_checked + self.refresh_duration < Time::now() {
            trace!(
                "RISwhois update requested but refresh duration \
                 has not yet passed."
            );
            return Ok(false)
        }

        self.riswhois.store(Some(Arc::new(loader.load().await?)));
        self.last_checked.store(Time::now().timestamp(), Ordering::Relaxed);
        Ok(true)
    }

    /// Creates a BGP analysis report for a set of ROAs and resources.
    ///
    /// The ROAs to be analysed are given via `roas` and the resources held
    /// by the CA publishing the ROAs via `resources_held`. If required,
    /// the ROAs to be analysed can be limited to those covered by the
    /// resource set given through `limited_scope`.
    ///
    /// The method returns a BGP analysis report providing information on
    /// how the ROAs and resources based on the current RISwhois data. If no
    /// data is currently available, the report will contain “no announcement
    /// info” for each ROA.
    pub fn analyse(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisReport {
        let mut entries = Vec::new();

        // Create a list of the ROAs that are contained in the held
        // resources but not in the limited scope. Everything that is in
        // neither goes directly into the `entries` as ‘not held.’
        let mut roas_held = Vec::new();
        for roa in roas {
            if let Some(limit) = limited_scope.as_ref() {
                if !limit.contains_roa_address(
                    &roa.roa_configuration.payload.as_roa_ip_address()
                ) {
                    continue
                }
            }

            if resources_held.contains_roa_address(
                &roa.roa_configuration.payload.as_roa_ip_address()
            ) {
                roas_held.push(roa.clone());
            }
            else {
                entries.push(BgpAnalysisEntry::roa_not_held(roa.clone()));
            }
        }

        // If we don’t have RISwhois data, we can add the held ROAs as well
        // and return.
        let seen = self.riswhois.load();
        let Some(seen) = seen.as_ref() else {
            for roa in roas_held {
                entries.push(BgpAnalysisEntry::roa_no_announcement_info(roa));
            }
            return BgpAnalysisReport::new(entries)
        };

        // Determine the scope of our analysis. This is `limited_scope` if
        // present or the held resources otherwise.
        let scope = limited_scope.as_ref().unwrap_or(resources_held);

        // Convert the scope to a list of prefixes for v4 and v6 each.
        let (v4_scope, v6_scope) = Self::get_prefixes_from_scope(scope);

        // The original code now collects all route origins seen under these
        // prefixes into `scoped_announcements`. We don’t really need that
        // since we can just walk our trees if necessary.

        // Extract the ROA prefixes and break them up into v4 and v6.
        let (v4_roas, v6_roas) = Self::split_roas(&roas_held);

        // Next, go over all route origins in scope and validate them using
        // the held ROAs.
        let mut v4_validated = Vec::new();
        for v4 in v4_scope {
            for route_origins in seen.v4().eq_or_more_specific(v4) {
                ValidatedRouteOrigin::validate_set(
                    route_origins, &v4_roas, &mut v4_validated,
                )
            }
        }
        let mut v6_validated = Vec::new();
        for v6 in v6_scope {
            for route_origins in seen.v6().eq_or_more_specific(v6) {
                ValidatedRouteOrigin::validate_set(
                    route_origins, &v6_roas, &mut v6_validated,
                )
            }
        }

        // Finally, go over all ROAs and determine their state based on the
        // validated route_origins.
        for roa in &v4_roas {
            entries.push(
                Self::categorise_roa(
                    *roa, &v4_validated, &v4_roas,
                )
            );
        }
        for roa in &v6_roas {
            entries.push(
                Self::categorise_roa(
                    *roa, &v6_validated, &v6_roas,
                )
            );
        }

        // Add the status of all route origins.
        entries.extend(v4_validated.into_iter().map(|origin| {
            origin.into_analysis_entry()
        }));
        entries.extend(v6_validated.into_iter().map(|origin| {
            origin.into_analysis_entry()
        }));

        BgpAnalysisReport::new(entries)
    }

    /// Create a BGP suggestions report for a set of ROAs and resources.
    ///
    /// This is very similar to the [`analyse`][Self::analyse] method but
    /// the returned report also contains suggestions what ROAs the CA should
    /// contain.
    pub fn suggest(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisSuggestion {
        let mut suggestion = BgpAnalysisSuggestion::default();

        // perform analysis
        let entries = self.analyse(
            roas, resources_held, limited_scope
        ).into_entries();
        for entry in &entries {
            match entry.state() {
                BgpAnalysisState::RoaUnseen => {
                    suggestion.stale.push(entry.configured_roa().clone())
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

                    suggestion.too_permissive.push(
                        ReplacementRoaSuggestion {
                            current: entry.configured_roa().clone(),
                            new: replace_with,
                        }
                    );
                }
                BgpAnalysisState::RoaSeen | BgpAnalysisState::RoaAs0 => {
                    suggestion.keep.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaDisallowing => {
                    suggestion.disallowing.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaRedundant => {
                    suggestion.redundant.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaNotHeld => {
                    suggestion.not_held.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaAs0Redundant => {
                    suggestion.as0_redundant.push(
                        entry.configured_roa().clone()
                    )
                }
                BgpAnalysisState::AnnouncementValid => {}
                BgpAnalysisState::AnnouncementNotFound => {
                    suggestion.not_found.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidAsn => {
                    suggestion.invalid_asn.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidLength => {
                    suggestion.invalid_length.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementDisallowed => {
                    suggestion.keep_disallowing.push(entry.announcement())
                }
                BgpAnalysisState::RoaNoAnnouncementInfo => {
                    suggestion.keep.push(entry.configured_roa().clone())
                }
            }
        }

        suggestion
    }

    /// Returns the address prefixes contained in a resource set.
    ///
    /// The function will return two vecs, one for IPv4 and one for IPv6
    /// prefixes.
    fn get_prefixes_from_scope(
        scope: &ResourceSet
    ) -> (Vec<Ipv4Prefix>, Vec<Ipv6Prefix>) {
        let mut v4 = Vec::new();
        for block in scope.ipv4().iter() {
            match block {
                IpBlock::Prefix(prefix) => v4.push(Ipv4Prefix::from(prefix)),
                IpBlock::Range(range) => {
                    v4.extend(range.to_v4_prefixes().map(Ipv4Prefix::from))
                }
            }
        }

        let mut v6 = Vec::new();
        for block in scope.ipv6().iter() {
            match block {
                IpBlock::Prefix(prefix) => v6.push(Ipv6Prefix::from(prefix)),
                IpBlock::Range(range) => {
                    v6.extend(range.to_v6_prefixes().map(Ipv6Prefix::from))
                }
            }
        }

        // XXX This chould drop prefixes that are covered by other prefixes.
        //     Allthough, in practice, this shouldn’t happen, since the
        //     relevant RFC doesn’t allow resource sets to be like that.

        (v4, v6)
    }

    /// Splits a set of ROAs into those for IPv4 and IPv6.
    ///
    /// The function wraps each ROA into a type that also contains the
    /// address prefix of the ROA and a reference to the [`ConfiguredRoa`].
    fn split_roas(
        roas: &[ConfiguredRoa]
    ) -> (Vec<Roa<'_, Ipv4Prefix>>, Vec<Roa<'_, Ipv6Prefix>>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for roa in roas {
            match roa.roa_configuration.payload.prefix {
                TypedPrefix::V4(prefix) => v4.push(Roa::new(prefix, roa)),
                TypedPrefix::V6(prefix) => v6.push(Roa::new( prefix, roa)),
            }
        }
        (v4, v6)
    }

    /// Categorises a ROA for analysis.
    ///
    /// The function takes a roa, a set of validated route origins, and the
    /// set of all ROAs and translates it into a [`BgpAnalysisEntry`] for the
    /// report.
    fn categorise_roa<P: RoutePrefix>(
        roa: Roa<P>,
        validated_origins: &[ValidatedRouteOrigin<P>],
        all_roas: &[Roa<P>],
    ) -> BgpAnalysisEntry {
        // Get all validated origins covered by the prefix.
        let covered = validated_origins.iter().filter(|origin| {
            roa.prefix.covers(origin.route_origin.prefix)
        }).collect::<Vec<_>>();

        // Find other ROAs that cover this ROA. Their max-len may be less,
        // so they don’t make this announcement superfluous. 
        let other_roas_covering_this_prefix = all_roas.iter().filter(|other| {
            other.prefix.covers(roa.prefix) && roa.payload() != other.payload()
        }).map(|roa| roa.payload()).collect::<Vec<_>>();

        // Find other ROAs that include this ROA’s definition and thus make
        // it superfluous.
        let other_roas_including_this_definition
            = other_roas_covering_this_prefix.iter().filter(|other| {
                other.asn == roa.origin()
                    && other.prefix.addr_len() <= roa.prefix.addr_len()
                    && other.effective_max_length() >= roa.effective_max_len()
            }).copied().collect::<Vec<_>>();

        // Find all route origins that are made valid by this ROA.
        //
        // (Using filter and then map here makes the code quite a bit
        // easier ...)
        let authorizes = covered.iter().filter(|origin| {
            matches!(origin.validity, RouteOriginValidity::Valid(_))
                && origin.route_origin.prefix.addr_len()
                    <= roa.effective_max_len()
                && origin.route_origin.origin == roa.origin()
        }).map(|origin| origin.announcement()).collect::<Vec<_>>();

        // Find all route origins that are made invalid by this ROA.
        let disallows = covered.iter().filter(|origin| {
            matches!(
                origin.validity,
                RouteOriginValidity::InvalidLength
                    | RouteOriginValidity::InvalidAsn
            )
        }).map(|origin| origin.announcement()).collect::<Vec<_>>();

        // Is the ROA too permissive?
        //
        // XXX: I don’t understand why this does what it does.
        let authorizes_excess = {
            let max_len = roa.effective_max_len();
            let nr_of_specific_origins = u128::try_from(
                authorizes.iter().filter(|origin| {
                    origin.prefix.addr_len() == max_len
                }).count()
            ).unwrap_or(u128::MAX);

            nr_of_specific_origins > 0
                && nr_of_specific_origins
                    < roa.payload().nr_of_specific_prefixes()
        };

        // Now we have everything we need to categorize the ROA.
        if roa.origin() == AsNumber::AS0 {
            if other_roas_covering_this_prefix.is_empty() {
                // Disallows all covered route origins.
                BgpAnalysisEntry::roa_as0(
                    roa.roa.clone(),
                    covered.iter().map(|origin| {
                        origin.announcement()
                    }).collect()
                )
            }
            else {
                // This AS0 ROA is redundant.
                BgpAnalysisEntry::roa_as0_redundant(
                    roa.roa.clone(),
                    other_roas_covering_this_prefix,
                )
            }
        }
        else if !other_roas_including_this_definition.is_empty() {
            BgpAnalysisEntry::roa_redundant(
                roa.roa.clone(),
                authorizes,
                disallows,
                other_roas_including_this_definition
            )
        }
        else if authorizes.is_empty() && disallows.is_empty() {
            BgpAnalysisEntry::roa_unseen(roa.roa.clone())
        }
        else if authorizes_excess {
            BgpAnalysisEntry::roa_too_permissive(
                roa.roa.clone(), authorizes, disallows
            )
        }
        else if authorizes.is_empty() {
            BgpAnalysisEntry::roa_disallowing(roa.roa.clone(), disallows)
        }
        else {
            BgpAnalysisEntry::roa_seen(roa.roa.clone(), authorizes, disallows)
        }
    }

}


//------------ Roa -----------------------------------------------------------

/// A configured ROA plus its address prefix.
///
/// This type only exists to be generic over the address family. Thus, `P`
/// can either be [`Ipv4Prefix`] or [`Ipv6Prefix`].
#[derive(Clone, Copy, Debug)]
pub struct Roa<'a, P> {
    /// The address prefix of the ROA.
    prefix: P,

    /// A reference to the actual ROA.
    roa: &'a ConfiguredRoa,
}

impl<'a, P: RoutePrefix> Roa<'a, P> {
    /// Creates a new value from its parts.
    fn new(prefix: P, roa: &'a ConfiguredRoa) -> Self {
        Self { prefix, roa }
    }

    /// Returns the ROA payload definition of the ROA.
    fn payload(self) -> RoaPayload {
        self.roa.roa_configuration.payload
    }

    /// Returns the origin AS number of the ROA definition.
    fn origin(self) -> AsNumber {
        self.roa.roa_configuration.payload.asn
    }

    /// Retuns the maximum prefix length of the ROA definition.
    fn max_len(self) -> Option<u8> {
        self.roa.roa_configuration.payload.max_length
    }

    /// Returns the effective maximum prefix length of the ROA definition.
    ///
    /// This is the maximum prefix length if provided or the address prefix
    /// length otherwise.
    fn effective_max_len(self) -> u8 {
        self.max_len().unwrap_or(self.prefix.addr_len())
    }
}


//------------ ValidatedRouteOrigin ------------------------------------------

/// A route origin with route origin validation applied to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRouteOrigin<P> {
    /// The route origin, i.e., address prefix and origin AS number.
    route_origin: RouteOrigin<P>,

    /// The validation status of the route origin.
    validity: RouteOriginValidity,

    /// The ROAs that contributed to invalidating the route origin.
    disallowing: Vec<RoaPayload>,
}

impl<P: RoutePrefix> ValidatedRouteOrigin<P> {
    /// Validates a set of route origin against a set of ROAs.
    ///
    /// Appends the validation verdict for each route origin to the end of
    /// `target`.
    fn validate_set(
        route_origins: RouteOriginSet<P>,
        roas: &[Roa<P>],
        target: &mut Vec<Self>,
    ) {
        // Find all ROAs that cover the route origin’s prefix.
        let covering = roas.iter().copied().filter(|roa| {
            roa.prefix.covers(route_origins.prefix())
        }).collect::<Vec<_>>();

        // If there aren’t any, all route origins in the set are unknown.
        if covering.is_empty() {
            target.extend(route_origins.iter().map(|origin| {
                Self {
                    route_origin: origin,
                    validity: RouteOriginValidity::NotFound,
                    disallowing: Vec::new(),
                }
            }));
            return
        }

        for origin in route_origins.iter() {
            target.push(Self::validate(origin, &covering));
        }
    }

    /// Validates a single route origin against a set of ROAs.
    ///
    /// Returns the verdict.
    fn validate(
        origin: RouteOrigin<P>,
        covering: &[Roa<P>]
    ) -> Self {
        let mut invalidating = Vec::new();
        let mut same_asn_found = false;
        let mut none_as0_found = false;
        for roa in covering.iter().copied() {
            if roa.origin() == origin.origin {
                if roa.prefix.covers(origin.prefix)
                    && roa.effective_max_len() >= origin.prefix.addr_len()
                {
                    return Self {
                        route_origin: origin,
                        validity: RouteOriginValidity::Valid(roa.payload()),
                        disallowing: Vec::new(),
                    }
                }
                else {
                    same_asn_found = true;
                }
            }
            if roa.origin() != AsNumber::AS0 {
                none_as0_found = true;
            }
            invalidating.push(roa.payload());
        }

        Self {
            route_origin: origin,
            validity: if same_asn_found {
                RouteOriginValidity::InvalidLength
            }
            else if none_as0_found {
                RouteOriginValidity::InvalidAsn
            }
            else {
                RouteOriginValidity::Disallowed
            },
            disallowing: invalidating,
        }
    }

    /// Returns the announcement correlating with the route origin.
    ///
    /// “Announcement” is the term used in the API for a route origin.
    fn announcement(&self) -> Announcement {
        self.route_origin.into()
    }

    /// Converts the value into a BGP analysis entry.
    fn into_analysis_entry(self) -> BgpAnalysisEntry {
        match self.validity {
            RouteOriginValidity::Valid(roa) => {
                BgpAnalysisEntry::announcement_valid(
                    self.route_origin.into(), roa
                )
            }
            RouteOriginValidity::Disallowed => {
                BgpAnalysisEntry::announcement_disallowed(
                    self.route_origin.into(),
                    self.disallowing,
                )
            }
            RouteOriginValidity::InvalidLength => {
                BgpAnalysisEntry::announcement_invalid_length(
                    self.route_origin.into(),
                    self.disallowing,
                )
            }
            RouteOriginValidity::InvalidAsn => {
                BgpAnalysisEntry::announcement_invalid_asn(
                    self.route_origin.into(),
                    self.disallowing,
                )
            }
            RouteOriginValidity::NotFound => {
                BgpAnalysisEntry::announcement_not_found(
                    self.route_origin.into(),
                )
            }
        }
    }
}


//------------ RouteOriginValidity -------------------------------------------

/// The status of a route origin after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOriginValidity {
    /// The route origin is valid.
    ///
    /// The included ROA is the one that made the origin valid.
    Valid(RoaPayload),

    /// The route origin is invalid due to having an invalid prefix length.
    InvalidLength,

    /// The route origin is invalid due to having an invalid origin AS number.
    InvalidAsn,

    /// The route origin is invalid due to an AS0 ROA.
    Disallowed,

    /// No covering ROA exists and the route origin is “not found.”
    NotFound,
}


//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::str::FromStr;
    use crate::api::roa::RoaConfigurationUpdates;
    use crate::commons::test::{configured_roa};
    use super::super::riswhois::RouteOriginCollection;
    use super::*;

    fn ann(s: &str) -> Announcement {
        Announcement::from_str(s).unwrap()
    }

    fn test_analyser() -> BgpAnalyser {
        fn origin<P>(prefix: &str, origin: u32) -> RouteOrigin<P>
        where
            P: FromStr,
            <P as FromStr>::Err: fmt::Debug
        {
            RouteOrigin {
                prefix: P::from_str(prefix).unwrap(),
                origin: AsNumber::from_u32(origin)
            }
        }

        BgpAnalyser {
            loader: None,
            refresh_duration: Duration::seconds(12),
            last_checked: i64::MIN.into(),
            riswhois: ArcSwapOption::new(Some(Arc::new(RisWhois::new(
                RouteOriginCollection::new(
                    vec![
                        origin("10.0.0.0/22", 64496),
                        origin("10.0.2.0/23", 64496),
                        origin("10.0.0.0/24", 64496),
                        origin("10.0.0.0/22", 64497),
                        origin("10.0.0.0/21", 64497),
                        origin("192.168.0.0/24", 64497),
                        origin("192.168.0.0/24", 64496),
                        origin("192.168.1.0/24", 64497),
                    ]
                ).unwrap(),
                RouteOriginCollection::new(
                    vec![
                        origin("2001:DB8::/32", 64498),
                    ]
                ).unwrap(),
            ))))
        }
    }

    fn test_analyser_full() -> BgpAnalyser {
        let v4 = RisWhoisLoader::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv4"
        ).as_ref()).unwrap();
        let v6 = RisWhoisLoader::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv6"
        ).as_ref()).unwrap();
        let ris = RisWhois::new(v4, v6);

        BgpAnalyser {
            loader: None,
            refresh_duration: Duration::seconds(12),
            last_checked: i64::MIN.into(),
            riswhois: ArcSwapOption::new(Some(Arc::new(ris))),
        }
    }

    fn empty_analyser() -> BgpAnalyser {
        BgpAnalyser {
            loader: None,
            refresh_duration: Duration::seconds(12),
            last_checked: i64::MIN.into(),
            riswhois: ArcSwapOption::new(None),
        }
    }

    #[test]
    fn analyse_bgp() {
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

        let analyser = test_analyser();

        let report = analyser.analyse(
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
        );

        let expected: BgpAnalysisReport = serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_full_report.json"
        ))
        .unwrap();

        assert_eq!(report, expected);
    }

    #[test]
    fn analyse_bgp_disallowed_announcements() {
        let roa = configured_roa("10.0.0.0/22 => 0");

        let roas = &[roa];
        let analyser = test_analyser();

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let report = analyser.analyse(roas, &resources_held, None);

        assert!(!report.contains_invalids());

        let mut disallowed = report
            .matching_announcements(BgpAnalysisState::AnnouncementDisallowed);
        disallowed.sort();

        let disallowed_1 = ann("10.0.0.0/22 => 64496");
        let disallowed_2 = ann("10.0.0.0/22 => 64497");
        let disallowed_3 = ann("10.0.0.0/24 => 64496");
        let disallowed_4 = ann("10.0.2.0/23 => 64496");
        let mut expected =
            vec![disallowed_1, disallowed_2, disallowed_3, disallowed_4];
        expected.sort();

        assert_eq!(disallowed, expected);

        // The suggestion should not try to add the disallowed announcements
        // because they were disallowed by an AS0 roa.
        let suggestion = analyser.suggest(roas, &resources_held, None);
        let updates = RoaConfigurationUpdates::from(suggestion);

        let added = &updates.added;
        for announcement in disallowed {
            assert!(!added.iter().any(|added_roa| {
                let added_payload = added_roa.payload;
                let announcement_payload = RoaPayload::from(announcement);
                added_payload.includes(announcement_payload)
            }));
        }
    }

    #[test]
    fn analyse_bgp_no_announcements() {
        let roa1 = configured_roa("10.0.0.0/23-24 => 64496");
        let roa2 = configured_roa("10.0.3.0/24 => 64497");
        let roa3 = configured_roa("10.0.4.0/24 => 0");

        let roas = vec![roa1, roa2, roa3];

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = empty_analyser();
        let table = analyser.analyse(&roas, &resources_held, None);
        let table_entries = table.entries();
        assert_eq!(3, table_entries.len());

        let roas_no_info: Vec<ConfiguredRoa> = table_entries
            .iter()
            .filter(|e| e.state() == BgpAnalysisState::RoaNoAnnouncementInfo)
            .map(|e| e.configured_roa().clone())
            .collect();

        assert_eq!(roas_no_info, roas);
    }

    #[test]
    fn make_bgp_analysis_suggestion() {
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

        let analyser = test_analyser();

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let limit =
            Some(ResourceSet::from_strs("", "10.0.0.0/22", "").unwrap());
        let suggestion_resource_subset =
            analyser.suggest(roas, &resources_held, limit);

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_suggestion_some_roas.json"
        ))
            .unwrap();
        assert_eq!(suggestion_resource_subset, expected);

        let suggestion_all_roas_in_scope =
            analyser.suggest(roas, &resources_held, None);

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../../../test-resources/bgp/expected_suggestion_all_roas.json"
        ))
            .unwrap();

        assert_eq!(suggestion_all_roas_in_scope, expected);
    }

    #[test]
    fn analyse_nlnet_labs_snapshot() {
        let analyser = test_analyser_full();

        let asns = "AS204325, AS211321";
        let ipv4s = "185.49.140.0/22";
        let ipv6s = "2a04:b900::/29";
        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let roas = &[
            configured_roa("2a04:b906::/48-48 => 0"),
            configured_roa("2a04:b907::/48-48 => 0"),
            configured_roa("185.49.142.0/24-24 => 0"),
            configured_roa("2a04:b900::/30-32 => 8587"),
            configured_roa("185.49.140.0/23-23 => 8587"),
            configured_roa("2a04:b900::/30-30 => 8587"),
            configured_roa("2a04:b905::/48-48 => 16509"),
            configured_roa("2a04:b904::/48-48 => 211321"),
            configured_roa("2a04:b907::/47-47 => 211321"),
            configured_roa("185.49.142.0/23-23 => 211321"),
            configured_roa("2a04:b902::/48-48 => 211321"),
            configured_roa("185.49.143.0/24-24 => 211321"),
        ];

        let report = analyser.analyse(roas, &set, None);

        let entry_expect_roa = |x: &str, y| {
            let x = x.to_string();
            dbg!(&x, &y);
            assert!(report.entries().iter().any(|s| 
                s.state() == y &&
                s.configured_roa().to_string() == x 
            ));
        };

        let entry_expect_ann = |x: &str, y: u32, z: BgpAnalysisState| {
            let x = x.to_string();
            dbg!(&x, &y, &z);
            assert!(report.entries().iter().any(|s|
                s.state() == z &&
                s.announcement().asn == AsNumber::from_u32(y) &&
                s.announcement().prefix.to_string() == x
            ));
        };

        entry_expect_roa(
            "2a04:b906::/48-48 => 0", BgpAnalysisState::RoaAs0
        );
        entry_expect_roa(
            "2a04:b907::/48-48 => 0", BgpAnalysisState::RoaAs0Redundant
        );
        entry_expect_roa(
            "185.49.142.0/24-24 => 0", BgpAnalysisState::RoaAs0Redundant
        );
        entry_expect_roa(
            "2a04:b900::/30-32 => 8587", BgpAnalysisState::RoaSeen
        );
        entry_expect_roa(
            "185.49.140.0/23-23 => 8587", BgpAnalysisState::RoaSeen
        );
        entry_expect_roa(
            "2a04:b900::/30-30 => 8587", BgpAnalysisState::RoaRedundant
        );
        entry_expect_roa(
            "2a04:b905::/48-48 => 16509", BgpAnalysisState::RoaSeen
        );
        entry_expect_roa(
            "2a04:b904::/48-48 => 211321", BgpAnalysisState::RoaSeen
        );
        entry_expect_roa(
            "2a04:b907::/47-47 => 211321", BgpAnalysisState::RoaSeen
        );
        entry_expect_roa(
            "185.49.142.0/23-23 => 211321", BgpAnalysisState::RoaSeen
        );
        entry_expect_ann(
            "2a04:b907::/48", 211321,
            BgpAnalysisState::AnnouncementInvalidLength
        );
        entry_expect_ann(
            "185.49.142.0/24", 211321,
            BgpAnalysisState::AnnouncementInvalidLength
        );
        entry_expect_roa(
            "2a04:b902::/48-48 => 211321", BgpAnalysisState::RoaUnseen
        );
        entry_expect_roa(
            "185.49.143.0/24-24 => 211321", BgpAnalysisState::RoaUnseen
        );
    }
}

