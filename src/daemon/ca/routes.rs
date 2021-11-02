use std::{cmp::Ordering, collections::HashMap, fmt, ops::Deref, str::FromStr};

use chrono::Duration;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::repository::{
    roa::{Roa, RoaBuilder},
    sigobj::SignedObjectBuilder,
    x509::Time,
};

use crate::{
    commons::{
        api::{ObjectName, ResourceSet, RoaAggregateKey, RoaDefinition, RoaDefinitionUpdates},
        crypto::{KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::events::RoaUpdates,
        ca::CertifiedKey,
        config::{Config, IssuanceTimingConfig},
    },
};

//------------ RouteAuthorization ------------------------------------------

/// This type defines a prefix and optional maximum length (other than the
/// prefix length) which is to be authorized for the given origin ASN.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteAuthorization(RoaDefinition);

impl fmt::Display for RouteAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl RouteAuthorization {
    pub fn new(definition: RoaDefinition) -> Self {
        RouteAuthorization(definition)
    }

    pub fn explicit_length(self) -> Self {
        RouteAuthorization(self.0.explicit_max_length())
    }
}

impl AsRef<RoaDefinition> for RouteAuthorization {
    fn as_ref(&self) -> &RoaDefinition {
        &self.0
    }
}

impl Deref for RouteAuthorization {
    type Target = RoaDefinition;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Ordering is based on the ordering implemented by RoaDefinition
impl Ord for RouteAuthorization {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for RouteAuthorization {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// We use RouteAuthorization as (json) map keys and therefore we need it
/// to be serializable to a single simple string.
impl Serialize for RouteAuthorization {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

/// We use RouteAuthorization as (json) map keys and therefore we need it
/// to be deserializable from a single simple string.
impl<'de> Deserialize<'de> for RouteAuthorization {
    fn deserialize<D>(d: D) -> Result<RouteAuthorization, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        let def = RoaDefinition::from_str(string.as_str()).map_err(de::Error::custom)?;
        Ok(RouteAuthorization(def))
    }
}

impl From<RoaDefinition> for RouteAuthorization {
    fn from(def: RoaDefinition) -> Self {
        RouteAuthorization(def)
    }
}

impl From<RouteAuthorization> for RoaDefinition {
    fn from(auth: RouteAuthorization) -> Self {
        auth.0
    }
}

//------------ RouteAuthorizationUpdates -----------------------------------

///
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteAuthorizationUpdates {
    added: Vec<RouteAuthorization>,
    removed: Vec<RouteAuthorization>,
}

impl Default for RouteAuthorizationUpdates {
    fn default() -> Self {
        RouteAuthorizationUpdates {
            added: vec![],
            removed: vec![],
        }
    }
}

impl RouteAuthorizationUpdates {
    /// Use this when receiving updates through the API, until the v0.7 ROA clean up can be deprecated,
    /// which would imply that pre-0.7 versions can not longer be directly updated.
    pub fn into_explicit(self) -> Self {
        let added = self.added.into_iter().map(|a| a.explicit_length()).collect();
        let removed = self.removed.into_iter().map(|r| r.explicit_length()).collect();
        RouteAuthorizationUpdates { added, removed }
    }

    pub fn new(added: Vec<RouteAuthorization>, removed: Vec<RouteAuthorization>) -> Self {
        RouteAuthorizationUpdates { added, removed }
    }

    pub fn added(&self) -> &Vec<RouteAuthorization> {
        &self.added
    }

    pub fn removed(&self) -> &Vec<RouteAuthorization> {
        &self.removed
    }

    pub fn unpack(self) -> (Vec<RouteAuthorization>, Vec<RouteAuthorization>) {
        (self.added, self.removed)
    }

    pub fn filter(&self, resources: &ResourceSet) -> Self {
        let added = self
            .added()
            .iter()
            .filter(|auth| resources.contains_roa_address(&auth.as_roa_ip_address()))
            .cloned()
            .collect();

        let removed = self
            .removed()
            .iter()
            .filter(|auth| resources.contains_roa_address(&auth.as_roa_ip_address()))
            .cloned()
            .collect();

        RouteAuthorizationUpdates { added, removed }
    }

    pub fn affected_prefixes(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for roa in &self.added {
            resources = resources.union(&roa.prefix().into());
        }
        for roa in &self.removed {
            resources = resources.union(&roa.prefix().into());
        }
        resources
    }
}

impl From<RoaDefinitionUpdates> for RouteAuthorizationUpdates {
    fn from(definitions: RoaDefinitionUpdates) -> Self {
        let (added, removed) = definitions.unpack();
        let mut added: Vec<RouteAuthorization> = added.into_iter().map(RoaDefinition::into).collect();
        added.sort();
        added.dedup();

        let mut removed: Vec<RouteAuthorization> = removed.into_iter().map(RoaDefinition::into).collect();
        removed.sort();
        removed.dedup();

        RouteAuthorizationUpdates { added, removed }
    }
}

impl fmt::Display for RouteAuthorizationUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.added.is_empty() {
            write!(f, "added:")?;
            for a in &self.added {
                write!(f, " {}", a)?;
            }
            write!(f, " ")?;
        }
        if !self.removed.is_empty() {
            write!(f, "removed:")?;
            for r in &self.removed {
                write!(f, " {}", r)?;
            }
        }
        Ok(())
    }
}

//------------ Routes ------------------------------------------------------

/// The current authorizations and corresponding meta-information for a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Routes {
    map: HashMap<RouteAuthorization, RouteInfo>,
}

impl Default for Routes {
    fn default() -> Self {
        Routes { map: HashMap::new() }
    }
}

impl Routes {
    pub fn filter(&self, resources: &ResourceSet) -> Self {
        let filtered = self
            .map
            .iter()
            .flat_map(|(auth, info)| {
                if resources.contains_roa_address(&auth.as_roa_ip_address()) {
                    Some((*auth, info.clone()))
                } else {
                    None
                }
            })
            .collect();
        Routes { map: filtered }
    }

    pub fn all(&self) -> impl Iterator<Item = (&RouteAuthorization, &RouteInfo)> {
        self.map.iter()
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &RouteAuthorization> {
        self.map.keys()
    }

    pub fn into_authorizations(self) -> Vec<RouteAuthorization> {
        self.map.into_iter().map(|(auth, _)| auth).collect()
    }

    pub fn as_aggregates(&self) -> HashMap<RoaAggregateKey, Vec<RouteAuthorization>> {
        let mut map: HashMap<RoaAggregateKey, Vec<RouteAuthorization>> = HashMap::new();

        for auth in self.map.keys() {
            let key = RoaAggregateKey::new(auth.asn(), None);
            if let Some(authorizations) = map.get_mut(&key) {
                authorizations.push(*auth);
                authorizations.sort();
            } else {
                map.insert(key, vec![*auth]);
            }
        }
        map
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn info(&self, auth: &RouteAuthorization) -> Option<&RouteInfo> {
        self.map.get(auth)
    }

    pub fn has(&self, auth: &RouteAuthorization) -> bool {
        self.map.contains_key(auth)
    }

    /// Adds a new authorization, or updates an existing one.
    pub fn add(&mut self, auth: RouteAuthorization) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Removes an authorization
    pub fn remove(&mut self, auth: &RouteAuthorization) -> bool {
        self.map.remove(auth).is_some()
    }
}

//------------ RouteInfo ---------------------------------------------------

/// Meta-information about a configured RouteAuthorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteInfo {
    since: Time, // authorization first added by user

    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<u32>,
}

impl Default for RouteInfo {
    fn default() -> Self {
        RouteInfo {
            since: Time::now(),
            group: None,
        }
    }
}

//------------ AggregateRoaInfo --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateRoaInfo {
    authorizations: Vec<RouteAuthorization>,

    #[serde(flatten)]
    roa: RoaInfo,
}

impl AggregateRoaInfo {
    pub fn new(authorizations: Vec<RouteAuthorization>, roa: RoaInfo) -> Self {
        AggregateRoaInfo { authorizations, roa }
    }

    pub fn authorizations(&self) -> &Vec<RouteAuthorization> {
        &self.authorizations
    }

    pub fn roa_info(&self) -> &RoaInfo {
        &self.roa
    }
}

impl AsRef<RoaInfo> for AggregateRoaInfo {
    fn as_ref(&self) -> &RoaInfo {
        &self.roa
    }
}

//------------ RoaInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoaInfo {
    roa: Roa,
    since: Time, // first ROA in RC created
}

impl RoaInfo {
    pub fn new(roa: Roa, since: Time) -> Self {
        RoaInfo { roa, since }
    }

    pub fn new_roa(roa: Roa) -> Self {
        RoaInfo {
            roa,
            since: Time::now(),
        }
    }

    pub fn updated_roa(old: &RoaInfo, roa: Roa) -> Self {
        RoaInfo { roa, since: old.since }
    }

    pub fn roa(&self) -> &Roa {
        &self.roa
    }

    pub fn since(&self) -> Time {
        self.since
    }

    pub fn expires(&self) -> Time {
        self.roa.cert().validity().not_after()
    }
}

impl PartialEq for RoaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.roa.to_captured().as_slice() == other.roa.to_captured().as_slice()
    }
}

impl Eq for RoaInfo {}

//------------ RoaMode -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum RoaMode {
    Simple,           // below aggregation threshold, and currently simple
    StopAggregating,  // below de-aggregation threshold, and currently aggregating
    StartAggregating, // above aggregation threshold, and currently simple
    Aggregate,        // above de-aggregation threshold, and currently aggregating
}

//------------ Roas --------------------------------------------------------

/// ROAs held by a resource class in a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roas {
    #[serde(alias = "inner", skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    simple: HashMap<RouteAuthorization, RoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate: HashMap<RoaAggregateKey, AggregateRoaInfo>,
}

impl Default for Roas {
    fn default() -> Self {
        Roas {
            simple: HashMap::new(),
            aggregate: HashMap::new(),
        }
    }
}

impl Roas {
    pub fn get(&self, auth: &RouteAuthorization) -> Option<&RoaInfo> {
        self.simple.get(auth)
    }

    pub fn updated(&mut self, updates: RoaUpdates) {
        let (updated, removed, aggregate_updated, aggregate_removed) = updates.unpack();

        for (auth, info) in updated.into_iter() {
            self.simple.insert(auth, info);
        }

        for auth in removed.keys() {
            self.simple.remove(auth);
        }

        for (key, aggregate) in aggregate_updated.into_iter() {
            self.aggregate.insert(key, aggregate);
        }

        for key in aggregate_removed.keys() {
            self.aggregate.remove(key);
        }
    }

    /// Returns whether ROAs are currently being aggregated. I.e. whether
    /// there are any aggregated ROAs for which no explicit group number
    /// was set.
    fn is_currently_aggregating(&self) -> bool {
        self.aggregate.keys().any(|k| k.group().is_none())
    }

    /// Returns the desired RoaMode based on the current situation, and
    /// the intended changes.
    fn mode(&self, total: usize, de_aggregation_threshold: usize, aggregation_threshold: usize) -> RoaMode {
        let mode = {
            if total == 0 {
                // if everything will be removed, make sure no strategy change is triggered
                if self.is_currently_aggregating() {
                    RoaMode::Aggregate
                } else {
                    RoaMode::Simple
                }
            } else if self.is_currently_aggregating() {
                if total < de_aggregation_threshold {
                    RoaMode::StopAggregating
                } else {
                    RoaMode::Aggregate
                }
            } else if total > aggregation_threshold {
                RoaMode::StartAggregating
            } else {
                RoaMode::Simple
            }
        };

        debug!("Selecting ROA publication mode: {:?}", mode);

        mode
    }

    /// Process authorization updates below the aggregation threshold
    fn update_simple(
        &self,
        relevant_routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut roa_updates = RoaUpdates::default();

        // Add new ROAs
        for auth in relevant_routes.authorizations() {
            if !self.simple.contains_key(auth) {
                let name = ObjectName::from(auth);
                let roa = Self::make_roa(
                    &[*auth],
                    &name,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let info = RoaInfo::new_roa(roa);
                roa_updates.update(*auth, info);
            }
        }

        // Remove surplus ROAs
        for (auth, info) in self.simple.iter() {
            if !relevant_routes.has(auth) {
                roa_updates.remove(*auth, info.roa().into());
            }
        }

        Ok(roa_updates)
    }

    /// Process authorization updates that triggered de-aggregating ROAs
    fn update_stop_aggregating(
        &self,
        relevant_routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        // First trigger the simple update, this will make sure that all current routes
        // are added as simple (one prefix) ROAs
        let mut roa_updates = self.update_simple(relevant_routes, certified_key, issuance_timing, signer)?;

        // Then remove all aggregate ROAs
        for (roa_key, aggregate) in self.aggregate.iter() {
            roa_updates.remove_aggregate(*roa_key, aggregate.roa_info().roa().into());
        }

        Ok(roa_updates)
    }

    /// Process authorization updates that triggered aggregating ROAs
    fn update_start_aggregating(
        &self,
        relevant_routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        // First trigger the aggregate update, this will make sure that all current routes
        // are added as aggregate ROAs
        let mut roa_updates = self.update_aggregate(relevant_routes, certified_key, issuance_timing, signer)?;

        // Then remove all simple ROAs
        for (roa_key, roa_info) in self.simple.iter() {
            debug!("Will remove simple authorization for: {}", roa_key);
            roa_updates.remove(*roa_key, roa_info.roa().into());
        }

        Ok(roa_updates)
    }

    /// Process authorization updates in aggregation mode
    fn update_aggregate(
        &self,
        relevant_routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut roa_updates = RoaUpdates::default();

        let desired_aggregates = relevant_routes.as_aggregates();

        debug!("Will create '{}' aggregates", desired_aggregates.len());

        // Add new ROAs, and update ROAs with changed authorizations
        for (key, authorizations) in desired_aggregates.iter() {
            if let Some(existing) = self.aggregate.get(key) {
                // check if we need to update
                let mut existing_authorizations = existing.authorizations().clone();
                existing_authorizations.sort();

                if authorizations != &existing_authorizations {
                    // replace ROA
                    let aggregate = Self::make_aggregate_roa(
                        key,
                        authorizations.clone(),
                        Some(existing.roa_info()),
                        certified_key,
                        issuance_timing,
                        signer,
                    )?;
                    roa_updates.update_aggregate(*key, aggregate);
                }
            } else {
                // new ROA
                let aggregate = Self::make_aggregate_roa(
                    key,
                    authorizations.clone(),
                    None,
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                roa_updates.update_aggregate(*key, aggregate);
            }
        }

        // Remove surplus ROAs
        for (key, aggregate) in self.aggregate.iter() {
            if !desired_aggregates.contains_key(key) {
                roa_updates.remove_aggregate(*key, aggregate.roa_info().roa().into());
            }
        }

        Ok(roa_updates)
    }

    /// Process updates, return [`RoaUpdates`] and create new ROA objects if
    /// authorizations change, or if ROAs are about to expire.
    pub fn update(
        &self,
        all_routes: &Routes,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let relevant_routes = all_routes.filter(certified_key.incoming_cert().resources());

        match self.mode(
            relevant_routes.len(),
            config.roa_deaggregate_threshold,
            config.roa_aggregate_threshold,
        ) {
            RoaMode::Simple => self.update_simple(&relevant_routes, certified_key, &config.issuance_timing, signer),
            RoaMode::StopAggregating => {
                self.update_stop_aggregating(&relevant_routes, certified_key, &config.issuance_timing, signer)
            }
            RoaMode::StartAggregating => {
                self.update_start_aggregating(&relevant_routes, certified_key, &config.issuance_timing, signer)
            }
            RoaMode::Aggregate => {
                self.update_aggregate(&relevant_routes, certified_key, &config.issuance_timing, signer)
            }
        }
    }

    /// Re-new ROAs before they would expire
    pub fn renew(
        &self,
        force: bool,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        let renew_threshold = Time::now() + Duration::weeks(issuance_timing.timing_roa_reissue_weeks_before);

        for (auth, roa_info) in self.simple.iter() {
            let name = ObjectName::from(auth);
            if force || roa_info.expires() < renew_threshold {
                let roa = Self::make_roa(
                    &[*auth],
                    &name,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let roa_info = RoaInfo::updated_roa(roa_info, roa);
                updates.update(*auth, roa_info);
            }
        }

        for (roa_key, aggregate) in self.aggregate.iter() {
            let roa_info = aggregate.roa_info();

            if force || roa_info.expires() < renew_threshold {
                let authorizations = aggregate.authorizations().clone();
                let name = ObjectName::from(roa_key);
                let new_roa = Self::make_roa(
                    authorizations.as_slice(),
                    &name,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let new_roa_info = RoaInfo::updated_roa(roa_info, new_roa);
                let aggregate = AggregateRoaInfo::new(authorizations, new_roa_info);

                updates.update_aggregate(*roa_key, aggregate);
            }
        }

        Ok(updates)
    }

    /// Re-generate all ROAs when a new key is being activated
    pub fn activate_key(
        &self,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        for (auth, roa) in self.simple.iter() {
            let name = ObjectName::from(auth);
            let new_roa = Self::make_roa(
                &[*auth],
                &name,
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa_info = RoaInfo::updated_roa(roa, new_roa);
            updates.update(*auth, new_roa_info);
        }

        for (roa_key, aggregate) in self.aggregate.iter() {
            let roa = aggregate.roa_info();

            let authorizations = aggregate.authorizations().clone();
            let name = ObjectName::from(roa_key);
            let new_roa = Self::make_roa(
                authorizations.as_slice(),
                &name,
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa_info = RoaInfo::updated_roa(roa, new_roa);
            let aggregate = AggregateRoaInfo::new(authorizations, new_roa_info);

            updates.update_aggregate(*roa_key, aggregate);
        }

        Ok(updates)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RouteAuthorization, &RoaInfo)> {
        self.simple.iter()
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &RouteAuthorization> {
        self.simple.keys()
    }

    pub fn make_roa(
        authorizations: &[RouteAuthorization],
        name: &ObjectName,
        certified_key: &CertifiedKey,
        weeks: i64,
        signer: &KrillSigner,
    ) -> KrillResult<Roa> {
        let incoming_cert = certified_key.incoming_cert();
        let signing_key = certified_key.key_id();

        let crl_uri = incoming_cert.crl_uri();
        let roa_uri = incoming_cert.uri_for_name(name);
        let aia = incoming_cert.uri();

        let asn = authorizations
            .first()
            .ok_or_else(|| Error::custom("Attempt to create ROA without prefixes"))?
            .asn();

        let mut roa_builder = RoaBuilder::new(asn.into());

        for auth in authorizations {
            if auth.asn() != asn {
                return Err(Error::custom("Attempt to create ROA for multiple ASNs"));
            }
            let prefix = auth.prefix();
            if auth.effective_max_length() > prefix.prefix().addr_len() {
                roa_builder.push_addr(prefix.ip_addr(), prefix.addr_len(), auth.max_length());
            } else {
                roa_builder.push_addr(prefix.ip_addr(), prefix.addr_len(), None);
            }
        }

        let mut object_builder = SignedObjectBuilder::new(
            signer.random_serial()?,
            SignSupport::sign_validity_weeks(weeks),
            crl_uri,
            aia.clone(),
            roa_uri,
        );
        object_builder.set_issuer(Some(incoming_cert.cert().subject().clone()));
        object_builder.set_signing_time(Some(Time::now()));

        Ok(signer.sign_roa(roa_builder, object_builder, signing_key)?)
    }

    pub fn make_aggregate_roa(
        key: &RoaAggregateKey,
        authorizations: Vec<RouteAuthorization>,
        old_roa: Option<&RoaInfo>,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AggregateRoaInfo> {
        let name = ObjectName::from(key);
        let roa = Self::make_roa(
            authorizations.as_slice(),
            &name,
            certified_key,
            issuance_timing.timing_roa_valid_weeks,
            signer,
        )?;
        let info = match old_roa {
            Some(old_roa) => RoaInfo::updated_roa(old_roa, roa),
            None => RoaInfo::new_roa(roa),
        };
        Ok(AggregateRoaInfo::new(authorizations, info))
    }
}

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::commons::api::AsNumber;

    fn authorization(s: &str) -> RouteAuthorization {
        let def = RoaDefinition::from_str(s).unwrap();
        RouteAuthorization(def)
    }

    #[test]
    fn serde_route_authorization() {
        fn parse_encode_authorization(s: &str) {
            let auth = authorization(s);
            let json = serde_json::to_string(&auth).unwrap();
            assert_eq!(format!("\"{}\"", s), json);

            let des: RouteAuthorization = serde_json::from_str(&json).unwrap();
            assert_eq!(des, auth);
        }

        parse_encode_authorization("192.168.0.0/16 => 64496");
        parse_encode_authorization("192.168.0.0/16-24 => 64496");
        parse_encode_authorization("2001:db8::/32 => 64496");
        parse_encode_authorization("2001:db8::/32-48 => 64496");
    }

    #[test]
    fn routes_as_aggregates() {
        let mut routes = Routes::default();
        let auth1_1 = authorization("192.168.0.0/16 => 64496");
        let auth1_2 = authorization("192.168.0.0/16-24 => 64496");
        let auth1_3 = authorization("2001:db8::/32 => 64496");
        let auth2_1 = authorization("2001:db8::/32-48 => 64497");
        routes.add(auth1_1);
        routes.add(auth1_2);
        routes.add(auth1_3);
        routes.add(auth2_1);

        let aggregates = routes.as_aggregates();

        assert_eq!(2, aggregates.keys().len());

        let agg_1 = aggregates
            .get(&RoaAggregateKey::new(AsNumber::new(64496), None))
            .unwrap();

        let mut agg_1_expected = vec![auth1_1, auth1_2, auth1_3];
        agg_1_expected.sort();

        assert_eq!(agg_1, &agg_1_expected);

        let agg_2 = aggregates
            .get(&RoaAggregateKey::new(AsNumber::new(64497), None))
            .unwrap();

        assert_eq!(agg_2, &vec![auth2_1])
    }
}
