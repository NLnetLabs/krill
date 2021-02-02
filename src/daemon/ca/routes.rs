use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use chrono::Duration;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::roa::{Roa, RoaBuilder};
use rpki::sigobj::SignedObjectBuilder;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::{
    CurrentObject, CurrentObjects, ObjectName, ReplacedObject, ResourceSet, RoaAggregateKey, RoaDefinition,
    RoaDefinitionUpdates,
};
use crate::commons::crypto::{KrillSigner, SignSupport};
use crate::commons::error::Error;
use crate::commons::KrillResult;
use crate::daemon::ca::events::RoaUpdates;
use crate::daemon::ca::CertifiedKey;
use crate::daemon::config::{Config, IssuanceTimingConfig};

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
    added: HashSet<RouteAuthorization>,
    removed: HashSet<RouteAuthorization>,
}

impl Default for RouteAuthorizationUpdates {
    fn default() -> Self {
        RouteAuthorizationUpdates {
            added: HashSet::new(),
            removed: HashSet::new(),
        }
    }
}

impl RouteAuthorizationUpdates {
    /// Use this when receiving updates through the API, until the v0.7 ROA clean up can be deprecated,
    /// which would imply that pre-0.7 versions can not longer be directly updated.
    pub fn into_explicit(self) -> Self {
        let mut added = HashSet::new();
        for add in self.added.into_iter() {
            added.insert(add.explicit_length());
        }

        let mut removed = HashSet::new();
        for rem in self.removed.into_iter() {
            removed.insert(rem.explicit_length());
        }

        RouteAuthorizationUpdates { added, removed }
    }

    pub fn new(added: HashSet<RouteAuthorization>, removed: HashSet<RouteAuthorization>) -> Self {
        RouteAuthorizationUpdates { added, removed }
    }

    pub fn added(&self) -> &HashSet<RouteAuthorization> {
        &self.added
    }

    pub fn removed(&self) -> &HashSet<RouteAuthorization> {
        &self.removed
    }

    pub fn unpack(self) -> (HashSet<RouteAuthorization>, HashSet<RouteAuthorization>) {
        (self.added, self.removed)
    }

    pub fn filter(&self, resources: &ResourceSet) -> Self {
        let mut added = HashSet::new();
        for auth in &self.added {
            if resources.contains_roa_address(&auth.as_roa_ip_address()) {
                added.insert(*auth);
            }
        }

        let mut removed = HashSet::new();
        for auth in &self.removed {
            if resources.contains_roa_address(&auth.as_roa_ip_address()) {
                removed.insert(*auth);
            }
        }

        RouteAuthorizationUpdates { added, removed }
    }

    pub fn affected_prefixes(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for roa in &self.added {
            resources = resources.union(&roa.prefix().clone().into());
        }
        for roa in &self.removed {
            resources = resources.union(&roa.prefix().clone().into());
        }
        resources
    }
}

impl From<RoaDefinitionUpdates> for RouteAuthorizationUpdates {
    fn from(definitions: RoaDefinitionUpdates) -> Self {
        let (added, removed) = definitions.unpack();
        let added = added.into_iter().map(RoaDefinition::into).collect();
        let removed = removed.into_iter().map(RoaDefinition::into).collect();
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
            if let Some(authzs) = map.get_mut(&key) {
                authzs.push(*auth);
                authzs.sort();
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

    pub fn roa(&self) -> &RoaInfo {
        &self.roa
    }
}

impl AsRef<RoaInfo> for AggregateRoaInfo {
    fn as_ref(&self) -> &RoaInfo {
        &self.roa
    }
}

//------------ RoaInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaInfo {
    object: CurrentObject,            // actual ROA
    name: ObjectName,                 // Name for object in repo
    since: Time,                      // first ROA in RC created
    replaces: Option<ReplacedObject>, // for revoking when re-newing
}

impl RoaInfo {
    pub fn new_roa(roa: &Roa, name: ObjectName) -> Self {
        let object = CurrentObject::from(roa);
        RoaInfo {
            object,
            name,
            since: Time::now(),
            replaces: None,
        }
    }

    pub fn updated_roa(old: &RoaInfo, roa: &Roa, name: ObjectName) -> Self {
        let object = CurrentObject::from(roa);
        let replaces = Some(ReplacedObject::from(old.object()));
        RoaInfo {
            object,
            name,
            since: old.since,
            replaces,
        }
    }

    pub fn object(&self) -> &CurrentObject {
        &self.object
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn since(&self) -> Time {
        self.since
    }

    pub fn replaces(&self) -> Option<&ReplacedObject> {
        self.replaces.as_ref()
    }
}

//------------ RoaMode -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum RoaMode {
    Simple,           // below agg threshold, and currently simple
    StopAggregating,  // below deagg threshold, and currently aggregating
    StartAggregating, // above agg threshold, and currently simple
    Aggregate,        // above deagg threshold, and currently aggregating
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
    fn mode(&self, total: usize, deagg_threshold: usize, agg_threshold: usize) -> RoaMode {
        let mode = {
            if total == 0 {
                // if everything will be removed, make sure no strategy change is triggered
                if self.is_currently_aggregating() {
                    RoaMode::Aggregate
                } else {
                    RoaMode::Simple
                }
            } else if self.is_currently_aggregating() {
                if total < deagg_threshold {
                    RoaMode::StopAggregating
                } else {
                    RoaMode::Aggregate
                }
            } else if total > agg_threshold {
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
        routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut roa_updates = RoaUpdates::default();

        // Add new ROAs
        for auth in routes.authorizations() {
            if !self.simple.contains_key(auth) {
                let name = ObjectName::from(auth);
                let roa = Self::make_roa(
                    &[*auth],
                    &name,
                    None,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let info = RoaInfo::new_roa(&roa, name);
                roa_updates.update(*auth, info);
            }
        }

        // Remove surplus ROAs
        for (auth, info) in self.simple.iter() {
            if !routes.has(auth) {
                roa_updates.remove(*auth, info.object().into());
            }
        }

        Ok(roa_updates)
    }

    /// Process authorization updates that triggered de-aggregating ROAs
    fn update_stop_aggregating(
        &self,
        routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        // First trigger the simple update, this will make sure that all current routes
        // are added as simple (one prefix) ROAs
        let mut roa_updates = self.update_simple(routes, certified_key, issuance_timing, signer)?;

        // Then remove all aggregate ROAs
        for (roa_key, aggregate) in self.aggregate.iter() {
            roa_updates.remove_aggregate(*roa_key, aggregate.roa().object().into());
        }

        Ok(roa_updates)
    }

    /// Process authorization updates that triggered aggregating ROAs
    fn update_start_aggregating(
        &self,
        routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        // First trigger the aggregate update, this will make sure that all current routes
        // are added as aggregate ROAs
        let mut roa_updates = self.update_aggregate(routes, certified_key, issuance_timing, signer)?;

        // Then remove all simple ROAs
        for (roa_key, roa) in self.simple.iter() {
            debug!("Will remove simple authorization for: {}", roa_key);
            roa_updates.remove(*roa_key, roa.object().into());
        }

        Ok(roa_updates)
    }

    /// Process authorization updates in aggregation mode
    fn update_aggregate(
        &self,
        routes: &Routes,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut roa_updates = RoaUpdates::default();

        let desired_aggregates = routes.as_aggregates();

        debug!("Will create '{}' aggregates", desired_aggregates.len());

        // Add new ROAs, and update ROAs with changed authzs
        for (key, authzs) in desired_aggregates.iter() {
            if let Some(existing) = self.aggregate.get(key) {
                // check if we need to update
                let mut existing_authzs = existing.authorizations().clone();
                existing_authzs.sort();

                if authzs != &existing_authzs {
                    // replace ROA
                    let aggregate = Self::make_aggregate_roa(
                        key,
                        authzs.clone(),
                        Some(existing.roa()),
                        certified_key,
                        issuance_timing,
                        signer,
                    )?;
                    roa_updates.update_aggregate(*key, aggregate);
                }
            } else {
                // new ROA
                let aggregate =
                    Self::make_aggregate_roa(key, authzs.clone(), None, certified_key, issuance_timing, signer)?;
                roa_updates.update_aggregate(*key, aggregate);
            }
        }

        // Remove surplus ROAs
        for (key, aggregate) in self.aggregate.iter() {
            if !desired_aggregates.contains_key(key) {
                roa_updates.remove_aggregate(*key, aggregate.roa().object().into());
            }
        }

        Ok(roa_updates)
    }

    /// Process updates, return [`RoaUpdates`] and create new ROA objects if
    /// authorizations change, or if ROAs are about to expire.
    pub fn update(
        &self,
        routes: &Routes,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        match self.mode(
            routes.len(),
            config.roa_deaggregate_threshold,
            config.roa_aggregate_threshold,
        ) {
            RoaMode::Simple => self.update_simple(routes, certified_key, &config.issuance_timing, signer),
            RoaMode::StopAggregating => {
                self.update_stop_aggregating(routes, certified_key, &config.issuance_timing, signer)
            }
            RoaMode::StartAggregating => {
                self.update_start_aggregating(routes, certified_key, &config.issuance_timing, signer)
            }
            RoaMode::Aggregate => self.update_aggregate(routes, certified_key, &config.issuance_timing, signer),
        }
    }

    /// Re-new ROAs before they would expire
    pub fn renew(
        &self,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        let renew_threshold = Time::now() + Duration::weeks(issuance_timing.timing_roa_reissue_weeks_before);

        for (auth, roa) in self.simple.iter() {
            if roa.object().expires() < renew_threshold {
                let name = roa.name();
                let new_roa = Self::make_roa(
                    &[*auth],
                    name,
                    None,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
                updates.update(*auth, new_roa);
            }
        }

        for (roa_key, aggregate) in self.aggregate.iter() {
            let roa = aggregate.roa();

            if roa.object().expires() < renew_threshold {
                let authzs = aggregate.authorizations().clone();
                let name = roa.name();
                let new_roa = Self::make_roa(
                    authzs.as_slice(),
                    name,
                    None,
                    certified_key,
                    issuance_timing.timing_roa_valid_weeks,
                    signer,
                )?;
                let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
                let aggregate = AggregateRoaInfo::new(authzs, new_roa);

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
            let name = roa.name();
            let new_roa = Self::make_roa(
                &[*auth],
                name,
                None,
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
            updates.update(*auth, new_roa);
        }

        for (roa_key, aggregate) in self.aggregate.iter() {
            let roa = aggregate.roa();

            let authzs = aggregate.authorizations().clone();
            let name = roa.name();
            let new_roa = Self::make_roa(
                authzs.as_slice(),
                name,
                None,
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
            let aggregate = AggregateRoaInfo::new(authzs, new_roa);

            updates.update_aggregate(*roa_key, aggregate);
        }

        Ok(updates)
    }

    /// Re-generate all ROAs to be published in a new repository
    pub fn migrate_repo(
        &self,
        new_repo: &uri::Rsync,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        for (auth, roa) in self.simple.iter() {
            let name = roa.name();
            let new_roa = Self::make_roa(
                &[*auth],
                name,
                Some(new_repo),
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
            updates.update(*auth, new_roa);
        }

        for (roa_key, aggregate) in self.aggregate.iter() {
            let roa = aggregate.roa();

            let authzs = aggregate.authorizations().clone();
            let name = roa.name();
            let new_roa = Self::make_roa(
                authzs.as_slice(),
                name,
                Some(new_repo),
                certified_key,
                issuance_timing.timing_roa_valid_weeks,
                signer,
            )?;
            let new_roa = RoaInfo::updated_roa(roa, &new_roa, name.clone());
            let aggregate = AggregateRoaInfo::new(authzs, new_roa);

            updates.update_aggregate(*roa_key, aggregate);
        }

        Ok(updates)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RouteAuthorization, &RoaInfo)> {
        self.simple.iter()
    }

    #[deprecated]
    pub fn current_objects(&self) -> CurrentObjects {
        let mut objects = CurrentObjects::default();
        for info in self.simple.values() {
            objects.insert(info.name().clone(), info.object().clone());
        }
        for agg in self.aggregate.values() {
            let roa = agg.roa();
            objects.insert(roa.name().clone(), roa.object().clone());
        }
        objects
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &RouteAuthorization> {
        self.simple.keys()
    }

    pub fn make_roa(
        authzs: &[RouteAuthorization],
        name: &ObjectName,
        new_repo: Option<&uri::Rsync>,
        certified_key: &CertifiedKey,
        weeks: i64,
        signer: &KrillSigner,
    ) -> KrillResult<Roa> {
        let incoming_cert = certified_key.incoming_cert();
        let crl_uri = match &new_repo {
            None => incoming_cert.crl_uri(),
            Some(base_uri) => base_uri.join(incoming_cert.crl_name().as_bytes()),
        };

        let roa_uri = match &new_repo {
            None => incoming_cert.uri_for_name(name),
            Some(base_uri) => base_uri.join(name.as_bytes()),
        };

        let aia = incoming_cert.uri();

        let signing_key = certified_key.key_id();

        let asn = authzs
            .first()
            .ok_or_else(|| Error::custom("Attempt to create ROA without prefixes"))?
            .asn();

        let mut roa_builder = RoaBuilder::new(asn.into());

        for auth in authzs {
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
        authzs: Vec<RouteAuthorization>,
        old_roa: Option<&RoaInfo>,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AggregateRoaInfo> {
        let name = ObjectName::from(key);
        let roa = Self::make_roa(
            authzs.as_slice(),
            &name,
            None,
            certified_key,
            issuance_timing.timing_roa_valid_weeks,
            signer,
        )?;
        let info = match old_roa {
            Some(old_roa) => RoaInfo::updated_roa(old_roa, &roa, name),
            None => RoaInfo::new_roa(&roa, name),
        };
        Ok(AggregateRoaInfo::new(authzs, info))
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
