use std::fmt;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::str::FromStr;

use log::debug;
use rpki::{
    repository::{
        resources::ResourceSet,
        roa::{Roa, RoaBuilder},
        sigobj::SignedObjectBuilder,
        x509::{Time, Validity},
    },
};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    commons::{
        crypto::KrillSigner,
        error::Error,
        KrillResult,
    },
    daemon::{
        config::{Config, IssuanceTimingConfig},
    },
};
use crate::commons::api::ca::ObjectName;
use crate::commons::api::roa::{
    AsNumber, RoaConfiguration, RoaInfo, RoaPayload, RoaPayloadJsonMapKey,
};
use super::keys::CertifiedKey;


//------------ Routes ------------------------------------------------------

/// The current authorizations and corresponding meta-information for a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Routes {
    map: HashMap<RoaPayloadJsonMapKey, RouteInfo>,
}

impl Routes {
    pub fn filter(&self, resources: &ResourceSet) -> Self {
        let filtered = self
            .map
            .iter()
            .flat_map(|(auth, info)| {
                if resources.contains_roa_address(
                    &auth.as_ref().as_roa_ip_address()
                ) {
                    Some((*auth, info.clone()))
                } else {
                    None
                }
            })
            .collect();
        Routes { map: filtered }
    }

    pub fn all(
        &self,
    ) -> impl Iterator<Item = (&RoaPayloadJsonMapKey, &RouteInfo)> {
        self.map.iter()
    }

    pub fn roa_configurations(&self) -> Vec<RoaConfiguration> {
        self.map
            .iter()
            .map(|(payload_key, route_info)| {
                RoaConfiguration {
                    payload: payload_key.clone().into(),
                    comment: route_info.comment().cloned(),
                }
            })
            .collect()
    }

    pub fn roa_payload_keys(
        &self,
    ) -> impl Iterator<Item = &RoaPayloadJsonMapKey> {
        self.map.keys()
    }

    pub fn into_roa_payload_keys(self) -> Vec<RoaPayloadJsonMapKey> {
        self.map.into_keys().collect()
    }

    pub fn as_aggregates(
        &self,
    ) -> HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> {
        let mut map: HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> =
            HashMap::new();

        for auth in self.map.keys() {
            let key = RoaAggregateKey::new(auth.as_ref().asn, None);
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

    pub fn info(&self, auth: &RoaPayloadJsonMapKey) -> Option<&RouteInfo> {
        self.map.get(auth)
    }

    pub fn has(&self, auth: &RoaPayloadJsonMapKey) -> bool {
        self.map.contains_key(auth)
    }

    /// Adds a new authorization
    pub fn add(&mut self, auth: RoaPayloadJsonMapKey) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Updates the comment for an authorization
    pub fn comment(
        &mut self,
        auth: &RoaPayloadJsonMapKey,
        comment: Option<String>,
    ) {
        if let Some(info) = self.map.get_mut(auth) {
            info.set_comment(comment)
        }
    }

    /// Removes an authorization
    pub fn remove(&mut self, auth: &RoaPayloadJsonMapKey) -> bool {
        self.map.remove(auth).is_some()
    }
}

//------------ RouteInfo ---------------------------------------------------

/// Meta-information about a configured RouteAuthorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteInfo {
    since: Time, // authorization first added by user

    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<u32>,
}

impl RouteInfo {
    pub fn since(&self) -> Time {
        self.since
    }

    pub fn comment(&self) -> Option<&String> {
        self.comment.as_ref()
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    /// The idea was to allow grouping of specific payloads.
    /// But perhaps we should deprecate this as it's not used.
    pub fn group(&self) -> Option<u32> {
        self.group
    }
}

impl Default for RouteInfo {
    fn default() -> Self {
        RouteInfo {
            since: Time::now(),
            comment: None,
            group: None,
        }
    }
}


//------------ RoaAggregateKey ---------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoaAggregateKey {
    asn: AsNumber,
    group: Option<u32>,
}

impl RoaAggregateKey {
    pub fn new(asn: AsNumber, group: Option<u32>) -> Self {
        RoaAggregateKey { asn, group }
    }

    pub fn asn(&self) -> AsNumber {
        self.asn
    }

    pub fn group(&self) -> Option<u32> {
        self.group
    }
}

impl fmt::Display for RoaAggregateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.group {
            None => write!(f, "AS{}", self.asn),
            Some(nr) => write!(f, "AS{}-{}", self.asn, nr),
        }
    }
}

impl From<&RoaAggregateKey> for ObjectName {
    fn from(roa_group: &RoaAggregateKey) -> Self {
        ObjectName::new(
            match roa_group.group() {
                None => format!("AS{}.roa", roa_group.asn()),
                Some(number) => {
                    format!("AS{}-{}.roa", roa_group.asn(), number)
                }
            }
        )
    }
}

impl FromStr for RoaAggregateKey {
    type Err = RoaAggregateKeyFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');

        let asn_part = parts
            .next()
            .ok_or_else(|| RoaAggregateKeyFmtError::string(s))?;

        if !asn_part.starts_with("AS") || asn_part.len() < 3 {
            return Err(RoaAggregateKeyFmtError::string(s));
        }

        let asn = AsNumber::from_str(&asn_part[2..])
            .map_err(|_| RoaAggregateKeyFmtError::string(s))?;

        let group = if let Some(group) = parts.next() {
            let group = u32::from_str(group)
                .map_err(|_| RoaAggregateKeyFmtError::string(s))?;
            Some(group)
        } else {
            None
        };

        if parts.next().is_some() {
            Err(RoaAggregateKeyFmtError::string(s))
        } else {
            Ok(RoaAggregateKey { asn, group })
        }
    }
}

/// We use RoaGroup as (json) map keys and therefore we need it
/// to be serializable to a single simple string.
impl Serialize for RoaAggregateKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

/// We use RoaGroup as (json) map keys and therefore we need it
/// to be deserializable from a single simple string.
impl<'de> Deserialize<'de> for RoaAggregateKey {
    fn deserialize<D>(d: D) -> Result<RoaAggregateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        RoaAggregateKey::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

/// Ordering is based on ASN first, and group second if there are
/// multiple keys for the same ASN. Note: we don't currently use
/// such groups. It's here in case we want to give users more
/// options in future.
impl Ord for RoaAggregateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.asn.cmp(&other.asn) {
            Ordering::Equal => self.group.cmp(&other.group),
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less,
        }
    }
}

impl PartialOrd for RoaAggregateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ RoaMode -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum RoaMode {
    Simple, // below aggregation threshold, and currently simple
    StopAggregating, /* below de-aggregation threshold, and currently
             * aggregating */
    StartAggregating, // above aggregation threshold, and currently simple
    Aggregate,        /* above de-aggregation threshold, and currently
                       * aggregating */
}

//------------ Roas --------------------------------------------------------

/// ROAs held by a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roas {
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    simple: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    aggregate: HashMap<RoaAggregateKey, RoaInfo>,
}

impl Roas {
    pub fn is_empty(&self) -> bool {
        self.simple.is_empty() && self.aggregate.is_empty()
    }

    pub fn updated(&mut self, updates: RoaUpdates) {
        let (updated, removed, aggregate_updated, aggregate_removed) =
            updates.unpack();

        for (auth, info) in updated.into_iter() {
            self.simple.insert(auth, info);
        }

        for auth in removed {
            self.simple.remove(&auth);
        }

        for (key, aggregate) in aggregate_updated.into_iter() {
            self.aggregate.insert(key, aggregate);
        }

        for key in aggregate_removed {
            self.aggregate.remove(&key);
        }
    }

    /// Returns all the current RoaInfos matching the given config
    pub fn matching_roa_infos(
        &self,
        config: &RoaConfiguration,
    ) -> Vec<RoaInfo> {
        let payload = RoaPayloadJsonMapKey::from(
            config.payload.into_explicit_max_length(),
        );
        let mut roa_infos: Vec<RoaInfo> = self
            .simple
            .values()
            .filter(|info| info.authorizations.contains(&payload))
            .cloned()
            .collect();

        roa_infos.append(
            &mut self
                .aggregate
                .values()
                .filter(|info| info.authorizations.contains(&payload))
                .cloned()
                .collect(),
        );

        roa_infos
    }

    /// Returns whether ROAs are currently being aggregated. I.e. whether
    /// there are any aggregated ROAs for which no explicit group number
    /// was set.
    fn is_currently_aggregating(&self) -> bool {
        self.aggregate.keys().any(|k| k.group().is_none())
    }

    /// Returns the desired RoaMode based on the current situation, and
    /// the intended changes.
    fn mode(
        &self,
        total: usize,
        de_aggregation_threshold: usize,
        aggregation_threshold: usize,
    ) -> RoaMode {
        let mode = {
            if total == 0 {
                // if everything will be removed, make sure no strategy change
                // is triggered
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
        for auth in relevant_routes.roa_payload_keys() {
            if !self.simple.contains_key(auth) {
                let name = ObjectName::from(*auth);
                let authorizations = vec![*auth];
                let roa = Self::make_roa(
                    &authorizations,
                    &name,
                    certified_key,
                    issuance_timing.new_roa_validity(),
                    signer,
                )?;
                let info = RoaInfo::new(authorizations, roa);
                roa_updates.update(*auth, info);
            }
        }

        // Remove surplus ROAs
        for auth in self.simple.keys() {
            if !relevant_routes.has(auth) {
                roa_updates.remove(*auth);
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
        // First trigger the simple update, this will make sure that all
        // current routes are added as simple (one prefix) ROAs
        let mut roa_updates = self.update_simple(
            relevant_routes,
            certified_key,
            issuance_timing,
            signer,
        )?;

        // Then remove all aggregate ROAs
        for roa_key in self.aggregate.keys() {
            roa_updates.remove_aggregate(*roa_key);
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
        // First trigger the aggregate update, this will make sure that all
        // current routes are added as aggregate ROAs
        let mut roa_updates = self.update_aggregate(
            relevant_routes,
            certified_key,
            issuance_timing,
            signer,
        )?;

        // Then remove all simple ROAs
        for roa_key in self.simple.keys() {
            debug!("Will remove simple authorization for: {}", roa_key);
            roa_updates.remove(*roa_key);
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
                let mut existing_authorizations =
                    existing.authorizations.clone();
                existing_authorizations.sort();

                if authorizations != &existing_authorizations {
                    // replace ROA
                    let aggregate = Self::make_aggregate_roa(
                        key,
                        authorizations.clone(),
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
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                roa_updates.update_aggregate(*key, aggregate);
            }
        }

        // Remove surplus ROAs
        for key in self.aggregate.keys() {
            if !desired_aggregates.contains_key(key) {
                roa_updates.remove_aggregate(*key);
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
        let relevant_routes =
            all_routes.filter(&certified_key.incoming_cert().resources);

        match self.mode(
            relevant_routes.len(),
            config.roa_deaggregate_threshold,
            config.roa_aggregate_threshold,
        ) {
            RoaMode::Simple => self.update_simple(
                &relevant_routes,
                certified_key,
                &config.issuance_timing,
                signer,
            ),
            RoaMode::StopAggregating => self.update_stop_aggregating(
                &relevant_routes,
                certified_key,
                &config.issuance_timing,
                signer,
            ),
            RoaMode::StartAggregating => self.update_start_aggregating(
                &relevant_routes,
                certified_key,
                &config.issuance_timing,
                signer,
            ),
            RoaMode::Aggregate => self.update_aggregate(
                &relevant_routes,
                certified_key,
                &config.issuance_timing,
                signer,
            ),
        }
    }

    /// Re-new ROAs before they would expire, or when forced e.g. in case
    /// ROAs need to be reissued because of a keyroll, or because of a change
    /// in encoding (like forcing shorter subject names, see issue #700)
    pub fn renew(
        &self,
        force: bool,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaUpdates> {
        let mut updates = RoaUpdates::default();

        let renew_threshold = issuance_timing.new_roa_issuance_threshold();

        for (auth, roa_info) in self.simple.iter() {
            let name = ObjectName::from(*auth);
            if force || roa_info.expires() < renew_threshold {
                let authorizations = vec![*auth];
                let roa = Self::make_roa(
                    &authorizations,
                    &name,
                    certified_key,
                    issuance_timing.new_roa_validity(),
                    signer,
                )?;
                let new_roa_info = RoaInfo::new(authorizations, roa);
                updates.update(*auth, new_roa_info);
            }
        }

        for (roa_key, roa_info) in self.aggregate.iter() {
            if force || roa_info.expires() < renew_threshold {
                let authorizations = roa_info.authorizations.clone();
                let name = ObjectName::from(roa_key);
                let new_roa = Self::make_roa(
                    authorizations.as_slice(),
                    &name,
                    certified_key,
                    issuance_timing.new_roa_validity(),
                    signer,
                )?;

                let new_roa_info = RoaInfo::new(authorizations, new_roa);
                updates.update_aggregate(*roa_key, new_roa_info);
            }
        }

        Ok(updates)
    }

    pub fn make_roa(
        authorizations: &[RoaPayloadJsonMapKey],
        name: &ObjectName,
        certified_key: &CertifiedKey,
        validity: Validity,
        signer: &KrillSigner,
    ) -> KrillResult<Roa> {
        let incoming_cert = certified_key.incoming_cert();
        let signing_key = certified_key.key_id();

        let crl_uri = incoming_cert.crl_uri();
        let roa_uri = incoming_cert.uri_for_name(name);
        let aia = &incoming_cert.uri;

        let asn = authorizations
            .first()
            .ok_or_else(|| {
                Error::custom("Attempt to create ROA without prefixes")
            })?
            .as_ref().asn;

        let mut roa_builder = RoaBuilder::new(asn.into());

        for auth in authorizations {
            let auth = RoaPayload::from(*auth);
            if auth.asn != asn {
                return Err(Error::custom(
                    "Attempt to create ROA for multiple ASNs",
                ));
            }
            let prefix = auth.prefix;
            if auth.effective_max_length() > prefix.prefix().addr_len() {
                roa_builder.push_addr(
                    prefix.ip_addr(),
                    prefix.addr_len(),
                    auth.max_length,
                );
            } else {
                roa_builder.push_addr(
                    prefix.ip_addr(),
                    prefix.addr_len(),
                    None,
                );
            }
        }

        let mut object_builder = SignedObjectBuilder::new(
            signer.random_serial()?,
            validity,
            crl_uri,
            aia.clone(),
            roa_uri,
        );
        object_builder.set_issuer(Some(incoming_cert.subject.clone()));
        object_builder.set_signing_time(Some(Time::now()));

        Ok(signer.sign_roa(roa_builder, object_builder, signing_key)?)
    }

    pub fn make_aggregate_roa(
        key: &RoaAggregateKey,
        authorizations: Vec<RoaPayloadJsonMapKey>,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaInfo> {
        let name = ObjectName::from(key);
        let roa = Self::make_roa(
            &authorizations,
            &name,
            certified_key,
            issuance_timing.new_roa_validity(),
            signer,
        )?;
        Ok(RoaInfo::new(authorizations, roa))
    }
}


//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaUpdates {
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    pub updated: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub removed: Vec<RoaPayloadJsonMapKey>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    pub aggregate_updated: HashMap<RoaAggregateKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub aggregate_removed: Vec<RoaAggregateKey>,
}

impl RoaUpdates {
    pub fn new(
        updated: HashMap<RoaPayloadJsonMapKey, RoaInfo>,
        removed: Vec<RoaPayloadJsonMapKey>,
        aggregate_updated: HashMap<RoaAggregateKey, RoaInfo>,
        aggregate_removed: Vec<RoaAggregateKey>,
    ) -> Self {
        RoaUpdates {
            updated,
            removed,
            aggregate_updated,
            aggregate_removed,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.updated.is_empty()
            && self.removed.is_empty()
            && self.aggregate_updated.is_empty()
            && self.aggregate_removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn update(&mut self, auth: RoaPayloadJsonMapKey, roa: RoaInfo) {
        self.updated.insert(auth, roa);
    }

    pub fn remove(&mut self, auth: RoaPayloadJsonMapKey) {
        self.removed.push(auth);
    }

    pub fn remove_aggregate(&mut self, key: RoaAggregateKey) {
        self.aggregate_removed.push(key);
    }

    pub fn update_aggregate(&mut self, key: RoaAggregateKey, info: RoaInfo) {
        self.aggregate_updated.insert(key, info);
    }

    pub fn added_roas(&self) -> HashMap<ObjectName, RoaInfo> {
        let mut res = HashMap::new();

        for (auth, info) in &self.updated {
            let name = ObjectName::from(*auth);
            res.insert(name, info.clone());
        }

        for (agg_key, info) in &self.aggregate_updated {
            let name = ObjectName::from(agg_key);
            res.insert(name, info.clone());
        }

        res
    }

    pub fn removed_roas(&self) -> Vec<ObjectName> {
        let mut res = vec![];

        for simple in &self.removed {
            res.push(ObjectName::from(*simple))
        }

        for agg in &self.aggregate_removed {
            res.push(ObjectName::from(agg))
        }

        res
    }

    #[allow(clippy::type_complexity)]
    pub fn unpack(
        self,
    ) -> (
        HashMap<RoaPayloadJsonMapKey, RoaInfo>,
        Vec<RoaPayloadJsonMapKey>,
        HashMap<RoaAggregateKey, RoaInfo>,
        Vec<RoaAggregateKey>,
    ) {
        (
            self.updated,
            self.removed,
            self.aggregate_updated,
            self.aggregate_removed,
        )
    }
}

impl fmt::Display for RoaUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.updated.is_empty() {
            write!(f, "Updated single VRP ROAs: ")?;
            for roa in self.updated.keys() {
                write!(f, "{} ", ObjectName::from(*roa))?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, "Removed single VRP ROAs: ")?;
            for roa in &self.removed {
                write!(f, "{} ", ObjectName::from(*roa))?;
            }
        }
        if !self.aggregate_updated.is_empty() {
            write!(f, "Updated ASN aggregated ROAs: ")?;
            for roa in self.aggregate_updated.keys() {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        if !self.aggregate_removed.is_empty() {
            write!(f, "Removed ASN aggregated ROAs: ")?;
            for roa in &self.aggregate_removed {
                write!(f, "{} ", ObjectName::from(roa))?;
            }
        }
        Ok(())
    }
}


//------------ AuthorizationFmtError -------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoaAggregateKeyFmtError(String);

impl fmt::Display for RoaAggregateKeyFmtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid ROA Group format ({})", self.0)
    }
}

impl RoaAggregateKeyFmtError {
    fn string(s: &str) -> Self {
        RoaAggregateKeyFmtError(s.to_string())
    }
}

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::commons::api::roa::{AsNumber, RoaPayload};
    use super::*;

    fn authorization(s: &str) -> RoaPayloadJsonMapKey {
        RoaPayload::from_str(s).unwrap().into()
    }

    #[test]
    fn serde_route_authorization() {
        fn parse_encode_authorization(s: &str) {
            let auth = authorization(s);
            let json = serde_json::to_string(&auth).unwrap();
            assert_eq!(format!("\"{}\"", s), json);

            let des: RoaPayloadJsonMapKey =
                serde_json::from_str(&json).unwrap();
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
            .get(&RoaAggregateKey::new(AsNumber::from_u32(64496), None))
            .unwrap();

        let mut agg_1_expected = vec![auth1_1, auth1_2, auth1_3];
        agg_1_expected.sort();

        assert_eq!(agg_1, &agg_1_expected);

        let agg_2 = aggregates
            .get(&RoaAggregateKey::new(AsNumber::from_u32(64497), None))
            .unwrap();

        assert_eq!(agg_2, &vec![auth2_1])
    }

    #[test]
    fn roa_group_string() {
        let roa_group_asn_only = RoaAggregateKey {
            asn: AsNumber::from_u32(0),
            group: None,
        };

        let roa_group_asn_only_expected_str = "AS0";
        assert_eq!(
            roa_group_asn_only.to_string().as_str(),
            roa_group_asn_only_expected_str
        );

        let roa_group_asn_only_expected =
            RoaAggregateKey::from_str(roa_group_asn_only_expected_str)
                .unwrap();
        assert_eq!(roa_group_asn_only, roa_group_asn_only_expected)
    }
}
