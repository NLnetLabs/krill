//! Route Origin Authorizations (ROAs).

use std::fmt;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::str::FromStr;
use log::debug;
use rpki::ca::idexchange::CaHandle;
use rpki::repository::resources::ResourceSet;
use rpki::repository::roa::{Roa, RoaBuilder};
use rpki::repository::sigobj::SignedObjectBuilder;
use rpki::repository::x509::{Time, Validity};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::api::ca::ObjectName;
use crate::api::roa::{
    AsNumber, RoaConfiguration, RoaConfigurationUpdates, RoaInfo, RoaPayload,
    RoaPayloadJsonMapKey,
};
use crate::commons::KrillResult;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::{Error, RoaDeltaError};
use crate::server::config::{Config, IssuanceTimingConfig};
use super::events::CertAuthEvent;
use super::keys::CertifiedKey;


//------------ Routes --------------------------------------------------------

/// The current configured route authorizations of a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Routes {
    /// The route authorization keyed by ROA payload.
    map: HashMap<RoaPayloadJsonMapKey, RouteInfo>,
}

impl Routes {
    /// Returns the subset of routes for the given resources.
    pub fn filter(&self, resources: &ResourceSet) -> Self {
        Self {
            map: self.map.iter().flat_map(|(auth, info)| {
                if resources.contains_roa_address(
                    &auth.as_ref().as_roa_ip_address()
                ) {
                    Some((*auth, info.clone()))
                } else {
                    None
                }
            }).collect()
        }
    }

    /// Returns the number of routes.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns whether the routes set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns whether there is a route authorization for the given key.
    pub fn has(&self, auth: &RoaPayloadJsonMapKey) -> bool {
        self.map.contains_key(auth)
    }

    /// Returns the route authorization intent for the given key.
    pub fn get(&self, auth: &RoaPayloadJsonMapKey) -> Option<&RouteInfo> {
        self.map.get(auth)
    }

    /// Returns the ROA configurations for the current content.
    pub fn roa_configurations(&self) -> Vec<RoaConfiguration> {
        self.map.iter().map(|(payload_key, route_info)| {
            RoaConfiguration {
                payload: (*payload_key).into(),
                comment: route_info.comment.clone(),
            }
        }).collect()
    }

    /// Returns an iterator over all the ROA payload keys.
    pub fn roa_payload_keys(
        &self,
    ) -> impl Iterator<Item = RoaPayloadJsonMapKey> + '_ {
        self.map.keys().copied()
    }

    /// Returns aggregated ROA payload.
    ///
    /// The method collects all the ROA payload for the same originating
    /// ASN into one vec and returns those vecs.
    fn to_aggregates(
        &self,
    ) -> HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> {
        let mut map: HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> =
            HashMap::new();

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

    /// Adds a new authorization with default route info.
    pub fn add(&mut self, auth: RoaPayloadJsonMapKey) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Updates the comment for an authorization.
    ///
    /// If the authorization isn’t present, does nothing.
    pub fn update_comment(
        &mut self, auth: &RoaPayloadJsonMapKey, comment: Option<String>
    ) {
        if let Some(info) = self.map.get_mut(auth) {
            info.comment = comment
        }
    }

    /// Removes an authorization.
    ///
    /// Returns whether the authorization was present and thus was removed.
    pub fn remove(&mut self, auth: &RoaPayloadJsonMapKey) -> bool {
        self.map.remove(auth).is_some()
    }

    /// Processes configuration updates.
    ///
    /// Verifies that the updates are correct, i.e.:
    /// * additions are for prefixes that are part of `all_resources`,
    /// * removals are for known authorizations
    /// * additions are
    ///   - no duplicates, or
    ///   - not covered by remaining after the removals.
    ///
    /// Returns the resulting desired configurations and the events for
    /// persisting the changes, or an error in case of issues.
    pub fn process_updates(
        &self,
        handle: &CaHandle,
        all_resources: &ResourceSet,
        updates: &RoaConfigurationUpdates,
    ) -> KrillResult<(Self, Vec<CertAuthEvent>)> {
        let mut delta_errors = RoaDeltaError::default();
        let mut res = vec![];

        // Keep track of routes as they will be after applying the updates
        let mut desired_routes = self.clone();

        // make sure that all removals are held
        for roa_payload in &updates.removed {
            let auth = RoaPayloadJsonMapKey::from(*roa_payload);
            if desired_routes.remove(&auth) {
                res.push(CertAuthEvent::RouteAuthorizationRemoved { auth });
            }
            else {
                delta_errors.add_unknown(*roa_payload)
            }
        }

        // make sure that all new additions are allowed
        for roa_configuration in &updates.added {
            let roa_payload = roa_configuration.payload;
            let comment = roa_configuration.comment.as_ref();

            let auth = RoaPayloadJsonMapKey::from(roa_payload);

            if !roa_payload.max_length_valid() {
                // The (max) length is invalid for this prefix
                delta_errors.add_invalid_length(roa_configuration.clone());
            }
            else if !all_resources.contains_roa_address(
                &roa_payload.as_roa_ip_address()
            ) {
                // We do not hold the prefix
                delta_errors.add_notheld(roa_configuration.clone());
            }
            else if let Some(info) = desired_routes.get(&auth) {
                // We have an existing info for this payload, this may be an
                // attempt to update the comment.
                if info.comment.as_ref() != comment {
                    // Update comment
                    res.push(CertAuthEvent::RouteAuthorizationComment {
                        auth,
                        comment: comment.cloned(),
                    });
                }
                else {
                    // Duplicate entry. We could be idempotent, but perhaps
                    // it's best to return an error
                    // instead because it seems that the user is out of sync
                    // with the current state.
                    delta_errors.add_duplicate(roa_configuration.clone());
                }
            }
            else {
                // Ok, this seems okay now
                res.push(CertAuthEvent::RouteAuthorizationAdded { auth });

                // Track to check if update has duplicates
                desired_routes.add(auth);

                if comment.is_some() {
                    // Track to check if update has duplicates
                    desired_routes.update_comment(
                        &auth, comment.cloned()
                    );
                    res.push(CertAuthEvent::RouteAuthorizationComment {
                        auth,
                        comment: comment.cloned(),
                    });
                }
            }
        }

        if !delta_errors.is_empty() {
            Err(Error::RoaDeltaError(handle.clone(), delta_errors))
        }
        else {
            Ok((desired_routes, res))
        }
    }
}


//------------ RouteInfo -----------------------------------------------------

/// Meta-information about a configured route authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteInfo {
    /// The time the authorization was first added by the user.
    pub since: Time,

    /// An optional comment for the authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// An optional group for the authorization.
    ///
    /// The original idea was to allow grouping of specific payloads instead
    /// of aggregating all of them into one ROA if they have the same ASN.
    /// However, this is currently not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<u32>,
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

/// The key for an aggregated ROA.
///
/// An aggregated ROA collects all the ROA payload for a single origin ASN.
/// In addition, these payloads can be grouped into separate aggregated ROAs
/// using a group.
///
/// We currently don’t use grouping. It is here in case we want to give
/// users more options in the future.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoaAggregateKey {
    /// The origin ASN.
    asn: AsNumber,

    /// The optional group.
    group: Option<u32>,
}

impl RoaAggregateKey {
    /// Creates a new aggregate ROA key from an ASN and an optional group.
    pub fn new(asn: AsNumber, group: Option<u32>) -> Self {
        RoaAggregateKey { asn, group }
    }

    /// Returns the origin ASN portion of the key.
    pub fn asn(&self) -> AsNumber {
        self.asn
    }

    /// Returns the group portion of the key.
    pub fn group(&self) -> Option<u32> {
        self.group
    }

    /// Returns the object name for the aggregate key.
    pub fn object_name(&self) -> ObjectName {
        ObjectName::new(
            match self.group {
                None => format!("AS{}.roa", self.asn),
                Some(number) => {
                    format!("AS{}-{}.roa", self.asn, number)
                }
            }
        )
    }
}


//--- FromStr

impl FromStr for RoaAggregateKey {
    type Err = RoaAggregateKeyFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');

        let asn_part = parts.next().ok_or_else(|| {
            RoaAggregateKeyFmtError(s.into())
        })?;

        if !asn_part.starts_with("AS") || asn_part.len() < 3 {
            return Err(RoaAggregateKeyFmtError(s.into()));
        }

        let asn = AsNumber::from_str(&asn_part[2..])
            .map_err(|_| RoaAggregateKeyFmtError(s.into()))?;

        let group = if let Some(group) = parts.next() {
            let group = u32::from_str(group).map_err(|_| {
                RoaAggregateKeyFmtError(s.into())
            })?;
            Some(group)
        }
        else {
            None
        };

        if parts.next().is_some() {
            return Err(RoaAggregateKeyFmtError(s.into()))
        }

        Ok(Self { asn, group })
    }
}


//--- PartialOrd and Ord

/// Partial order of two aggregate keys.
///
/// Ordering is based on ASN first, and group second if there are
/// multiple keys for the same ASN.
impl PartialOrd for RoaAggregateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Total order of two aggregate keys.
///
/// Ordering is based on ASN first, and group second if there are
/// multiple keys for the same ASN.
impl Ord for RoaAggregateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.asn.cmp(&other.asn) {
            Ordering::Equal => self.group.cmp(&other.group),
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less,
        }
    }
}


//--- Display

impl fmt::Display for RoaAggregateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.group {
            None => write!(f, "AS{}", self.asn),
            Some(nr) => write!(f, "AS{}-{}", self.asn, nr),
        }
    }
}


//--- Deserialize and Serialize 

/// Deserializing of a ROA aggregate key.
///
/// We use the value as JSON object keys and therefore need it to be
/// deserializable from a single simple string.
impl<'de> Deserialize<'de> for RoaAggregateKey {
    fn deserialize<D: Deserializer<'de>>(
        d: D
    ) -> Result<RoaAggregateKey, D::Error> {
        RoaAggregateKey::from_str(
            String::deserialize(d)?.as_str()
        ).map_err(de::Error::custom)
    }
}

/// Serializing of a ROA aggregate key.
///
/// We use values as JSON object keys and therefore need it to be
/// serialized into a single simple string.
impl Serialize for RoaAggregateKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(s)
    }
}


//------------ Roas --------------------------------------------------------

/// ROA configurations held by a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roas {
    /// The simple ROAs held by the resource class.
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    simple: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    /// The aggregated ROAs held by the resource class.
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    aggregate: HashMap<RoaAggregateKey, RoaInfo>,
}

impl Roas {
    /// Returns whether the resource class doesn’t hold any ROAs.
    pub fn is_empty(&self) -> bool {
        self.simple.is_empty() && self.aggregate.is_empty()
    }

    /// Applies the updates.
    pub fn apply_updates(&mut self, updates: RoaUpdates) {
        for (auth, info) in updates.updated.into_iter() {
            self.simple.insert(auth, info);
        }

        for auth in updates.removed {
            self.simple.remove(&auth);
        }

        for (key, aggregate) in updates.aggregate_updated.into_iter() {
            self.aggregate.insert(key, aggregate);
        }

        for key in updates.aggregate_removed {
            self.aggregate.remove(&key);
        }
    }

    /// Returns all the ROA infos matching the given ROA configuration.
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

    /// Returns the necessary updates to the ROAs of the resource class.
    ///
    /// All intended ROA configurtions 
    pub fn create_updates(
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
            RoaMode::Simple => {
                self.update_simple(
                    &relevant_routes,
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )
            }
            RoaMode::StopAggregating => {
                self.update_stop_aggregating(
                    &relevant_routes,
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )
            }
            RoaMode::StartAggregating => {
                self.update_start_aggregating(
                    &relevant_routes,
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )
            }
            RoaMode::Aggregate => {
                self.update_aggregate(
                    &relevant_routes,
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )
            }
        }
    }

    /// Returns whether ROAs are currently being aggregated.
    ///
    /// I.e. whether there are any aggregated ROAs for which no explicit
    /// group number was set.
    fn is_currently_aggregating(&self) -> bool {
        self.aggregate.keys().any(|k| k.group().is_none())
    }

    /// Returns the ROA mode for the current situation and intended changes.
    ///
    /// The overall number of ROA configuratons in the CA (i.e., for all
    /// resource classes) is given by `total`. Based on this number,
    /// `de_aggregation_threshold` provides the number below which
    /// aggregation should be stopped and `aggregation_threshold` the number
    /// above which aggregation should be started.
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
                }
                else {
                    RoaMode::Simple
                }
            }
            else if self.is_currently_aggregating() {
                if total < de_aggregation_threshold {
                    RoaMode::StopAggregating
                }
                else {
                    RoaMode::Aggregate
                }
            }
            else if total > aggregation_threshold {
                RoaMode::StartAggregating
            }
            else {
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
            if !self.simple.contains_key(&auth) {
                let name = ObjectName::from(auth);
                let authorizations = vec![auth];
                let roa = Self::make_roa(
                    &authorizations,
                    &name,
                    certified_key,
                    issuance_timing.new_roa_validity(),
                    signer,
                )?;
                let info = RoaInfo::new(authorizations, roa);
                roa_updates.updated.insert(auth, info);
            }
        }

        // Remove surplus ROAs
        for auth in self.simple.keys() {
            if !relevant_routes.has(auth) {
                roa_updates.removed.push(*auth);
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
            roa_updates.aggregate_removed.push(*roa_key);
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
            roa_updates.removed.push(*roa_key);
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

        let desired_aggregates = relevant_routes.to_aggregates();

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
                    roa_updates.aggregate_updated.insert(*key, aggregate);
                }
            }
            else {
                // new ROA
                let aggregate = Self::make_aggregate_roa(
                    key,
                    authorizations.clone(),
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                roa_updates.aggregate_updated.insert(*key, aggregate);
            }
        }

        // Remove surplus ROAs
        for key in self.aggregate.keys() {
            if !desired_aggregates.contains_key(key) {
                roa_updates.aggregate_removed.push(*key);
            }
        }

        Ok(roa_updates)
    }

    /// Create an update with renewed ROAs.
    ///
    /// If `force` is `true`, all ROAs will be renewed. Otherwise only those
    /// that are about to expire will be.
    pub fn create_renewal(
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
                updates.updated.insert(*auth, new_roa_info);
            }
        }

        for (roa_key, roa_info) in self.aggregate.iter() {
            if force || roa_info.expires() < renew_threshold {
                let authorizations = roa_info.authorizations.clone();
                let name = roa_key.object_name();
                let new_roa = Self::make_roa(
                    authorizations.as_slice(),
                    &name,
                    certified_key,
                    issuance_timing.new_roa_validity(),
                    signer,
                )?;

                let new_roa_info = RoaInfo::new(authorizations, new_roa);
                updates.aggregate_updated.insert(*roa_key, new_roa_info);
            }
        }

        Ok(updates)
    }

    /// Creates an aggregate ROA.
    fn make_aggregate_roa(
        key: &RoaAggregateKey,
        authorizations: Vec<RoaPayloadJsonMapKey>,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<RoaInfo> {
        let name = key.object_name();
        let roa = Self::make_roa(
            &authorizations,
            &name,
            certified_key,
            issuance_timing.new_roa_validity(),
            signer,
        )?;
        Ok(RoaInfo::new(authorizations, roa))
    }

    /// Creates a new ROA.
    fn make_roa(
        authorizations: &[RoaPayloadJsonMapKey],
        name: &ObjectName,
        certified_key: &CertifiedKey,
        validity: Validity,
        signer: &KrillSigner,
    ) -> KrillResult<Roa> {
        let crl_uri = certified_key.incoming_cert().crl_uri();
        let roa_uri = certified_key.incoming_cert().uri_for_name(name);
        let aia = &certified_key.incoming_cert().uri;

        let asn = authorizations.first().ok_or_else(|| {
            Error::custom("Attempt to create ROA without prefixes")
        })?.as_ref().asn;

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
        object_builder.set_issuer(
            Some(certified_key.incoming_cert().subject.clone())
        );
        object_builder.set_signing_time(Some(Time::now()));

        Ok(signer.sign_roa(
            roa_builder, object_builder, &certified_key.key_id()
        )?)
    }
}


//------------ RoaMode -----------------------------------------------------

/// The aggregation mode of a ROA.
#[derive(Clone, Debug, Eq, PartialEq)]
enum RoaMode {
    /// The ROA is below aggregation threshold, and currently simple.
    Simple,

    /// The ROA is below de-aggregation threshold, and currently aggregating.
    StopAggregating,

    /// The ROA is above aggregation threshold, and currently simple.
    StartAggregating,

    /// The ROA is above de-aggregation threshold, and currently aggregating.
    Aggregate,
}


//------------ RoaUpdates --------------------------------------------------

/// Describes an update to the set of ROAs under a ResourceClass.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaUpdates {
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    updated: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    removed: Vec<RoaPayloadJsonMapKey>,

    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    aggregate_updated: HashMap<RoaAggregateKey, RoaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    aggregate_removed: Vec<RoaAggregateKey>,
}

impl RoaUpdates {
    /// Creates new updates from the components.
    ///
    /// This is only used in upgrades.
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

    /// Returns whether there are no updates.
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty()
            && self.removed.is_empty()
            && self.aggregate_updated.is_empty()
            && self.aggregate_removed.is_empty()
    }

    /// Returns information about the ROAs to be added by this update.
    pub fn added_roas(
        &self
    ) -> impl Iterator<Item = (ObjectName, &RoaInfo)> + '_ {
        self.updated.iter().map(|(auth, info)| {
            (ObjectName::from(*auth), info)
        }).chain(
            self.aggregate_updated.iter().map(|(agg_key, info)| {
                (agg_key.object_name(), info)
            })
        )
    }

    /// Returns the names of the ROAs to be removed by this update.
    pub fn removed_roas(&self) -> impl Iterator<Item = ObjectName> + '_ {
        self.removed.iter().map(|simple| ObjectName::from(*simple)).chain(
            self.aggregate_removed.iter().map(|agg| agg.object_name())
        )
    }

    /// Formats the updates as part of an event.
    pub fn fmt_event(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.updated.is_empty()
            || !self.aggregate_updated.is_empty()
        {
            write!(f, " added: ")?;
            for auth in self.updated.keys() {
                write!(f, "{} ", ObjectName::from(*auth))?;
            }
            for agg_key in self.aggregate_updated.keys() {
                write!(f, "{} ", agg_key.object_name())?;
            }
        }
        if !self.removed.is_empty()
            || !self.aggregate_removed.is_empty()
        {
            write!(f, " removed: ")?;
            for auth in &self.removed {
                write!(f, "{} ", ObjectName::from(*auth))?;
            }
            for agg_key in &self.aggregate_removed {
                write!(f, "{} ", agg_key.object_name())?;
            }
        }
        Ok(())
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
                write!(f, "{} ", roa.object_name())?;
            }
        }
        if !self.aggregate_removed.is_empty() {
            write!(f, "Removed ASN aggregated ROAs: ")?;
            for roa in &self.aggregate_removed {
                write!(f, "{} ", roa.object_name())?;
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
        write!(f, "Invalid ROA Group format '{}'", self.0)
    }
}


//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::api::roa::{AsNumber, RoaPayload};
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

        let aggregates = routes.to_aggregates();

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

