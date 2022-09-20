use std::{collections::HashMap, fmt, ops::Deref, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::{
    ca::publication::Base64,
    repository::{
        resources::ResourceSet,
        roa::{Roa, RoaBuilder},
        sigobj::SignedObjectBuilder,
        x509::{Serial, Time, Validity},
    },
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        api::{ObjectName, Revocation, RoaAggregateKey, RoaConfiguration, RoaPayload},
        crypto::KrillSigner,
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::events::RoaUpdates,
        ca::CertifiedKey,
        config::{Config, IssuanceTimingConfig},
    },
};

//------------ RoaPayloadKey -----------------------------------------------

/// This type wraps a [`RoaPayload`] but implements its own serialization
/// based on the string representation of the definition so that it can be
/// used as a single key in json map representations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct RoaPayloadJsonMapKey(RoaPayload);

// Display

impl fmt::Display for RoaPayloadJsonMapKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Conversions

impl AsRef<RoaPayload> for RoaPayloadJsonMapKey {
    fn as_ref(&self) -> &RoaPayload {
        &self.0
    }
}

impl Deref for RoaPayloadJsonMapKey {
    type Target = RoaPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<RoaPayload> for RoaPayloadJsonMapKey {
    fn from(def: RoaPayload) -> Self {
        RoaPayloadJsonMapKey(def)
    }
}

impl From<RoaPayloadJsonMapKey> for RoaPayload {
    fn from(auth: RoaPayloadJsonMapKey) -> Self {
        auth.0
    }
}

// Serde

impl Serialize for RoaPayloadJsonMapKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for RoaPayloadJsonMapKey {
    fn deserialize<D>(d: D) -> Result<RoaPayloadJsonMapKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        let def = RoaPayload::from_str(string.as_str()).map_err(de::Error::custom)?;
        Ok(RoaPayloadJsonMapKey(def))
    }
}

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
                if resources.contains_roa_address(&auth.as_roa_ip_address()) {
                    Some((*auth, info.clone()))
                } else {
                    None
                }
            })
            .collect();
        Routes { map: filtered }
    }

    pub fn all(&self) -> impl Iterator<Item = (&RoaPayloadJsonMapKey, &RouteInfo)> {
        self.map.iter()
    }

    pub fn roa_configurations(&self) -> Vec<RoaConfiguration> {
        self.map
            .iter()
            .map(|(payload_key, route_info)| RoaConfiguration::new(payload_key.0, route_info.comment().cloned()))
            .collect()
    }

    pub fn roa_payload_keys(&self) -> impl Iterator<Item = &RoaPayloadJsonMapKey> {
        self.map.keys()
    }

    pub fn into_roa_payload_keys(self) -> Vec<RoaPayloadJsonMapKey> {
        self.map.into_iter().map(|(auth, _)| auth).collect()
    }

    pub fn as_aggregates(&self) -> HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> {
        let mut map: HashMap<RoaAggregateKey, Vec<RoaPayloadJsonMapKey>> = HashMap::new();

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
    pub fn comment(&mut self, auth: &RoaPayloadJsonMapKey, comment: Option<String>) {
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

//------------ RoaInfo -----------------------------------------------------

/// This type defines information about a ROA *object*
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaInfo {
    // The route or routes authorized by this ROA
    authorizations: Vec<RoaPayloadJsonMapKey>,

    // The validity time for this ROA.
    validity: Validity,

    // The serial number (needed for revocation)
    serial: Serial,

    // The URI where this object is expected to be published
    uri: uri::Rsync,

    // The actual ROA in base64 format.
    base64: Base64,

    // The ROA's hash
    hash: Hash,
}

impl RoaInfo {
    pub fn new(authorizations: Vec<RoaPayloadJsonMapKey>, roa: Roa) -> Self {
        let validity = roa.cert().validity();
        let serial = roa.cert().serial_number();
        let uri = roa.cert().signed_object().unwrap().clone(); // safe for our own ROAs
        let base64 = Base64::from(&roa);
        let hash = base64.to_hash();

        RoaInfo {
            authorizations,
            validity,
            serial,
            uri,
            base64,
            hash,
        }
    }

    pub fn authorizations(&self) -> &Vec<RoaPayloadJsonMapKey> {
        &self.authorizations
    }

    pub fn serial(&self) -> Serial {
        self.serial
    }

    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    pub fn revoke(&self) -> Revocation {
        Revocation::new(self.serial, self.validity.not_after())
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }
}

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
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roas {
    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    simple: HashMap<RoaPayloadJsonMapKey, RoaInfo>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    aggregate: HashMap<RoaAggregateKey, RoaInfo>,
}

impl Roas {
    pub fn is_empty(&self) -> bool {
        self.simple.is_empty() && self.aggregate.is_empty()
    }

    pub fn get(&self, auth: &RoaPayloadJsonMapKey) -> Option<&RoaInfo> {
        self.simple.get(auth)
    }

    pub fn updated(&mut self, updates: RoaUpdates) {
        let (updated, removed, aggregate_updated, aggregate_removed) = updates.unpack();

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
    pub fn matching_roa_infos(&self, config: &RoaConfiguration) -> Vec<RoaInfo> {
        let payload = RoaPayloadJsonMapKey::from(config.payload().into_explicit_max_length());
        let mut roa_infos: Vec<RoaInfo> = self
            .simple
            .values()
            .filter(|info| info.authorizations().contains(&payload))
            .cloned()
            .collect();

        roa_infos.append(
            &mut self
                .aggregate
                .values()
                .filter(|info| info.authorizations().contains(&payload))
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
        for auth in relevant_routes.roa_payload_keys() {
            if !self.simple.contains_key(auth) {
                let name = ObjectName::from(auth);
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
        // First trigger the simple update, this will make sure that all current routes
        // are added as simple (one prefix) ROAs
        let mut roa_updates = self.update_simple(relevant_routes, certified_key, issuance_timing, signer)?;

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
        // First trigger the aggregate update, this will make sure that all current routes
        // are added as aggregate ROAs
        let mut roa_updates = self.update_aggregate(relevant_routes, certified_key, issuance_timing, signer)?;

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
                let mut existing_authorizations = existing.authorizations().clone();
                existing_authorizations.sort();

                if authorizations != &existing_authorizations {
                    // replace ROA
                    let aggregate =
                        Self::make_aggregate_roa(key, authorizations.clone(), certified_key, issuance_timing, signer)?;
                    roa_updates.update_aggregate(*key, aggregate);
                }
            } else {
                // new ROA
                let aggregate =
                    Self::make_aggregate_roa(key, authorizations.clone(), certified_key, issuance_timing, signer)?;
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
            let name = ObjectName::from(auth);
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
                let authorizations = roa_info.authorizations().clone();
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

        let mut object_builder =
            SignedObjectBuilder::new(signer.random_serial()?, validity, crl_uri, aia.clone(), roa_uri);
        object_builder.set_issuer(Some(incoming_cert.subject().clone()));
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

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::commons::api::AsNumber;

    fn authorization(s: &str) -> RoaPayloadJsonMapKey {
        let def = RoaPayload::from_str(s).unwrap();
        RoaPayloadJsonMapKey(def)
    }

    #[test]
    fn serde_route_authorization() {
        fn parse_encode_authorization(s: &str) {
            let auth = authorization(s);
            let json = serde_json::to_string(&auth).unwrap();
            assert_eq!(format!("\"{}\"", s), json);

            let des: RoaPayloadJsonMapKey = serde_json::from_str(&json).unwrap();
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
