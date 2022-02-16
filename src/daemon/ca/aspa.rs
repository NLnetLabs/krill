//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/
//!

use std::{collections::HashMap, fmt::Debug};

use rpki::repository::{
    aspa::{Aspa, AspaBuilder},
    sigobj::SignedObjectBuilder,
    x509::Time,
};

use crate::{
    commons::{
        api::{AspaCustomer, AspaDefinition, AspaProvidersUpdate, ObjectName},
        crypto::{KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::{AspaObjectsUpdates, CertifiedKey},
        config::{Config, IssuanceTimingConfig},
    },
};

pub fn make_aspa_object(
    aspa_def: AspaDefinition,
    certified_key: &CertifiedKey,
    weeks: i64,
    signer: &KrillSigner,
) -> KrillResult<Aspa> {
    let name = ObjectName::from(&aspa_def);

    let aspa_builder = {
        let (customer_as, providers) = aspa_def.unpack();
        AspaBuilder::new(customer_as, providers).map_err(|e| Error::Custom(format!("Cannot use aspa config: {}", e)))
    }?;

    let object_builder = {
        let incoming_cert = certified_key.incoming_cert();

        let crl_uri = incoming_cert.crl_uri();
        let aspa_uri = incoming_cert.uri_for_name(&name);
        let ca_issuer = incoming_cert.uri().clone();

        let mut object_builder = SignedObjectBuilder::new(
            signer.random_serial()?,
            SignSupport::sign_validity_weeks(weeks),
            crl_uri,
            ca_issuer,
            aspa_uri,
        );
        object_builder.set_issuer(Some(incoming_cert.cert().subject().clone()));
        object_builder.set_signing_time(Some(Time::now()));

        object_builder
    };

    Ok(signer.sign_aspa(aspa_builder, object_builder, certified_key.key_id())?)
}

//------------ AspaDefinitions ---------------------------------------------

/// This type contains the ASPA definitions for a CA. Generally speaking
/// the [`AspaCustomer`] ASN will be held in a single [`ResourceClass`] only,
/// but at least in theory the CA could issue ASPA objects in each RC that
/// holds the ASN.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitions {
    attestations: HashMap<AspaCustomer, AspaDefinition>,
}

impl AspaDefinitions {
    // Add or replace a new definition
    pub fn add_or_replace(&mut self, aspa_def: AspaDefinition) {
        let customer = aspa_def.customer();
        self.attestations.insert(customer, aspa_def);
    }

    // Remove an existing definition (if it is present)
    pub fn remove(&mut self, customer: AspaCustomer) {
        self.attestations.remove(&customer);
    }

    // Applies an update. This assumes that the update was verified beforehand.
    pub fn apply_update(&mut self, customer: AspaCustomer, update: &AspaProvidersUpdate) {
        let current = self.attestations.get_mut(&customer).unwrap();
        current.apply_update(update);
    }

    pub fn all(&self) -> impl Iterator<Item = &AspaDefinition> {
        self.attestations.values()
    }
}

/// # Set operations
///
impl AspaDefinitions {
    pub fn get(&self, customer: AspaCustomer) -> Option<&AspaDefinition> {
        self.attestations.get(&customer)
    }

    pub fn has(&self, customer: AspaCustomer) -> bool {
        self.attestations.contains_key(&customer)
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

//------------ AspaObjects -------------------------------------------------

/// ASPA objects held by a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjects(HashMap<AspaCustomer, AspaInfo>);

impl AspaObjects {
    pub fn make_aspa(
        &self,
        aspa_def: AspaDefinition,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AspaInfo> {
        let weeks = issuance_timing.timing_aspa_valid_weeks;
        let aspa = make_aspa_object(aspa_def.clone(), certified_key, weeks, signer)?;
        Ok(AspaInfo::new_aspa(aspa_def, aspa))
    }

    /// Issue new ASPA objects based on configuration, and remove
    /// object for which the customer AS is no longer held.
    ///
    /// Note: we pass in *all* AspaDefinitions for the CA, not all
    ///   definitions will be relevant for the RC (key) holding
    ///   this AspaObjects.
    pub fn update(
        &self,
        all_aspa_defs: &AspaDefinitions,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        let mut object_updates = AspaObjectsUpdates::default();
        let resources = certified_key.incoming_cert().resources();

        // Issue new and updated ASPAs for definitions relevant to the resources in scope
        for relevant_aspa in all_aspa_defs
            .all()
            .filter(|aspa| resources.contains_asn(aspa.customer()))
        {
            let need_to_issue = self
                .0
                .get(&relevant_aspa.customer())
                .map(|existing| existing.definition() != relevant_aspa)
                .unwrap_or(true);

            if need_to_issue {
                let aspa_info =
                    self.make_aspa(relevant_aspa.clone(), certified_key, &config.issuance_timing, signer)?;
                object_updates.add_updated(aspa_info);
            }
        }

        // Check if any currently held ASPA object needs to be removed
        for customer in self.0.keys() {
            if !all_aspa_defs.has(*customer) || !resources.contains_asn(*customer) {
                // definition was removed, or it's overclaiming
                object_updates.add_removed(*customer);
            }
        }

        Ok(object_updates)
    }

    // Re-new ASPAs, if the renew_threshold is specified, then
    // only objects which will expire before that time will be
    // renewed.
    pub fn renew(
        &self,
        certified_key: &CertifiedKey,
        renew_threshold: Option<Time>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        let mut updates = AspaObjectsUpdates::default();

        for aspa in self.0.values() {
            let renew = renew_threshold
                .map(|threshold| aspa.expires() < threshold)
                .unwrap_or(true); // always renew if no threshold is specified

            if renew {
                let aspa_definition = aspa.definition().clone();

                let new_aspa = self.make_aspa(aspa_definition, certified_key, issuance_timing, signer)?;
                updates.add_updated(new_aspa);
            }
        }

        Ok(updates)
    }

    pub fn updated(&mut self, updates: AspaObjectsUpdates) {
        let (updated, removed) = updates.unpack();
        for aspa_info in updated {
            let customer = aspa_info.customer();
            self.0.insert(customer, aspa_info);
        }
        for customer in removed {
            self.0.remove(&customer);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

//------------ AspaInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AspaInfo {
    definition: AspaDefinition,
    aspa: Aspa,
    since: Time, // Creation time
}

impl AspaInfo {
    pub fn new(definition: AspaDefinition, aspa: Aspa, since: Time) -> Self {
        AspaInfo {
            definition,
            aspa,
            since,
        }
    }

    pub fn new_aspa(definition: AspaDefinition, aspa: Aspa) -> Self {
        AspaInfo::new(definition, aspa, Time::now())
    }

    pub fn definition(&self) -> &AspaDefinition {
        &self.definition
    }

    pub fn customer(&self) -> AspaCustomer {
        self.definition.customer()
    }

    pub fn aspa(&self) -> &Aspa {
        &self.aspa
    }

    pub fn since(&self) -> Time {
        self.since
    }

    pub fn expires(&self) -> Time {
        self.aspa.cert().validity().not_after()
    }
}

impl PartialEq for AspaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.aspa.to_captured().as_slice() == other.aspa.to_captured().as_slice()
    }
}

impl Eq for AspaInfo {}
