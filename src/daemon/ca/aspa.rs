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
        api::{AspaConfigurationUpdate, AspaCustomer, AspaDefinition, ObjectName},
        crypto::{KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::{
        ca::{AspaObjectsUpdates, CertifiedKey},
        config::Config,
    },
};

pub fn make_aspa_object(
    aspa_config: AspaDefinition,
    certified_key: &CertifiedKey,
    weeks: i64,
    signer: &KrillSigner,
) -> KrillResult<Aspa> {
    let name = ObjectName::from(&aspa_config);

    let aspa_builder = {
        let (customer_as, providers) = aspa_config.unpack();
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitions {
    attestations: HashMap<AspaCustomer, AspaDefinition>,
}

impl AspaDefinitions {
    pub fn add(&mut self, aspa: AspaDefinition) {
        let customer = aspa.customer();
        self.attestations.insert(customer, aspa);
    }

    // Applies an update. This assumes that the update was
    // verified beforehand.
    pub fn apply_update(&mut self, customer: AspaCustomer, update: &AspaConfigurationUpdate) {
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

impl Default for AspaDefinitions {
    fn default() -> AspaDefinitions {
        AspaDefinitions {
            attestations: HashMap::new(),
        }
    }
}

//------------ AspaObjects -------------------------------------------------

/// ASPA objects held by a resource class in a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjects(HashMap<AspaCustomer, AspaInfo>);

impl AspaObjects {
    pub fn make_aspa(
        &self,
        aspa_config: AspaDefinition,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<AspaInfo> {
        let weeks = config.issuance_timing.timing_aspa_valid_weeks;
        let aspa = make_aspa_object(aspa_config.clone(), certified_key, weeks, signer)?;
        Ok(AspaInfo::new_aspa(aspa_config, aspa))
    }

    /// Issue new ASPA objects based on configuration, and remove
    /// object for which the customer AS is no longer held.
    ///
    /// Note: we pass in *all* AspaDefinitions for the CA, not all
    ///   definitions will be relevant for the RC (key) holding
    ///   this AspaObjects.
    pub fn update(
        &self,
        all_aspas: &AspaDefinitions,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<AspaObjectsUpdates> {
        let mut object_updates = AspaObjectsUpdates::default();
        let resources = certified_key.incoming_cert().resources();

        // Issue new and updated ASPAs for definitions relevant to the resources in scope
        for relevant_aspa in all_aspas.all().filter(|aspa| resources.contains_asn(aspa.customer())) {
            let need_to_issue = self
                .0
                .get(&relevant_aspa.customer())
                .map(|existing| existing.definition() != relevant_aspa)
                .unwrap_or(true);

            if need_to_issue {
                let aspa_info = self.make_aspa(relevant_aspa.clone(), certified_key, config, signer)?;
                object_updates.add_updated(aspa_info);
            }
        }

        // Remove overclaiming
        for overclaiming in self.0.keys().filter(|existing| !resources.contains_asn(**existing)) {
            object_updates.add_removed(*overclaiming);
        }

        Ok(object_updates)
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
}

impl Default for AspaObjects {
    fn default() -> Self {
        Self(HashMap::new())
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
}

impl PartialEq for AspaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.aspa.to_captured().as_slice() == other.aspa.to_captured().as_slice()
    }
}

impl Eq for AspaInfo {}
