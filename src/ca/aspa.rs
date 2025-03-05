//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::{collections::HashMap, fmt::Debug};
use rpki::{uri, rrdp};
use rpki::ca::publication::Base64;
use rpki::repository::aspa::{Aspa, AspaBuilder};
use rpki::repository::sigobj::SignedObjectBuilder;
use rpki::repository::x509::{Serial, Time, Validity};
use serde::{Deserialize, Serialize};
use crate::commons::KrillResult;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use crate::daemon::config::{Config, IssuanceTimingConfig};
use crate::commons::api::aspa::{
    AspaDefinition, AspaProvidersUpdate, CustomerAsn
};
use crate::commons::api::ca::ObjectName;
use super::keys::CertifiedKey;


//------------ AspaDefinitions ---------------------------------------------

/// All ASPA objects defined for a CA.
///
/// The [`AspaCustomer`] ASN will be held in a single
/// [`ResourceClass`] only, but at least in theory the CA could issue ASPA
/// objects in each RC that holds the ASN.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitions {
    /// The definitions for each customer ASN.
    attestations: HashMap<CustomerAsn, AspaDefinition>,
}

impl AspaDefinitions {
    /// Adds or replaces a definition.
    pub fn add_or_replace(&mut self, aspa_def: AspaDefinition) {
        self.attestations.insert(aspa_def.customer, aspa_def);
    }

    /// Removes an definition for the given customer ASN.
    pub fn remove(&mut self, customer: CustomerAsn) {
        self.attestations.remove(&customer);
    }

    /// Applies an ASPA definitions update.
    ///
    /// Assumes that the update was verified beforehand.
    pub fn apply_update(
        &mut self,
        customer: CustomerAsn,
        update: &AspaProvidersUpdate,
    ) {
        if let Some(current) = self.attestations.get_mut(&customer) {
            current.apply_update(update);

            // If there are no remaining providers for this AspaDefinition,
            // then remove it so that its ASPA object will also be
            // removed.
            if current.providers.is_empty() {
                self.attestations.remove(&customer);
            }
        }
        else {
            // There was no AspaDefinition. So create an empty definition,
            // apply the update and then add it.
            let mut def = AspaDefinition { customer, providers: vec![] };
            def.apply_update(update);

            self.attestations.insert(customer, def);
        }
    }

    /// Returns an iterator over all ASPA definitions.
    pub fn iter(&self) -> impl Iterator<Item = &AspaDefinition> {
        self.attestations.values()
    }
}

/// # Set operations
impl AspaDefinitions {
    pub fn get(&self, customer: CustomerAsn) -> Option<&AspaDefinition> {
        self.attestations.get(&customer)
    }

    pub fn has(&self, customer: CustomerAsn) -> bool {
        self.attestations.contains_key(&customer)
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}


//------------ AspaObjects -------------------------------------------------

/// ASPA objects held by a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjects(HashMap<CustomerAsn, AspaInfo>);

impl AspaObjects {
    /// Returns whether the ASPA definitions are empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
        let resources = &certified_key.incoming_cert().resources;

        // Issue new and updated ASPAs for definitions relevant to the
        // resources in scope
        for relevant_aspa in all_aspa_defs
            .iter()
            .filter(|aspa| resources.contains_asn(aspa.customer))
        {
            let need_to_issue = self
                .0
                .get(&relevant_aspa.customer)
                .map(|existing| existing.definition() != relevant_aspa)
                .unwrap_or(true);

            if need_to_issue {
                let aspa_info = self.make_aspa(
                    relevant_aspa.clone(),
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )?;
                object_updates.add_updated(aspa_info);
            }
        }

        // Check if any currently held ASPA object needs to be removed
        for customer in self.0.keys() {
            if !all_aspa_defs.has(*customer)
                || !resources.contains_asn(*customer)
            {
                // definition was removed, or it's overclaiming
                object_updates.add_removed(*customer);
            }
        }

        Ok(object_updates)
    }

    /// Renews ASPAs.
    ///
    /// If the renew_threshold is specified, then only objects which will
    /// expire before that time will be renewed.
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

                let new_aspa = self.make_aspa(
                    aspa_definition,
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                updates.add_updated(new_aspa);
            }
        }

        Ok(updates)
    }

    /// Creates a new signed ASPA object.
    fn make_aspa(
        &self,
        aspa_def: AspaDefinition,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<AspaInfo> {
        let name = ObjectName::from(&aspa_def);

        let aspa_builder = {
            AspaBuilder::new(
                aspa_def.customer,
                aspa_def.providers.clone(),
            ).map_err(|e| {
                Error::Custom(format!("Cannot use aspa config: {}", e))
            })
        }?;

        let object_builder = {
            let incoming_cert = certified_key.incoming_cert();

            let crl_uri = incoming_cert.crl_uri();
            let aspa_uri = incoming_cert.uri_for_name(&name);
            let ca_issuer = incoming_cert.uri.clone();

            let mut object_builder = SignedObjectBuilder::new(
                signer.random_serial()?,
                issuance_timing.new_aspa_validity(),
                crl_uri,
                ca_issuer,
                aspa_uri,
            );
            object_builder.set_issuer(Some(incoming_cert.subject.clone()));
            object_builder.set_signing_time(Some(Time::now()));

            object_builder
        };

        let aspa = signer.sign_aspa(
            aspa_builder,
            object_builder,
            certified_key.key_id(),
        )?;
        Ok(AspaInfo::new(aspa_def, aspa))
    }

    /// Applies the updates to the ASPA definitions.
    pub fn apply_updates(&mut self, updates: AspaObjectsUpdates) {
        for aspa_info in updates.updated {
            let customer = aspa_info.customer();
            self.0.insert(customer, aspa_info);
        }
        for customer in updates.removed {
            self.0.remove(&customer);
        }
    }
}


//------------ AspaInfo ----------------------------------------------------

/// Information about a single ASPA obejct.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaInfo {
    /// The customer ASN and all Provider ASNs
    definition: AspaDefinition,

    /// The validity time for this ASPA.
    validity: Validity,

    /// The serial number (needed for revocation)
    serial: Serial,

    /// The URI where this object is expected to be published
    uri: uri::Rsync,

    /// The actual ASPA object in base64 format.
    base64: Base64,

    /// The ASPA object's hash
    hash: rrdp::Hash,
}

impl AspaInfo {
    /// Creates a new value from an ASPA definition and the ASPA.
    pub fn new(definition: AspaDefinition, aspa: Aspa) -> Self {
        let validity = aspa.cert().validity();
        let serial = aspa.cert().serial_number();
        // unwrapping is safe for our own objects
        let uri = aspa.cert().signed_object().unwrap().clone(); 
        let base64 = Base64::from(&aspa);
        let hash = base64.to_hash();

        AspaInfo {
            definition,
            validity,
            serial,
            uri,
            base64,
            hash,
        }
    }

    /// Returns the ASPA definition.
    pub fn definition(&self) -> &AspaDefinition {
        &self.definition
    }

    /// Returns the customer ASN of the ASPA.
    pub fn customer(&self) -> CustomerAsn {
        self.definition.customer
    }

    /// Returns the expiry time of the ASPA object.
    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    /// Returns the serial number of the ASPA object’s certificate.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Returns the rsync URI identifying the ASPA object.
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    /// Returns the encoded ASPA object.
    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    /// Returns the RRDP hash of the ASPA object.
    pub fn hash(&self) -> rrdp::Hash {
        self.hash
    }
}


//------------ AspaObjectsUpdates --------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub updated: Vec<AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<CustomerAsn>,
}

impl AspaObjectsUpdates {
    pub fn new(updated: Vec<AspaInfo>, removed: Vec<CustomerAsn>) -> Self {
        AspaObjectsUpdates { updated, removed }
    }

    pub fn for_new_aspa_info(new_aspa: AspaInfo) -> Self {
        AspaObjectsUpdates {
            updated: vec![new_aspa],
            removed: vec![],
        }
    }

    pub fn add_updated(&mut self, update: AspaInfo) {
        self.updated.push(update)
    }

    pub fn add_removed(&mut self, customer: CustomerAsn) {
        self.removed.push(customer)
    }

    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn unpack(self) -> (Vec<AspaInfo>, Vec<CustomerAsn>) {
        (self.updated, self.removed)
    }

    pub fn updated(&self) -> &Vec<AspaInfo> {
        &self.updated
    }

    pub fn removed(&self) -> &Vec<CustomerAsn> {
        &self.removed
    }
}

