//! Autonomous System Provider Authorization (ASPA).

use std::fmt;
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


//------------ AspaDefinitions -----------------------------------------------

/// All ASPA definitions for a CA.
///
/// An [`AspaDefinition`] describes the intended authorization to be published
/// by a CA for a customer ASN number. There can be at most one definition per
/// customer ASN. The customer ASN will be held by a single resource class 
/// only, but at least in theory the CA could issue ASPA objects in each
/// resource class that holds the ASN.
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


//------------ AspaObjects ---------------------------------------------------

/// All ASPA objects held by a single resource class of a CA.
///
/// Each ASPA object is described by an [`AspaInfo`]. There can at most by
/// one ASPA object per customer ASN.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjects(HashMap<CustomerAsn, AspaInfo>);

impl AspaObjects {
    /// Returns whether there are no ASPA objects.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the updates to the ASA objects based on configuration.
    ///
    /// The method takes all ASPA definitions for the CA but will only act
    /// on definitions for the resource class indicated by `certified_key`.
    ///
    /// It issues new ASPA objects for customer ASNs for which there are no
    /// objects yet and for those for which the definition has changed. It
    /// removes ASPA objects for those customer ASNs for which there are no
    /// longer any definitions.
    pub fn create_updates(
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
                .map(|existing| existing.definition != *relevant_aspa)
                .unwrap_or(true);

            if need_to_issue {
                let aspa_info = self.make_aspa(
                    relevant_aspa.clone(),
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )?;
                object_updates.updated.push(aspa_info);
            }
        }

        // Check if any currently held ASPA object needs to be removed
        for &customer in self.0.keys() {
            if !all_aspa_defs.has(customer)
                || !resources.contains_asn(customer)
            {
                // definition was removed, or it's overclaiming
                object_updates.removed.push(customer);
            }
        }

        Ok(object_updates)
    }

    /// Returns the ASPA objects that need to be renewed.
    ///
    /// If the renew_threshold is specified, then only objects which will
    /// expire before that time will be renewed. Otherwise, all 
    pub fn create_renewal(
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
                let aspa_definition = aspa.definition.clone();

                let new_aspa = self.make_aspa(
                    aspa_definition,
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                updates.updated.push(new_aspa);
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

        let aspa_builder = AspaBuilder::new(
            aspa_def.customer,
            aspa_def.providers.clone(),
        ).map_err(|e| {
            Error::Custom(format!("Cannot use aspa config: {}", e))
        })?;

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
            self.0.insert(aspa_info.customer(), aspa_info);
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
    pub definition: AspaDefinition,

    /// The validity time for this ASPA.
    pub validity: Validity,

    /// The serial number (needed for revocation)
    pub serial: Serial,

    /// The URI where this object is expected to be published
    pub uri: uri::Rsync,

    /// The encoded ASPA object.
    pub base64: Base64,

    /// The RRDP hash of the encoded ASPA object.
    pub hash: rrdp::Hash,
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

    /// Returns the customer ASN of the ASPA object.
    pub fn customer(&self) -> CustomerAsn {
        self.definition.customer
    }

    /// Returns when the ASPA object expires.
    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }
}


//------------ AspaObjectsUpdates --------------------------------------------

/// The updates to the ASPA objects of a resource class.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjectsUpdates {
    /// Newly added or updated ASPA objects.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<AspaInfo>,

    /// Customer ASNs of the ASPA objects to be removed.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<CustomerAsn>,
}

impl AspaObjectsUpdates {
    /// Returns whether the updates object is empty.
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
    }

    /// Returns the updated objects.
    pub fn updated(&self) -> &[AspaInfo] {
        &self.updated
    }

    /// Returns the removed objects.
    pub fn removed(&self) -> &[CustomerAsn] {
        &self.removed
    }
}

impl fmt::Display for AspaObjectsUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.updated.is_empty() {
            write!(f, " updated:")?;
            for upd in &self.updated {
                write!(
                    f, " {}",
                    ObjectName::aspa_from_customer(upd.customer())
                )?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, " removed:")?;
            for rem in &self.removed {
                write!(f,
                    " {}",
                    ObjectName::aspa_from_customer(*rem)
                )?;
            }
        }
        Ok(())
    }
}

