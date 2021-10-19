//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/
//!

use std::{collections::HashMap, fmt::Debug};

use rpki::{
    repository::{
        aspa::{Aspa, AspaBuilder},
        sigobj::SignedObjectBuilder,
        x509::Time,
    },
    uri,
};

use crate::{
    commons::{
        api::{AspaConfiguration, AspaCustomer, ObjectName},
        crypto::{KrillSigner, SignSupport},
        error::Error,
        KrillResult,
    },
    daemon::ca::CertifiedKey,
};

pub fn make_aspa_object(
    aspa_config: AspaConfiguration,
    certified_key: &CertifiedKey,
    alternate_repo: Option<&uri::Rsync>,
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
        let crl_uri = match &alternate_repo {
            None => incoming_cert.crl_uri(),
            Some(base_uri) => base_uri.join(incoming_cert.crl_name().as_bytes()).unwrap(),
        };

        let aspa_uri = match &alternate_repo {
            None => incoming_cert.uri_for_name(&name),
            Some(base_uri) => base_uri.join(name.as_bytes()).unwrap(),
        };

        let mut object_builder = SignedObjectBuilder::new(
            signer.random_serial()?,
            SignSupport::sign_validity_weeks(weeks),
            crl_uri,
            incoming_cert.uri().clone(),
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
    attestations: HashMap<AspaCustomer, AspaConfiguration>,
}

impl AspaDefinitions {}

/// # Set operations
///
impl AspaDefinitions {
    pub fn get(&self, customer: AspaCustomer) -> Option<&AspaConfiguration> {
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

impl Default for AspaObjects {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

//------------ AspaInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AspaInfo {
    customer: AspaCustomer,
    aspa: Aspa,
    since: Time, // Creation time
}

impl AspaInfo {
    pub fn new(customer: AspaCustomer, aspa: Aspa, since: Time) -> Self {
        AspaInfo { customer, aspa, since }
    }

    pub fn new_aspa(customer: AspaCustomer, aspa: Aspa) -> Self {
        AspaInfo::new(customer, aspa, Time::now())
    }

    pub fn customer(&self) -> AspaCustomer {
        self.customer
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
