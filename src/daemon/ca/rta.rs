use std::{collections::HashMap, fmt};

use bytes::Bytes;

use rpki::repository::{
    crypto::{DigestAlgorithm, KeyIdentifier},
    rta,
    sigobj::MessageDigest,
    x509::Validity,
};

use crate::commons::{
    api::{Base64, ResourceClassName, ResourceSet, Revocation, RtaList, RtaName},
    error::Error,
    util::ext_serde,
    KrillResult,
};

//------------ Rtas ---------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Rtas {
    map: HashMap<RtaName, RtaState>,
}

impl Rtas {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn list(&self) -> RtaList {
        RtaList::new(self.map.keys().cloned().collect())
    }

    pub fn has(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    pub fn signed_rta(&self, name: &str) -> KrillResult<ResourceTaggedAttestation> {
        let state = self.map.get(name).ok_or_else(|| Error::custom("Unknown RTA"))?;
        match state {
            RtaState::Signed(signed) => Ok(signed.rta.clone()),
            RtaState::Prepared(_) => Err(Error::custom("RTA is not signed yet")),
        }
    }

    pub fn prepared_rta(&self, name: &str) -> KrillResult<&PreparedRta> {
        let state = self.map.get(name).ok_or_else(|| Error::custom("Unknown RTA"))?;
        match state {
            RtaState::Signed(_) => Err(Error::custom("RTA was already signed")),
            RtaState::Prepared(prepped) => Ok(prepped),
        }
    }

    pub fn add_prepared(&mut self, name: RtaName, prepared: PreparedRta) {
        self.map.insert(name, RtaState::Prepared(prepared));
    }

    pub fn add_signed(&mut self, name: RtaName, signed: SignedRta) {
        self.map.insert(name, RtaState::Signed(signed));
    }
}

//------------ RtaState -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
enum RtaState {
    Prepared(PreparedRta),
    Signed(SignedRta),
}

//------------ PreparedRta --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedRta {
    resources: ResourceSet,
    validity: Validity,
    keys: HashMap<ResourceClassName, KeyIdentifier>,
}

impl PreparedRta {
    pub fn new(resources: ResourceSet, validity: Validity, keys: HashMap<ResourceClassName, KeyIdentifier>) -> Self {
        PreparedRta {
            resources,
            validity,
            keys,
        }
    }

    pub fn validity(&self) -> Validity {
        self.validity
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn keys(&self) -> Vec<KeyIdentifier> {
        self.keys.values().cloned().collect()
    }

    pub fn key_map(&self) -> &HashMap<ResourceClassName, KeyIdentifier> {
        &self.keys
    }
}

//------------ SignedRta -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedRta {
    resources: ResourceSet,
    revocation_info: HashMap<ResourceClassName, Revocation>,
    rta: ResourceTaggedAttestation,
}

impl SignedRta {
    pub fn new(
        resources: ResourceSet,
        revocation_info: HashMap<ResourceClassName, Revocation>,
        rta: ResourceTaggedAttestation,
    ) -> Self {
        SignedRta {
            resources,
            revocation_info,
            rta,
        }
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }
}

//------------ RtaPrepareRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaPrepareRequest {
    resources: ResourceSet,
    validity: Validity,
}

impl RtaPrepareRequest {
    pub fn new(resources: ResourceSet, validity: Validity) -> Self {
        RtaPrepareRequest { resources, validity }
    }

    pub fn unpack(self) -> (ResourceSet, Validity) {
        (self.resources, self.validity)
    }
}

//------------ RtaContentRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaContentRequest {
    resources: ResourceSet,
    validity: Validity,
    subject_keys: Vec<KeyIdentifier>,
    #[serde(deserialize_with = "ext_serde::de_bytes", serialize_with = "ext_serde::ser_bytes")]
    content: Bytes,
}

impl RtaContentRequest {
    pub fn new(resources: ResourceSet, validity: Validity, subject_keys: Vec<KeyIdentifier>, content: Bytes) -> Self {
        RtaContentRequest {
            resources,
            validity,
            subject_keys,
            content,
        }
    }

    pub fn unpack(self) -> (ResourceSet, Validity, Vec<KeyIdentifier>, Bytes) {
        (self.resources, self.validity, self.subject_keys, self.content)
    }
}

impl fmt::Display for RtaContentRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "resources: {}", &self.resources)?;
        writeln!(
            f,
            "validity, {}-{}",
            self.validity.not_before().to_rfc3339(),
            self.validity.not_after().to_rfc3339()
        )?;

        write!(f, "keys: ")?;
        for key in self.subject_keys.iter() {
            write!(f, "{} ", key)?;
        }
        writeln!(f)?;
        writeln!(f, "content (base64): {}", Base64::from_content(self.content.as_ref()))?;

        Ok(())
    }
}

//------------ ResourceTaggedAttestation ------------------------------------

/// Resource Tagged Attestations
///
/// See: https://tools.ietf.org/id/draft-michaelson-rpki-rta-01.html
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct ResourceTaggedAttestation {
    #[serde(deserialize_with = "ext_serde::de_bytes", serialize_with = "ext_serde::ser_bytes")]
    bytes: Bytes,
}

impl AsRef<Bytes> for ResourceTaggedAttestation {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl ResourceTaggedAttestation {
    pub fn new(bytes: Bytes) -> Self {
        ResourceTaggedAttestation { bytes }
    }

    pub fn to_builder(&self) -> KrillResult<rta::RtaBuilder> {
        let rta =
            rta::Rta::decode(self.bytes.as_ref(), true).map_err(|_| Error::custom("Cannot decode existing RTA"))?;
        Ok(rta::RtaBuilder::from_rta(rta))
    }

    pub fn rta_builder(
        resources: &ResourceSet,
        content: Bytes,
        keys: Vec<KeyIdentifier>,
    ) -> KrillResult<rta::RtaBuilder> {
        let algo = DigestAlgorithm::default();
        let digest = algo.digest(content.as_ref());
        let mut attestation_builder = rta::AttestationBuilder::new(algo, MessageDigest::from(digest));

        for key in keys.into_iter() {
            attestation_builder.push_key(key);
        }

        for asn in resources.asn().iter() {
            attestation_builder.push_as(asn);
        }

        let v4_resources = resources.to_ip_resources_v4();
        let v4_blocks = v4_resources
            .to_blocks()
            .map_err(|_| Error::custom("Cannot inherit IPv4 on RTA"))?;
        for v4 in v4_blocks.iter() {
            attestation_builder.push_v4(v4)
        }

        let v6_resources = resources.to_ip_resources_v6();
        let v6_blocks = v6_resources
            .to_blocks()
            .map_err(|_| Error::custom("Cannot inherit IPv6 on RTA"))?;
        for v6 in v6_blocks.iter() {
            attestation_builder.push_v6(v6)
        }

        Ok(rta::RtaBuilder::from_attestation(
            attestation_builder.into_attestation(),
        ))
    }

    pub fn finalize(rta_builder: rta::RtaBuilder) -> Self {
        let rta = rta_builder.finalize();
        ResourceTaggedAttestation {
            bytes: rta.to_captured().into_bytes(),
        }
    }
}

impl fmt::Display for ResourceTaggedAttestation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Base64::from_content(self.as_ref()))
    }
}
