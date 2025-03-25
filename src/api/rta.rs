//! Resource Tagged Attestations.

use std::fmt;
use bytes::Bytes;
use rpki::ca::publication::Base64;
use rpki::crypto::{DigestAlgorithm, KeyIdentifier};
use rpki::repository::rta;
use rpki::repository::resources::ResourceSet;
use rpki::repository::sigobj::MessageDigest;
use rpki::repository::x509::Validity;
use serde::{Deserialize, Serialize};
use crate::commons::ext_serde;
use crate::commons::error::KrillError;


//------------ RtaPrepareRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaPrepareRequest {
    pub resources: ResourceSet,
    pub validity: Validity,
}


//------------ RtaContentRequest --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RtaContentRequest {
    pub resources: ResourceSet,
    pub validity: Validity,
    pub subject_keys: Vec<KeyIdentifier>,
    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes"
    )]
    pub content: Bytes,
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
        writeln!(
            f,
            "content (base64): {}",
            Base64::from_content(self.content.as_ref())
        )?;

        Ok(())
    }
}


//------------ ResourceTaggedAttestation ------------------------------------

/// Resource Tagged Attestations
///
/// See: <https://tools.ietf.org/id/draft-michaelson-rpki-rta-01.html>
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct ResourceTaggedAttestation {
    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes"
    )]
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

    pub fn to_builder(&self) -> Result<rta::RtaBuilder, KrillError> {
        let rta = rta::Rta::decode(self.bytes.as_ref(), true)
            .map_err(|_| KrillError::custom("Cannot decode existing RTA"))?;
        Ok(rta::RtaBuilder::from_rta(rta))
    }

    pub fn rta_builder(
        resources: &ResourceSet,
        content: Bytes,
        keys: Vec<KeyIdentifier>,
    ) -> Result<rta::RtaBuilder, KrillError> {
        let algo = DigestAlgorithm::default();
        let digest = algo.digest(content.as_ref());
        let mut attestation_builder =
            rta::AttestationBuilder::new(algo, MessageDigest::from(digest));

        for key in keys.into_iter() {
            attestation_builder.push_key(key);
        }

        for asn in resources.asn().iter() {
            attestation_builder.push_as(asn);
        }

        let v4_resources = resources.to_ip_resources_v4();
        let v4_blocks = v4_resources
            .to_blocks()
            .map_err(|_| KrillError::custom("Cannot inherit IPv4 on RTA"))?;
        for v4 in v4_blocks.iter() {
            attestation_builder.push_v4(v4)
        }

        let v6_resources = resources.to_ip_resources_v6();
        let v6_blocks = v6_resources
            .to_blocks()
            .map_err(|_| KrillError::custom("Cannot inherit IPv6 on RTA"))?;
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
