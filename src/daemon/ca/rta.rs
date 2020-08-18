use std::fmt;

use bytes::Bytes;

use bcder::OctetString;
use rpki::cert::Cert;
use rpki::crypto::{DigestAlgorithm, KeyIdentifier};
use rpki::rta;
use rpki::sigobj::MessageDigest;
use rpki::x509::Validity;

use crate::commons::api::{Base64, ResourceSet};
use crate::commons::error::Error;
use crate::commons::util::ext_serde;
use crate::commons::KrillResult;
use crate::daemon::ca::Signer;

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct RtaRequest {
    resources: ResourceSet,
    validity: Validity,
    subject_keys: Vec<KeyIdentifier>,
    #[serde(deserialize_with = "ext_serde::de_bytes", serialize_with = "ext_serde::ser_bytes")]
    content: Bytes,
}

impl RtaRequest {
    pub fn new(resources: ResourceSet, validity: Validity, subject_keys: Vec<KeyIdentifier>, content: Bytes) -> Self {
        RtaRequest {
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

impl fmt::Display for RtaRequest {
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
    pub fn rta_builder(
        resources: &ResourceSet,
        content: Bytes,
        keys: Vec<KeyIdentifier>,
    ) -> KrillResult<rta::RtaBuilder> {
        let mut attestation_builder = rta::AttestationBuilder::new(
            DigestAlgorithm::default(),
            MessageDigest::from(OctetString::new(content)),
        );

        for key in keys.into_iter() {
            attestation_builder.push_key(key);
        }

        for asn in resources.asn().iter() {
            attestation_builder.push_as(asn.clone());
        }

        let v4_resources = resources.to_ip_resources_v4();
        let v4_blocks = v4_resources
            .to_blocks()
            .map_err(|_| Error::custom("Cannot inherit IPv4 on RTA"))?;
        for v4 in v4_blocks.iter() {
            attestation_builder.push_v4(v4.clone())
        }

        let v6_resources = resources.to_ip_resources_v6();
        let v6_blocks = v6_resources
            .to_blocks()
            .map_err(|_| Error::custom("Cannot inherit IPv6 on RTA"))?;
        for v6 in v6_blocks.iter() {
            attestation_builder.push_v6(v6.clone())
        }

        Ok(rta::RtaBuilder::from_attestation(
            attestation_builder.into_attestation(),
        ))
    }

    pub fn sign_with_ee<S: Signer>(rta_builder: &mut rta::RtaBuilder, ee: Cert, signer: &S) -> KrillResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        rta_builder.sign(signer, &key, None, None).map_err(Error::signer)?;

        Ok(())
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
