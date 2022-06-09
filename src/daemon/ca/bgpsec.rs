use std::collections::HashMap;

use rpki::{
    ca::{csr::BgpsecCsr, publication::Base64},
    crypto::PublicKey,
    repository::{
        cert::{ExtendedKeyUsage, KeyUsage, Overclaim, TbsCert},
        resources::Asn,
        x509::{Serial, Time},
        Cert,
    },
};

use crate::{
    commons::{
        api::BgpSecAsnKey,
        crypto::{KrillSigner, SignSupport},
        KrillResult,
    },
    daemon::config::{Config, IssuanceTimingConfig},
};

use super::{BgpSecCertificateUpdates, CertifiedKey};

//------------ BgpSecObjects -----------------------------------------------

/// The issued BGPSec certificates under a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecObjects(HashMap<BgpSecAsnKey, BgpSecCertInfo>);

impl BgpSecObjects {
    fn make_bgpsec_cert(
        &self,
        asn: Asn,
        csr: &StoredBgpSecCsr,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertInfo> {
        let serial_number = signer.random_serial()?;

        let incoming_cert = certified_key.incoming_cert();
        let issuer = incoming_cert.subject().clone();
        let crl_uri = incoming_cert.crl_uri();
        let aki = incoming_cert.subject_public_key_info().key_identifier();
        let aia = incoming_cert.uri().clone();

        let validity = SignSupport::sign_validity_weeks(issuance_timing.timing_bgpsec_valid_weeks);

        let mut router_cert = TbsCert::new(
            serial_number,
            issuer,
            validity,
            None,
            csr.key.clone(),
            KeyUsage::Ee,
            Overclaim::Refuse,
        );

        router_cert.set_extended_key_usage(Some(ExtendedKeyUsage::create_router()));
        router_cert.set_authority_key_identifier(Some(aki));
        router_cert.set_ca_issuer(Some(aia));
        router_cert.set_crl_uri(Some(crl_uri));
        router_cert.build_as_resource_blocks(|b| b.push(asn));

        let signing_key = certified_key.key_id();

        let cert = signer.sign_cert(router_cert, signing_key)?;

        Ok(BgpSecCertInfo::new(asn, cert))
    }

    /// Update issued BGPSec certificates
    ///
    /// Will issued new BGPSec certificates for definitions using the resources of
    /// this certified key which did not yet exist.
    ///
    /// Will remove any existing BGPSec certificates for which the certified key no
    /// longer holds the asn.
    ///
    /// Note that we pass in ALL BGPSec definitions, including definitions that may only
    /// be eligible under another owning RC.
    pub fn update(
        &self,
        definitions: &BgpSecDefinitions,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        let mut updates = BgpSecCertificateUpdates::default();

        let resources = certified_key.incoming_cert().resources();
        let issuance_timing = &config.issuance_timing;

        // Issue BGPSec certificates for any ASN held by the certified key
        // for which the required router key has not yet been certified.
        for (key, csr) in definitions
            .iter()
            .filter(|(k, _)| !self.0.contains_key(k) && resources.contains_asn(k.asn()))
        {
            // resource held here, but BGPSec certificate was not yet issued.
            let cert = self.make_bgpsec_cert(key.asn(), csr, certified_key, issuance_timing, signer)?;
            updates.add_updated(cert);
        }

        // Remove any BGPSec certificates for resources no longer held.
        for (key, _) in self.0.iter().filter(|(k, _)| !resources.contains_asn(k.asn())) {
            updates.add_removed(*key);
        }

        Ok(updates)
    }

    /// Re-new BGPSec certificates
    ///
    /// Used to renew certificates which would expire, in which case the renew_threshold
    /// should be specified. Or, to re-issue all existing certificates during a key rollover
    /// activation of a new certified_key - in which case the renew_threshold is expected to
    /// be None, and the certified_key is expected to have have changed.
    pub fn renew(
        &self,
        certified_key: &CertifiedKey,
        renew_threshold: Option<Time>,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        let mut updates = BgpSecCertificateUpdates::default();
    }

    /// Applies updates from an event.
    pub fn updated(&mut self, updates: BgpSecCertificateUpdates) {
        let (updated, removed) = updates.unpack();
        for info in updated {
            let key = info.asn_key;
            self.0.insert(key, info);
        }
        for key in removed {
            self.0.remove(&key);
        }
    }
}

//------------ BgpSecCertInfo ----------------------------------------------

/// An issued BGPSec certificate under a resource class
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCertInfo {
    #[serde(flatten)]
    asn_key: BgpSecAsnKey,
    serial: Serial,
    expires: Time,
    binary: Base64,
}

impl BgpSecCertInfo {
    fn new(asn: Asn, cert: Cert) -> Self {
        let pub_key = cert.subject_public_key_info();
        let asn_key = BgpSecAsnKey::new(asn, pub_key.key_identifier());
        let serial = cert.serial_number();
        let expires = cert.validity().not_after();
        let binary = Base64::from(&cert);

        BgpSecCertInfo {
            asn_key,
            serial,
            expires,
            binary,
        }
    }
}

//------------ BgpSecDefinitions -------------------------------------------

/// All BGPSec definitions held by a CA.
///
/// Actual BGPSec certificates will be issued under the relevant
/// resource classes. The resulting published objects are held by
/// the CaObjects structure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecDefinitions(HashMap<BgpSecAsnKey, StoredBgpSecCsr>);

impl BgpSecDefinitions {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BgpSecAsnKey, &StoredBgpSecCsr)> {
        self.0.iter()
    }

    pub fn get_stored_csr(&self, key: &BgpSecAsnKey) -> Option<&StoredBgpSecCsr> {
        self.0.get(key)
    }

    pub fn has(&self, key: &BgpSecAsnKey) -> bool {
        self.0.contains_key(key)
    }

    /// Inserts or updates the CSR entry for the given key.
    pub fn add_or_replace(&mut self, key: BgpSecAsnKey, csr: StoredBgpSecCsr) {
        self.0.insert(key, csr);
    }

    /// Removes the CSR entry for the given key.
    pub fn remove(&mut self, key: &BgpSecAsnKey) -> bool {
        self.0.remove(key).is_some()
    }
}

//------------ StoredBgpSecCsr ---------------------------------------------

/// A stored BGP Sec CSR.
///
/// The original CSR is stored as a base64 structure in order to avoid
/// issues if (when?) our CSR parsing should become more strict in a
/// future release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredBgpSecCsr {
    since: Time,
    key: PublicKey,
    binary: Base64,
}

impl From<&BgpsecCsr> for StoredBgpSecCsr {
    fn from(csr: &BgpsecCsr) -> Self {
        let since = Time::now();
        let key = csr.public_key().clone();
        let binary = Base64::from_content(csr.to_captured().as_slice());
        StoredBgpSecCsr { since, key, binary }
    }
}
