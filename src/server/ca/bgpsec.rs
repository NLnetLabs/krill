//! BGPsec router keys.

use std::fmt;
use std::collections::HashMap;
use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::publication::Base64;
use rpki::crypto::PublicKey;
use rpki::repository::cert::{
    Cert, ExtendedKeyUsage, KeyUsage, Overclaim, TbsCert
};
use rpki::repository::resources::{Asn, ResourceSet};
use rpki::repository::x509::{Serial, Time};
use serde::{Deserialize, Serialize};
use crate::api::bgpsec::{
    BgpSecAsnKey, BgpSecCsrInfo, BgpSecCsrInfoList, BgpSecDefinitionUpdates,
};
use crate::api::ca::ObjectName;
use crate::commons::KrillResult;
use crate::commons::error::Error;
use crate::commons::crypto::KrillSigner;
use crate::config::{Config, IssuanceTimingConfig};
use super::events::CertAuthEvent;
use super::keys::CertifiedKey;


//------------ BgpSecDefinitions ---------------------------------------------

/// All BGPsec router key definitions held by a CA.
///
/// Actual BGPsec certificates will be issued under the relevant
/// resource classes.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecDefinitions(HashMap<BgpSecAsnKey, StoredBgpSecCsr>);

impl BgpSecDefinitions {
    /// Returns whether the list of definitions is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the stored definitions.
    ///
    /// The iterator’s item is a tuple with the ASN and key identifier as
    /// its first element and the certificate signing request as its second
    /// item.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&BgpSecAsnKey, &StoredBgpSecCsr)> {
        self.0.iter()
    }

    /// Creates a BGPsec info list.
    pub fn create_info_list(&self) -> BgpSecCsrInfoList {
        BgpSecCsrInfoList::new(
            self.0
                .iter()
                .map(|(key, csr)| {
                    BgpSecCsrInfo {
                        asn: key.asn,
                        key_identifier: key.key,
                        csr: csr.csr.clone(),
                    }
                })
                .collect(),
        )
    }

    /// Returns the certificate signing request for a BGPsec router key.
    pub fn get_stored_csr(
        &self,
        key: &BgpSecAsnKey,
    ) -> Option<&StoredBgpSecCsr> {
        self.0.get(key)
    }

    /// Returns whether a BGPsec router key is present.
    pub fn has(&self, key: &BgpSecAsnKey) -> bool {
        self.0.contains_key(key)
    }

    /// Inserts or updates the certificate signing request for the given key.
    pub fn add_or_replace(
        &mut self,
        key: BgpSecAsnKey,
        csr: StoredBgpSecCsr,
    ) {
        self.0.insert(key, csr);
    }

    /// Removes the given BGPsec router key.
    pub fn remove(&mut self, key: &BgpSecAsnKey) -> bool {
        self.0.remove(key).is_some()
    }

    /// Proceses updates.
    ///
    /// Returns both the new definition and the events leading to it.
    ///
    /// Returns an error if the updates cannot be applied cleanly.
    pub fn process_updates(
        &self,
        handle: &CaHandle,
        all_resources: &ResourceSet,
        updates: BgpSecDefinitionUpdates,
    ) -> KrillResult<(Self, Vec<CertAuthEvent>)> {
        let mut events = vec![];

        // We keep a copy of the definitions so that we can:
        // a. remove and then re-add definitions
        // b. use the updated definitions to generate objects in
        //    applicable RCs
        //
        // (note: actual modifications of self are done when the events are
        // applied)
        let mut definitions = self.clone();

        for key in updates.remove {
            if !definitions.remove(&key) {
                return Err(Error::BgpSecDefinitionUnknown(
                    handle.clone(),
                    key,
                ));
            } else {
                events.push(CertAuthEvent::BgpSecDefinitionRemoved { key });
            }
        }

        // Verify that the CSR in each 'addition' is valid. Then either add
        // a new or update an existing definition.
        for definition in updates.add {
            // ensure the CSR is validly signed
            definition.csr.verify_signature().map_err(|e| {
                Error::BgpSecDefinitionInvalidlySigned(
                    handle.clone(),
                    definition.clone(),
                    e.to_string(),
                )
            })?;

            let key = BgpSecAsnKey::from(&definition);
            let csr = StoredBgpSecCsr::from_csr(&definition.csr);

            // ensure this CA holds the AS
            if !all_resources.contains_asn(key.asn) {
                return Err(Error::BgpSecDefinitionNotEntitled(
                    handle.clone(),
                    key,
                ));
            }

            if let Some(stored_csr) = definitions.get_stored_csr(&key) {
                if stored_csr != &csr {
                    events.push(CertAuthEvent::BgpSecDefinitionUpdated {
                        key,
                        csr: csr.clone(),
                    });
                    definitions.add_or_replace(key, csr);
                }
            } else {
                events.push(CertAuthEvent::BgpSecDefinitionAdded {
                    key,
                    csr: csr.clone(),
                });
                definitions.add_or_replace(key, csr);
            }
        }
        Ok((definitions, events))
    }
}


//------------ StoredBgpSecCsr -----------------------------------------------

/// A stored BGP Sec CSR.
///
/// The original CSR is stored as a base64 structure in order to avoid
/// issues if (when?) our CSR parsing should become more strict in a
/// future release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredBgpSecCsr {
    /// The time we first processed this CSR.
    pub since: Time,

    /// The public key from the CSR.
    pub key: PublicKey,

    /// The encoded CSR.
    pub csr: Base64,
}

impl StoredBgpSecCsr {
    pub fn from_csr(csr: &BgpsecCsr) -> Self {
        let since = Time::now();
        let key = csr.public_key().clone();
        let binary = Base64::from_content(csr.to_captured().as_slice());
        StoredBgpSecCsr {
            since,
            key,
            csr: binary,
        }
    }
}


//------------ BgpSecCertificates --------------------------------------------

/// The BGPsec certificates issued under a resource class in a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCertificates(HashMap<BgpSecAsnKey, BgpSecCertInfo>);

impl BgpSecCertificates {
    /// Returns whether aren’t any BGPsec router keys.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the updates to issued BGPsec certificates.
    ///
    /// The method takes all BGPsec definitions of a CA and filters the
    /// relevant definitions for the ASN resources included in the
    /// `certified_key`.
    ///
    /// It will issue new BGPsec certificates for definitions using
    /// the resources of this certified key which did not yet exist and
    /// will remove any existing BGPSec certificates which are no longer
    /// present in the definitions or for which the certified key no longer
    /// holds the ASN.
    pub fn create_updates(
        &self,
        definitions: &BgpSecDefinitions,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        let mut updates = BgpSecCertificateUpdates::default();

        let resources = &certified_key.incoming_cert().resources;
        let issuance_timing = &config.issuance_timing;

        // Issue BGPsec certificates for any ASN held by the certified key
        // for which the required router key has not yet been certified.
        for (key, csr) in definitions.iter().filter(|(k, _)| {
            !self.0.contains_key(k) && resources.contains_asn(k.asn)
        }) {
            // resource held here, but BGPSec certificate was not yet issued.
            let cert = self.make_bgpsec_cert(
                key.asn,
                csr.key.clone(),
                certified_key,
                issuance_timing,
                signer,
            )?;
            updates.updated.push(cert);
        }

        // Remove any existing BGPSec certificates which:
        // - are no longer present in the definitions; or
        // - for which the certified key no longer holds the asn.
        for (key, _) in self.0.iter().filter(|(k, _)| {
            !definitions.has(k) || !resources.contains_asn(k.asn)
        }) {
            updates.removed.push(*key);
        }

        Ok(updates)
    }

    /// Returns an update with all certificates that need renewal.
    ///
    /// If a `renew_threshold` is given, all certificates that expire before
    /// that time will be re-issued and included in the returned update.
    ///
    /// Otherwise, all certificates will be re-issued and returned.
    pub fn create_renewal(
        &self,
        certified_key: &CertifiedKey,
        renew_threshold: Option<Time>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertificateUpdates> {
        let mut updates = BgpSecCertificateUpdates::default();

        for cert in self.0.values().filter(|cert| {
            renew_threshold
                .map(|threshold| cert.expires < threshold) // will expire
                .unwrap_or(true) // always renew if no renew_threshold was
                                 // given
        }) {
            let cert = self.make_bgpsec_cert(
                cert.asn,
                cert.public_key.clone(),
                certified_key,
                issuance_timing,
                signer,
            )?;
            updates.updated.push(cert);
        }

        Ok(updates)
    }

    /// Creates a BGPsec router key certificate.
    fn make_bgpsec_cert(
        &self,
        asn: Asn,
        public_key: PublicKey,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<BgpSecCertInfo> {
        let serial_number = signer.random_serial()?;

        let issuer = certified_key.incoming_cert().subject.clone();
        let crl_uri = certified_key.incoming_cert().crl_uri();
        let aki = certified_key.incoming_cert().key_identifier();
        let aia = certified_key.incoming_cert().uri.clone();

        // Perhaps implement recommendation of 3.1.1 RFC 8209 somehow.
        // However, it is not at all clear how/why this is relevant.
        // RPs will typically discard this information and the subject
        // is not communicated to routers. If this is for
        // debugging purposes then using a sensible file name (like we do) is
        // more important.
        let subject = None;

        let mut router_cert = TbsCert::new(
            serial_number,
            issuer,
            issuance_timing.new_bgpsec_validity(),
            subject,
            public_key,
            KeyUsage::Ee,
            Overclaim::Refuse,
        );

        router_cert.set_extended_key_usage(
            Some(ExtendedKeyUsage::create_router())
        );
        router_cert.set_authority_key_identifier(Some(aki));
        router_cert.set_ca_issuer(Some(aia));
        router_cert.set_crl_uri(Some(crl_uri));
        router_cert.build_as_resource_blocks(|b| b.push(asn));

        let cert = signer.sign_cert(router_cert, &certified_key.key_id())?;

        Ok(BgpSecCertInfo::new(asn, cert))
    }

    /// Applies the given updates.
    pub fn apply_updates(&mut self, updates: BgpSecCertificateUpdates) {
        for info in updates.updated {
            let key = info.asn_key();
            self.0.insert(key, info);
        }
        for key in updates.removed {
            self.0.remove(&key);
        }
    }
}


//------------ BgpSecCertInfo ------------------------------------------------

/// An issued BGPsec certificate under a resource class
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCertInfo {
    /// The ASN of the autonomous system that uses this router key.
    pub asn: Asn,

    /// The router key.
    pub public_key: PublicKey,

    /// The serial number of the BGPsec certificate.
    pub serial: Serial,

    /// The expiry time of the certificate.
    pub expires: Time,

    /// The encoded certficate.
    pub base64: Base64,
}

impl BgpSecCertInfo {
    /// Creates a new value from the ASN and BGPsec certificate.
    fn new(asn: Asn, cert: Cert) -> Self {
        let public_key = cert.subject_public_key_info().clone();
        let serial = cert.serial_number();
        let expires = cert.validity().not_after();
        let base64 = Base64::from(&cert);

        BgpSecCertInfo {
            asn,
            public_key,
            serial,
            expires,
            base64,
        }
    }

    /// Returns the BGPsec router key payload.
    pub fn asn_key(&self) -> BgpSecAsnKey {
        BgpSecAsnKey { asn: self.asn, key: self.public_key.key_identifier() }
    }

    /// Returns the file name of the certificate.
    pub fn name(&self) -> ObjectName {
        ObjectName::bgpsec(self.asn, self.public_key.key_identifier())
    }
}


//------------ BgpSecCertificateUpdates --------------------------------------

/// Updates to the published BGPsec router key certificates.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCertificateUpdates {
    /// The certificates to be added or updated.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    updated: Vec<BgpSecCertInfo>,

    /// The certificates to be removed.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    removed: Vec<BgpSecAsnKey>,
}

impl BgpSecCertificateUpdates {
    /// Returns whether there are no updates.
    pub fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.removed.is_empty()
    }

    /// Returns the updated certificates.
    pub fn updated(&self) -> &[BgpSecCertInfo] {
        &self.updated
    }

    /// Returns the removed certificates.
    pub fn removed(&self) -> &[BgpSecAsnKey] {
        &self.removed
    }
}

impl fmt::Display for BgpSecCertificateUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.updated.is_empty() {
            write!(f, " added: ")?;
            for cert in &self.updated {
                write!(f, "{} ", cert.name())?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, " removed: ")?;
            for key in &self.removed {
                write!(f, "{} ", ObjectName::from(key))?;
            }
        }
        Ok(())
    }
}
