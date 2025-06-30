//! Importing CA structures for testing or automated set ups.

use std::fmt;
use std::collections::HashMap;
use rpki::uri;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{CaHandle, ChildHandle, ParentHandle};
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::ResourceSet;
use serde::{Deserialize, Deserializer, Serialize};
use crate::commons::KrillResult;
use crate::commons::crypto::CsrInfo;
use crate::commons::error::Error;
use crate::commons::ext_serde::OneOrMany;
use crate::constants::ta_handle;
use super::admin::PublicationServerUris;
use super::roa::RoaConfiguration;


//------------ Structure -----------------------------------------------------

/// The full structure of CAs and signed objects set up when the imported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Structure {
    /// Information about the trust anchor to import the CA under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ta: Option<ImportTa>,

    /// Information about the publication server to use for the CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_server: Option<PublicationServerUris>,

    /// Information about the CAs to import.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub cas: Vec<ImportCa>,
}

impl Structure {
    /// Creates the import structure for testbed CAs.
    pub fn for_testbed(
        ta_aia: uri::Rsync,
        ta_uri: uri::Https,
        publication_server_uris: PublicationServerUris,
        cas: Vec<ImportCa>,
    ) -> Self {
        Structure {
            ta: Some(ImportTa {
                ta_aia,
                ta_uri,
                ta_key_pem: None,
                ta_mft_nr_override: None,
            }),
            publication_server: Some(publication_server_uris),
            cas,
        }
    }

    /// Checks the CA hierarchy in this strucuture.
    ///
    /// Check that all parents are valid for the CAs in this structure
    /// in the order in which they appear, and that the parent CAs have
    /// the resources for each child CA.
    pub fn validate_ca_hierarchy(
        &self,
        mut existing_cas: HashMap<ParentHandle, ResourceSet>,
    ) -> KrillResult<()> {
        // Note we define the parent child relationship in the child only.
        // So, the child refers to one or more parents that should have
        // already been seen in the import structure.
        //
        // Furthermore, the child defines which resources it will get from
        // the named parent. So we *also* expect that the parent claimed
        // all those resources itself.
        //
        // We will always have a TA, with ALL resources in this setup. This
        // TA is not mentioned in the CAs part of this structure. So, we
        // will mark it as implicitly seen.
        let ta_handle = ta_handle();
        existing_cas.insert(ta_handle.convert(), ResourceSet::all());

        for ca in &self.cas {
            if ca.handle == ta_handle {
                return Err(Error::Custom(format!(
                    "CA name {ta_handle} is reserved."
                )));
            }

            if existing_cas.contains_key(&ca.handle.convert()) {
                return Err(Error::Custom(format!(
                    "CA with name {} already exists. \
                     Check import and server state!",
                    ca.handle
                )));
            }

            let mut ca_resources = ResourceSet::empty();
            for ca_parent in &ca.parents {
                if let Some(seen_parent_resources) = existing_cas.get(
                    &ca_parent.handle
                ) {
                    if seen_parent_resources.contains(&ca_parent.resources) {
                        ca_resources = ca_resources.union(
                            &ca_parent.resources
                        );
                    }
                    else {
                        return Err(Error::Custom(format!(
                            "CA '{}' under parent '{}' claims resources not \
                             held by parent.",
                            ca.handle,
                            ca_parent.handle
                        )));
                    }
                }
                else {
                    return Err(Error::Custom(format!(
                        "CA '{}' wants parent '{}', but this parent CA does \
                         not appear before this CA.",
                        ca.handle,
                        ca_parent.handle
                    )));
                }
            }
            existing_cas.insert(ca.handle.convert(), ca_resources);
        }
        Ok(())
    }
}


//------------ ImportTa ------------------------------------------------------

/// Information about the TA to import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportTa {
    /// The rsync URI for the TA certificate.
    pub ta_aia: uri::Rsync,

    /// The HTTPS for the TA certificate.
    pub ta_uri: uri::Https,

    /// The PEM encoded public key of the TA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ta_key_pem: Option<String>,

    /// The manifest number of the first manifest of the TA CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ta_mft_nr_override: Option<u64>,
}


//------------ ImportCa ------------------------------------------------------

/// The structure of a CA to be imported.
///
/// The type describes a CA at the top of a branch and recursively includes 0
/// or more/ children of this same type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportCa {
    /// The local handle identifying the CA.
    pub handle: CaHandle,

    /// The parent CAs of the CA.
    ///
    /// In the majority of cases there will only be one parent, so this
    /// field can be deserialized from a single element or a list of elements.
    #[serde(rename = "parent", deserialize_with = "deserialize_parent")]
    pub parents: Vec<ImportParent>,

    /// The ROAs to be published by the CA.
    #[serde(default = "Vec::new")]
    pub roas: Vec<RoaConfiguration>,
}


//------------ ImportParent --------------------------------------------------

/// Information about the parent CA of an imported CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportParent {
    /// The local handle of the parent CA.
    pub handle: ParentHandle,

    /// The resources the new CA should be entitled to under the parent.
    pub resources: ResourceSet,
}


//------------ ImportChild ---------------------------------------------------

/// A child CA that can be imported from or exported to another parent CA.
///
/// Only supports the simplest scenario where the child has only
/// one certificate in only one resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportChild {
    /// The local handle of the child CA.
    pub name: ChildHandle,

    /// The ID certificate used to communicate with the client CA.
    pub id_cert: IdCert,

    /// The resource set the client CA is entitled to.
    pub resources: ResourceSet,

    /// The certificate issued to the child CA.
    pub issued_cert: ImportChildCertificate,
}


//------------ ImportChildCertificate ----------------------------------------

/// A certificate to be issued to a child CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportChildCertificate {
    /// The certificate signing request for the certificate.
    #[serde(flatten)]
    pub csr: CsrInfo,

    /// The resource class name for the child resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<ChildResourceClassName>,
}

impl fmt::Display for ImportChild {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Name:         {}", self.name)?;
        writeln!(
            f,
            "Id Key:       {}",
            self.id_cert.public_key().key_identifier()
        )?;
        writeln!(f, "Resources:    {}", self.resources)?;
        if let Some(class_name) = &self.issued_cert.class_name {
            writeln!(f, "Classname:    {class_name}")?;
        }
        let (ca_repository, rpki_manifest, rpki_notify, key) =
            self.issued_cert.csr.clone().unpack();

        writeln!(f, "Issued Certificate:")?;
        writeln!(f, "  Key Id:       {}", key.key_identifier())?;
        writeln!(f, "  CA repo:      {ca_repository}")?;
        writeln!(f, "  CA mft:       {rpki_manifest}")?;
        if let Some(rrdp) = rpki_notify {
            writeln!(f, "  RRDP:         {rrdp}")?;
        }

        Ok(())
    }
}


//------------ ChildResourceClassName ----------------------------------------

pub type ChildResourceClassName = ResourceClassName;


//------------ Helper Functions ----------------------------------------------

/// Deserializes for `ImportParent`.
fn deserialize_parent<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ImportParent>, D::Error> {
    OneOrMany::<ImportParent>::deserialize(deserializer)
        .map(|oom| oom.into())
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cas_only() {
        let json = include_str!(
            "../../test-resources/bulk-ca-import/structure.json"
        );

        let structure: Structure = serde_json::from_str(json).unwrap();
        assert!(structure.validate_ca_hierarchy(HashMap::new()).is_ok());
    }

    #[test]
    fn parse_import_delegated_child() {
        let json = include_str!(
            "../../test-resources/bulk-ca-import/import-nicbr.json"
        );

        let _child: ImportChild = serde_json::from_str(json).unwrap();
    }
}
