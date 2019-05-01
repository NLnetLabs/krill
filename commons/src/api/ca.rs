//! Common data types for Certificate Authorities

use std::str::FromStr;

use bytes::Bytes;

use rpki::crypto::PublicKey;
use rpki::resources::{AsResources, Ipv4Resources, Ipv6Resources};
use rpki::uri;

use crate::util::ext_serde;
use crate::util::softsigner::SignerKeyId;

//------------ Cert ----------------------------------------------------------

#[derive(Clone, Debug, Deserialize,  Eq, PartialEq, Serialize)]
pub struct Cert {
    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    content: Bytes
}

//------------ RepoInfo ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rrdp_uri: uri::Http
}

impl RepoInfo {
    pub fn new(base_uri: uri::Rsync, rrdp_uri: uri::Http) -> Self {
        RepoInfo { base_uri, rrdp_uri}
    }

    pub fn signed_object(&self) -> uri::Rsync {
        self.base_uri.clone()
    }

    pub fn rpki_manifest(&self, pub_key: &PublicKey) -> uri::Rsync {
        let key_id_hex = hex::encode(pub_key.key_identifier().as_ref());
        let uri_string = format!(
            "{}{}.mft",
            self.base_uri.to_string(),
            key_id_hex
        );

        uri::Rsync::from_string(uri_string).unwrap()
    }

    pub fn rpki_notify(&self) -> uri::Http {
        self.rrdp_uri.clone()
    }
}

impl PartialEq for RepoInfo {
    fn eq(&self, other: &RepoInfo) -> bool {
        self.base_uri == other.base_uri && self.rrdp_uri.as_str() == other.rrdp_uri.as_str()
    }
}

impl Eq for RepoInfo {}


//------------ ResourceClass -------------------------------------------------

#[derive(Clone, Debug, Deserialize,  Eq, PartialEq, Serialize)]
pub struct ResourceClass {
    resources: ResourceSet,
    current_key: ActiveKey
}

impl ResourceClass {
    pub fn new(resources: ResourceSet, key: SignerKeyId, cert: Cert) -> Self {
        let current_key = ActiveKey { key, cert};
        ResourceClass { resources, current_key }
    }
}

//------------ ActiveKey -----------------------------------------------------

#[derive(Clone, Debug, Deserialize,  Eq, PartialEq, Serialize)]
struct ActiveKey {
    key: SignerKeyId,
    cert: Cert
}


//------------ ResourceSet ---------------------------------------------------

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSet {
    asn: AsResources,
    v4: Ipv4Resources,
    v6: Ipv6Resources
}

impl ResourceSet {
    pub fn from_strs(asns: &str, ipv4: &str, ipv6: &str) -> Result<Self, ResourceSetError> {
        let asn = AsResources::from_str(asns).map_err(|_| ResourceSetError::AsnParsing)?;
        let v4 = Ipv4Resources::from_str(ipv4).map_err(|_| ResourceSetError::Ipv4Parsing)?;
        let v6 = Ipv6Resources::from_str(ipv6).map_err(|_| ResourceSetError::Ipv6Parsing)?;
        Ok(ResourceSet { asn , v4, v6 })
    }

    pub fn asn(&self) -> &AsResources {
        &self.asn
    }

    pub fn v4(&self) -> &Ipv4Resources {
        &self.v4
    }

    pub fn v6(&self) -> &Ipv6Resources {
        &self.v6
    }
}


//------------ TrustAnchor ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorInfo {
    resource_class: ResourceClass,
    repo_info: RepoInfo,
}

impl TrustAnchorInfo {
    pub fn new(resource_class: ResourceClass, repo_info: RepoInfo) -> Self {
        TrustAnchorInfo { resource_class, repo_info }
    }
}

//------------ ResourceSetError ----------------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum ResourceSetError {
    #[display(fmt="Cannot parse ASN resources")]
    AsnParsing,

    #[display(fmt="Cannot parse IPv4 resources")]
    Ipv4Parsing,

    #[display(fmt="Cannot parse IPv6 resources")]
    Ipv6Parsing,

    #[display(fmt="Mixed Address Families in configured resource set")]
    MixedFamilies,
}


//============ Tests =========================================================

#[cfg(test)]
mod test {

    use super::*;
    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;
    use crate::util::test;
    use crate::util::softsigner::OpenSslSigner;

    fn base_uri() -> uri::Rsync {
        test::rsync_uri("rsync://localhost/repo/ta/")
    }

    fn rrdp_uri() -> uri::Http {
        test::http_uri("https://localhost/rrdp/notification.xml")
    }

    fn info() -> RepoInfo {
        RepoInfo { base_uri: base_uri(), rrdp_uri: rrdp_uri() }
    }

    #[test]
    fn signed_objects_uri() {
        let signed_objects_uri = info().signed_object();
        assert_eq!(base_uri(), signed_objects_uri)
    }

    #[test]
    fn mft_uri() {
        test::test_with_tmp_dir(|d| {
            let mut signer = OpenSslSigner::build(&d).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::default()).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().rpki_manifest(&pub_key);

            unsafe {
                use std::str;

                let mft_path = str::from_utf8_unchecked(
                    mft_uri.relative_to(&base_uri()).unwrap()
                );

                assert_eq!(44, mft_path.len());

                // the file name should be the hexencoded pub key info
                // not repeating that here, but checking that the name
                // part is validly hex encoded.
                let name = &mft_path[..40];
                hex::decode(name).unwrap();

                // and the extension is '.mft'
                let ext = &mft_path[40..];
                assert_eq!(ext, ".mft");
            }
        });
    }

    #[test]
    fn serialize_deserialize_asn_blocks() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "";
        let ipv6s = "";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }


    #[test]
    fn serialize_deserialize_resource_set() {
        let asns = "inherit";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }


}
