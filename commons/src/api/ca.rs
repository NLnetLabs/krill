//! Common data types for Certificate Authorities

use std::fmt;
use std::str::FromStr;

use bytes::Bytes;

use rpki::cert::Cert;
use rpki::crypto::PublicKey;
use rpki::resources::{AsResources, Ipv4Resources, Ipv6Resources};
use rpki::uri;

use crate::api::Base64;
use crate::util::ext_serde;
use crate::util::softsigner::SignerKeyId;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>, // We won't create TALs with rsync, this is not for parsing.

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    encoded_ski: Bytes,
}

impl TrustAnchorLocator {
    pub fn new(uris: Vec<uri::Https>, cert: &Cert) -> Self {
        let encoded_ski = cert.subject_public_key_info().to_info_bytes();
        TrustAnchorLocator { uris, encoded_ski }
    }
}

impl fmt::Display for TrustAnchorLocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base64 = Base64::from_content(&self.encoded_ski).to_string();

        for uri in self.uris.iter() {
            writeln!(f, "{}", uri)?;
        }
        writeln!(f)?;

        let len = base64.len();
        let wrap = 64;

        for i in 0..=(len / wrap) {
            if (i * wrap + wrap) < len {
                writeln!(f, "{}", &base64[i * wrap .. i * wrap + wrap])?;
            } else {
                write!(f, "{}", &base64[i * wrap .. ])?;
            }
        }

        Ok(())
    }
}


//------------ RepoInfo ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    base_uri: uri::Rsync,
    rpki_notify: uri::Https
}

impl RepoInfo {
    pub fn new(base_uri: uri::Rsync, rpki_notify: uri::Https) -> Self {
        RepoInfo { base_uri, rpki_notify }
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

    pub fn rpki_notify(&self) -> uri::Https {
        self.rpki_notify.clone()
    }
}

impl PartialEq for RepoInfo {
    fn eq(&self, other: &RepoInfo) -> bool {
        self.base_uri == other.base_uri && self.rpki_notify.as_str() == other.rpki_notify.as_str()
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
    pub fn new(resources: ResourceSet, key: SignerKeyId) -> Self {
        let current_key = ActiveKey { key };
        ResourceClass { resources, current_key }
    }
}

//------------ ActiveKey -----------------------------------------------------

#[derive(Clone, Debug, Deserialize,  Eq, PartialEq, Serialize)]
pub struct ActiveKey {
    key: SignerKeyId,
}

impl ActiveKey {
    pub fn new(key: SignerKeyId) -> Self {
        ActiveKey { key }
    }
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


//------------ TrustAnchorInfo -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorInfo {
    resources: ResourceSet,
    repo_info: RepoInfo,
    tal: TrustAnchorLocator
}

impl TrustAnchorInfo {
    pub fn new(
        resources: ResourceSet,
        repo_info: RepoInfo,
        tal: TrustAnchorLocator
    ) -> Self {
        TrustAnchorInfo {resources, repo_info, tal }
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
    use bytes::Bytes;

    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;
    use crate::util::test;
    use crate::util::softsigner::OpenSslSigner;

    fn base_uri() -> uri::Rsync {
        test::rsync_uri("rsync://localhost/repo/ta/")
    }

    fn rrdp_uri() -> uri::Https {
        test::https_uri("https://localhost/rrdp/notification.xml")
    }

    fn info() -> RepoInfo {
        RepoInfo { base_uri: base_uri(), rpki_notify: rrdp_uri() }
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

    #[test]
    fn serialize_deserialize_resource_class() {
        let asns = "inherit";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();
        let key = SignerKeyId::new("some_key");

        let rc = ResourceClass::new(set, key);

        let json = serde_json::to_string(&rc).unwrap();
        let deser_rc = serde_json::from_str(&json).unwrap();

        assert_eq!(rc, deser_rc);
    }

    #[test]
    fn serialize_deserialise_repo_info() {
        let info = RepoInfo::new(
            test::rsync_uri("rsync://some/module/folder/"),
            test::https_uri("https://host/notification.xml")
        );

        let json = serde_json::to_string(&info).unwrap();
        let deser_info = serde_json::from_str(&json).unwrap();

        assert_eq!(info, deser_info);
    }

    #[test]
    fn create_and_display_tal() {
        let der = include_bytes!("../../test-resources/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();
        let uri = test::https_uri("https://localhost/ta.cer");

        let tal = TrustAnchorLocator::new(vec![uri], &cert);

        let expected_tal = include_str!("../../test-resources/test.tal");
        let found_tal = tal.to_string();

        assert_eq!(expected_tal, &found_tal);

    }


}
