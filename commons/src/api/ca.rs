//! Common data types for Certificate Authorities, defined here so that the CLI
//! can have access without needing to depend on the full krill_ca module.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bytes::Bytes;

use rpki::cert::Cert;
use rpki::crypto::PublicKey;
use rpki::resources::{
    AsBlocks,
    AsResources,
    IpBlocks,
    Ipv4Resources,
    Ipv6Resources,
    IpResources,
};
use rpki::uri;
use rpki::x509::{
    Serial,
    Time,
};

use crate::api::Base64;
use crate::api::EncodedHash;
use crate::api::publication;
use crate::util::ext_serde;
use crate::util::softsigner::SignerKeyId;
use crate::rpki::crl::{
    Crl,
    CrlEntry,
};
use crate::rpki::manifest::{
    FileAndHash,
    Manifest,
};


//------------ TaCertificate -------------------------------------------------

/// Contains a CA Certificate that has been issued to this CA, for some key.
///
/// Note, this may be a self-signed TA Certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncomingCertificate {
    cert: Cert,
    uri: uri::Rsync,
    resources: ResourceSet
}

impl IncomingCertificate {

    pub fn new(cert: Cert, uri: uri::Rsync) -> Self {
        let resources = ResourceSet::from(&cert);
        IncomingCertificate { cert, uri, resources }
    }

    pub fn cert(&self) -> &Cert { &self.cert }
    pub fn uri(&self) -> &uri::Rsync { &self.uri }
    pub fn resources(&self) -> &ResourceSet { &self.resources }

    pub fn der_encoded(&self) -> Bytes {
        self.cert.to_captured().into_bytes()
    }
}

impl AsRef<Cert> for IncomingCertificate {
    fn as_ref(&self) -> &Cert {
        &self.cert
    }
}

impl PartialEq for IncomingCertificate {
    fn eq(&self, other: &IncomingCertificate) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() &&
            self.uri == other.uri
    }
}

impl Eq for IncomingCertificate {}


//------------ TrustAnchorLocator --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>, // We won't create TALs with rsync, this is not for parsing.

    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    encoded_ski: Bytes,
}

impl TrustAnchorLocator {
    /// Creates a new TAL, panics when the provided Cert is not a TA cert.
    pub fn new(uris: Vec<uri::Https>, cert: &Cert) -> Self {
        if cert.authority_key_identifier().is_some() {
            panic!("Trying to create TrustAnchorLocator for a non-TA certificate.")
        }
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

    pub fn signed_object(&self, name_space: &str) -> uri::Rsync {
        match name_space {
            "" => self.base_uri.clone(),
            _  => uri::Rsync::from_string(format!("{}{}/", self.base_uri.to_string(), name_space)).unwrap()
        }
    }

    pub fn resolve(&self, name_space: &str, file_name: &str) -> uri::Rsync {
        let uri = format!("{}{}", self.signed_object(name_space).to_string(), file_name);
        uri::Rsync::from_string(uri).unwrap()
    }

    pub fn rpki_notify(&self) -> uri::Https {
        self.rpki_notify.clone()
    }

    pub fn mft_name(signing_key: &PublicKey) -> String {
        format!("{}.mft", &Self::hex_sha1_ki(signing_key))
    }

    pub fn crl_name(signing_key: &PublicKey) -> String {
        format!("{}.crl", &Self::hex_sha1_ki(signing_key))
    }

    pub fn mft_uri(
        &self,
        name_space: &str,
        signing_key: &PublicKey
    ) -> uri::Rsync {
        self.resolve(name_space, &Self::mft_name(signing_key))
    }

    fn hex_sha1_ki(pub_key: &PublicKey) -> String {
        hex::encode(pub_key.key_identifier().as_ref())
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
    name: String,
    current_key: CaKey
}


//------------ CaKey ---------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Describes a Key that is active. I.e. it received an incoming certificate
/// and has at least a MFT and CRL.
pub struct CaKey {
    key_id: SignerKeyId,
    incoming_cert: IncomingCertificate,
    current_set: CurrentObjectSet
}

impl CaKey {
    pub fn new(key_id: SignerKeyId, incoming_cert: IncomingCertificate) -> Self {
        let current_set = CurrentObjectSet::default();

        CaKey {
            key_id, incoming_cert, current_set
        }
    }

    pub fn key_id(&self) -> &SignerKeyId { &self.key_id }
    pub fn incoming_cert(&self) -> &IncomingCertificate { &self.incoming_cert }
    pub fn current_set(&self) -> &CurrentObjectSet { &self.current_set }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.current_set.apply_delta(delta)
    }
}


//------------ CurrentObject -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObject {
    content: Base64,
    #[serde(
        deserialize_with = "ext_serde::de_serial",
        serialize_with = "ext_serde::ser_serial")]
    serial: Serial,

    #[serde(
    deserialize_with = "ext_serde::de_time",
    serialize_with = "ext_serde::ser_time")]
    expires: Time
}

impl CurrentObject {
    pub fn content(&self) -> &Base64 { &self.content }
    pub fn serial(&self) -> Serial { self.serial }
    pub fn expires(&self) -> Time { self.expires }
}

impl From<&Cert> for CurrentObject {
    fn from(cert: &Cert) -> Self {
        let content = Base64::from(cert);
        let serial = cert.serial_number();
        let expires = cert.validity().not_after();
        CurrentObject {
            content, serial, expires
        }
    }
}

impl From<&Crl> for CurrentObject {
    fn from(crl: &Crl) -> Self {
        let content = Base64::from(crl);
        let serial = crl.crl_number();  // never revoked
        let expires = crl.next_update();

        CurrentObject {
            content, serial, expires
        }
    }
}

impl From<&Manifest> for CurrentObject {
    fn from(mft: &Manifest) -> Self {
        let content = Base64::from(mft);
        let serial = mft.cert().serial_number();
        let expires = mft.content().next_update();

        CurrentObject {
            content, serial, expires
        }
    }
}

pub type ObjectName = String;


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjects(HashMap<ObjectName, CurrentObject>);

impl Default for CurrentObjects {
    fn default() -> Self {
        CurrentObjects(HashMap::new())
    }
}

impl CurrentObjects {
    pub fn insert(&mut self, name: String, object: CurrentObject) -> Option<CurrentObject> {
        self.0.insert(name, object)
    }

    pub fn apply_delta(&mut self, delta: ObjectsDelta) {

        for add in delta.added.into_iter() {
            self.0.insert(add.name, add.object);
        }
        for upd in delta.updated.into_iter() {
            self.0.insert(upd.name, upd.object);
        }
        for wdr in delta.withdrawn.into_iter() {
            self.0.remove(&wdr.name);
        }
    }

    pub fn object_for(&self, name: &str) -> Option<&CurrentObject> {
        self.0.get(name)
    }

    /// Returns Manifest Entries, i.e. excluding the manifest itself
    pub fn mft_entries(&self) -> Vec<FileAndHash<Bytes, Bytes>> {
        self.0.keys().filter(|k| !k.ends_with("mft")).map(|k| {
            let name_bytes = Bytes::from(k.as_str());
            let hash_bytes = self.0.get(k).unwrap().content.to_encoded_hash().into();
            FileAndHash::new(name_bytes, hash_bytes)
        }).collect()
    }
}


//------------ Revocation ----------------------------------------------------

/// A Crl Revocation. Note that this type differs from CrlEntry in
/// that it implements De/Serialize and Eq/PartialEq
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    #[serde(deserialize_with = "ext_serde::de_serial", serialize_with = "ext_serde::ser_serial")]
    serial: Serial,

    #[serde(deserialize_with = "ext_serde::de_time", serialize_with = "ext_serde::ser_time")]
    revocation_date: Time
}

impl From<&CurrentObject> for Revocation {
    fn from(co: &CurrentObject) -> Self {
        Revocation {
            serial: co.serial,
            revocation_date: Time::now()
        }
    }
}

impl From<&Manifest> for Revocation {
    fn from(m: &Manifest) -> Self {
        let serial = m.cert().serial_number();
        let revocation_date = Time::now();
        Revocation { serial, revocation_date }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocations(Vec<Revocation>);

impl Revocations {
    pub fn to_crl_entries(&self) -> Vec<CrlEntry> {
        self.0.iter().map(|r| CrlEntry::new(Serial::from(r.serial), r.revocation_date)).collect()
    }

    /// Purges all expired revocations, and returns them.
    pub fn purge(&mut self) -> Vec<Revocation> {

        let (relevant, expired) = self.0.iter().partition(|r| {
            r.revocation_date.validate_not_after(Time::now()).is_ok()
        });
        self.0 = relevant;
        expired
    }

    pub fn add(&mut self, revocation: Revocation) {
        self.0.push(revocation);
    }

    pub fn apply_delta(&mut self, delta: RevocationsDelta) {
        self.0.retain(|r| !delta.dropped.contains(r));
        for r in delta.added {
            self.add(r);
        }
    }
}

impl Default for Revocations {
    fn default() -> Self {
        Revocations(vec![])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationsDelta {
    added: Vec<Revocation>,
    dropped: Vec<Revocation>
}

impl Default for RevocationsDelta {
    fn default() -> Self {
        RevocationsDelta {
            added: vec![],
            dropped: vec![]
        }
    }
}

impl RevocationsDelta {
    pub fn add(&mut self, revocation: Revocation) {
        self.added.push(revocation);
    }
    pub fn drop(&mut self, revocation: Revocation) {
        self.dropped.push(revocation);
    }
}

//------------ CurrentObjectSet ----------------------------------------------

/// This type describes the complete current set of objects for CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSet {
    #[serde(deserialize_with = "ext_serde::de_time", serialize_with = "ext_serde::ser_time")]
    this_update: Time,

    #[serde(deserialize_with = "ext_serde::de_time", serialize_with = "ext_serde::ser_time")]
    next_update: Time,

    number: u64,

    revocations: Revocations,

    objects: CurrentObjects
}

impl Default for CurrentObjectSet {
    fn default() -> Self {
        CurrentObjectSet {
            this_update: Time::now(),
            next_update: Time::tomorrow(),
            number: 1,
            revocations: Revocations::default(),
            objects: CurrentObjects::default()
        }
    }
}

impl CurrentObjectSet {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn revocations(&self) -> &Revocations {
        &self.revocations
    }
    pub fn objects(&self) -> &CurrentObjects {
        &self.objects
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.this_update = delta.this_update;
        self.next_update = delta.next_update;
        self.number = delta.number;
        self.revocations.apply_delta(delta.revocations);
        self.objects.apply_delta(delta.objects)
    }
}


//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationDelta {
    #[serde(deserialize_with = "ext_serde::de_time", serialize_with = "ext_serde::ser_time")]
    this_update: Time,

    #[serde(deserialize_with = "ext_serde::de_time", serialize_with = "ext_serde::ser_time")]
    next_update: Time,

    number: u64, // crl and mft number

    revocations: RevocationsDelta,
    objects: ObjectsDelta
}

impl PublicationDelta {
    pub fn new(
        this_update: Time,
        next_update: Time,
        number: u64,
        revocations: RevocationsDelta,
        objects: ObjectsDelta
    ) -> Self {
        PublicationDelta {
            this_update, next_update, number, revocations, objects
        }
    }

    pub fn objects(&self) -> &ObjectsDelta {
        &self.objects
    }
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectsDelta {
    signed_objects_uri: uri::Rsync,
    added: Vec<AddedObject>,
    updated: Vec<UpdatedObject>,
    withdrawn: Vec<WithdrawnObject>
}

impl ObjectsDelta {
    pub fn new(signed_objects_uri: uri::Rsync) -> Self {
        ObjectsDelta { signed_objects_uri, added: vec![], updated: vec![], withdrawn: vec![]}
    }

    pub fn add(&mut self, added: AddedObject) {
        self.added.push(added);
    }
    pub fn update(&mut self, updated: UpdatedObject) {
        self.updated.push(updated);
    }
    pub fn withdraw(&mut self, withdrawn: WithdrawnObject) {
        self.withdrawn.push(withdrawn);
    }
}

impl Into<publication::PublishDelta> for ObjectsDelta {
    fn into(self) -> publication::PublishDelta {
        let mut builder = publication::PublishDeltaBuilder::new();

        fn resolve(uri: &uri::Rsync, name: &ObjectName) -> uri::Rsync {
            let uri = format!("{}{}", uri.to_string(), name);
            uri::Rsync::from_string(uri).unwrap()
        }

        for a in self.added.into_iter() {
            let publish = publication::Publish::new(
                None, resolve(&self.signed_objects_uri, &a.name), a.object.content
            );
            builder.add_publish(publish);
        }
        for u in self.updated.into_iter() {
            let update = publication::Update::new(
                None, resolve(&self.signed_objects_uri, &u.name), u.object.content, u.old
            );
            builder.add_update(update);
        }
        for w in self.withdrawn.into_iter() {
            let withdraw = publication::Withdraw::new(
                None,
                resolve(&self.signed_objects_uri, &w.name),
                w.hash
            );
            builder.add_withdraw(withdraw);
        }
        builder.finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddedObject {
    name: ObjectName,
    object: CurrentObject
}

impl AddedObject {
    pub fn new(
        name: ObjectName,
        object: CurrentObject
    ) -> Self {
        AddedObject { name, object }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdatedObject {
    name: ObjectName,
    object: CurrentObject,
    old: EncodedHash
}

impl UpdatedObject {
    pub fn new(
        name: ObjectName,
        object: CurrentObject,
        old: EncodedHash
    ) -> Self {
        UpdatedObject { name, object, old }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawnObject {
    name: ObjectName,
    hash: EncodedHash
}

impl WithdrawnObject {
    pub fn new(
        name: ObjectName,
        hash: EncodedHash
    ) -> Self {
        WithdrawnObject { name, hash}
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

    pub fn all_resources() -> Self {
        let asns = "AS0-AS4294967295";
        let v4 = "0.0.0.0/0";
        let v6 = "::/0";
        ResourceSet::from_strs(asns, v4, v6).unwrap()
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

impl From<&Cert> for ResourceSet {
    fn from(cert: &Cert) -> Self {
        let asn = match cert.as_resources() {
            None => AsResources::blocks(AsBlocks::empty()),
            Some(set) => set.clone()
        };

        let v4 = {
            let v4 = match cert.v4_resources() {
                None => IpResources::blocks(IpBlocks::empty()),
                Some(res) => res.clone()
            };
            match v4.to_blocks() {
                Ok(blocks) => Ipv4Resources::blocks(blocks),
                Err(_) => Ipv4Resources::inherit()
            }
        };

        let v6 = {
            let v6 = match cert.v6_resources() {
                None => IpResources::blocks(IpBlocks::empty()),
                Some(res) => res.clone()
            };
            match v6.to_blocks() {
                Ok(blocks) => Ipv6Resources::blocks(blocks),
                Err(_) => Ipv6Resources::inherit()
            }
        };


        ResourceSet { asn, v4, v6 }
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

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
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
        let signed_objects_uri = info().signed_object("");
        assert_eq!(base_uri(), signed_objects_uri)
    }

    #[test]
    fn mft_uri() {
        test::test_with_tmp_dir(|d| {
            let mut signer = OpenSslSigner::build(&d).unwrap();
            let key_id = signer.create_key(PublicKeyFormat::default()).unwrap();
            let pub_key = signer.get_key_info(&key_id).unwrap();

            let mft_uri = info().mft_uri("", &pub_key);

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
