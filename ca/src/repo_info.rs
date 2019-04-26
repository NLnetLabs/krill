//! Support for repository related matters for Certificate Authorities.

use rpki::uri;

use krill_commons::util::ext_serde;
use rpki::crypto::PublicKey;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoInfo {
    #[serde(
        deserialize_with = "ext_serde::de_rsync_uri",
        serialize_with = "ext_serde::ser_rsync_uri")]
    base_uri: uri::Rsync,

    #[serde(
        deserialize_with = "ext_serde::de_http_uri",
        serialize_with = "ext_serde::ser_http_uri")]
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

//============ Tests =========================================================

#[cfg(test)]
mod test {

    use super::*;
    use krill_commons::util::test;
    use krill_commons::util::softsigner::OpenSslSigner;
    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;

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
            let key_id = signer.create_key(PublicKeyFormat).unwrap();
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

}

