// Note: suppressing unused imports here, because this is only used with
// #[cfg(test)]
#[allow(unused_imports)] use rpki::oob::exchange::PublisherRequest;
#[allow(unused_imports)] use rpki::uri;
#[allow(unused_imports)] use rpki::remote::idcert::IdCert;
#[allow(unused_imports)] use rpki::signing::builder::IdCertBuilder;
#[allow(unused_imports)] use rpki::signing::signer::Signer;
#[allow(unused_imports)] use rpki::signing::softsigner::OpenSslSigner;
#[allow(unused_imports)] use rpki::signing::PublicKeyAlgorithm;

#[cfg(test)]
pub fn test_with_tmp_dir<F>(op: F) where F: FnOnce(String) -> () {
    use std::fs;
    use std::path::PathBuf;

    let dir = create_sub_dir("work");
    let path = PathBuf::from(&dir);

    op(dir);

    fs::remove_dir_all(path).unwrap();
}

#[cfg(test)]
pub fn create_sub_dir(base_dir: &str) -> String {
    use std::fs;
    use std::path::PathBuf;
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let r: u32 = rng.gen();

    let dir = format!("{}/{}", base_dir, r);

    let full_path = PathBuf::from(&dir);
    fs::create_dir(&full_path).unwrap();

    dir
}

#[cfg(test)]
pub fn rsync_uri(s: &str) -> uri::Rsync {
    uri::Rsync::from_str(s).unwrap()
}

#[cfg(test)]
pub fn new_id_cert() -> IdCert {
    let mut s = OpenSslSigner::new();
    let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
    IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
}

#[cfg(test)]
pub fn new_publisher_request(publisher_handle: &str) -> PublisherRequest {
    let id_cert = new_id_cert();
    PublisherRequest::new(
        None,
        publisher_handle,
        id_cert
    )
}