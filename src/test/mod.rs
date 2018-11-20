use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use rpki::oob::exchange::PublisherRequest;
use rpki::uri;
use rpki::remote::idcert::IdCert;
use rpki::signing::builder::IdCertBuilder;
use rpki::signing::signer::Signer;
use rpki::signing::softsigner::OpenSslSigner;
use rpki::signing::PublicKeyAlgorithm;

pub fn test_with_tmp_dir<F>(op: F) where F: FnOnce(PathBuf) -> () {
    use std::fs;
    use std::path::PathBuf;

    let dir = create_sub_dir(&PathBuf::from("work"));
    let path = PathBuf::from(&dir);

    op(dir);

    fs::remove_dir_all(path).unwrap();
}

pub fn create_sub_dir(base_dir: &PathBuf) -> PathBuf {
    use std::fs;
    use std::path::PathBuf;
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let rnd: u32 = rng.gen();

    let mut dir = base_dir.clone();
    dir.push(PathBuf::from(format!("{}", rnd)));

    let full_path = PathBuf::from(&dir);
    fs::create_dir(&full_path).unwrap();

    full_path
}

pub fn rsync_uri(s: &str) -> uri::Rsync {
    uri::Rsync::from_str(s).unwrap()
}

pub fn http_uri(s: &str) -> uri::Http {
    uri::Http::from_str(s).unwrap()
}

pub fn new_id_cert() -> IdCert {
    let mut s = OpenSslSigner::new();
    let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
    IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
}

pub fn new_publisher_request(publisher_handle: &str) -> PublisherRequest {
    let id_cert = new_id_cert();
    PublisherRequest::new(
        None,
        publisher_handle,
        id_cert
    )
}

pub fn save_file(base_dir: &PathBuf, file_name: &str, content: &[u8]) {
    let mut full_name = base_dir.clone();
    full_name.push(PathBuf::from(file_name));
    let mut f = File::create(full_name).unwrap();
    f.write(content).unwrap();
}