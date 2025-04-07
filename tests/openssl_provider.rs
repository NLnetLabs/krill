use std::{ops::Deref, panic};

#[test]
fn openssl_provider() {
    // panic::catch_unwind(|| {
        // let res = openssl::provider::Provider::try_load(None, "tpm2", false).unwrap();
        // let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        // let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        // let pub_key = pkey.public_key_to_pem().unwrap();
        // dbg!(&pub_key);
        // let _ = openssl::provider::Provider::deref(&res);
    // }).unwrap_err();
}