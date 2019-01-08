//! Some helper stuff for creating a private key and certificate for HTTPS
//! in case they are not provided

use std::io::Write;
use std::fs::File;
use std::path::PathBuf;
use bytes::Bytes;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use rpki::cert::SubjectPublicKeyInfo;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::signer::{
    CreateKeyError,
    KeyId,
    KeyUseError,
    OneOffSignature,
    Signature,
    Signer};
use crate::remote::builder::IdCertBuilder;
use crate::util::file;

const KEY_SIZE: u32 = 2048;
pub const HTTPS_SUB_DIR: &'static str = "ssl";
pub const KEY_FILE: &'static str = "key.pem";
pub const CERT_FILE: &'static str = "cert.pem";

/// Creates a new private key and certificate file if either is found to be
/// missing in the base_path directory.
pub fn create_key_cert_if_needed(data_dir: &PathBuf) -> Result<(), Error> {
    let mut https_dir = data_dir.clone();
    https_dir.push(HTTPS_SUB_DIR);

    let key_file_path = file::file_path(&https_dir, KEY_FILE);
    let cert_file_path = file::file_path(&https_dir, CERT_FILE);

    if ! key_file_path.exists() || ! cert_file_path.exists() {
        create_key_and_cert(https_dir)
    } else {
        Ok(())
    }
}

/// Creates a new private key and certificate to be used when serving HTTPS.
/// Only call this in case there is no current key and certificate file
/// present, or have your files ruthlessly overwritten!
fn create_key_and_cert(https_dir: PathBuf) -> Result<(), Error> {
    if ! https_dir.exists() {
        file::create_dir(&https_dir)?;
    }

    let mut signer = HttpsSigner::new()?;
    signer.save_private_key(&https_dir)?;
    signer.save_certificate(&https_dir)?;

    Ok(())
}


//------------ HttpsSigner ---------------------------------------------------

/// Signer specifically for generating an HTTPS key pair and certificate, and
/// saving them both as PEM files in a directory.
struct HttpsSigner {
    private: PKey<Private>
}

impl HttpsSigner {
    fn new() -> Result<Self, Error> {
        let rsa = Rsa::generate(KEY_SIZE)?;
        let private = PKey::from_rsa(rsa)?;
        Ok(HttpsSigner { private })
    }

    fn save_private_key(&self, https_dir: &PathBuf) -> Result<(), Error> {
        let path =file::file_path(https_dir, KEY_FILE);
        let mut pem_file = File::create(path)?;

        let pem = self.private.private_key_to_pem_pkcs8()?;
        pem_file.write(&pem)?;
        Ok(())
    }

    fn save_certificate(&mut self, https_dir: &PathBuf) -> Result<(), Error> {
        let path = file::file_path(https_dir, CERT_FILE);
        let mut pem_file = File::create(path)?;

        let key_id = KeyId::new("n/a".to_string());
        let cert = IdCertBuilder::new_ta_id_cert(&key_id, self)?;

        let der = cert.to_bytes();
        let cert_pem = base64::encode(&der);

        pem_file.write("-----BEGIN CERTIFICATE-----\n".as_ref())?;
        pem_file.write(cert_pem.as_bytes())?;
        pem_file.write("\n-----END CERTIFICATE-----\n".as_ref())?;

        Ok(())
    }
}

impl Signer for HttpsSigner {
    /// Not implemented. This type only ever has one key.
    fn create_key(
        &mut self,
        _algorithm: &PublicKeyAlgorithm
    ) -> Result<KeyId, CreateKeyError> {
        unimplemented!()
    }

    /// Returns the SubjectPublicKeyInfo for the one and only key for this
    /// type.
    fn get_key_info(
        &self,
        _id: &KeyId
    ) -> Result<SubjectPublicKeyInfo, KeyUseError> {
        let mut b = Bytes::from(self.private.rsa().unwrap().public_key_to_der()?);
        Ok(SubjectPublicKeyInfo::decode(&mut b)?)
    }

    /// Not implemented. People can just delete / replace the files on disk.
    fn destroy_key(&mut self, _id: &KeyId) -> Result<(), KeyUseError> {
        unimplemented!()
    }

    /// Used when the self-signed certificate is made for the HTTPS server.
    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        _id: &KeyId,
        data: &D
    ) -> Result<Signature, KeyUseError> {

        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            &self.private
        )?;
        signer.update(data.as_ref())?;

        Ok(Signature::new(Bytes::from(signer.sign_to_vec()?)))
    }

    /// Not implemented. We won't sign CMS with this.
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _data: &D
    ) -> Result<OneOffSignature, KeyUseError> {
        unimplemented!()
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "IO error: {}", _0)]
    IoError(std::io::Error),

    #[fail(display = "Key Use Error: {:?}", _0)]
    KeyUseError(KeyUseError),

    #[fail(display = "OpenSSL error: {}", _0)]
    OpenSslError(openssl::error::ErrorStack),

}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSslError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<KeyUseError> for Error {
    fn from(e: KeyUseError) -> Self {
        Error::KeyUseError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use actix_web::*;
    use actix_web::server::HttpServer;
    use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
    use crate::util::test;

    #[test]
    fn should_create_key_and_cert_and_start_server() {
        test::test_with_tmp_dir(|d| {

            let mut p_key_file_path = d.clone();
            p_key_file_path.push("ssl");
            p_key_file_path.push("key.pem");

            let mut cert_file_path = d.clone();
            cert_file_path.push("ssl");
            cert_file_path.push("cert.pem");

            create_key_cert_if_needed(&d).unwrap();

            let mut builder = SslAcceptor::mozilla_intermediate(
                SslMethod::tls()
            ).unwrap();

            builder.set_private_key_file(
                p_key_file_path,
                SslFiletype::PEM
            ).unwrap();

            builder.set_certificate_chain_file(cert_file_path).unwrap();

            HttpServer::new(|| {App::new()})
                .bind_ssl("127.0.0.1:8443", builder)
                .unwrap();
        });
    }

}