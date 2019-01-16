//! Some helper stuff for creating a private key and certificate for HTTPS
//! in case they are not provided

use std::io::Write;
use std::fs::File;
use std::path::PathBuf;
use bytes::Bytes;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use crate::remote::builder::IdCertBuilder;
use crate::util::file;
use rpki::crypto::Signer;
use rpki::crypto::PublicKeyFormat;
use rpki::crypto::PublicKey;
use rpki::crypto::SignatureAlgorithm;
use rpki::crypto::Signature;
use rpki::crypto::SigningError;
use util::softsigner::SignerKeyId;
use remote::builder;
use rpki::crypto::signer::KeyError;
use bcder::decode;

const KEY_SIZE: u32 = 2048;
pub const HTTPS_SUB_DIR: &'static str = "ssl";
pub const KEY_FILE: &'static str = "key.pem";
pub const CERT_FILE: &'static str = "cert.pem";

/// Creates a new private key and certificate file if either is found to be
/// missing in the base_path directory.
pub fn create_key_cert_if_needed(data_dir: &PathBuf) -> Result<(), HttpsSignerError> {
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
fn create_key_and_cert(https_dir: PathBuf) -> Result<(), HttpsSignerError> {
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
    fn new() -> Result<Self, HttpsSignerError> {
        let rsa = Rsa::generate(KEY_SIZE)?;
        let private = PKey::from_rsa(rsa)?;
        Ok(HttpsSigner { private })
    }

    fn save_private_key(&self, https_dir: &PathBuf) -> Result<(), HttpsSignerError> {
        let path =file::file_path(https_dir, KEY_FILE);
        let mut pem_file = File::create(path)?;

        let pem = self.private.private_key_to_pem_pkcs8()?;
        pem_file.write(&pem)?;
        Ok(())
    }

    fn save_certificate(&mut self, https_dir: &PathBuf) -> Result<(), HttpsSignerError> {
        let path = file::file_path(https_dir, CERT_FILE);
        let mut pem_file = File::create(path)?;

        let key_id = SignerKeyId::new("n/a");
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

    type KeyId = SignerKeyId;
    type Error = HttpsSignerError;


    /// Not implemented. This type only ever has one key.
    fn create_key(
        &mut self,
        _algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {
        unimplemented!()
    }

    /// Returns the SubjectPublicKeyInfo for the one and only key for this
    /// type.
    fn get_key_info(
        &self,
        _id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        let mut b = Bytes::from(
            self.private.rsa().unwrap().public_key_to_der()
                .map_err(|e| { KeyError::Signer(HttpsSignerError::OpenSslError(e))})?
        );
        let pk = PublicKey::decode(&mut b)
            .map_err(|e| { KeyError::Signer(HttpsSignerError::DecodeError(e))})?;
        Ok(pk)
    }

    /// Not implemented. People can just delete / replace the files on disk.
    fn destroy_key(
        &mut self,
        _id: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        unimplemented!()
    }

    /// Used when the self-signed certificate is made for the HTTPS server.
    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        _key: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SigningError<Self::Error>> {

        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            &self.private
        ).map_err(|e| { SigningError::from(HttpsSignerError::OpenSslError(e))})?;
        signer.update(data.as_ref())
            .map_err(|e| { SigningError::from(HttpsSignerError::OpenSslError(e))})?;

        let signature_bytes = signer.sign_to_vec()
            .map_err(|e| { SigningError::Signer(
                HttpsSignerError::OpenSslError(e))})?;

        let signature = Signature::new(
            SignatureAlgorithm,
            Bytes::from(signature_bytes)
        );
        Ok(signature)
    }

    /// Not implemented. We won't sign CMS with this.
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        _data: &D
    ) -> Result<(Signature, PublicKey), Self::Error> {
        unimplemented!()
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum HttpsSignerError {
    #[display(fmt = "{}", _0)]
    IoError(std::io::Error),

    #[display(fmt = "{}", _0)]
    OpenSslError(openssl::error::ErrorStack),

    #[display(fmt = "{}", _0)]
    DecodeError(decode::Error),

    #[display(fmt="Could not make certificate")]
    BuildError
}

impl From<openssl::error::ErrorStack> for HttpsSignerError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        HttpsSignerError::OpenSslError(e)
    }
}

impl From<std::io::Error> for HttpsSignerError {
    fn from(e: std::io::Error) -> Self {
        HttpsSignerError::IoError(e)
    }
}

impl From<builder::Error<HttpsSignerError>> for HttpsSignerError {
    fn from(_: builder::Error<HttpsSignerError>) -> Self {
        HttpsSignerError::BuildError
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