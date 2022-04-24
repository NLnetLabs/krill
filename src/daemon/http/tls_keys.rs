//! Some helper stuff for creating a private key and certificate for HTTPS
//! in case they are not provided
use std::{fmt, path::Path, path::PathBuf};

use bytes::Bytes;

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
};

use bcder::{
    decode,
    encode::{self, Constructed, PrimitiveContent, Values},
    BitString, Mode, Tag,
};

use rpki::{
    ca::idcert::IdCert,
    repository::{
        crypto::{KeyIdentifier, PublicKey, Signature, SignatureAlgorithm},
        x509::{Name, Time, Validity},
    },
};

use crate::commons::{api::IdCertPem, error::KrillIoError, util::file};

const KEY_SIZE: u32 = 2048;
pub const HTTPS_SUB_DIR: &str = "ssl";
pub const KEY_FILE: &str = "key.pem";
pub const CERT_FILE: &str = "cert.pem";

pub fn key_file_path(data_dir: &Path) -> PathBuf {
    let mut https_dir = data_dir.to_path_buf();
    https_dir.push(HTTPS_SUB_DIR);
    file::file_path(&https_dir, KEY_FILE)
}

pub fn cert_file_path(data_dir: &Path) -> PathBuf {
    let mut https_dir = data_dir.to_path_buf();
    https_dir.push(HTTPS_SUB_DIR);
    file::file_path(&https_dir, CERT_FILE)
}

/// Creates a new private key and certificate file if either is found to be
/// missing in the base_path directory.
pub fn create_key_cert_if_needed(data_dir: &Path) -> Result<(), Error> {
    let key_file_path = key_file_path(data_dir);
    let cert_file_path = cert_file_path(data_dir);

    if !key_file_path.exists() || !cert_file_path.exists() {
        create_key_and_cert(data_dir)
    } else {
        Ok(())
    }
}

/// Creates a new private key and certificate to be used when serving HTTPS.
/// Only call this in case there is no current key and certificate file
/// present, or have your files ruthlessly overwritten!
fn create_key_and_cert(data_dir: &Path) -> Result<(), Error> {
    let mut signer = HttpsSigner::build()?;
    signer.save_private_key(data_dir)?;
    signer.save_certificate(data_dir)?;

    Ok(())
}

//------------ HttpsSigner ---------------------------------------------------

/// Signer specifically for generating an HTTPS key pair and certificate, and
/// saving them both as PEM files in a directory.
struct HttpsSigner {
    private: PKey<Private>,
}

impl rpki::repository::crypto::Signer for HttpsSigner {
    type KeyId = KeyIdentifier;
    type Error = Error;

    fn create_key(&self, algorithm: rpki::repository::crypto::PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        unimplemented!("not needed in this context")
    }

    fn get_key_info(
        &self,
        _key: &Self::KeyId,
    ) -> Result<PublicKey, rpki::repository::crypto::signer::KeyError<Self::Error>> {
        self.public_key_info()
            .map_err(rpki::repository::crypto::signer::KeyError::Signer)
    }

    fn destroy_key(&self, key: &Self::KeyId) -> Result<(), rpki::repository::crypto::signer::KeyError<Self::Error>> {
        unimplemented!("not needed in this context")
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        _key: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, rpki::repository::crypto::SigningError<Self::Error>> {
        self.sign(data).map_err(rpki::repository::crypto::SigningError::Signer)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        unimplemented!("not needed in this context")
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        unimplemented!("not needed in this context")
    }
}

impl HttpsSigner {
    fn build() -> Result<Self, Error> {
        let rsa = Rsa::generate(KEY_SIZE)?;
        let private = PKey::from_rsa(rsa)?;
        Ok(HttpsSigner { private })
    }

    /// Saves the private key in PEM format so that hyper can use it.
    fn save_private_key(&self, data_dir: &Path) -> Result<(), Error> {
        let key_file_path = key_file_path(data_dir);
        let bytes = Bytes::from(self.private.private_key_to_pem_pkcs8()?);
        file::save(&bytes, &key_file_path)?;
        Ok(())
    }

    fn public_key_info(&self) -> Result<PublicKey, Error> {
        let mut b = Bytes::from(
            self.private
                .rsa()
                .unwrap()
                .public_key_to_der()
                .map_err(Error::OpenSslError)?,
        );
        let pk = PublicKey::decode(&mut b).map_err(Error::DecodeError)?;
        Ok(pk)
    }

    // See OpenSslSigner::sign_with_key for reference.
    fn sign<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> Result<Signature, Error> {
        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), &self.private)?;
        signer.update(data.as_ref())?;

        let signature = Signature::new(SignatureAlgorithm::default(), Bytes::from(signer.sign_to_vec()?));
        Ok(signature)
    }

    /// Saves a self-signed certificate so that hyper can use it.
    fn save_certificate(&mut self, data_dir: &Path) -> Result<(), Error> {
        let validity = Validity::new(Time::five_minutes_ago(), Time::years_from_now(100));
        let pub_key = self.public_key_info()?;

        let id_cert = IdCert::new_ta(validity, &pub_key.key_identifier(), self).map_err(Error::signer)?;
        let id_cert_pem = IdCertPem::from(&id_cert);

        let path = cert_file_path(data_dir);

        file::save(id_cert_pem.pem().as_bytes(), &path)?;

        Ok(())
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    IoError(KrillIoError),
    OpenSslError(openssl::error::ErrorStack),
    DecodeError(decode::Error),
    BuildError,
    EmptyCertStack,
    Pkcs12(String),
    Connection(String),
    SignerError(String),
}

impl Error {
    pub fn signer(e: impl fmt::Display) -> Self {
        Error::SignerError(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(e) => e.fmt(f),
            Error::OpenSslError(e) => e.fmt(f),
            Error::DecodeError(e) => e.fmt(f),
            Error::BuildError => write!(f, "Could not make certificate"),
            Error::EmptyCertStack => write!(f, "Certificate PEM file contains no certificates"),
            Error::Pkcs12(e) => write!(f, "Cannot create PKCS12 Identity: {}", e),
            Error::Connection(e) => write!(f, "Connection error: {}", e),
            Error::SignerError(e) => write!(f, "Error signing self-signed HTTPS certificate: {}", e),
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSslError(e)
    }
}

impl From<KrillIoError> for Error {
    fn from(e: KrillIoError) -> Self {
        Error::IoError(e)
    }
}

impl std::error::Error for Error {}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::test;

    use super::*;

    #[test]
    fn should_create_key_and_cert() {
        test::test_under_tmp(|d| {
            create_key_cert_if_needed(&d).unwrap();
        });
    }
}
