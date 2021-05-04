//! Some helper stuff for creating a private key and certificate for HTTPS
//! in case they are not provided
use std::path::PathBuf;
use std::{fmt, path::Path};

use bytes::Bytes;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;

use bcder::encode::{Constructed, PrimitiveContent, Values};
use bcder::{decode, encode};
use bcder::{BitString, Mode, Tag};

use rpki::crypto::{PublicKey, Signature, SignatureAlgorithm};
use rpki::x509::{Name, Validity};

use crate::commons::util::file;
use crate::commons::{crypto::IdExtensions, error::KrillIoError};

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

    fn sign(&self, data: &Bytes) -> Result<Signature, Error> {
        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), &self.private)?;

        signer.update(data.as_ref())?;

        let signature_bytes = signer.sign_to_vec()?;

        let signature = Signature::new(SignatureAlgorithm::default(), Bytes::from(signature_bytes));
        Ok(signature)
    }

    /// Saves a self-signed certificate so that hyper can use it.
    fn save_certificate(&mut self, data_dir: &Path) -> Result<(), Error> {
        let pub_key = self.public_key_info()?;
        let tbs_cert = TbsHttpsCertificate::from(&pub_key);

        let encoded_tbs = tbs_cert.encode().to_captured(Mode::Der);
        let (_, signature) = self.sign(encoded_tbs.as_ref())?.unwrap();

        let signature = BitString::new(0, signature);

        let encoded_cert = encode::sequence((
            encoded_tbs,
            SignatureAlgorithm::default().x509_encode(),
            signature.encode(),
        ))
        .to_captured(Mode::Der);

        let cert_pem = base64::encode(&encoded_cert);

        let path = cert_file_path(data_dir);
        let pem_file = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert_pem);
        let bytes: Bytes = Bytes::from(pem_file);
        file::save(&bytes, &path)?;

        Ok(())
    }
}

struct TbsHttpsCertificate {
    // The General structure is documented in section 4.1 or RFC5280
    //
    //    TBSCertificate  ::=  SEQUENCE  {
    //        version         [0]  EXPLICIT Version DEFAULT v1,
    //        serialNumber         CertificateSerialNumber,
    //        signature            AlgorithmIdentifier,
    //        issuer               Name,
    //        validity             Validity,
    //        subject              Name,
    //        subjectPublicKeyInfo SubjectPublicKeyInfo,
    //        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        extensions      [3]  EXPLICIT Extensions OPTIONAL
    //                             -- If present, version MUST be v3
    //        }

    // version is always 3
    // serial_number is always 1
    // signature is always Sha256WithRsaEncryption
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: PublicKey,
    // issuerUniqueID is not used
    // subjectUniqueID is not used
    extensions: IdExtensions,
}

impl From<&PublicKey> for TbsHttpsCertificate {
    fn from(pk: &PublicKey) -> Self {
        let issuer = Name::from_pub_key(pk);
        let validity = {
            let dur = ::chrono::Duration::weeks(52000);
            Validity::from_duration(dur)
        };
        let subject = issuer.clone();
        let subject_public_key_info = pk.clone();
        let extensions = IdExtensions::from(pk);

        TbsHttpsCertificate {
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
        }
    }
}

impl TbsHttpsCertificate {
    #[allow(clippy::needless_lifetimes)]
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            (
                Constructed::new(
                    Tag::CTX_0,
                    2_i32.encode(), // Version 3 is encoded as 2
                ),
                1_i32.encode(),
                SignatureAlgorithm::default().x509_encode(),
                self.issuer.encode_ref(),
            ),
            (
                self.validity.encode(),
                self.subject.encode_ref(),
                self.subject_public_key_info.clone().encode(),
                self.extensions.encode(),
            ),
        ))
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
