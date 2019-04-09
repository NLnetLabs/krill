//! Some helper stuff for creating a private key and certificate for HTTPS
//! in case they are not provided

use std::io::Write;
use std::fs::File;
use std::path::PathBuf;
use bcder::BitString;
use bcder::Mode;
use bcder::Tag;
use bcder::decode;
use bcder::encode;
use bcder::encode::Constructed;
use bcder::encode::Values;
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use rpki::x509::Name;
use rpki::cert::Validity;
use rpki::cert::ext::BasicCa;
use rpki::cert::ext::SubjectKeyIdentifier;
use rpki::cert::ext::AuthorityKeyIdentifier;
use rpki::crypto::Signature;
use rpki::crypto::PublicKey;
use rpki::crypto::SignatureAlgorithm;
use krill_commons::util::file;


const KEY_SIZE: u32 = 2048;
pub const HTTPS_SUB_DIR: &str = "ssl";
pub const KEY_FILE: &str = "key.pem";
pub const CERT_FILE: &str = "cert.pem";

/// Creates a new private key and certificate file if either is found to be
/// missing in the base_path directory.
pub fn create_key_cert_if_needed(data_dir: &PathBuf) -> Result<(), Error> {
    let mut https_dir = data_dir.clone();
    https_dir.push(HTTPS_SUB_DIR);

    let key_file_path = file::file_path(&https_dir, KEY_FILE);
    let cert_file_path = file::file_path(&https_dir, CERT_FILE);

    if ! key_file_path.exists() || ! cert_file_path.exists() {
        create_key_and_cert(&https_dir)
    } else {
        Ok(())
    }
}

/// Creates a new private key and certificate to be used when serving HTTPS.
/// Only call this in case there is no current key and certificate file
/// present, or have your files ruthlessly overwritten!
fn create_key_and_cert(https_dir: &PathBuf) -> Result<(), Error> {
    if ! https_dir.exists() {
        file::create_dir(&https_dir)?;
    }

    let mut signer = HttpsSigner::build()?;
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
    fn build() -> Result<Self, Error> {
        let rsa = Rsa::generate(KEY_SIZE)?;
        let private = PKey::from_rsa(rsa)?;
        Ok(HttpsSigner { private })
    }

    /// Saves the private key in PEM format so that actix can use it.
    fn save_private_key(&self, https_dir: &PathBuf) -> Result<(), Error> {
        let path = file::file_path(https_dir, KEY_FILE);
        let mut pkey_file = File::create(path)?;

        let pem = self.private.private_key_to_pem_pkcs8()?;
        pkey_file.write_all(&pem)?;
        Ok(())
    }

    fn public_key_info(&self) -> Result<PublicKey, Error> {
        let mut b = Bytes::from(
            self.private.rsa().unwrap().public_key_to_der()
                .map_err(|e| { Error::OpenSslError(e) })?
        );
        let pk = PublicKey::decode(&mut b)
            .map_err(|e| { Error::DecodeError(e)})?;
        Ok(pk)
    }

    fn sign(&self, data: &Bytes) -> Result<Signature, Error> {

        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            &self.private
        )?;

        signer.update(data.as_ref())?;

        let signature_bytes = signer.sign_to_vec()?;

        let signature = Signature::new(
            SignatureAlgorithm,
            Bytes::from(signature_bytes)
        );
        Ok(signature)
    }

    /// Saves a self-signed certificate so that actix can use it.
    fn save_certificate(&mut self, https_dir: &PathBuf) -> Result<(), Error> {

        let pub_key = self.public_key_info()?;
        let tbs_cert = TbsHttpsCertificate::from(&pub_key);

        let encoded_tbs = tbs_cert.encode().to_captured(Mode::Der);
        let (_, signature) = self.sign(encoded_tbs.as_ref())?.unwrap();

        let signature = BitString::new(
            0,
            signature
        );

        let encoded_cert = encode::sequence(
            (
                encoded_tbs,
                SignatureAlgorithm.x509_encode(),
                signature.encode()
            )
        ).to_captured(Mode::Der);

        let cert_pem = base64::encode(&encoded_cert);

        let path = file::file_path(https_dir, CERT_FILE);
        let mut pem_file = File::create(path)?;

        pem_file.write_all("-----BEGIN CERTIFICATE-----\n".as_ref())?;
        pem_file.write_all(cert_pem.as_bytes())?;
        pem_file.write_all("\n-----END CERTIFICATE-----\n".as_ref())?;

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
    extensions: HttpsCertExtensions
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
        let extensions = HttpsCertExtensions::from(pk);

        TbsHttpsCertificate {
            issuer, validity, subject, subject_public_key_info, extensions
        }
    }
}

impl TbsHttpsCertificate {
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {

        encode::sequence((
            (
                Constructed::new(
                    Tag::CTX_0,
                    2_i32.encode() // Version 3 is encoded as 2
                ),
                1_i32.encode(),
                SignatureAlgorithm.x509_encode(),
                self.issuer.encode()
            ),
            (
                self.validity.encode(),
                self.subject.encode(),
                self.subject_public_key_info.clone().encode(),
                self.extensions.encode()
            )
        ))
    }
}


//------------ IdExtensions --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsCertExtensions {
    /// Basic Constraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: BasicCa,

    /// Subject Key Identifier.
    subject_key_id: SubjectKeyIdentifier,

    /// Authority Key Identifier
    authority_key_id: AuthorityKeyIdentifier,
}

impl From<&PublicKey> for HttpsCertExtensions {
    fn from(pk: &PublicKey) -> Self {
        let basic_ca = BasicCa::new(true, true);
        let subject_key_id = SubjectKeyIdentifier::new(pk);
        let authority_key_id = AuthorityKeyIdentifier::new(pk);

        HttpsCertExtensions {
            basic_ca, subject_key_id, authority_key_id
        }
    }
}

/// # Encoding
impl HttpsCertExtensions {

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        Constructed::new(
            Tag::CTX_3,
            encode::sequence(
                (
                    self.basic_ca.encode(),
                    self.subject_key_id.clone().encode(),
                    self.authority_key_id.clone().encode()
                )
            )
        )
    }

}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(std::io::Error),

    #[display(fmt = "{}", _0)]
    OpenSslError(openssl::error::ErrorStack),

    #[display(fmt = "{}", _0)]
    DecodeError(decode::Error),

    #[display(fmt="Could not make certificate")]
    BuildError
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

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use actix_web::*;
    use actix_web::server::HttpServer;
    use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
    use krill_commons::util::test;

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