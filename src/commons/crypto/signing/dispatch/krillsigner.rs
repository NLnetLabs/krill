use std::path::Path;

use rpki::repository::{
    cert::TbsCert,
    crl::{CrlEntry, TbsCertList},
    crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError},
    manifest::ManifestContent,
    roa::RoaBuilder,
    rta,
    sigobj::SignedObjectBuilder,
    x509::Serial,
    Cert, Crl, Csr, Manifest, Roa,
};

use crate::commons::{
    api::RepoInfo,
    crypto::{self, dispatch::signerrouter::SignerRouter, CryptoResult, SignerError},
    KrillResult,
};

/// High level signing interface between Krill and the [SignerRouter].
///
/// KrillSigner:
///   - Delegates Signer management and dispatch to [SignerRouter].
///   - Maps Result<SignerError> to KrillResult.
///   - Directs signers to use the RPKI standard key format (RSA).
///   - Directs signers to use the RPKI standard signature algorithm (RSA PKCS #1 v1.5 with SHA-256).
///   - Offers additional high level functions compared to the [Signer] trait.
///
/// We delegate to [SignerRouter] because our interface differs to that of the [Signer] trait and because the code is
/// easier to read if we separate out responsibilities.
///
/// We need dispatch to the correct [Signer] to be done by a Struct that implements the [Signer] trait itself because
/// otherwise functions elsewhere in Krill that take a [Signer] trait as input will not invoke the correct [Signer].
///
/// We _could_ implement the [Signer] trait in [KrillSigner] but then we would implement two almost identical but
/// subtly different interfaces in the same struct AND implement management of signers and dispatch to the correct
/// signer all in one place, and that quickly becomes harder to read, understand and maintain.
#[derive(Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        Ok(KrillSigner {
            router: SignerRouter::build(work_dir)?,
        })
    }

    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        self.router
            .create_key(PublicKeyFormat::Rsa)
            .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        self.router.destroy_key(key_id).map_err(crypto::Error::key_error)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        self.router.get_key_info(key_id).map_err(crypto::Error::key_error)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        Serial::random(&self.router).map_err(crypto::Error::signer)
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, key_id: &KeyIdentifier, data: &D) -> CryptoResult<Signature> {
        self.router
            .sign(key_id, SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> CryptoResult<(Signature, PublicKey)> {
        self.router
            .sign_one_off(SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signer)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Csr> {
        let pub_key = self.router.get_key_info(key).map_err(crypto::Error::key_error)?;
        let enc = Csr::construct(
            &self.router,
            key,
            &base_repo.ca_repository(name_space).join(&[]).unwrap(), // force trailing slash
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(crypto::Error::signing)?;
        Ok(Csr::decode(enc.as_slice())?)
    }

    pub async fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        //tbs.into_cert(&self.router, key_id).map_err(crypto::Error::signing)
        self.router
            .sign_with_key(key_id, tbs.sign())
            .await
            .map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        // TODO: Update to use self.router.sign_with_key() once Crl has been extended with Sign and SignWithKey support
        tbs.into_crl(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        content
            .into_manifest(builder, &self.router, key_id)
            .map_err(crypto::Error::signing)

        // TODO: Revisit this code once we have a way to do SignedObjectBuilder::finalize() without passing a Signer
        // or can reproduce what finalize() does without needing access to its internal private fields, in particular
        // SignedAttrs::new() is currently private and thus inaccessible and does a lot of work rather than being an
        // easily replicated dumb factory function.
        // use crate::bcder::encode::Values;
        // use bcder::{Mode, OctetString, Oid};
        // use bytes::Bytes;
        // use rpki::repository::{
        //     cert::{KeyUsage, Overclaim},
        //     oid,
        //     sigobj::{SignedAttrs, SignedObject},
        // };

        // fn into_manifest(
        //     mut sigobj: SignedObjectBuilder,
        //     content: ManifestContent,
        //     signer: &SignerRouter,
        //     issuer_key: &KeyIdentifier,
        // ) -> Result<Manifest, SigningError<SignerError>> {
        //     sigobj.set_v4_resources_inherit();
        //     sigobj.set_v6_resources_inherit();
        //     sigobj.set_as_resources_inherit();
        //     let signed = sigobj_finalize(
        //         sigobj,
        //         Oid(oid::CT_RPKI_MANIFEST.0.into()),
        //         content.encode_ref().to_captured(Mode::Der).into_bytes(),
        //         signer,
        //         issuer_key,
        //     )?;
        //     Ok(Manifest { signed, content })
        // }

        // fn sigobj_finalize(
        //     sigobj: SignedObjectBuilder,
        //     content_type: Oid<Bytes>,
        //     content: Bytes,
        //     signer: &SignerRouter,
        //     issuer_key: &KeyIdentifier,
        // ) -> Result<SignedObject, SigningError<SignerError>> {
        //     let issuer_pub = signer.get_key_info(issuer_key)?;

        //     // Produce signed attributes.
        //     let message_digest = sigobj.digest_algorithm().digest(&content).into();
        //     let signed_attrs = SignedAttrs::new(
        //         &content_type,
        //         &message_digest,
        //         sigobj.signing_time(),
        //         sigobj.binary_signing_time(),
        //     );

        //     // Sign signed attributes with a one-off key.
        //     let (signature, key_info) =
        //         signer.sign_one_off(SignatureAlgorithm::default(), &signed_attrs.encode_verify())?;
        //     let sid = KeyIdentifier::from_public_key(&key_info);

        //     // Make the certificate.
        //     let mut cert = TbsCert::new(
        //         sigobj.serial_number,
        //         sigobj.issuer.unwrap_or_else(|| issuer_pub.to_subject_name()),
        //         sigobj.validity,
        //         sigobj.subject,
        //         key_info,
        //         KeyUsage::Ee,
        //         Overclaim::Refuse,
        //     );
        //     cert.set_authority_key_identifier(Some(issuer_pub.key_identifier()));
        //     cert.set_crl_uri(Some(sigobj.crl_uri));
        //     cert.set_ca_issuer(Some(sigobj.ca_issuer));
        //     cert.set_signed_object(Some(sigobj.signed_object));
        //     cert.set_v4_resources(sigobj.v4_resources);
        //     cert.set_v6_resources(sigobj.v6_resources);
        //     cert.set_as_resources(sigobj.as_resources);
        //     let cert = cert.into_cert(signer, issuer_key)?;

        //     Ok(SignedObject {
        //         digest_algorithm: sigobj.digest_algorithm,
        //         content_type,
        //         content: OctetString::new(content),
        //         cert,
        //         sid,
        //         signed_attrs,
        //         signature,
        //         message_digest,
        //         signing_time: sigobj.signing_time,
        //         binary_signing_time: sigobj.binary_signing_time,
        //     })
        // }

        // into_manifest(builder, content, key_id, &self.router).map_err(crypto::Error::signing)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        roa_builder
            .finalize(object_builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        rta_builder
            .sign(&self.router, &key, None, None)
            .map_err(crypto::Error::signing)
    }
}
