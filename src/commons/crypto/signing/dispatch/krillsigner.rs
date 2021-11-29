use std::{path::Path, sync::Arc};

use rpki::repository::{
    aspa::{Aspa, AspaBuilder},
    cert::TbsCert,
    crl::{CrlEntry, TbsCertList},
    crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer},
    manifest::ManifestContent,
    roa::RoaBuilder,
    rta,
    sigobj::SignedObjectBuilder,
    x509::Serial,
    Cert, Crl, Csr, Manifest, Roa,
};

use crate::{
    commons::{
        api::RepoInfo,
        crypto::{
            self,
            dispatch::{
                signerinfo::SignerMapper,
                signerprovider::{SignerFlags, SignerProvider},
                signerrouter::SignerRouter,
            },
            CryptoResult, OpenSslSigner,
        },
        error::Error,
        KrillResult,
    },
    daemon::config::{SignerConfig, SignerType},
};

#[cfg(feature = "hsm")]
use crate::commons::crypto::signers::{kmip::KmipSigner, pkcs11::Pkcs11Signer};

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

type SignerBuilderFn =
    fn(&SignerType, SignerFlags, &Path, &str, &Option<Arc<SignerMapper>>) -> KrillResult<SignerProvider>;

#[derive(Debug)]
pub struct KrillSignerBuilder<'a> {
    work_dir: &'a Path,
    signer_configs: &'a [SignerConfig],
    default_signer: Option<&'a SignerConfig>,
    one_off_signer: Option<&'a SignerConfig>,
}

impl<'a> KrillSignerBuilder<'a> {
    pub fn new(work_dir: &'a Path, signer_configs: &'a [SignerConfig]) -> Self {
        Self {
            work_dir,
            signer_configs,
            default_signer: None,
            one_off_signer: None,
        }
    }

    pub fn with_default_signer(&'a mut self, signer_config: &'a SignerConfig) -> &'a mut Self {
        self.default_signer = Some(signer_config);
        self
    }

    pub fn with_one_off_signer(&'a mut self, signer_config: &'a SignerConfig) -> &'a mut Self {
        self.one_off_signer = Some(signer_config);
        self
    }

    pub fn build(&'a mut self) -> KrillResult<KrillSigner> {
        if self.signer_configs.is_empty() {
            return Err(Error::ConfigError("At least one signer must be defined".to_string()));
        }

        if self.signer_configs.len() == 1 {
            if self.default_signer.is_none() {
                self.default_signer = Some(&self.signer_configs[0]);
            }
            if self.one_off_signer.is_none() {
                self.one_off_signer = Some(&self.signer_configs[0]);
            }
        }

        if self.default_signer.is_none() {
            return Err(Error::ConfigError("No default signer is defined".to_string()));
        }
        let default_signer = self.default_signer.unwrap();

        if !self.signer_configs.contains(default_signer) {
            return Err(Error::ConfigError(
                "The default signer must be one of the defined signers".to_string(),
            ));
        }

        if self.one_off_signer.is_none() {
            return Err(Error::ConfigError("No one-off signer is defined".to_string()));
        }
        let one_off_signer = self.one_off_signer.unwrap();

        if !self.signer_configs.contains(one_off_signer) {
            return Err(Error::ConfigError(
                "The one-off signer must be one of the defined signers".to_string(),
            ));
        }

        KrillSigner::build(self.work_dir, self.signer_configs, default_signer, one_off_signer)
    }
}

#[derive(Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    fn build(
        work_dir: &Path,
        signer_configs: &[SignerConfig],
        default_signer: &SignerConfig,
        one_off_signer: &SignerConfig,
    ) -> KrillResult<Self> {
        #[cfg(not(feature = "hsm"))]
        let signer_mapper = None;
        #[cfg(feature = "hsm")]
        let signer_mapper = Some(Arc::new(SignerMapper::build(work_dir)?));
        let signers = Self::build_signers(
            signer_builder,
            work_dir,
            &signer_mapper,
            signer_configs,
            default_signer,
            one_off_signer,
        )?;
        let router = SignerRouter::build(signer_mapper, signers)?;
        Ok(KrillSigner { router })
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

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        tbs.into_cert(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
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

    pub fn sign_aspa(
        &self,
        aspa_builder: AspaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Aspa> {
        aspa_builder
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

impl KrillSigner {
    fn build_signers(
        signer_builder: SignerBuilderFn,
        work_dir: &Path,
        mapper: &Option<Arc<SignerMapper>>,
        configs: &[SignerConfig],
        default_signer: &SignerConfig,
        one_off_signer: &SignerConfig,
    ) -> KrillResult<Vec<SignerProvider>> {
        // There must always be at least one signer
        if configs.is_empty() {
            return Err(Error::signer(
                "Internal error: At least one signer config must be provided",
            ));
        }

        // Instantiate each configured signer
        let mut signers = Vec::new();
        for config in configs.iter() {
            let flags = SignerFlags::new(config.name == default_signer.name, config.name == one_off_signer.name);

            info!(
                "Configuring signer '{}' (type: {}, {})",
                config.name, config.signer_type, flags
            );

            let signer = (signer_builder)(&config.signer_type, flags, work_dir, &config.name, mapper)?;

            signers.push(signer);
        }

        Ok(signers)
    }
}

fn signer_builder(
    r#type: &SignerType,
    flags: SignerFlags,
    work_dir: &Path,
    name: &str,
    mapper: &Option<Arc<SignerMapper>>,
) -> KrillResult<SignerProvider> {
    match r#type {
        SignerType::OpenSsl(conf) => {
            let data_dir = if let Some(ref path) = conf.keys_path {
                path.as_path()
            } else {
                work_dir
            };

            let signer = OpenSslSigner::build(data_dir, name, mapper.clone())?;

            Ok(SignerProvider::OpenSsl(flags, signer))
        }
        #[cfg(feature = "hsm")]
        SignerType::Pkcs11(conf) => {
            let signer = Pkcs11Signer::build(name, &conf, mapper.as_ref().unwrap().clone())?;
            Ok(SignerProvider::Pkcs11(flags, signer))
        }
        #[cfg(feature = "hsm")]
        SignerType::Kmip(conf) => {
            let signer = KmipSigner::build(name, &conf, mapper.as_ref().unwrap().clone())?;
            Ok(SignerProvider::Kmip(flags, signer))
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(all(
    test,
    feature = "hsm",
    not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))
))]
pub mod tests {
    use std::path::PathBuf;

    use crate::{
        commons::crypto::signers::mocksigner::{MockSigner, MockSignerCallCounts},
        daemon::config::Config,
        test,
    };

    use super::*;

    /// A signer builder fn that builds MockSigner instances instead of real signer instances.
    /// Used to test KrillSigner::build_signers().
    fn mock_signer_builder(
        r#type: &SignerType,
        flags: SignerFlags,
        _: &Path,
        name: &str,
        mapper: &Option<Arc<SignerMapper>>,
    ) -> KrillResult<SignerProvider> {
        let call_counts = Arc::new(MockSignerCallCounts::new());
        let mut mock_signer = MockSigner::new(name, mapper.as_ref().unwrap().clone(), call_counts.clone(), None, None);
        mock_signer.set_info(&format!("mock {} signer", r#type));
        Ok(SignerProvider::Mock(flags, mock_signer))
    }

    /// Create a Krill Config object from a Krill config file text fragment.
    fn config_fragment_to_config_object(fragment: &str) -> Result<Config, toml::de::Error> {
        let mut config_str = r#"admin_token = "***""#.to_string();
        config_str.push_str(fragment);
        toml::from_str(&config_str)
    }

    fn build_krill_signer_from_config(
        signers_config_fragment: &str,
        work_dir: &PathBuf,
        mapper: Arc<SignerMapper>,
    ) -> KrillResult<Vec<SignerProvider>> {
        let mut config = config_fragment_to_config_object(signers_config_fragment).unwrap();
        config.process().map_err(|err| Error::ConfigError(err.to_string()))?;
        let mapper = Some(mapper);
        KrillSigner::build_signers(
            mock_signer_builder,
            work_dir,
            &mapper,
            &config.signers,
            config.default_signer(),
            config.one_off_signer(),
        )
    }

    fn assert_signer_name(signer: &SignerProvider, expected: &str) {
        assert_eq!(signer.get_name(), expected);
    }

    fn assert_signer_type(signer: &SignerProvider, expected: &str) {
        assert_eq!(signer.get_info().unwrap(), format!("mock {} signer", expected));
    }

    fn assert_signer_name_and_type(signer: &SignerProvider, expected: &str) {
        assert_signer_name(signer, expected);
        assert_signer_type(signer, expected);
    }

    fn assert_signer_flags(signer: &SignerProvider, expected_default: bool, expected_one_off: bool) {
        assert_eq!(expected_default, signer.is_default_signer());
        assert_eq!(expected_one_off, signer.is_one_off_signer());
    }

    /// Prior to the addition of HSM support Krill had no notion of configurable signers. Instead it always created a
    /// single OpenSSL signer that was used for all signing related operations (i.e. key creation, deletion, signing,
    /// one-off signing and random number generation). With HSM support enabled, if no signers are defined in the Krill
    /// configuration file the behaviour should be the same as it was before HSM support was added.
    #[test]
    pub fn no_signers_equals_one_openssl_signer_for_backward_compatibility() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let signers = build_krill_signer_from_config("", &d, mapper).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_signer_name(signer, "Default OpenSSL signer");
            assert_signer_type(signer, "OpenSSL");
            assert_signer_flags(signer, true, true);
        });
    }

    #[test]
    pub fn signer_name_is_respected() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let signers_config_fragment = r#"
                [[signers]]
                type = "OpenSSL"
                name = "Some test name"
            "#;
            let signers = build_krill_signer_from_config(signers_config_fragment, &d, mapper).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_signer_name(signer, "Some test name");
            assert_signer_type(signer, "OpenSSL");
            assert_signer_flags(signer, true, true);
        });
    }

    /// To make it easier for the operator we don't want them to have to manually remember to mark a single OpenSSL
    /// signer configuration as the default one, it should just automatically be the default signer and should in fact
    /// be used for all signing related operations, i.e. one-off signing and random number generation as well as the
    /// key creation, deletion and signing operations handled by the default signer.
    #[test]
    pub fn single_openssl_signer_is_made_the_default_all_signer() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let signers_config_fragment = r#"
                [[signers]]
                type = "OpenSSL"
                name = "OpenSSL"
            "#;
            let signers = build_krill_signer_from_config(signers_config_fragment, &d, mapper).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_signer_name_and_type(signer, "OpenSSL");
            assert_signer_flags(signer, true, true);
        });
    }

    #[test]
    pub fn create_openssl_signer_for_one_off_signing() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let signer_config_fragment = r#"
                [[signers]]
                type = "KMIP"
                name = "KMIP"
                host = "dummy host"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper.clone()).unwrap();
            assert_eq!(signers.len(), 2);
            let signer = &signers[0];
            assert_signer_name_and_type(signer, "KMIP");
            assert_signer_flags(signer, true, false);

            let signer = &signers[1];
            assert_signer_name(signer, "OpenSSL one-off signer");
            assert_signer_type(signer, "OpenSSL");
            assert_signer_flags(signer, false, true);

            // ---

            let signer_config_fragment = r#"
                [[signers]]
                type = "PKCS#11"
                name = "PKCS#11"
                lib_path = "dummy"
                slot = "dummy slot"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper).unwrap();
            assert_eq!(signers.len(), 2);
            let signer = &signers[0];
            assert_signer_name_and_type(signer, "PKCS#11");
            assert_signer_flags(signer, true, false);

            let signer = &signers[1];
            assert_signer_name(signer, "OpenSSL one-off signer");
            assert_signer_type(signer, "OpenSSL");
            assert_signer_flags(signer, false, true);
        });
    }

    #[test]
    pub fn one_off_signer_is_respected() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let signer_config_fragment = r#"
                one_off_signer = "KMIP"

                [[signers]]
                type = "KMIP"
                name = "KMIP"
                host = "dummy host"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper.clone()).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_signer_name_and_type(signer, "KMIP");
            assert_signer_flags(signer, true, true);

            // ---

            let signer_config_fragment = r#"
                one_off_signer = "PKCS#11"

                [[signers]]
                type = "PKCS#11"
                name = "PKCS#11"
                lib_path = "dummy"
                slot = "dummy slot"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_signer_name_and_type(signer, "PKCS#11");
            assert_signer_flags(signer, true, true);
        });
    }

    #[test]
    pub fn default_signer_is_respected() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let signer_config_fragment = r#"
                default_signer = "Signer 2"

                [[signers]]
                type = "OpenSSL"
                name = "Signer 1"

                [[signers]]
                type = "KMIP"
                name = "Signer 2"
                host = "dummy host"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper.clone()).unwrap();
            assert_eq!(signers.len(), 2);

            let signer = &signers[0];
            assert_signer_type(signer, "OpenSSL");
            assert_signer_name(signer, "Signer 1");
            assert_signer_flags(signer, false, true);

            let signer = &signers[1];
            assert_signer_type(signer, "KMIP");
            assert_signer_name(signer, "Signer 2");
            assert_signer_flags(signer, true, false);
        });
    }

    #[test]
    pub fn default_signer_and_one_off_signer_are_respected() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let signer_config_fragment = r#"
                default_signer = "Signer 2"
                one_off_signer = "Signer 2"

                [[signers]]
                type = "OpenSSL"
                name = "Signer 1" # unused / historic signer

                [[signers]]
                type = "KMIP"
                name = "Signer 2" # default and one off signer
                host = "dummy host"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper.clone()).unwrap();
            assert_eq!(signers.len(), 2);

            let signer = &signers[0];
            assert_signer_type(signer, "OpenSSL");
            assert_signer_name(signer, "Signer 1");
            assert_signer_flags(signer, false, false);

            let signer = &signers[1];
            assert_signer_type(signer, "KMIP");
            assert_signer_name(signer, "Signer 2");
            assert_signer_flags(signer, true, true);
        });
    }

    #[test]
    pub fn historic_signers_are_permitted() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let signer_config_fragment = r#"
                default_signer = "Signer 2"
                one_off_signer = "Signer 3"

                [[signers]]
                type = "OpenSSL"
                name = "Signer 1" # historic signer only used with previously created keys

                [[signers]]
                type = "KMIP"
                name = "Signer 2" # default signer for new keys
                host = "dummy host"

                [[signers]]
                type = "PKCS#11"
                name = "Signer 3" # one off signer
                lib_path = "dummy"
                slot = "dummy slot"
            "#;
            let signers = build_krill_signer_from_config(signer_config_fragment, &d, mapper.clone()).unwrap();
            assert_eq!(signers.len(), 3);

            let signer = &signers[0];
            assert_signer_type(signer, "OpenSSL");
            assert_signer_name(signer, "Signer 1");
            assert_signer_flags(signer, false, false);

            let signer = &signers[1];
            assert_signer_type(signer, "KMIP");
            assert_signer_name(signer, "Signer 2");
            assert_signer_flags(signer, true, false);

            let signer = &signers[2];
            assert_signer_type(signer, "PKCS#11");
            assert_signer_name(signer, "Signer 3");
            assert_signer_flags(signer, false, true);
        });
    }
}
