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
                signerprovider::{SignerFlags, SignerProvider},
                signerrouter::SignerRouter,
            },
            CryptoResult, OpenSslSigner,
        },
        KrillResult,
    },
    daemon::config::SignerConfig,
};

#[cfg(feature = "hsm")]
use crate::{
    commons::{
        crypto::{
            dispatch::signerinfo::SignerMapper,
            signers::{kmip::KmipSigner, pkcs11::Pkcs11Signer},
            OpenSslSignerConfig,
        },
        error::Error,
    },
    daemon::config::SignerType,
};

#[cfg(feature = "hsm-tests-kmip")]
use crate::commons::crypto::KmipSignerConfig;

#[cfg(feature = "hsm-tests-pkcs11")]
use crate::commons::crypto::Pkcs11SignerConfig;

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

#[cfg(feature = "hsm")]
type SignerBuilderFn = fn(&SignerType, SignerFlags, &Path, &str, Arc<SignerMapper>) -> KrillResult<SignerProvider>;

#[derive(Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    #[cfg(not(feature = "hsm"))]
    pub fn build(work_dir: &Path, _: &[SignerConfig]) -> KrillResult<Self> {
        let signer = Arc::new(SignerProvider::OpenSsl(
            SignerFlags::default(),
            OpenSslSigner::build(work_dir)?,
        ));
        let router = SignerRouter::build(signer)?;
        Ok(KrillSigner { router })
    }

    #[cfg(feature = "hsm")]
    pub fn build(work_dir: &Path, signer_configs: &[SignerConfig]) -> KrillResult<Self> {
        let signer_mapper = Arc::new(SignerMapper::build(work_dir)?);
        let signers = Self::build_signers(signer_builder, work_dir, signer_mapper.clone(), signer_configs)?;
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

#[cfg(feature = "hsm")]
impl KrillSigner {
    fn build_signers(
        signer_builder: SignerBuilderFn,
        work_dir: &Path,
        mapper: Arc<SignerMapper>,
        configs: &[SignerConfig],
    ) -> KrillResult<Vec<SignerProvider>> {
        // For backward compatibility, no configured signers is the same as a single OpenSSL signer that will provide
        // all signer functionality. To support running the Krill test suite against SoftHSM and PyKMIP we modify this
        // behaviour slightly when special Krill Rust feature testing related flags are enabled.
        let mut configs = configs.to_vec();
        if configs.is_empty() {
            configs.push(Self::get_default_signer_config()?);
        }

        // One and only one signer should be the default. The default signer is used for operations that don't concern
        // an existing key, i.e. key creation, one-off signing and random number generation. The latter two are
        // delegated by default to an OpenSSL signer as the security benefit is minimal and the incurred delay can be
        // significant when communicating with an HSM.
        let mut num_default_signers = configs.iter().filter(|c| c.default).count();
        let num_one_off_signers = configs.iter().filter(|c| c.oneoff).count();
        let num_rand_fallback_signers = configs.iter().filter(|c| c.random).count();

        if configs.len() == 1 {
            configs[0].default = true;
            num_default_signers = 1;
        }

        #[rustfmt::skip]
        match (num_default_signers, num_one_off_signers, num_rand_fallback_signers) {
            (1, 1, 1) => Ok(()),
            (1, o, r) if o == 0 || r == 0 => {
                let oneoff = o == 0;
                let random = r == 0;

                // We need an OpenSSL signer to act as one-off and/or fallback random number generating signer.
                if let Some(openssl_signer) = configs.iter_mut().find(|c| matches!(c.signer_type, SignerType::OpenSsl(_))) {
                    // Use an existing OpenSSL signer
                    openssl_signer.oneoff = oneoff;
                    openssl_signer.random = random;
                } else {
                    // Create a new OpenSSL signer
                    let config = SignerConfig {
                        name: Some("Fallback OpenSSL signer".to_string()),
                        default: false,
                        oneoff,
                        random,
                        signer_type: SignerType::OpenSsl(OpenSslSignerConfig::default()),
                    };
                    configs.push(config);
                }
                Ok(())
            }
            (0, _, _) => Err(Error::ConfigError("One signer must be set as the default signer".to_string())),
            (d, _, _) if d > 1 => Err(Error::ConfigError(format!("Expected one default signer but found {}", d))),
            (_, o, _) if o > 1 => Err(Error::ConfigError(format!("Expected one one-off signer but found {}", o))),
            (_, _, r) if r > 1 => Err(Error::ConfigError(format!("Expected one fallback random number generator signer but found {}", r))),
            (d, o, r) => Err(Error::ConfigError(format!("Internal error: Unable to create signers: d={}, o={}, r={}", d, o, r))),
        }?;

        // Instantiate each configured signer
        let mut signers = Vec::new();
        for config in configs.iter() {
            let name = Self::get_or_generate_signer_name(config);
            let flags = SignerFlags::new(config.default, config.oneoff, config.random);

            info!(
                "Configuring signer '{}' (type: {}, {})",
                name, config.signer_type, flags
            );

            let signer = (signer_builder)(&config.signer_type, flags, work_dir, &name, mapper.clone())?;

            signers.push(signer);
        }

        Ok(signers)
    }

    fn get_or_generate_signer_name(config: &SignerConfig) -> String {
        if let Some(name) = &config.name {
            name.clone()
        } else {
            config.generate_name()
        }
    }

    fn get_default_signer_config() -> KrillResult<SignerConfig> {
        let signer_name = "default".to_string();

        #[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
        {
            // Use the OpenSSL signer for everything.
            Ok(SignerConfig::all(
                Some(signer_name),
                SignerType::OpenSsl(OpenSslSignerConfig::default()),
            ))
        }

        #[cfg(feature = "hsm-tests-kmip")]
        {
            // Use the KMIP signer for one-off signing but not random number generation. Normally we wouldn't use it
            // for one-off signing as it can be slow making round trips to a HSM and for little gain and so we would
            // then use an OpenSSL signer instead, but for testing purposes we exercise the KMIP signer as much as
            // possible. We can't do random number generation with it as the tests use PyKMIP which doesn't support
            // generation of random numbers.
            Ok(SignerConfig::default_only(
                Some(signer_name),
                SignerType::Kmip(KmipSignerConfig::default()),
            ))
        }

        #[cfg(feature = "hsm-tests-pkcs11")]
        {
            // Use the PKCS#11 signer for everything. Normally we wouldn't use it for one-off signing or random number
            // generation as it can be slow making round trips to a HSM and for little gain and so we would then use an
            // OpenSSL signer as well for those cases, but for testing purposes we exercise the PKCS#11 signer as much
            // as possible.
            Ok(SignerConfig::all(
                Some(signer_name),
                SignerType::Pkcs11(Pkcs11SignerConfig::default()),
            ))
        }
    }
}

#[cfg(feature = "hsm")]
fn signer_builder(
    r#type: &SignerType,
    flags: SignerFlags,
    work_dir: &Path,
    name: &str,
    mapper: Arc<SignerMapper>,
) -> KrillResult<SignerProvider> {
    match r#type {
        SignerType::OpenSsl(conf) => {
            let data_dir = if let Some(ref path) = conf.keys_path {
                path.as_path()
            } else {
                work_dir
            };

            let signer = OpenSslSigner::build(data_dir, name, Some(mapper))?;

            Ok(SignerProvider::OpenSsl(flags, signer))
        }
        SignerType::Pkcs11(conf) => {
            let signer = Pkcs11Signer::build(name, &conf, mapper)?;
            Ok(SignerProvider::Pkcs11(flags, signer))
        }
        SignerType::Kmip(conf) => {
            let signer = KmipSigner::build(name, &conf, mapper)?;
            Ok(SignerProvider::Kmip(flags, signer))
        }
    }
}

#[cfg(all(test, feature = "hsm"))]
pub mod tests {
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
        mapper: Arc<SignerMapper>,
    ) -> KrillResult<SignerProvider> {
        let call_counts = Arc::new(MockSignerCallCounts::new());
        let mut mock_signer = MockSigner::new(name, mapper.clone(), false, call_counts.clone(), None, None);
        mock_signer.set_info(&format!("mock {} signer", r#type));
        Ok(SignerProvider::Mock(flags, mock_signer))
    }

    /// Create a Krill Config object from a Krill config file text fragment.
    fn config_fragment_to_config_object(fragment: &str) -> Result<Config, toml::de::Error> {
        let mut config_str = r#"admin_token = "***""#.to_string();
        config_str.push_str(fragment);
        toml::from_str(&config_str)
    }

    /// Prior to the addition of HSM support Krill had no notion of configurable signers. Instead it always created a
    /// single OpenSSL signer that was used for all signing related operations (i.e. key creation, deletion, signing,
    /// one-off signing and random number generation). With HSM support enabled, if no signers are defined in the Krill
    /// configuration file the behaviour should be the same as it was before HSM support was added.
    #[test]
    pub fn test_backward_compatibility() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let config = config_fragment_to_config_object("").unwrap();
            let signers = KrillSigner::build_signers(mock_signer_builder, &d, mapper, config.signers()).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_eq!(signer.get_name(), "default");
            assert_eq!(signer.get_info().unwrap(), "mock OpenSSL signer");
            assert!(signer.is_default_signer());
            assert!(signer.is_one_off_signer());
            assert!(signer.is_rand_fallback_signer());
        });
    }

    /// To make it easier for the operator we don't want them to have to manually remember to mark a single signer
    /// configuration as the default one, it should just automatically be the default signer and should in fact be used
    /// for all signing related operations, i.e. one-off signing and random number generation as well as the key
    /// creation, deletion and signing operations handled by the default signer.
    #[test]
    pub fn test_single_signer_is_made_the_default_all_signer() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let signers_config_fragment = r#"
                [[signers]]
                type = "OpenSSL"
"#;
            let config = config_fragment_to_config_object(signers_config_fragment).unwrap();
            let signers = KrillSigner::build_signers(mock_signer_builder, &d, mapper, config.signers()).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_eq!(signer.get_name(), "OpenSSL");
            assert_eq!(signer.get_info().unwrap(), "mock OpenSSL signer");
            assert!(signer.is_default_signer());
            assert!(signer.is_one_off_signer());
            assert!(signer.is_rand_fallback_signer());
        });
    }

    /// When there is only a single signer with explicit roles assigned those roles should not be overridden.
    #[test]
    pub fn test_single_signer_is_forced_to_be_the_default_all_signer() {
        test::test_under_tmp(|d| {
            let mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let signers_config_fragment = r#"
                [[signers]]
                type = "OpenSSL"
                default = false
                oneoff = false
                random = false
"#;
            let config = config_fragment_to_config_object(signers_config_fragment).unwrap();
            let signers = KrillSigner::build_signers(mock_signer_builder, &d, mapper, config.signers()).unwrap();
            assert_eq!(signers.len(), 1);
            let signer = &signers[0];
            assert_eq!(signer.get_name(), "OpenSSL");
            assert_eq!(signer.get_info().unwrap(), "mock OpenSSL signer");
            assert!(!signer.is_default_signer());
            assert!(!signer.is_one_off_signer());
            assert!(!signer.is_rand_fallback_signer());
        });
    }
}
