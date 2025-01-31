//! Managing the Trust Anchor Signer.

use std::sync::Arc;
use openssl::error::ErrorStack;
use rpki::ca::idexchange;
use rpki::uri;
use crate::ta;
use crate::commons::actor::Actor;
use crate::commons::api::{IdCertInfo, Success};
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error as KrillError;
use crate::commons::eventsourcing::{
    namespace, AggregateStore, AggregateStoreError, Namespace,
};
use crate::commons::util::httpclient;
use crate::ta::{
    Config, TrustAnchorHandle, TrustAnchorProxySignerExchanges,
    TrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSigner, TrustAnchorSignerCommand, TrustAnchorSignerInfo,
    TrustAnchorSignerInitCommand, TrustAnchorSignerInitCommandDetails,
};


//------------ Client Error --------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SignerClientError {
    DataDirMissing,
    UnrecognizedMatch,
    HttpClientError(httpclient::Error),
    KrillError(KrillError),
    StorageError(AggregateStoreError),
    ConfigError(ta::ConfigError),
    Other(String),
}

impl SignerClientError {
    fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for SignerClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignerClientError::DataDirMissing => {
                write!(f, "Cannot find data dir")
            }
            SignerClientError::UnrecognizedMatch => {
                write!(f, "Unrecognised argument. Use 'help'")
            }
            SignerClientError::HttpClientError(e) => {
                write!(f, "HTTP client error: {}", e)
            }
            SignerClientError::KrillError(e) => write!(f, "{}", e),
            SignerClientError::StorageError(e) => {
                write!(f, "Issue with persistence layer: {}", e)
            }
            SignerClientError::ConfigError(e) => {
                write!(f, "Issue with configuration file: {}", e)
            }
            SignerClientError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<ta::ConfigError> for SignerClientError {
    fn from(e: ta::ConfigError) -> Self {
        Self::ConfigError(e)
    }
}

impl From<KrillError> for SignerClientError {
    fn from(e: KrillError) -> Self {
        Self::KrillError(e)
    }
}

impl From<AggregateStoreError> for SignerClientError {
    fn from(e: AggregateStoreError) -> Self {
        Self::StorageError(e)
    }
}


//------------ SignerInitInfo ------------------------------------------------

#[derive(Debug)]
pub struct SignerInitInfo {
    pub proxy_id: IdCertInfo,
    pub repo_info: idexchange::RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
    pub private_key_pem: Option<String>,
    pub ta_mft_nr_override: Option<u64>,
    pub force: bool
}


//------------ TrustAnchorSignerManager --------------------------------------

pub struct TrustAnchorSignerManager {
    store: AggregateStore<TrustAnchorSigner>,
    ta_handle: TrustAnchorHandle,
    config: Config,
    signer: Arc<KrillSigner>,
    actor: Actor,
}

impl TrustAnchorSignerManager {
    pub fn create(config: Config) -> Result<Self, SignerClientError> {
        let store = AggregateStore::create(
            &config.storage_uri,
            namespace!("signer"),
            config.use_history_cache,
        )
        .map_err(KrillError::AggregateStoreError)?;
        let ta_handle = TrustAnchorHandle::new("ta".into());
        let signer = config.signer()?;
        let actor = Actor::krillta();

        Ok(TrustAnchorSignerManager {
            store,
            ta_handle,
            config,
            signer,
            actor,
        })
    }

    pub fn init(
        &self,
        info: SignerInitInfo,
    ) -> Result<Success, SignerClientError> {
        if let Ok(cert) = self.store.get_latest(&self.ta_handle) {
            if !info.force {
                return Err(SignerClientError::other(
                    "Trust Anchor Signer was already initialised.",
                ));
            } 
            if let Some(priv_key) = &info.private_key_pem {
                let res = || -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
                    let priv_key = openssl::pkey::PKey::private_key_from_pem(
                        priv_key.as_bytes()
                    )?;
                    let signer_info = cert.get_signer_info();
                    let pub_key = signer_info.ta_cert_details.cert().csr_info().key();
                    let k1 = priv_key.public_key_to_der()?;
                    let k2 = pub_key.to_info_bytes().to_vec();
                    return Ok((k1, k2));
                }();
                if let Ok((k1, k2)) = res {
                    if k1 != k2 {
                        return Err(SignerClientError::other(
                            "You are not using the same private key."
                        ));
                    }
                } else if let Err(e) = res {
                    return Err(SignerClientError::other(
                        e.to_string()
                    ));
                }

                if let Err(e) = self.store.drop(&self.ta_handle) {
                    return Err(SignerClientError::other(
                        e.to_string(),
                    ));
                }
            } else {
                return Err(SignerClientError::other(
                    "Private key must be provided when force reinitialising."
                ));
            }
        }
        let cmd = TrustAnchorSignerInitCommand::new(
            &self.ta_handle,
            TrustAnchorSignerInitCommandDetails {
                proxy_id: info.proxy_id,
                repo_info: info.repo_info,
                tal_https: info.tal_https,
                tal_rsync: info.tal_rsync,
                private_key_pem: info.private_key_pem,
                ta_mft_nr_override: info.ta_mft_nr_override,
                force_recreate: info.force,
                timing: self.config.ta_timing,
                signer: self.signer.clone(),
            },
            &self.actor,
        );

        self.store.add(cmd)?;

        Ok(Success)
    }

    pub fn show(&self) -> Result<TrustAnchorSignerInfo, SignerClientError> {
        let ta_signer = self.get_signer()?;
        Ok(ta_signer.get_signer_info())
    }

    pub fn process(
        &self,
        signed_request: TrustAnchorSignedRequest,
        ta_mft_number_override: Option<u64>,
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        let cmd = TrustAnchorSignerCommand::make_process_request_command(
            &self.ta_handle,
            signed_request,
            self.config.ta_timing,
            ta_mft_number_override,
            self.signer.clone(),
            &self.actor,
        );
        self.store.command(cmd)?;

        self.show_last_response()
    }

    pub fn show_last_response(
        &self,
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        self.get_signer()?
            .get_latest_exchange()
            .map(|exchange| exchange.response.clone())
            .ok_or_else(|| SignerClientError::other("No response found."))
    }

    pub fn show_exchanges(
        &self,
    ) -> Result<TrustAnchorProxySignerExchanges, SignerClientError> {
        let signer = self.get_signer()?;
        // In this context it's okay to clone the exchanges.
        // If we are afraid that this would become too expensive, then we will
        // need to rethink the model where we return data in the enum that we
        // use. We can't have references and lifetimes because the signer will
        // be gone..
        //
        // But, again, in this context this should never be huge with
        // exchanges happening every couple of months. So, it should
        // all be fine.
        Ok(signer.get_exchanges().clone())
    }

    fn get_signer(
        &self
    ) -> Result<Arc<TrustAnchorSigner>, SignerClientError> {
        if self.store.has(&self.ta_handle)? {
            self.store
                .get_latest(&self.ta_handle)
                .map_err(SignerClientError::KrillError)
        } else {
            Err(SignerClientError::other(
                "Trust Anchor Signer is not initialised.",
            ))
        }
    }
}

