pub(crate) mod dispatch;

pub(super) mod signers;

mod misc;

pub use dispatch::krillsigner::{KrillSigner, KrillSignerBuilder};
pub use signers::error::SignerError;
pub use signers::softsigner::OpenSslSigner;

#[cfg(feature = "hsm")]
pub use signers::kmip::signer::KmipSignerConfig;

#[cfg(feature = "hsm")]
pub use signers::pkcs11::signer::Pkcs11SignerConfig;

pub use signers::softsigner::OpenSslSignerConfig;

pub use misc::*;
