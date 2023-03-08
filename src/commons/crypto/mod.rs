mod error;
use rpki::ca::idexchange::MyHandle;

pub use self::error::*;

mod signing;
pub use self::signing::*;

pub type SignerHandle = MyHandle;

pub type CryptoResult<T> = std::result::Result<T, self::error::Error>;

#[cfg(feature = "hsm")]
pub use self::signers::pkcs11::signer::PubKeyAccess;
