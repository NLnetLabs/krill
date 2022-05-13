//! Support for signing things using an external KMIP compliant cryptographic token.
//!
//! Currently only intended for sanity checking the use of KMIP with Krill by running as the only signer in place of
//! the usual [OpenSslSigner]. Assumes that the KMIP server is a [PyKMIP] instance that is created for and destroyed
//! after the Krill tests have run. Uses hard-coded connection details and in-memory storage of key identifiers issued
//! by the KMIP server.
//!
//! The current implementation splits the KMIP signer into four Rust modules:
//!   - `connpool`: Connection pooling related functionality.
//!   - `internal`: KMIP server interaction, including probing and retry/backoff logic.
//!   - `keymap`: In-memory mapping of `KeyIdentifier` to KMIP key identifiers.
//!   - `signer`: The public signer trait implementation. Delegates to `internal`.
//!
//! [OpenSslSigner]: crate::commons::util::softsigner::OpenSslSigner
//! [PyKMIP]: https://github.com/OpenKMIP/PyKMIP
pub mod connpool;
pub mod signer;

pub use signer::KmipSigner;
