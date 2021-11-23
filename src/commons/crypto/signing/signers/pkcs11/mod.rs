pub mod context;
/// # Thread safety
///
/// From section 6.7.6 "Capabilities of sessions":
///
///   "A consequence of the fact that a single session can, in general, perform only one operation at a time is that an
///    application should never make multiple simultaneous function calls to Cryptoki which use a common session.  If
///    multiple threads of an application attempt to use a common session concurrently in this fashion, Cryptoki does
///    not define what happens. This means that if multiple threads of an application all need to use Cryptoki to access
///    a particular token, it might be appropriate for each thread to have its own session with the token, unless the
///    application can ensure by some other means (e.g., by some locking mechanism) that no sessions are ever used by
///    multiple threads simultaneously.  This is true regardless of whether or not the Cryptoki library was initialized
///    in a fashion which permits safe multi-threaded access to it. Even if it is safe to access the library from
///    multiple threads simultaneously, it is still not necessarily safe to use a particular session from multiple
///    threads simultaneously.""
///
/// # Terminology
///
/// The PKCS#11 specification defines the term token as a "logical view of a cryptographic device" and slot as "a
/// logical reader that potentially contains a token". However, rather than refer to "tokens" we instead here refer to
/// the PKCS#11 server. This is because Krill uses the term token to refer to the token used to authenticate with the
/// Krill API.
///
/// By using "server" the code is more consistent with the KmipSigner code, we avoid the overlap with the Krill meaning
/// of "token" and, while it may at first seem misleading because for example the SoftHSMv2 PKCS#11 library communicates
/// with a local process and not a remote server, this is no worse than the KMIP scenario when the "server" is actually
/// a locally running PyKMIP Python process, and in cases such as the AWS CloudHSM PKCS#11 library is actually
/// representative of the remote cloud server or server cluster nature of the backend being communicated with by the
/// PKCS#11 library.
pub mod signer;
pub mod session;

pub use signer::Pkcs11Signer;
