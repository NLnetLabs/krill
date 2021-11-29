# HSM: Architecture

## Terminology

- `Signer` trait: A trait defined by the `rpki` Rust crate, used by functions offered by the `rpki` Rust crate, and implemented by Krill. Defines an interface for creation and deletion of key pairs, lookup of and signing of data by a key known to the `Signer`, and generation of random byte sequences.

- `Signer` implementation: Until now Krill had a single implementation, `OpenSslSigner`. The `HSM` feature adds two new signers to Krill: `Pkcs11Signer` and `KmipSigner`.

- `Signer`: An instance of an implementation of most of the `Signer` trait (everything except random number generation). Krill can be configured to create multiple instances of the same `Signer` trait implementation, each using a different configuration. When referring to a Signer this is what is usually being referred to.

- `Signer` backend: 3rd party logic and storage, usually running outside Krill either on the same host or remotely, that works with keys on behalf of Krill. The backend details vary per signer implementation and configuration.

- `KeyIdentifier`: The SHA-1 hash of the bits of the binary DER encoding of the `SubjectPublicKey` field of the X.509 ASN.1 `SubjectPublicKeyInfo` data structure. It uniquely (or the likelyhood of collisions is sufficiently low that it can be considered unique) identifies a public/private key pair, e.g. the private key that was used to sign a certificate.

## Signer backends

The introduction of HSM support greatly expands the kinds of issues Krill can encounter and complexities it must handle when working with signing keys.

- The backend for the existing `OpenSslSigner` implementation is the OpenSSL library (either provided by the host O/S provided or embedded into Krill at compilation time) with key material being stored on the local file system and identified by `KeyIdentifier`.

- The backend for the new `Pkcs11Signer` implementation is a composite of logic provided by a 3rd party library loaded at runtime by Krill from a file on the host filesystem specified by the Krill configuration, and any services and storage used by that library.
  
  The PKCS#11 library MUST implement the "Cryptoki" interface defined by the **_stateful_** PKCS#11 v2.20 specification ([HTML](https://www.cryptsoft.com/pkcs11doc/v220/), [PDF](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11v2-20.pdf)), _"the most widely used version of the PKCS#11 standard"_ (according to [Cryptsoft](https://www.cryptsoft.com/pkcs11doc/)).  The Krill process invokes functions loaded into its process space from the configured PKCS#11 library.

  The PKCS#11 interface is a synchronous design meaning that Krill has to invoke the functions and wait for them to complete. The specification does not include any capability to poll for completion of a previously started task. It is also stateful such that Krill must open and close sessions with the interface and that key identifiers used in a session for a given key will be different to the identifiers used for the same key in a later session (the specification says _"A particular object on a token does not necessarily have a handle which is fixed for the lifetime of the object"_). Krill therefore labels keys and stores a mapping from `KeyIdentifier` to label so that it can later lookup the session specific key identifier in order to work with the key.

  Implementations vary signficantly in their design. Examples include [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) which uses logic provided by the library and local file system storage for keys, or the [Yubico SDK PKCS#11 library](https://www.yubico.com/press-releases/yubico-introduces-open-source-yubihsm-sdk-for-securing-infrastructures-and-hardware-private-key-storage/) which communicates via HTTP(S) with a "Connector" daemon which in turn communicates with the cryptographic device, to the [AWS CloudHSM PKCS#11 Client SDK 5 library](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html) that makes outbound TCP/IP connections to a cluster of servers running on, and storing key data in, the Amazon Web Services cloud.

- The backend for the new `KmipSigner` implementation is a 3rd party service that offers an interface compatible with the _stateless_ [Key Management Interoperability Protocol (KMIP) v1.2](http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html) specification.

  Krill establishes one or more TCP/IP connections to the offered interface. Data exchanged with the interface is protected by TLS encryption and is encoded according to the TTLV binary protocol defined by the KMIP specification.
  
  KMIP is primarily a synchronous design, i.e. Krill must wait for requests to complete, Krill does not poll to see if a previously started task has since completed. Key identifiers issued by KMIP are persistent and unchanging. Krill stores a mapping from `KeyIdentifier` to KMIP key identifier so that it can work with the keys again later.
  
  Connections are kept alive for a period to reduce the overhead and delay that would otherwise be incurred when processing several KMIP requests in quick succession. Krill will attempt to reconnect if it encounters difficulty in communicating with the KMIP compatible service.
  
  KMIP supports batching of several requests together and some limited provision for referencing the output of a previous request in a subsequent request in the same batch, but Krill doesn't use this capability at present.


## The all important `KeyIdentifier`

The design revolves in many ways around the Krill `KeyIdentifier` which uniquely identifies a particular signing key pair.

> **A note about the uniqueness of the KeyIdentifier**
> 
> It is theoretically possible for more than one `Signer` backend to possess a copy of the same key pair identified by the same `KeyIdentifier`, e.g. if the key pair were extracted from one backend and imported to another, or if one backend instance is part of a cluster of instances with access to the same data or where one instance is a spare kept (reasonably) in sync with a primary or if multiple instances were restored from the same backup data. However, for a given piece of data the same signature will be generated by each backend that signs the data using a key identified by the same key pair. For a given `KeyIdentifier` Krill will use the `Signer` that it noted as owning the key (which under-the-hood)

The `KeyIdentifier` is used in many places by Krill. While theoretically the `Signer` interface permits individual implementations to designate their own key identifier, the type of identifer used by Krills implementations cannot be changed. Standards require that the `KeyIdentifier` be recorded in certificates that Krill generates and works with. When working with a certificate the `KeyIdentifier` is the only information available to Krill to identify the related key, nor should code in such parts of Krill be extended to to know about the internals of how keys are actually stored and identified in order to overcome this limitation.

The `KeyIdentifier` is passed to implementers of the `rpki` crate `Signer` trait meaning in turn that `Signer` implementations must be able to locate the key that is associated with the `KeyIdentifier`. For the existing `OpenSslSigner` this isn't a problem as the keys are stored on disk using the `KeyIdentifier` as the file name. For other signers a mapping has to be maintained from `KeyIdentifier` to owning `Signer` and from `KeyIdentifier` to implementation specific key identifier.

## Relating `KeyIdentifier` to RFC terms used in the PKCS#11 and KMIP specifications

When reading the KMIP and PKCS#11 specifications various RFC defined terms are used which are relevant to our need to relate HSM keys to the Krill `KeyIdentifier`. It is useful to understand how terminology used by the code in Krill relates to the terms defined in the related specifications and RFCs.

We can trace some of the relationships as follows:

- The [`rpki::PublicKey::key_identifier()`](https://docs.rs/rpki/0.5.0/rpki/crypto/keys/struct.PublicKey.html#method.key_identifier) function uses the [`bcder::BitString::octets_slice()`](https://docs.rs/bcder/0.6.0/bcder/string/struct.BitString.html#method.octet_slice) function to obtain the inner [`bcder::BitString::bits`](https://docs.rs/bcder/0.6.0/src/bcder/string/bit.rs.html#64-70) subfield of the [`rpki::PublicKey::bits`](https://docs.rs/rpki/0.5.0/src/rpki/crypto/keys.rs.html#87-90) field and then invokes the [`ring::digest::digest()`](https://docs.rs/ring/0.16.20/ring/digest/fn.digest.html) function to SHA-1 hash it. The resulting value is the Krill `KeyIdentifier`.

- SHA-1 is mandated by [section 3 Asymmetric Key Pair Formats of RFC 7935](https://datatracker.ietf.org/doc/html/rfc7935#section-3) which says _"The RSA key pairs used to compute the signatures MUST have a 2048-bit modulus and a public exponent (e) of 65,537"_ (more below on RSA modulus and public exponent for why this is relevant).

- Assuming that `length` is implied and `tag` is not included then the `bits` to be hashed correspond to the `value of the BIT STRING` mentioned in [section 4.2.1.2 "Subject Key Identifier" of RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2) when it states that _"The **keyIdentifier** is composed of the 160-bit **SHA-1** hash of the value of the **BIT STRING** subjectPublicKey (excluding the tag, length, and number of unused bits)"_.

- The `bcder::BitString::bits` inner subfield of the `rpki::PublicKey::bits` field is an encoded form of the public key format defined in [section 3.1 Public Key Format of RFC 7935](https://datatracker.ietf.org/doc/html/rfc7935#section-3.1) and _"subjectPublicKey"_ defined in [Appendix A.1 of RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1):

  ```rust
  Rust rpki::PublicKey               RFC 7935            RFC 5280 Appendix A.1
  ===============================    ================    =============================================
  pub struct PublicKey {                                 SubjectPublicKeyInfo  ::=  SEQUENCE  {
      algorithm: PublicKeyFormat,    algorithm               algorithm            AlgorithmIdentifier,
      bits: BitString,               subjectPublicKey        subjectPublicKey     BIT STRING  }
  }
  ```

- [Section 3.1 Public Key Format of RFC 7935](https://datatracker.ietf.org/doc/html/rfc7935#section-3.1) defines `subjectPublicKey` as _"RSAPublicKey MUST be used to encode the certificate's subjectPublicKey field, as specified in [RFC4055]"_ and [section 1.2 RSA Public Keys of RFC 4055](https://datatracker.ietf.org/doc/html/rfc4055#section-1.2) states:

  > The RSA public key MUST be encoded using the type RSAPublicKey type:
  > ```
  >    RSAPublicKey  ::=  SEQUENCE  {
  >       modulus            INTEGER,    -- n
  >       publicExponent     INTEGER  }  -- e
  > ```
  > Here, the modulus is the modulus n, and publicExponent is the public
  > exponent e.  The DER encoded RSAPublicKey is carried in the
  > subjectPublicKey BIT STRING within the subject public key
  > information.

Understanding these structures, meanings and relationships is important when considering how to get the desired information out of a PKC#11 or KMIP compliant HSM and why the Krill HSM supporting code is able to derive the `KeyIdentifier` from RSA modulus and public exponent values.

References:
- [PKCS#11 v2.20](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11v2-20.pdf): Cryptographic Token Interface Standard
- [KMIP v1.2](http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html): Key Management Interoperability Protocol Specification Version 1.2
- [RFC 4055](https://datatracker.ietf.org/doc/html/rfc4055): Additional Algorithms and Identifiers for RSA Cryptography for use in the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280): Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- [RFC 7935](https://datatracker.ietf.org/doc/html/rfc7935): The Profile for Algorithms and Key Sizes for Use in the Resource Public Key Infrastructure


## Decision log

- Roll our own Rust KMIP library as no actively maintained Rust support for KMIP with sufficient functionality for Krill existed at the time of writing.

  The best candidate I found for use instead of rolling our own was the https://github.com/visa/kmip crate. This crate was used to explore KMIP support in the Krill HSM prototype. However, I considered it insufficient for use in final Krill HSM support because:

  - It lacked the ability to execute some KMIP operations needed by Krill (e.g. `Destroy`, `ModifyAttribute`, `RngRetrieve`, `Sign`).
  - It did not offer any TCP/IP TLS client capability, only byte level (de)serialization.
  - It did not have any tests of its own functionality.
  - It did not have any tests showing conformance with the KMIP specification.
  - It was not published on https://crates.io/ and thus a new version of Krill that depended on it would not be releasable to https://crates.io/ unless we embedded the `visa/kmip` crate code inside Krill.
  - Error reporting was quite basic (presumably because it targets no-std environments which limits its ability to construct abitrary complex error messages).
  - There was no indication that the crate was intended for use by others nor any advertisement of support or potential for support.
  - There was no indication of activity at the time of writing (no releases, issues or pull requests) since the initial release in July 2020.

- Don't include the KMIP code in the main Krill code base as it is orthogonal to and independently useful outside of
  Krill, and the Krill code base is already quite large & slow to compile.

- Support multiple concurrently active signers for use cases such as:
  
  - Rollover to a new signer (creation of new keys with the new signer while continued use of keys created by the previous signer).

  - Generation of one-off keys using OpenSSL even when using a separate signer for creation of other keys, as doing this with an HSM can require multiple potentially slow requests (create, activate, sign, deactivate, destroy, potentially each being a network round trip plus relatively slow execution of operations compared to local OpenSSL) and because the security benefits of an HSM are not thought to be necessary for one-off signing keys.

- Maintain mappings of Krill `KeyIdentifier` to signer identifier (so that we can dispatch signing requests to the
  correct signer) and `KeyIdentifier` to signer specific key identifiers (so that we can instruct the signer to work with the correct key).
  
  Initially it was hoped that this would not be needed as keys could be tagged on creation or maybe even created with a supplied primary identifier, but in testing with actual PKCS#11 and KMIP providers it was discovered to be necessary. 
  
  For example the KMIP specification says that the key Unique Identifier _"SHALL be assigned by the key management system at creation or registration time, and then SHALL NOT be changed or deleted before the object is destroyed"_ and thus cannot be modified after creation to be the `KeyIdentifier` nor at the time of writing did the AWS CloudHSM support the PKCS#11 `C_SetAttributeValue` function that would be needed to apply some sort of identifier or label to the key after creation.
  
  Instead some other identifier must be stored with the key in another attribute at key creation time. For PKCS#11 the `CKA_ID` attribute was chosen for this as `CKA_LABEL` was thought to be better used for storing a descriptive label to be shown by HSM client tooling. For KMIP the `Name` attribute is used.

- Support generation of the `KeyIdentifier` from component parts (RSA modulus and exponent) for cases where the signer
  doesn't support (or guarantee support for) exposing that itself but does provides access to the component parts which can be used to reconstitute it.

  For example the PKCS#11 v2.20 specification defines the `CKA_HASH_OF_SUBJECT_PUBLIC_KEY` key attribute which might be used to to obtain the `KeyIdentifier` for a created key, but the AWS CloudHSM PKCS#11 implementation didn't support it at the time of writing.
  
  There is also the v2.40 definied `CKA_PUBLIC_KEY_INFO` key attribute (_"DER-encoding of the SubjectPublicKeyInfo (see above) for the public key contained in this certificate (default empty)"_) whose value could be deconstructed to obtain the `KeyIdentifier` (see the notes above the relationship between `SubjectPublicKeyInfo` and `KeyIdentifier`), but it is an optional field which is allowed to be empty (and at least with SoftHSMv2 at the time of writing was always empty) and the [AWS CloudHSM list of supported PKCS#11 attributes](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes.html) didn't inlcude it) and would not anyway be supported by clients that implement an earlier version of the PKCS#11 specification.
  
  In theory PKCS#11 clients support locating a key by its `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` but KMIP doesn't support this, though should support locating a key by its "digest".

- Don't fail to start Krill if a signer backend is not reachable or lacks required capabilities. Preventing Krill from
  operating won't fix the problem and prevents Krill from doing anything else useful with keys from other signers or
  offering its API or UI.

- Be robust in case of network delays and errors and problems in external signing services. Retry requests that fail due to issues potentially caused by transient network degradation. Re-use TCP+TLS sessions to avoid costly TCP+TLS setup and teardown costs per request to the signer service.

## Design

Old: Prior to the addition of HSM support there was only ever a single Signer and control flow looked like this:

```
Krill calling code -> KrillSigner -> OpenSslSigner
```

New: With the addition of HSM support there may be multiple concurrently active Signers and the control flow becomes this:

```
                    Creates signers    + Pending Signers: [SignerProvider, SignerProvider, ...]
                           :           |
Krill calling code -> KrillSigner -> SignerRouter
                                       |
  where:                               + Ready Signers:   [SignerProvider, SignerProvider, ...]
    SignerProvider is one of:          |                    ^               ^
      - KmipSigner                     + SignerMapper ------+---------------+
      - OpenSslSigner                          |
      - Pkcs11Signer                           + AggregateStore<SignerInfo>
```

- `KrillSigner` remains the central interface between Krill and the signer backends,, handling config file parsing and initial signer creation, conversion of error types and providing higher level functions that make use of the underlying signers. `KrillSigner` delegates signer registration and dispatch to `SignerRouter`.
  
- `SignerRouter` uses an instance of `SignerMapper` to record which signer backends exist and which keys they possess. Signers use the same `SignerMapper` instance to register the keys as their own and to register the mapping between Krill `KeyIdentifier` and signer backend specific internal identifier(s).
  
- `SignerRouter` registers/binds and dispatches to signers. Signers start in the pending set and are not yet usable. Registration and binding are the process of probing a singer backend to establish if we can connect to it and if so if it is usable. New signers are registered by creating an identity key inside it and recording it in the `SignerMapper`. Later invocations of Krill will verify the identity of the signer (and thus which `SignerMapper` ID relates to it and which keys it possesses) using this identity key. A signer is moved to the ready set once it has been successfully probed and registered/bound and its `SignerMapper` ID has been determined and communicated to it. Signers that fail to be probed or are discovered to be unusable are dropped from the pending set without being added to the ready set.

- `SignerRouter` identifies the appropriate signer for a given request. Signer selection happens in one of two ways:
  - For requests relating to an existing key the request is routed to the signer that owns the key, as identified by the `SignerMapper`. 
  - For all other requests the signer with  is selected based on its assigned roles, e.g. default signer or one-off signer roles can be assigned to specific signers, as defined by `SignerFlags`.
 
  Actual dispatch is delegated to an instance of `SignerProvider` because enum based dispatch is noisy and the "Provider" enum dispatch pattern was alrady established in the multi-user auth code.

- `SignerProvider` dispatchses requests using enum based dispatching. This approach was chosen over use of Rust traits due to complexities associated with traits (e.g. async traits are not yet officially supported) and the lack of requirement to support an arbitrary number of as yet unseen implementations of some trait. We know exactly how many different signer implementations we need to support: OpenSSL soft signer, PKCS#11 based signer and KMIP based signer.

## Signer mapper stored data example

From `<krill_data_dir>/signers/<signer_uuid>/snapshot.json`:
```json
{
  "id": "a32392f6-da5d-4341-98c1-cecdb0c12416",
  "version": 9,
  "signer_name": "Pkcs11Signer - No config file name available yet",
  "signer_info": "PKCS#11 Signer [token: My token 1 (model: SoftHSM v2, vendor: SoftHSM project), slot: 2146913893, server: SoftHSM (Cryptoki v2.6), library: libsofthsm2.so]",
  "signer_identity": {
    "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbJR0aHy3tFzXhs/lWlCfWpFH7xFk+HRyGA3GYTIsUBwwu2uS9QAZXb8X3NjPLSvw+0Cfcy9n7yHC6B4pQda13bxVSvshC1f4mUc/iXWtMLg4x/F2fJNcTGVW3DbmPWKMXQVeBboFMwF+FZll7EgMsvmiZXn6qeoLm5hfcjihqb88k+HUuMvsGcz939jOIirxv8xP6jT/vJGDxidgoBSIBL3AUSbjh0WEopAzGX8Z+nNvaAPtanhWEB7n0mktyTis4G+GPh1N0pOT5pGxEPf7BnOb1gnPTbb0sTz7M64vkXkxCL69Yxlz3c3MxW4zncwKmGwXo4cmEpN8CTWC5ORbQIDAQAB",
    "private_key_internal_id": "32b25442dbf26971ffa556d2415810f80e3139d2"
  },
  "keys": {
    "422A26E19291F094B5182FC993DF32B14682D9D2": "b740d70d1e6ad8ebc91d7011753cdb43b76b719b",
    "87F9B52806A0E7B3812D87DDCC943FF51C8749B6": "03332ef8050c393a42395c4e55aba64c3d64c953",
    "7858DEB28A517BF21F2B2D540A904FDB22615B76": "d322f65668fc7821c18f037237facce403a331df",
    "63CDB21953376A88588990E77F423B4832A03F5A": "61f0c63e9288aed063fdfe8ca7482cd62544fc70",
    "AB41906ECA2F59D7A8DC76DADF46F63062FE765B": "bc49cd8983ddc3177b47a87d19365d75cb4ecfc6",
    "B83D0D7B9B8264F2170EA21C6CECE54A4D9F4549": "a76440202b5ab2113b4b9cdca199b5b38f23308e",
    "395B687CB0BCAAE074A299BB08DA82911A83D971": "c0c0b61047dec3514d9f9ce19c0253c0c381bb3a",
    "05770B676863B9459A19480B283E025DF0AD96BC": "a9a7bd64a9c48a112c639910b5528feede52dff9"
  }
}
```

Here we see an example of a PKCS#11 signer using the SoftHSMv2 PKCS#11 library. The snapshot includes the set of keys created by this signer with both their Krill `KeyIdentifier` and the CKA_ID stored with the key in SoftHSMv2. We also see the identity details needed to confirm that the backend is indeed the owner of these keys.

## Crate dependencies

- Loading and interfacing with PKCS#11 libraries is handled by the [`pkcs11`](https://crates.io/crates/pkcs11) crate.
- Communicating with KMIP servers is handled by the NLnet Labs [`kmip-protocol`](https://crates.io/crates/kmip-protocol) crate.
- Connection pooling is handled by the [`r2d2`](https://crates.io/crates/r2d2) crate.
- Retry and backoff is handled by the [`backoff`](https://crates.io/crates/backoff) crate.
- KMIP TLS is handled by the (already used) [`openssl`](https://crates.io/crates/openssl) crate rather than the [`rustls`](https://crates.io/crates/rustls) crate as the latter may impose stricter limits on outbound connectivity to HSMs than can be pragmatically expected to work in all customer environments.

## Known issues

- Ideally signers would be Rust async and async changes to the `rpki` crate were designed. At the time of writing however, supporting async signing would require deeper changes in core Krill code that we will leave for now as it's not yet clear whether or not blocking signers with potentially slow backends is really a problem or not.
- TBD: Switch to `tokio-native-tls` to keep the benefits of and control of local O/S native TLS providers and avoid the
  'modern security' limitations of `rustls` while switching to an `async` model.
- There are no timeouts on PKCS#11 operations.
