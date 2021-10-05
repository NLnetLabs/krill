# HSM: Architecture

## Key data

- Krill `KeyIdentifier`: SHA-1 of the binary DER encoding of the X.509 ASN.1 SubjectPublicKeyInfo data structure) used
  by Krill. Cannot be changed as it is stored in certificates as per standards and then later the certificate is the
  only information available to the calling code, i.e. it doesn't have anything else to identify the key involved.

## Key architectural decisions

- Create our own KMIP Rust library as no actively maintained Rust support for KMIP with sufficient functionality for 
  Krill existed at the time of writing. The closest candidate, https://github.com/visa/kmip, was used to explore KMIP
  support in the Krill HSM prototype code. However, it was decided to create our own KMIP library because the visa 
  crate:

  - Was not published on crates.io.
  - Had only rudimentary error reporting (as it targets no-std environments).
  - Lacked documentation, support for needed KMIP operations & TCP+TLS client support.

  Don't include the KMIP library in the main Krill code base as it is orthogonal to and independently useful outside of
  Krill, and the Krill codebase is already quite large & slow to compile.

- Support multiple concurrently active signers to support rollover to a new signer (creation of new keys with the new
  signer while continued use of keys created by the previous signer), fallback to the OpenSSL signer for random number
  generation whne the chosen doesn't support this capability, generation of one-time keys using OpenSSL as doing this
  with an HSM would be slow (create, activate, sign, deactivate, destroy, potentially each being a network round trip
  plus relatively slow execution of operations compared to local OpenSSL) and because the security benefits of an HSM
  are not needed for one-time signing keys.

- Maintain a mapping of Krill `KeyIdentifier` to signer identifier so that we can dispatch signing requests to the
  correct signer.

- Maintain a mapping of Krill `KeyIdentifier` to signer specific key identifiers.

- Support generation of the `KeyIdentifier` from component parts (RSA modulus and exponent) for cases where the signer
  doesn't (guarantee) support for exposing that for us itself but only provides access to the component parts.

- Don't fail to start Krill if a signer backend is not reachable or lacks required capabilities. Preventing Krill from
  operating won't fix the problem and prevents Krill from doing anything else useful with keys from other signers or
  offering its API or UI.

## Design

- KrillSigner acts as the central hub aware of all signers and key mappings and dispatches requests to the correct
  signer based on the action being performed and/or the `KeyIdentifier` involved.

- Persist key mappings to: TBD

- Permit signers to be async: TBD

- Be robust in case of network delays and errors and problems in external signing services. Retry requests that fail
  due to issues potentially caused by transient network degradation. Re-use TCP+TLS sessions to avoid costly TCP+TLS
  setup and teardown costs per request to the signer service.

- The signer can be in one of three statuses:
  - Proving  - Rather than constantly attempt to "probe" (contact the server and check its capabilities) we track in
               this state when we last probed the server so that we can limit how often we try probing the server.
  - Unusable - Probing was able to contact the server and found it unusable.
  - Usable   - Probing was able to contact the server and found it usable.

## Implementation details

- Connection pooling is handled by the `r2d2` crate.
- Retry and backoff is handled by the `backoff` crate.
- TLS is handled by the `openssl` crate as `rustls` may impose stricter limits on outbound connectivity to HSMs than
  can be pragmatically expected to work in all customer environments.
- TBD: Switch to `tokio-native-tls` to keep the benefits of and control of local O/S native TLS providers and avoid the
  'modern security' limitations of `rustls` while switching to an `async` model.

## Control flow

Prior to the addition of HSM support there was only ever a single Signer and control flow looked like this:

```
Krill calling code -> KrillSigner -> OpenSslSigner
```

With the addition of HSM support there may be multiple concurrently active Signers and the control flow becomes this:

```
Krill calling code -> KrillSigner -> SignerRouter -> SignerProvider -> One of: OpenSslSigner, KmipSigner or Pkcs11Signer.
                                          |                              |
                                          +--------> KeyMapper <---------+
```

_(note: in the current version of the code there is only an in-memory KeyMap used only by the KmipSigner and only ever
 one active Signer impl)_

The SignerRouter either:
- Uses the KeyMapper to determine which Signer owns the KeyIdentifier being used, OR
- Uses internal rules to decide which Signer to invoke (e.g. always generate random values and do one-off signing using
  the OpenSslSigner for example)

The Signers:
- Update the KeyMapper when new keys are created to indicate that this Signer owns the key.
- Store KeyIdentifier to HSM internal key identifier mappings in the KeyMapper.
- Retrieve HSM internal key identifiers from the KeyMapper based on the KeyIdentifier being used.