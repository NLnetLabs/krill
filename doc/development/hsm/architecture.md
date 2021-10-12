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
                                          +-------> SignerMapper <-------+
```

The SignerRouter either:
- Uses the SignerMapper to determine which Signer owns the KeyIdentifier being used, OR
- Uses internal rules to decide which Signer to invoke (e.g. always generate random values and do one-off signing using
  the OpenSslSigner for example)

The Signers:
- Update the SignerMapper when new keys are created to indicate that this Signer owns the key.
- Store KeyIdentifier to HSM internal key identifier mappings in the SignerMapper.
- Retrieve HSM internal key identifiers from the SignerMapper based on the KeyIdentifier being used.

The SignerRouter also manages signer instances based on configuration settings:
  (note: in the current version the configuration is hard-coded)
- Create instances of the appropriate signers (structs that implement the Signer trait) based on configuration.
- On attempts to use signers:
  1. Bind all pending signers.
  2. Select the appropriate signer for the request.
  3. Delegate to the signer, if bound.

Binding of signers is done by cryptographically connecting the signer configuration/backend to the SignerMapper stored
keys:
- Created signers have a reference to the `SignerMapper` and an uninitialized `Handle`.
- Created signers are added to an in-memory collection of "pending" signers in the `SignerRouter`.
- When the `SignerRouter` receives a signing request, when no signers previously existed:
  - For each pending signer request that it create a key pair. If it is not yet contactable we will try again later.
  - Combine the string forms of the KeyIdentifier from the public key and the signer internal id of the private half of
    the key and use that as a "handle" for the newly created signer. This proves that we can connect to the signer and
    use it and that it can create RSA key pairs.
  - Verify that the signer is able to correctly sign a given challenge string such that verification of the created
    signature using the public key works. This proves that the signer can perform signing operations and that the 
    created signatures are valid.
  - Add a `SignerInfo` to the `SignerMapper` internal `AggregateStore` using the new signer handle, and store the entire
    created public key as metadata attached to the `SignerInfo`. We also attach at this point any details about the
    signer backend, e.g. type, vendor, FQDN and port number (for KMIP) or path on disk (for OpenSSL) etc.
  - Tell the `Signer` instance the `Handle` it should use with the `SignerMapper` reference it has to lookup existing
    keys and record new keys. The `SignerMapper` store is located on disk as a `signers` subdirectory under the Krill
    data directory.
  - Remove the signer from the pending collection.

On subsequent restarts of Krill:
- When the `SignerRouter` receives a signing request and signers previously existed:
  - For each `SignerInfo` `Handle` stored in the `SignerMapper` extract the signer internal private key id from the
    `Handle` and ask the signer to sign a challenge string using the specified private key.
    - If we can't contact the signer at this point we will try again later.
    - If we can contact the signer and it doesn't know the private key id then this signer configuration/signe
      instance is not associated with this `SignerInfo` `Handle` and key store.
    - If the signer returns signed data, verify it using the public key stored with this `Handle` `SignerInfo`. If
      the verification fails it might be that the signer used simple internal key ids (e.g. PyKMIP uses ascending
      integer numbers) and so we accidentally found the "right" key but this isn't the right signer.
    - Otherwise this is the right signer so tell the `Signer` instance the `Handle` it should use with the
     `SignerMapper` reference that it has.
     - We also record a "name" metadata property with each `SignerInfo`. If the name and/or signer backend details
       have changed then they are updated in the `SignerStore` 
    - Remove the signer from the pending collection.

This gives us verified connections and confirmation of capability in a standard way irrespective of signer type,
between the configuration specified by an operator and the actual signer backend such as a local OpenSSL key store or
a "remote" PKCS#11 or KMIP HSM service. The operator can rename the instance without impacting the mapping and
doesn't need to manage a signer specific identifier correctly, and we can correctly route signing requests to the
right signer without knowing anything about how to relate the configuration to the actual signer backend. If the
operator replaces a HSM server and restores data from backup and the new one is on a different IP address and/or
uses different authentication credentials we can work out for ourself which existing keys it should be used with.
If the operator connects a new HSM not used by this Krill instance before, even if used by a different Krill instance,
we can use it. We're also capable of using HSMs when they come online without blocking the operation of Krill.

If we were to also drop signers from the active set when they are unreachable we could automagically migrate from
a live HSM to a cold spare (assuming the spare has most of the data from the live HSM, in particular the "registration"
key that we created).

No connection details or secrets are stored in the `SignerInfo` store. If later the `AggregateStore` mechanism is
upgraded to work with some central key value store service used between multiple Krill instances then each Krill
instance could have its own connection details and secrets and connect to separate HSMs in a cluster and both
think that they are talking to the same "signer" because of the presence of the "registration" signing key in
both HSM nodes and the public half being available to both Krill nodes via the central KV store.