# HSM: Overview

## New or changed functionality

The feature adds (or will add) the following to Krill:
  - Pluggable signers:
    - Three "plugins":
      - Host file-based OpenSSL key management & signing
      - [PKCS#11](https://www.cryptsoft.com/pkcs11doc/) dynamic library support
      - [Key Management Interoperability Protocol (KMIP)](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip) support
        - Partial support for KMIP 1.0-1.2 (signing was introduced in 1.2)
        - TTLV over TLS only, no XML/JSON over HTTPS
    
  - Key ownership tracking:
    - To sign with a key the request must be delegated to the correct signer.
    - Therefore we must keep track of which signer "owns" each key.

  - Signer tracking:
    - To delegate a request to the correct signer we must know which signer "instance" corresponds to which signer
      "configuration".

  - Random value generation fallback support:
    - Not all PKCS#11 or KMIP compatible devices support generating random values.
    - Fallback in such cases to the OpenSSL signer (or to a user specified signer?)

  - The concept of signing with specific signers for specific purposes:
    - Signer for one-time keys (avoid slow HSMs for keys that don't need the security guarantees an HSM provides)
    - Signer for new keys
    - Signer for existing keys (based on key tracking as mentioned above)
    - Signer for key rollover
    - Signer for fallback random value generation

The feature also adds two new Rust crates for KMIP support:
  - https://github.com/NLnetLabs/kmip-protocol (https://crates.io/crates/kmip-protocol)
    - High level TCP+TLS client for (de)serializing and reading/writing KMIP 1.0-1.2 responses/requests.

  - https://github.com/NLnetLabs/kmip-ttlv (https://crates.io/crates/kmip-ttlv)
    - Low level (de)serialization of the KMIP TTLV binary encoding.

## Impacted source components

The feature only lightly touches the core RPKI related code in Krill in order to dispatch signing
related requests to the correct signer. The main source code components impacted by this feature are:

  - ``src/daemon/crypto/signing.rs``
