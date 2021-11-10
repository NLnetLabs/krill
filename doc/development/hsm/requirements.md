# HSM: Requirements

The primary initial requirements that influenced the architecture were:

  - Support for key creation, deletion, signing using HSMs via two standard protocols:
    - [PKCS#11](https://www.cryptsoft.com/pkcs11doc/)
    - [Key Management Interoperability Protocol (KMIP)](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip)

Further analysis extended & refined these requirements such that:
  - Krill `Signer` implementations also support random number generation, so possibly support that via HSMs too.
  - PKCS#11 v2.20 is the most widely deployed version thus we should target that.
  - KMIP didn't support signing until v1.2 so target that.
  - KMIP v1.0 supported only TCP+TLS+TTLV where TTLV is a custom binary wire format defined by the KMIP specification. Later KMIP versions added support for HTTPS, XML and JSON, but only TCP+TLS+TTLV is mandatory for all KMIP servers. Therefore we should support TCP+TLS+TTLV.