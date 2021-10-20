# HSM: Architecture

## Why create new KMIP crates?

No well or actively maintained Rust support for KMIP with sufficient functionality for Krill
existed at the time of writing.

The closest candidate, https://github.com/visa/kmip, was used to explore KMIP support in the
Krill HSM prototype code. However, it was decided to create our own KMIP library because the
visa crate:

  - Was not published on crates.io.
  - Had only rudimentary error reporting (as it targets no-std environments).
  - Lacks documentation.
  - Lacked TCP+TLS client support.
  - Lacked support for KMIP operations that Krill requires.
  - Did not appear to be actively maintained or intended for use by others.

## Why not add KMIP code to Krill directly?

The Krill code base is already large enough and slow enough to compile. KMIP support may also
be of interest to others. It thus seemed a good candidate for separation from Krill itself.