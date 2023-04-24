# Multi-User: Overview

## New or changed functionality

The feature adds several related but distinct capabilities to Krill:
  - Pluggable authentication:
    - Changes the interface with Lagosta
    - Three "plugins" so far:
      - Admin API Token
      - Config File Users
      - OpenID Connect _(powered by [openidconnect-rs](https://crates.io/crates/openidconnect))_, including:
        - A mock OpenID Connect server for testing
        - JMESPath based claim selection _(powered by [jmespatch](https://crates.io/crates/jmespatch))_
        - Custom JMESPath regular expression functions
    
  - Authorization, including:
    - Identity
    - Permissions
    - Roles
    - Policy _(powered on [Oso](https://crates.io/crates/oso))_
  
  - Stateless login sessions via support for rich bearer tokens, including:
    - Caching
    - (De)Serialization
    - (En/De)cryption _(powered by [rust-openssl](https://crates.io/crates/openssl))_
  
  - Password hashing support in `krillc`
  
  - Propagation of the current identity all the way down to the event history

It also required changes in Lagosta to:
  - Support the modified interface with Krill
  - Display user attributes (e.g. ID, role, etc)
  - Check for and handle errors in many more situations
  - Actively logout with Krill, don't just forget the token

## Impacted source components

The feature only lightly touches the core RPKI related code in Krill in order to propagate the
current actor details. The main source code components impacted by this feature are:

  - ``src/daemon/auth/``
  - ``src/daemon/http/``
  - ``src/daemon/config.rs``
  - ``src/daemon/krillserver.rs``
  - ``src/daemon/scheduler.rs``
  - ``src/lagosta/``
  - ``src/test-resources/ui/``
  - ``src/tests/multi_user_*.rs``
  - ``src/tests/ui/``