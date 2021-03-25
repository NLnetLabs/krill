# Multi-User Feature

Multi-User is a feature both in the sense that it adds the functionality to Krill for enabling
multiple different user identities to login via Lagosta, and in the sense that the functionality
is gated behind a Cargo feature of the same name.

The feature is enabled by default. To disable the feature when building pass the
`--no-default-features` argument to the `cargo build` command.

> NOTE: Login with distinct identities is only supported via Lagosta. The `/auth/` HTTP endpoints
> involved are not documented as part of the Krill REST API. Technically a client _could_ POST to
> them to login and get back a bearer token which could then be used with the REST API, either
> directly or via `krillc`, but it would be cumbersome to do. Proper support for clients with 
> limited interaction capabilities to authenticate with distinct identities should probably be
> implemented in terms of the [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/).

Further reading:

- [Overview](./overview.md)
- [Requirements](./requirements.md)
- [Architecture](./architecture.md)
- [Authentication & Authorization](./authn.md)
- [Testing](./testing.md)