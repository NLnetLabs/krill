# Multi-User: Architecture

## Key architectural decisions

  - Don't add to the state stored by the server as that will complicate later efforts to run Krill as a distributed
    service. Instead be stateless by storing (encrypted) session state on the client.

  - Use a "plugin" style model but only internally in the code, be able to support more identity providers later
    if wanted, but FFI to an actual separately loaded dynamic libraries was considered unnecessary overkill with
    downsides.

  - Don't roll our own OpenID Connect client code if there's an existing suitable Rust crate we can use instead.

## Primary components & flow

Multi-user support centres on four key components in Krill: `Authorizer`, `Actor`, `AuthPolicy` and `AuthProvider`.

The `Authorizer` sits at the middle of the web. It owns the `AuthProvider` instance(s) and the `AuthPolicy`. It is also
the sole issuer of `Actor` instances.

All command events are attributed to the `.name()` of an `Actor`, thus all internal
actions performed by Krill require an `Actor` instance which must be obtained from
the `Authorizer`.

`Actor` instances are obtained from the `Authorizer` in one of two ways:

  - By calling `.authenticate()` to authenticate an HTTP request.
  - By calling `.actor_from_def()` to obtain a representation of one of the built-in actors.

Authentication is delegated by the `Authorizer` to an `AuthProvder` which is a trait with three implementations:

- `MasterTokenAuthProvider`
- `ConfigFileAuthProvider`
- `OpenIDConnectAuthProvider`

Authorization is done by calling through `Actor::is_allowed(action, resource)` to a shared reference to the `AuthPolicy` which in turn delegates to [Oso](https://crates.io/crates/oso).
## Authentication

There is *always* an instance of `MasterTokenAuthProvider` because it is required to authenticate direct REST API calls
and indirect REST API calls (via `krillc`) which use the master API token to authenticate.

If the configured provider (via `auth_type = "..."` in `krill.conf`) is `config-file` or `openid-connect` there will
also be an instance of `ConfigFileAuthProvider` or `OpenIDConnectAuthProvider` respectively.

The `Authorizer` asks the `MasterTokenAuthProvider` to attempt to authenticate a request first, if that fails and there
is another `AuthProvider` that is then asked to authenticate.

The `MasterTokenAuthProvider` is tried first because:

  - The check it performs is quick and cheap (simple string comparison) while the `OpenIDConnectAuthProvider` has to
    base64 decode, decrypt and deserialize the bearer token (although it has a v short lived cache to minimize the impact
    of bursts of parallel requests from the user agent), and
  - It can only fail in very simple ways, while it can be hard to know for a given error from the
    `OpenIDConnectAuthProvider` whether or not it should be a hard failure or if it would be okay to try the
    `MasterTokenAuthProvider` as a fallback.

## Debatable design choices

A couple of design properties that emerged and that should perhaps be revisited are:

  - Requests to the `OpenIDConnectAuthProvider` are handled in parallel, which can cause bursts of connectivity to the
    actual 3rd party OpenID Connect provider. It might make sense to use some sort of queue being serviced by workers to
    avoid this.

  - The AuthProviders are `sync` code while a lot of Krill is now `async` code.

  - There's a second `reqwest` dependency because using the main v0.10 `reqwest` dependency in the
    `OpenIDConnectAuthProvider` caused panics from its use of an internal async Tokio loop wrapper around its
    synchronous client implementation, while in earlier versions of `reqwest` the sychronous client is actually
    synchronous code.
    
  - Switching to the `async` `reqwest` client would require working around the problem that
    Rust `async` traits are not yet supported unless you use the `async_trait` crate.

  - If we continue to bundle more and more "plugin" implementations into Krill it will gain more and more crate
    dependencies, will increase in size, in compile time and test execution time. The more plugins that are added
    the more the separate FFI plugin dynamic library model might make sense.

  - The term "resource" in authorization was inherited from Oso but clashes with the arguably more important (for Krill)
    RPKI meaning of the term "resource".