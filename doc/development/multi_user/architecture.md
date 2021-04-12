# Multi-User: Architecture

**Contents:**
  * [Key architectural decisions](#key-architectural-decisions)
  * [Primary components &amp; flow](#primary-components--flow)
  * [Authentication](#authentication)
  * [ActorDef vs Actor vs LoggedInUser](#actordef-vs-actor-vs-loggedinuser)
  * [Built-in Actors](#built-in-actors)
  * [Debatable design choices](#debatable-design-choices)

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

  - By calling `.actor_from_request()` to authenticate an HTTP request.
  - By calling `.actor_from_def()` to obtain a representation of one of the built-in actors. This is only used by
    `KrillServer` to obtain the internal Krill actor to attribute internal Krill actions to, and by the testbuid API to
    upgrade an anonymous actor to a special `testbed` actor.


Authentication is delegated by the `Authorizer` to an `AuthProvder` which is a trait with three implementations:

- `MasterTokenAuthProvider`
- `ConfigFileAuthProvider`
- `OpenIDConnectAuthProvider`

Authorization is done by calling through `Actor::is_allowed(action, resource)` to a shared reference to the `AuthPolicy` which in turn delegates to [Oso](https://crates.io/crates/oso).

## Authentication

There is *always* an instance of `MasterTokenAuthProvider` because it is required to authenticate direct REST API calls
and indirect REST API calls (via `krillc`) which use the master API token to authenticate. If the configured provider
(via `auth_type = "..."` in `krill.conf`) is `config-file` or `openid-connect` there will also be an instance of
`ConfigFileAuthProvider` or `OpenIDConnectAuthProvider` respectively.

The `Authorizer` asks the `MasterTokenAuthProvider` to attempt to authenticate a request first, if that fails and there
is another `AuthProvider` that is then asked to authenticate. The `MasterTokenAuthProvider` is tried first because:

  - The check it performs is quick and cheap (simple string comparison) while the `OpenIDConnectAuthProvider` has to
    base64 decode, decrypt and deserialize the bearer token (although it has a v short lived cache to minimize the
    impact of bursts of parallel requests from the user agent), and
  - It can only fail in very simple ways, while it can be hard to know for a given error from the
    `OpenIDConnectAuthProvider` whether or not it should be a hard failure or if it would be okay to try the
    `MasterTokenAuthProvider` as a fallback.

## ActorDef vs Actor vs LoggedInUser

A deliberate separation exists that is worth mentioning: `ActorDef` vs `Actor` vs `LoggedInUser`.

`AuthProvider` implementations return `Result<Option<ActorDef>>` from `authenticate()` to indicate either:

  - `Ok(None)` if no credentials were found, OR
  - `Ok(Some<ActorDef>)` if the credentials were good, OR
  - `Err` if credentials were present but incorrect.

An `ActorDef` defines what an actor could look like but is not an instance of `Actor`. It is returned instead of `Actor`
because only the `Authorizer` is allowed to create `Actor` instances. The `AuthProvider` therefore indicates the kind of
`Actor` that could be created if the `Authorizer` permits it.

`AuthProvider` implementations return `Result<LoggedInUser>` from `login()`. We could possibly return an `ActorDef` here
but the `LoggedInUser` type is returned instead as its purposely limited to contain only information about the logged in
user which is needed by Lagosta. Unlike `ActorDef` the type is also therefore serializable.

In both the `authenticate()` and `login()` cases the `Authorizer` does any additional checks required (e.g. checks with
the Oso [authorization](./authorization.md) policy engine if the user has the `LOGIN` permission) and only then accepts
the recommendation of the `AuthProvider`. This is especially important in the OpenID Connect case because a corporate
employee will be able to login to the central identity provider at their organization but that is not the same as saying
that all 10,000 employees should have the right to login to Krill.
## Built-in Actors

There are currently four built-in actors, which for convenience have entries in `constants.rs`: _(ordered from most to
least powerful)_

Actor | Represents | Role | Comments
------|------------|------|----------
`ACTOR_DEF_KRILL` | Krill itself | `admin` | Used for initial startup and scheduled actions that are not directlyattributable to a REST API client.
`ACTOR_DEF_MASTER_TOKEN` | A client using the master API token | `admin` | Used by the users of Lagosta when `auth_type = "master-token"` (the default), or by direct clients of the REST API, or indirect clients of the REST API via `krillc`. |
`ACTOR_DEF_TESTBED` | An anonmymous client of the testbed | `testbed` (temporarily) | Used by the testbed REST API handler functions to make internal requests to restricted APIs on the behalf of the anonymous client. See `Request::upgrade_from_anonymous`. |
`ACTOR_DEF_ANON` | An anonymous client | None | Used for REST API calls that lack credentials or for which an error occurs during authentication. By still having an actor even in this case we can handle all API calls the same way. The anonymous actor has no role and so, unless overriden by a custom authorization policy, has no rights in Krill. It can thus only successfully request REST API endpoints that do not require authentication. |

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