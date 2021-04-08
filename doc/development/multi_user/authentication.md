# Multi-User: Authentication

> Authentication is the process of proving that you are who you say you are.<br/>
> _Source: https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-vs-authorization_

Authentication in the context of Krill is the act of determining whether a client of the REST API that claims to be a
particular identity possesses the details needed to confirm that identity. It doesn't actually tell you that the client
**IS** that identity, they could for example be using borrowed or stolen proof to verify their claim.

**Contents:**

<!-- generated using gh-md-toc -->

* [Abstract 'plugin' interface](#abstract-plugin-interface)
* [Expected call sequence](#expected-call-sequence)
* [Raising errors](#raising-errors)
* [Impact on Lagosta](#impact-on-lagosta)
* [Interface with Lagosta](#interface-with-lagosta)
* [Stateless providers](#stateless-providers)
    * [MasterTokenAuthProvider](#mastertokenauthprovider)
* [Stateful providers](#stateful-providers)
    * [Storing session state](#storing-session-state)
    * [Protecting sensitive details](#protecting-sensitive-details)
    * [Session caching](#session-caching)
    * [ConfigFileAuthProvider](#configfileauthprovider)
        * [Password management](#password-management)
        * [Modified login form](#modified-login-form)
        * [AuthProvider implementation](#authprovider-implementation)
    * [OpenIDConnectAuthProvider](#openidconnectauthprovider)
        * [Rust crate dependencies](#rust-crate-dependencies)
        * [Security](#security)
        * [Standards](#standards)
        * [Interoperability](#interoperability)
        * [Terminology](#terminology)
        * [Code smell](#code-smell)
        * [Testing](#testing)
        * [Flow](#flow)


## Abstract 'plugin' interface

The `AuthProvider` Rust trait enables Krill to support different authentication providers without Lagosta needing to
know much about it. We say "much" because if a particular provider implementation requires its own login form and that
login form must be part of Lagosta then clearly the form has to be added to Lagosta. When a login form is part of
Lagosta, submitting the form has to invoke the Krill login REST API, but the form is otherwise self-contained and
nothing else in Lagosta needs to be changed to support a new provider. If the login form is hosted by some external
service such as an OpenID Connect provider then no changes are needed in Lagosta at all to support the new provider!

`AuthProvider` is not named `AuthenticationProvider` because its function overlaps with that of authorization too. The
`AuthProvider` does not make a determination about whether or not a given client is authorized to do something, but it
does supply requested metadata about the authenticated client (when available) which is then used by the
[authorization policy engine](./authorization) to make an authorization determination.

The `AuthProvider` defines four functions which every provider must implement:

```rust
pub trait AuthProvider: Send + Sync {
    /// Given a HTTP request, determine whether it is unauthenticated (Ok(None)), correctly authenticated (Ok(Some)), or
    /// incorrectly authenticated (Err). If it is correctly authenticated the Some value will be an ActorDef stating the
    /// ID and metadata for the end user or client represented by the credentials. Typically authentication is performed
    /// by verifying the HTTP `Authorization` header.
    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>>;

    /// Tell the caller where an end user should login. The response body should consist of a URL that the caller should
    /// be (re)directed to (the manner of how the user is sent to the login URL is determined by Lagosta). If the
    /// response URL is relative, Lagosta will treat it as a Vue router path to "redirect" to, otherwise it will direct
    /// the browser to navigate to the specified URL. The AuthProvider can set HTTP response headers if needed, e.g. to
    /// set HTTP cookies.
    fn get_login_url(&self) -> KrillResult<HttpResponse>;

    /// Given a HTTP request, attempt to log the end user in to Krill. On success the result is a representation of
    /// the user to login including a token that when later passed back in to `authenticate()`will be considered valid
    /// by the same AuthProvider that issued it. The result is not an ActorDef but rather only those details that should
    /// be serialized and passed back to Lagosta.
    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser>;

    /// Given a HTTP request, attempt to log the end user out of Krill AND, if possible, out of the provider. The
    /// response body should consist of a URL that the caller should be (re)directed to (the manner of how the user is
    /// sent to the login URL is determined by Lagosta). By returning a HTTP response rather than just a URL, the
    /// AuthProvider implementation has more control without requiring logic specific to the AuthProvider to exist
    /// higher up the call chain, for example to instruct the user agent to delete provider specific cookies.
    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse>;
}
```

## Expected call sequence

The expected flow through the `AuthProvider` functions is as follows:

  1. (optional) A client requests via `get_login_url()` the URL at which the end user can submit their login
     credentials. This URL may contain query parameters that differ from one login attempt to the next and so must not
     be fetched once and cached at the caller.

  2. (optional) A client presents the credentials of an end user to `login()` which on success results in `LoggedInUser`
     details being returned. The `LoggedInUser` includes a token to be used provided by the client on subsequent calls
     to the Krill REST API and which will be validated by `authenticate()`. It also contains details about the logged in
     user for display purposes (these details are NOT used for any authentication or authorization, they are purely
     for display purposes).

  3. (required) A client presents its authentication token (either already known to the client or previously obtained by
     a call to `login()`) for verification. On success an `ActorDef` representing the clients identity and associated
     metadata is returned to the caller. These details can then be used by Krill to make an authorization determination.

  4. (optional) A client invokes `logout()` to terminate the provider login session, if any such session state is being
     managed by Krill.

Some `AuthProvider` implementations will use more of/do more in the optional function calls in this flow, others less.


## Raising errors

Krill exposes errors to REST API clients in a structured JSON format which can be used by the client to select the
appropriate language specific template string and to populate it where relevant with values specific to the issue.

The multi-user feature builds on this ability by adding a few new variants of the Krill Error type which are mapped to
the following HTTP status codes:

Error Variant | HTTP Status Code
--------------|-----------------
`ApiInsufficientRights(String)` | 403 Forbidden **(see note below)**
`ApiInvalidCredentials(String)` | 401 Unauthorized
`ApiAuthPermanentError(String)` | 401 Unauthorized
`ApiAuthSessionExpired(String)` | 401 Unauthorized
`ApiAuthTransientError(String)` | 401 Unauthorized
`ApiLoginError(String)`         | 401 Unauthorized

**Note:** `ApiInsufficientRights` is included here for completeness but is never raised by an `AuthProvider` as they
do not handle authorization.

## Impact on Lagosta

Prior to multi-user support the Lagosta web user interface only needed to check on Vue "view" activation if the current
user has a valid bearer token and after that could assume that calls to the API would not fail for authentication
reasons. With multi-user support any call to the Krill REST API can fail because the Krill server can expire or
terminate the login session, while previously only Lagosta could terminate a login session.

Lagosta has not been redesigned for multi-user support, instead it has been grafted on top with as few changes as
possible. One consequence of this is that Lagosta still checks if the user is "authorized" on every Vue "view"
activation which in turn causes an authentication failure when the UI is initially browsed to by an end user. Rather
than pollute the Krill log with a warning every time a user loads the UI we treat these failures when invoking the
`/api/authorized` endpoint as benign and deliberately do not log them as warnings.

## Interface with Lagosta

If we look at Krill upto and including v0.8.2, the interface with Lagosta was extremely simple:
  - The Lagosta login form would store the given API token in browser storage and then attempt to visit the welcome page
    of the UI.
  - Every Vue "view" load would make a call to the Krill `GET /api/v1/authorized` endpoint passing the stored API token
    in the `Authorize: bearer xxx` HTTP request header.
  - Krill would then compare the API token string to the one it was configured with and respond with success or failure.

That was it. No login, no logout, no login form discovery, no OpenID Connect callback handler and no receipt, use or
storage of user identity or metadata.

The API that Lagosta now uses to login and logout of Krill is not part of the publically documented Krill API. The
essence of it (taken from `daemon/http/auth.rs`) is:

```rust
pub async fn auth(req: Request) -> RoutingResult {
    match req.path.full() {
        #[cfg(feature = "multi-user")]
        "/auth/callback" if *req.method() == Method::GET => {
            req.login()
                .await
                .and_then(|user| {
                    Ok(build_auth_redirect_location(user).map_err(|err| {
                        Error::custom(format!(
                            "Unable to build redirect with logged in user details: {:?}",
                            err
                        ))
                    })?)
                })
                .map(|location| HttpResponse::found(&location))
                .or_else(render_error_redirect)
        }
        "/auth/login" if *req.method() == Method::GET => req.get_login_url().await.or_else(render_error),
        "/auth/login" if *req.method() == Method::POST => match req.login().await {
            Ok(logged_in_user) => Ok(HttpResponse::json(&logged_in_user)),
            Err(err) => render_error(err),
        },
        "/auth/logout" if *req.method() == Method::POST => req.logout().await.or_else(render_error),
        _ => Err(req),
    }
}
```

These endpoints map on to and are routed to the four functions each `AuthProvider` has to implement.

Firstly, notice that the "GET /auth/callback" endpoint is not handled unless the multi-user feature is enabled. This is
because this endpoint is only needed by the OpenID Connect provider.

The "POST /auth/login" endpoint is roughly equivalent to what was done in Krill v0.8.2 and earlier. It is a POST
endpoint now rather than GET because login can have side-effects, e.g. it could cause Krill to make changes to its
internal state _(in actual fact all of the `AuthProvider` implementations are currently stateless on the Krill
server-side)_.

## Stateless providers

### `MasterTokenAuthProvider`

This is the default provider which is backward compatible with earlier versions of Krill. It is an extremely simple
provider. The essence of this provider implementation can be reduced to something like the following (based on
`daemon/auth/providers/master_token.rs`):

Login and post-logout-redirect URLs are hard-coded, and logout doesn't actually do anything.

```rust
impl AuthProvider for MasterTokenAuthProvider {
    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        Ok(HttpResponse::text_no_cache("/login"))
    }

    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        Ok(HttpResponse::text_no_cache("/"))
    }
}
```

Authenticating a request simply checks if it the given bearer token matches the master API token Krill has been
configured with:

```rust
impl AuthProvider for MasterTokenAuthProvider {
    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        match self.get_bearer_token(request) {
            Some(token) if token == self.required_token => Ok(Some(ACTOR_DEF_MASTER_TOKEN)),
            Some(_) => Err(Error::ApiInvalidCredentials("Invalid bearer token".to_string())),
            None => Ok(None),
        }
    }
```

And as there are no other credentials such as a password to check, login verification is the same as authentication. The
only extra piece is that login is for the UI and the UI wants to know the users ID and any attributes they have so these
are packaged up and returned to the caller:

```rust
impl AuthProvider for MasterTokenAuthProvider {
    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        match self.authenticate(request)? {
            Some(actor_def) => Ok(LoggedInUser {
                token: self.required_token.clone(),
                id: actor_def.name.as_str().to_string(),
                attributes: actor_def.attributes.as_map(),
            }),
            None => Err(Error::ApiInvalidCredentials("Missing bearer token".to_string())),
        }
    }
```

Note that the hard-coded URL responses are marked as uncacheable. This is important because if we later reconfigure this
Krill instance to use a different auth provider, the same requests will be made by Lagosta and thus if the responses
were cached the users browser might used cached responses from the previous provider instead of contacting Krill again
to get responses from the new provider.

## Stateful providers


### Storing session state

Unlike with the `MasterTokenAuthProvider` where the user identity and attributes are implicitly "master-token" and
"role=admin" respectively, the `ConfigFileAuthProvider` and `OpenIDConnectAuthProvider` cannot know the identity and
user attributes from an arbitrary bearer token. They need therefore to store these details somewhere.

The details could be kept in an in-memory mapping of issued tokens to user details but this wouldn't work in future if
we want to support distributed Krill deployment scenarios. We could store the data in a key value store on disk and 
cache it in memory as Krill does with other data. Any changes required later to support distributing the current key
value store would also then work for the login session state as well. 

Instead the current approach avoids the distributed Krill deployment scenario problems almost entirely by storing the
session state in the client browser. This is done by creating an en/decryption key on startup and storing it on disk and
using this key to en/decrypt a structured bearer token that contains the session details. The only thing clustered Krill
servers would need to share then would be the en/decryption key file.

### Protecting sensitive details

Why encrypt the data when the connection to the client browser should already be TLS encrypted? The data we send inside
the bearer token is stored by the browser in local storage which is vulnerable, especially on a shared computer. The 
data is opaque to the Krill web user interface, it does not read or interpret it, it only sends it back as a bearer
token to Krill on subsequent requests to the Krill REST API.

In the OpenIDConnectAuthProvider case we also need to remember a sensitive access token issued by the provider. That 
token [must not be leaked to unauthorized parties](https://openid.net/specs/openid-connect-core-1_0.html#AccessTokenDisclosure).
User attributes that are used for authorization but marked as "hidden" so that they are not displayed by the Krill web
user interface in the client browser are also part of the encrypted structured bearer token and could potentially contain sensistive information.

As such we use the encrypted structured bearer token approach for both the `ConfigFileAuthProvider` and the
`OpenIDConnectAuthProvider`.

### Session caching

As browsers can make multiple requests in parallel or in short succession (e.g. for static assets) and every HTTP
request is checked for the authentication, it could be wasteful and possibly impacting if Krill has to repeatedly base64
decode, decrypt and JSON deserialize the same bearer token over and over again. The results of this process are
therefore stored in an in-memory "cache" in the Krill server. As the content of the bearer token may contain sensitive
details and thus should not be stored for longer than necessary, and as the cache is only intended to assist with short
bursts of activity, the cache is therefore very short lived. The cache is implemented by
`daemon::auth::common::session::LoginSessionCache`. A Krill scheduled job sweeps the cache periodically to evict expired
entries.

### `ConfigFileAuthProvider`

This provider is instantiated if `krill.conf` contains `auth_type = "config-file"`. This `AuthProvider` supports the 
definition of arbitrary user identities each with their own metadata by adding TOML keys to an `[auth_users]` section in 
`krill.conf`.

#### Password management

As storing passwords is a security risk we instead store password hashes.

We considered using the popular Apache `.htpasswd` format but unfortunately it either uses insecure SHA1, or
[non-standard MD5](https://httpd.apache.org/docs/current/misc/password_encryptions.html) or would require additional
crate dependencies to support bcrypt or Linux crypt, and even then would only be useful if the operator already had the
Apache tooling installed to be able to work with `.htpasswd` files. Also any hash also needs to be computable by the
Lagosta web user interface client code from a password entered by the user as avoiding transmiting passwords also
reduces the attack surface.

So, instead `krillc` has been extended with a `config user` subcommand to generate hex encoded SHA-256 hashes and
Lagosta uses the [CryptoJS library](https://www.npmjs.com/package/crypto-js) to SHA-256 hash the given password.
The hex encoding ensures the produced hash is the same as produced by CryptoJS.

#### Modified login form

The standard login view built-in to Lagosta at `/login` only has a single input field for the master API token. This has
been extended so that when invoked as `/login?withId=true` it will instead show username and password input fields. When
the `GET /auth/login` Krill endpoint is queried by Lagosta to determine the login URL to use,
`ConfigFileAuthProvider::get_login_url()` responds with `/login?withId=true` to cause this modified login form to be
shown to the user.

#### AuthProvider implementation

The actual implementation is quite simple and similar to that of the `MasterTokenAuthProvider`. The essence of this
provider implementation can be reduced to something like the following (based on
`daemon/auth/providers/config_file/provider.rs`):

Login and post-logout-redirect URLs are hard-coded. Logout evicts the session from the cache, though it would quickly
expire anyway:

```rust
impl AuthProvider for ConfigFileAuthProvider {
    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        Ok(HttpResponse::text_no_cache("/login?withId=true"))
    }

    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        if let Some(token) = self.get_bearer_token(request) {
            self.session_cache.remove(&token);
        }

        Ok(HttpResponse::text_no_cache("/"))
    }
}
```
Authenticating a request checks if the given bearer token can be fetched from the cache, or otherwise can be decoded,
decrypted and deserialized and stored in the cache:

```rust
impl AuthProvider for ConfigFileAuthProvider {
    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        match self.get_bearer_token(request) {
            Some(token) => {
                let session = self.session_cache.decode(token, &self.key, true)?;
                Ok(Some(ActorDef::user(session.id, session.attributes, None)))
            }
            _None_ => Ok(None),
        }
    }
```

Login checks for the required id and password hash query parameters, looks up the user in the users that were loaded on
startup from `krill.conf` and creates and caches a session object based on the users detailsm and returns the generated
token and user details to the `Authorizer` for eventual transmission back to Lagosta as JSON:

```rust
impl AuthProvider for ConfigFileAuthProvider {
    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        if let Some(Auth::IdAndPasswordHash { id, password_hash }) = self.get_auth(request) {
            if let Some(user) = self.users.get(&id) {
                if user.password_hash == password_hash {
                    let api_token =
                        self.session_cache
                            .encode(&id, &user.attributes, HashMap::new(), &self.key, None)?;

                    Ok(LoggedInUser {
                        token: api_token,
                        id: id.to_string(),
                        attributes: user.attributes.clone(),
                    })
                }
            }
        }
    }
```

### `OpenIDConnectAuthProvider`

This provider is instantiated if `krill.conf` contains `auth_type = "openid-connect"`. This `AuthProvider` supports
connecting to an external OpenID Connect Core 1.0 compliant identity provider to authenticate users and provide user
metadata on our behalf.

#### Rust crate dependencies

The core client implementation is provided by the
[openidconnect v2](https://crates.io/crates/openidconnect/2.0.0-beta.1) Rust crate which in turn builds on the
[oauth2 v4](https://crates.io/crates/oauth2/4.0.0-beta.1) crate (both by the same author). We use these newest (and at
the time of writing not yet finally released) versions as they are based on newer dependencies, contain support for
OAuth 2.0 Token Revocation (which I contributed) and better error reporting, and these versions despite being new have
been stable for quite some time.

Additional dependencies are added for HTTP cookie parsing, JMESPath, regular expressions, URL parsing, etc. See also
[Krill issue #428](https://github.com/NLnetLabs/krill/issues/428) concerning a second `reqwest` dependency.

#### Security

There are LOTS of documents about OAuth 2.0, bearer token and OpenID Connect security and things you should or shouldn't
do. Reviewing the current implementation against these is yet to be done.

_**Note:** Encrypted payload based communication with the OP is not currently supported._

#### Standards

- OAuth 2.0 standardizes authentication but says nothing about identity.
- OpenID Connect Core 1.0 standardizes identity on top of OAuth 2.0 but requires a lot of client side configuration and
  says nothing about logout.
- OpenID Connect Discovery 1.0 solves the configuration problem by standardizing a provider endpoint which can be used
  to greatly reduce the amount of client side configuration required.
- Various OpenID Connect drafts attempt to standardize login sessions and various logout mechanisms.
- Some providers lack support for a standardized logout mechanism but do support the OAuth 2.0 Token Revocation
  standard.

This provider implements the following standards:

- [RFC 6749 The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7009 OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0 (DRAFT)](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

Where the standards define optional elements, only support for those needed thus far have been implemented.

#### Interoperability

This implementation has been seen to work without any known issues with Micorosft Azure Active Directory, AWS Cognito,
RedHat KeyCloak, Google Cloud Platform and Micro Focus NetIQ Access Manager 4.5.

#### Terminology

The OAuth 2.0 and OpenID Connect Core specifications define terms which have the following meaning in the context of
Krill:

| OAuth 2.0 Term | OpenID Connect Term | Meaning in Krill |
|---|---|---|
| Authorization Server | OpenID Provider (OP) | Remote OpenID Connect Core 1.0 compliant identity provider service. |
| Client | Relying Party (RP) | The Krill server. |
| Resource Owner | End-User | End-user interacting with the Lagosta web user interface. |
| Resource Server | N/A | We do not access resources of the provider, we only use it for authentication & identity. |
| User-Agent | User-Agent | The browser running the Lagosta web user interface. |

#### Code smell

In no particular order:

- The terminology used by the specificaitons is **NOT** used, or not used consistently, in the Rust code
  implementation in Krill.
- There are lots of possibly out-dated comments in the code which need reviewing and updating or removing.
- The core `provider.rs` source code file is too large.
- There are likely opportunities to simplify and make the code more Rust idiomatic.
- There are very few comments on the structs and functions.
- There are no unit tests (there are however LOTS of 'integration' tests).

#### Testing

Testing the provider code in isolation cannot ensure that the chain of communication from Lagosta
via Krill to the OP and back again works as expected and yields an acceptable end user experience. Therefore the
majority of the tests use Cypress to drive Lagosta in a browser connected to an instance of Krill which in turn connects
to a locally deployed mock OP.
#### Flow

This implementation supports the [OpenID Connect Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) 
which builds on the [OAuth 2.0 Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1) flow.

Before any of that can happen however three things must first happen:

1. The instance of Krill must be registered with the OP, resulting in client credentials and an issuer URL.
2. The discovery issuer URL of the OP and the issued client credentials must be configured in the `krill.conf` file.
3. The `krill.conf` file and the OP must be suitably configured to permit users access to and grant them a role in
   Krill.

Once these have been properly setup the "login" flow according to RFC 6749 looks like this (with Krill specific
annotations added in parentheses):

```
4.1.  Authorization Code Grant

   The authorization code grant type is used to obtain both access
   tokens and refresh tokens and is optimized for confidential clients.
   Since this is a redirection-based flow, the client must be capable of
   interacting with the resource owner's user-agent (typically a web
   browser) and capable of receiving incoming requests (via redirection)
   from the authorization server.

     +----------+
     | Resource |
     |   Owner  |
     |(End-User)|
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent  -+----(B)-- User authenticates --->|     Server    |
     | (Lagosta)|                                 |    (OpenID    |
     |         -+----(C)-- Authorization Code ---<|    Provider)  |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     | (Krill) |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)

   Note: The lines illustrating steps (A), (B), and (C) are broken into
   two parts as they pass through the user-agent.

                     Figure 3: Authorization Code Flow
```

[RFC 6749 section 4.1](https://tools.ietf.org/html/rfc6749#section-4.1) goes into a lot of detail about what happens at
each step. The OpenID Connect Core 1.0 specification summarizes this more succinctly (and more relevant to us) as (with
letters referencing the diagram above added by me in parantheses)

> 3.1.1.  Authorization Code Flow Steps
>
> The Authorization Code Flow goes through the following steps.
> 
> 1. Client prepares an Authentication Request containing the desired request parameters. (A)
> 2. Client sends the request to the Authorization Server. (A)
> 3. Authorization Server Authenticates the End-User. (B)
> 4. Authorization Server obtains End-User Consent/Authorization. (B)
> 5. Authorization Server sends the End-User back to the Client with an Authorization Code. (C)
> 6. Client requests a response using the Authorization Code at the Token Endpoint. (D)
> 7. Client receives a response that contains an ID Token and Access Token in the response body. (E)
> 8. Client validates the ID token and retrieves the End-User's Subject Identifier.

#### Architecture

The current implementation handles concurrent requests by making onward requests to the OP in the same thread as the 
caller. There is no centralized management or queueing of requests and thus not rate limiting or deduplication of
requests (e.g. multiple requests for static assets from the user-agent causing multiple concurrent requests to the OP to
refresh an expiring or expired access token).

Diagnosing problems and handling errors from the provider may involve logging sensitive or complex details such as
access tokens or entire request/response exchanges with the OP. The implementation endeavours to hide this complexity
from the end user while still giving them meaningful errors in the Lagosta web user interface.

