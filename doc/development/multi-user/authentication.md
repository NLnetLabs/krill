# Multi-User: Authentication

> Authentication is the process of proving that you are who you say you are.<br/>
> _Source: https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-vs-authorization_

Authentication in the context of Krill is the act of determining whether a client of the REST API that claims to be a
particular identity possesses the details needed to confirm that identity. It doesn't actually tell you that the client
**IS** that identity, they could for example be using borrowed or stolen proof to verify their claim.

`AuthProvider` is not named `AuthenticationProvider` because its function overlaps with that of authorization too. The
`AuthProvider` does not make a determination about whether or not a given client is authorized to do something, but it
does supply requested metadata about the authenticated client (when available) which is then used by the
[authorization policy engine](./authorization) to make an authorization determination.

## Abstract 'plugin' interface

The `AuthProvider` Rust trait enables Krill to support different authentication providers without Lagosta needing to
know much about it. We say "much" because if a particular provider implementation requires its own login form and that
login form must be part of Lagosta then clearly the form has to be added to Lagosta. When a login form is part of
Lagosta, submitting the form has to invoke the Krill login REST API, but the form is otherwise self-contained and
nothing else in Lagosta needs to be changed to support a new provider. If the login form is hosted by some external
service such as an OpenID Connect provider then no changes are needed in Lagosta at all to support the new provider!

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

Some `AuthProvider` implementations will use more of the optional function calls in this flow, others less.


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

Prior to multi-user support the Lagosta web user interface only needed to check on page load if the current user has a
valid bearer token and after that could assume that calls to the API would not fail for authentication reasons. With
multi-user support any call to the Krill REST API can fail because the Krill server can expire or terminate the login
session, while previously only Lagosta could terminate a login session.