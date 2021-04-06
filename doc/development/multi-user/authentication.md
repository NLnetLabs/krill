# Multi-User: Authentication

## AuthProviders

Authentication is bearer token based. Every `AuthProvider` implements four functions:

```rust
pub trait AuthProvider: Send + Sync {
    /// Given a HTTP request, determine whether it is unauthenticated (Ok(None)), correctly authenticated (Ok(Some)), or
    /// incorrectly authenticated (Err). If it is correctly authenticated the Some value will be an ActorDef stating the
    /// ID and metadata for the end user or client represented by the credentials.
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

`krillc` and direct API clients only use `authenticate()` as they already possess the correct bearer token and only need
to present it to Krill along with each request to authenticate themselves. Their identity and rights are implicitly tied
to their authentication details; that is, we cannot know who they actually are, we only know they are a client in
possession of the master API token and for backward compatibility we grant them the `admin` role.

## Abstracting away AuthProviders for Lagosta

The other three `AuthProvider` functions exist to enable Lagosta to authenticate clients of the Krill web user interface
without needing to know anything about which authentication mechanism is being used. Lagosta doesn't even have any
special knowledge about the master API token based authentication and authorization mechanism. Of course the master API
token login form still exists in Lagosta but Lagosta doesn't direct the user to it itself, it directs the user where
Krill tells it to which is in turn based on `AuthProvider::get_login_url()`.