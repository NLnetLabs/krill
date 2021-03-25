# Multi-User: Authentication

Authentication is bearer token based.

Every `AuthProvider` implements four functions:

```rust
pub trait AuthProvider: Send + Sync {
    fn get_bearer_token(&self, request: &hyper::Request<hyper::Body>) -> Option<Token> {
        ...
        // there's a default implementation here
        ...
    }

    /// Given a HTTP request, return an ActorDef
    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>>;

    fn get_login_url(&self) -> KrillResult<HttpResponse>;

    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser>;

    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse>;
}
```