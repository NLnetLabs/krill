# Multi-User: Authorization

> Authorization is the act of granting an authenticated party permission to do something.<br/>
> _Source: https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-vs-authorization_


## Where is authorization applied?

The `Authorizer` is responsible for authorization but delegates the responsibility to two other components:

  - An instance of `AuthPolicy` which it owns.
  - An instance of `Actor` which it created and to which it gave a reference to the `AuthPolicy`.

## When is authorization applied?

When a Krill `Actor` needs to perform some action on some resource, we ask the `Actor` if it
`is_allowed(permission, resource)`. The `Actor` then asks the `AuthPolicy` to decide if the requested action is allowed
by the actor on the resource.

Most calls to `Actor::is_allowed()` happen in the Krill REST API handler functions. In some cases the API call cannot be
rejected or permitted outright but instead the values included in the response are filtered based on the rights of the
caller. In such cases calls to `Actor::is_allowed()` occur deeper within Krill, e.g. when listing the CAs which exist a
user may have the right to list CAs but may not be permitted to know about some CAs.

## Resource terminology

*Resource* in this context is **NOT** a resource in the RPKI sense. Rather the term resource comes from the
[Oso](http://www.osohq.com/) policy engine which powers Krills authorization decision making process and is anything
that can be acted upon by an actor.

_**TODO:** Rename all such authorization related uses of 'resource' to 'target' instead?_

A resource is currently either a CA `Handle` or `NoResource`. The latter applies to actions such as logging in or
listing all CAs, which do not relate to a single specific resource. In Oso policy language `NoReource` is mapped to Oso
`nil`.

## Permissions

Permissions in Krill are defined as a variants of a `Permission` enum. Every action that must be secured behind a
permission check invokes `Actor::is_allowed(perimssion, resource)` with the required permission for that action.

Authorization rules are written in terms of needing a specific permission. An alternative would have been to grant
access to Krill based on the requested HTTP REST API relative path. However, that would then require that writers of
custom authorization policy rules be aware of and tie their policy definition to the implementation details of the REST
API. Furthermore there may be subsets of the REST API which do not make logical sense to split access to, e.g. ROAs can
be updated via the API, it does not make sense to permit ROA creation but not deletion or vice versa. Therefore we
define higher level Krill "permissions" and authorization policy is based around these, not around the REST API relative
paths and HTTP methods used to invoke them.

## Tight integration with [Oso](http://www.osohq.com/)

The core of Oso is written in Rust and can thus be tightly integrated with Krill.

On startup the `Authorizer` loads embedded policy "scripts" into an instance of Oso and registers the Krill `Actor`,
`Handle` and `Permission` Rust types with Oso so that they can be referred to directly in Oso policy syntax.

Optionally, user defined Oso policy files can be loaded from disk at runtime on Krill startup providing the ability to
write custom authorization rules to match a customers specific needs.

If needed this tight integration can be used to expose useful business logic via custom functions that can be invoked
directly from the Oso policy language, e.g. one might think of something like `CA::is_owner(actor)` (not currently
implemented, instead the policy language currently works with CA handles rather than CA "objects", but Oso makes it
possible).

## The aa! macro

As Krill does not use a REST API framework but handles the HTTP requests itself there is no middleware interface that
we can plug the authorization step into. I considered defining a function level attribute such as `#[authz(...)]` which
could be used to "annotate" the REST API handler functions with the details of what authorization should be required to
invoke the function, however with Rust that would require a procedural macro which would in turn require a separate Rust
crate. It would also make the check more magic and less obvious, and without more flexibility would also not be usable
within a handler function thereby requiring the function to be split up if separate rules need to be applied to
different flows within it.

Instead, for the case where REST API handler functions all have to do almost but not quite exactly the same thing, the
authorization check has been extracted to a Rust declarative macro (which does not require a separate crate). With more
changes to the Krill REST API handling code it might be possible to use a normal function instead of a macro, but for
now REST API handler functions invoke this macro via `aa!(...)`. AA here denotes that the macro checks that the given
actor is both authenticated and authorized.


The `aa!` macro can be described like so: 

```rust
aa!($req, $permission, $resource, $action)
```

This should be read as: invoke the given action only if the actor identified by the given HTTP request has the specified
permission on the specified "resource". 

There are two additional combinatorial variants of the macro invocation syntax:

  - `aa!(no_warn ...` - this is only used by the handler function for
    `GET /api/authorized` to supress logging of auth failures which would otherwise be caused by every initial load of
    the Lagosta web user interface.
  - `aa!($req, $permission, $action)` - this is used in cases where the permission check is not related to a specific
    "resource", e.g. `LOGIN`.

`$action` is a Rust code block containing any code that should be executed, e.g.:

```rust
aa!(req, LOGIN, { /* do something here only if the aa check succeeds */ })
```

If the `aa!` checks fail the `$action` is not invoked, instead a nice human readable error message is returned to the
client.

This slightly strange construction was originally created to work on but not consume the request object that is passed
through the "pipe" of REST API handler function invocations as it used to exist in the code:

```rust
let res = api(req)
    .or_else(health)
    .or_else(metrics)
    ...
```

_(a similar construction still exists but was unpacked to not use `.or_else()` due to problems with explosive async
recursive compilation)_

## The Oso policy

Useful reading:
  - https://docs.osohq.com/rust/learn/polar-foundations.html
  - https://docs.osohq.com/rust/getting-started/policies.html
  - https://docs.osohq.com/rust/reference/polar/classes.html
  - https://docs.rs/oso/0.11.3/oso/index.html
  - [defaults/rules.polar](../../../defaults/rules.polar)
  - [defaults/roles.polar](../../../defaults/roles.polar)

`Actor::is_allowed()` defers to [`Oso::is_allowed()`](https://docs.rs/oso/0.11.3/oso/struct.Oso.html#method.is_allowed).
Oso will evaluate whether the given `Actor`, `Permission` and resource combination yields true or false according to the
policy. A resource is either a CA `Handle` or `NoResource`, the latter being treatable as `nil` in Oso Polar syntax.

While the policy is static, the data it uses is dynamic. Via the `Actor` type it has access to all of the logged-in
users metadata. When using the OpenID Connect provider this metadata is controlled by the provider and thus can be
updated without restarting Krill. Note however that Krill will not see any changes to the metadata until the user logs
in again via the OpenID Connect provider.

Thus the same static policy can return true for Joe having read-access to CA `some_ca` but can return false for the same
check for Alice.

The rule enforcement process starts with lines starting of the form `allow(...)` in `rules.polar`. Oso will follow
`allow(...)` rules to other rules defined in the `.polar` files, but always starts at the most specific `allow(...)`
match that it can find. It will evaluate all matching `allow(...)` root rules until a rule results in `true` or all
rules are exhausted, e.g.:

```rust
allow(actor: Actor, action: Permission, _resource: Option) if
    _resource = nil and
    not disallow(actor, action, _resource) and
    actor_has_role(actor, role) and
    role_allow(role, action);
```

_(the `_resource = nil` bit is a workaround for [Oso bug #788](https://github.com/osohq/oso/issues/788) which is already
closed and so hopefully will be fixed in a new release of Oso soon)_

This rule says allow the requested action if it is not expressly disallowed and the actor has the role required by the
specified action. If we look at a role definition in `roles.polar`:

```rust
role_allow("admin", _action: Permission);
```

Here we see an extremely simple rule that says any action (of type `Permission`) can be used with role name `admin`.
This will feed back into the `allow(...)` rule above so that `actor_has_role(actor, "admin")` will be evaluated. If we
look at that rule back in `rules.polar`:

```rust
actor_has_role(actor: Actor, role) if role in actor.attr("role");
```

This says that the actor has the role if the actors attributes include an attribute called `role` which has the given
role value.

Note that only the `allow` rule name has special meaning to Oso, there is nothing special about the names `role_allow`
or `actor_has_role`, these could be named anything we like.

Finally, if we follow `ACTOR_DEF_MASTER_TOKEN` from `constants.rs` we see an example of an `ActorDef` which
would yield an `Actor` with a `role` attribute with value `admin`. According to the rules we just looked at, that actor
would have all Permissions in Krill:

```rust
// --- constants.rs ---
pub const ACTOR_DEF_MASTER_TOKEN: ActorDef = ActorDef::system("master-token", "admin");

// --- actor.rs ---
impl ActorDef {
    pub const fn system(name: &'static str, role: &'static str) -> ActorDef {
        ActorDef {
            name: ActorName::AsStaticStr(name),
            attributes: Attributes::RoleOnly(role),
            is_user: false,
            new_auth: None,
            auth_error: None,
        }
    }
```

The `Actor` object exposed to Oso Polar syntax is actually a proxy type defined in `policy.rs` like this: _(with some parts stripped out to keep it simpler here)_

```rust
impl PolarClass for Actor {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .add_method("attr", Actor::attribute)
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}
```

Notice the `attr` "method" definition. It is this that allows Oso Polar syntax to invoke `actor.attr("role")` and reach in and retrieve an actual attribute value from the `Actor` instance.

## Putting it all together

Let's look at a complete example with a simplified version of a real code path from `http/server.rs`:

```rust
async fn map_requests(req: hyper::Request<hyper::Body>, state: State) -> Result<hyper::Response<hyper::Body>, Error> {
    let req = Request::new(req, state).await;                 // 1

    let new_auth = req.actor().new_auth();                    // 2

    let logger = ApiCallLogger::new(&req);                    // 3

    let mut res = api(req).await;                             // 4
    if let Err(req) = res {
        res = auth(req).await;                                // 5
    }
    // ...

    let res = add_new_auth_to_response(res, new_auth);        // 6

    logger.log(res.as_ref());                                 // 7

    res.map(|res| res.response())                             // 8
}

// An example of a resource-less restriction
async fn api(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/api/v1") {
        Err(req)                                              // 9
    } else {
        let mut path = req.path().clone();
        path.next();

        match path.next() {
            Some("authorized") => api_authorized(req).await,  // 10
            restricted_endpoint => {
                aa!(req, Permission::LOGIN, {                 // 11
                    match restricted_endpoint {
                        Some("cas") => api_cas(req, &mut path).await,
                        // ...
                        _ => render_unknown_method(),
                    }
                })
            }
        }
    }
}

// An example of no_warn
async fn api_authorized(req: Request) -> RoutingResult {
    aa!(no_warn                                               // 12
        req,
        Permission::LOGIN,
        match *req.method() {
            Method::GET => render_ok(),
            _ => render_unknown_method(),F
        }
    )
}

// An example of a resource specific restriction
async fn api_ca_delete(req: Request, handle: Handle) -> RoutingResult {
    let actor = req.actor();
    aa!(
        req,
        Permission::CA_DELETE,
        handle.clone(),                                       // 13
        render_json_res(req.state().read().await.ca_delete(&handle, &actor).await)
    )
}

// An example of resource specific restriction deeper within Krill
async fn api_cas_list(req: Request) -> RoutingResult {
    aa!(req, Permission::CA_LIST, {                           // 14
        let actor = req.actor();
        render_json_res(req.state().read().await.ca_list(&actor))
    })
}

// --- defined in daemon/ca/manager.rs ---
pub fn ca_list(&self, actor: &Actor) -> KrillResult<CertAuthList> {
    Ok(CertAuthList::new(
        self.ca_store
            .list()?
            .into_iter()
            .filter(|handle| {matches!(actor.is_allowed(Permission::CA_READ, handle.clone()), Ok(true))) // 15
            .map(CertAuthSummary::new)
            .collect(),
    ))
}


```

| # | Description
|---|------------
| 1 | Construct a Krill `Request` object from the Hyper request object. This object has access to `KrillServer` (via `State`) and internally calls `Authorizer::actor_from_request()` which in turn invokes `AuthProvider::authenticate()` so that there is an actor  associated with the request. In case of authentication failure the actor is [`ACTOR_DEF_ANON`](./architecture.md) as some endpoints can be used without authentication.
| 2 | Extract any "new auth" that was created as part of invoking `AuthProvider::authenticate()`. This is a new token that the client should use in subsequent requests instead of the one it has now. New auth can be generated for example if a token was due to expire and was refreshed.
| 3 | Create a logger for, at trace level, logging more details about the request and the response. This logger honours the "benign" flag which the `aa!` macro sets on the response if `no_warn` is specified.
| 4 | Invoke the chain of handler functions. If the request is not for the handler it passes the `Request` through to the next handler via the `Err` return value. The first link in the chain checks for requests to `/api/`.
| 5 | This next handler is worth calling out here. It handles requests to `/auth/` which are the endpoints used by Lagosta to interact with the `AuthProvider` interface, i.e. `get_login_url()`, `login()` and `logout()`.
| 6 | If "new auth" is available, piggy back it on the HTTP response (whether success or failure) as an `Authorize` header. The client should extract the bearer token and use it on subsequent requests to the REST API.
| 7 | Log based on current log level: at INFO or above a summary of the request and response is logged here; at DEBUG and lower the detailed request was logged at step 3 and the detailed response is logged here. <br/><br/> _**TODO:** At the time I couldn't find a way to make `reqwest` or `fern` cause such logging,, but I recently came across [reqwest::ClientBuilder::connection_verbose()](https://docs.rs/reqwest/0.10.8/reqwest/struct.ClientBuilder.html#method.connection_verbose) which perhaps is the missing piece of this puzzle._
| 8 | Pass the constructed HTTP response back to the caller.
| 9 | Chain to the next handler by returning an Err if we are not the handler for this request.
| 10 | Handle the `/api/v1/authorized` endpoint separately (see 12 below).
| 11 | Don't proceed to handle the following endpoints unless the user has `LOGIN` permission.
| 12 | Check also for the `LOGIN` permission when handling `/api/v1/authorize`, but via `no_warn` supress failure logging.
| 13 | To delete a CA the user must have both `CA_DELETE` permission AND access to the particular CA handle.
| 14 | To list CAs the user must have `CA_LIST` permission. However, notice that the `actor` is passed in to `ca_list()`...
| 15 | ... Looking closely at `ca_list()` we see that it further requires `CA_READ` permission on each individual CA handle in order to include that CA in the list result.