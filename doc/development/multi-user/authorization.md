# Multi-User: Authorization

## Who authorizes whom?

An `AuthProvider` authenticates a user and supplies metadata about that user to the `Authorizer` but neither the
`AuthProivder` nor the `Authorizer` authorize actions by the user in Krill. The `Authorizer` is responsible for
authorization but delegates the responsibility to two other components:

  - An instance of `AuthPolicy` which it owns.
  - An instance of `Actor` which it created and to which it gave a reference to the `AuthPolicy`.

## To do what when?

When a Krill `Actor` needs to perform some action on some resource, we ask the `Actor` if it
`is_allowed(permission, resource)`. The `Actor` then asks the `AuthPolicy` to decide if the requested action is allowed
by the actor on the resource.

### Resource?

*Resource* in this context is **NOT** a resource in the RPKI sense. Rather the term resource comes from the
[Oso](http://www.osohq.com/) policy engine which powers Krills authorization decision making process and is anything
that can be acted upon by an actor.

_**TODO:** Rename all such authorization related uses of 'resource' to 'target' instead?_

A resource is either a CA `Handle` or `NoResource`. The latter applies to actions such as logging in or listing all CAs,
which do not relate to a single specific resource. In Oso policy language `NoReource` is mapped to Oso `nil`.

### Permission?

Permissions in Krill are defined as a variants of a `Permission` enum. Every action that must be secured behind a
permission check invokes `Actor::is_allowed(perimssion, resource)` with the required permission for that action.

## Tightly integrated with Oso

Oso core is written in Rust and is capable of integrating tightly with Krill.

On startup the `Authorizer` loads embedded policy "scripts" into an instance of Oso and registers the Krill `Actor`,
`Handle` and `Permission` Rust types with Oso so that they can be referred to directly in Oso policy syntax.

Optionally, user defined Oso policy files can be loaded from disk at runtime on Krill startup providing the ability to
write custom authorization rules to match a customers specific needs.
