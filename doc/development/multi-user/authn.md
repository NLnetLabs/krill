# Multi-User: Authentication & Authorization

## Built-in Actors

There are currently four built-in actors, which for convenience have entries in `constants.rs`: _(ordered from most to least powerful)_

Actor | Represents | Role | Comments
------|------------|------|----------
`ACTOR_DEF_KRILL` | Krill itself | `admin` | Used for initial startup and scheduled actions that are not directly attributable to a REST API client.
`ACTOR_DEF_MASTER_TOKEN` | A client using the master API token | `admin` | Used by the users of Lagosta when `auth_type = "master-token"` (the default), or by direct clients of the REST API, or indirect clients of the REST API via `krillc`. |
`ACTOR_DEF_TESTBED` | An anonmymous client of the testbed | `testbed` (temporarily) | Used by the testbed REST API handler functions to make internal requests to restricted APIs on the behalf of the anonymous client. See `Request::upgrade_from_anonymous`. |
`ACTOR_DEF_ANON` | An anonymous client | None | Used for REST API calls that lack credentials or for which an error occurs during authentication. By still having an actor even in this case we can handle all API calls the same way. The anonymous actor has no role and so, unless overriden by a custom authorization policy, has no rights in Krill. It can thus only successfully request REST API endpoints that do not require authentication. |
