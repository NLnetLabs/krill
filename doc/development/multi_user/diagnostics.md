# Multi-User Feature: Diagnostics

## Prometheus metrics

Currently there is only one additional Prometheus metric:

```
# HELP krill_auth_session_cache_size total number of cached login session tokens
# TYPE krill_auth_session_cache_size gauge
krill_auth_session_cache_size 3
```

This value should nearly always be zero however as the cache is very short lived.

## Logs

Enabling `DEBUG` or `TRACE` level logging to see things like:

  - Detailed information about the activity of the `Authorizer` and `AuthProvider` implementations.
  - Detailed logging of Krill HTTP server received requests and served responses.
  - Detailed logging of Krill HTTP client requests to and responses from the external OpenID Connect provider, if any.

VERY detailed logging of the Oso policy engine decision making process can be enabled by setting environment variable
`POLAR_LOG` to some value.
  
