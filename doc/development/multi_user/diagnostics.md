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
  
## Following the complete HTTP conversation when using OpenID Connect
  
When diagnosing issues with the OpenID Connect integration the following setup can help:

1. Set the `SSLKEYLOGFILE=/some/path` variable in the environment before running Krill to cause Krill to record the TLS
keys in use for communication e.g. with the client browser and/or an OpenID Connect provider (if in use).

2. Disable HTTP/2 and HTTP/3 in your browser (as these are harder to follow and filter on in Wireshark), e.g. with Firefox go to about:config and set `network.http.http2.enabled` and `network.http.http3.enable` both to false.

3. Configure Krill to use the OIDC provider via HTTP rather than HTTPS by setting `insecure = true` in `krill.conf` in the OpenID Connect provider section. If using KeyCloak via Docker no special action needs to be taken as it listens on both HTTP (8080) and HTTPS (8443) by default.

4. In Wireshark Preferences -> Protocols -> TLS set "(Pre)-Master-Secret log filename" with the path you used with `SSLKEYLOGFILE` in step 1.

5. In Wireshark Preferences -> HTTP add port number 3000 (Krill HTTPS) in "SSL/TLS Ports".

6. In Wireshark Preferences -> HTTP add (if not already present) port number 8080 (KeyCloak HTTP) in "TCP port(s)".

7. Capture traffic on all interfaces in Wireshark and set the display filter to one of:

- `http && (tcp.port == 8080 || tcp.port == 3000) && not http.request.full_uri contains assets && http.request` _(for a quick overview)_
- `http && (tcp.port == 8080 || tcp.port == 3000) && not http.request.full_uri contains assets` _(for the full request/response flow)_

8. Start your OpenID Connect provider.

9. Start Krill.

10. Browse to https://localhost:3000/ to login to Krill. Follow the HTTP flow in Wireshark.
