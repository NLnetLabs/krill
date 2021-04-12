API Changes Introduced in Release 0.9
=====================================

In this release we removed the concept of 'embedded' CA parents and children, and embedded repositories.
As a result some API changes were introduced.

### Get RFC 8183 Child Request

The endpoints for getting the RFC Child Request XML and JSON have moved, and are now under 'id':

```
/api/v1/cas/<name>/child_request.xml  -> /api/v1/cas/<name>/id/child_request.xml
/api/v1/cas/<name>/child_request.json -> /api/v1/cas/<name>/id/child_request.json
```

### Get RFC 8183 Publisher Request

The endpoints for getting the RFC Publisher Request XML and JSON have moved from 'repo', and are now under 'id':

```
/api/v1/cas/<name>/repo/request.xml  -> /api/v1/cas/<name>/id/publisher_request.xml
/api/v1/cas/<name>/repo/request.json -> /api/v1/cas/<name>/id/publisher_request.json
```



### Add Child `POST /cas/{ca_handle}/children`

The JSON format no longer supports `embedded` and no longer include unused fields:

Old:
```json
{
  "handle": "ca",
  "resources": {
    "asn": "AS1",
    "v4": "10.0.0.0/8",
    "v6": "::"
  },
  "auth": {
    "rfc8183": {
      "tag": null,
      "child_handle": "ca",
      "id_cert": "<base64>"
    }
  }
}
```

New:
```json
{
  "handle": "ca",
  "resources": {
    "asn": "AS1",
    "v4": "10.0.0.0/8",
    "v6": "::"
  },
  "id_cert": "<base64>"
}
```


### Add/Update Parent

There is no separate endpoint anymore for adding a named parent by posting XML to `/api/v1/cas/<ca>/parents-xml/<parent-name>`.

Instead adding a parent can be done by posting XML or JSON to: `/api/v1/cas/<ca>/parents` in which case the parent name will be extracted
from the XML, or by posting to `/api/v1/cas/<ca>/parents/<parent-name>` in which case the parent name in the path will
override the name in the submitted JSON or XML.

In all cases the server will verify that the parent can be reached, and if so, will add the parent if there
was no parent for that name, or update the parent contact details in case there was.

When posting the *LOCAL* parent name can be included in the path, in which case it overrides the parent handle in submitted
XML. If the parent name is included in the path and JSON is submitted, then an error will be returned if the names
in the path and the JSON do not match.

Paths:
```
POST /cas/{ca_handle}/parents
POST /cas/{ca_handle}/parents/{parent_handle}
```

The JSON body has to include the local name by which the CA will refer to its parent, this is also the
name show to the user in the UI. The local name maps to the `handle` field in the JSON below. The second
component is the `contact`. Krill used to support an `embedded` type, but this is no longer supported, so
this structure MUST have `"type": "rfc6492"`. We still have this type because we need to support the notion
of a (test) Trust Anchor as well. The remainder of this structure maps to the RFC 8183 Parent Response XML,
but then in JSON format. Note that the `parent_handle` is the handle that the parent wants the CA to use
in messages sent to it - and it may be different from the local name stored in `handle`:

```json
{
  "handle": "string",
  "contact": {
    "type": "rfc6492",
    "tag": null,
    "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5NjczMEUwQTg2MkE0RDkyNjQ1NEY5RTgzNzYxMzMzQkI0Qjc0QTVDMB4XDTIxMDMwNDE2MTQwNFoXDTM2MDMwNDE2MTkwNFowMzExMC8GA1UEAxMoOTY3MzBFMEE4NjJBNEQ5MjY0NTRGOUU4Mzc2MTMzM0JCNEI3NEE1QzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCNekDo59PLdJnfiPg9kUycEb3EF17TnnUEKJaCunheH/brWakMumqpBox3H2fn1XY7e2e1SFezp52yqcIggLUOj3K49SvTzdDCCwA2MGuzaDHK6IhOuLKH9D9BqA2FTWVr3PNk77g+Bn1TfKF+G+JMr3jvDMkJAW9+58vnl7UJ/g+H6/lWqWAW1JeA3go9B+qdxC9DA02h+7vXPGhsVeUw688LFBv1fDGlQFX02zx0uNrKQQHddL1aJIM01i5M+N3uWJ5u3wCJRvxAr/P9KNtCO1sTFxR2dE/8W0+rfJWkAnDcgzeDCjznICF1146Thjxir08dYlj5YAeR3c5r5L8CAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlnMOCoYqTZJkVPnoN2EzO7S3SlwwHwYDVR0jBBgwFoAUlnMOCoYqTZJkVPnoN2EzO7S3SlwwDQYJKoZIhvcNAQELBQADggEBAGUq4w7nv6Ez4kBdqfgyU0taKHgxIOTKJ6EwsDZj6eVGF6ThrutAonMVUeu1zs5ZW/uYaRWPffHzY8m1wdyrwYVw0HxRWY96vrhOOrVk32J6ip9V9bfFSjZLVnVcBz5V/odB++bJHhMoFNUaoqEGSNleiPotBtOHahlIL1EDEAt7bC5Kk7vEl0VmRJs7Hp1kpdZRJlVy7sLWL082hCJCulG57qL2UbsQ2wmFk+ImJ2RO3GSrNEI4//kHIw7GQFeeROfeb5HvyC/QOCzfBmMc/ipApuyzROSXHsE6CiaM2uWCjHs1NZBu+Za2EoFOhgYN1akeqqo50vRfO3Dd6Bm/rQY=",
    "parent_handle": "ta",
    "child_handle": "testbed",
    "service_uri": "https://localhost:3000/rfc6492/ta"
  }
}
```


### Get Parent `GET /cas/{ca_handle}/parents/{parent_handle}`

Returns the parent contact with the type `rfc6492` as an embedded field call `type`.

```json
{
  "type": "rfc6492",
  "tag": null,
  "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5NjczMEUwQTg2MkE0RDkyNjQ1NEY5RTgzNzYxMzMzQkI0Qjc0QTVDMB4XDTIxMDMwNDE2MTQwNFoXDTM2MDMwNDE2MTkwNFowMzExMC8GA1UEAxMoOTY3MzBFMEE4NjJBNEQ5MjY0NTRGOUU4Mzc2MTMzM0JCNEI3NEE1QzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCNekDo59PLdJnfiPg9kUycEb3EF17TnnUEKJaCunheH/brWakMumqpBox3H2fn1XY7e2e1SFezp52yqcIggLUOj3K49SvTzdDCCwA2MGuzaDHK6IhOuLKH9D9BqA2FTWVr3PNk77g+Bn1TfKF+G+JMr3jvDMkJAW9+58vnl7UJ/g+H6/lWqWAW1JeA3go9B+qdxC9DA02h+7vXPGhsVeUw688LFBv1fDGlQFX02zx0uNrKQQHddL1aJIM01i5M+N3uWJ5u3wCJRvxAr/P9KNtCO1sTFxR2dE/8W0+rfJWkAnDcgzeDCjznICF1146Thjxir08dYlj5YAeR3c5r5L8CAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlnMOCoYqTZJkVPnoN2EzO7S3SlwwHwYDVR0jBBgwFoAUlnMOCoYqTZJkVPnoN2EzO7S3SlwwDQYJKoZIhvcNAQELBQADggEBAGUq4w7nv6Ez4kBdqfgyU0taKHgxIOTKJ6EwsDZj6eVGF6ThrutAonMVUeu1zs5ZW/uYaRWPffHzY8m1wdyrwYVw0HxRWY96vrhOOrVk32J6ip9V9bfFSjZLVnVcBz5V/odB++bJHhMoFNUaoqEGSNleiPotBtOHahlIL1EDEAt7bC5Kk7vEl0VmRJs7Hp1kpdZRJlVy7sLWL082hCJCulG57qL2UbsQ2wmFk+ImJ2RO3GSrNEI4//kHIw7GQFeeROfeb5HvyC/QOCzfBmMc/ipApuyzROSXHsE6CiaM2uWCjHs1NZBu+Za2EoFOhgYN1akeqqo50vRfO3Dd6Bm/rQY=",
  "parent_handle": "ta",
  "child_handle": "testbed",
  "service_uri": "https://localhost:3000/rfc6492/ta"
}
```


## Show Repository `GET /cas/{ca_handle}/repo`

Since we no longer support `embedded`, the JSON format of the show repository API response has changed a bit.
The JSON member `rfc8181` now appears as `repository_response`. We still have a JSON member called `contact`,
so that we remain a bit flexible in case we would like to include more information in future, next to which
repository is configured.

Old:
```json
{
  "contact": {
    "rfc8181": {
      "tag": null,
      "publisher_handle": "ca",
      "id_cert": "MIID..Vg==",
      "service_uri": "https://localhost:3000/rfc8181/ca",
      "repo_info": {
        "base_uri": "rsync://localhost/repo/ca/",
        "rpki_notify": "https://localhost:3000/rrdp/notificati.xml"
      }
    }
  }
}
```

New:
```json
{
  "contact": {
    "repository_response": {
      "tag": null,
      "publisher_handle": "ca",
      "id_cert": "MIID..Vg==",
      "service_uri": "https://localhost:3000/rfc8181/ca",
      "repo_info": {
        "base_uri": "rsync://localhost/repo/ca/",
        "rpki_notify": "https://localhost:3000/rrdp/notificati.xml"
      }
    }
  }
}
```

## Add or Update Repository `POST /cas/{ca_handle}/repo`

To add or update the repository the RFC 8183 Repository Response needs to be submitted, either as
XML, or in JSON format. The JSON format no longer supports `embedded`, so the following is **no longer**
supported:

Old:
```json
{
  "tag": "string",
  "id_cert": "string",
  "child_handle": "string"
}
```

New:
```json
{
  "repository_response": {
    "tag": null,
    "publisher_handle": "publisher",
    "id_cert": "MIID..6g==",
    "service_uri": "https://repo.example.com/rfc8181/publisher/",
    "repo_info": {
      "base_uri": "rsync://localhost/repo/ca/",
      "rpki_notify": "https://localhost:3000/rrdp/notification.xml"
    }
  }
}
```
