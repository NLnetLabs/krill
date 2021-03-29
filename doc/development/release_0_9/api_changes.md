API Changes Introduced in Release 0.9
=====================================

In this release we removed the concept of 'embedded' CA parents and children, and embedded repositories.
As a result some API were introduced.

### Add Child

The JSON format no longer supports 'embedded'.

Old:
```
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
```
{
  "handle": "ca",
  "resources": {
    "asn": "AS1",
    "v4": "10.0.0.0/8",
    "v6": "::"
  },
  "child_request": {
    "tag": null,
    "child_handle": "ca",
    "id_cert": "<base64>"
  }
}
```

## Add Parent

Embedded is no longer allowed, there is still a notion of a 'type' because we support "ta".

```
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

### Update Parent

To update a parent submit the RFC 8183 Parent Response, or the contact JSON (i.e. minus the handle in the Add Parent):

```
{
  "type": "rfc6492",
  "tag": null,
  "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5NjczMEUwQTg2MkE0RDkyNjQ1NEY5RTgzNzYxMzMzQkI0Qjc0QTVDMB4XDTIxMDMwNDE2MTQwNFoXDTM2MDMwNDE2MTkwNFowMzExMC8GA1UEAxMoOTY3MzBFMEE4NjJBNEQ5MjY0NTRGOUU4Mzc2MTMzM0JCNEI3NEE1QzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCNekDo59PLdJnfiPg9kUycEb3EF17TnnUEKJaCunheH/brWakMumqpBox3H2fn1XY7e2e1SFezp52yqcIggLUOj3K49SvTzdDCCwA2MGuzaDHK6IhOuLKH9D9BqA2FTWVr3PNk77g+Bn1TfKF+G+JMr3jvDMkJAW9+58vnl7UJ/g+H6/lWqWAW1JeA3go9B+qdxC9DA02h+7vXPGhsVeUw688LFBv1fDGlQFX02zx0uNrKQQHddL1aJIM01i5M+N3uWJ5u3wCJRvxAr/P9KNtCO1sTFxR2dE/8W0+rfJWkAnDcgzeDCjznICF1146Thjxir08dYlj5YAeR3c5r5L8CAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlnMOCoYqTZJkVPnoN2EzO7S3SlwwHwYDVR0jBBgwFoAUlnMOCoYqTZJkVPnoN2EzO7S3SlwwDQYJKoZIhvcNAQELBQADggEBAGUq4w7nv6Ez4kBdqfgyU0taKHgxIOTKJ6EwsDZj6eVGF6ThrutAonMVUeu1zs5ZW/uYaRWPffHzY8m1wdyrwYVw0HxRWY96vrhOOrVk32J6ip9V9bfFSjZLVnVcBz5V/odB++bJHhMoFNUaoqEGSNleiPotBtOHahlIL1EDEAt7bC5Kk7vEl0VmRJs7Hp1kpdZRJlVy7sLWL082hCJCulG57qL2UbsQ2wmFk+ImJ2RO3GSrNEI4//kHIw7GQFeeROfeb5HvyC/QOCzfBmMc/ipApuyzROSXHsE6CiaM2uWCjHs1NZBu+Za2EoFOhgYN1akeqqo50vRfO3Dd6Bm/rQY=",
  "parent_handle": "ta",
  "child_handle": "testbed",
  "service_uri": "https://localhost:3000/rfc6492/ta"
}
```

### Get Parent

Returns the parent contact with the type "rfc6492" as an embedded field call "type".

```
{
  "type": "rfc6492",
  "tag": null,
  "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5NjczMEUwQTg2MkE0RDkyNjQ1NEY5RTgzNzYxMzMzQkI0Qjc0QTVDMB4XDTIxMDMwNDE2MTQwNFoXDTM2MDMwNDE2MTkwNFowMzExMC8GA1UEAxMoOTY3MzBFMEE4NjJBNEQ5MjY0NTRGOUU4Mzc2MTMzM0JCNEI3NEE1QzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCNekDo59PLdJnfiPg9kUycEb3EF17TnnUEKJaCunheH/brWakMumqpBox3H2fn1XY7e2e1SFezp52yqcIggLUOj3K49SvTzdDCCwA2MGuzaDHK6IhOuLKH9D9BqA2FTWVr3PNk77g+Bn1TfKF+G+JMr3jvDMkJAW9+58vnl7UJ/g+H6/lWqWAW1JeA3go9B+qdxC9DA02h+7vXPGhsVeUw688LFBv1fDGlQFX02zx0uNrKQQHddL1aJIM01i5M+N3uWJ5u3wCJRvxAr/P9KNtCO1sTFxR2dE/8W0+rfJWkAnDcgzeDCjznICF1146Thjxir08dYlj5YAeR3c5r5L8CAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlnMOCoYqTZJkVPnoN2EzO7S3SlwwHwYDVR0jBBgwFoAUlnMOCoYqTZJkVPnoN2EzO7S3SlwwDQYJKoZIhvcNAQELBQADggEBAGUq4w7nv6Ez4kBdqfgyU0taKHgxIOTKJ6EwsDZj6eVGF6ThrutAonMVUeu1zs5ZW/uYaRWPffHzY8m1wdyrwYVw0HxRWY96vrhOOrVk32J6ip9V9bfFSjZLVnVcBz5V/odB++bJHhMoFNUaoqEGSNleiPotBtOHahlIL1EDEAt7bC5Kk7vEl0VmRJs7Hp1kpdZRJlVy7sLWL082hCJCulG57qL2UbsQ2wmFk+ImJ2RO3GSrNEI4//kHIw7GQFeeROfeb5HvyC/QOCzfBmMc/ipApuyzROSXHsE6CiaM2uWCjHs1NZBu+Za2EoFOhgYN1akeqqo50vRfO3Dd6Bm/rQY=",
  "parent_handle": "ta",
  "child_handle": "testbed",
  "service_uri": "https://localhost:3000/rfc6492/ta"
}
```


## Show Repository

Since we no longer support 'embedded', the JSON format of the show repository API response has changed a bit.
The JSON member "rfc8181" now appears as "repository_response". We still have a JSON member called "contact",
so that we remain a bit flexible in case we would like to include more information in future, next to which
repository is configured.

OLD:
```
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

NEW:
```
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

## Add or Update Repository

To add or update the repository the RFC 8183 Repository Response needs to be submitted, either as
XML, or in JSON format. The JSON format no longer supports 'embedded', so the following is NO LONGER
supported:

```
{
  "tag": "string",
  "id_cert": "string",
  "child_handle": "string"
}
```

NEW:
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

