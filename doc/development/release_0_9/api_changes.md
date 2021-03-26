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

AddCAChildRequest


