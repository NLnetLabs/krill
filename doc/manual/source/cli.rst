.. _doc_krill_cli:
.. highlight:: none

Using the CLI or API
====================

Introduction
------------

Every function of Krill can be controlled from the command line interface (CLI).
The Krill CLI is a wrapper around the API which is based on JSON over HTTPS.

We will document all current functions below, providing examples of both the
CLI and API.

Note that you can use the CLI from another machine, but then you will need to
set up a proxy server in front of Krill and make sure that it has a real TLS
certificate.

To use the CLI you need to invoke :command:`krillc` followed by one or more
subcommands, and some arguments. Help is built-in:

.. code-block:: text

   USAGE:
       krillc <subcommand..> [FLAGS] [OPTIONS]

   FLAGS:
           --api        Only show the API call and exit. Or set env: KRILL_CLI_API=1
       -h, --help       Prints help information
       -V, --version    Prints version information

   OPTIONS:
       -c, --ca <name>         The name of the CA you wish to control. Or set env: KRILL_CLI_MY_CA
       -f, --format <type>     Report format: none|json|text (default). Or set env: KRILL_CLI_FORMAT
       -s, --server <URI>      The full URI to the krill server. Or set env: KRILL_CLI_SERVER
       -t, --token <string>    The secret token for the krill server. Or set env: KRILL_CLI_TOKEN


Setting Defaults
----------------

As noted in the OPTIONS help text above you can set default values via
environment variables for the most common arguments that need to be supplied to
``krillc`` subcommands. When setting environment variables note the following
requirements:

  - ``KRILL_CLI_SERVER`` must be in the form ``https://<host:port>/``.
  - ``KRILL_CLI_MY_CA`` must consist only of alphanumeric characters, dashes and
    underscores, i.e. ``a-zA-Z0-9_``.

For example:

.. code-block:: bash

   export KRILL_CLI_TOKEN="correct-horse-battery-staple"
   export KRILL_CLI_MY_CA="Acme-Corp-Intl"

If you do use the command line argument equivalents, you will override whatever
value you set in the ENV. Krill will give you a friendly error message if you
did not set the applicable ENV variable, and don't include the command line
argument equivalent.

Explore the API
----------------

The reference below documents the available ``krillc`` subcommands and the
equivalent API functions by example.

You can also explore the CLI and API yourself:

 - Each subcommand can be prefixed with ``help`` to access the CLI built-in help
 - You can always use ``--api`` argument to make the CLI print out the API
   call that it would do, without actually sending it to the server.
 - You can use ``--format=json`` to have the API print out the JSON returned by
   the server without reformatting or filtering information. Of course, be
   careful if you use this option for subcommands with side-effects, such as
   ``krillc delete --ca <ca>``

If you want a to have a safe sandbox environment to test your Krill CA and
really explore the API, then we recommend that you set up a local Krill testbed
as described in :ref:`doc_krill_testbed`.

*Tip*: Click subcommand names in this section to jump to its detailed description.

Subcommands for managing your Krill server:

.. parsed-literal::

   :ref:`config<cmd_krillc_config>`        Creates a configuration file for krill and prints it to STDOUT
   :ref:`health<cmd_krillc_health>`        Perform an authenticated health check
   :ref:`info<cmd_krillc_info>`          Show server info

Subcommands for adding / removing CA instances in your Krill server:

.. parsed-literal::

   :ref:`add<cmd_krillc_add>`           Add a new CA
   :ref:`delete<cmd_krillc_delete>`        Delete a CA and let it withdraw its objects and request revocation. WARNING: Irreversible!
   :ref:`list<cmd_krillc_list>`          List the current CAs


Subcommands for initialising a CA:

.. parsed-literal::

   :ref:`parents<cmd_krillc_parents>`       Manage parents for a CA.
   :ref:`repo<cmd_krillc_repo>`          Manage the repository for a CA.

Subcommands for showing the details of a CA:

.. parsed-literal::

   :ref:`show<cmd_krillc_show>`          Show details of a CA.
   :ref:`issues<cmd_krillc_issues>`        Show issues for a CA
   :ref:`history<cmd_krillc_history>`       Show the history of a CA


Manage ROAs:

.. parsed-literal::

   :ref:`roas<cmd_krillc_roas>`          Manage ROAs for a CA.

Other operations:

.. parsed-literal::

   :ref:`bulk<cmd_krillc_bulk>`          Manually trigger refresh/republish/resync for all CAs
   :ref:`children<cmd_krillc_children>`      Manage children for a CA
   :ref:`keyroll<cmd_krillc_keyroll>`       Perform a manual key rollover for a CA



.. _cmd_krillc_config:

krillc config
-------------

This subcommand is implemented on the CLI only and is intended to help generate a configuration
file which can be used for your Krill server.

We currently support two subcommands for this: `krillc config simple` and `krillc config user`.
The first can be used to generate general server configuration. The second can be used to generate
user (`id`) entries to use if you want to have multiple local users access the Krill UI by their own
name and password.

....

.. _cmd_krillc_health:

krillc health
-------------

Perform an authenticated health check. Verifies that the specified Krill server
can be connected to, is able to verify the specified token and is, at least thus
far, healthy. This does NOT check whether your CAs have any issues, please have
a look at the :ref:`issues<cmd_krillc_issues>` subcommand for this.

Can be used in automation scripts by checking the exit code:

+-----------+------------------------------------------------------------------+
| Exit Code | Meaning                                                          |
+===========+==================================================================+
| 0         | the Krill server appears to be healthy.                          |
+-----------+------------------------------------------------------------------+
| non-zero  | incorrect server URI, token, connection failure or server error. |
+-----------+------------------------------------------------------------------+

Example CLI:

.. code-block:: bash

  $ krillc health
  $ echo $?
  0

Example API:

.. code-block:: text

  $ krillc health --api
  GET:
    https://localhost:3000/api/v1/authorized
  Headers:
    Authorization: Bearer secret

If you need to do an unauthorized health check, then you can just call the following
endpoint instead. This will always return a 200 OK response if the server is running:

.. code-block:: text

  GET:
    https://localhost:3000/health

....

.. _cmd_krillc_info:

krillc info
-----------

Show server info. Prints the version of the Krill *server* and the date and time
that it was last started, e.g.:

Example CLI:

.. code-block:: text

  $ krillc info
  Version: 0.9.0
  Started: 2021-04-07T12:36:00+00:00

Example API call:

.. code-block:: text

  $ krillc info --api
    GET:
      https://localhost:3000/stats/info
    Headers:
      Authorization: Bearer secret


Example API resonse:

.. code-block:: json

  {
    "version": "0.9.0",
    "started": 1617798960
  }


....

.. _cmd_krillc_add:

krillc add
----------

Adds a new CA.

When adding a CA you need to choose a handle, essentially just a name. The term
"handle" comes from :RFC:`8183` and is used in the communication protocol
between parent and child CAs, as well as CAs and publication servers. The handle
may consist of alphanumeric characters, dashes and underscores, i.e. ``a-zA-Z0-9_``.

The handle you select is not published in the RPKI but used as identification to
parent and child CAs you interact with. You should choose a handle that helps
others recognise your organisation. Once set, the handle cannot be be changed
as it would interfere with the communication between parent and child CAs, as
well as the publication repository.

When a CA has been added, it is registered to publish locally in the Krill
instance where it exists, but other than that it has no configuration yet. In
order to do anything useful with a CA you will first have to add at least one
parent to it, followed by some Route Origin Authorisations and/or child CAs.

Example CLI:

.. code-block:: text

  $ krillc add --ca newca


Example API:

.. code-block:: text

  $ krillc add --ca newca --api
  POST:
    https://localhost:3000/api/v1/cas
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "handle": "newca"
  }

The API response is an empty 200 OK response, unless an issue occurred - e.g.
the handle was already in use:

.. code-block:: json

  {"label":"ca-duplicate","msg":"CA 'newca' was already initialised","args":{"ca":"newca"}}


....

.. _cmd_krillc_delete:

krillc delete
-------------

Deletes a CA in your Krill server. The CA will try (best effort) to request revocation of its
current certificates from its parents, and withdraw its objects from its repository.

.. Warning:: This action is irreversible!

Example CLI:

.. code-block:: text

  $ krillc delete --ca ca

Example API:

.. code-block:: text

   $ krillc delete --ca ca --api
   DELETE:
      https://localhost:3000/api/v1/cas/ca
   Headers:
      Authorization: Bearer secret

The API response is an empty 200 OK response, unless an issue occurred - e.g.
the CA is not known:

.. code-block:: json

  {"label":"ca-unknown","msg":"CA 'unknown' is unknown","args":{"ca":"unknown"}}


....


.. _cmd_krillc_list:

krillc list
-----------

List the current CAs.

Example CLI:

.. code-block:: text

  $ krillc list
  testbed
  ta

Example API:

.. code-block:: text

  $ krillc list --api
  GET:
    https://localhost:3000/api/v1/cas
  Headers:
    Authorization: Bearer secret


Example API response:

.. code-block:: json

  {
    "cas": [
      {
        "handle": "testbed"
      },
      {
        "handle": "ta"
      }
    ]
  }

....

.. _cmd_krillc_parents:

krillc parents
--------------

Manage parents for a CA. You will need to add at least one parent, and a repository (see below), before
your CA can request any resource certificate.

The Krill CLI and API have a number of subcommands to manage CA parents:

.. parsed-literal::
   :ref:`request<cmd_krillc_parents_request>`    Show RFC8183 Publisher Request XML
   :ref:`add<cmd_krillc_parents_add>`        Add a parent to this CA
   :ref:`statuses<cmd_krillc_parents_statuses>`   Show overview of all parent statuses of a CA
   :ref:`contact<cmd_krillc_parents_contact>`    Show contact information for a parent of this CA
   :ref:`remove<cmd_krillc_parents_remove>`     Remove an existing parent from this CA

.. _cmd_krillc_parents_request:

krillc parents request
----------------------

Before you can add a parent to any CA, you will need to present an :rfc:`8183` Publisher Request XML
to that parent. Their response XML can then be used to add them as a parent.

For more information on how this is done through the UI see: :ref:`doc_krill_using_ui_parent_setup`.

Example CLI:

.. code-block:: text

  $ krillc parents request --ca newca
  <child_request xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" child_handle="newca">
    <child_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJENzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEuL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8OlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEoBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtONdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9iKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDVbXTPM8YLRgc=</child_bpki_ta>
  </child_request>


The API can be called to return the Publisher Request in XML format if you use the following path scheme:

.. code-block:: text

  GET:
    https://localhost:3000/api/v1/cas/newca/id/child_request.xml
  Headers:
    Authorization: Bearer secret


The API also supports a JSON equivalent of the response if the `child_request.json` is requested instead:

.. code-block:: text

  GET:
    https://localhost:3000/api/v1/cas/newca/id/child_request.json
  Headers:
    Authorization: Bearer secret


.. _cmd_krillc_parents_add:

krillc parents add
------------------

Add a parent to a CA. Or update the information for an existing parent.

In order to add a parent to a CA you will need to present the :rfc:`8183` Parent Response. You will
usually get this response in the standard RFC XML format. The Krill API supports submitting this file
in its plain XML form, in which case the *local* name for the parent - i.e. the name that your CA will
use for it in the presentation to you - will be derived from the path, or if it is not supplied there
from the `parent_handle` in the XML.

The API also supports a JSON format where the parent *local* `handle` can be explicitly specified. If
you use the CLI then it will expect that you provide this local handle, parse a supplied XML file, and
then combine both in a JSON body sent to the server:

.. code-block:: text

  $ krillc parents add --parent my_parent --response ./data/new-ca-parent-response.xml --api
  POST:
    https://localhost:3000/api/v1/cas/ca/parents
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "handle": "my_parent",
    "contact": {
      "type": "rfc6492",
      "tag": null,
      "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=",
      "parent_handle": "testbed",
      "child_handle": "newca",
      "service_uri": "https://localhost:3000/rfc6492/testbed"
    }
  }

Note that whichever handle you choose, your CA will use the handles that the
parent response included for itself *and* for your CA in its communication with
this parent. I.e. you may want to inspect the response and use the same handle
for the parent (parent_handle attribute), and do not be surprised or alarmed if
the parent refers to your ca (child_handle attribute) by some seemingly random
name. Some parents do this to ensure uniqueness.

In case you have multiple parents you may want to refer to them by names that
make sense in your context, or to avoid name collisions in case they all like
to go by the same the name.

In order to specify the parent 'handle' on the path it can simply be added as
a path parameter in the call. This is primarily intended for XML in which case
the path argument will be taken from here. If you submit a JSON body *and*
specify a the handle as path parameter, then Krill will return an error in case
the handles do not match.

.. Important:: The API path for ADDING a parent is the same as the API path for updating a parent.
     This means that adding the same parent multiple times is idempotent. If you are unsure about
     The parents that your CA currently has, then have a look at the :ref:`show<cmd_krillc_show>`
     subcommand.

.. _cmd_krillc_parents_statuses:

krillc parents statuses
-----------------------

Show the current status between a CA and all of its parents.

.. Warning:: This command will return an empty result if you did not yet
   configure a repository for the CA. This is because Krill will not even
   attempt to contact parent CAs until it knows which URIs to use in
   certificate requests.

Example CLI:

.. code-block:: text

  $  krillc parents statuses --ca newca
  Parent: my_parent
  URI: https://localhost:3000/rfc8181/localname/
  Status: success
  Last contacted: 2021-04-08T11:20:00+00:00
  Resource Entitlements: asn: AS65000, ipv4: 10.0.0.0/8, ipv6: 2001:db8::/32
    resource class: 0
    entitled resources: asn: 'AS65000', ipv4: '10.0.0.0/8', ipv6: '2001:db8::/32'
    entitled not after: 2023-03-15T14:23:57+00:00
    issuing cert uri: rsync://localhost/repo/ta/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.cer
    issuing cert PEM:

  -----BEGIN CERTIFICATE-----
  MIIFKzCCBBOgAwIBA...
  -----END CERTIFICATE-----

    received certificate(s):
      published at: rsync://localhost/repo/testbed/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.cer
      resources:    asn: AS65000, v4: 10.0.0.0/8, v6: 2001:db8::/32
      cert PEM:

  -----BEGIN CERTIFICATE-----
  MIIFYDCCBEigAwIBAgIUN5PzATTKVrjgual4CpJMaggW2EIwDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQzAeFw0yMTA0MDgwOTQ4MjVaFw0yMjA0MDcwOTUzMjVaMDMxMTAvBgNVBAMTKDE2QjMxQzkyRUIxMTZCQzYwMDI2QzUwOTQ0QUQ0NDIwNUREOUFDQkQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsBouGWEPhWg+XsRDGZyuFLDPiIExy7p4b3bjNPBfHeSqHCeOwiVIVS2xiIAGO2NBcv+hL2OFKNCAnpd71hOXMBNXW/7OHN8TU6crIu1/w1gkf6UCXFrv+poW9EJHnLonMa4ZFLSFsvQACIGUpxIuiQjaSYFltTbb+o2c9KWoKsX0kZqt5zOrgAP8cke8SFGHdqqenPInXKTgyss9kCs9pFtMk6BIa6KjRvqFVZIf6xG53ytJ3JqsGjvEo8qoHYxkvkMtbjhjlmW097i6DeC1241X3SG64DSMk1CNv1xt5MSXubLzWOD+2lLId/ngql4OV0bLkbb63J/26c8FZOThZAgMBAAGjggJqMIICZjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQWsxyS6xFrxgAmxQlErUQgXdmsvTAfBgNVHSMEGDAWgBQLpcEyuUiRyy06ie3hLwGspLzT3DAOBgNVHQ8BAf8EBAMCAQYwXgYDVR0fBFcwVTBToFGgT4ZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jcmwwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhyc3luYzovL2xvY2FsaG9zdC9yZXBvL3RhLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jZXIwgdgGCCsGAQUFBwELBIHLMIHIMC8GCCsGAQUFBzAFhiNyc3luYzovL2xvY2FsaG9zdC9yZXBvL2xvY2FsbmFtZS8wLzBbBggrBgEFBQcwCoZPcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9sb2NhbG5hbWUvMC8xNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JELm1mdDA4BggrBgEFBQcwDYYsaHR0cHM6Ly9sb2NhbGhvc3Q6MzAwMC9ycmRwL25vdGlmaWNhdGlvbi54bWwwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAsBggrBgEFBQcBBwEB/wQdMBswCgQCAAEwBAMCAAowDQQCAAIwBwMFACABDbgwGgYIKwYBBQUHAQgBAf8ECzAJoAcwBQIDAP3oMA0GCSqGSIb3DQEBCwUAA4IBAQB8hxBbJjvgVRMfXsotTNwKCc2Q0QO92xmZlV19Uh0/Yja+sYhyg/pG1/ZTvhOLIxGWap8JmqOnYa9XgX8uUlsV8LgJoEH3Gde3txcGtfLO99ugvbnKKGOcPxB8AX5hAhhfdiSnt3V06dEz3HUoTYdUKTV0bZr3dhRIBa94esAS7lsP2vhHEQ8gVjZGWVvS7lGju+kuwm9H3PBscW/K8349vN0QJUZGm3gAUsM5PlnAqbkM7VFIyu8g2Yp9g+M/iwaHar8CqABKxLBThYgqrPLLv6CsZD3mjk5BkXVZh6R9dBcR7sPbSfGBWPWCv8SwLknyQDOvsWTho1Ga6AibjUQp
  -----END CERTIFICATE-----

Note that in case there are any issues, i.e. the status is "failure" then Krill will keep
trying to resynchronise the CA with this parent automatically. There is usually no need to
trigger this manually before the next planned contact, but you can use :ref:`krillc bulk refresh<cmd_krillc_bulk_refresh>`
if you are debugging an issue.

The JSON response returned by the server contains some additional information, in particular about the
certificates used by parent CAs to sign the certificates of your CA:

.. code-block:: json

  {
    "my_parent": {
      "last_exchange": {
        "timestamp": 1617881400,
        "uri": "https://localhost:3000/rfc8181/localname/",
        "result": "Success"
      },
      "last_success": 1617881400,
      "all_resources": {
        "asn": "AS65000",
        "ipv4": "10.0.0.0/8",
        "ipv6": "2001:db8::/32"
      },
      "classes": [
        {
          "class_name": "0",
          "resource_set": {
            "asn": "AS65000",
            "ipv4": "10.0.0.0/8",
            "ipv6": "2001:db8::/32"
          },
          "not_after": "2023-03-15T14:23:57Z",
          "issued_certs": [
            {
              "uri": "rsync://localhost/repo/testbed/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.cer",
              "req_limit": {},
              "cert": "MII..."
            }
          ],
          "signing_cert": {
            "url": "rsync://localhost/repo/ta/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.cer",
            "cert": "MII..."
          }
        }
      ]
    }
  }

Example API:

.. code-block:: text

  $ krillc parents statuses --ca newca --api
  GET:
    https://localhost:3000/api/v1/cas/newca/parents
  Headers:
    Authorization: Bearer secret


.. _cmd_krillc_parents_contact:

krillc parents contact
----------------------

Show contact information for a parent of this CA.

This can be useful for verifying that the parent contact information matches
the :rfc:`8183` Parent Response that is expected for the given parent.

The API returns the response in JSON format, but this is converted to XML by
the CLI when the default text format is used.

.. code-block:: text

  $ krillc parents contact --ca newca --parent my_parent


Here we will show the JSON output:

.. code-block:: json

  {
    "type": "rfc6492",
    "tag": null,
    "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=",
    "parent_handle": "testbed",
    "child_handle": "newca",
    "service_uri": "https://localhost:3000/rfc6492/testbed"
  }

Example API:

.. code-block:: text

  $ krillc parents contact --ca newca --parent my_parent --api
  GET:
    https://localhost:3000/api/v1/cas/newca/parents/my_parent
  Headers:
    Authorization: Bearer secret


.. _cmd_krillc_parents_remove:

krillc parents remove
---------------------

Remove an existing parent from this CA.

The CA will do a best effort attempt to request revocation of any certificate received under
the parent - meaning that if the parent cannot be reached the operation just continues without
error. After all a parent may well be removed *because* it is no longer reachable. Furthermore
any RPKI published under those certificate(s) will be withdrawn.

Note that although revocations are requested the parent may not be aware that they have been
removed. You may want to notify them through different channels. The RPKI provisioning protocol
:rfc:`6492` does not have verbs by which a child CA can ask the parent to be removed completely.

Example CLI:

.. code-block:: text

  $ krillc parents remove --ca newca --parent my_parent


Example API:

.. code-block:: text

  $ krillc parents remove --ca newca --parent my_parent --api
  DELETE:
    https://localhost:3000/api/v1/cas/newca/parents/my_parent
  Headers:
    Authorization: Bearer secret

....

.. _cmd_krillc_repo:

krillc repo
-----------

Manage the repository where a CA will publish its objects. There are a number of
subcommands provided for this:

.. parsed-literal::

   USAGE:
       krillc repo [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`request<cmd_krillc_repo_request>`    Show RFC8183 Publisher Request
       :ref:`configure<cmd_krillc_repo_configure>`     Configure which repository this CA uses
       :ref:`show<cmd_krillc_repo_show>`       Show current repo config
       :ref:`status<cmd_krillc_repo_status>`      Show current repo status

.. _cmd_krillc_repo_request:

krillc repo request
-------------------

Show the :rfc:`8183` Publisher Request XML for a CA. You will need to hand this
over to your repository so that they can add your CA.

Example CLI:

.. code-block:: text

  $ krillc repo request --ca newca
  <publisher_request xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" publisher_handle="newca">
    <publisher_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJENzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEuL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8OlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEoBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtONdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9iKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDVbXTPM8YLRgc=</publisher_bpki_ta>
  </publisher_request>

The CLI will present the Publisher Request in its RFC XML format by default. The API supports both the
XML and an equivalent JSON format dependent on the file extension used in the request URI:

XML:

.. code-block:: text

  GET:
    https://localhost:3000/api/v1/cas/newca/id/publisher_request.xml
  Headers:
    Authorization: Bearer secret

JSON:

.. code-block:: text

  GET:
    https://localhost:3000/api/v1/cas/newca/id/publisher_request.json
  Headers:
    Authorization: Bearer secret

.. _cmd_krillc_repo_configure:

krillc repo configure
---------------------

This is used to configure the repository used by a CA.

Your CA needs a repository configuration before it will request any certificates from
parents. You can chose to configure a repository first and then add the first parent
to your CA, or vice versa. The order does not matter, but both are needed for your
CA to function.

You can use the CLI to configure a repository by submitting the :rfc:`8183` Repository
Response XML to your CA. Before committing the configuration Krill checks whether the
Publication Server can be reached and responds to a query sent by your CA. If this fails,
then an error is reported and the configuration is aborted. You can try again when you
think the issue has been resolved.

Example CLI:

.. code-block:: text

  $ krillc repo configure --ca newca --response ./data/new-ca-repository-response.xml


The API will accept the plain :rfc:`8183` Repository Response XML if it's posted
to the API path for the CA in question, but the CLI will post the XML formatted
as its JSON equivalent:

Example API:

.. code-block:: text

  $ krillc repo configure --ca newca --response ./data/new-ca-repository-response.xml --api
  POST:
    https://localhost:3000/api/v1/cas/newca/repo
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "repository_response": {
      "tag": null,
      "publisher_handle": "localname",
      "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg4OEJBMzA2QkMzMUVFRkU3NzRDNzYzRUY1N0VBNUZEQzdBMTlERTI1MB4XDTIxMDMyOTA3NTg0M1oXDTM2MDMyOTA4MDM0M1owMzExMC8GA1UEAxMoODhCQTMwNkJDMzFFRUZFNzc0Qzc2M0VGNTdFQTVGREM3QTE5REUyNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAORLpfOKS8M2QGBto1OdnDYdrgjxJeF+uU7mJLgqTT3l5NbkOXxgPClUqbbbfp/c7x5sy3JbmUWaQHtkl6N9l8vcRlQQfhk0vwlVCHcQQrcMViJ5GmGtEjo7+Uf9e0TDA+rrkdqOkpOLcGRKjs1SZNqCRktubQU7Ndc0ICLo6KsQ5VYvw0p6YJcsL33+jcOWsFe6D4dhYlQkw5QHXn5c0Eenvz1SQqE96pcXJ57gmnzO9iVjY9RqPoLWXSRub0pG3Q6x8naOq16uaJZyk8kVjYOayx5umR73fI9iyMG0YOF8H5vy6/gYAnYssX26kObXan0fD9rgv4aWK0Xzp5hwz1ECAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUiLowa8Me7+d0x2PvV+pf3HoZ3iUwHwYDVR0jBBgwFoAUiLowa8Me7+d0x2PvV+pf3HoZ3iUwDQYJKoZIhvcNAQELBQADggEBAMtieNiamax1gUeSeGuA72NucPCZIdx2JrTIDhCAjLmPpvnXu1djGSa07YpgLiosnbtMMfsQO2O/Yz1VkQUTjLn2x7DKwuL9A8+IrYELSth4aCNSgPkhZfDL238MflAxptNRAoIeRGn8l3oSg4AUzBuScErwvBbHWShO66nV0wzVFb+mLvNas3Wd/GMiZHI/MwGZpj86Q/8wvyyw2C0b0ddWaoXwDyJjuxja0nHPDHVriJ8/xsOfBk144n1zyP++apQXmXorCy4hs9GPyr+HGeoL6kNydDxdwzJLCqWW7u3wSnxjCJk+hfGq82qNm90ALv5PaOb58fDgWwBwuvTP0AA=",
      "service_uri": "https://localhost:3000/rfc8181/localname/",
      "repo_info": {
        "sia_base": "rsync://localhost/repo/localname/",
        "rrdp_notification_uri": "https://localhost:3000/rrdp/notification.xml"
      }
    }
  }

.. Important:: If you need to change your repository configuration, then
    follow :ref:`this<doc_krill_ca_migrate_repo>` process to migrate your
    CA to a new repository.

.. _cmd_krillc_repo_status:

krillc repo status
------------------

This subcommand can be used to verify the status between a CA and its repository. Note that Krill will
keep trying to re-sync CAs with their repositories in case of any issues and the response includes an
indication of the next planned moment for this. In other words, there should not be a need to trigger
this synchronisation manually, but for the impatient, you can use :ref:`krillc bulk sync<cmd_krillc_bulk_sync>`.

Example CLI:

.. code-block:: text

  $ krillc repo status --ca newca
  URI: https://localhost:3000/rfc8181/localname/
  Status: success
  Last contacted: 2021-04-08T09:53:27+00:00
  Next contact on or before: 2021-04-09T01:53:27+00:00


So the CLI text output does NOT include the files which are published. If you want to see these files
then you can look at the JSON response instead:

.. code-block:: json

  {
    "last_exchange": {
      "timestamp": 1617875607,
      "uri": "https://localhost:3000/rfc8181/localname/",
      "result": "Success"
    },
    "next_exchange_before": 1617933207,
    "published": [
      {
        "base64": "MIIJTQYJKoZIhvcNAQcCoIIJPjCCCToCAQMxDTALBglghkgBZQMEAgEwgZsGCyqGSIb3DQEJEAEaoIGLBIGIMIGFAgEBGA8yMDIxMDQwODA5NDgyNVoYDzIwMjEwNDA5MDk1MzI1WgYJYIZIAWUDBAIBMFMwURYsMTZCMzFDOTJFQjExNkJDNjAwMjZDNTA5NDRBRDQ0MjA1REQ5QUNCRC5jcmwDIQDYb3KmzVBt0Ee3CkVLOpcale0dr9EHoL/NWi2U6R7ffaCCBtgwggbUMIIFvKADAgECAhQfMMPbsoNAMCZM8zHTPf4QMZ06vjANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygxNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JEMB4XDTIxMDQwODA5NDgyNVoXDTIxMDQxNTA5NTMyNVowggItMYICKTCCAiUGA1UEAxOCAhwzMDgyMDEwQTAyODIwMTAxMDBBQzhDQzlEMkUzM0ZCQ0U4MzdDMDIwRUFFQzYyNjA4OEY3NkNFQTM3MTA3MzNBMDhFNTYyQTg5M0UyMDBDRTA2QkIzMUQ0QkU3QTJGNzQ5QTM0Rjg1RTYyODdCNjE1MzQzODA2NDJBOTUzNzQyQUY2RDM0RTIxRDY0MkJFOUMwQjg1OURDQjcxMDJGRDJGNDM1MjE1ODI0RDU5NjVFNDlBNDBGRDBFOTZCQTFDRjRDQkM3QzM3RkFCRTBBNzlCNkEzRkM4OTE2MzA1RjY1MjYwREE0NERCMUEzOEZBN0MzM0UwNzRGQTRBMTVFODc5MkJEQzQwMDZCQUM2Mzc4RkU3M0Y1MEMxQjRBMTdFQ0EwNjU4NkQwRjRERUFFREQzQzJGOTlDQ0E2NzM3ODU4MUZFRUM5RjRGNjk3QTcwN0I5QUY4Q0RGQTFDREE1RERCNzA3MUU3QjY5QTNCMDQ2MUJBMDMyOTg3OEVFOTkwMDBFNDhBQUU0NzIwMjY0OEI3RjZCNUZENDc4NUFBREIzMUUwM0U0QjMxNzEzQTNGODVFNzQ4RjFCQUY0QURBNjQyMUFFODE4QjIwOEFFQkVCMUQwQjAxNzk0NEQyRTM0MDkxODExQzFFNzk5RDI3MDVBQ0IwNkQxMUEwQzQ0NjdGODlCMjU4RjBFNEY2OTRBQjkwQjAyMDMwMTAwMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsjMnS4z+86DfAIOrsYmCI92zqNxBzOgjlYqiT4gDOBrsx1L56L3SaNPheYoe2FTQ4BkKpU3Qq9tNOIdZCvpwLhZ3LcQL9L0NSFYJNWWXkmkD9Dpa6HPTLx8N/q+Cnm2o/yJFjBfZSYNpE2xo4+nwz4HT6ShXoeSvcQAa6xjeP5z9QwbShfsoGWG0PTert08L5nMpnN4WB/uyfT2l6cHua+M36HNpd23Bx57aaOwRhugMph47pkADkiq5HICZIt/a1/UeFqtsx4D5LMXE6P4XnSPG69K2mQhroGLIIrr6x0LAXlE0uNAkYEcHnmdJwWssG0RoMRGf4myWPDk9pSrkLAgMBAAGjggHiMIIB3jAdBgNVHQ4EFgQU0iBYgw/6TJwtHRc735eady5RAOIwHwYDVR0jBBgwFoAUFrMckusRa8YAJsUJRK1EIF3ZrL0wDgYDVR0PAQH/BAQDAgeAMGAGA1UdHwRZMFcwVaBToFGGT3JzeW5jOi8vbG9jYWxob3N0L3JlcG8vbG9jYWxuYW1lLzAvMTZCMzFDOTJFQjExNkJDNjAwMjZDNTA5NDRBRDQ0MjA1REQ5QUNCRC5jcmwwaQYIKwYBBQUHAQEEXTBbMFkGCCsGAQUFBzAChk1yc3luYzovL2xvY2FsaG9zdC9yZXBvL3Rlc3RiZWQvMC8xNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JELmNlcjBrBggrBgEFBQcBCwRfMF0wWwYIKwYBBQUHMAuGT3JzeW5jOi8vbG9jYWxob3N0L3JlcG8vbG9jYWxuYW1lLzAvMTZCMzFDOTJFQjExNkJDNjAwMjZDNTA5NDRBRDQ0MjA1REQ5QUNCRC5tZnQwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAhBggrBgEFBQcBBwEB/wQSMBAwBgQCAAEFADAGBAIAAgUAMBUGCCsGAQUFBwEIAQH/BAYwBKACBQAwDQYJKoZIhvcNAQELBQADggEBAJQiHZ91d7/a52qM0DyXp7jbkygm2MkT5tc6pp6sxHv6pDfXxAzJS8OtgcFCTDKC57pKvVvw8THE079nbMSxfaA5nP8egedxeuTzrj8iOh9nHk/X4pWhIWsAvNgiTebYj+Eax97MmRWAkDgxWpDQ+CWQBl2gBstLmBKCBTw6cFlkGrBCLVe+gSDTnHpy4ltza6pD+EawTNrGLBnFn+/+dgzx/GA2qbRXiBLm2/R4HR7zI/QYy+wWDoaZraCu6dUZEF4WomS99aihEyNp8tzyuEntmmMfw0z/xYt1I7VN1pzc5umEPksSRvILmA3eJO3Khw2xWZzYjYcVyZAo0QbujdExggGqMIIBpgIBA4AU0iBYgw/6TJwtHRc735eady5RAOIwCwYJYIZIAWUDBAIBoGswGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEaMBwGCSqGSIb3DQEJBTEPFw0yMTA0MDgwOTUzMjVaMC8GCSqGSIb3DQEJBDEiBCDjDAYghzZK/MgJG2G+mOfNzHsAV6ysGcb89bMa7KTEmTANBgkqhkiG9w0BAQEFAASCAQCHxZ3CeXicDOpmXZ/uhEGtvsuzpepVryk58zBLnSpbKfjnJWwiL0t3PsvlQuKAXgW0Xc5cC4Bbvb8Aysr4W1c0SKjnWz4dPLqgNCzvIVJRToc2xHFd6lbJGuqii6tNRvYKzPtuUMrToyHTgh6+SdWI98RsBVtQsSt68f6620ow9r4aGjdXokkayCyOBZ/DF2j3h8eZpEM1Y09kOTQfwkn297UYOv9Hi74iKIzhS3+8FmfSP0UTA207+U7HBQp9SNkK2HjFa3milgV+hJHOPutNsbgvwd5YPAFMbuve+J5k4/qvfTN0hZlGafx5ODIppv+tqJ76zts9wzgVXrpl6tKQ",
        "uri": "rsync://localhost/repo/localname/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.mft"
      },
      {
        "base64": "MIIBrzCBmAIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygxNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JEFw0yMTA0MDgwOTQ4MjVaFw0yMTA0MDkwOTUzMjVaMACgLzAtMB8GA1UdIwQYMBaAFBazHJLrEWvGACbFCUStRCBd2ay9MAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUAA4IBAQDJ3GxaYCxDCyfyfqdsUtM/OQx341/wWYrBrEAQ56NE6AVN+r0qjmO2mhNgVNQ1VdCLjo67ilQufmxGhtUQxBS625f1hr69cYw1l15wHDP4SFpXO96ysTxBhxpLGL215nT0S6FkQ+PLJ2IFLMhwn7Sns7RpQ9HDugNtz7QMRLbxeAz8ckeJHItUfyTpBhsweZEocTej1I7K4FugjZ+qSLDUFiy3QIcHO7lkepPraWLz9RVMuaJjcA7gAz3lNrtdRkygWRwGEC0eDwBa7MJ44feymQjsol6cr7m09MjSqTJyrNECjuNvLfilYuUMdW965Ih1HJQySE+FaetLQLbsTJxr",
        "uri": "rsync://localhost/repo/localname/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.crl"
      }
    ]
  }



Example API:


.. code-block:: text

  $ krillc repo status --ca newca --api
  GET:
    https://localhost:3000/api/v1/cas/newca/repo/status
  Headers:
    Authorization: Bearer secret


.. _cmd_krillc_repo_show:

krillc repo show
----------------

Show the repository configuration for your CA.

Example CLI:

.. code-block:: text

  $ krillc repo show --ca newca
  Repository Details:
    service uri: https://localhost:3000/rfc8181/localname/
    base_uri:    rsync://localhost/repo/localname/
    rpki_notify: https://localhost:3000/rrdp/notification.xml


Example API:

.. code-block:: text

  $ krillc repo show --ca newca --api
  GET:
    https://localhost:3000/api/v1/cas/newca/repo
  Headers:
    Authorization: Bearer secret

....

.. _cmd_krillc_show:

krillc show
-----------

Shows lots of details of a CA. Note, we may still extend the JSON response in future
but we will aim to add new information only.

Example CLI:

.. code-block:: text

  $ krillc show --ca newca
  Name:     newca

  Base uri: rsync://localhost/repo/localname/
  RRDP uri: https://localhost:3000/rrdp/notification.xml

  ID cert PEM:
  -----BEGIN CERTIFICATE-----
  MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJE
  NzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0
  MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2
  QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEP
  ADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8
  ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEu
  L+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8O
  lB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEo
  BjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3
  Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUw
  AwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU
  7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtO
  NdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh
  3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9i
  KantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ
  7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6
  t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDV
  bXTPM8YLRgc=
  -----END CERTIFICATE-----

  Hash: 992ac17d85fef11d8be4aa37806586ce68b61fe9cf65c0965928dbce0c398a99

  Total resources:
      ASNs: AS65000
      IPv4: 10.0.0.0/8
      IPv6: 2001:db8::/32

  Parents:
  Handle: my_parent Kind: RFC 6492 Parent

  Resource Class: 0
  Parent: my_parent
  State: active    Resources:
      ASNs: AS65000
      IPv4: 10.0.0.0/8
      IPv6: 2001:db8::/32

  Children:
  <none>


Example JSON response of the API:

.. code-block:: json

  {
    "handle": "newca",
    "id_cert": {
      "pem": "-----BEGIN CERTIFICATE-----\nMIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJE\nNzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0\nMzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2\nQTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8\nugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEu\nL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8O\nlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEo\nBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3\nPi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUw\nAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU\n7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtO\nNdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh\n3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9i\nKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ\n7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6\nt/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDV\nbXTPM8YLRgc=\n-----END CERTIFICATE-----\n",
      "hash": "992ac17d85fef11d8be4aa37806586ce68b61fe9cf65c0965928dbce0c398a99"
    },
    "repo_info": {
      "sia_base": "rsync://localhost/repo/localname/",
      "rrdp_notification_uri": "https://localhost:3000/rrdp/notification.xml"
    },
    "parents": [
      {
        "handle": "my_parent",
        "kind": "rfc6492"
      }
    ],
    "resources": {
      "asn": "AS65000",
      "ipv4": "10.0.0.0/8",
      "ipv6": "2001:db8::/32"
    },
    "resource_classes": {
      "0": {
        "name_space": "0",
        "parent_handle": "my_parent",
        "keys": {
          "active": {
            "active_key": {
              "key_id": "16B31C92EB116BC60026C50944AD44205DD9ACBD",
              "incoming_cert": {
                "cert": "MIIFYDCCBEigAwIBAgIUN5PzATTKVrjgual4CpJMaggW2EIwDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQzAeFw0yMTA0MDgwOTQ4MjVaFw0yMjA0MDcwOTUzMjVaMDMxMTAvBgNVBAMTKDE2QjMxQzkyRUIxMTZCQzYwMDI2QzUwOTQ0QUQ0NDIwNUREOUFDQkQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsBouGWEPhWg+XsRDGZyuFLDPiIExy7p4b3bjNPBfHeSqHCeOwiVIVS2xiIAGO2NBcv+hL2OFKNCAnpd71hOXMBNXW/7OHN8TU6crIu1/w1gkf6UCXFrv+poW9EJHnLonMa4ZFLSFsvQACIGUpxIuiQjaSYFltTbb+o2c9KWoKsX0kZqt5zOrgAP8cke8SFGHdqqenPInXKTgyss9kCs9pFtMk6BIa6KjRvqFVZIf6xG53ytJ3JqsGjvEo8qoHYxkvkMtbjhjlmW097i6DeC1241X3SG64DSMk1CNv1xt5MSXubLzWOD+2lLId/ngql4OV0bLkbb63J/26c8FZOThZAgMBAAGjggJqMIICZjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQWsxyS6xFrxgAmxQlErUQgXdmsvTAfBgNVHSMEGDAWgBQLpcEyuUiRyy06ie3hLwGspLzT3DAOBgNVHQ8BAf8EBAMCAQYwXgYDVR0fBFcwVTBToFGgT4ZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jcmwwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhyc3luYzovL2xvY2FsaG9zdC9yZXBvL3RhLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jZXIwgdgGCCsGAQUFBwELBIHLMIHIMC8GCCsGAQUFBzAFhiNyc3luYzovL2xvY2FsaG9zdC9yZXBvL2xvY2FsbmFtZS8wLzBbBggrBgEFBQcwCoZPcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9sb2NhbG5hbWUvMC8xNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JELm1mdDA4BggrBgEFBQcwDYYsaHR0cHM6Ly9sb2NhbGhvc3Q6MzAwMC9ycmRwL25vdGlmaWNhdGlvbi54bWwwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAsBggrBgEFBQcBBwEB/wQdMBswCgQCAAEwBAMCAAowDQQCAAIwBwMFACABDbgwGgYIKwYBBQUHAQgBAf8ECzAJoAcwBQIDAP3oMA0GCSqGSIb3DQEBCwUAA4IBAQB8hxBbJjvgVRMfXsotTNwKCc2Q0QO92xmZlV19Uh0/Yja+sYhyg/pG1/ZTvhOLIxGWap8JmqOnYa9XgX8uUlsV8LgJoEH3Gde3txcGtfLO99ugvbnKKGOcPxB8AX5hAhhfdiSnt3V06dEz3HUoTYdUKTV0bZr3dhRIBa94esAS7lsP2vhHEQ8gVjZGWVvS7lGju+kuwm9H3PBscW/K8349vN0QJUZGm3gAUsM5PlnAqbkM7VFIyu8g2Yp9g+M/iwaHar8CqABKxLBThYgqrPLLv6CsZD3mjk5BkXVZh6R9dBcR7sPbSfGBWPWCv8SwLknyQDOvsWTho1Ga6AibjUQp",
                "uri": "rsync://localhost/repo/testbed/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.cer",
                "resources": {
                  "asn": "AS65000",
                  "ipv4": "10.0.0.0/8",
                  "ipv6": "2001:db8::/32"
                }
              },
              "request": null
            }
          }
        }
      }
    },
    "children": [],
    "suspended_children": []
  }


Example API call:

.. code-block:: text

  $ krillc show --ca newca --api
  GET:
    https://localhost:3000/api/v1/cas/newca
  Headers:
    Authorization: Bearer secret


....

.. _cmd_krillc_issues:

krillc issues
-------------

Show issues for CAs. The response will be empty unless there are actual current
issues.

Example CLI:

.. code-block:: text

  $ krillc issues --ca newca
  no issues found


Example JSON response with issues:

.. code-block:: json

  {
    "repo_issue": {
      "label": "sys-http-client",
      "msg": "HTTP client error: Access Forbidden",
      "args": {
        "cause": "Access Forbidden"
      }
    },
    "parent_issues": [
      {
        "parent": "parent",
        "issue": {
          "label": "rfc6492-invalid-signature",
          "msg": "Invalidly signed RFC 6492 CMS",
          "args": {}
        }
      }
    ]
  }


Example API call:

.. code-block:: text

  $ krillc issues --ca newca --api
  GET:
    https://localhost:3000/api/v1/cas/newca/issues
  Headers:
    Authorization: Bearer secret

....

.. _cmd_krillc_history:

krillc history
--------------

Show the history of a CA. Using this command you can show the history of all
the things that happened to your CA.

There are two subcommands for this:

.. parsed-literal::

   USAGE:
       krillc history [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`commands<cmd_krillc_history_commands>`    Show the commands sent to a CA
       :ref:`details<cmd_krillc_history_details>`     Show details for a command in the history of a CA

.. _cmd_krillc_history_commands:

krillc history commands
-----------------------

With this subcommand you can look at an overview of all commands that were sent to a CA.

Example CLI:

.. code-block:: text

  $ krillc history commands --ca newca
  time::command::key::success
  2021-04-07T15:25:01Z::Add parent 'my_parent' as 'RFC 6492 Parent' ::command--1617809101--1--cmd-ca-parent-add::OK
  2021-04-08T09:53:23Z::Update repo to server at: https://localhost:3000/rfc8181/localname/ ::command--1617875603--2--cmd-ca-repo-update::OK
  2021-04-08T09:53:24Z::Update entitlements under parent 'my_parent': 0 => asn: AS65000, v4: 10.0.0.0/8, v6: 2001:db8::/32  ::command--1617875604--3--cmd-ca-parent-entitlements::OK
  2021-04-08T09:53:25Z::Update received cert in RC '0', with resources 'asn: 1 blocks, v4: 1 blocks, v6: 1 blocks' ::command--1617875605--4--cmd-ca-rcn-receive::OK


The JSON response includes some data which we do not (yet) show in the text output - e.g. the name of
the user who sent a command. This will become more relevant in future as people start using the multi-user
feature of the Krill UI:

.. code-block:: json

  {
    "offset": 0,
    "total": 4,
    "commands": [
      {
        "key": "command--1617809101--1--cmd-ca-parent-add",
        "actor": "master-token",
        "timestamp": 1617809101616,
        "handle": "newca",
        "version": 1,
        "sequence": 1,
        "summary": {
          "msg": "Add parent 'my_parent' as 'RFC 6492 Parent'",
          "label": "cmd-ca-parent-add",
          "args": {
            "parent": "my_parent",
            "parent_contact": "RFC 6492 Parent"
          }
        },
        "effect": {
          "result": "success",
          "events": [
            1
          ]
        }
      },
      {
        "key": "command--1617875603--2--cmd-ca-repo-update",
        "actor": "master-token",
        "timestamp": 1617875603613,
        "handle": "newca",
        "version": 2,
        "sequence": 2,
        "summary": {
          "msg": "Update repo to server at: https://localhost:3000/rfc8181/localname/",
          "label": "cmd-ca-repo-update",
          "args": {
            "service_uri": "https://localhost:3000/rfc8181/localname/"
          }
        },
        "effect": {
          "result": "success",
          "events": [
            2
          ]
        }
      },
      {
        "key": "command--1617875604--3--cmd-ca-parent-entitlements",
        "actor": "krill",
        "timestamp": 1617875604550,
        "handle": "newca",
        "version": 3,
        "sequence": 3,
        "summary": {
          "msg": "Update entitlements under parent 'my_parent': 0 => asn: AS65000, v4: 10.0.0.0/8, v6: 2001:db8::/32 ",
          "label": "cmd-ca-parent-entitlements",
          "args": {
            "parent": "my_parent"
          }
        },
        "effect": {
          "result": "success",
          "events": [
            3,
            4
          ]
        }
      },
      {
        "key": "command--1617875605--4--cmd-ca-rcn-receive",
        "actor": "krill",
        "timestamp": 1617875605662,
        "handle": "newca",
        "version": 5,
        "sequence": 4,
        "summary": {
          "msg": "Update received cert in RC '0', with resources 'asn: 1 blocks, v4: 1 blocks, v6: 1 blocks'",
          "label": "cmd-ca-rcn-receive",
          "args": {
            "asn_blocks": "1",
            "class_name": "0",
            "ipv4_blocks": "1",
            "ipv6_blocks": "1",
            "resources": "asn: AS65000, v4: 10.0.0.0/8, v6: 2001:db8::/32"
          }
        },
        "effect": {
          "result": "success",
          "events": [
            5
          ]
        }
      }
    ]
  }


The CLI and API support pagination:

.. parsed-literal::
    --after <<RFC 3339 DateTime>>     Show commands issued after date/time in RFC 3339 format, e.g. 2020-04-
                                      09T19:37:02Z
    --before <<RFC 3339 DateTime>>    Show commands issued after date/time in RFC 3339 format, e.g. 2020-04-
                                      09T19:37:02Z
    --offset <<number>>               Number of results to skip
    --rows <<number>>                 Number of rows (max 250)

And these values are converted to path parameters in the API call:

.. code-block:: text

  $ krillc history commands --ca newca --after 2020-12-01T00:00:00Z --before 2021-04-09T00:00:00Z --rows 2 --offset 1 --api
  GET:
    https://localhost:3000/api/v1/cas/newca/history/commands/2/1/1606780800/1617926400
  Headers:
    Authorization: Bearer secret


.. _cmd_krillc_history_details:

krillc history details
----------------------

Show details for a specific historic CA command. This subcommand expects the command
key as reported by :ref:`krillc history commands<cmd_krillc_history_commands>`.

The text output of the CLI will show a summary of the command details, and the state
changes in the CA (called events) that followed:

.. code-block:: text

  $ krillc history details --ca newca --key command--1617875604--3--cmd-ca-parent-entitlements
  Time:   2021-04-08T09:53:24Z
  Action: Update entitlements under parent 'my_parent': 0 => asn: AS65000, v4: 10.0.0.0/8, v6: 2001:db8::/32
  Changes:
    added resource class with name '0'
    requested certificate for key (hash) '16B31C92EB116BC60026C50944AD44205DD9ACBD' under resource class '0'


If you want to see the full details, then have a look at the JSON response instead:

.. code-block:: json

  {
    "command": {
      "actor": "krill",
      "time": "2021-04-08T09:53:24.550017Z",
      "handle": "newca",
      "version": 3,
      "sequence": 3,
      "details": {
        "type": "update_resource_entitlements",
        "parent": "my_parent",
        "entitlements": [
          {
            "resource_class_name": "0",
            "resources": {
              "asn": "AS65000",
              "ipv4": "10.0.0.0/8",
              "ipv6": "2001:db8::/32"
            }
          }
        ]
      },
      "effect": {
        "result": "success",
        "events": [
          3,
          4
        ]
      }
    },
    "result": {
      "Events": [
        {
          "id": "newca",
          "version": 3,
          "details": {
            "type": "resource_class_added",
            "resource_class_name": "0",
            "parent": "my_parent",
            "parent_resource_class_name": "0",
            "pending_key": "16B31C92EB116BC60026C50944AD44205DD9ACBD"
          }
        },
        {
          "id": "newca",
          "version": 4,
          "details": {
            "type": "certificate_requested",
            "resource_class_name": "0",
            "req": {
              "class_name": "0",
              "limit": {
                "asn": "none",
                "ipv4": "none",
                "ipv6": "none"
              },
              "csr": "MIIDjzCCAncCAQAwMzExMC8GA1UEAxMoMTZCMzFDOTJFQjExNkJDNjAwMjZDNTA5NDRBRDQ0MjA1REQ5QUNCRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOwGi4ZYQ+FaD5exEMZnK4UsM+IgTHLunhvduM08F8d5KocJ47CJUhVLbGIgAY7Y0Fy/6EvY4Uo0ICel3vWE5cwE1db/s4c3xNTpysi7X/DWCR/pQJcWu/6mhb0QkecuicxrhkUtIWy9AAIgZSnEi6JCNpJgWW1Ntv6jZz0pagqxfSRmq3nM6uAA/xyR7xIUYd2qp6c8idcpODKyz2QKz2kW0yToEhroqNG+oVVkh/rEbnfK0ncmqwaO8SjyqgdjGS+Qy1uOGOWZbT3uLoN4LXbjVfdIbrgNIyTUI2/XG3kxJe5svNY4P7aUsh3+eCqXg5XRsuRtvrcn/bpzwVk5OFkCAwEAAaCCARUwggERBgkqhkiG9w0BCQ4xggECMIH/MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMIHbBggrBgEFBQcBCwEBAASByzCByDAvBggrBgEFBQcwBYYjcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9sb2NhbG5hbWUvMC8wWwYIKwYBBQUHMAqGT3JzeW5jOi8vbG9jYWxob3N0L3JlcG8vbG9jYWxuYW1lLzAvMTZCMzFDOTJFQjExNkJDNjAwMjZDNTA5NDRBRDQ0MjA1REQ5QUNCRC5tZnQwOAYIKwYBBQUHMA2GLGh0dHBzOi8vbG9jYWxob3N0OjMwMDAvcnJkcC9ub3RpZmljYXRpb24ueG1sMA0GCSqGSIb3DQEBCwUAA4IBAQBFxEkEqMOnNWuIZalQkX/hxjAia3vtLrYtET1InOF/5UtRClDX5EWl34JRCXEIkDgWWbCVmxQyTw0VfqKImT/JqzC/NXrWMJBVJ27JgkHH5TITHGgfIjDRS19+JOFdiCBlQWgU3V5zfMGlB0263xRteX7A1kLedLuvt51DgNMwyWFgp/PkJKUCTEYi27j6DOF5J8jZ7JD5lMBs7gOGAiUJSzCBY7XfjEeVmePRLJ8hB0Wa/n3h+ni6UTOF6itKPmHqddxpiEb8ij987gCTjuZQisi9j+JKoPqzXon2vOx+GJjo4Sb++HD0buatiEmj5SvUmV8gl0F/msh4F4a5YG8r"
            },
            "ki": "16B31C92EB116BC60026C50944AD44205DD9ACBD"
          }
        }
      ]
    }
  }


Example API call:

.. code-block:: text

  $ krillc history details --ca newca --key command--1617875604--3--cmd-ca-parent-entitlements --api
  GET:
    https://localhost:3000/api/v1/cas/newca/history/details/command--1617875604--3--cmd-ca-parent-entitlements
  Headers:
    Authorization: Bearer secret

....

.. _cmd_krillc_roas:

krillc roas
-----------

Manage ROAs for your CA.

Krill lets users create Route Origin Authorisations (ROAs), the signed objects
that state which Autonomous System (AS) is authorised to originate one of your
prefixes, along with the maximum prefix length it may have.

Note that we use a Krill specific notation for desscribing ROAs.

.. code-block::

   <prefix>[-max-length] => <ASN> [# optional comment]

   Examples:
   185.49.140.0/22 => 65501
   185.49.140.0/22 => 65501 # with comment
   185.49.140.0/22-22 => 65501 # with explicit max length equal to prefix length
   185.49.140.0/22-24 => 65501 # with max length allowing more specifics

.. Important:: Krill CAs let operators configure which authorizations they want
    to have on ROA **objects**. But it's Krill that will figure out which objects
    to create for this. I.e. users just configure their intent to authorise an
    ASN to originate a prefix, but they do not need to worry about things like
    the actual ROA encoding, before and after times, object renewals, publishing,
    and under which parent the ROA is to be created - if there are multiple.
    However, we will refer to these authorizations as ROAs, because for all intent
    and purposes this difference is an implementation detail that Krill, by design,
    abstracts away from the operator.



.. parsed-literal::

   USAGE:
       krillc roas [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`list<cmd_krillc_roas_list>`      Show current authorizations
       :ref:`update<cmd_krillc_roas_update>`    Update authorizations
       :ref:`bgp<cmd_krillc_roas_bgp>`       Show current authorizations in relation to known announcements

.. _cmd_krillc_roas_list:

krillc roas list
----------------

Show current configured ROAs.

.. parsed-literal::

   USAGE:
       krillc roas list [FLAGS] [OPTIONS]

   OPTIONS:
       -c, --ca <name>         The name of the CA you wish to control. Or set env: KRILL_CLI_MY_CA

The text output shows all your current ROA configurations:

.. code-block:: bash

   $ krillc roas list
   185.49.140.0/22-22 => 65501
   2a04:b900::/29-29 => 65503 # my v6 router
   185.49.140.0/22-22 => 65502 # my secondary!!

The JSON response also includes information about the ROA objects that
were issued for each of your configurations. Typically, you will have
exactly one ROA object issued for each configuration. However, you may
have more than one ROA object in case your CA holds the same prefix under
more than one parent organisation - this should be extremely rare but
this can happen in theory. You may have 0 ROA objects in case you added
a ROA *configuration*, but you no longer hold the prefix on your CA
certificate(s).

Because of this the JSON response includes an array of ROA objects rather
than a single object:

.. code-block:: json

  [
    {
      "asn": 65502,
      "prefix": "185.49.140.0/22",
      "max_length": 22,
      "comment": "my secondary!!",
      "roa_objects": [
        {
          "authorizations": [
            "185.49.140.0/22-22 => 65502"
          ],
          "validity": {
            "not_before": "2022-09-09T11:12:07.726607Z",
            "not_after": "2023-09-08T11:17:07.726609Z"
          },
          "serial": "128656053576697823461520414002914294079408872181",
          "uri": "rsync://localhost/repo/ca/0/3138352e34392e3134302e302f32322d3232203d3e203635353032.roa",
          "base64": "MIIGxgYJKoZIhvcNAQcCoIIGtzCCBrMCAQMxDTALBglghkgBZQMEAgEwKgYLKoZIhvcNAQkQARigGwQZMBcCAwD/3jAQMA4EAgABMAgwBgMEArkxjKCCBMMwggS/MIIDp6ADAgECAhQWiSMQcj0WabA0/uwNQqQu5PCa9TANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhDQzI0ODdDRjNBOUM3NzRCRkFFMkRDRTRERDgzNjg0NDFDNzVDNzIwMB4XDTIyMDkwOTExMTIwN1oXDTIzMDkwODExMTcwN1owMzExMC8GA1UEAxMoQjcxODRCMjZGMjJFMTQxQ0QyQzFDRDM3QzJCRjg0Qzc0NTEwODg0MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMz5gS4RE2gWak6+C8wNJQckJK3iLf6x309WmTGPCe1SxnRc9mqxUxshpzAKgPKWqXpzsKUidTnAnQZzKlJeOnn/bMPcM5Kh3PSsD8ZPVGFVqN1YHE/1Y4kdWXyPMQThBh+sR2JHOspmMVz773bNouswV8o2MFNSQY0ODsntalya9dCnrKQ9eJ+hquADSVTvNq7bQ7VjtLIq0SfEMRZ3xZjce/QaOGRNaOpObD7DUUygixUQpIZGtsDsQTPPOIIiCqkQzYaykE3HGwcMIu/xoeCQTDIBCETQWAvl8l91y/dDTqlCM6pDRvDE0h1AXWp5+N4u4bzAb6h+r9fkOFZQAo8CAwEAAaOCAckwggHFMB0GA1UdDgQWBBS3GEsm8i4UHNLBzTfCv4THRRCIQzAfBgNVHSMEGDAWgBTMJIfPOpx3S/ri3OTdg2hEHHXHIDAOBgNVHQ8BAf8EBAMCB4AwWQYDVR0fBFIwUDBOoEygSoZIcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9jYS8wL0NDMjQ4N0NGM0E5Qzc3NEJGQUUyRENFNEREODM2ODQ0MUM3NUM3MjAuY3JsMGkGCCsGAQUFBwEBBF0wWzBZBggrBgEFBQcwAoZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvQ0MyNDg3Q0YzQTlDNzc0QkZBRTJEQ0U0REQ4MzY4NDQxQzc1QzcyMC5jZXIwcgYIKwYBBQUHAQsEZjBkMGIGCCsGAQUFBzALhlZyc3luYzovL2xvY2FsaG9zdC9yZXBvL2NhLzAvMzEzODM1MmUzNDM5MmUzMTM0MzAyZTMwMmYzMjMyMmQzMjMyMjAzZDNlMjAzNjM1MzUzMDMyLnJvYTAYBgNVHSABAf8EDjAMMAoGCCsGAQUFBw4CMB8GCCsGAQUFBwEHAQH/BBAwDjAMBAIAATAGAwQCuTGMMA0GCSqGSIb3DQEBCwUAA4IBAQBAWJ1E4zrF8xF/QFdJkVNDIoUwaVGxM8VFz8mh+KhDYzpGQEgGVcvNmsiGEXXJ4TkCfICinMEh88EhP/5kx0sE5dzaIxKdh+r6aoeIhSH3iKGYH1+ZDQ3dC1TiJSqDnK6wrs62A7R/oCOq1R9h6cqZ0GzIgJyG80Z9j1QleaS3evPuuSCgOls2MPlk68LR4Pn+rUwt7NVaDwXwXon0+QasB9mkjHa3mT1KP2OaZTsqcjTIy/Fdhxupi52+WEfNXYkQbr4sTIPKBoQD8JMa96DeZQtUlj/U7CbKR/jAaWmIevcUjw8u50k1o7UVaCxsaYETp2So1npX9bFBqJ6wCuo6MYIBqjCCAaYCAQOAFLcYSybyLhQc0sHNN8K/hMdFEIhDMAsGCWCGSAFlAwQCAaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABGDAcBgkqhkiG9w0BCQUxDxcNMjIwOTA5MTExNzA3WjAvBgkqhkiG9w0BCQQxIgQgb9OF51MA1l9ozTu3fsFGvz5KTdJmXLfr7OwirJ8NaTcwDQYJKoZIhvcNAQEBBQAEggEAN6SjlxmS9rgnbAV74xP7rvYhfyiIV9GTVApeojXg96xUej7AIuxYxTN/dHhTb00n4a2Xt2WYeJCu31x9n+Liib/wqSDut5zYJuZacl7gtPqiGAcckUesWyD6GORr65wXvMne7WxaZS2ud5eluLyoQPwzbnuJWdgm2zvqiLYFyBnc7K93eYoSRy16GxGNJjYke3XUY0w4mafF4w/f8v5obZmnNRb465/IBgAWpWJfsq49bCT6+ayiwAZ/ld6tKT/Bdmjw5mhA6ukWvVeO3+xB3t0mzgJEHHABvlvHK7dmZyzXUYbSkPzgS85WiLF+NsVmcBCzCci1cePDc00uDQHb5A==",
          "hash": "a5eb7f117a920f938cfee05294284e8107b0f2b4eb33306b44c0e0a4321f0730"
        }
      ]
    },
    {
      "asn": 65501,
      "prefix": "185.49.140.0/22",
      "max_length": 22,
      "comment": null,
      "roa_objects": [
        {
          "authorizations": [
            "185.49.140.0/22-22 => 65501"
          ],
          "validity": {
            "not_before": "2022-09-09T11:12:07.804941Z",
            "not_after": "2023-09-08T11:17:07.804943Z"
          },
          "serial": "383786375903727552044603555364114288366864376546",
          "uri": "rsync://localhost/repo/ca/0/3138352e34392e3134302e302f32322d3232203d3e203635353031.roa",
          "base64": "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",
          "hash": "b84e4a840bfa171c22836be8b9918a1a85da1f1578fa168a4cf598f73adf9d01"
        }
      ]
    },
    {
      "asn": 65503,
      "prefix": "2a04:b900::/29",
      "max_length": 29,
      "comment": "my v6 router",
      "roa_objects": [
        {
          "authorizations": [
            "2a04:b900::/29-29 => 65503"
          ],
          "validity": {
            "not_before": "2022-09-09T11:12:07.764079Z",
            "not_after": "2023-09-08T11:17:07.764081Z"
          },
          "serial": "725767789577338305707073298821075818220425658157",
          "uri": "rsync://localhost/repo/ca/0/326130343a623930303a3a2f32392d3239203d3e203635353033.roa",
          "base64": "MIIGxgYJKoZIhvcNAQcCoIIGtzCCBrMCAQMxDTALBglghkgBZQMEAgEwKwYLKoZIhvcNAQkQARigHAQaMBgCAwD/3zARMA8EAgACMAkwBwMFAyoEuQCgggTCMIIEvjCCA6agAwIBAgIUfyCNoaRxBo0L8TDM3oYpk+rtPy0wDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoQ0MyNDg3Q0YzQTlDNzc0QkZBRTJEQ0U0REQ4MzY4NDQxQzc1QzcyMDAeFw0yMjA5MDkxMTEyMDdaFw0yMzA5MDgxMTE3MDdaMDMxMTAvBgNVBAMTKDdGRkU0MDZDQTM0QURDMjdEQTdBMkVGQ0RDMkQ2QThGMzI5OTI2MTQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0HIIJJlCBsTicJBHris5xy3Vrq8KRle9MyAZOJgbjojiccCw2a+M50oMEdXk2KRooKSOVdcxEi1jQ1h2nZo6AKTIbxSngRWVLhIA9UBIIxX4aIl6z2llHbx0PGS06KurV6Vcr+3LntLqwxY0ID7q0/Dt9dL9yZGHF7vt9dDPPNjbzrwE1hVfo9LomhPW/skh5dOrcge75PJZjmy0CSKFasEt4veEfDcjFGxnE1MWhh2JhVOGwMY5/IG1e12izhpsy1csRldUT4a1vrjKmu/tkgr1hk5+5JTg6FinAd8cva5xyyhfwcgZ2BJiwbUCpqPumC/VoLGQJo83mDRJb1lEFAgMBAAGjggHIMIIBxDAdBgNVHQ4EFgQUf/5AbKNK3Cfaei783C1qjzKZJhQwHwYDVR0jBBgwFoAUzCSHzzqcd0v64tzk3YNoRBx1xyAwDgYDVR0PAQH/BAQDAgeAMFkGA1UdHwRSMFAwTqBMoEqGSHJzeW5jOi8vbG9jYWxob3N0L3JlcG8vY2EvMC9DQzI0ODdDRjNBOUM3NzRCRkFFMkRDRTRERDgzNjg0NDFDNzVDNzIwLmNybDBpBggrBgEFBQcBAQRdMFswWQYIKwYBBQUHMAKGTXJzeW5jOi8vbG9jYWxob3N0L3JlcG8vdGVzdGJlZC8wL0NDMjQ4N0NGM0E5Qzc3NEJGQUUyRENFNEREODM2ODQ0MUM3NUM3MjAuY2VyMHAGCCsGAQUFBwELBGQwYjBgBggrBgEFBQcwC4ZUcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9jYS8wLzMyNjEzMDM0M2E2MjM5MzAzMDNhM2EyZjMyMzkyZDMyMzkyMDNkM2UyMDM2MzUzNTMwMzMucm9hMBgGA1UdIAEB/wQOMAwwCgYIKwYBBQUHDgIwIAYIKwYBBQUHAQcBAf8EETAPMA0EAgACMAcDBQMqBLkAMA0GCSqGSIb3DQEBCwUAA4IBAQBEAKtyFG7RrQ8QxYeOjgZ9WWKvmnQFWXHZcOtR5Z9TcIwwDB8K/Ep2vPpyvJ23q/gaepwo2VMC2bt84jYkTWGTeKKqd3pCn3dOs17NldEmBU9etH8oMoRH0XcaSI6bSN56nu4PlCUgs5Qt9bl8qnDMLwtr9W530K9y6htfRV/0Goleg9J8kPJf32SNNKIos60LHY2zb4TJ9JVdnEC++tku0w7AbdhvaU37ekAIuGC+YeH/KHMcVln1+bx8y9CKDxsVmtqjzfE8c4WIoyWnbtwy2PbLcUWcRMDcJoCllXxryUea59lXw103WdskR70vCPGT6eIUfPw8msRdnW5xNCtgMYIBqjCCAaYCAQOAFH/+QGyjStwn2nou/Nwtao8ymSYUMAsGCWCGSAFlAwQCAaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABGDAcBgkqhkiG9w0BCQUxDxcNMjIwOTA5MTExNzA3WjAvBgkqhkiG9w0BCQQxIgQgrRdT14e2Dt+cfcphbSqTaWtKqpG4MmSQ5MCwdfzr+IowDQYJKoZIhvcNAQEBBQAEggEATGhF9lUpgNa8jInLpnTd9yW8nfdEtWtkH8yTGNm1TdbEN0VCUgWDEeKZEbU4c0tshMF8DWDPT1iwNauyf0rgEOvJZypeDrEhgdRaJSOGnfJZGz+oi5o4hwn4GI3Xv2ByZ9eVUTrhuyDr0+Tml/Cym7j9FUv5APObQ2LnHjr3paGHitJff+5V8NVr5FC39oF4weXQyqvXOTo7t3iuv5Fp+jPgwtUpl5qO3Ene44EAzrqLMaEj7vr62KVFVGX826jak/mEt+X9zS1G+FNGKF9WmPJGcRv39SfJzMfDg3ASUjCyHbqa1dntlqzfb8pEMdB7+QT/c6bUfjt6aTB2gVsliA==",
          "hash": "f35bd38a7cdec57faa9df7a76bb5b98c61b09385f25cd89b43e33973e70e0560"
        }
      ]
    }
  ]


.. Important:: Krill always uses an explicit max length for stored ROA configurations.
     You can leave out the max length when submitting a new ROA configuration, but
     Krill will then convert it to use an explicit max length equal to the prefix
     length internally. The reason behind this is that Krill wants to avoid duplicate
     equivalent entries in its configuration. The ROA *objects* generated by Krill
     will only use an explicit max length if it is indeed more specific than the
     prefix length.


.. _cmd_krillc_roas_update:

krillc roas update
------------------

Update ROAs.

The CLI supports adding or removing individual ROAs as well as submitting a file
with a delta of additions and removals as an atomic delta. In terms of the API these
options will call the same API end-point and always submit a JSON body with a delta.

* Add a single ROA

Example CLI usage to add a ROA:


.. code-block:: text

  $ krillc roas update --add '2a04:b900::/29 => 65503 # my v6 router'


This will submit the following JSON to the API:

.. code-block:: text

  $ krillc roas update --add "192.168.0.0/16 => 64496" --api
  POST:
    https://localhost:3000/api/v1/cas/ca/routes
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "added": [
      {
        "asn": 65503,
        "prefix": "2a04:b900::/29",
        "comment": "my v6 router"
      }
    ],
    "removed": []
  }

NOTE: if you want to leave out the comment in the API update
you can either set its value to `null` or leave the json field
out altogether in which case it will default to `null`.

.. Important:: ROA configurations can only be added if they are
     not yet present. Re-adding the same configuration will
     result in an error. That said, if an


* Remove a single ROA

Example CLI usage to remove a ROA:

.. code-block:: text

  $ krillc roas update --remove  '2a04:b900::/29 => 65503'

.. Important:: The # style comments are not allowed when
     removing ROAs and will result in an error if included
     here.


This will submit the following JSON to the API:

.. code-block:: text

  $ krillc roas update --remove  '2a04:b900::/29 => 65503' --api
  POST:
    https://localhost:3000/api/v1/cas/ca/routes
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "added": [],
    "removed": [
      {
        "asn": 65503,
        "prefix": "2a04:b900::/29"
      }
    ]
  }



* Update multiple ROAs

You can also update multiple ROAs as a single delta. You can either
use multiple `--add` and/or `--remove` arguments, or you can use
`--delta` and refer to a file with all updates using the following
format:

.. code-block:: text

   # Some comment
     # Indented comment

   A: 10.0.0.0/24 => 64496
   A: 10.1.0.0/16-20 => 64496   # Add prefix with max length
   R: 10.0.3.0/24 => 64496      # Remove existing authorization

And then call the CLI with the ``--delta`` option. The CLI will parse the delta file
and submit a JSON body containing multiple changes:


.. code-block:: text

  krillc roas update --delta ./data/roa-delta.txt --ca newca --api
  POST:
   https://localhost:3000/api/v1/cas/newca/routes
  Headers:
   content-type: application/json
   Authorization: Bearer secret
  Body:
  {
   "added": [
     {
       "asn": 64496,
       "prefix": "10.0.0.0/24"
     },
     {
       "asn": 64496,
       "prefix": "10.1.0.0/16",
       "max_length": 20
     }
   ],
   "removed": [
     {
       "asn": 64496,
       "prefix": "10.0.3.0/24"
     }
   ]
  }

* Errors

You will get an error response if ROA updates cannot be applied. For
example adding a duplicate ROA will result in the following error:

.. code-block:: text

  $ krillc roas update --ca newca --add "192.168.0.0/16 => 64496"
  Delta rejected:

  Cannot add the following duplicate ROAs:
    192.168.0.0/16-16 => 64496

The returned JSON for an error with with the label "ca-roa-delta-error" has a format similar
to the normal error response, but with the addition of a `delta_error` entry with details. There
you can expect 4 categories of errors:

+----------------+------------------------------------------------------------------+
| duplicates     | You are trying to add a ROA that already exists                  |
+----------------+------------------------------------------------------------------+
| notheld        | You are trying to add a ROA for a prefix you don't hold          |
+----------------+------------------------------------------------------------------+
| unknowns       | You are trying to remove a ROA that does not exist               |
+----------------+------------------------------------------------------------------+
| invalid_length | You specified an invalid length/max_length for a prefix          |
+----------------+------------------------------------------------------------------+

Example:

.. code-block:: json

  {
    "label": "ca-roa-delta-error",
    "msg": "Delta rejected, see included json",
    "args": {},
    "delta_error": {
      "duplicates": [
        {
          "asn": 1,
          "prefix": "10.0.0.0/20",
          "max_length": 24,
          "comment": null
        }
      ],
      "notheld": [
        {
          "asn": 1,
          "prefix": "10.128.0.0/9"
        }
      ],
      "unknowns": [
        {
          "asn": 1,
          "prefix": "192.168.0.0/16",
          "comment": null
        }
      ],
      "invalid_length": [
        {
          "asn": 1,
          "prefix": "10.0.1.0/25",
          "comment": null
        }
      ]
    }
  }


* Try

With RPKI ROAs you can create RPKI invalids in BGP if for example your prefix is multi homed
and you authorise one ASN, but not another. Another cause of invalids might be that you authorise
a covering prefix, but not more specific announcements that you do.

To help with this Krill also comes with a "try", or "feeling lucky" feature. Meaning that when
``--try`` is specified with an update, Krill will check the effect of the update against what it
knows about BGP announcements. If the effect has no negative side-effects then it will just be
applied, but if it would result in any invalid announcements then an error report will be
returned instead:

.. code-block:: text

  $ krillc roas update --ca newca --add "192.168.0.0/16 => 64496" --try
  Unsafe update, please review

  Effect would leave the following invalids:

    Announcements from invalid ASNs:
      192.168.0.0/24 => 64497

      192.168.1.0/24 => 64497


    Announcements too specific for their ASNs:

      192.168.0.0/24 => 64496

  You may want to consider this alternative:
  Authorize these announcements which are currently not covered:
    192.168.0.0/24 => 64496
    192.168.0.0/24 => 64497
    192.168.1.0/24 => 64497

Example JSON response:

.. code-block:: json

  {
    "effect": [
      {
        "asn": 64496,
        "prefix": "192.168.0.0/16",
        "max_length": 16,
        "state": "roa_disallowing",
        "comment": null,
        "roa_objects": [ ... ],
        "disallows": [
          {
            "asn": 64496,
            "prefix": "192.168.0.0/24"
          },
          {
            "asn": 64497,
            "prefix": "192.168.0.0/24"
          },
          {
            "asn": 64497,
            "prefix": "192.168.1.0/24"
          }
        ]
      },
      {
        "asn": 64496,
        "prefix": "192.168.0.0/24",
        "state": "announcement_invalid_length",
        "disallowed_by": [
          {
            "asn": 64496,
            "prefix": "192.168.0.0/16",
            "max_length": 16
          }
        ]
      },
      {
        "asn": 64497,
        "prefix": "192.168.0.0/24",
        "state": "announcement_invalid_asn",
        "disallowed_by": [
          {
            "asn": 64496,
            "prefix": "192.168.0.0/16",
            "max_length": 16
          }
        ]
      },
      {
        "asn": 64497,
        "prefix": "192.168.1.0/24",
        "state": "announcement_invalid_asn",
        "disallowed_by": [
          {
            "asn": 64496,
            "prefix": "192.168.0.0/16",
            "max_length": 16
          }
        ]
      }
    ],
    "suggestion": {
      "not_found": [
        {
          "asn": 64496,
          "prefix": "192.168.0.0/24"
        },
        {
          "asn": 64497,
          "prefix": "192.168.0.0/24"
        },
        {
          "asn": 64497,
          "prefix": "192.168.1.0/24"
        }
      ]
    }
  }


The API call for this is the same as when posting a normal ROA delta, except that `/try` is
appended to the path, e.g.: `POST https://localhost:3000/api/v1/cas/newca/routes/try`

.. Important:: Krill does this analysis based on RIPE RIS BGP information. This information
    may be outdated, or incomplete. More importantly it may also include erroneous or even
    malicious announcements that are seen in the global BGP. So **ALWAYS** review the report
    and suggestions returned by Krill! Note, we plan to support other ways of getting BGP
    information into Krill in future - e.g. by parsing a local BGP feed or table.

* Dryrun

The ``dryrun`` option is similar to ``try``, except that, well, it doesn't even try to apply
a change. It just reports the effects of a change including positive effects.. so, actually,
it *is* different:

.. code-block:: text

  $ krillc roas update --ca newca --add "10.0.0.0/24 => 64496" --dryrun
  Authorizations covering announcements seen:

          Definition: 10.0.0.0/24-24 => 64496

                  Authorizes:
                  10.0.0.0/24 => 64496

  Announcements which are valid:

          Announcement: 10.0.0.0/24 => 64496

.. _cmd_krillc_roas_bgp:

krillc roas bgp
---------------

.. Important:: Krill does BGP analysis based on RIPE RIS BGP information. This information
    may be outdated, or incomplete. More importantly it may also include erroneous or even
    malicious announcements that are seen in the global BGP. So **ALWAYS** review the reports
    and suggestions returned by Krill! Note, we plan to support other ways of getting BGP
    information into Krill in future - e.g. by parsing a local BGP feed or table.

The ROA vs BGP analysis is used in the ``try`` and ``dryrun`` options when applying a
ROA delta, but this can also be accessed proactively. For this the CLI has the following
subcommands:

.. parsed-literal::

   krillc roas bgp analyze   Show full report of ROAs vs known BGP announcements
   krillc roas bgp suggest   Show ROA suggestions based on known BGP announcements


Example of the analyze function:

.. code-block:: text

  $ krillc roas bgp analyze --ca newca
  Authorizations covering announcements seen:

          Definition: 192.168.0.0/24-24 => 64496

                  Authorizes:
                  192.168.0.0/24 => 64496

                  Disallows:
                  192.168.0.0/24 => 64497

  Authorizations disallowing announcements seen. You may want to use AS0 ROAs instead:

          Definition: 192.168.0.0/16-16 => 64496


                  Disallows:
                  192.168.0.0/24 => 64497
                  192.168.1.0/24 => 64497

  Announcements which are valid:

          Announcement: 192.168.0.0/24 => 64496

  Announcements from an unauthorized ASN:

          Announcement: 192.168.0.0/24 => 64497

                  Disallowed by authorization(s):
                  192.168.0.0/16-16 => 64496
                  192.168.0.0/24-24 => 64496

          Announcement: 192.168.1.0/24 => 64497

                  Disallowed by authorization(s):
                  192.168.0.0/16-16 => 64496

  Announcements which are 'not found' (not covered by any of your authorizations):

          Announcement: 10.0.0.0/21 => 64497
          Announcement: 10.0.0.0/22 => 64496
          Announcement: 10.0.0.0/22 => 64497
          Announcement: 10.0.0.0/24 => 64496
          Announcement: 10.0.2.0/23 => 64496

Example output of the "suggest" option:

.. code-block:: text

  $ krillc roas bgp suggest --ca newca
  Remove the following ROAs which only disallow announcements (did you use the wrong ASN?), if this is intended you may want to use AS0 instead:
    192.168.0.0/16-16 => 64496

  Keep the following authorizations:
    192.168.0.0/24-24 => 64496

  Authorize these announcements which are currently not covered:
    10.0.0.0/21 => 64497
    10.0.0.0/22 => 64496
    10.0.0.0/22 => 64497
    10.0.0.0/24 => 64496
    10.0.2.0/23 => 64496

  Authorize these announcements which are currently invalid because they are not allowed for these ASNs:
    192.168.0.0/24 => 64497
    192.168.1.0/24 => 64497

....


.. _cmd_krillc_bgpsec:

krillc bgpsec
-------------

Manage BGPSec Router Certificates for your CA.

Krill lets users create :RFC:`8209` BGPSec Router Certificates. These
certificates are used in BGPSec to authorise a router key for an ASN
in the RPKI.

At the moment BGPSec deployment is virtually non-existent, so you are
unlikely to need this. However, this functionality is provided in the
hope that it will help the community gain operational experience that
may help BGPSec deployment.

Currently BGPSec Router Certificates can only be managed through the
API. If there is popular demand we will add this to the UI in future.

.. parsed-literal::

   USAGE:
       krillc bgpsec [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`list<cmd_krillc_bgpsec_list>`      Show current BGPSec configurations
       :ref:`add<cmd_krillc_bgpsec_add>`      Add BGPSec configurations
       :ref:`remove<cmd_krillc_bgpsec_remove>`      Remove a BGPSec definition


.. _cmd_krillc_bgpsec_list:

krillc bgpsec list
------------------

Show the current BGPSec configurations.

Example CLI:

.. code-block:: bash

  $ krillc bgpsec list
  ASN, key identifier, CSR base64
  AS211321, 17316903F0671229E8808BA8E8AB0105FA915A07, MIH.....

Example JSON response:

.. code-block:: json
  [
    {
      "asn": 65000,
      "key_identifier": "17316903F0671229E8808BA8E8AB0105FA915A07",
      "csr": "MIH7...."
    }
  ]

.. _cmd_krillc_bgpsec_add:

krillc bgpsec add
-----------------

Add a new BGPSec configurations. I.e. choose an ASN you hold and a
Certificate Sign Request (CSR) you got from your router so that Krill
can create a BGPSec Router Certificate for it.

Example CLI:

.. code-block:: bash

  $ krillc bgpsec add --asn AS65000 --csr ./router-csr.der

This will submit the following JSON to the API:

.. code-block:: text

  $ krillc bgpsec add --asn AS65000 --csr ./router-csr.der --api
  POST:
    https://localhost:3000/api/v1/cas/local-testbed-child/bgpsec
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "add": [
      {
        "asn": 65000,
        "csr": "MIH7MIGiAgEAMBoxGDAWBgNVBAMMD1JPVVRFUi0wMDAwM0NDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE9dBTAcT+j96+mhvyAqX7JLae1+spSSGPCsnus5EITTrdMvnEc2J4B/DBs2N3Fzb2euM+AqWdtoH+LXsmxqvKOgJjAkBgkqhkiG9w0BCQ4xFzAVMBMGA1UdJQQMMAoGCCsGAQUFBwMeMAoGCCqGSM49BAMCA0gAMEUCIQCKJSWZeF7XHuHkFeAN7zOzhEgM+6WyaklaIo3J3lRPmgIgD9kPSO0AjVf1cEUnQrgC5D/5SMaUJ2hp3r8joKFq3hA="
      }
    ],
    "remove": []
}


.. _cmd_krillc_bgpsec_remove:

krillc bgpsec remove
--------------------

Note that Krill may actually create multiple BGPSec Router Certificates
based on the CSR *if* you hold the ASN multiple times. E.g. under
mutliple parents. In practice this is unlikely to happen, but this is
conceptually important when it comes to removal. You can remove any and
all BGPSec Router Certificate by asking Krill to remove the configuration
for a given ASN and router key identifier (as shown in the list command).

Example CLI:

.. code-block:: text

  $ krillc bgpsec remove --asn AS65000 --key 17316903F0671229E8808BA8E8AB0105FA915A07

This submits the following JSON to the API:

.. code-block:: text

  $ krillc bgpsec remove --asn AS65000 --key 17316903F0671229E8808BA8E8AB0105FA915A07 --api
  POST:
    https://localhost:3000/api/v1/cas/local-testbed-child/bgpsec
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "add": [],
    "remove": [
      "ROUTER-00033979-17316903F0671229E8808BA8E8AB0105FA915A07"
    ]
  }

Careful observers may have noticed that the API supports mutliple additions
and removals in a single update. However, such bulk changes are not yet
supported in the CLI.


.. _cmd_krillc_bulk:

krillc bulk
-----------

Manually trigger refresh/republish/resync for all CAs.

Normally there is no need to use these functions. Krill has background processes that
these functions run whenever they are needed. However, they may be useful in cases where
the connection between your CA(s) and their remote parents or repository may be broken
for example, and you want to debug the issue.

There are three "bulk" subcommands available:

.. parsed-literal::

   USAGE:
       krillc bulk [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`publish<cmd_krillc_bulk_publish>`    Force that all CAs create new objects if needed (in which case they will also sync)
       :ref:`refresh<cmd_krillc_bulk_refresh>`    Force that all CAs ask their parents for updated certificates
       :ref:`sync<cmd_krillc_bulk_sync>`       Force that all CAs sync with their repo server

.. _cmd_krillc_bulk_publish:

krillc bulk publish
-------------------

Force that all CAs create new objects if needed (in which case they will also sync).
Note that this function is executed when Krill starts up and then again every 10
minutes.

Example CLI:

.. code-block:: text

  $ krillc bulk publish


Example API call:

.. code-block:: text

  $ krillc bulk publish --api
  POST:
    https://localhost:3000/api/v1/bulk/cas/publish
  Headers:
    Authorization: Bearer secret
  Body:
  <empty>

.. _cmd_krillc_bulk_refresh:

krillc bulk refresh
-------------------

Force that all CAs ask their parents for updated certificates. Note that this function
is executed when Krill starts up and then again every 10 minutes.

Example CLI:

.. code-block:: text

  $ krillc bulk refresh


Example API call:

.. code-block:: text

  $ krillc bulk refresh --api
  POST:
    https://localhost:3000/api/v1/bulk/cas/sync/parent
  Headers:
    Authorization: Bearer secret
  Body:
  <empty>

.. _cmd_krillc_bulk_sync:

krillc bulk sync
----------------

Force that all CAs sync with their publication server.

This function is executed when Krill starts up. When Krill is running then
CAs will synchronise with their publication server whenever there is new
content to publish. And if such a synchronisation fails, then Krill will
schedule another attempt every 5 minutes until synchronisation succeeds.

However, if you believe that there is an issue with the publication server,
or you wish to debug connection issues, then you can trigger this function
manually:

.. code-block:: text

  $ krillc bulk sync --api
  POST:
    https://localhost:3000/api/v1/bulk/cas/sync/repo
  Headers:
    Authorization: Bearer secret
  Body:
  <empty>

....


.. _cmd_krillc_children:

krillc children
---------------

Manage children for a CA in Krill.

Most operators will not need this, but just like you can operate your Krill CA under
an RIR or NIR, you can delegate your resources to so-called child CAs. This may be
useful in case you need to authorise different units of your organisation or customers
to manage some of your prefixes.

.. parsed-literal::

   USAGE:
       krillc children [SUBCOMMAND]

   SUBCOMMANDS:
       :ref:`add<cmd_krillc_children_add>`            Add a child to a CA
       :ref:`info<cmd_krillc_children_info>`           Show info for a child (id and resources)
       :ref:`update<cmd_krillc_children_update>`         Update an existing child of a CA
       :ref:`response<cmd_krillc_children_response>`       Show the RFC8183 Parent Response XML
       :ref:`connections<cmd_krillc_children_connections>`    Show connections stats for children of a CA
       :ref:`suspend<cmd_krillc_children_suspend>`        Suspend a child CA: hide certificate(s) issued to child
       :ref:`unsuspend<cmd_krillc_children_unsuspend>`      Suspend a child CA: republish certificate(s) issued to child
       :ref:`remove<cmd_krillc_children_remove>`         Remove an existing child from a CA

.. _cmd_krillc_children_add:

krillc children add
-------------------

Add a child to a CA. To add a child, you will need to:
  1. Choose a unique local name (handle) that the parent will use for the child
  2. Choose initial resources (asn, ipv4, ipv6)
  3. Present the child's :rfc:`8183` request

The default response is the :rfc:`8183` parent response XML file. Or, if you set
``--format json`` you will get the plain API response.

If you need the response again, you can use the
:ref:`krillc children response<cmd_krillc_children_response>` command.

When you use the CLI you can provide a path to the Child Request XML and the CLI
will parse this, and convert it to the JSON that Krill expects when adding a child.
We chose to use a different format here because we needed to include other information
not contained in the XML. I.e. just submitting the plain XML would not work here.

Example CLI:

.. code-block:: text

  $ krillc children add --ca testbed --child newca --ipv4 "10.0.0.0/8" --ipv6 "2001:db8::/32" --asn "AS65000" --request ./data/new-ca-child-request.xml
  <parent_response xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" service_uri="https://localhost:3000/rfc6492/testbed" child_handle="newca" parent_handle="testbed">
    <parent_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=</parent_bpki_ta>
  </parent_response>

Example API call:

.. code-block:: text

  $ krillc children add --ca testbed --child newca --ipv4 "10.0.0.0/8" --ipv6 "2001:db8::/32" --asn "AS65000" --request ./data/new-ca-child-request.xml --api
  POST:
    https://localhost:3000/api/v1/cas/testbed/children
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "handle": "newca",
    "resources": {
      "asn": "AS65000",
      "ipv4": "10.0.0.0/8",
      "ipv6": "2001:db8::/32"
    },
    "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJENzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEuL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8OlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEoBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtONdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9iKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDVbXTPM8YLRgc="
  }

.. _cmd_krillc_children_info:

krillc children info
--------------------

Show info for a child: state, id certificate info and resources. The
"state" can either be "active", or "suspended".

Example CLI:

.. code-block:: text

  $ krillc children info --ca testbed --child newca
  -----BEGIN CERTIFICATE-----
  MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJE
  NzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0
  MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2
  QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEP
  ADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8
  ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEu
  L+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8O
  lB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEo
  BjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3
  Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUw
  AwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU
  7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtO
  NdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh
  3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9i
  KantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ
  7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6
  t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDV
  bXTPM8YLRgc=
  -----END CERTIFICATE-----

  SHA256 hash of PEM encoded certificate: 992ac17d85fef11d8be4aa37806586ce68b61fe9cf65c0965928dbce0c398a99
  resources: asn: , v4: 10.0.0.0/8, 192.168.0.0/16, v6:
  state: active

Example JSON response:

.. code-block:: json

  {
    "state": "active",
    "id_cert": {
      "pem": "-----BEGIN CERTIFICATE-----\nMIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJE\nNzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0\nMzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2\nQTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8\nugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEu\nL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8O\nlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEo\nBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3\nPi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUw\nAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU\n7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtO\nNdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh\n3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9i\nKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ\n7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6\nt/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDV\nbXTPM8YLRgc=\n-----END CERTIFICATE-----\n",
      "hash": "992ac17d85fef11d8be4aa37806586ce68b61fe9cf65c0965928dbce0c398a99"
    },
    "entitled_resources": {
      "asn": "",
      "ipv4": "10.0.0.0/8, 192.168.0.0/16",
      "ipv6": ""
    }
  }

Example API call:

.. code-block:: text

  $ krillc children info --ca testbed --child newca  --api
  GET:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    Authorization: Bearer secret

.. _cmd_krillc_children_update:

krillc children update
----------------------

Update the resource entitlements of an existing child of a CA, or update the
identity certificate that they will use when sending :rfc:`6492` requests.

.. IMPORTANT:: When updating resources you need to specify the full new set
    of resource entitlements for the child. This is not a delta. Also if you specify
    one resource type only like ``--ipv4``, then ``--ipv6`` and ``--asn`` will be
    assumed to be intentionally empty:

.. code-block:: text

  $ krillc children update --ca testbed --child newca --ipv4 "10.0.0.0/8"  --api
  POST:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "id_cert": null,
    "resources": {
      "asn": "",
      "ipv4": "10.0.0.0/8",
      "ipv6": ""
    }
  }


When updating an ID certificate the CLI expects it to be DER encoded. It will
submit it in base64 encoded form to the API and leave the "resources" as `null`
then. The `null` value means that this is not updated:

.. code-block:: text

  $ krillc children update --ca testbed --child newca --idcert ./data/new-ca.cer --api
  POST:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJENzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEuL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8OlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEoBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtONdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9iKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDVbXTPM8YLRgc=",
    "resources": null
  }


.. _cmd_krillc_children_response:

krillc children response
------------------------

Get the :rfc:`8183` Parent Response for a child. The child will need this to add your
CA as their parent.

Example CLI:

.. code-block:: text

  $ krillc children response --ca testbed --child newca
  <parent_response xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" service_uri="https://localhost:3000/rfc6492/testbed" child_handle="newca" parent_handle="testbed">
    <parent_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=</parent_bpki_ta>
  </parent_response>

Example API call:

.. code-block:: text

  $ krillc children response --ca testbed --child newca --api
  GET:
    https://localhost:3000/api/v1/cas/testbed/children/newca/contact
  Headers:
    Authorization: Bearer secret

Note that the API always returns the :rfc:`8183` Parent Response in JSON format, but
the CLI converts it. Other API endpoints support getting such files in either JSON or
RFC standard XML format. If there is desire to support this here as well, then we will
add this in a future release.

.. _cmd_krillc_children_connections:

krillc children connections
---------------------------

Show the connections stats for children of a CA. This can be useful for monitoring
for potentially deactivated child CAs. Furthermore the user-agent for the last known
connection from each child is shown. This can help to monitor for children running
potentially outdated RPKI CA implementations (old krill versions or other implementations).

Example CLI:

.. code-block:: text

  $ krillc children connections --ca testbed
  handle,user_agent,last_exchange,result,state
  CA2,krill/0.9.2-rc3,2021-09-24T10:00:00+00:00,success,active
  ca,krill/0.9.2-rc3,2021-09-24T10:00:00+00:00,success,active
  CA1,krill/0.9.2-rc1,2021-09-13T14:30:00+00:00,success,active
  dummy_ca,n/a,never,n/a,active


Example API call:

.. code-block:: text

  $ krillc children connections --ca testbed --api
  GET:
    https://localhost:3000/api/v1/cas/testbed/stats/children/connections
  Headers:
    Authorization: Bearer secret

Example JSON response:

.. code-block:: json

  {
    "children": [
      {
        "handle": "newca",
        "last_exchange": {
          "timestamp": 1632477600,
          "result": "Success",
          "user_agent": "krill/0.9.2"
        },
        "state": "active"
      },
      {
        "handle": "oldca",
        "last_exchange": {
          "timestamp": 1632477600,
          "result": "Success",
          "user_agent": "krill"
        },
        "state": "active"
      },
      {
        "handle": "brandnewca",
        "last_exchange": null,
        "state": "active"
      },
    ]
  }

Note that krill 0.9.1 and below use the user-agent "krill", while krill
0.9.2 and above include the version, e.g.: "krill/0.9.2". Other RPKI CA
implementation may or may not include user-agents strings in their requests.

Furthermore note that the "last_exchange" may be "null" in case a CA was
just added by the parent, but the child CA did not import the parent XML
response yet - or was otherwise unable to connect.

The "last_exchange" field will also be "null" after upgrading to krill 0.9.2.
This information was not kept prior to krill 0.9.2 so, after upgrading, this
will only be set when your existing child CAs connect for the first time.


.. _cmd_krillc_children_suspend:

krillc children suspend
-----------------------

If you believe that a child CA has been deactivated then you may wish to "suspend"
it, rather than remove it altogether. If you suspend a child CA, then any
certificate(s) issued to it by your CA will be withdrawn, and they will no longer
be processed by RPKI validation software. This is particularly useful if the
manifest and CRL of the child CA have expired, and presumably their ROAs are no
longer maintained either.

If and when a "suspended" child CA connects to your CA again, it will automatically
be "un-suspended". Meaning that any certificate(s) previously issued  to this
child will be published again.

The main goal of this is to facilitate an easier recovery path in cases where
a child CA suffers a long outage. By "suspending" them until the child CA is
reactivated you suppress RPKI validation errors for their expired publication
point, while ensuring that the delegation to this CA will be re-enabled as soon
as it is successfully started.

Example CLI/API:

.. code-block:: text

  $ krillc children suspend --ca testbed --child newca --api

  POST:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "suspend": true
  }

.. Important:: It is not always trivial to figure out if a child CA has been
               deactivated. The expiry of the child CA's manifest and CRL is
               a strong indication of this, but this information is not available
               to the krill CA parent. What it *does* have is the knowledge of
               when a child CA connected for the last time.

               If the child CA did not connect for a long time, then the parent
               may be inclined to think that they have been deactived. This
               is true for child CAs running Krill 0.9.2 or above, because here
               the maximum configurable 'refresh' rate is one hour. So, if you
               have not seen any connection attempts for such child CAs for, say
               8 hours, then you can safely suspend them.

               However, earlier krill versions, while using a default of 10 minutes,
               would allow overriding this value without any upper bound. Other
               RPKI CA implementations may also use longer cycles.

               In short: be careful before deciding that a child CA is truly
               deactived.


.. _cmd_krillc_children_unsuspend:

krillc children unsuspend
-------------------------

If needed you can manually "un-suspend" a "suspended" child CA. Generally speaking
there is no need do this, because a child will be un-suspended automatically whenever
it re-connects with your CA.

Example CLI/API:

.. code-block:: text

  $ krillc children unsuspend --ca testbed --child newca --api
  POST:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "suspend": false
  }


.. _cmd_krillc_children_remove:

krillc children remove
----------------------

Remove an existing child from a CA. This removes and revokes any certificate(s)
issued to this child CA. Furthermore this child CA, if still active or re-activated,
will no longer be allowed to connect to your CA. They will have to remove you as
a parent first and then re-do the XML exchange with you in order to be re-added
as a child.

if you think that the child CA may be temporarily disabled, then you may wish to
"suspend" them instead.

.. Important:: If the child CA was created in krill using the `krillc children add --ca testbed --child newca` 
               command, this command does not remove the child CA.  You must still execute 
               `krillc delete --ca newca` in order to compelety remove the child CA.

Example CLI / API call:

.. code-block:: text

  $ krillc children remove --ca testbed --child newca --api
  DELETE:
    https://localhost:3000/api/v1/cas/testbed/children/newca
  Headers:
    Authorization: Bearer secret

....


.. _cmd_krillc_keyroll:

krillc keyroll
--------------

Perform a key rollover for a CA.

Krill supports :rfc:`6489` Key Rollovers. The process is manual for now. I.e. it's up to the
operator to initiate a key rollover - there is no automation based on key age for example.
We expect that this is what operators would want. More importantly though, this also means
that operators should execute *both* steps in the process to start *and* finish the key
rollover:

.. parsed-literal::

  :ref:`krillc keyroll init<cmd_krillc_keyroll_init>`        Initialise roll for all keys held by this CA.
  :ref:`krillc keyroll activate<cmd_krillc_keyroll_activate>`    Finish roll for all keys held by this CA.


.. _cmd_krillc_keyroll_init:

krillc keyroll init
-------------------

Initialise roll for all keys held by this CA.

Example CLI/API call:

.. code-block:: text

  $ krillc keyroll init --ca newca --api
  POST:
    https://localhost:3000/api/v1/cas/newca/keys/roll_init
  Headers:
    Authorization: Bearer secret
  Body:
  <empty>

.. _cmd_krillc_keyroll_activate:

krillc keyroll activate
^^^^^^^^^^^^^^^^^^^^^^^

Finish roll for all keys held by this CA.

Note that :rfc:`6489` says that you should wait 24 hours before doing this step. So, please
observe this period for planned key rollovers. For emergency rollovers where the old key is
compromised, or if this rollover is part of an emergency migration to a new publication server,
do this step as soon as possible.

Example CLI/API:

.. code-block:: text

  $ krillc keyroll activate --ca newca --api
  POST:
    https://localhost:3000/api/v1/cas/newca/keys/roll_activate
  Headers:
    Authorization: Bearer secret
  Body:
  <empty>
