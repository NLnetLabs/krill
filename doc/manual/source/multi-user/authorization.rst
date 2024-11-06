.. _doc_krill_multi_user_access_control:

Roles, Permissions and Resources
================================

.. versionadded:: v0.9.0

This page summarizes how Krill supports restricting access for *named users*
that login to Krill. For backward compatibility, users that authenticate with
the secret token are given unrestricted access to Krill.

Roles
-----

Rather than restricting access to individual users, Krill adds an
intermediary concept of roles. Each user is assigned a role and these roles
in turn define access restrictions.

Roles can be defined in the config file through the ``[auth_roles]`` section.
Each role has a name, a set of permissions, and optionally a list of CAs
access is restricted to.

By default, i.e., if you do not provide your own ``[auth_roles]`` in the
config file, Krill uses three roles:

.. Glossary::

    ``admin``
        Grants unrestricted access to all CAs.

    ``readwrite``
        Grants the right to list, view and modify all *existing* CAs.

    ``readonly``
        Grants the right to list and view all CAs.

If you do provide your own roles, these will *not* be present.


Permissions
-----------

Internally within Krill each REST API endpoint requires the logged in user to
have a specific Krill permission in order to execute the request. When
defining your own roles, you can combine these permissions into a specific
set by listing those you wish to grant to the role.

Currently, the following permissions are defined:

.. Glossary::

    ``login``
        required for logging into the Krill UI,

    ``pub-admin``
        required for access to the built-in publication server,

    ``pub-list``
        required for listing the currently configured publishers of the
        publication server,

    ``pub-read``
        required to show details of configured publishers of the
        publication server, including the publication response to be returned
        to a publisher,

    ``pub-create``
        required to add new publishers to the publication server,

    ``pub-delete``
        required to removed publishers from the publication server,

    ``ca-list``
        required to list existing CAs,

    ``ca-read``
        required to show details of existing CAs,

    ``ca-create``
        required to create new CAs,

    ``ca-update``
        required to update configuration of existing CAs as well as adding
        and removing child CAs,

    ``ca-admin``
        required for administrative tasks related to all CAs as well as
        importing CAs, also required for access to the trust anchor module,

    ``ca-delete``
        required to remove CAs,

    ``routes-read``
        required to show the ROAs configured for a CA,

    ``routes-update``
        required to update the ROAs configured for a CA,

    ``routes-analysis``
        required to perform BGP route analysis for a CA,

    ``aspas-read``
        required to show the ASPA records configured for a CA,

    ``aspas-update``
        required to update the ASPA records configured for a CA,

    ``bgpsec-read``
        required to show the BGPsec router keys configured for a CA,

    ``bgpsec-update``
        required to update the BGPsec router keys configured for a CA.

In addition, there two shortcuts that can be used to specify multiple
permission at ones:

.. Glossary::
    ``any`
        grants all permissions,

    ``read``
        grants the ``ca-read``, ``routes-read``, ``aspas-read``, and
        ``bgpsec-read`` permissions,

    ``update``
        grants the ``ca-update``, ``routes-update``, ``aspas-update``, and
        ``bgpsec-update`` permissions,


Configuring Roles
-----------------

When the default roles are not sufficient, you can create your own set of
roles in the Krill config file. You do so by creating a new block
``[auth_roles]`` which contains a list of all your roles. Each role needs
to have a mapping of one or two fields:

* The mandatory field ``permissions`` provides a list of the permissions
  to be granted by the role, and

* the optional field ``cas`` is a list of the CAs that the role grants
  access to.

If the ``"cas"`` field is not present, access to all CAs is granted.

As an example, here is the definition of the default roles plus a special
role that only allows read access to the ``"example"`` CA.

.. code-block:: toml

    [auth_roles]
    "admin" = { permissions = [ "any" ] }
    "readwrite" = { permissions = [ "pub-list", "pub-read", "pub-create", "pub-delete", "ca-list", "ca-create", "ca-delete", "read", "update" ] }
    "readonly" = { permissions = [ "pub-read", "ca-list", "read" ] }
    "read-example" = { permissions = [ "read" ], cas = [ "example" ] }

