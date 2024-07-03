.. _doc_krill_multi_user_access_control:

Permissions, Roles & Attributes
===============================

.. versionadded:: v0.9.0

This page summarizes the different ways that Krill supports for restricting access
to *named users* that login to Krill. For backward compatibility, users that
authenticate with the secret token are given unrestricted access to Krill.

Permissions
-----------

Internally within Krill each REST API endpoint requires the logged in user to have
a specific Krill permission in order to execute the request.


User Attributes
---------------

User attributes are assigned by the identity provider, either in the
``krill.conf`` file for locally defined users, or in the management interface of
the OpenID Connect provider that manages your users.

.. Warning:: By default, user attributes and their values are shown in the Krill
             web user interface and the web user interface stores these 
             attributes in browser local storage. To prevent sensitive attributes
             being revealed in the browser you can mark them as private. One
             possible use for this is to restrict access using the ``exc_cas``
             attribute but not reveal the name of the restricted CA by doing
             so. See ``auth_private_attributes`` in ``krill.conf`` file for more
             information.

Role Based Access Control
-------------------------

At the highest level Krill can restrict access based on user roles. A role is a
named collection of internal Krill permissions.

By default Krill supports three roles which can be assigned to users. A user can
only have one role at a time. A role is assigned to a user via the ``role``
user attribute (see below for more on attributes).

The default roles are:

- ``admin``    : Grants users unrestricted access.
- ``readwrite``: Grants users the right to list, view and modify *existing*
  CAs.
- ``readonly`` : Grants users the right to list and view CAs only.

Attribute Based Access Control
------------------------------

Krill supports ``inc_cas`` and ``exc_cas`` user attributes which can be used
to permit or deny access to one or more Certificate Authorities in Krill. User
attributes can also be used to make decisions in :ref:`custom authorization policies <doc_krill_multi_user_custom_policies>`.

