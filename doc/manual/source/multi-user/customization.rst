.. _doc_krill_multi_user_custom_policies:

Custom Authorization Policies
=============================

.. versionadded:: v0.9.0

.. contents::
  :local:
  :depth: 2

Introduction
------------

.. note:: This is an advanced topic, you don't need this feature to
          get started with Named Users. If you are considering
          implementing a custom authorization policy `we'd love to hear from you <mailto:rpki-team@nlnetlabs.nl>`_!

Custom authorization policies are a way of extending Krill by supplying
one or more files containing rules that will be added to those used by
Krill when deciding if a given action by a user should be permitted or
denied.

Examples
--------

Some examples showing the power of this can be seen in `doc/policies <https://github.com/NLnetLabs/krill/tree/main/doc/policies>`_
directory in the Krill source code repository.

`role-per-ca-demo`
""""""""""""""""""

By default Krill lets you assign a role to a user that will be enforced
for all of the actions that they take irrespective of the CA being
worked with. The `role-per-ca-demo` example extends Krill so that a
user can be given different roles for different CAs.

The demo also shows how to use new user attributes to influence
authorization decisions, in this case by looking for a user attribute
by the same name as the CA being worked with, and if found it uses the
attribute value as the role that the user should have when working with
that CA.

Finally, the demo demonstrates how to add new roles to Krill by adding
two new roles that are more limited in power than the default roles in
Krill:

  - A `readonly`-like role that also has the right to update ROAs.
  - A role that only permits a user to login and list CAs.

`team-based-access-demo`
""""""""""""""""""""""""

The `team-based-access-demo` shows how one can define teams in the
policy:

  - Users can optionally belong to a team.
  - Users can have a different role in the team than outside of it.
  - Being a member of a team grants access to the CAs that the team
    works with.

The example works by defining the team names in the policy file. Each
team is given a name and a list of CAs it works with. Krill is then
extended to understand two new user attributes:

  - `team` - which team a user belongs to
  - `teamrole` - which role the user has in the team

Using custom policies
---------------------

To use a custom policies there must be an ``auth_policies`` setting
in ``krill.conf`` specifying the path to one ore more custom policy
files to load on startup.

.. code-block:: none

   auth_type = "..."
   auth_policies = [ "doc/policies/role-per-ca-demo.polar" ]

.. warning:: Krill will fail to start if a custom authorization
             policy file is syntactically invalid or if one of the
             self-checks in the policy fails.

.. warning:: Policy files should only be readable by Krill and
             trusted operating system user accounts.
             
             Krill performs some basic sanity checks on startup to
             verify that its authorization policies are working as
             expected, but a malicious actor could make more subtle
             changes to the policy logic which may go undetected,
             like granting their own user elevated rights in Krill.

             If a malicious user is able to write to the policy
             file they may however already be able to do much more
             significant damage than editing a policy file!

.. note:: Policy files are not reloaded if changed on disk while
          Krill is running.

          For policies that only contain rules this is not a
          problem as they would not be expected to change
          very often, if ever.

          However, for policies that define configuration in the
          policy file, such as the `team-based-access-demo`,
          changes to the policy configuration will not take effect
          until Krill is restarted.

Writing custom policies
-----------------------

Policies are written in the Polar language. The following articles
from the Oso website can help you get started with Polar:

  - `The Polar Language <https://docs.osohq.com/rust/learn/polar-foundations.html>`_
  - `Write Oso Policies (30 min) <https://docs.osohq.com/rust/getting-started/policies.html>`_
  - `Polar Syntax Reference <https://docs.osohq.com/rust/reference/polar/polar-syntax.html>`_
  - `Rust Types in Polar <https://docs.osohq.com/rust/reference/polar/classes.html>`_

The core policies and permissions that Krill uses are embedded into
Krill itself and cannot be changed. It is however possible to add
new roles and to add new logic based around the value of custom user
attributes.

Defining new roles
""""""""""""""""""

Krill roles are defined by ``role_allow("rolename", action: Permission)``
Polar rules. The rule is tested if the role of the current user is
"rolename". The current role definitions test if the requested
action is in a set defined to be valid for that role.

.. tip:: You can see the built-in `role <https://github.com/NLnetLabs/krill/blob/master/defaults/roles.polar>`_
         and `permission <https://github.com/NLnetLabs/krill/blob/master/src/daemon/auth/common/permissions.rs>`_
         definitions in the Krill GitHub repository.

To define a new role that grants read only rights plus the right to
update ROAs one could write the following Polar rule:

.. code-block:: none

   role_allow("roawrite", action: Permission)
       role_allow("readonly", action) or
       action = ROUTES_UPDATE;

This example is actually taken from the `role-per-ca-demo.polar` policy.

Defining new rules
""""""""""""""""""

Let's write a rule that completely prevents the update of ROAs.

When Oso does a permission check the search for a matching rule
starts by matching rules of the form ``allow(actor, action, resource)``.

.. tip:: "resource" in this context is a Polar term and should not be
         confused with the RPKI term "resource".

The Krill policy delegates from its `allow` rules immediately to a
special ``disallow(actor, action, resource)`` rule. The only definition
of the ``disallow()`` rule in Krill by default says ``if false``, i.e.
nothing is disallowed.

While technically you can prevent an action by ``cut`` -ing out of an
``allow()`` rule that is more specific than any other ``allow()`` rules,
it's not always possible to ensure that your rule is the most specific
match. That's where ``disallow()`` comes in handy.

Let's use ``disallow()`` to implement our rule.

Create a file called ``no_roa_updates.polar`` containing the following
content:

.. code-block:: none

   # define our new rule: disallow all ROA updates
   disallow(_, ROUTES_UPDATE, _);

   # we could also write this more explicitly like so:
   # disallow(_, ROUTES_UPDATE, _) if true;

   # add a test to check that our new rule works by
   # showing that an admin user can no longer update
   # ROAs!
   ?= not allow(new Actor("test", { role: "admin" }), ROUTES_UPDATE, new Handle("some_ca"));

Let's break this down:

  - The ``_`` character is Polar syntax for "match any".
  - Lines starting with ``#`` are comments.
  - Lines starting with ``?=`` defines self-test inline queries that
    will be executed when Krill starts. If a self-test inline query
    fails Krill will exit with an error.

The rule that we have created says that for any actor trying to update
a ROA on any "resource" (i.e. Certificate Authority), succeed (i.e.
disallow the attempt).

If we now set ``auth_policies = [ "path/to/no_roa_updates.polar" ]``
in our ``krill.conf`` file and restart Krill it will no longer be
possible for anyone to update ROAs.

This is obviously not the most useful policy, but it demonstrates
the idea :-)

Diagnosing issues
"""""""""""""""""

If a rule doesn't work as expected a good way to investigate is to
add more self-test inline queries.

If that fails you can set ``log_level = "debug"`` and set O/S
environment variable ``POLAR_LOG=1`` when runnng Krill. This will
cause a huge amount of internal Polar diagnostic logging which
will show exactly which rules Polar evaluated in which order with
which parameters and what the results were.

