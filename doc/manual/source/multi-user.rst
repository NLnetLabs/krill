.. _doc_krill_multi_user:

Login with Named Users
======================

.. versionadded:: v0.9.0

.. figure:: img/multi-user-banner.png
    :align: center
    :width: 100%
    :alt: Multi-user user identity head & shoulders popup

    Checking the currently logged in user and user attributes

By default Krill requires users to authenticate using the configured secret token,
and actions in the event history are attributed to a client using the secret token or
to Krill itself.

Krill also supports authenticating users **of the web user interface** with their
own username and credentials. Actions taken by such logged in users are attributed
in the event history to their username.

To login users by username Krill must first be configured either with locally
defined user details and credentials, or with the details necessary to interact with
a separate `OpenID Connect <https://openid.net/connect/>`_ compliant identity provider system.

Further reading:

.. toctree::
  :maxdepth: 1
  :name: toc-multi-user

  multi-user/authorization
  multi-user/config-file-provider
  multi-user/openid-connect-provider
  multi-user/customization

.. history
.. authors
.. license

.. note:: Clients using the Krill REST API directly or via ``krillc`` cannot
          authenticate using named users, they can only authenticate using the
          secret token. If you need this capability `please let us know <https://github.com/NLnetLabs/krill/issues/new/choose>`_.

