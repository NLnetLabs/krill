.. _doc_krill_manage_children:

Delegate to Child CAs
=====================

Krill supports delegating resources from your CA(s) to so-called child
CAs. This function is primarily used by National Internet Registries (NIRs)
that use Krill for their RPKI service. Most non-registry organisations will
have no need for this function, as they simply have no members or customers
to delegate resources to.

However, this function may still come in useful for example for larger
organisations with many resources and complex organisational structure or
customers who are in charge of using some of their IP or ASN resources.

There is no UI support for managing child CAs, but you can use the CLI
:ref:`krillc children<cmd_krillc_children>` subcommands to achieve this:

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
