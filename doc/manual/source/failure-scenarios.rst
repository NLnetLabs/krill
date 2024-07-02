.. _doc_krill_failure_scenarios:

Failure and Recovery Scenarios
===============================


CA Temporarily Unavailable
--------------------------

+------------------------------------------------------------------------------+
| Issue                                                                        |
+==============================================================================+
| The Krill instance for your CA is temporarily unavailable                    |
+------------------------------------------------------------------------------+

+------------------------------------------------------------------------------+
| Consequences                                                                 |
+==============================================================================+
| You cannot change ROAs                                                       |
+------------------------------------------------------------------------------+
| You cannot change delegations to child CAs                                   |
+------------------------------------------------------------------------------+
| Krill will not update its repository                                         |
+------------------------------------------------------------------------------+

If the outage is short, e.g. because you are performing a
planned upgrade, then this will have little or no impact.
The RPKI objects which were published by your CA will remain
unchanged, so your ROAs will still be found and considered
valid by RPKI validators.

Note that if you are using automation to keep your ROAs in
sync with your routing configuration, you should take care
to ensure that your set up can deal with a short outage of
your CA and tries to re-apply any possible ROA changes in
case your CA was unavailable.

If the outage takses longer than 8 hours (using default settings),
then your :ref:`CA publication point will become expired<failure_repo_expired>`
and the impact will be bigger.


Parent Temporarily Unavailable
------------------------------

+------------------------------------------------------------------------------+
| Issue                                                                        |
+==============================================================================+
| The parent of your CA is temporarily unavailable                             |
+------------------------------------------------------------------------------+

+------------------------------------------------------------------------------+
| Consequences                                                                 |
+==============================================================================+
| You will not receive changes to your resource certificate                    |
+------------------------------------------------------------------------------+
| You cannot perform a key roll                                                |
+------------------------------------------------------------------------------+

As long as the parent repository is not expired (:ref:`see below<failure_parent_repo_expired>`) this has minimal impact
on your CA. Krill CAs will check for updated resource and validity time entitlements
every 10 minutes, and they will just keep trying.

The status is shown in the UI, but you can also use the following CLI command:

.. code-block:: bash

  krillc parents statuses

If you parent CA is unavailable due to an outage, or an ongoing upgrade, then there
is not much that you can do. You may want to talk to them, but a responsible parent
should monitor their own operations, so they are expected to become available again
without the need for you to take action. But note that you should verify whether the
issue on your side. E.g. there may be a network issue, or firewall rule preventing
your CA for contacting the parent CA.


.. _failure_repo_expired:

Publication Point Expired
-------------------------

+------------------------------------------------------------------------------+
| Issue                                                                        |
+==============================================================================+
| The manifest or CRL of your CA expired                                       |
+------------------------------------------------------------------------------+

+------------------------------------------------------------------------------+
| Consequences                                                                 |
+==============================================================================+
| Your published objects are no longer valid                                   |
+------------------------------------------------------------------------------+
| Your routes become "not found" in most cases                                 |
+------------------------------------------------------------------------------+

When your manifest or CRL become expired your RPKI objects
will become invalid. This problem can occur if your CA is
down, or if your CA cannot publish updated objects at its
publication server, for a prolonged period of time.

Krill uses a default validity time of 24 hours for manifests
and CRLs, and replaces them 8 hours before they would expire.
This means that from the moment of the outage you have 8-24
hours to prevent that your objects will be invalidated.

It is possible to change these defaults if you want to have
more time to deal with potential issues. However, we recommend
that you avoid using long validity times because in theory
they could make you vulnerable to replay attacks where a malicious
actor feeds old objects to RPKI validators. This attack is not
trivial, but it's not impossible either.

A reasonable compromise could be to use a validity time of 36 hours,
and have Krill reissue manifests and CRLs 24 hours before they would
expire. You can achieve this by adding the following directives
to your configuration file:

.. code-block:: text

  timing_publish_next_hours = 36
  timing_publish_hours_before_next = 24

When your objects, most importantly ROAs, become invalid your
routes will usually become "not found", rather than "invalid".
Meaning that your routes will no longer benefit from Route
Origin Validation, but they will still be accepted.

For a route to become RPKI "invalid" it would need to be covered
by one or more valid ROA objects which include this prefix, none
of which allow the possibly more specific prefix and ASN.

In the set up we see today this is unlikely to happen as most
Krill CAs will operate directly under a parent RIR or NIR, and
will not delegate prefixes to children. RIRs and NIRs do not
issue ROAs for delegated prefixes, so in case your publication
point would be rejected there would be no remaining valid ROA
objects for your announcement. The result is that they then
get an RPKI validity state "not found".

However, in complicated setups your routes can become invalid. For
example if your organisation operates a main CA under an RIR, and
it publishes ROAs, while delegating some resources covered by those
ROAs to you (e.g. a business unit or customer), and your publication
point is expired while your parent's publication point is still current..
then your routes can become "invalid".

If it can be helped it would therefore be advisable that your parent
does not delegate resources for which they also manage ROAs.

.. _failure_parent_repo_expired:

Parent Publication Point Expired
--------------------------------

+------------------------------------------------------------------------------+
| Issue                                                                        |
+==============================================================================+
| The manifest or CRL of your parent CA expired                                |
+------------------------------------------------------------------------------+

+------------------------------------------------------------------------------+
| Consequences                                                                 |
+==============================================================================+
| Your published objects are no longer valid                                   |
+------------------------------------------------------------------------------+
| Your routes become "not found" in most cases                                 |
+------------------------------------------------------------------------------+

If your parent CA's publication point is expired, then its objects will become
invalid. This includes the certificate for the delegation done to you, and therefore
your objects will also no longer be considered valid by RPKI validators.

As described :ref:`above<failure_repo_expired>` this will typically mean that
your routes end up with the RPKI validity state "not found". The chances of them
becoming "invalid" are actually somewhat lower still becuase any possible ROAs
issued by your parent or siblings (other children under the same parent) covering
your resources would also be invalid.
