.. _doc_krill_ca_keyroll:

Key Rollover
============

Krill supports the :rfc:`6489` RPKI Certification Authority Key Rollover process.
In a nutshell this process allows RPKI CAs to replace their key in such a way that
the content of all 'objects', like ROAs and possibly certificates issued to child CAs,
is preserved in re-issued objects under the new key, without noticeable interruptions
to RPKI validators.

Before we can dive in to key rollovers we need to take a step back and talk a bit
about RPKI CA certificates and keys.

For most users their CA will have only one parent CA and only one key and CA certificate
under that parent. But, krill supports having multiple so-called "Resource Classes" under
a parent. The term Resource Class stems from :rfc:`6492` - essentially you can think of
these as a way to to group a set of resources that can appear on a single certificate.
This construct is needed because RPKI CA certificates can have only one signing parent CA
certificate. So, if your parent received resources on different certificate (presumably from
different sources), then they cannot sign a single certificate to you with all those resources.
They would have to give you a signed certificate under each of their own certificates
with the applicable resources.

Furthermore, Krill also supports the notion of having multiple parent CAs. Conceptually
this is only a small leap from having to deal with potentially multiple Resource Classes
under a single parent. Under the hood it's all just more Resource Classes to Krill - it
will just remember which parent to talk to in relation to each of them. Each resource
class has its own key, or during a key rollover: keys.


Quick Guide to Key Rollovers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to understand the background of key rollovers better, then we urge you
to read the section below this one. Here we will just give you the quick gist of it.

If you want to do a key rollover for your CA, you will need to run two CLI commands.

First you need to initialise a new key to start the process:

.. code-block:: text

   krillc keyroll init


Then, you should wait 24 hours and before activating the new key and retiring the old:

.. code-block:: text

   krillc keyroll activate


Caveats:

 - The ``init`` command will have no effect if your CA is in the middle of a rollover
 - The ``activate`` command will have no effect if your CA does not have a new key

Your ROAs and possible other objects, such as CA certificates delegated to child CAs
if you have those, will be safe during a rollover. They will be re-issued under the
new key when you run the ``activate`` command.


Key Life Cycle Background
^^^^^^^^^^^^^^^^^^^^^^^^^

The key life cycle for a Resource Class has the following possible stages:

 - pending
 - active
 - roll phase 1: pending and active key
 - roll phase 2: new and active key
 - roll phase 3: active and old key

- Pending

The 'pending' state indicates that a parent has told your CA that it is entitled
to resources under a Resource Class hitherto unknown to your CA. When this happens
Krill will create a new local Resource Class associated with this parent with a fresh
key pair and a 'pending' Certificate Sign Request (CSR).

This stage is usually short-lived, because it immediately triggers that the CSR is
sent to the parent. However, it needs to exist in order for Krill to deal with the
possibility that the parent is unreachable or unresponsive to the CSR right after
it was told about this entitlement.

- Active

The 'active' state is the normal stable state for keys under a Resource Class.
It indicates that Krill has a single key under a resource class and it has received
a certificate for it from its parent.

Krill will continue to query the parent for entitlements and in case there is a
change in eligible resources or certificate validity it will create a CSR which is
sent to the parent. The key as such remains in the 'active' state even if there
are pending CSRs.

At this point we should probably also mention that if a Resource Class no longer
appears in a parent's :rfc:`6492` list response, Krill will simply clean up the
lost resource class and all its (one or more) keys in whatever state they happen
to be, and withdraw any objects published.

- roll phase 1: pending and active key

This state indicates that key rollover was initiated for a Resource Class. This
can only be done for Resource Classes that are in an 'active' state. In other
words: if your Resource Class is in the middle of a key rollover, then that has
to be finished before you can initialise a new rollover.

You can use the following CLI command to start this process for all your eligible
Resource Classes:

.. code-block:: text

   krillc keyroll init

When your Resource Class enters this stage, it will generate a new key and
corresponding CSR. This phase is normally short-lived, because as above Krill
will immediately send the CSR(s) to the appropriate parent(s).

- roll phase 2: new and active key

This state indicates that we received a new certificate for the 'new' key in the
Resource Class. In conformance with :rfc:`6489` Krill will now start publishing
a CRL and manifest for this key, but it will continue to publish all of its
objects such as ROAs under the previous, still 'active' key.

You can check whether your CA has reached this stage by running ``krillc show``.
This will print a section for **each** of your Resource Classes with their
current 'state'. For example:

.. code-block:: text

  Resource Class: 0
  Parent: testbed
  State: roll phase 2: new and active key    Resources:
      ASNs:
      IPv4: 192.168.0.0/16
      IPv6:


- roll phase 3: active and old key

You can complete your key rollover for any Resource Class that is currently
in phase 2 by issuing the following CLI command:

.. code-block:: text

   krillc keyroll activate

Note that according to :rfc:`6489` you should wait **at least 24 hours**
before initiating this step.

This stage will trigger that the 'new' key is activated. All objects, like ROAs,
which were issued under the previous 'active' key will now be published
under that new key. Furthermore Krill will generate a revocation revocation
request for the previous active key. But, until it is indeed confirmed to
be revoked by the parent Krill will continue to issue a CRL and manifest,
but no other objects for it.

This stage should be short-lived. The revocation request is sent to the
parent immediately. But it exists in order to deal with a possible failure
to communicate with the parent when the revocation request is sent. In that
case Krill will continue to try in the background. As soon as the old key
is revoked Krill will remove it. After this has been done there is only
one key again, and it's 'active'.
