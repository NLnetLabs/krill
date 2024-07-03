.. _doc_krill_before_you_start:

Before You Start
================

RPKI is a very modular system and so is Krill. Which parts you need and how you
fit them together depends on your situation. Before you begin with installing
Krill, there are some basic concepts you should understand and some decisions
you need to make.

The Moving Parts
----------------

With Krill there are two fundamental pieces at play. The first part is the
Certificate Authority (CA), which takes care of all the cryptographic operations
involved in RPKI. Secondly, there is the publication server which makes your
certificate and ROAs available to the world.

In almost all cases you will need to run the CA that Krill provides under a
parent CA, usually your Regional Internet Registry (RIR) or National Internet
Registry (NIR). The communication between the parent and the child CA is
initiated through the exchange of two XML files, which you need to handle
manually: a child request XML and a parent response XML. This involves
generating the request file, providing it to your parent, and giving the
response file back to your CA.

After this initial exchange has been completed, all subsequent requests and
responses are handled by the parent and child CA themselves. This includes the
entitlement request and response that determines which resources you receive on
your certificate, the certificate request and response, as well as the revoke
request and response.

.. Important:: The initial XML file exchange is the only manual step required
               to get started with Delegated RPKI. All other requests and
               responses, as well as re-signing and renewing certificates and
               ROAs are automated. **As long as Krill is running, it will
               automatically update the entitled resources on your certificate,
               as well as reissue certificates, ROAs and all other objects
               before they expire or become stale.** Note that even if Krill
               does go down, you have 8 hours to bring it back up before data
               starts going stale.

Whether you also run the Krill publication server depends on if you can, or want
to use one offered by a third party. For the general wellbeing of the RPKI
ecosystem, we would generally recommend to publish with your parent CA, if
available. Setting this up is done in the same way as with the CA: exchanging a
publisher request XML and a repository response XML.

Publishing With Your Parent
---------------------------

If you can use a publication server provided by your parent, the installation
and configuration of Krill becomes extremely easy. After the installation has
completed, you perform the XML exchange twice and you are done.

.. figure:: img/parent-child-rir-nir-repo.*
    :align: center
    :width: 100%
    :alt: A repository hosted by the parent CA

    A repository hosted by the parent CA, in this case the RIR or NIR.

Krill is designed to run continuously, but there is no strict uptime requirement
for the CA. If the CA is not available you just cannot create or update ROAs.
This means you can bring Krill down to perform maintenance or migration, as long
as you bring it back up within 8 hours to ensure your cryptographic objects are
re-signed before they go stale.

.. Note:: This scenario illustrated here also applies if you use an RPKI
          publication server offered by a third party.

At this time, APNIC, ARIN and Brazilian NIR NIC.br offer a publication server for
their members. Several other RIRs have this functionality on their roadmap. This
means that in some cases, you will have to publish yourself.

Publishing Yourself
-------------------

Krill features a publication server, disabled by default, but which can be used
to host a server for yourself, and others, such as customers or business units
who run their own Krill CAs as children under your CA, and to whom you have
delegated resource certificates.

If you run Krill as a publication server, you will be faced with running a
public service with all related responsibilities, such as uptime and DDoS
protection. This option is not recommended if you don't have a clear need
to run your own server.

Read more about this option in :ref:`doc_krill_publication_server`

System Requirements
-------------------

The system requirements for Krill are quite minimal. The cryptographic
operations that need to be performed by the Certificate Authority have a
negligible performance and memory impact on any modern day machine.

When you publish ROAs yourself using the Krill publication server in combination
with Rsyncd and a web server of your choice, you will see traffic from several
hundred relying party software tools querying every few minutes. The total
amount of traffic is also negligible for any modern day situation.

.. Tip:: For reference, NLnet Labs runs Krill in production and serves ROAs to
         the world using a 2 CPU / 2GB RAM / 60GB disk virtual machine. Although
         we only serve four ROAs and our repository size is 16KB, the situation
         would not be different if serving 100 ROAs.
