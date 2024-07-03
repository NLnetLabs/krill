.. _doc_krill_trust_anchor:

Krill as a Trust Anchor
=======================

Krill can be set up to operate an RPKI Trust Anchor (TA). An RPKI TA
serves as an `entry point for RPKI validators <https://rpki.readthedocs.io/en/latest/rpki/using-rpki-data.html#connecting-to-the-trust-anchor>`_.
There are currently `five globally used TAs <https://rpki.readthedocs.io/en/latest/rpki/introduction.html#mapping-the-resource-allocation-hierarchy-into-the-rpki>`_
operated by the five RIRs, where each RIR is responsible for IPv4, IPv6
and AS number resources that are allocated to them by IANA.

If you are not an RIR, then you will not need to run your own RPKI TA for
normal RPKI operations. Instead, you would operate one or more RPKI CAs that get
their IPv4, IPv6 and ASN number resources under one or more of the RIR
operated TAs.

That said, some users may want to operate their own TA outside of the
TAs provided by the RIRs for testing, study or research reasons. Or perhaps
even to manage private use address space.

Furthermore, this documentation may be of interest to readers who simply
wish to understand how Krill is used to operate a TA.

Overview
^^^^^^^^

The Krill TA is logically separated into 'Proxy' and 'Signer'
components which are associated with each other.

.. parsed-literal::

          TA Online Host             TA Disconnected Host
   +---------------------------+    +--------------------+
   |                           |    |                    |
   |  krillc    krillta proxy  |    |   krillta signer   |
   |    |             |   ^    |    |         ^          |
   |    +--> krill <--+   .    |    +---------.----------+
   |                      .    |              .
   +----------------------.----+              . offline
                          .                   . transport
                          + . . . . . . . . . +

The TA Signer is responsible for generating and using the TA RPKI key. It
is designed to be operated using its own standalone command line tool
called ``krillta``. For improved security this tool can be used on a
system that is kept disconnected from the network and offline when it is
not in use, and optionally an HSM could be used for handling the key.

The TA Proxy always lives inside Krill itself and is responsible for all
*online* operations such as handling :rfc:`6492` communications with a
child CA and publishing materials signed by the TA Signer using the
:rfc:`8181` communication protocol with a Publication Server. The TA
Proxy uses its own "identity" key and certificate for these protocols.

The TA Proxy is responsible for managing which child CA(s) can operate
under the TA, and what resources they are entitled to. When the TA Proxy
first receives an :rfc:`6492` request from a child it will reply with a
dedicated not-performed-response (code 1104) indicating that the request is
scheduled for processing. The child can (and does) keep sending the same
request, and it will get a different dedicated not-performed-response (code
1101) indicating that the request was already scheduled.

Contrary to the other not-performed-responses these codes do not indicate
that any error occurred. These codes exist to support the asynchronous
signing by the offline TA Signer.

The actual signing process is initiated by the TA Proxy which generates
a request for the signer through the CLI/API. The TA Signer then processes
the request, does all the necessary signing and generates a response.
This response is then given to the TA Proxy which will then publish any
new signed objects. The TA Proxy will also keep the now completed response
for the child CA, which will be returned the next time that the child CA
sends their request to the TA Proxy.

Even though in principle there could be multiple child CAs under the TA
Proxy our design is intended to use a single child CA only. Furthermore,
theoretically, this child CA could access the TA Proxy from a remote
system (another Krill or RPKI CA installation) - but at this time we only
support a local Krill CA for this purpose.

One key advantage of this model is that it allows us to trigger a re-sync
of the local CA child with its TA Proxy parent immediately after the
latter processed the TA Signer response.

For now, we include *all* IPv4, IPv6 and AS number resources on the TA
certificate, as well as the one immediate child CA. In future, we can
add support for initialising a TA with a smaller set of resources, and
changing that set of resources.

Set Up
^^^^^^

At this time you can have only 1 Trust Anchor per Krill instance. We
believe that there is not likely going to be a need for managing multiple
TAs in a single installation.

Krillta Command Line Tool
-------------------------

A ``krillta`` command line tool is now available as a separate package.
It is not included in the main Krill package because it will likely only
be needed by a very small number of Krill users.

``krillta`` can be used to manage both the TA Signer, in which case it
will expect to keep its state on a local disk, and the TA Proxy, in which
case it will connect to the Krill server in the same way that ``krillc``
does.

The communication between the TA Proxy and Signer is done using signed
CMS messages - much like the CMS used in :rfc:`6492` allowing both the
TA Proxy and Signer to validate requests and responses. Furthermore, each
request includes a nonce value that is expected to be repeated in the
corresponding response. Nonce values may not be repeated. This helps to
protect against replay attacks, although in practice it's more likely
to catch mistakes where the wrong request or response is used by accident.

Run Krill with TA Support
-------------------------

Set up an empty Krill installation following the normal installation
process. Add the following to your ``krill.conf`` files in addition to
any other set up that you need to do:

.. code-block:: text

  ta_support_enabled = true

Then run Krill as usual so that it can accessed by ``krillc``, ``krillta``
and the UI.

Initialise TA Proxy
-------------------

The first step in the actual set up of the Krill TA Signer and Proxy
couple is to initialise the TA Proxy. This will create an empty TA Proxy
that has an identity key for communication, and pretty much nothing else.

.. code-block:: bash

  krillta proxy init


Initialise Publication Server
-----------------------------

We recommend that you set up and use a Publication Server in the same
Krill instance that hosts your TA Proxy, and online TA child for that
matter, which we will get to in a bit.

The reason for this is that communication will be more efficient, and
more importantly less error prone. I.e. it's unlikely that the same
Krill instance would work for the TA Proxy but refuse to work for its
Publication Server.

The setup of a Krill Publication Server is described
:ref:`here<doc_krill_publication_server>`.

TA Proxy Publisher Request
--------------------------

Get the TA Proxy :rfc:`8183` Publisher Request XML file and save it
so it can be uploaded to the Publication Server:

.. code-block:: bash

  krillta proxy repo request > ./pub-req.xml

Add TA Proxy as Publisher
-------------------------

Add the TA Proxy as a publisher and capture the :rfc:`8183` Repository
Response XML:

.. code-block:: bash

  krillc pubserver publishers add --request ./pub-req.xml >./repo-res.xml

.. Note:: The Krill TA uses "ta" as its name (handle in RFC terms).
     Krill Publication Servers normally add the handle name as a sub-dir
     to the global base rsync path (``sia_base`` in RFC terms). However,
     if the handle is "ta", then no sub-dir will be added. The reason is
     that this way recursive rsync fetches for the TA certificate's
     publication point will get the full repository content in one go.

Configure Repository for TA Proxy
---------------------------------

Now add the Publication Server (and its associated Repository) to the
TA Proxy:

.. code-block:: bash

  krillta proxy repo configure --response ./repo-res.xml


Configure the TA Signer
-----------------------

Create a working directory where your TA Signer can keep its state and
log file. Then create a configuration file. If you use ``/etc/krillta.conf``
as the configuration file, then ``krillta`` will be able to find it
automatically, otherwise use ``-c /path/to/krillta.conf`` to override
this default.

The configuration file must at least contain a setting for the data
directory. Other settings are optional - you only need to change them
if you want to change the default logging and/or use an HSM.

.. NOTE:: At this moment "timing" parameters for the TA are hard coded. Child
   CA certificates are signed (and re-signed) with a validity of 52 weeks.
   The CRL and MFT next update and MFT EE certificate not after time are
   set to 12 weeks after the moment of signing. We may add support for
   overriding these values if desired.

Example configuration file:

.. code-block::

  ######################################################################################
  #                                                                                    #
  #                                      DATA                                          #
  #                                                                                    #
  ######################################################################################

  # Specify the directory where the TA Signer will store its data.
  data_dir = "/var/lib/krillta/data"

  ######################################################################################
  #                                                                                    #
  #                                     LOGGING                                        #
  #                                                                                    #
  ######################################################################################

  # Log level
  #
  # The maximum log level ("off", "error", "warn", "info", or "debug") for
  # which to log messages.
  #
  # Defaults to "warn"
  #
  ### log_level = "warn"

  # Log type
  #
  # Where to log to. One of "stderr" for stderr, "syslog" for syslog, or "file"
  # for a file in which case $data_dir/krillta.log will be used. This cannot (yet)
  # be overridden.
  #
  # Defaults to "file"
  #
  ### log_type = "file"

  ######################################################################################
  #                                                                                    #
  #                                SIGNER CONFIGURATION                                #
  #                                                                                    #
  ######################################################################################

  #
  # By default OpenSSL is used for key generation and signing.
  #
  # But.. The usual Krill HSM support should also work in this context. If you want to
  # use an HSM please read the documentation here:
  # https://krill.docs.nlnetlabs.nl/en/stable/hsm.html
  #
  # Note that this configuration cannot be changed after the TA Signer has been
  # initialised. Or rather.. where for normal Krill CAs defaults may be changed and
  # key rolls can be used to start using a different signer, there is no key roll
  # support for the TA. This may be implemented in future in which case we would
  # also support RPKI Signed TALs for this process.


Initialise the TA Signer
------------------------

The TA Signer is always associated with a single TA Proxy. We initialised the
TA Proxy and configured a repository for it in the earlier steps. We now
need to export some of this information so that we can an initialise the
one single TA Signer for that Proxy.

Step 1: Get the proxy ID

.. code-block:: bash

  krillta proxy id --format json > ./proxy-id.json

Step 2: Get the proxy repo contact

.. code-block:: bash

  krillta proxy repo contact --format json  >./proxy-repo.json

Step 3: Initialise

Here you need to use the files saved in steps 1 and 2.

In addition to this you will need to specify the URIs that should be used
on the Trust Anchor Locator (TAL). Of course that TA certificate does not
yet exist - we need to know the URIs so it can be generated properly. You
will be able to download the TA certificate at a later stage. For now,
make sure that you choose URIs (rsync and HTTPS) where you will host a
copy of that certificate later.

Note that TA certificate itself is not published using the :rfc:`8181`
Publication Protocol. The Krill Publication Server expects that no other
files are present in its RRDP and rsync directories besides except for
the files published through this procotol.

For this reason you will need to use separate dedicated HTTPS and rsync
endpoints for the TA certificate.

.. code-block:: bash

  krillta signer init --proxy_id ./proxy-id.json \
                      --proxy_repository_contact ./proxy-repo.json \
                      --tal_https <HTTPS URI for TA cert on TAL> \
                      --tal_rsync <RSYNC URI for TA cert on TAL>


Associate the TA Signer with the Proxy
--------------------------------------

Get the TA Signer 'info' JSON file and save it:

.. code-block:: bash

  krillta signer show > ./signer-info.json


Then 'initialise' the signer associated with the TA Proxy. (we should
probably rename this to 'associate' instead):

.. code-block:: bash

  krillta proxy signer init --info ./signer-info.json


At this point you should see that the TAL is available under the ``/ta/ta.tal``
endpoint. It will include the HTTPS and rsync URIs that were specified
when the signer was initialised. You can download a copy of the TA
certificate under the ``/ta/ta.cer`` endpoint. Copy it, and place it
where your web server and rsync daemon can serve it.

You should also see that a manifest and CRL were published for your
TA. These files should be published in your Publication Server's base
rsync directory. As explained above, the "ta" does not use a sub-dir.


Create Child CA under TA
------------------------

As mentioned in the overview section we recommend creating a single
child CA under the TA, with all resources. This will in effect be the
acting "online" TA.

Step 1: Create the "online" CA

.. code-block:: bash

  krillc add --ca online

Step 2: Add "online" as a child of "ta"

.. code-block:: bash

  krillc show --ca online --format json >./online.json
  krillta proxy children add --info ./online.json >./res.xml

Step 3: Add "ta" as a parent of "online"

.. code-block:: bash

  krillta proxy children response --child online >./res.xml
  krillc parents add --ca online --parent ta --response ./res.xml

Step 4: Add "online" as a Publisher

.. code-block:: bash

  krillc repo request --ca online > ./pub-req.xml
  krillc pubserver publishers add --request ./pub-req.xml > ./repo-res.xml
  krillc repo configure --ca online --response ./repo-res.xml

If you now look at your CA using ``krillc show --ca online`` you should
see that the parent ``ta`` was added, but no resources were received. Instead,
you will see that the CA ``online`` has a key in state "pending".

There will also be a pending Certificate Sign Request (CSR) from ``online``
to its parent ``ta``. The CSR will be re-sent periodically, but ``online``
will get a not-performed-response from ``ta`` with codes 1104 or 1101,
indicating that the CSR is received and is scheduled for signing. You may
see messages to this effect in the log - this is not alarming.

If you follow the exchange process described below then the TA Signer will
sign the certificate. Since the ``online`` CA lives in the same Krill
instance as the TA Proxy it will be made aware of this update immediately
and get its signed certificate without further delay.


Typical Proxy Signer Exchange
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The typical exchange between the Proxy and Signer follows these steps:

- Make the request in the Proxy
- Download the Proxy request
- Process the Proxy request
- Save the Signer response
- Upload the Signer response

Make a TA Proxy Request
-----------------------

.. code-block:: bash

  krillta proxy signer make-request


*Note that the ``krillta`` subcommand combination ``proxy signer`` is
used for actions for the ``proxy`` relating to its associated ``signer``.

Download the TA Proxy Request
-----------------------------

.. code-block:: bash

  krillta proxy signer show-request --format json > ./request.json

.. Note:: the request JSON includes both a readable representation of the
    request that is made by the ``proxy`` for the ``signer``, and a
    base64 encoded signed (CMS) object containing that same request. Any
    attempt to tamper with the clear text part of the request, the
    corresponding response for that matter, will result in a validation
    failure and rejection.

Process TA Proxy Request
------------------------

.. code-block:: bash

  krillta signer process --request ./request.json

Save the TA Signer Response
---------------------------

.. code-block:: bash

  krillta signer last > ./response.json


Upload the Signer Response
--------------------------

.. code-block:: bash

  krillta proxy signer process-response --response ./response.json


Auditing
^^^^^^^^

You can review the exchanges seen by the TA Signer. The default output
uses JSON and contains a lot of information. The text output is somewhat
friendlier to the human eye:

.. code-block:: bash

  krillta signer exchanges --format text
