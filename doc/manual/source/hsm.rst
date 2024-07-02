.. _doc_krill_hsm:

Hardware Security Modules
=========================

Overview
--------

Krill uses OpenSSL by default for key generation, and it stores the
private keys thus generated in the `keys` directory under its data
directory. For many organisations this will be good enough, provided
of course that they ensure that access to the server and backup data
is restricted.

If you want to take security one (big) step up, then you may want to
use a Hardware Security Module (HSM) instead. HSMs are devices that can
be used to safeguard and manage digital keys. They are designed to allow
applications to use private keys, whilst ensuring that the actual
private keys are never leaked outside of the device - not even to the
application that is using the key.

However, be aware that your existing keys cannot (easily) be imported
into your HSM. One could also argue that if a key had not been generated
inside the actual HSM importing it will not increase security
significantly, because there is no way of knowing for sure that the key
was never leaked.

So, in order to use HSMs on an existing Krill installation you will have
to perform a :ref:`key rollover<doc_krill_ca_keyroll>`. This will ensure
that the keys used for your RPKI CA certificates will use the HSM. But,
unfortunately, there is no standards supported way to perform a key
rollover for the identity key that Krill uses for its communication with
parent (and child) CAs and its Publication Server. We are planning to
work on a solution for this and will reach out to the IETF to seek
standardisation.

Integrating with an HSM
-----------------------

Krill uses what it calls a "signer" to create and manage keys and to
sign data with them. For the most part the Krill CA code is unaware of
which signer implementation is associated with a key. For long-lived
key-pairs such as the keys used in RPKI CA certificates (the resource
certificate signed by the parent) and the ID certifcate used in the
:RFC:`6492` (provisioning) and :RFC:`8181` (publication) protocols, it
will only keep track of the public key identifier.

It falls to the "signer" then to map these public key identifier to an
actual private key that can be used for signing operations. As mentioned,
the default signer uses OpenSSL, in which case the actual private keys
are simply stored on disk in the `keys` sub-directory of Krill data
directory.

If you have access to a Hardware Security Module (HSM) you can instead
configure "signer" implementations which will use the HSM to create and
safeguard the private keys and perform any signing operation inside the
HSM.

.. Note:: Krill uses one-off signing keys for the EE certificates used
          in RPKI Signed Objects (such as ROAs and Manifests). These
          keys are generated whenever such an object is created, and
          used only once for signing, and then they are destroyed.

          Such keys will **NOT** be created with, stored in or signed
          with the HSM. This is because it can be slow to generate, sign
          with and destroy one-off signing keys using an HSM.

          On the other hand, because these one-off keys are immediately
          destroyed, they do not need to be protected to the same degree
          as RPKI CA private keys, or CA identity keys. Assuming that
          the OpenSSL generation of a 2048 bit RSA key pair is secure
          enough.


Compatible HSMs
---------------

In theory Krill supports any HSM that is compatible with the
`PKCS#11 <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11>`_
2.40 and/or the `KMIP <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>`_
1.2 standards. The HSM must already be setup and you must already be in
possession of any access credentials which Krill will need to use to
connect to the HSM.

Krill has been tested with the following (in alphabetical order):

==================================   ================   ==================   ============
Cryptographic Token Name             Tested Protocols   Tested Token Form    Test Results
==================================   ================   ==================   ============
`AWS CloudHSM`_                      PKCS#11            Cloud Service        `#556`_
`Kryptus kNET HSM`_ v1.25.0          PKCS#11 & KMIP     Cloud Service        `#554`_, `#565`_
`PyKMIP`_ v0.10.0                    KMIP               Software             `#564`_
`SoftHSMv2`_ v2.6.1                  PKCS#11            Software             `#553`_
`Utimaco Security Server`_ v4.45.3   PKCS#11            Software Simulator   `#732`_
`YubiHSM 2`_                         PKCS#11            USB key              `#555`_
==================================   ================   ==================   ============

.. Note:: For the latest information on Krill HSM compatibility
          see `here <https://github.com/NLnetLabs/krill/issues?q=label%3A%22interop+testing%22+label%3A%22hsm%22>`_.

.. _AWS CloudHSM: https://aws.amazon.com/cloudhsm/
.. _Kryptus kNET HSM: https://www.kryptus.com/knet/
.. _PyKMIP: https://github.com/OpenKMIP/PyKMIP
.. _SoftHSMv2: https://github.com/opendnssec/SoftHSMv2
.. _Utimaco Security Server: https://www.utimaco.com/products/categories/general-purpose-solutions/securityserver
.. _YubiHSM 2: https://www.yubico.com/products/hardware-security-module/

.. _#553: https://github.com/NLnetLabs/krill/issues/553
.. _#554: https://github.com/NLnetLabs/krill/issues/554
.. _#555: https://github.com/NLnetLabs/krill/issues/555
.. _#556: https://github.com/NLnetLabs/krill/issues/556
.. _#564: https://github.com/NLnetLabs/krill/issues/564
.. _#565: https://github.com/NLnetLabs/krill/issues/565
.. _#732: https://github.com/NLnetLabs/krill/issues/732


In order to work with Krill the HSM must support the following operations:

===================  =================
PKCS#11              KMIP
===================  =================
C_CloseSession       Activate
C_DeleteObject       Create Key Pair
C_Finalize           Destroy
C_FindObjects        Get
C_FindObjectsFinal   Modify Attribute
C_FindObjectsInit    Query
C_GenerateKeyPair    Revoke
C_GetAttributeValue  Sign
C_GetInfo
C_GetSlotInfo
C_GetSlotList
C_GetTokenInfo
C_Initialize
C_Login
C_OpenSession
C_Sign
C_SignInit
===================  =================

Krill can use a cluster of HSMs if the cluster appears to Krill as a
single HSM, i.e. if Krill is not aware that the "single" HSM is in fact
a cluster of HSMs.

PKCS#11 or KMIP?
""""""""""""""""

PKCS#11 and KMIP are very similar in the capabilities they provide, so
much so that there are commercial offerings that can bridge from one to
the other, HSMs may offer support for both and both standards are
maintained by `OASIS <https://www.oasis-open.org/>`_. From a Krill server
operation perspective however they are very different and each has its
own pros and cons.

PKCS#11 works by delegating configuration, logging, administration,
maintenance and upgrade of the interface with the HSM to a library file
outside of Krill that Krill loads when it runs. You therefore have to
manage and monitor this library and its logs as a separate component on
the system running Krill. However, as a separate component it can
connect in any way it needs to the backend which can be local or remote,
or possibly even to a cluster of systems. Krill sees only the library,
it has no way of knowing whether the backend is local or remote,
singular or clustered. This means it also has no way of controlling how
long the library will block to wait for a task to complete or how many
requests it can handle at once or how many system resources it uses.

KMIP is arguably simpler to setup. With KMIP you only need to manage
Krill and the HSM, there is no additional library component to manage as
with PKCS#11. Krill itself communicates directly with the HSM and so all
configuration, logging and resource usage is determined by Krill. In addition,
monitoring is done by monitoring Krill itself. Krill connects to the
KMIP server via TLS encrypted TCP and thus could also potentially be
routed to one of many backend servers in a cluster, or the server could
be a process running locally on the same host such as PyKMIP.

Scenarios
---------

Fresh installation
""""""""""""""""""

With a fresh installation of Krill you can use the HSM from the start.
No keys will be stored locally, instead all long-lived keys will be
stored in the HSM.

Migrating to or between HSMs
""""""""""""""""""""""""""""

Krill does not support migration of existing RPKI CA private keys from
one signer to another. Instead you will need to perform a
:ref:`key rollover<doc_krill_ca_keyroll>` for each CA.

.. Note:: Not all keys can be rolled. See the warning above about
          migration of ID keys used in parent/child and CA/publication
          server relationships.


To perform a key roll from one signer to another you must first change
the ``default_signer`` in ``krill.conf`` to the new signer, and then
restart Krill. After this point any new keys that are created by Krill,
including the new key resulting from a rollover, will be created in
using the new ``default_signer``.

Configuration
-------------

See ``krill.conf`` for full details.

.. Note:: Any changes to the configuration file will not take effect
          until Krill is restarted.

For backward compatibility if no ``[[signers]]`` sections exist in
``krill.conf`` then Krill will use the default OpenSSL signer for all
signing related operations. To use a signer other than the default you
must add one or more ``[[signers]]`` sections to your ``krill.conf``
file, one for each signer that you wish to define.

All signers must have a ``type`` and a ``name`` and properties specific
to the type of signer.

The default configuration is equivalent to addding the following in
``krill.conf``:

.. code-block::

   [[signers]]
   type = "OpenSSL"
   name = "Default OpenSSL signer"

Signer Roles
""""""""""""

When configuring more than one signer, one may be designated the
``default_signer`` and another (or the same one) may be designated the
``one_off_signer``. The ``default_signer`` is used to create all new
keys, except in the case of one-off signing for which the
``one_off_signer`` signer will be used to create a new temporary key,
sign with it then destroy it.

Specifying the ``default_signer`` and ``one_off_signer`` is done by
referencing the name of the signer. For example the above is equivalent
to:

.. code-block::

   default_signer = "Default OpenSSL signer"
   one_off_signer = "Default OpenSSL signer"

   [[signers]]
   type = "OpenSSL"
   name = "Default OpenSSL signer"

When only a single signer is defined it will implicitly be the
``default_signer``. When defining more than one signer the
``default_signer`` must be set explicitly.

If the ``default_signer`` is not of type ``OpenSSL`` and is not
explicitly set as the ``one_off_signer``, an OpenSSL signer will
automatically be used as the ``one_off_signer``.

Configuring a PKCS#11 signer
""""""""""""""""""""""""""""

.. Note:: To actually use a PKCS#11 based signer you must first set it
          up according to the vendor's instructions. This may require
          creating additional configuration files outside of Krill,
          setting passwords, provisioning users, exporting shell
          environment variables for use by the library while running as
          part of the Krill process, creating or determining a slot ID
          or label, etc.

For a PKCS#11 signer you must specify the path to the dynamic library
file for the HSM that was supplied by the HSM provider and a slot ID or
label, and if needed, a user pin.

.. code-block::

   [[signers]]
   type = "PKCS#11"
   name = "SoftHSMv2 via PKCS#11"
   lib_path = "/usr/local/lib/softhsm/libsofthsm2.so"
   slot = 0x12a9f8f7
   user_pin = "xxxx"                                       # optional
   login = true                                            # optional, default = true

Note:
  - If using a slot label rather than ID you can supply the label using ``slot = "my label"``.
  - You can also supply an integer slot ID, e.g. ``slot = 123456``.
  - If your HSM does not require you to login you can set ``login = false``.
  - If your HSM requires you to supply a pin via an external key pad you can omit the ``user_pin`` setting.

Configuring a KMIP signer
"""""""""""""""""""""""""

.. note:: To actually use a KMIP based signer you must first set it up
          according to the vendors instructions. This may require
          setting up users and passwords and/or obtaining certificates
          in order to populate the associated settings in the
          ``krill.conf`` file.

For a KMIP signer you must specify the fully-qualified domain name (FQDN) or IP address of the host, and
optionally other connection details such as port number, client
certificate, server CA certificate, username and password.

.. code-block::

   [[signers]]
   type = "KMIP"
   name = "Kryptus via KMIP"
   host = "my.hsm.example.com"
   port = 5696                                             # optional, default = 5696
   server_ca_cert_path = "/path/to/some/ca.pem"            # optional
   client_cert_path = "/path/to/some/cert.pem"             # optional
   client_cert_private_key_path = "/path/to/some/key.pem"  # optional
   username = "user1"                                      # optional
   password = "xxxxxx"                                     # optional
   insecure = false                                        # optional
   force = false                                           # optional

Note:
  - ``host`` can also be an IP address.
  - ``insecure`` will disable verification of any certificate presented by the server.
  - ``force`` should only be used if the HSM fails to advertize support for a feature that Krill requires but actually
    the HSM **does** support the feature.

Signer Lifecycle
----------------

At startup Krill will announce the configured signers in its logs but
will not yet attempt to connect to them. Only once a signing related
operation needs to be performed will Krill attempt to connect to the signer.

If there is a problem connecting to a signer Krill will retry, unless
the problem is fatal such as the signer lacking support for required
operations. A problem with a signer will not stop Krill from running and
continuing to serve the UI and API or from executing background tasks.
Thus if some keys are owned by one signer that is reachable and another
signer is not reachable, Krill will continue to operate correctly for
operations involving the reachable signer.

On initial connection to a new signer Krill will create a "signer
identity key" in the HSM. This serves to verify that the signer is able
to create and sign with keys and in future that the signer is the one
that owns keys attributed to it.

New keys are created by the ``default_signer`` unless they are one-off
keys in which case they are created by the ``one_off_signer``. Signing
with a key is handled by the signer that possesses the key.

.. Note:: Krill determines the signer that possesses a key by consulting
          a mapping that it keeps from key identifier to a Krill
          internal signer ID and associated metadata.

          On initial connection to a signer it "binds" the internal
          representation of the connected signer to the matching
          internal signer ID and updates the metadata about the signer.
          It verifies that the internal signer ID corresponds to the
          backend by verifying the existence of a previously created
          "signer identity key" within the backend and that the backend
          is able to correctly sign with that key.

          Krill is able to maintain the mapping between keys associated
          with a signer ID and the actual connected signer even if the
          name and server connection details in ``krill.conf`` are
          changed so you are free to rename the signer or replace the
          physical server by a (synchronized) spare or upgrade or change
          its IP address or the credentials used to access it and Krill
          will still know when connecting to it which keys it possesses.

.. Warning:: If Krill is not configured to connect to the signer that
             possesses a key that Krill needs to sign with, or is unable
             to connect to it using the configured settings, then Krill
             will be unable to sign with that key!

             One particular scenario to watch out for is when
             reconfiguring an existing Krill instance to use an HSM when
             that Krill instance already has at least one CA (and thus
             already created at least one key pair using OpenSSL).

             In this scenario, if the changes to ``krill.conf`` to use
             the HSM define only the one signer (the HSM) and do NOT set
             that signer as the ``one_off_signer``, then Krill will
             activate the default OpenSSL signer for one-off key signing
             and will use it to find the previously created OpenSSL keys.

             If however the one and only HSM signer is also set as the
             ``one_off_signer`` then Krill will not activate the OpenSSL
             signer and so will not find the previously created OpenSSL
             keys. In this case you must explicitly add a ``[[signers]]``
             block of ``type = "OpenSSL"`` with default settings thereby
             causing Krill to activate the default OpenSSL signer.

SoftHSMv2 Example
-----------------

Let's see how to setup `SoftHSMv2 <https://github.com/opendnssec/SoftHSMv2>`_
with Krill. This example uses commands suitable for an Ubuntu operating
system, for other operating systems you may need to use slightly
different commands.

First, install and setup SoftHSM v2:

.. code-block::

   $ sudo apt install -y softhsm2
   $ softhsm2-util --init-token --slot 0 --label "My token 1" --so-pin 1234 --pin 5678

Next add the following to your `krill.conf` file:

.. code-block::

   [[signers]]
   type = "PKCS#11"
   name = "SoftHSMv2"
   lib_path = "/usr/lib/softhsm/libsofthsm2.so"
   slot = "My token 1"
   user_pin = 5678

Now (re)start Krill.

That's it! When you next create a CA Krill will create a key pair for it
in SoftHSMv2 instead of using OpenSSL.

One way to inspect the keys stored inside OpenSSL is using the
``pkcs11-tool`` command:

.. code-block::

   $ sudo apt install -y opensc
   $ pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -O -p 5678
   Using slot 0 with a present token (0x542bc831)
   Public Key Object; RSA 2048 bits
     label:      Krill
     ID:         e83e96883ee73e69e0e57d54b6726c9d45f788c5
     Usage:      verify
     Access:     local
   Public Key Object; RSA 2048 bits
     label:      Krill
     ID:         9ecd3796786c7a073d5384c155d8d475d103df74
     Usage:      verify
     Access:     local
   ...


Configuration Reference
-----------------------

The following configuration file description should give you all the
pointers you need to get this setup working:

.. code-block:: text

   ######################################################################################
   #                                                                                    #
   #                       ----==== SIGNER CONFIGURATION ====----                       #
   #                                                                                    #
   #       The settings below can be used to configure the signer used by Krill.        #
   #                                                                                    #
   ######################################################################################

   # Signers
   # -------
   #
   # A signer is a cryptographic token, either hardware or software, local or remote,
   # that can create RSA public/private key pairs and can sign data with the private key.
   #
   # Supported signer types
   # ----------------------
   #
   # Krill supports three types of signer:
   #
   #   - OpenSSL based: Uses the OpenSSL library installed on the host O/S. On older
   #     operating systems it might be that a newer version of OpenSSL than is supported
   #     by the host O/S has been compiled into Krill itself and will be used instead.
   #
   #   - PKCS#11 based: Uses a PKCS#11 v2.20 conformant library file from the filesystem.
   #     How the library handles the requests on behalf of Krill is library specific. A
   #     library such as SoftHSMv2 contains all of the code needed to handle the request
   #     and stores generated keys on the host filesystem. Libraries provided by well
   #     known HSM vendors will dispatch requests to one or a cluster of hardware
   #     security modules connected either physically or by network connection to the
   #     host on which Krill is running.
   #
   #   - KMIP based: Makes TLS encrypted TCP connections to an operator specified server
   #     running a KMIP v1.2 conformant service.
   #
   # Key creation policy
   # -------------------
   #
   # Krill creates keys at different times for different purposes. Some keys are fixed
   # such as the identity key for the RFC 8183 defined provisioning protocol, others can
   # be rolled (e.g. the keys used for RPKI CA certificates in resource classes) and
   # still others are one-off keys (e.g. keys used for EE certificates in CMS) that are
   # discarded after use.
   #
   # Signer roles
   # ------------
   #
   # Signers can be assigned to roles to implement the desired policy. Roles are assigned
   # by setting the following top level configuration file settings:
   #
   #   - default_signer: The signer will be used to generate new long-term key pairs.
   #     Only one signer may be designated as the default. If only one signer is defined
   #     it will be the default. If more than one signer is defined one must be
   #     explicitly set as the default.
   #
   #   - one_off_signer: The signer will be used to generate, sign with and destroy
   #     one-off key pairs. Only one signer may be designated as the oneoff signer. When
   #     not specified an OpenSSL signer will be used for this.
   #
   # These settings must be set to the name of a single signer, e.g.:
   #
   #   default_signer = "My signer"
   #
   #   [[signers]]
   #   type = "OpenSSL"
   #   name = "My signer"
   #
   # Required capabiliites
   # ---------------------
   #
   # When Krill first connects to a new signer it will verify that the signer meets its
   # requirements. In particular it will require the signer to generate an RSA key pair
   # and to demonstrate that it can sign data correctly using the generated private key.
   #
   # Config file settings
   # --------------------
   #
   # At a minimum the "name" and "type" must be specified for a signer.
   #
   # One optional setting can also be set for all signers:
   #
   # - signer_probe_retry_seconds: When initially connecting to the signer on first use
   #   after Krill startup, wait at least N seconds between attempts to connect and
   #   test the signer for compatibility with Krill. Defaults to 30 seconds.
   #
   # The remaining details that must be supplied to configure a signer vary by signer
   # type and by specific implementation. For example an OpenSSL signer doesn't require
   # a path to a library file to load, while a PKCS#11 signer does, and one PKCS#11
   # vendor may require login by PIN code while another might allow operations to be
   # performed with external PIN entry or no PIN entry at all.
   #
   # Default configuration
   # ---------------------
   #
   # The default configuration is equivalent to:
   #
   #   [[signers]]
   #   type = "OpenSSL"
   #   name = "Default OpenSSL signer"
   #
   # Changing the configuration
   # --------------------------
   #
   # The number, type, order, settings, names of signers can be changed at any time.
   # Krill will apply the changes when next restarted. Via the use of identity key
   # based signer binding Krill will still find the keys that it has created as long as
   # the same backend is connected to, irrespective of name or connection details, and
   # that the identity key in the signer has not been deleted.
   #
   # Warning about removing an in-use signer
   # ---------------------------------------
   #
   # Removing a signer that owns keys that Krill is still using will prevent Krill from
   # accessing those keys!
   #
   # Example configuration
   # ---------------------
   #
   # Below is an example configuration. This example defines many signers but normally
   # one would define only a single signer, or two signers if migrating from one signer
   # to another.
   #
   #   default_signer = "SoftHSMv2 via PKCS#11"
   #
   #   [[signers]]
   #   type = "OpenSSL"
   #   name = "Signer 1"
   #
   #   [[signers]]
   #   type = "OpenSSL"
   #   name = "Signer 2"
   #   keys_path = "/tmp/keys"
   #
   #   [[signers]]
   #   type = "PKCS#11"
   #   name = "Kryptus via PKCS#11"
   #   lib_path = "/usr/local/lib/kryptus/libknetpkcs11_64/libkNETPKCS11.so"
   #   user_pin = "xxxxxx"
   #   slot = 313129207
   #
   #   [[signers]]
   #   type = "PKCS#11"
   #   name = "SoftHSMv2 via PKCS#11"
   #   lib_path = "/usr/local/lib/softhsm/libsofthsm2.so"
   #   user_pin = "xxxx"
   #   slot = 0x12a9f8f7
   #
   #   [[signers]]
   #   type = "KMIP"
   #   name = "Kryptus via KMIP"
   #   host = "my.hsm.example.com"
   #   port = 5696
   #   server_ca_cert_path = "/path/to/some/ca.pem"
   #   username = "user1"
   #   password = "xxxxxx"


   # OpenSSL signer configuration
   # ----------------------------
   #
   # This signer uses the operating system provided OpenSSL library (or on older
   # operating systems it may use a modern version of the OpenSSL library compiled into
   # Krill itself) to generate keys, to sign data using them and to generate random
   # values. Keys are persisted as files on disk in a dedicated directory.
   #
   # Key        Value Type   Default          Req'd  Description
   # ====================================================================================
   # keys_path  path string  "$datadir/keys"  No     The directory in which key files
   #                                                 should be created.
   #


   # PKCS#11 signer configuration
   #
   # Krill interacts with a PKCS#11 v2.20 compatible cryptographic device via the Cryptoki
   # interface which involves loading a library file from disk at runtime to which all
   # cryptographic operations will be delegated. The library will in turn communicate
   # with the actual cryptographic device.
   #
   # Note: The PKCS#11 library is not part of Krill nor is it supplied with Krill. Please
   # consult the documentation for your PKCS#11 compatible cryptographic device to learn
   # where you can find the .so library file and how to set up and configure it. For
   # example when using SoftHSMv2 the library is commonly available at filesystem path
   # /usr/lib/softhsm/libsofthsm2.so.
   #
   # Key        Value Type   Default          Req'd  Description
   # ====================================================================================
   # lib_path           path string  None     Yes    The path to the .so dynamic library
   #                                                 file to load.
   # slot                integer or  None     Yes    An integer PKCS#11 "slot" ID or a
   #                     string                      string "slot" label. Can also be
   #                                                 given in hexadecimal, e.g. 0x12AB.
   #                                                 When a label is given Krill will
   #                                                 inspect all available slots and use
   #                                                 the first slot whose label matches.
   # ------------------------------------------------------------------------------------
   # user_pin            string      None     No     The pin or password or secret value
   #                                                 used to authenticate with the
   #                                                 PKCS#11 provider. The format varies
   #                                                 by provider, SoftHSMv2 uses numeric
   #                                                 PINs such as "12345" while AWS
   #                                                 CloudHSM expects this to be in the
   #                                                 form "username:password".
   # login               boolean     True     No     Whether the signer must be logged in
   #                                                 to before performing other
   #                                                 operations.
   # ------------------------------------------------------------------------------------
   # retry_seconds       integer     2        No     Wait N seconds before retrying a
   #                                                 failed request.
   # backoff_multiplier  float       1.5      No     How much longer to wait before retry
   #                                                 N+1 compared to retry N.
   # max_retry_seconds   integer     30       No     Stop retrying after N seconds.


   # KMIP signer configuration
   #
   # Krill interacts with a KMIP v1.2 compatible cryptographic device via the TCP+TTLV
   # protocol. This requires knowing the hostname, port number, and details required to
   # authenticate with the provider.
   #
   # Key                 Value Type  Default  Req'd  Description
   # ====================================================================================
   # host                string      None     Yes    The domain name or IP address to
   #                                                 connect to.
   # port                integer     5696     No     The port number to connect to.
   # ------------------------------------------------------------------------------------
   # insecure            boolean     false    No     If true, do not verify the servers
   #                                                 TLS certificate.
   # force               boolean     false    No     If true, ignore server claims that
   #                                                 it lacks functionality that we
   #                                                 require. For example PyKMIP 0.10.0
   #                                                 says it doesn't support operation
   #                                                 ModifyAttribute but sending a
   #                                                 modify attribute request succeeds.
   # ------------------------------------------------------------------------------------
   # server_cert_path                                File system paths to certificate
   #                     string      None     No     files (in PEM format) for verifying
   # server_ca_cert_path                             the identity of the server.
   #                     string      None     No
   # ------------------------------------------------------------------------------------
   # client_cert_path                                File system paths to certificate and
   #                     string      None     No     key files (in PEM format) for
   # client_cert_private_key_path                    proving our identity to the server.
   #                     string      None     No
   # ------------------------------------------------------------------------------------
   # username            string      None     No     Credentials for authenticating with
   # password            string      None     No     the server.
   # ------------------------------------------------------------------------------------
   # retry_seconds       integer     2        No     Wait N seconds before retrying a
   #                                                 failed request.
   # backoff_multiplier  float       1.5      No     How much longer to wait before retry
   #                                                 N+1 compared to retry N.
   # max_retry_seconds   integer     30       No     Stop retrying after N seconds.
   # ------------------------------------------------------------------------------------
   # connect_timeout_seconds                         Wait at most N seconds to make a TCP
   #                     integer     5        No     connection to the KMIP server.
   # read_timeout_seconds                            Wait at most N seconds for more
   #                     integer     5        No     response bytes to be received from
   #                                                 the KMIP server.
   # write_timeout_seconds                           Wait at most N seconds to write more
   #                     integer     5        No     request bytes to the connection to
   #                                                 the KMIP server.
   # max_use_seconds     integer     60*30    No     Don't use an idle connection to the
   #                                                 KMIP server if it has been connected
   #                                                 for at least N seconds.
   # max_idle_seconds    integer     60*10    No     Close open connections to the KMIP
   #                                                 server if not used in the last N
   #                                                 seconds.
   # ------------------------------------------------------------------------------------
   # max_connections     integer     5        No     The maximum number of concurrent
   #                                                 connections to permit to the server.
   # max_response_bytes  integer     64*1024  No     The maximum number of response bytes
   #                                                 to accept from the KMIP server, or
   #                                                 otherwise treat the request as
   #                                                 failed.
