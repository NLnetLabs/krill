# Change Log

## Unreleased next version

Bug fixes

* Improved the message printed when the TA proxy’s signer request does not
  contain any actual requests. ([#1305])
* Fixed various migration issues. ([#1306], [#1307])

Other changes

* Add packaging for Debian 13. ([#1308])

[#1305]: https://github.com/NLnetLabs/krill/pull/1305
[#1306]: https://github.com/NLnetLabs/krill/pull/1306
[#1307]: https://github.com/NLnetLabs/krill/pull/1307
[#1308]: https://github.com/NLnetLabs/krill/pull/1308


## 0.15.0-rc4

Released 2025-06-26.

Bug fixes

* Improve performance by using buffered reading and writing in the store.
  ([#1300], [#1301])

Other changes

* Updated dependencies.

[#1300]: https://github.com/NLnetLabs/krill/pull/1300
[#1301]: https://github.com/NLnetLabs/krill/pull/1301


## 0.15.0-rc3

Released 2025-06-18.

Other changes

* Upgraded the bundled Krill UI to
  [release 0.9.0](https://github.com/NLnetLabs/krill-ui/releases/tag/v0.9.0).
  ([#1295])
* Added packaging support for RHEL 10-alikes. ([#1297])

[#1295]: https://github.com/NLnetLabs/krill/pull/1295
[#1297]: https://github.com/NLnetLabs/krill/pull/1297


## 0.15.0-rc2

Released 2025-06-13.

Bug fixes

* Fix Krill refusing to start if the now unnecessary “refresh announcements
  info” task is still present by adding it back as a dummy task. ([#1292])
* Fix redirect of `/` to `/ui` and allow additional segments on the `/ui`
  path in the HTTP server. ([#1293])


[#1292]: https://github.com/NLnetLabs/krill/pull/1292
[#1293]: https://github.com/NLnetLabs/krill/pull/1293


## 0.15.0-rc1

Released 2025-06-13.

Breaking Changes

* Refactored command line options processing for all binaries. As a
  result, options for both `krillc` and `krillta` have slightly changed.
  For `krillc`, the `--server`, `--token`, `--format`, and `--api` options
  are now before the first subcommand (since they affect all commands). For
  `krillta`, those options are now after `krillta proxy` but before the next
  subcommand, while `--format` is now after `krillta signer`. ([#1228])
* Removed support for RTA in `krillc`. Support is currently still
  present in the Krill server, though behind a (non-default) feature flag.
  ([#1228])
* Changed how authorization works with OpenID Connect and configuration
  files. Custom profiles have been replaced with a straightforward mapping
  from access permission to roles and assigning roles to users. For
  configuration file-based authentication, the file format has slightly
  changed but the current format is still accepted. If you are using
  OpenID Connect, you will have to update your configuration. Please, see
  the manual for details. ([#1232])
* Replaced downloading of RISwhois file for ROA analysis with calls to the
  [Roto API](https://github.com/NLnetLabs/roto-api). This can be
  controlled via new configuration settings `bgp_api_enabled`,
  `bgp_api_uri`, and `bgp_api_cache_seconds`. ([#1233], [#1266])

New

* Added a command to re-initialize the trust anchor signer with different
  timing values or TAL URLs. ([#1255])
* Disables the protection against early re-issuance for CA certificates that
  have the full resource set, typically TA certificates. ([#1281])

Bug Fixes

* Fixed a potential infinite recursion in PKCS11 error handling. ([#1215])
* Open ID connect: Re-initialize the connection after 60s to pick up
  configuration changes at the provider. ([#1226])
* Fixed the naming of the trust anchor timing configuration. It was
  expected to be `timing_config` for the config used by Krill and
  `ta_timing` if used by the Krill TA signer. It is now `ta_timing` in
  both cases while `timing_config` is accepted as an alias in both cases.
  ([#1241])

Other changes

* Refactored Prometheus metrics generation which resulted in a slightly
  different formatting but should still be syntactically correct.
  ([#1249])
* Added packaging support for Ubuntu Noble; removed packaging support for
  Ubuntu Xenial and Bionic, and Debian Stretch. ([#1239])
* The minimum supported Rust version is now 1.85. ([#1288])

[#1215]: https://github.com/NLnetLabs/krill/pull/1215
[#1226]: https://github.com/NLnetLabs/krill/pull/1226
[#1228]: https://github.com/NLnetLabs/krill/pull/1228
[#1232]: https://github.com/NLnetLabs/krill/pull/1232
[#1233]: https://github.com/NLnetLabs/krill/pull/1233
[#1239]: https://github.com/NLnetLabs/krill/pull/1239
[#1241]: https://github.com/NLnetLabs/krill/pull/1241
[#1249]: https://github.com/NLnetLabs/krill/pull/1249
[#1255]: https://github.com/NLnetLabs/krill/pull/1255
[#1266]: https://github.com/NLnetLabs/krill/pull/1266
[#1281]: https://github.com/NLnetLabs/krill/pull/1281
[#1288]: https://github.com/NLnetLabs/krill/pull/1288


## 0.14.6 ‘Roll Initiative!’

Released 2025-04-08.

There were no changes since 0.14.6-rc1.


## 0.14.6-rc1

Released 2025-03-26.

Bug fixes

* Fixed the naming of the trust anchor timing configuration. It was
  expected to be `timing_config` for the config used by Krill and
  `ta_timing` if used by the Krill TA signer. It is now `ta_timing` in
  both cases while `timing_config` is accepted as an alias in both cases.
  ([#1242])

Other changes

* The minimum supported Rust version is now 1.81. ([#1260])

[#1242]: https://github.com/NLnetLabs/krill/pull/1242
[#1260]: https://github.com/NLnetLabs/krill/pull/1260


## 0.14.5 ‘Who dis? New Phone’

Released 2024-06-27.

There were no changes since 0.14.5-rc1.


## 0.14.5-rc1

Released 2024-06-21.

New

* Allow overriding the initial manifest number when initializing the TA
  signer, either by specifying `--initial_manifest_number` in the CLI or by
  including `ta_mft_nr_override: #nr` in the `ImportTa` JSON. ([#1178])
* Allow overriding the TA manifest number when signing a TA proxy request by
  specifying `--ta_mft_number_override` in the CLI. ([#1178])

Bug fixes

* Prevent empty RRDP delta lists to be produced. ([#1181])
* Correctly encode empty revocation lists in CRLs. (via [rpki-rs#295])
* Allow read access to the RIS dump while downloading a new dump.
  ([#1179])
* Don’t apply “child revoke key” command if the resource class does not
  exist. ([#1208])

Other changes

* The minimum supported Rust version is now 1.70.0. ([#1198])

[#1178]: https://github.com/NLnetLabs/krill/pull/1178
[#1179]: https://github.com/NLnetLabs/krill/pull/1179
[#1181]: https://github.com/NLnetLabs/krill/pull/1181
[#1198]: https://github.com/NLnetLabs/krill/pull/1198
[#1208]: https://github.com/NLnetLabs/krill/pull/1208
[rpki-rs#295]: https://github.com/NLnetLabs/rpki-rs/pull/295


## 0.14.4 'A Flock of Krill'

This release fixes the following issues:

- Krill should not freeze if lockfiles were not deleted properly #1171 (since Krill 0.14.0)
- Don't warn about yanked dependencies when installing Krill via Cargo #1173

## 0.14.3 'Temp'

This release fixes a number of issues found in 0.14.0 through 0.14.2:

- Use rpki-rs 0.18.0 to support builds on more platforms #1166
- Fix aspa migration issues #1163
- Depend on kvx 0.9.2 to ensure temp files are used properly #1160

Most importantly, Krill will now use temp files for *all* data that it
stores to avoid issues with half-written files in case the disk is full,
or the server is rebooted in the middle of writing. This issue was introduced
in release 0.14.0, and we recommend that all users upgrade to this version
to avoid issues.

This release also includes:
- Updated German UI translations krill-ui/#51

## 0.14.2 'Extra, Extra, Extra!'

This release fixes an additional corner case in the migration code that affects
certain installations that archived 'surplus' commands (issue: #1147). There is
no need to upgrade to this version if you already upgraded to 0.14.0 or 0.14.1.

## 0.14.1 'Extra, Extra!'

This release fixes a bug in the migration code that affects certain installations
that archived 'surplus' data (issue: #1147). There is no need to upgrade to
this version if you already upgraded to 0.14.0.

## 0.14.0 'ASPA'

This release adds support for the updated ASPA v1 profile (issue #1080).
Any existing ASPA objects will be re-issued automatically.

In addition, the following small features and fixes were done:
- Show delete ROA button when no BGP preview is available #1139
- Add traditional and simplified Chinese translations #1075
- Let the testbed automatically renew the TA manifest and CRL #1095 (see below)
- Show the delete icon for AS0 ROA when there is another existing announcement #1109

The main effort in this release was spent on less user-visible
improvements in the way that Krill stores its data. This will
help to improve robustness today, and it paves the way for introducing
support for Krill clustering using a database back-end in a future release.

For now, these issues have been done:
- Improve transactionality of changes (e.g. #1076-1078, #1085, #1108, #1090)
- Remove no longer needed 'always_recover_data' function #1086 
- Improve upgrade failed error: tell users to downgrade #1042
- Crash Krill if the task scheduler encounters a fatal error. #1132

You can find the full list of issues here:
https://github.com/NLnetLabs/krill/projects/25

Finally, regarding issue #1095. If you were running 0.13.1 as a testbed, you
may have symlinked the "signer" directory to "ta_signer" to support a manual
workaround for re-signing the trust anchor CRL and manifest. If you did, you
may need to delete any surplus files and directories under "data/ta_signer"
other than the directory called "ta".


## 0.13.2-rc1

Released 2024-06-21.

Bug fixes

* Updated the locked version of the h2 crate to 0.3.26 to fix
  [RUSTSEC-2024-0332]. ([#1206])
* Don’t apply “child revoke key” command if the resource class does not
  exist. ([#1207])

[#1206]: https://github.com/NLnetLabs/krill/pull/1206
[#1207]: https://github.com/NLnetLabs/krill/pull/1207
[RUSTSEC-2024-0332]: https://rustsec.org/advisories/RUSTSEC-2024-0332

## 0.13.1 'Scrollbars!'

The Krill UI includes a CA selection dropdown in case you have multiple CAs.
This dropdown used to have a scrollbar, which accidentally got lost in the
UI overhaul we did in version 0.13.0. This is now fixed (#1071)


## 0.13.0 'DRY'

### Summary

This release contains an important fix for an issue affecting v0.12.x Publication
Servers (see PR #1023). It is recommended that affected installations are upgraded
as soon as possible.

The user interface was completely re-implemented in this release resulting in
a smaller browser footprint. Functionality is mostly unchanged, except that users
can now have an optional comment with each of their ROA configurations. These
comments are not part of published ROA objects - they are meant for local bookkeeping
only.

ASPA objects are now supported through the CLI by default. We hope to add UI support
later this year.

Krill can now be used as a full RPKI Trust Anchor, using a detached (possibly offline)
signer for Trust Anchor key operations.

### Publication Server

Krill 0.12.x Publication servers suffer from an issue where multiple entries
for the same URI, but with different hashes can appear in a single RRDP snapshot.

This problem was solved by removing published objects data duplication in the
Krill architecture and ensuring that the URI rather than an object's hash is
used as its primary key internally. More information can be found in pull
request #1023.

We recommend that existing 0.12.x Publication Server installations are upgraded
to this version.

### Updated User Interface

A lot of changes were introduced in this release. For most users the following
improvements will be most visible and relevant:
- Updated UI to new and smaller code base (#995)
- Allow ROA comments in UI (#995)

The new krill-ui project has its own repository where issues can be tracked:
https://github.com/NLnetLabs/krill-ui

### ASPA Support

ASPA support is now enabled in the CLI (#1031). We hope to add UI support
later this year.

We added a number of new restrictions 
- Krill MUST NOT create only a single AFI ASPA (#1063)
- ASPA object MUST NOT allow the customer AS in the provider AS list (#1058)

You can read more about ASPA support here:
https://krill.docs.nlnetlabs.nl/en/0.13.0/manage-aspas.html

### API Changes

We removed the repository next update time from the stats and metrics output.
It was inaccurate (usually 8 hours off), and not very informative. More useful
metrics are still provided: last exchange and last successful exchange. If these
times differ, then there is an issue that may need attention.

### Krill as a Trust Anchor

A lot of work has been done to support using Krill as a Trust Anchor. If you
are not an RIR, then you will not need to run your own RPKI TA for normal
RPKI operations. That said, some users may want to operate their own TA outside
of the TAs provided by the RIRs for testing, study or research reasons. Or
perhaps even to manage private use address space.

You can read more about this here:
https://krill.docs.nlnetlabs.nl/en/0.13.0-rc1/trust-anchor.html

Implemented issues:
- Support offline TA (#976)
- Support initialising offline TA with existing key (#979)
- Bulk import/configure CAs with ROAs (#968, #969) 
- Support migration of existing TAs (#978)
- Use new TA for embedded (test) TA (#977)

### Other Changes

Publication Server Improvements:
- Remove published object data duplication (#1023)
- Delete repository files by URI (#991)

Miscellaneous improvements and fixes:
- Log for which child / parent / publisher CMS validation failed (#1027)
- Permit setting CKA_PRIVATE to CK_FALSE on PKCS#11 RSA public keys (#1019)
- Ensure that the CSR uses a trailing slash for id-ad-caRepository (#1030)
- Accept id-cert with path len constraints (#966)
- Publication Server should check uri, not hash, in publish elements (#981)

The overview of all issues for this release can be found here:
https://github.com/NLnetLabs/krill/projects/24


## 0.12.3 'Sakura'

This release contains a feature that enables Publication Server operators to
remove unwanted, surplus, files from their repository. This feature was cherry
picked from the upcoming major release branch so that Publication Server
operators can use this without delay.

Note that if you do not use Krill to operate a Publication Server, then there
is no need to upgrade to this version now.

For more details see: https://github.com/NLnetLabs/krill/pull/1022

## 0.12.2 'Dijkstra'

This release fixes a locking issue that can affect a Krill Publication Server
with a large number of concurrent publishers. See PR #1007.

If you only use Krill as an RPKI Certificate Authority and publish elsewhere,
e.g. in an RPKI Publication Server provided by your RIR or NIR, then there is
no need to update to this release.

## 0.12.1 'Safety Belts'

This release introduces two fixes for the Krill Publication Server. If you
only use Krill as an RPKI Certificate Authority and publish elsewhere, e.g.
in an RPKI Publication Server provided by your RIR or NIR, then there is no
need to update to this release.

Firstly, this release fixes CVE-2023-0158:
https://nlnetlabs.nl/downloads/krill/CVE-2023-0158.txt

This CVE describes an exposure where remote attackers could cause Krill to
crash if it is used as an RPKI Publication Server and if its "/rrdp" endpoint
is accessible over the public internet.

Note that servers are not affected if the advice in our documentation was followed
and a separate web server is used to serve the RRDP data:

https://krill.docs.nlnetlabs.nl/en/stable/publication-server.html#synchronise-repository-data

Secondly, locking was added in this release to ensure that updates to the
repository content are always applied sequentially. This fixes a concurrency
issue introduced in Krill 0.12.0 that could result in rejecting an update
from a publishing CA. In such cases the affected update would not be visible
for RPKI validators, until a later publication attempt would be successful.

We advise that users upgrade to this version of Krill if they use it as their
RPKI Publication Server. We also continue to recommend that a separate web
server is used for serving the RRDP data.

## 0.12.0 'Crickets'

This release vastly reduces the CPU usage by Publication Servers for big RPKI
repositories.

In addition to this we added a small feature, and fixed an interop issue:
- Listen on IPv4+IPv6 #955
- Fix rfc6492 interop (AKI format) #948

Upgrade instructions this release are here:
https://krill.docs.nlnetlabs.nl/en/stable/upgrade.html#v0-12-0

The overview of all issues for this release can be found here:
https://github.com/NLnetLabs/krill/projects/23

Full documentation can be found here:
https://krill.docs.nlnetlabs.nl/

## 0.11.0 'What about that ROA?'

In this release we introduce two features in the Krill API and CLI:
- Support optional comment for each ROA configuration #863
- Show ROA object(s) for each ROA configuration #864

This is not yet supported in the UI, but will be in the near future as the
current UI will get a make-over soon.

Other than this we included a few minor issues and fixes:
- Query initialisation parameters for Krill pubserver (rrdp/rsync URI) #835
- Tasks for removed CAs should not result in errors #906
- Disallow negative numbers in config #808

Documentation can be found here:
https://krill.docs.nlnetlabs.nl/en/stable/

And here:
https://krill.docs.nlnetlabs.nl/en/stable/upgrade.html#v0-11-0

## 0.10.3 'Down Under'

This release fixes an interoperability issue with the APNIC CA system which
didn't occur in the public test environment. See issue #933.

## 0.10.2 'All Types'

This release fixes an issue where Krill 0.10.0 and 0.10.1 parent CAs would issue
an RFC 6492 Resource Class List Response with a missing, rather than empty,
attribute for resource types that a child CA had no entitlements for. See
issue #925.

Note this issue did not impact CAs that have no delegated child CAs. Futhermore,
it would result in the child CA rejecting the parent response, log an error, and
try synchronising again, but it would not result in any changes to the CA certificate
issued by the parent to the child.

Furthermore, this release fixes an issue where the data for a Publication Server
(if configured) would not be migrated if the previous Krill version was 0.9.0.
See issue #928.

## 0.10.1 'Slash'

Krill 0.10.0, or rather rpki-rs 0.15.4 became quite strict in its validation of
the RFC 8183 XML files used when setting up a CA. As a result Krill 0.10.0 rejected
the XML generated by earlier versions because the trailing slash in the XML namespace
was missing.

Because the namespace is not critical in this context, this new Krill release will
no longer reject the XML files because of this missing trailing slash.

## 0.10.0 'Hush'

In this release we introduce the following major features:
- BGPSec Router Certificate Signing
- Support the use of Hardware Security Modules (HSMs) for key operations

The documentation has more information:

| Subject   | Section                                                        |
|-----------|----------------------------------------------------------------|
|API changes|https://krill.docs.nlnetlabs.nl/en/stable/upgrade.html#v0-10-0  |
|BGPSec     |https://krill.docs.nlnetlabs.nl/en/stable/cli.html#krillc-bgpsec|
|HSM support|https://krill.docs.nlnetlabs.nl/en/stable/hsm.html              |

Besides these major features we added a number of small improvements
and bugfixes:
- CRL revocation dates in the future #788
- Prevent that two krill instances modify the same data #829
- Let user force RRDP session reset on restore #828
- Various code improvements aimed at maintainability
- Using a jitter of 0 results in a panic #859
- Security fixes in KMIP dependencies #860 (HSM support)
- Add SSLKEYLOGFILE support #615
- Allow explicit disabling of HTTPS #913

The full list of changes can be found here:
https://github.com/NLnetLabs/krill/projects/19

## 0.9.6 'Newer ROAs Please'

This release fixes an issue introduced in 0.9.5 where the background job to
automatically renew ROAs was not added to Krill's task queue on startup. Thanks
to Alberto Leiva for finding this issue!

All users who upgraded to 0.9.5 are advised to upgrade to this version as soon
as possible. Not doing so can lead to ROAs expiring and becoming invalid. If you
did not upgrade to 0.9.5 you are not affected by this issue.

This release contains no other changes.

## 0.9.5 'Have You considered these Upgrades?'

This release is primarily intended to improve support for migrations of pre-0.9.0
installations. The upgrade code has been separated more cleanly into a step where
the new 0.9.0 data structures are prepared in a new directory first, and a second
step where this new data is made active and the old data is archived. Earlier versions
of krill were performing data migrations in-place.

If you simply upgrade krill and restart it, then it will automatically execute both
steps. If the preparation step should fail, then the original data remains unchanged.
You can then downgrade back to your previous krill version. This is in itself is
an improvement over 0.9.4 and earlier, because for those versions you would have
to make a back-up of your data first, and restore it in order to revert your upgrade.

Furthermore, we have now added a new command line tool called 'krillup', which can
be installed and upgraded separately to krill itself. This new tool can be used
to execute the krill migration *preparation* step only. Meaning, you can install
this tool on your server and do all the preparations, and only then upgrade krill.

This has the following advantages:
- The downtime for data migrations is reduced for servers with lots of data
- If the preparation fails, there is no need to revert a krill update

In addition to this we have also made some changes to the CA parent refresh logic.
Krill CAs were checking their entitlements with their parents every 10 minutes,
and this causes too much load on parent CAs with many children. There should be
no need to check this often. CAs will now check every 24 to 36 hours, using a
random spread. This will decrease the load on parent CAs significantly.

Note that you can always force a 'parent refresh' sooner through the UI or command
line (krillc bulk refresh). You may want to use this if your parent informs you
through other channels that your resources have changed - e.g. you were allocated
a new prefix.

Secondly, because the next synchronisation time is now difficult to predict in the
code that reports the parent status - it is now no longer shown in the UI/API.
We may add this back in a future release. See issue #807.

You can read more about this upgrade process here:
https://krill.docs.nlnetlabs.nl/en/latest/upgrade.html

In addition to this we added a few other quick fixes in this release:
- Make RRDP session reset manual option #793
- Improve http connection error reporting #776
- Fix deserialization bug for CAs with children #774
- Connect to local parent directly #791
- Do not sign/validate RFC6492 messages to/from local parent #797
- Use per CA locking for CA statuses #795
- Decrease CA update frequency and use jitter to spread load #802
- Accept missing tag in RFC8181 Error Response #809
- Improve efficiency of connection status tracking #811
- Do not resync CAs with repo on startup if there are too many #818

The full list of changes can be found here:
https://github.com/NLnetLabs/krill/projects/20

## 0.9.4 'One shall be the number thou shalt count from'

This release includes the following:
- RRDP serial should start from 1, not 0 (#741)
- Allow configuring RFC6492/8181 client timeouts (#743)

The first addresses a non-critical bug found when running Krill as a Publication
Server. The second addresses an issue seen in Krill 0.7.3 running with 100s of
CAs in a single Krill instance - timeouts have not been seen in Krill 0.9.x - but
it does not hurt to give operators control over this configuration.

If you are using Krill for RPKI CA functions only, and you have already
upgraded to version 0.9.3 then there is no immediate need to upgrade to this
version. If you are running a version from before 0.9.3, then you are still
advised to upgrade to this version for the reasons list under version 0.9.3.

## 0.9.3 'The Thundering Herd'

This release adds the following features and fixes:
- Prevent a thundering herd of hosted CAs publishing at the same time (#692) 
- Re-issue ROAs to ensure that short EE subject names are used (#700)
- Handle rate limits when updating parents (#680)
- Support experimental ASPA objects through CLI (#685)

Note that ASPA objects are not intended for use in production environments just yet.
We have added experimental support for this to support the development of the ASPA
standards in the IETF. Information on how to use Krill to manage ASPA objects can
be found here:
https://krill.docs.nlnetlabs.nl/en/prototype-aspa-support/manage-aspas.html

The full list of changes can be found here:
https://github.com/NLnetLabs/krill/projects/18

## 0.9.2 'Motive and Opportunity'

This release includes two features aimed at users who run a Krill CA to maintain ROAs:
- Warn about ROA configurations for resources no longer held #602
- Re-enable migration of CA content to a new Publication Server #480

In addition to this we have added a lot of smaller improvements:
- Synchronize the manifest EE lifetime and next update time #589
- Improve error reporting on I/O errors #587
- Add rsync URI to testbed TAL #624
- Improve status reporting and monitoring #651, #650, #648

The following features were added to support users who operate Krill as a parent
CA, or Publication Server:
- Optionally suspend inactive child CAs using krill 0.9.2 and up #670
- Perform RRDP session reset on restart #533
- Use unguessable URIs for RRDP deltas and snapshots #515

The updated documentation for this release can be found here:
https://krill.docs.nlnetlabs.nl/en/0.9.2/index.html

The full list of changes can be found here:
https://github.com/NLnetLabs/krill/projects/16

## 0.9.1 'All for One'

This release fixes an issue where the Publication Server would lock up (#606). Users who do
not use Krill to operate their own Publication Server do not need to upgrade to this release.

This locking issue was cause by slow deserialisation of the repository content. It primarily
affected large repositories because more content makes this process slower, and having more
publishers who publish regularly means it is triggered more frequently.

## 0.9.0 'One for All'

This is the first major release of Krill in a while.

While basic ROA management is unchanged, there were many changes under the hood:

- Multi-user support in the User Interface (local users or OpenID Connect)
- Reduce disk space usage and growth over time
- API and naming consistency (in preparation for 1.0 in future)
- Publication Server improvements (to whom it may concern)
- Many small improvements and minor bug fixes

For a full list of issues that were included in this release see:
https://github.com/NLnetLabs/krill/projects/4

Updated documentation is available here:
https://krill.docs.nlnetlabs.nl/en/stable/index.html

With multi-user support you can now give people in your organization individual access rights to
your CA - and they no longer need to share a password. If you have an OpenID Connect provider then
you can integrate Krill with it. Read more here:
https://krill.docs.nlnetlabs.nl/en/stable/multi-user.html

Krill versions before 0.9.0 keep a lot of data around that is not strictly needed. This can clog up
your system *and* it makes the Krill history difficult to parse. History can seen using `krillc history`.
We will include support for inspecting history in the UI soon.

There were some API and CLI changes introduced in this release. Over time things had become a bit
inconsistent and we felt we needed to fix that before we can consider going for the Krill 1.0 release.
If you are using automation then these changes may break your current integrations. Please have a
look at the following page to see if and how this affects you:
https://krill.docs.nlnetlabs.nl/en/stable/upgrade.html

Note that your Krill data store will be upgraded automatically if you upgrade to this release. This
upgrade can take some time, up to around 30 minutes dependent on the amount of history which accumulated
over time and the speed of your system. During the migration you will not be able to update your ROAs,
but your existing ROAs will remain available to RPKI validators. I.e. there is no downtime expected
with regards to RPKI validation.

We have tested this on various (big) Krill instances running CAs as well as Publication Servers. Still,
we recommend that you make a backup of your data store before upgrading. In case the upgrade should
unexpectedly fail for you, please restore your old data, run the previous binary, and contact us so
that we can make a fix. Alternatively, copy your data except for the `keys` directory to a test system
and then use the new Krill binary there with the following env variable set so you can test the data
migration:

   KRILL_UPGRADE_ONLY=1

Finally, note that you need to run at least Krill 0.6.0 in order to upgrade. If you run an older version
you will need to upgrade to version 0.8.2 first.

## 0.8.2 'Can't touch this'

As it turned out the previous release (0.8.1) still insisted on cleaning up 'redundant ROAs'
when migrating to that version. This clean-up would not cause any issues with regards to the
validity of your announcements. However, we realized in 0.8.1 that users should be the once
to decide whether they want to have extra ROAs or not. Therefore this clean-up should have
been removed then.

This release removes this clean-up and introduces no other changes. We recommend that users
who did not upgrade already upgrade to this release. However, if you already successfully 
upgraded to 0.8.1, then upgrading to this release is not needed.

## 0.8.1 'The Gentle Art' 

The ROA guidance introduced in release 0.8.0 was more strict than it should be. This release
allows users to create redundant ROAs once again, while providing guidance in the form of warnings
and suggestions only. Full documentation on the Krill suggestions have been added to the
[online documentation](https://rpki.readthedocs.io/en/latest/krill/manage-roas.html).

In addition to this we have included some small improvements for the Krill Publication
Server.

## 0.8.0 'The Art of ROA Maintenance'

This release includes all changes from the -rc1 and -rc2 release candidates. In addition to this
the main UI (everything except the testbed pages) now includes Spanish translations.

In summary this upgrade is recommended to all Krill users. It offers improved ROA guidance support
in the UI, better status reporting on interactions between your CA and its parent and repository,
and a number of improvements aimed at improving resiliency.

Furthermore, we would like to draw attention once more to our [testbed](https://blog.nlnetlabs.nl/testing----123-delegated-rpki/) 
which allows new users to get familiar with Krill, and existing users to try out new functionality
before upgrading.

## 0.8.0-rc2 'The Small Print'

Because of some changes we decided to have another RC release before 0.8.0, which is now planned
for Monday 26 October 2020.

The reason for these changes is that while documenting the 0.8.0 release we decided that we would
like to include two more small features:
- Detect and remove surplus events at start-up #332
- Add option to force recover on Krill startup #333

Issue #332 will allow Krill to recover smoothly in case the Krill process stopped in the middle
of writing changes to disk. This also allows for backup strategies where the data directory is saved
in its entirety from cron while Krill is running - half completed transactions will be discarded on
restore.

Issue #333 should not be needed, but is added as an option in case of severe data corruption. It
will force Krill to try to go back to its last 'recoverable' state. Of course this state may be too
far in the past to be useful. So, please make sure you do your backups.

We have now added the updated translations for: German, Dutch, Portuguese and French. That only
leaves Spanish out of the currently supported languages. Since these changes do not change the logic
we feel safe to include Spanish when we release 0.8.0 without the need for an additional release
candidate.


## 0.8.0-rc1 'Festina Lente'

As of now we will use release candidates as part of the Krill release process. If no major issues
are found we plan to do the real 0.8.0 release on Monday 19 October 2020.

This new release brings a number of internal improvements, as well as new features.

#### New or updated features:

- added detailed ROA suggestions
- warn about ROAs which are too permissive
- support AS0 ROAs (see below!)
- allow aggregation of ROAs to lower the number of objects
- allow archiving old data in order to save space
- added a best effort recovery in case data on disk is incomplete (e.g. resulting from a full disk)
- better reporting on communication with parents and repository
- re-sync with parents and repository on start-up
- crash in case data cannot be written to disk (prevent inconsistent states)

We want to invite users to test this new version and give us feedback, in particular with regards
to ROA suggestions, and so-called AS0 ROAs:
 
ROAs that use AS0 can be used in the RPKI to indicate that the holder of a prefix does NOT want
the prefix to be routed on the global internet. In our understanding this precludes that ROAs for
a real ASN for those resources should be made. Krill will therefore refuse to make AS0 ROAs for
prefixes already covered by a real ASN ROA, and vice versa. Furthermore the presence of an AS0
ROA implies that announcements for covered prefixes are intentionally RPKI invalid. Therefore
Krill will not suggest to authorize such announcements.

#### Open issues before 0.8.0:

The UI still needs translations for the updated pages. We will reach out to our translators and
include these in the release. Since text changes will not affect the inner workings of Krill we
believe we can do these changes without the need for an additional release candidate cycle. If you
want to contribute to the translations please contact us!  


## 0.7.4 'Multipass!'

There is no need to upgrade to this version. It was created only so that you can continue
to compile Krill locally using the latest Rust compiler.

As it turns out the use of many asynchronous calls, the cool stuff which make Krill thread safe,
cause the compiler to do quite a bit of work in a process called 'Monomorphization'. The latest
compiler version will go on strike as a result, unless we instruct it beforehand that more work
is coming its way.

## 0.7.3 'Slow Food'

This release fixes an issue where the BGP Ris Dump files were reloaded and checked too
frequently causing high CPU and bandwidth usage.

## 0.7.2 'Small Bites'

This release fixes an issue where BGP RIS Dump files that were not properly retrieved would
cause a thread to choke. As this can lead to lock poisoning this type of event could cause
other Krill processes to stop functioning properly. All users of Krill 0.7.0 and 0.7.1 are
advised to upgrade.

In addition to this German translations have been added to the UI.

## 0.7.1 'Sobremesa'

This release fixes the ROA migration introduced in 0.7.0. We identified an issue where the
clean up of ROAs would fail because Krill tried adding explicit forms of ROAs - with max
length set - before removing the implicit definitions.

## 0.7.0 'Escondidinho de Lagosta'

This release brings significant improvements aimed at maintaining your ROAs. For now, Krill
will download aggregated BGP dumps from the RIPE NCC Routing Information Service (*) and
analyse how your ROAs affect announcements seen for your resources. In future we will extend
this system, so that it can use near-real-time data, or even a local feed with your own BGP
information instead. 

For these changes to work well we needed to do some work on cleaning up existing ROAs. Until
now Krill has allowed the creation of essentially duplicate, or nonsensical ROAs, such as:
* ROAs for an ASN and prefix with and without an explicit max length matching the prefix 
* ROAs for a prefix and ASN which were already permitted by another ROA.  

On upgrade Krill will clean up such redundant authorizations for ROAs. For example if the
following authorizations would exist:

 192.168.0.0/16      => 64496
 192.168.0.0/24      => 64496
 192.168.0.0/16-24   => 64496
 
Then only this last authorization needs to be kept, the first two are also covered by it.

Before this release it was also possible to have the same authorization with, and without, using
an explicit max length. For example:

 192.168.0.0/16      => 64496
 192.168.0.0/16-16   => 64496

Now Krill will *always* use an explicit max length in the definitions. Note however, that it is
still best practice to use the same max length as the announced prefix length, so Krill will just
set this by default if it is not specified.

*: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris

## 0.6.3 'Play it again, Sam'

This release addresses an issue where users with a CA that has delegated children, which in turn
had performed a key roll over in the past, could not upgrade to Release 0.6.2.

Users who already successfully upgraded to Release 0.6.2 do not need to upgrade urgently. This
release includes a number of fixes for minor issues, which will also be included in the 0.7.0
Release which is due in 2-4 weeks:
* `krillc issues` fails with `Error: Unknown API method` (#248)
* `krillc parents` help text refers incorrectly to publisher request instead of child request (#251)
* Normalize request/response `krillc help` texts (#252)
* `krillc` incorrectly reports XML as a supported output format (#253)
* Inconsistent use of "cas" in `krillc bulk` subcommand summary text (#254)
* Be consistent when referring to ending with a / (#255)

## 0.6.2 'That was even faster!'

So, as it turns out.. the code used to determine the age of snapshot files used in the previous
release was not safe on all platforms. This release fixes this!

Users who upgraded to 0.6.1 and see messages like: "Creation time is not available on this
platform currently" in their logs, please upgrade!

## 0.6.1 'That was fast!'

This release fixes an issue where the Krill Repository Server deleted RRDP snapshot files as soon
as a new notification file was published. This leads to issues in case a cached notification file
is served to validators. 

Users who use Krill as their own Repository Server are advised to upgrade.

Users who publish at a repository provided to them by a third party (e.g. nic.br) can safely skip
this release.  

## 0.6.0 'Go with the Flow'

The most visible change in this release is that the embedded Lagosta UI now includes French, Greek
and Spanish translations. But, the vast majority of the work went into making Krill use asynchronous
code.

We migrated from actix-web to Hyper. Hyper is a fast, safe and fully asynchronous web framework
which has a lot of momentum behind it. This change also meant that we needed to ensure that
Krill itself uses safe asynchronous code whenever it connects to a remote system, like a parent
or repository, or in case of the CLI the Krill API itself.

In addition to this we improved the history API to ensure that Krill will no longer use an
excessive amount of history in cases where a CA has a long history. The API is still subject to
change, and therefore we will only document this in future. In the meantime however, the CLI
may be used to show the history of your CA.

Lagosta:
* Now includes French, Greek and Spanish translations
* Minor improvements in functionality

Krill back-end:
* Migrated from actix-web to hyper.
* Krill now uses asynchronous code where applicable.
* Krill CA history improved. (prevent server crash due to excessive memory usage) 

Breaking changes:
* The API end-points for bulk operations changed to /api/v1/bulk/*
* The API end-point for CA issues moved to /api/v1/cas/{handle}/issues
* The history API changed, this is not yet stable and therefore undocumented

## 0.5.0 'Serve no Turf'

The most striking change in this release is the inclusion of a new front-end: Lagosta.

Lagosta 0.1 'Fritto Misto' supports the following features:
* Set up your Krill CA under an RIR/NIR parent
* Configure your CA to publish at a remote repository
* Maintain ROAs
* Internationalization (English and Portuguese)

Please talk to us if you want to contribute other languages! Many advanced features are currently available in the CLI only, but we will continue to extend the front-end functionality.
 
On a technical note: the front-end is based on static HTML/CSS and JS (Vue) which is served as static files to your browser by Krill. This front-end application then uses the same API back-end as the CLI. 

The following features and improvements were introduced to the core Krill and CLI:
* Added option to CLI to generate a Krill config file.
* Added check for reporting status between CAs and their parents and repository
* Added simple Prometheus endpoint (/metrics)
* Disable the embedded repository by default (see docs for info)
* Added guards against using 'localhost' in non-test environments 

Breaking changes:
* The error responses have been overhauled.
* Some CLI options have been changed to make naming and behavior more consistent.

For more information please have a look at [Read the Docs](https://rpki.readthedocs.io/en/latest/krill/index.html).

We wish to thank Cynthia Revström for the great help she provided in ironing out some issues we found when setting up Krill under ARIN.

## 0.4.2 'Finer Things'

This release fixes a bug, and introduces minor usability improvements:
* Certain adjacent resources were encoded incorrectly (#161)
* Let users explicitly specify a repository before adding a parent (#160)
* Allow timezone to be set on the Docker container (#156)
* Improve error messaging when failing to start Krill (#155)
* Improve readability for CLI error responses (#162)
* Introduce configurable size limits for data submitted to Krill (#158)

Note that contrary to previous versions a new CA is set up without a default repository. For most
users we recommend that a remote (RFC 8181) repository is used, e.g. provided by their RIR or NIR.
A repository MUST be configured before a parent can be added to a CA.

## 0.4.1 'Fogo de Krill'

This release fixes two issues:
* Certain resource sets were handled incorrectly (#152)
* Krill should not allow impossible max length values for ROAs (#153)

We recommend that all users upgrade to this release. There were no configuration or data model
changes introduced, so the binary can just be used to replace any installed 0.4.0 release.  

## 0.4.0 'The Krill Factor'

This release focuses on stabilizing the API and internal data format, which allows upgrades to 
future versions of Krill without the need for complicated data migrations. We do not expect to
introduce breaking changes to the API from this point forward. Please note however, that in some
cases the JSON structure in API responses might be extended with additional information in new
JSON members.

Overview of changes:
* Document the Krill server API using OpenAPI 3 (#148)
* Stabilize JSON API (#141)
* Better API response when a method does not exist (#146)
* Support upgrading, preserving data (#53)
* Set up automated end-to-end testing (TA-CA-ROAs-validation) (#66)
* Add config option allowing to serve RRDP from a different host (#147)
* Let Krill log to syslog (#121)
* Audit commands and errors (#142)
* Log all RFC 8181 and 6492 protocol messages (#143)


## 0.3.0 'The Krilling is on the wall'

This release focused on remote publication.

You can now use Krill as an RFC8181 compliant Repository Server. If you want to use it as a dedicated
repository server only, you can simply do this by not configuring any CAs in that particular instance.

You can now also update your CAs to use a remote RFC8181 Repository Server. This is particularly
useful if you want to outsource the responsibility of 24/7 availability of your RPKI repository
to a third party.   

We have also made some breaking changes to the API. So, you may have to look again at any
automation you may have set previously up for release 0.2.0.

Updated documentation can be found on [Read the Docs](https://rpki.readthedocs.io/en/latest/krill/index.html).

Two of the known issues listed under release 0.2.0 have been solved:
 * CAs now do full re-syncs when publishing (solves #116)
 * RIPE NCC RPKI Validator 3.1 now validates our objects (solves #115) 

The next release of Krill is aimed for early December and will focus fully on stability, and the
other known issues listed under release 0.2.0. But, note that there may still be small API changes
in the coming release, as we are still optimizing things.

## 0.2.0 'Interkrillactic, Planetary'

This release focused on testing, and fixing, any issues found when running Krill under various
parent CAs (Apnic, Lacnic and RIPE NCC). ROAs were tested using routinator, OctoRPKI, FORT, RIPE
NCC RPKI Validator 2.x and 3.x.

Furthermore, the CLI got a big overhaul aimed at making it easier to use, especially for users
who manage one CA only. You can now use ENV variables to set defaults for the Krill instance to
connect to, the token, and which CA you want to operate on.

We also added the '--api' argument which will simply print out the API call that the CLI would
have made, without executing it. We plan to add proper (OpenAPI) documentation for the API, but
for the moment this can help to explore it.

Updated documentation can be found on [Read the Docs](https://rpki.readthedocs.io/en/latest/krill/index.html).

Known issues:
* Despite our best efforts RIPE NCC RPKI Validator 3.1 is the only remaining RP we tested, which
  does not seem to like our manifests. We will look into this again later. (#115)
* There appears to be a race condition that can cause commands to be processed twice. (#64)
* Showing the full history, or logging it in case of the above condition, uses too much memory. (#112)
* The CA and publication server can be out of sync after a re-start. (#116)

Work for the next release has already started. [Release 0.3](https://github.com/NLnetLabs/krill/projects/6)
will focus on (remote) publication, and will also solve the out-of-sync issue.

## 0.1.0 'A View to a Krill'

This is the first version of Krill that we are testing in the real world. Please note that the
API and data structures have not yet stabilized. 

Features:
* Run an embedded Trust Anchor for testing purposes
* Run a CA under an embedded Trust Anchor
* Run a CA under APNIC (Lacnic, RIPE NCC and other remote parents coming soon)
* Have multiple parent CAs for one logical CA
* Have multiple child CAs, embedded or remote
* Create ROAs based on intent
* Publish locally
* API and CLI

Known issues:
* Krill does not handle concurrent updates well. See this [issue](https://github.com/NLnetLabs/krill/issues/64).
* The UI is very basic and behind the CLI.
