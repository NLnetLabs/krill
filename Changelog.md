# Change Log

## 0.9.3 (RC3) 'The Thundering Herd'

RC3 fixes the following issues in RC2:
- Use the, now official, ASPA OID (#700)
- Re-issue ASPA objects on key rolls (717)

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

#### Public Krill Testbed Service

With this release we have also started to operate a Krill testbed service. The testbed offers both
a parent CA and Repository. As such you can just run a Krill instance, on a laptop even, without
the need to operate real infrastructure for testing.
 
It allows you to register any resources for your Child CA, allowing you to test with your real
resources. Because this testbed uses its own TEST Trust Anchor - ROAs created here will not end
up being used by real routers. 

You can find the test service here:
https://testbed.rpki.nlnetlabs.nl/

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
