# Change Log

Please see [here](https://github.com/NLnetLabs/krill/projects?query=is%3Aopen+sort%3Aname-asc)
for planned releases.

## 0.7.5 'Time's Up'

This release is not intended for public use, please upgrade to the latest version - which is
Krill 0.9.3 'Thundering Herd' - if you can. We introduced this version as a quick fix to
deal with http client timeouts for publishing CAs.

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

Lagosta 0.1 'Fritto misto' supports the following features:
* Set up your Krill CA under an RIR/NIR parent
* Configure your CA to publish at a remote repository
* Maintain ROAs
* Internationalisation (English and Portuguese)

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
* Some CLI options have been changed to make naming and behaviour more consistent.

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

This release focuses on stabilising the API and internal data format, which allows upgrades to 
future versions of Krill without the need for complicated data migrations. We do not expect to
introduce breaking changes to the API from this point forward. Please note however, that in some
cases the JSON structure in API responses might be extended with additional information in new
JSON members.

Overview of changes:
* Document the Krill server API using OpenAPI 3 (#148)
* Stabilise JSON API (#141)
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
