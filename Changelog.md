# Change Log

Please see [here](https://github.com/NLnetLabs/krill/projects?query=is%3Aopen+sort%3Aname-asc)
for planned releases. 

## 0.3.0 'The Krilling is on the wall'

This release focused on publication.

You can now use Krill as an RFC8181 compliant Repository Server. If you want to use it as a dedicated
repository server only, you can simply do this by not configuring any CAs in that particular instance.

You can now also update your CAs to use a remote RFC8181 Repository Server. This is particularly
useful if you want to outsource the responsibility of 24/7 availability of your RPKI repository
to a third party.   

We have also made some breaking changes to the API. So, you may have to look again at any
automation you may have set previously up for version 0.2.0.

The known issue where Krill CAs and their publication server may become out-of-sync after
restarts has been solved. Krill CAs will always perform a check when publishing, and if needed
to do full re-syncs.

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
