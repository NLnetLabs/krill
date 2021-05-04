Krill Developer Documentation
=============================

> NOTE: If you are looking for Krill user or operational documentation, please have
> a look [here](https://rpki.readthedocs.io/en/latest/krill/index.html).

This documentation is aimed at providing Developers at NLnet Labs insight into how the
core Krill code works. But there are no secrets here, so anyone with a healthy interest
in the guts of this Krill species is welcome to have a look.

This is still a work-in-progress. The plan is to have separate chapters which explain
components and/or concepts in Krill: 

1. [Krill Daemon Code](./01_daemon.md)
2. [Krill CLI Code](./02_cli.md)
3. [Event Sourcing General Overview](./03_es_concepts.md)
4. [Event Sourcing in Krill](./04_es_krill.md)
5. [Repository Manager](./05_repo_manager.md)
6. [Certificate Authority Manager](./06_ca_manager.md)
7. [Multi-User Feature](./multi_user/readme.md)


Release Versions
----------------

Krill uses semantic versioning. We are currently still below version 1.0.0, meaning
that we may have incompatible API changes in MINOR releases. E.g. from 0.8.2 to 0.9.0.
We use PATCH versions for minor functionality as well as bug fixes.

Whenever it's feasible we will use release candidates, even for patch releases as they
may still include functional changes. We may skip this only in case a patch release is
purely an urgent bug fix release which does not introduce any functional changes.

In future, after 1.0.0, we plan to use semantic versioning rules as described here:
https://semver.org

I.e.:
Given a version number MAJOR.MINOR.PATCH, increment the:
1. MAJOR version when you make incompatible API changes,
2. MINOR version when you add functionality in a backwards compatible manner, and
3. PATCH version when you make backwards compatible bug fixes.

Release Checklist
-----------------

- [ ] Make a prep-release branch off the dev branch
- [ ] Update version in Cargo.toml
- [ ] Update Changelog.md
- [ ] Add the version to KeyStoreVersion
- [ ] Bump the version in the OpenAPI docs (to be deprecated in future)
- [ ] Update https://krill.readthedocs.io/en/latest/cli.html
- [ ] Make blog post (if deemed useful)
- [ ] Make a tagged release Lagosta and add it to Krill (refer to tag in commit)
- [ ] Make a PR to the dev branch, review, merge
- [ ] Make a PR to the main branch, final review, merge
- [ ] Make a GH release
- [ ] Add packages if needed (automated, may just work)
- [ ] Cargo publish
- [ ] Inform users: mailing list, discord, twitter


Release Candidate Steps
-----------------------

We aim to have RC releases available for 2-3 weeks during which time they can be tested
and hopefully accepted. If a new RC is needed, then we could use a shorter period for the
new RC release dependent on the nature of the fix.

Generally speaking we will want to do the following:

- [ ] Deploy to our own production environment
- [ ] Work with users with support contracts to test if needed
- [ ] Test data migrations of real systems (in addition to unit testing during development)
- [ ] Chase translations for new UI labels
- [ ] Get confirmation from a number of users
