# Change Log

## Unreleased next version

Breaking Changes

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

Other changes

* The minimum supported Rust version is now 1.70.0. ([#1198])

[#1178]: https://github.com/NLnetLabs/krill/pull/1178
[#1179]: https://github.com/NLnetLabs/krill/pull/1179
[#1181]: https://github.com/NLnetLabs/krill/pull/1181
[#1198]: https://github.com/NLnetLabs/krill/pull/1198
[rpki-rs#295]: https://github.com/NLnetLabs/rpki-rs/pull/295


## Previous releases

For previous releases, please see the
[releases page on Github](https://github.com/NLnetLabs/krill/releases)
for now.
