As part of this PR:

* command details history output has changed. Check and document.
* Krill internally always stores ROA payload with an explicit max length.
  Enforce this through a special type. (Make sure to be lenient when
  deserializing, though.)
* Move object name creation to daemon::ca.
* `BgpAnalysisEntry` contains a cloned `ConfiguredRoa`. Maybe it can
  contain a ref or a cow? Also, this should probably be switched into an
  enum to avoid `configured_roa? and `announcement` to panic.

Follow-up:

* Fix `impl Hash for crate::commons::api::admin::RepositoryContact`.
  (This will require a few changes in `crate::deamon::ca`.)
* `commons::api::ca::ParentStatuses::sync_candidates` can re-use the
  vec passed in and doesn’t need to allocate.
* Redesign `commons::api::roa::TypedPrefix` and `AsNumber`.
* `commons::api::rrdp` uses a lot of on-the-fly hashing.
* `commons::api::rrdp::RrdpFileRandom` shouldn’t wrap a `String``.
* Re-factor commons::error::Error and KrillResult.
* Change the store to use an FnOnce in execute so we don’t need to clone
  commands.
* Store no-op commands for auditing reasons.
* Remove event listeners.
* Shift httpclient to a stored reqwest::Client.
* Applying events can panic if events are inconsistent. Given that we
  are working on stored data which can be manipulated outside of our
  control, we should probably deal with that more gracefully.
* Split a TA Manager off the CA Manager.
* Use Cows in API structs to avoid cloning on the server side. This will
  also allow removing quite a few temporary vecs and replace them with
  iterators.

Notes

* I think we should apply API calls that create multiple commands
  atomically.
