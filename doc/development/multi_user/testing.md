# Multi-User: Testing

Testing the multi-user functionality is primarily done at the integration testing level, that is integration tests as
Rust [defines them](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html).

At the lowest level, any test that exercises Krill from the outside will exercise the multi-user code because all
external and internal actions require an `Actor` instance, and all external requests must pass authentication and
authorization checks.

However, not all tests will exercise login as that is only used by the UI. The existing Krill integration tests use a
fixed admin API token without login because that was all Krill supported before, and must continue to work for the
direct REST API clients and indirect REST API client via `krillc`.

Testing of the UI specific aspects of multi-user support is handled by dedicated tests in the UI repository.
