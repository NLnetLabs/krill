# HSM Feature

HSM is a feature both in the sense that it adds the functionality to Krill for enabling support for
using external cryptographic tokens such as hardware security modules (HSMs), and in the sense that
the functionality is gated behind a Cargo feature of the same name.

The feature is currently NOT enabled by default. To enable the feature when building pass the
`--features hsm` argument to the `cargo build` command.

Further reading:

- [Overview](./overview.md)
- [Requirements](./requirements.md)
- [Architecture](./architecture.md)
- [Connectivity](./connectivity.md)