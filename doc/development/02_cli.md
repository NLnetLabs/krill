Krill Command Line Client Setup
===============================

There is a CLI binary included in Krill: `krillc`

The CLI can be used to manage Certification Authorities, as well as the Publication Server (if used).
And it offers some functionality to users that the UI does not offer.

Essentially the CLI is a small convenient way to access the Krill API and represent responses
to the user. They parse command line arguments and/or files supplied by the user (where applicable),
and query or post (JSON) to the appropriate API end-point. Responses can be displayed as JSON, or
plain text.

From a development point of view it's important to know that the argument parsing by the CLIs
is tested manually. This can lead to issues as there is no strong typing enforced by the clapper
library that we use. So: CHECK whenever there are changes.

What **is** tested properly is the underlying code used by the CLIs to submit data and process
server responses. Our test code bypasses the command line parsing, but it uses the same underlying
code in the higher level tests such as `tests/functional.rs` in order to interact with a running
Krill instance.

The code can be found under `src/cli`. An overview of the most important elements follows:

| Element             | Code Path                    | Responsibility                                                       |
|---------------------|------------------------------|----------------------------------------------------------------------|
| `KrillClient`       | src/cli/client.rs            | The client code for Krill CA operations.                             |
| `Command`           | src/cli/options.rs           | Enum for the intended command.                                       |
| `ApiResponse`       | src/cli/report.rs            | Structure to represent API responses.                                |

