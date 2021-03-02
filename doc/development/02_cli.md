Krill Command Line Client Setup
===============================

There are two CLI binaries included in Krill: `krillc` is intended to manage Certification
Authorities, and `krillpubc` is used manage a Publication Server.

Essentially the CLIs are a small convenient way to access the Krill API and represent responses
to the user. They parse command line arguments and/or files supplied by the user (where applicable),
and query or post (json) to the appropriate API end-point. Responses can be displayed as json, or
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
| `KrillPubdClient`   | src/cli/client.rs            | The client code for Krill Publication Server operations.             |
| `Command`           | src/cli/options.rs           | Enum for the intended CA command.                                    |
| `PublishersCommand` | src/cli/options.rs           | Enum for the intended Publication Server command.                    |
| `ApiResponse`       | src/cli/report.rs            | Structure to represent API responses.                                |

